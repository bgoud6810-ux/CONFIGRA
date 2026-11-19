"""
checks/methods.py - Allowed and dangerous HTTP methods analysis

Tests OPTIONS to inspect the Allow header and verifies whether the TRACE
method is active by checking for request line reflection.
Evaluates method configurations across crawled endpoints and flags
risky methods without performing any state-changing or destructive requests.
"""

from typing import List, Tuple, Set, Optional

import requests

from core.models import Finding
from core.context import ScanContext

RISKY_METHODS = ("PUT", "DELETE")
EXTENDED_DANGEROUS_METHODS = ("CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")


def _send_method_request(
    ctx: ScanContext, method: str, path_or_url: str = "/"
) -> Optional[requests.Response]:
    """Helper to send non-destructive method requests via the scan context's safe pipeline."""
    if getattr(ctx, "cancelled", False):
        if hasattr(ctx, "_record_error"):
            ctx._record_error(f"Scan cancelled before {method} request to {path_or_url}")
        else:
            ctx.errors.append(f"Scan cancelled before {method} request to {path_or_url}")
        return None
    try:
        return ctx.request(method, path_or_url, timeout=getattr(ctx, "timeout", 10.0))
    except Exception as exc:
        err = f"Method request {method} {path_or_url} failed: {exc}"
        if hasattr(ctx, "_record_error"):
            ctx._record_error(err)
        else:
            ctx.errors.append(err)
        return None


def _parse_allow_header(allow_hdr: str) -> Set[str]:
    """
    Parse and tokenize comma-separated Allow header into discrete uppercase methods.
    Prevents false positives where substrings like 'INPUT' match 'PUT'.
    """
    if not allow_hdr:
        return set()
    return {token.strip().upper() for token in allow_hdr.split(",") if token.strip()}


def run(ctx: ScanContext) -> Tuple[List[Finding], List[str]]:
    """
    Evaluate HTTP methods via OPTIONS and safe TRACE probe.
    Returns:
        (findings, passed_checks)
    """
    findings: List[Finding] = []
    passed_checks: List[str] = []
    seen_finding_keys: Set[Tuple[str, str]] = set()

    def add_finding(f: Finding):
        key = (f.id, f.url)
        if key not in seen_finding_keys:
            seen_finding_keys.add(key)
            findings.append(f)

    # Determine endpoints to check (root + up to 1 crawled subpage for consistency check)
    endpoints_to_test = ["/"]
    if ctx.extra_pages:
        extra_url = ctx.extra_pages[0].url
        if extra_url not in endpoints_to_test and extra_url != ctx.base_url:
            endpoints_to_test.append(extra_url)

    trace_tested = False
    trace_confirmed = False
    risky_advertised_any = False

    for endpoint in endpoints_to_test:
        opt_resp = _send_method_request(ctx, "OPTIONS", endpoint)
        if opt_resp is None:
            continue

        endpoint_url = opt_resp.url or endpoint
        raw_allow = opt_resp.headers.get("Allow")

        if raw_allow is not None:
            allow_methods = _parse_allow_header(raw_allow)

            # Check for malformed / empty Allow header on successful OPTIONS response
            if opt_resp.status_code == 200 and not allow_methods:
                add_finding(Finding(
                    id="MTH-004",
                    title="Empty or malformed Allow header in OPTIONS response",
                    category="headers",
                    severity="Info",
                    evidence=f"OPTIONS returned HTTP 200 with malformed Allow header: '{raw_allow}'",
                    fix="Configure the server to return valid, comma-separated HTTP methods in the Allow header.",
                    confidence="Confirmed",
                    url=endpoint_url,
                ))

            # 1. Check for PUT / DELETE in Allow header (tokenized matching)
            found_risky = [m for m in RISKY_METHODS if m in allow_methods]
            if found_risky:
                risky_advertised_any = True
                add_finding(Finding(
                    id="MTH-002",
                    title=f"Potentially dangerous HTTP methods [{', '.join(found_risky)}] advertised in Allow header",
                    category="headers",
                    severity="Low",
                    evidence=f"Allow header lists '{raw_allow.strip()}'. Read from Allow header and NOT tested.",
                    fix="Restrict server configuration to only allow required methods (e.g. GET, HEAD, OPTIONS, POST).",
                    confidence="Likely",
                    url=endpoint_url,
                ))

            # 2. Check for extended dangerous methods (WebDAV / CONNECT)
            found_extended = [m for m in EXTENDED_DANGEROUS_METHODS if m in allow_methods]
            if found_extended:
                add_finding(Finding(
                    id="MTH-003",
                    title=f"Extended dangerous or WebDAV methods [{', '.join(found_extended)}] advertised in Allow header",
                    category="headers",
                    severity="Low",
                    evidence=f"Allow header advertises WebDAV/proxy methods: '{raw_allow.strip()}'. Read from Allow header and NOT tested.",
                    fix="Disable WebDAV extensions and unneeded proxy methods on public endpoints.",
                    confidence="Likely",
                    url=endpoint_url,
                ))

            # 3. Test TRACE method if advertised or on root endpoint
            if ("TRACE" in allow_methods or endpoint == "/") and not trace_confirmed:
                trace_tested = True
                trace_resp = _send_method_request(ctx, "TRACE", endpoint)
                if trace_resp is not None and trace_resp.status_code == 200:
                    if "TRACE " in trace_resp.text or "Host:" in trace_resp.text:
                        trace_confirmed = True
                        add_finding(Finding(
                            id="MTH-001",
                            title="HTTP TRACE method enabled (Cross-Site Tracing risk)",
                            category="headers",
                            severity="Medium",
                            evidence=f"TRACE returned 200 OK echoing request body: {trace_resp.text.strip()[:150]}",
                            fix="Disable HTTP TRACE method in server configuration (e.g. 'TraceEnable off' in Apache).",
                            confidence="Confirmed",
                            url=trace_resp.url,
                        ))

    # Compile passed checks
    if not trace_confirmed:
        passed_checks.append("HTTP TRACE method disabled")

    if not risky_advertised_any:
        passed_checks.append("Dangerous HTTP methods (PUT/DELETE) not advertised in Allow header")

    return findings, passed_checks
