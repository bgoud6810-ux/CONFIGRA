"""
checks/cors.py - Cross-Origin Resource Sharing (CORS) misconfiguration checks

Tests targets for:
1. Arbitrary Origin reflection (with and without credentials).
2. Wildcard Access-Control-Allow-Origin (*) with and without credentials.
3. Insecure null origin trust (Origin: null).
4. Multiple or malformed CORS headers (e.g. comma-separated origins).
5. Preflight (OPTIONS) response validation.
6. Multi-page CORS differences across crawled endpoints.
"""

from typing import List, Tuple, Set, Optional

import requests

from core.models import Finding
from core.context import ScanContext

UNTRUSTED_ORIGIN = "https://untrusted.example"
NULL_ORIGIN = "null"


def _send_cors_request(
    ctx: ScanContext, method: str, path_or_url: str, headers: dict
) -> Optional[requests.Response]:
    """Send an HTTP request using the scan context's safe request pipeline."""
    if getattr(ctx, "cancelled", False):
        if hasattr(ctx, "_record_error"):
            ctx._record_error(f"Scan cancelled before CORS {method} request to {path_or_url}")
        else:
            ctx.errors.append(f"Scan cancelled before CORS {method} request to {path_or_url}")
        return None
    try:
        return ctx.request(method, path_or_url, headers=headers, timeout=getattr(ctx, "timeout", 10.0))
    except Exception as exc:
        err = f"CORS request ({method}) failed for {path_or_url}: {exc}"
        if hasattr(ctx, "_record_error"):
            ctx._record_error(err)
        else:
            ctx.errors.append(err)
        return None


def _get_all_acao_headers(response: requests.Response) -> List[str]:
    """Retrieve all Access-Control-Allow-Origin headers from urllib3 raw or standard dict."""
    acao_list: List[str] = []
    raw = getattr(response, "raw", None)
    if raw and hasattr(raw, "headers"):
        raw_headers = raw.headers
        if hasattr(raw_headers, "getlist"):
            try:
                vals = raw_headers.getlist("access-control-allow-origin")
                if vals:
                    acao_list.extend(vals)
            except Exception:
                pass
        elif hasattr(raw_headers, "get_all"):
            try:
                vals = raw_headers.get_all("Access-Control-Allow-Origin", [])
                if vals:
                    acao_list.extend(vals)
            except Exception:
                pass

    if not acao_list and "Access-Control-Allow-Origin" in response.headers:
        val = response.headers.get("Access-Control-Allow-Origin")
        if val:
            acao_list.append(val)

    return [h.strip() for h in acao_list if h and h.strip()]


def _evaluate_cors_response(
    resp: requests.Response,
    tested_origin: str,
    findings: List[Finding],
    seen_keys: Set[Tuple[str, str]],
    is_preflight: bool = False,
):
    """
    Examine the response headers against CORS security rules and populate findings.
    """
    acao_headers = _get_all_acao_headers(resp)
    if not acao_headers:
        return

    acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"

    def add_finding(f: Finding):
        key = (f.id, f.url)
        if key not in seen_keys:
            seen_keys.add(key)
            findings.append(f)

    # 1. Multiple or comma-separated origins check
    if len(acao_headers) > 1 or any("," in h for h in acao_headers):
        combined = "; ".join(acao_headers)
        add_finding(Finding(
            id="COR-007",
            title="Malformed or multiple Access-Control-Allow-Origin headers",
            category="headers",
            severity="Low",
            evidence=f"Multiple or comma-separated origins detected: '{combined}'",
            fix="The CORS specification allows only a single origin or wildcard. Update server config to return exactly one origin.",
            confidence="Confirmed",
            url=resp.url,
        ))

    acao = acao_headers[0].strip()

    # 2. Preflight-specific checks
    if is_preflight:
        if acao == tested_origin or acao == "*":
            if acac:
                add_finding(Finding(
                    id="COR-008",
                    title="Insecure CORS preflight response allows arbitrary origin with credentials",
                    category="headers",
                    severity="High",
                    evidence=f"OPTIONS preflight returned ACAO: '{acao}' with ACAC: true for tested Origin: '{tested_origin}'",
                    fix="Validate Origin in preflight requests against a strict whitelist before granting credentials.",
                    confidence="Confirmed",
                    url=resp.url,
                ))
            else:
                add_finding(Finding(
                    id="COR-008",
                    title="Insecure CORS preflight response allows arbitrary origin",
                    category="headers",
                    severity="Medium",
                    evidence=f"OPTIONS preflight returned ACAO: '{acao}' for tested Origin: '{tested_origin}'",
                    fix="Only return Access-Control-Allow-Origin in preflight responses for authorized domain origins.",
                    confidence="Confirmed",
                    url=resp.url,
                ))
        return

    # 3. Wildcard origin check (*)
    if acao == "*":
        if acac:
            add_finding(Finding(
                id="COR-001",
                title="CORS wildcard origin with credentials allowed",
                category="headers",
                severity="Medium",
                evidence="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                fix="Disable credentials or specify explicit origins. Browsers reject wildcard origins when credentials are true.",
                confidence="Confirmed",
                url=resp.url,
            ))
        else:
            add_finding(Finding(
                id="COR-002",
                title="CORS wildcard origin allowed",
                category="headers",
                severity="Low",
                evidence="Access-Control-Allow-Origin: *",
                fix="Specify explicit trusted origins instead of wildcard if non-public data is served: Access-Control-Allow-Origin: https://trusted.example",
                confidence="Confirmed",
                url=resp.url,
            ))

    # 4. Null origin check
    elif acao.lower() == "null" or tested_origin == "null" and "null" in acao.lower():
        if acac:
            add_finding(Finding(
                id="COR-005",
                title="CORS trusts null origin with credentials",
                category="headers",
                severity="High",
                evidence="Access-Control-Allow-Origin: null; Access-Control-Allow-Credentials: true",
                fix="Remove 'null' from trusted origin lists. Sandboxed iframes and local documents use null origins and can bypass SOP.",
                confidence="Confirmed",
                url=resp.url,
            ))
        else:
            add_finding(Finding(
                id="COR-006",
                title="CORS allows null origin",
                category="headers",
                severity="Low",
                evidence="Access-Control-Allow-Origin: null",
                fix="Avoid trusting 'null' in Access-Control-Allow-Origin headers.",
                confidence="Confirmed",
                url=resp.url,
            ))

    # 5. Arbitrary untrusted origin reflection
    elif tested_origin == UNTRUSTED_ORIGIN and (acao == UNTRUSTED_ORIGIN or UNTRUSTED_ORIGIN in acao):
        if acac:
            add_finding(Finding(
                id="COR-003",
                title="CORS reflects arbitrary origin with credentials",
                category="headers",
                severity="High",
                evidence=f"Origin '{UNTRUSTED_ORIGIN}' reflected with Access-Control-Allow-Credentials: true",
                fix="Validate Origin header against an explicit server whitelist before reflecting with credentials.",
                confidence="Confirmed",
                url=resp.url,
            ))
        else:
            add_finding(Finding(
                id="COR-004",
                title="CORS reflects arbitrary origin",
                category="headers",
                severity="Medium",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                fix="Validate Origin header against an explicit server whitelist before reflecting.",
                confidence="Confirmed",
                url=resp.url,
            ))


def run(ctx: ScanContext) -> Tuple[List[Finding], List[str]]:
    """
    Evaluate CORS configuration using passive analysis and polite active probes.
    Returns:
        (findings, passed_checks)
    """
    findings: List[Finding] = []
    passed_checks: List[str] = []
    seen_keys: Set[Tuple[str, str]] = set()

    # Step 1: Passive check on already collected pages (0 extra requests)
    for page in ctx.all_pages:
        _evaluate_cors_response(page, tested_origin="", findings=findings, seen_keys=seen_keys)

    # Step 2: Active probe with untrusted origin on base URL
    probe_resp = _send_cors_request(ctx, "GET", "/", headers={"Origin": UNTRUSTED_ORIGIN})
    cors_active_on_root = False
    if probe_resp is not None:
        _evaluate_cors_response(probe_resp, tested_origin=UNTRUSTED_ORIGIN, findings=findings, seen_keys=seen_keys)
        cors_active_on_root = bool(probe_resp.headers.get("Access-Control-Allow-Origin"))

    # Step 3: Multi-page difference test (probe up to 1 crawled subpage if available)
    if ctx.extra_pages:
        extra_url = ctx.extra_pages[0].url
        sub_resp = _send_cors_request(ctx, "GET", extra_url, headers={"Origin": UNTRUSTED_ORIGIN})
        if sub_resp is not None:
            _evaluate_cors_response(sub_resp, tested_origin=UNTRUSTED_ORIGIN, findings=findings, seen_keys=seen_keys)

    # Step 4: Targeted probe for 'null' origin handling
    null_resp = _send_cors_request(ctx, "GET", "/", headers={"Origin": NULL_ORIGIN})
    if null_resp is not None:
        _evaluate_cors_response(null_resp, tested_origin=NULL_ORIGIN, findings=findings, seen_keys=seen_keys)

    # Step 5: Preflight check if CORS was active
    if cors_active_on_root:
        preflight_headers = {
            "Origin": UNTRUSTED_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
        pre_resp = _send_cors_request(ctx, "OPTIONS", "/", headers=preflight_headers)
        if pre_resp is not None:
            _evaluate_cors_response(
                pre_resp,
                tested_origin=UNTRUSTED_ORIGIN,
                findings=findings,
                seen_keys=seen_keys,
                is_preflight=True,
            )

    # Check if any findings were recorded
    if not findings:
        passed_checks.append("CORS Access-Control-Allow-Origin securely configured")

    return findings, passed_checks
