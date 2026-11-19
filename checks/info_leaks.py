"""
checks/info_leaks.py - Server and technology information disclosure checks

Scans all fetched pages in ctx.all_pages for technical information leakage:
1. Software version numbers in Server header.
2. Technology disclosure via X-Powered-By, X-Generator, and internal hostname headers.
3. ASP.NET / ASP.NET MVC version headers.
4. Debug and profiling headers (e.g. X-Debug-Token).
5. Detailed error messages and stack traces exposed in response bodies.
"""

import re
from typing import List, Tuple, Set
from core.models import Finding
from core.context import ScanContext

INTERNAL_HOST_HEADERS = ("x-backend-server", "x-served-by", "x-server-name", "x-host")
DEBUG_HEADERS = ("x-debug-token", "x-debug-token-link", "x-debug", "x-profiling", "x-sourcemap")

STACK_TRACE_PATTERNS = [
    (r"Traceback \(most recent call last\):[\s\S]{1,200}?File \"[^\"]+\", line \d+", "Python stack trace"),
    (r"java\.[a-zA-Z0-9_.]+(?:Exception|Error):[\s\S]{1,200}?\tat [a-zA-Z0-9_.]+\(", "Java stack trace"),
    (r"(?:TypeError|ReferenceError|SyntaxError): .+?\n\s+at (?:async )?[a-zA-Z0-9_.<>]+ \([^\)]+:\d+:\d+\)", "Node.js stack trace"),
    (r"(?:Fatal error|Parse error): .+ in /[^\s]+ on line \d+", "PHP fatal error with path"),
    (r"System\.[a-zA-Z0-9_.]+Exception: .+?\n\s+at [a-zA-Z0-9_.]+\(", ".NET stack trace"),
]


def _sanitize_evidence(text: str) -> str:
    """Redact sensitive parameter values and passwords from proof evidence."""
    sanitized = re.sub(
        r'(?i)(password|secret|token|api[_\-]?key|auth)\s*[:=]\s*(?:\'[^\']*\'|"[^"]*"|[^\s;,\'"&]+)',
        r'\1=***REDACTED***',
        text
    )
    sanitized = re.sub(r'\s+', ' ', sanitized)
    return sanitized.strip()[:200]


def run(ctx: ScanContext) -> Tuple[List[Finding], List[str]]:
    """
    Evaluate information disclosure across all fetched pages.
    Returns:
        (findings, passed_checks)
    """
    findings: List[Finding] = []
    passed_checks: List[str] = []

    pages_to_check = ctx.all_pages if ctx.all_pages else ([ctx.home_response] if ctx.home_response else [])
    if not pages_to_check:
        return findings, passed_checks

    seen_finding_keys: Set[Tuple[str, str]] = set()

    def add_finding(f: Finding):
        key = (f.id, f.url)
        if key not in seen_finding_keys:
            seen_finding_keys.add(key)
            findings.append(f)

    server_version_detected = False
    x_powered_by_detected = False
    aspnet_detected = False
    debug_header_detected = False
    stack_trace_detected = False

    for page in pages_to_check:
        headers = page.headers
        target_url = page.url

        # 1. Server header inspection (Flag ONLY if a version number is present)
        server_hdr = headers.get("Server")
        if server_hdr:
            if re.search(r"\d+\.\d+", server_hdr):
                server_version_detected = True
                add_finding(Finding(
                    id="INF-001",
                    title="Server header discloses software version",
                    category="info_leaks",
                    severity="Low",
                    evidence=f"Server: {server_hdr[:200]}",
                    fix="Configure web server to suppress version numbers (e.g. 'ServerTokens Prod' in Apache or 'server_tokens off' in Nginx)",
                    confidence="Confirmed",
                    url=target_url,
                ))

        # 2. X-Powered-By header inspection
        x_powered_by = headers.get("X-Powered-By")
        if x_powered_by:
            x_powered_by_detected = True
            add_finding(Finding(
                id="INF-002",
                title="X-Powered-By header discloses technology",
                category="info_leaks",
                severity="Low",
                evidence=f"X-Powered-By: {x_powered_by[:200]}",
                fix="Disable the X-Powered-By header (e.g. 'app.disable(\"x-powered-by\")' in Express or 'expose_php = Off' in php.ini)",
                confidence="Confirmed",
                url=target_url,
            ))

        # 3. ASP.NET version headers
        aspnet_ver = headers.get("X-AspNet-Version")
        aspnet_mvc_ver = headers.get("X-AspNetMvc-Version")

        if aspnet_ver:
            aspnet_detected = True
            add_finding(Finding(
                id="INF-003",
                title="ASP.NET version header disclosure",
                category="info_leaks",
                severity="Low",
                evidence=f"X-AspNet-Version: {aspnet_ver[:200]}",
                fix="Disable ASP.NET version header in web.config (<httpRuntime enableVersionHeader='false' />)",
                confidence="Confirmed",
                url=target_url,
            ))
        elif aspnet_mvc_ver:
            aspnet_detected = True
            add_finding(Finding(
                id="INF-004",
                title="ASP.NET MVC version header disclosure",
                category="info_leaks",
                severity="Low",
                evidence=f"X-AspNetMvc-Version: {aspnet_mvc_ver[:200]}",
                fix="Disable ASP.NET MVC version header via MvcHandler.DisableMvcResponseHeader = true",
                confidence="Confirmed",
                url=target_url,
            ))

        # 4. Internal server hostname headers
        for h_name in INTERNAL_HOST_HEADERS:
            h_val = headers.get(h_name)
            if h_val:
                add_finding(Finding(
                    id="INF-005",
                    title="Internal server hostname disclosed in headers",
                    category="info_leaks",
                    severity="Low",
                    evidence=f"{h_name}: {h_val[:200]}",
                    fix="Remove internal routing and proxy hostname headers from client responses.",
                    confidence="Confirmed",
                    url=target_url,
                ))

        # 5. X-Generator CMS disclosure
        x_gen = headers.get("X-Generator")
        if x_gen:
            add_finding(Finding(
                id="INF-006",
                title="X-Generator header discloses CMS/generator technology",
                category="info_leaks",
                severity="Low",
                evidence=f"X-Generator: {x_gen[:200]}",
                fix="Suppress CMS generator headers in web application settings.",
                confidence="Confirmed",
                url=target_url,
            ))

        # 6. Debug and profiling headers
        for d_hdr in DEBUG_HEADERS:
            d_val = headers.get(d_hdr)
            if d_val:
                debug_header_detected = True
                add_finding(Finding(
                    id="INF-007",
                    title="Debug or diagnostic header exposed",
                    category="info_leaks",
                    severity="Medium",
                    evidence=f"{d_hdr}: {d_val[:200]}",
                    fix="Disable development and diagnostic toolbars/headers in production environments.",
                    confidence="Confirmed",
                    url=target_url,
                ))

        # 7. Stack trace / detailed error disclosure in response body
        if page.text:
            body = page.text
            for pattern, trace_name in STACK_TRACE_PATTERNS:
                match = re.search(pattern, body)
                if match:
                    stack_trace_detected = True
                    start_pos = match.start()
                    raw_snippet = body[start_pos : start_pos + 250]
                    matched_snippet = _sanitize_evidence(raw_snippet)
                    add_finding(Finding(
                        id="INF-008",
                        title=f"Detailed error message or stack trace exposed in response body ({trace_name})",
                        category="info_leaks",
                        severity="Medium",
                        evidence=f"Observed pattern: {matched_snippet}",
                        fix="Disable verbose error display in production. Return generic error pages to users and log exceptions internally.",
                        confidence="Confirmed",
                        url=target_url,
                    ))
                    break

    # Passed checks compilation
    if not server_version_detected:
        passed_checks.append("Server header does not expose software version")

    if not x_powered_by_detected:
        passed_checks.append("X-Powered-By header suppressed")

    if not aspnet_detected:
        passed_checks.append("ASP.NET version headers suppressed")

    if not debug_header_detected and not stack_trace_detected:
        passed_checks.append("No debug headers or stack traces exposed")

    return findings, passed_checks
