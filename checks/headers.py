"""
checks/headers.py - Security HTTP response headers analysis

Analyses response header values (not just presence) across all fetched target pages.
Validates HSTS, CSP (including directive token parsing to avoid wildcard subdomain false positives),
Clickjacking protection (X-Frame-Options and frame-ancestors), MIME sniffing (nosniff),
Referrer-Policy, and Permissions-Policy.
"""

import re
from typing import List, Tuple, Dict, Set
from core.models import Finding
from core.context import ScanContext


def _parse_csp_directives(csp_header: str) -> Dict[str, List[str]]:
    """
    Parse a Content-Security-Policy header string into a dictionary of directive -> tokens.
    Example: "default-src 'self'; script-src 'self' 'unsafe-inline'"
    Returns: {"default-src": ["'self'"], "script-src": ["'self'", "'unsafe-inline'"]}
    """
    directives = {}
    for part in csp_header.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            name = tokens[0].lower()
            directives[name] = tokens[1:]
    return directives


def run(ctx: ScanContext) -> Tuple[List[Finding], List[str]]:
    """
    Evaluate security headers on all fetched pages.
    Returns:
        (findings, passed_checks)
    """
    findings: List[Finding] = []
    passed_checks: List[str] = []

    pages_to_check = ctx.all_pages if ctx.all_pages else ([ctx.home_response] if ctx.home_response else [])
    if not pages_to_check:
        return findings, passed_checks

    # Keep track of findings by finding ID to prevent duplicate listings on the same page
    seen_finding_keys: Set[Tuple[str, str]] = set()

    def add_finding(f: Finding):
        key = (f.id, f.url)
        if key not in seen_finding_keys:
            seen_finding_keys.add(key)
            findings.append(f)

    # 1. Evaluate HSTS (Strict-Transport-Security)
    if ctx.scheme != "https":
        passed_checks.append("HSTS not applicable on HTTP")
    else:
        hsts_found_any = False
        for page in pages_to_check:
            hsts = page.headers.get("Strict-Transport-Security")
            if not hsts:
                add_finding(Finding(
                    id="HDR-001",
                    title="HSTS header missing",
                    category="headers",
                    severity="Medium",
                    evidence=f"Strict-Transport-Security header not present on HTTPS endpoint: {page.url}",
                    fix="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    confidence="Confirmed",
                    url=page.url,
                ))
            else:
                hsts_found_any = True
                match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
                if match:
                    age = int(match.group(1))
                    if age == 0:
                        add_finding(Finding(
                            id="HDR-002",
                            title="HSTS is explicitly disabled (max-age is 0)",
                            category="headers",
                            severity="Medium",
                            evidence=f"Strict-Transport-Security header sets max-age=0, explicitly disabling transport security: '{hsts[:200]}'",
                            fix="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                            confidence="Confirmed",
                            url=page.url,
                        ))
                    elif age < 15552000:
                        add_finding(Finding(
                            id="HDR-002",
                            title="HSTS max-age is too short",
                            category="headers",
                            severity="Low",
                            evidence=f"Strict-Transport-Security max-age ({age}s) is under recommended 15552000s (180 days): '{hsts[:200]}'",
                            fix="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                            confidence="Confirmed",
                            url=page.url,
                        ))
                else:
                    add_finding(Finding(
                        id="HDR-002",
                        title="HSTS header missing valid max-age directive",
                        category="headers",
                        severity="Low",
                        evidence=f"Strict-Transport-Security header lacks valid max-age: '{hsts[:200]}'",
                        fix="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                        confidence="Confirmed",
                        url=page.url,
                    ))

        if hsts_found_any and not any(f.id.startswith("HDR-001") or f.id.startswith("HDR-002") for f in findings):
            passed_checks.append("HSTS header properly configured")

    # 2. Evaluate Content-Security-Policy (CSP) across pages
    csp_clean_any = False
    for page in pages_to_check:
        csp = page.headers.get("Content-Security-Policy")
        csp_report_only = page.headers.get("Content-Security-Policy-Report-Only")

        if not csp:
            if csp_report_only:
                add_finding(Finding(
                    id="HDR-003",
                    title="Content Security Policy is in Report-Only mode (not enforced)",
                    category="headers",
                    severity="Medium",
                    evidence=f"Only Content-Security-Policy-Report-Only is set; policies are logged but not actively enforced: '{csp_report_only[:200]}'",
                    fix="Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
                    confidence="Confirmed",
                    url=page.url,
                ))
            else:
                add_finding(Finding(
                    id="HDR-003",
                    title="Content Security Policy missing",
                    category="headers",
                    severity="Medium",
                    evidence=f"Content-Security-Policy header not set on {page.url}",
                    fix="Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
                    confidence="Confirmed",
                    url=page.url,
                ))
        else:
            # Parse directives to avoid regex false positives on wildcard subdomains (e.g. *.example.com)
            directives = _parse_csp_directives(csp)
            weak_reasons = []

            for dir_name in ("default-src", "script-src"):
                tokens = directives.get(dir_name, [])
                tokens_lower = [t.lower().strip("'\"") for t in tokens]

                if "unsafe-inline" in tokens_lower:
                    weak_reasons.append(f"{dir_name} contains 'unsafe-inline'")
                if "unsafe-eval" in tokens_lower:
                    weak_reasons.append(f"{dir_name} contains 'unsafe-eval'")
                # Look for standalone '*' source token (strictly not '*.domain.com')
                if "*" in tokens:
                    weak_reasons.append(f"{dir_name} uses standalone wildcard '*' source")

            if weak_reasons:
                add_finding(Finding(
                    id="HDR-004",
                    title="Content Security Policy is weak",
                    category="headers",
                    severity="Low",
                    evidence=f"CSP contains weak directive(s) [{', '.join(weak_reasons)}]: '{csp[:200]}'",
                    fix="Content-Security-Policy: default-src 'self'; script-src 'self';",
                    confidence="Confirmed",
                    url=page.url,
                ))
            else:
                csp_clean_any = True

    if csp_clean_any and not any(f.id in ("HDR-003", "HDR-004") for f in findings):
        passed_checks.append("Content Security Policy active")

    # 3. Evaluate Clickjacking Protection (X-Frame-Options or CSP frame-ancestors)
    clickjacking_protected_any = False
    for page in pages_to_check:
        csp_header = page.headers.get("Content-Security-Policy") or ""
        csp_dirs = _parse_csp_directives(csp_header)
        has_frame_ancestors = "frame-ancestors" in csp_dirs

        xfo = (page.headers.get("X-Frame-Options") or "").strip()
        xfo_upper = xfo.upper()

        # Check validity of X-Frame-Options if present
        is_xfo_valid = xfo_upper in ("DENY", "SAMEORIGIN")

        if not has_frame_ancestors and not is_xfo_valid:
            if xfo_upper.startswith("ALLOW-FROM"):
                add_finding(Finding(
                    id="HDR-005",
                    title="Clickjacking protection uses deprecated ALLOW-FROM",
                    category="headers",
                    severity="Medium",
                    evidence=f"X-Frame-Options uses 'ALLOW-FROM', which is obsolete and ignored by modern browsers: '{xfo}'",
                    fix="X-Frame-Options: DENY (or configure CSP frame-ancestors)",
                    confidence="Confirmed",
                    url=page.url,
                ))
            else:
                add_finding(Finding(
                    id="HDR-005",
                    title="Missing Clickjacking protection",
                    category="headers",
                    severity="Medium",
                    evidence=f"Neither valid X-Frame-Options (DENY/SAMEORIGIN) nor CSP frame-ancestors is configured on {page.url}",
                    fix="X-Frame-Options: DENY",
                    confidence="Confirmed",
                    url=page.url,
                ))
        else:
            clickjacking_protected_any = True

    if clickjacking_protected_any and not any(f.id.startswith("HDR-005") for f in findings):
        passed_checks.append("Clickjacking protection enabled")

    # 4. Evaluate X-Content-Type-Options (MIME Sniffing Prevention)
    xcto_protected_any = False
    for page in pages_to_check:
        xcto = (page.headers.get("X-Content-Type-Options") or "").strip().lower()
        if xcto != "nosniff":
            add_finding(Finding(
                id="HDR-006",
                title="Missing X-Content-Type-Options",
                category="headers",
                severity="Low",
                evidence=f"X-Content-Type-Options header value: '{xcto or 'missing'}' (expected 'nosniff') on {page.url}",
                fix="X-Content-Type-Options: nosniff",
                confidence="Confirmed",
                url=page.url,
            ))
        else:
            xcto_protected_any = True

    if xcto_protected_any and not any(f.id.startswith("HDR-006") for f in findings):
        passed_checks.append("X-Content-Type-Options present")

    # 5. Evaluate Referrer-Policy
    ref_pol_clean_any = False
    for page in pages_to_check:
        ref_pol = (page.headers.get("Referrer-Policy") or "").strip()
        if not ref_pol:
            add_finding(Finding(
                id="HDR-007",
                title="Referrer-Policy header missing",
                category="headers",
                severity="Low",
                evidence=f"Referrer-Policy header not present in response from {page.url}",
                fix="Referrer-Policy: strict-origin-when-cross-origin",
                confidence="Confirmed",
                url=page.url,
            ))
        elif ref_pol.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            add_finding(Finding(
                id="HDR-007",
                title="Insecure Referrer-Policy configured",
                category="headers",
                severity="Low",
                evidence=f"Referrer-Policy is set to '{ref_pol}', which may leak sensitive URL paths in cross-origin requests",
                fix="Referrer-Policy: strict-origin-when-cross-origin",
                confidence="Confirmed",
                url=page.url,
            ))
        else:
            ref_pol_clean_any = True

    if ref_pol_clean_any and not any(f.id.startswith("HDR-007") for f in findings):
        passed_checks.append("Referrer-Policy configured")

    # 6. Evaluate Permissions-Policy (Feature-Policy)
    perm_pol_clean_any = False
    for page in pages_to_check:
        perm_pol = page.headers.get("Permissions-Policy") or page.headers.get("Feature-Policy")
        if not perm_pol:
            add_finding(Finding(
                id="HDR-008",
                title="Permissions-Policy header missing",
                category="headers",
                severity="Info",
                evidence=f"Permissions-Policy (and legacy Feature-Policy) not present on {page.url}",
                fix="Permissions-Policy: camera=(), microphone=(), geolocation=()",
                confidence="Confirmed",
                url=page.url,
            ))
        else:
            perm_pol_clean_any = True

    if perm_pol_clean_any and not any(f.id.startswith("HDR-008") for f in findings):
        passed_checks.append("Permissions-Policy present")

    return findings, passed_checks
