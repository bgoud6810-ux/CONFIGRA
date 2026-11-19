"""
scanner.py - Command-line interface for Automated Security Misconfiguration Detector

Audits authorized web targets for security misconfigurations and outputs
terminal diagnostics, structured JSON, self-contained HTML reports,
and before-and-after re-scan comparisons.
"""

import sys
import os
import time
import json
import socket
import argparse
import re
import hashlib
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Any, Tuple, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.context import ScanContext, ScanCancelled
from core.runner import run_all
from core.scoring import score_and_grade
from core.safety import validate_url_target, normalize_target_url
from core.models import (
    SCAN_MODE_AUTHORIZED_ASSESSMENT,
    SCAN_MODE_LABELS,
    SCAN_MODE_PASSIVE_PUBLIC,
    VALID_SCAN_MODES,
)

try:
    from reports.html_report import generate_report
    HAS_REPORTER = True
except ImportError:
    HAS_REPORTER = False


def check_target_safety(target_url: str, i_have_permission: bool, scan_mode: str = SCAN_MODE_AUTHORIZED_ASSESSMENT) -> bool:
    """
    Hardened target safety validation.

    - Restricts scans without explicit authorization to loopback/private targets in authorized mode.
    - Passive public inspection allows public/global targets only for non-intrusive observation (SSRF protections preserved).
    - Blocks link-local, reserved, multicast, unspecified, and cloud-metadata destinations.
    - Validates URL scheme and hostname resolution (revalidated by request pipeline/redirects).
    """
    result = validate_url_target(target_url, i_have_permission=i_have_permission, scan_mode=scan_mode)
    if result.ok:
        return True

    # Keep clear CLI feedback while preserving compatibility with callers that only need bool.
    if scan_mode != SCAN_MODE_PASSIVE_PUBLIC and not i_have_permission and "require explicit authorized testing confirmation" in (result.reason or ""):
        print(f"[!] Refused: {result.reason}")
        print("[!] By default, scans are restricted to localhost and private network targets.")
        print("[!] To scan public/external targets, you must explicitly confirm authorized permission (--i-have-permission).")
    else:
        print(f"[!] Target validation failed: {result.reason}")
    return False


def resolve_target_ip(target_url: str) -> Optional[str]:
    """
    Safely resolve the target hostname to an IP address.
    Returns None on resolution failure without throwing exceptions.
    """
    try:
        # Resolution for reporting only; SSRF request-path validation is enforced separately.
        result = validate_url_target(target_url, i_have_permission=True, scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT)
        if result.ok and result.resolved_ips:
            return result.resolved_ips[0]
    except Exception:
        pass
    try:
        hostname = urlparse(normalize_target_url(target_url)).hostname
        if not hostname:
            return None
        addr_info = socket.getaddrinfo(hostname, None)
        if addr_info and addr_info[0] and addr_info[0][4]:
            return addr_info[0][4][0]
    except Exception:
        return None
    return None


def _get_comparison_key(item: Any) -> Tuple[str, str, str]:
    """
    Generate a stable, collision-free comparison key preserving distinct resources
    while preventing multi-page URL expansion churn.
    Returns: (category, identity_token, resource_discriminator)
    """
    if isinstance(item, dict):
        fid = str(item.get("id", "")).strip()
        cat = str(item.get("category", "")).strip().lower()
        title = str(item.get("title", "")).strip()
        raw_url = str(item.get("url", "")).strip()
        evidence = str(item.get("evidence", "")).strip()
    else:
        fid = str(getattr(item, "id", "")).strip()
        cat = str(getattr(item, "category", "")).strip().lower()
        title = str(getattr(item, "title", "")).strip()
        raw_url = str(getattr(item, "url", "")).strip()
        evidence = str(getattr(item, "evidence", "")).strip()

    # 1. Target-wide findings (headers, cors, methods, info_leaks)
    # Key primarily on finding ID
    if (
        cat in ("headers", "info_leaks")
        or fid.startswith("HDR-")
        or fid.startswith("COR-")
        or fid.startswith("MTH-")
        or fid.startswith("INF-")
    ):
        return (cat or "target_wide", fid, "")

    # 2. Cookie findings (preserve cookie-specific identity, avoid generic default collision)
    if cat == "cookies" or fid.startswith("CKE-") or fid.startswith("CK-"):
        # Check if ID contains cookie name suffix (e.g. CKE-001-SESSIONID)
        cookie_match = re.search(r"^CK[E]?-\d+-([A-Za-z0-9_\-.]+)$", fid, re.IGNORECASE)
        if cookie_match:
            cookie_name = cookie_match.group(1).lower()
            base_rule = fid.rsplit("-", 1)[0].upper()
        else:
            base_rule = fid
            # Extract from title: "Cookie 'sessionid' missing HttpOnly"
            title_match = re.search(r"Cookie\s+['\"]([^'\"]+)['\"]", title, re.IGNORECASE)
            if title_match:
                cookie_name = title_match.group(1).lower()
            else:
                # Extract from evidence: "Set-Cookie: sessionid="
                ev_match = re.search(r"Set-Cookie:\s*([A-Za-z0-9_\-.]+)\s*=", evidence, re.IGNORECASE)
                if ev_match:
                    cookie_name = ev_match.group(1).lower()
                else:
                    if fid == "CKE-003":
                        cookie_name = "http_scheme"
                    else:
                        # Unidentified cookie: use hash of title/evidence/url to avoid merging distinct cookies
                        cookie_name = hashlib.sha256(f"{title}:{evidence}:{raw_url}".encode()).hexdigest()[:8]
        return ("cookies", base_rule, cookie_name)

    # 3. Path / Directory category (preserve resource path, normalize comma-separated URLs)
    if cat == "paths" or fid.startswith("PTH-") or fid.startswith("DIR-"):
        urls = [u.strip() for u in raw_url.split(",") if u.strip()]
        norm_paths = sorted(list({urlparse(u).path.rstrip("/") or "/" for u in urls if u}))
        norm_path = norm_paths[0] if norm_paths else "/"
        return ("paths", fid, norm_path.lower())

    # Fallback for custom plugins
    return (cat or "general", fid, "")


def compare_scans(prev_data: dict, current_findings: list, current_score: int, current_grade: str) -> dict:
    """
    Compare current scan results against a previous results.json file.
    Matches findings using stable identity keys based on category, rule ID, and resource.
    """
    prev_findings = prev_data.get("findings", [])
    prev_map = {_get_comparison_key(f): f for f in prev_findings}
    curr_map = {_get_comparison_key(f): f for f in current_findings}

    prev_keys = set(prev_map.keys())
    curr_keys = set(curr_map.keys())

    fixed_keys = prev_keys - curr_keys
    open_keys = prev_keys & curr_keys
    new_keys = curr_keys - prev_keys

    fixed = [prev_map[k] for k in fixed_keys]
    still_open = [curr_map[k] for k in open_keys]
    new_findings = [curr_map[k] for k in new_keys]

    prev_score = prev_data.get("score", 0)
    prev_grade = prev_data.get("grade", "F")
    score_delta = current_score - prev_score

    return {
        "prev_score": prev_score,
        "prev_grade": prev_grade,
        "score_delta": score_delta,
        "fixed": fixed,
        "still_open": [f.to_dict() if hasattr(f, "to_dict") else f for f in still_open],
        "new": [f.to_dict() if hasattr(f, "to_dict") else f for f in new_findings],
        "counts": {
            "fixed": len(fixed),
            "still_open": len(still_open),
            "new": len(new_findings),
        },
    }


def run_scan(
    target_url: str,
    output_html: Optional[str] = "output/report.html",
    output_json: Optional[str] = "output/results.json",
    compare_path: Optional[str] = None,
    delay: float = 0.3,
    timeout: float = 10.0,
    insecure: bool = False,
    i_have_permission: bool = False,
    progress_callback: Optional[Any] = None,
    verbose: bool = True,
    scan_id: Optional[str] = None,
    cancel_event: Optional[threading.Event] = None,
    scan_mode: str = SCAN_MODE_AUTHORIZED_ASSESSMENT,
) -> dict:
    """
    Execute a full security misconfiguration scan against an authorized target.

    Args:
        target_url: URL to scan (e.g. 'http://localhost:3000')
        output_html: Destination filepath for the HTML report (or None to skip)
        output_json: Destination filepath for the JSON results (or None to skip)
        compare_path: Optional path to an earlier results.json for diff calculation
        delay: Delay in seconds between HTTP requests (default 0.3s)
        timeout: Network request timeout in seconds (default 10.0s)
        insecure: If True, disables SSL certificate verification
        i_have_permission: Must be True to scan non-private IP addresses in authorized mode;
            in passive public mode this confirms explicit user action for a non-intrusive public inspection
        progress_callback: Optional callable(step_message: str, percent: int)
        verbose: If True, prints formatted summary to standard output
        scan_id: Optional identifier assigned by the web application
        cancel_event: Optional threading.Event to cooperatively cancel the scan
        scan_mode: 'passive_public' or 'authorized_assessment'

    Returns:
        Structured scan results dictionary.
    """
    def _is_cancelled() -> bool:
        return bool(cancel_event and cancel_event.is_set())

    scan_mode = (scan_mode or SCAN_MODE_AUTHORIZED_ASSESSMENT).strip().lower()
    if scan_mode not in VALID_SCAN_MODES:
        raise ValueError(f"Invalid scan_mode '{scan_mode}'. Must be one of: {sorted(VALID_SCAN_MODES)}")
    scan_mode_label = SCAN_MODE_LABELS[scan_mode]

    # 1. Normalize and validate URL target (scheme, DNS, SSRF safety)
    target_url = normalize_target_url(str(target_url).strip())
    validation = validate_url_target(target_url, i_have_permission=i_have_permission, scan_mode=scan_mode)
    if not validation.ok:
        raise PermissionError(f"Target refused: {validation.reason}")
    target_url = validation.normalized_url or target_url

    if progress_callback:
        progress_callback("Initializing scan context...", 10)
    if verbose:
        print(f"[*] Initializing scan against target: {target_url}")
        print(f"[*] Scan mode: {scan_mode_label}")

    scan_started_dt = datetime.now(timezone.utc).astimezone()
    scan_start_perf = time.perf_counter()
    status = "completed"
    failure_reason = None

    # 3. Initialize scan context
    ctx = ScanContext(
        base_url=target_url,
        delay=delay,
        timeout=timeout,
        verify_ssl=not insecure,
        i_have_permission=i_have_permission,
        cancel_event=cancel_event,
        scan_mode=scan_mode,
    )

    reachable = False
    tls_observations = {}
    findings = []
    passed_checks = []
    errors = list(getattr(ctx, "errors", []))
    check_results = []
    checks_not_performed = []
    _skip_checks_due_to_tls_init_failure = False
    try:
        reachable = ctx.initialize()
    except ScanCancelled:
        reachable = False
        status = "cancelled"
    except Exception as exc:
        failure_reason = str(exc)

    if _is_cancelled():
        status = "cancelled"

    if status != "cancelled" and (not reachable or ctx.home_response is None):
        # If we failed before collecting any response, attempt TLS observation for HTTPS and
        # return a failed (but reported) scan when the obstacle is TLS/certificate-related so
        # evidence/limitations can be recorded accurately. Otherwise record a genuine failed
        # scan result (no successful scan, no fabricated findings).
        if not _is_cancelled():
            errors_now = list(getattr(ctx, "errors", []))
            detail = errors_now[-1] if errors_now else (failure_reason or "Target did not respond.")

            tls_related = False
            if getattr(ctx, "scheme", "") == "https":
                try:
                    tls_observations = ctx.observe_tls()
                except Exception as exc:
                    tls_observations = {"applicable": True, "status": "error", "error": str(exc)}
                detail_l = str(detail).lower()
                tls_tokens = (
                    "ssl", "tls", "certificate", "cert", "handshake", "hostname",
                    "self signed", "self-signed", "verify failed", "certificate_verify_failed",
                )
                tls_related = any(tok in detail_l for tok in tls_tokens) or bool(tls_observations.get("applicable"))

            if tls_related:
                status = "failed"
                failure_reason = detail
                ctx._record_error(
                    "HTTPS connection could not be established under current TLS/certificate conditions; "
                    "TLS observations were collected separately where possible."
                )
                errors = list(getattr(ctx, "errors", []))
                findings, passed_checks = [], []
                check_results = []
                checks_not_performed = []
                # Mark all required checks as NOT TESTED due to TLS/connection obstacle.
                from core.models import CheckResult
                from core.runner import CHECK_DISPLAY_NAMES, REQUIRED_CHECK_MODULES
                for req in REQUIRED_CHECK_MODULES:
                    cr = CheckResult(
                        name=CHECK_DISPLAY_NAMES.get(req, req),
                        status="NOT TESTED",
                        severity="Info",
                        evidence=detail,
                        affected_url=getattr(ctx, "home_url", "") or getattr(ctx, "base_url", ""),
                        explanation="Check not performed because the HTTPS/TLS connection could not be established for origin observation.",
                        remediation="Review TLS/certificate configuration and trust/hostname settings, then retry with appropriate verification settings for an authorized assessment.",
                        category=req,
                        findings_count=0,
                    )
                    check_results.append(cr.to_dict())
                checks_not_performed = list(check_results)
                try:
                    ctx.check_results = check_results
                    ctx.checks_not_performed = checks_not_performed
                except Exception:
                    pass
                # Skip normal check execution; fall through to scoring/reporting.
                _skip_checks_due_to_tls_init_failure = True
            else:
                status = "failed"
                failure_reason = detail
                findings, passed_checks = [], []
                check_results = []
                checks_not_performed = []
                try:
                    from core.models import CheckResult
                    from core.runner import CHECK_DISPLAY_NAMES, REQUIRED_CHECK_MODULES
                    for req in REQUIRED_CHECK_MODULES:
                        cr = CheckResult(
                            name=CHECK_DISPLAY_NAMES.get(req, req),
                            status="NOT TESTED",
                            severity="Info",
                            evidence=detail,
                            affected_url=getattr(ctx, "home_url", "") or getattr(ctx, "base_url", ""),
                            explanation="Check not performed because the target could not be reached or no genuine HTTP(S) response was obtained.",
                            remediation="Verify DNS resolution, network reachability, port/service availability, and timeouts, then rerun the scan.",
                            category=req,
                            findings_count=0,
                        )
                        check_results.append(cr.to_dict())
                    checks_not_performed = list(check_results)
                    ctx.check_results = check_results
                    ctx.checks_not_performed = checks_not_performed
                    ctx.connection_outcome = getattr(ctx, "connection_outcome", "failed") or "failed"
                    ctx.http_outcome = getattr(ctx, "http_outcome", "no_response") or "no_response"
                    if "Failed to resolve hostname" in detail or "Target validation failed" in detail or "gaierror" in detail.lower():
                        ctx.dns_outcome = "failed"
                except Exception:
                    pass
                errors = list(getattr(ctx, "errors", [])) or [detail]
                _skip_checks_due_to_tls_init_failure = True
        else:
            _skip_checks_due_to_tls_init_failure = False
    else:
        _skip_checks_due_to_tls_init_failure = False

    # Genuine response received but origin not observable (e.g. 429 rate limit/challenge):
    # record as failed/incomplete assessment, never as a successful clean scan.
    if status == "completed" and not _is_cancelled() and not _skip_checks_due_to_tls_init_failure and getattr(ctx, "home_unobservable", False):
        status = "failed"
        failure_reason = getattr(ctx, "home_unobservable_reason", "") or failure_reason or "Origin response was not observable."
        try:
            if not getattr(ctx, "http_outcome", "") or getattr(ctx, "http_outcome", "") in ("not_attempted", "unknown"):
                hr = getattr(ctx, "home_response", None)
                if hr is not None:
                    ctx.http_outcome = f"http_{getattr(hr, 'status_code', 'unknown')}"
        except Exception:
            pass

    if status == "cancelled":
        if verbose:
            print("[!] Scan cancelled during initialization.")
        if progress_callback:
            progress_callback("Scan cancelled.", 100)
    elif not _skip_checks_due_to_tls_init_failure:
        if verbose and ctx.home_response is not None:
            print(f"[*] Target responded (HTTP {ctx.home_response.status_code}). Running checks...")
        if progress_callback:
            progress_callback("Collecting observable responses and running checks...", 30)

    # 4. Run all registered security checks
    if _skip_checks_due_to_tls_init_failure:
        # findings/passed_checks/errors/check_results prepared above
        errors = list(getattr(ctx, "errors", [])) or errors
    else:
        findings, passed_checks, errors = ([], [], list(getattr(ctx, "errors", [])))
        if status != "cancelled":
            try:
                findings, passed_checks, errors = run_all(ctx)
            except ScanCancelled:
                status = "cancelled"
            except Exception as exc:
                # Unexpected runner failure: preserve any collected diagnostics and fail clearly.
                errors = list(dict.fromkeys(list(getattr(ctx, "errors", [])) + list(errors) + [f"Scan execution error: {exc}"]))
                failure_reason = str(exc)
                status = "failed"
        # Authoritative structured results from runner
        check_results = list(getattr(ctx, "check_results", []) or [])
        checks_not_performed = list(getattr(ctx, "checks_not_performed", []) or [cr for cr in check_results if str(cr.get("status", "")).upper() == "NOT TESTED"])

    # 4b. TLS certificate observation (non-intrusive) for HTTPS targets
    if not tls_observations:
        if progress_callback and status != "cancelled":
            progress_callback("Collecting TLS/certificate observations (if applicable)...", 55)
        try:
            tls_observations = ctx.observe_tls()
        except Exception as exc:
            tls_observations = {"applicable": (ctx.scheme == "https"), "status": "error", "error": str(exc)}
            try:
                ctx._record_error(f"TLS observation failed: {exc}")
            except Exception:
                pass
            errors = list(dict.fromkeys(list(errors) + [f"TLS observation failed: {exc}"]))
    else:
        # Keep any TLS-derived diagnostics in errors/limitations
        errors = list(dict.fromkeys(list(errors) + list(getattr(ctx, "errors", []))))

    # Surface TLS observation limitations in scan limitations for transparency.
    try:
        tls_lims = list((tls_observations or {}).get("limitations") or [])
        if tls_lims:
            existing = list(getattr(ctx, "scan_limitations", []) or [])
            for lim in tls_lims:
                if lim and lim not in existing:
                    existing.append(lim)
            ctx.scan_limitations = existing
    except Exception:
        pass

    if _is_cancelled():
        status = "cancelled"

    if progress_callback and status != "cancelled":
        progress_callback("Calculating security score and grade...", 70)

    # Ensure we have latest structured check results from context when available
    if not check_results:
        check_results = list(getattr(ctx, "check_results", []) or [])
    if not checks_not_performed:
        checks_not_performed = list(getattr(ctx, "checks_not_performed", []) or [cr for cr in check_results if str(cr.get("status", "")).upper() == "NOT TESTED"])

    # 5. Calculate score and letter grade (genuine tested results only)
    score, grade = score_and_grade(findings)
    # Failed/incomplete scans must not be presented as successful/clean results.
    if status in ("failed", "cancelled") or (status == "completed" and len(check_results) > 0 and all(
        str(cr.get("status", "")).upper() == "NOT TESTED" for cr in check_results
    ) and not findings):
        if status == "failed":
            grade = "N/A"
            score = 0
        elif status == "cancelled":
            # Partial genuine evidence may exist; keep computed score but UI/report must label cancelled/incomplete.
            pass
        elif status == "completed":
            grade = "N/A"
            score = 0

    # 6. Count findings by severity (consistent with findings list)
    counts = {
        "Critical": sum(1 for f in findings if str(getattr(f, "severity", "")).upper() == "CRITICAL"),
        "High": sum(1 for f in findings if str(getattr(f, "severity", "")).upper() == "HIGH"),
        "Medium": sum(1 for f in findings if str(getattr(f, "severity", "")).upper() == "MEDIUM"),
        "Low": sum(1 for f in findings if str(getattr(f, "severity", "")).upper() == "LOW"),
        "Info": sum(1 for f in findings if str(getattr(f, "severity", "")).upper() == "INFO"),
    }

    # 7. Print Terminal Summary
    if verbose:
        print("\n" + "=" * 70)
        print(" SCAN RESULTS SUMMARY")
        print("=" * 70)
        print(f" Target:       {target_url}")
        print(f" Status:       {status.upper()}")
        print(f" Grade:        {grade}")
        print(f" Score:        {score} / 100")
        print(
            f" Findings:     {len(findings)} total "
            f"(Critical: {counts['Critical']}, High: {counts['High']}, "
            f"Medium: {counts['Medium']}, Low: {counts['Low']}, Info: {counts['Info']})"
        )
        print(f" Requests:     {getattr(ctx, 'request_count', 0)} (Limit: {getattr(ctx, 'max_requests', 'n/a')})")
        print("=" * 70)

        if findings:
            print("\nDETECTED MISCONFIGURATIONS:")
            print("-" * 70)
            severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_display = sorted(findings, key=lambda f: severity_rank.get(str(getattr(f, "severity", "Info")).upper(), 99))
            for f in sorted_display:
                print(f"[{f.severity.upper()}] [{f.confidence}] {f.title}")
                print(f"  Category:  {f.category}")
                print(f"  Evidence:  {f.evidence}")
                if f.url:
                    print(f"  Endpoint:  {f.url}")
                print(f"  Fix:       {f.fix}")
                print("-" * 70)
        elif status == "completed":
            print("\n[+] No misconfigurations detected based on checks performed.")

        if passed_checks:
            print(f"\n[+] Passed Checks ({len(passed_checks)}):")
            for pc in passed_checks:
                print(f"    - {pc}")

    # 8. Handle --compare if specified
    comparison_results = None
    if compare_path and status == "completed":
        if os.path.exists(compare_path):
            try:
                with open(compare_path, "r", encoding="utf-8") as pf:
                    prev_json_data = json.load(pf)
                comparison_results = compare_scans(prev_json_data, findings, score, grade)

                if verbose:
                    print("\n" + "=" * 70)
                    print(" RE-SCAN COMPARISON (Changes since last scan)")
                    print("=" * 70)
                    delta_sign = "+" if comparison_results["score_delta"] >= 0 else ""
                    print(
                        f" Score Change:  {comparison_results['prev_score']} -> {score} "
                        f"({delta_sign}{comparison_results['score_delta']} pts)"
                    )
                    print(f" Grade Change:  {comparison_results['prev_grade']} -> {grade}")
                    print(
                        f" Summary:       Fixed: {comparison_results['counts']['fixed']}, "
                        f"Still open: {comparison_results['counts']['still_open']}, "
                        f"New: {comparison_results['counts']['new']}"
                    )

                    if comparison_results["fixed"]:
                        print("\n Fixed Findings:")
                        for fx in comparison_results["fixed"]:
                            print(f"   [FIXED] {fx['title']} ({fx['id']})")

                    if comparison_results["new"]:
                        print("\n New Findings:")
                        for nf in comparison_results["new"]:
                            print(f"   [NEW]   {nf['title']} ({nf['id']})")

                    print("=" * 70)

            except Exception as exc:
                if verbose:
                    print(f"[!] Warning: Failed to process comparison file '{compare_path}': {exc}")
                errors = list(dict.fromkeys(list(errors) + [f"Comparison failed for '{compare_path}': {exc}"]))
        else:
            if verbose:
                print(f"[!] Warning: Comparison file '{compare_path}' not found. Skipping comparison.")
            errors = list(dict.fromkeys(list(errors) + [f"Comparison file not found: {compare_path}"]))

    # 9. Record completion timing and target IP
    scan_completed_dt = datetime.now(timezone.utc).astimezone()
    duration_seconds = round(time.perf_counter() - scan_start_perf, 2)
    target_ip = None
    try:
        if getattr(ctx, "resolved_ips", None):
            target_ip = ctx.resolved_ips[0]
    except Exception:
        target_ip = None
    if not target_ip:
        target_ip = resolve_target_ip(target_url)
    scan_time = datetime.now().strftime("%b %d, %Y %H:%M:%S")

    # Structured per-check results and limitations (attached by runner/context)
    check_results = list(getattr(ctx, "check_results", []) or [])
    checks_not_performed = list(getattr(ctx, "checks_not_performed", []) or [cr for cr in check_results if str(cr.get("status", "")).upper() == "NOT TESTED"])
    scan_limitations = list(getattr(ctx, "scan_limitations", []) or [])
    # Include TLS observation limitations for transparency
    for lim in ((tls_observations or {}).get("limitations") or []):
        if lim and lim not in scan_limitations:
            scan_limitations.append(lim)
    # Ensure all runtime errors are reflected as limitations/diagnostics for transparency
    for e in (errors or []):
        if e and e not in scan_limitations:
            scan_limitations.append(e)
    if status == "cancelled" and "Scan was cancelled by user; results may be incomplete." not in scan_limitations:
        scan_limitations.append("Scan was cancelled by user; results may be incomplete.")
    scan_limitations = list(dict.fromkeys([s for s in scan_limitations if str(s).strip()]))
    errors = list(dict.fromkeys([e for e in errors if str(e).strip()]))

    if verbose and errors:
        print(f"\n[!] Notice: {len(errors)} diagnostic message(s) recorded during scan.")

    # 10. Assemble structured JSON data
    home_resp = getattr(ctx, "home_response", None)
    dns_outcome = "resolved" if (getattr(ctx, "resolved_ips", None) or target_ip) else getattr(ctx, "dns_outcome", "unknown")
    if getattr(ctx, "dns_outcome", None):
        # Prefer explicit context outcome (e.g. failed/blocked/nxdomain-aware)
        ctx_dns = getattr(ctx, "dns_outcome")
        if ctx_dns:
            dns_outcome = ctx_dns
    if getattr(ctx, "errors", None):
        # If validation/dns failed early, context may record it
        for e in getattr(ctx, "errors", []):
            if "Failed to resolve hostname" in str(e) or "Target validation failed" in str(e):
                if dns_outcome in ("unknown", "resolved"):
                    dns_outcome = "failed"
                break
    connection_outcome = getattr(ctx, "connection_outcome", "unknown")
    http_outcome = getattr(ctx, "http_outcome", "unknown")
    if home_resp is not None:
        if connection_outcome in ("not_attempted", "unknown", "attempted"):
            connection_outcome = "connected"
        http_outcome = f"http_{getattr(home_resp, 'status_code', 'unknown')}"
    elif status == "failed" and connection_outcome in ("not_attempted", "unknown"):
        connection_outcome = "failed"

    dns_verification = getattr(ctx, "dns_verification", {}) or {}

    results_data = {
        "scanner_version": "1.0.0",
        "scan_id": scan_id,
        "scan_mode": scan_mode,
        "scan_mode_label": scan_mode_label,
        "authorization_confirmed": bool(i_have_permission),
        "target": target_url,
        "target_ip": target_ip,
        "resolved_ips": list(getattr(ctx, "resolved_ips", []) or []),
        "dns_outcome": dns_outcome,
        "dns_verification": dns_verification,
        "connection_outcome": connection_outcome,
        "http_outcome": http_outcome,
        "tls_observations": tls_observations or getattr(ctx, "tls_observations", {}),
        "waf_indicators": list(getattr(ctx, "waf_indicators", []) or []),
        "rate_limit_events": list(getattr(ctx, "rate_limit_events", []) or []),
        "scan_started_at": scan_started_dt.isoformat(),
        "scan_completed_at": scan_completed_dt.isoformat(),
        "duration_seconds": duration_seconds,
        "scan_time": scan_time,
        "status": status,
        "grade": grade,
        "score": score,
        "counts": counts,
        "findings": [f.to_dict() for f in findings],
        "passed_checks": passed_checks,
        "errors": errors,
        "check_results": check_results,
        "checks_not_performed": checks_not_performed,
        "scan_limitations": scan_limitations,
    }
    if comparison_results:
        results_data["comparison"] = comparison_results
    if failure_reason and status == "failed":
        results_data["failure_reason"] = failure_reason

    # 11. Write JSON results if destination path provided
    if output_json:
        json_path = os.path.abspath(output_json)
        json_dir = os.path.dirname(json_path)
        if json_dir:
            os.makedirs(json_dir, exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(results_data, jf, indent=2)
        if verbose:
            print(f"\n[+] JSON results saved to: {json_path}")

    # 12. Write HTML Report if destination path provided
    if output_html:
        if HAS_REPORTER:
            html_path = os.path.abspath(output_html)
            try:
                generate_report(
                    target_url=target_url,
                    findings=[f.to_dict() for f in findings],
                    grade=grade,
                    score=score,
                    output_path=html_path,
                    passed_checks=passed_checks,
                    comparison=comparison_results,
                    metadata={
                        "scan_id": scan_id,
                        "scanner_version": results_data["scanner_version"],
                        "target_ip": target_ip,
                        "scan_started_at": results_data["scan_started_at"],
                        "scan_completed_at": results_data["scan_completed_at"],
                        "duration_seconds": duration_seconds,
                        "scan_time": scan_time,
                        "status": status,
                        "scan_mode": scan_mode,
                        "scan_mode_label": scan_mode_label,
                        "dns_outcome": dns_outcome,
                        "connection_outcome": connection_outcome,
                        "http_outcome": http_outcome,
                    },
                    check_results=check_results,
                    checks_not_performed=checks_not_performed,
                    scan_limitations=scan_limitations,
                    observations={
                        "tls_observations": tls_observations or getattr(ctx, "tls_observations", {}),
                        "waf_indicators": list(getattr(ctx, "waf_indicators", []) or []),
                        "rate_limit_events": list(getattr(ctx, "rate_limit_events", []) or []),
                    },
                )
                if verbose:
                    print(f"[+] HTML report saved to:  {html_path}")
            except Exception as exc:
                if verbose:
                    print(f"[!] Warning: Failed to generate HTML report: {exc}")
                errors = list(dict.fromkeys(list(errors) + [f"HTML report generation failed: {exc}"]))
        else:
            if verbose:
                print("[!] Warning: reports/html_report.py module not found. Skipping HTML report generation.")

    if progress_callback:
        if status == "cancelled":
            progress_callback("Scan cancelled.", 100)
        elif status == "failed":
            progress_callback("Scan failed.", 100)
        else:
            progress_callback("Scan completed successfully.", 100)

    # Return genuine failed/incomplete scan results (persisted above) so callers/UI/reporting
    # can label them accurately without fabricating a successful scan.
    return results_data


def main():
    parser = argparse.ArgumentParser(
        description="Automated Security Misconfiguration Detector - Authorized Security Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", help="Target URL to scan (e.g. http://localhost:3000)")
    parser.add_argument("--out", default="output/report.html", help="Filepath for output HTML report")
    parser.add_argument("--json", default="output/results.json", help="Filepath for output JSON results")
    parser.add_argument("--compare", help="Path to previous results.json to calculate diff/changes")
    parser.add_argument("--delay", type=float, default=0.3, help="Polite delay in seconds between HTTP requests")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument(
        "--i-have-permission",
        dest="i_have_permission",
        action="store_true",
        help="Acknowledge authorization/confirmation to scan targets (required for public targets in authorized mode; explicit confirmation for passive public inspection)",
    )
    parser.add_argument(
        "--scan-mode",
        dest="scan_mode",
        choices=[SCAN_MODE_PASSIVE_PUBLIC, SCAN_MODE_AUTHORIZED_ASSESSMENT],
        default=SCAN_MODE_AUTHORIZED_ASSESSMENT,
        help="Scan mode: passive_public (minimal, non-intrusive, publicly observable checks only) or authorized_assessment (existing safe checks for explicitly authorized targets)",
    )

    args = parser.parse_args()

    # Rule 1: Always print testing authorization banner
    print("[!] Authorized testing only\n")

    try:
        result = run_scan(
            target_url=args.url,
            output_html=args.out,
            output_json=args.json,
            compare_path=args.compare,
            delay=args.delay,
            timeout=args.timeout,
            insecure=args.insecure,
            i_have_permission=args.i_have_permission,
            scan_mode=args.scan_mode,
            verbose=True,
        )
        status = (result or {}).get("status")
        if status == "failed":
            sys.exit(2)
        if status == "cancelled":
            sys.exit(3)
    except PermissionError as exc:
        print(f"[!] Permission Error: {exc}")
        sys.exit(1)
    except ConnectionError as exc:
        print(f"[!] Connection Error: {exc}")
        sys.exit(2)
    except Exception as exc:
        print(f"[!] Scan execution failed: {exc}")
        sys.exit(3)


if __name__ == "__main__":
    main()
