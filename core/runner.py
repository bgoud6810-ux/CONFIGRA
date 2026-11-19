"""
core/runner.py - Check orchestrator, result synthesis, and finding de-duplicator

Executes all discovered check modules inside isolated try/except blocks,
merges evidence and URLs for duplicate findings, compiles passed checks, and
builds backward-compatible structured per-check results.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from checks import get_all_checks
from core.context import ScanContext
from core.models import CheckResult, Finding, SCAN_MODE_PASSIVE_PUBLIC


CHECK_DISPLAY_NAMES = {
    "headers": "Security HTTP response headers",
    "cookies": "Cookie security attributes",
    "cors": "Cross-origin resource sharing (CORS) configuration",
    "methods": "HTTP methods configuration",
    "info_leaks": "Information disclosure and diagnostic leakage",
    "paths": "Sensitive paths and directory exposure",
}

REQUIRED_CHECK_MODULES = ["headers", "cookies", "cors", "methods", "info_leaks", "paths"]

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Active-probe / intrusive checks excluded from Passive Public Inspection
PASSIVE_EXCLUDED_MODULES = {"cors", "methods", "paths"}


def _module_short_name(mod: Any) -> str:
    name = getattr(mod, "__name__", str(mod))
    return name.rsplit(".", 1)[-1]


def _top_finding_severity(findings: List[Finding]) -> str:
    if not findings:
        return "Info"
    top = max(findings, key=lambda f: SEV_RANK.get(str(getattr(f, "severity", "Info")).upper(), 0))
    return getattr(top, "severity", "Info")


def _first_nonempty_url(findings: List[Finding]) -> str:
    for f in findings:
        url = str(getattr(f, "url", "") or "").strip()
        if url:
            return url
    return ""


def _summarize_evidence(findings: List[Finding], passed_checks: List[str]) -> str:
    if findings:
        parts = []
        for f in findings[:3]:
            sev = getattr(f, "severity", "Info")
            title = getattr(f, "title", "Finding")
            ev = str(getattr(f, "evidence", "") or "").strip()
            if ev:
                parts.append(f"[{sev}] {title}: {ev}")
            else:
                parts.append(f"[{sev}] {title}")
        if len(findings) > 3:
            parts.append(f"(+{len(findings) - 3} more finding(s))")
        return " | ".join(parts)[:1000]
    if passed_checks:
        sample = "; ".join(passed_checks[:3])
        if len(passed_checks) > 3:
            sample += f"; (+{len(passed_checks) - 3} more)"
        return sample[:1000]
    return ""


def _not_tested_reason(ctx: ScanContext, new_errors: List[str]) -> Tuple[str, str, str]:
    """Return (explanation, evidence, remediation) for NOT TESTED checks."""
    cancelled = bool(getattr(ctx, "cancelled", False))
    stop_reason = str(getattr(ctx, "stop_requests_reason", "") or "")
    rate_limit_events = getattr(ctx, "rate_limit_events", []) or []
    waf_indicators = getattr(ctx, "waf_indicators", []) or []
    tls_obs = getattr(ctx, "tls_observations", {}) or {}

    if cancelled:
        return (
            "Scan was cancelled before this check could complete.",
            "Scan cancellation requested by user.",
            "Rerun the scan to completion if a full result set is required.",
        )

    if stop_reason == "http_429_rate_limited" or rate_limit_events:
        ev = rate_limit_events[0] if rate_limit_events else {}
        url = ev.get("url", getattr(ctx, "home_url", "") or getattr(ctx, "base_url", ""))
        ra = ev.get("retry_after", {}) if isinstance(ev, dict) else {}
        parts = [f"HTTP 429 rate-limited response observed for {url}."]
        if isinstance(ra, dict):
            if ra.get("seconds") is not None:
                parts.append(f"Retry-After: ~{ra.get('seconds')}s.")
            elif ra.get("raw"):
                parts.append(f"Retry-After: {ra.get('raw')}.")
        hdrs = ev.get("headers", {}) if isinstance(ev, dict) else {}
        if hdrs:
            parts.append("Rate-limit headers: " + ", ".join(f"{k}={v}" for k, v in list(hdrs.items())[:4]))
        parts.append("Further requests were stopped conservatively (no retries, no bypass).")
        return (
            "Check could not be fully performed because the target returned HTTP 429 (rate limited).",
            " ".join(parts)[:1000],
            "Respect Retry-After guidance, reduce scan frequency, and rerun later with explicit authorization if needed.",
        )

    # Intermediary/WAF challenge likely blocked meaningful observation
    if waf_indicators:
        wi = waf_indicators[0] if isinstance(waf_indicators[0], dict) else {}
        prov = wi.get("provider", "intermediary")
        conf = wi.get("confidence", "suspected")
        inds = ", ".join((wi.get("indicators") or [])[:3])
        status = wi.get("status")
        if status in (403, 503) or "challenge" in inds.lower() or "captcha" in inds.lower():
            return (
                f"Check could not be fully performed because a {conf} {prov} intermediary/challenge response was observed.",
                f"HTTP {status} with indicators: {inds}. Origin security posture may not be fully observable through this response."[:1000],
                "Perform testing from an authorized vantage point or coordinate with the target owner/CDN operator; do not bypass defenses.",
            )

    # TLS observation failures may prevent HTTPS checks
    if tls_obs and str(tls_obs.get("status", "")) == "error":
        terr = str(tls_obs.get("error") or tls_obs.get("verification_error") or "TLS observation failed")
        return (
            "Check could not be fully performed due to a TLS/certificate observation or connection issue.",
            terr[:1000],
            "Verify the target's TLS configuration and certificate validity, then rerun. Do not disable verification except in controlled lab testing.",
        )

    if new_errors:
        detail = "; ".join(new_errors[:2])
        explanation = "Check could not be fully performed due to request/connectivity/budget constraints or an intermediary response."
        remediation = "Ensure the target is reachable, respect rate limits, allow sufficient request budget/timeouts, and rerun the scan."
        return (explanation, detail[:1000], remediation)

    return (
        "Check could not be fully performed.",
        "No specific diagnostic evidence collected.",
        "Review scan limitations and rerun the scan if needed.",
    )


def _build_check_result(
    mod_short: str,
    findings: List[Finding],
    passed_checks: List[str],
    new_errors: List[str],
    ctx: ScanContext,
    execution_exception: str = "",
) -> CheckResult:
    name = CHECK_DISPLAY_NAMES.get(mod_short, f"Security check module: {mod_short}")
    affected_url = _first_nonempty_url(findings) or getattr(ctx, "home_url", "") or getattr(ctx, "base_url", "")
    category = mod_short

    if execution_exception:
        status = "NOT TESTED"
        severity = "Info"
        explanation = f"Check did not complete due to an internal execution error: {execution_exception}"
        evidence = execution_exception
        remediation = "Review scan limitations and rerun the scan. If the issue persists, inspect server logs and scanner diagnostics."
        return CheckResult(name=name, status=status, severity=severity, evidence=evidence[:1000], affected_url=affected_url, explanation=explanation, remediation=remediation, category=category, findings_count=0)

    if findings:
        status = "FAIL"
        severity = _top_finding_severity(findings)
        explanation = f"Detected {len(findings)} evidenced security misconfiguration finding(s) in this check area."
        remediation = "Apply the remediation guidance for each listed finding, prioritizing higher-severity issues."
        evidence = _summarize_evidence(findings, passed_checks)
        return CheckResult(name=name, status=status, severity=severity, evidence=evidence, affected_url=affected_url, explanation=explanation, remediation=remediation, category=category, findings_count=len(findings))

    if passed_checks:
        status = "PASS"
        severity = "Info"
        explanation = "Checks in this area executed and no evidenced misconfigurations were identified."
        remediation = "No remediation required based on the checks performed in this scan."
        evidence = _summarize_evidence(findings, passed_checks)
        return CheckResult(name=name, status=status, severity=severity, evidence=evidence, affected_url=affected_url, explanation=explanation, remediation=remediation, category=category, findings_count=0)

    # No findings and no explicit passed checks
    cancelled = bool(getattr(ctx, "cancelled", False))
    if cancelled or new_errors or getattr(ctx, "stop_requests_reason", "") or getattr(ctx, "rate_limit_events", []):
        status = "NOT TESTED"
        severity = "Info"
        explanation, evidence, remediation = _not_tested_reason(ctx, new_errors)
        return CheckResult(name=name, status=status, severity=severity, evidence=evidence[:1000], affected_url=affected_url, explanation=explanation, remediation=remediation, category=category, findings_count=0)

    status = "WARNING"
    severity = "Info"
    explanation = "Check executed but did not produce explicit pass/fail observations for this target state."
    evidence = "No specific evidence collected for this check area."
    remediation = "Review target responses and scan limitations; consider a manual verification if this control is relevant."
    return CheckResult(name=name, status=status, severity=severity, evidence=evidence, affected_url=affected_url, explanation=explanation, remediation=remediation, category=category, findings_count=0)


def run_all(ctx: ScanContext) -> Tuple[List[Finding], List[str], List[str]]:
    """
    Execute all registered plug-in check modules against the target context.

    Returns:
        (deduplicated_findings, passed_checks, errors)

    Backward-compatible tuple return. Structured per-check results and scan
    limitations are also attached to `ctx` for downstream reporting.
    """
    raw_findings: List[Finding] = []
    raw_passed_checks: List[str] = []
    errors: List[str] = list(getattr(ctx, "errors", []))
    check_results: List[Dict[str, Any]] = []

    check_modules = get_all_checks()
    executed_module_names = {_module_short_name(m) for m in check_modules}
    is_passive = getattr(ctx, "scan_mode", "") == SCAN_MODE_PASSIVE_PUBLIC
    home_unobservable = bool(getattr(ctx, "home_unobservable", False))
    home_unobservable_reason = str(getattr(ctx, "home_unobservable_reason", "") or "Origin response was not observable.")

    # Add NOT TESTED entries for required checks that are missing/unavailable
    for req in REQUIRED_CHECK_MODULES:
        if req not in executed_module_names:
            cr = CheckResult(
                name=CHECK_DISPLAY_NAMES.get(req, req),
                status="NOT TESTED",
                severity="Info",
                evidence="Required check module was not discovered or could not be loaded.",
                affected_url=getattr(ctx, "home_url", "") or getattr(ctx, "base_url", ""),
                explanation="This required security check was unavailable during the scan.",
                remediation="Verify the scanner installation includes all check modules and rerun the scan.",
                category=req,
                findings_count=0,
            )
            check_results.append(cr.to_dict())

    # If the target origin is not observable (e.g. 429/challenge), do not analyze
    # intermediary pages as origin misconfigurations.
    if home_unobservable:
        for req in REQUIRED_CHECK_MODULES:
            if req not in executed_module_names:
                continue
            cr = CheckResult(
                name=CHECK_DISPLAY_NAMES.get(req, req),
                status="NOT TESTED",
                severity="Info",
                evidence=home_unobservable_reason,
                affected_url=getattr(ctx, "home_url", "") or getattr(ctx, "base_url", ""),
                explanation="Check not performed because the origin response could not be observed (rate limit or intermediary challenge).",
                remediation="Respect rate limits/Retry-After guidance and retry later with authorization if appropriate, or test from an authorized vantage point without bypassing defenses.",
                category=req,
                findings_count=0,
            )
            check_results.append(cr.to_dict())

        scan_limitations = list(dict.fromkeys([str(e) for e in errors if str(e).strip()] + [home_unobservable_reason]))
        checks_not_performed = [cr for cr in check_results if str(cr.get("status", "")).upper() == "NOT TESTED"]
        unique_errors = list(dict.fromkeys([str(e) for e in errors if str(e).strip()]))
        try:
            ctx.check_results = check_results
            ctx.checks_not_performed = checks_not_performed
            ctx.scan_limitations = scan_limitations
            ctx.errors = unique_errors
        except Exception:
            pass
        return [], [], unique_errors

    for check_mod in check_modules:
        mod_name = getattr(check_mod, "__name__", str(check_mod))
        mod_short = _module_short_name(check_mod)
        before_err_count = len(getattr(ctx, "errors", []))
        mod_findings: List[Finding] = []
        mod_passed: List[str] = []
        exec_exception = ""

        # Passive Public Inspection: exclude active probing and sensitive-path enumeration
        if is_passive and mod_short in PASSIVE_EXCLUDED_MODULES:
            cr = CheckResult(
                name=CHECK_DISPLAY_NAMES.get(mod_short, f"Security check module: {mod_short}"),
                status="NOT TESTED",
                severity="Info",
                evidence=(
                    "Excluded in Passive Public Inspection mode. This check may involve active probing "
                    "(e.g. CORS/method probes) or sensitive-path enumeration and was not executed."
                ),
                affected_url=getattr(ctx, "home_url", "") or getattr(ctx, "base_url", ""),
                explanation="Not performed in Passive Public Inspection to keep the scan minimal and non-intrusive.",
                remediation=(
                    "Run an Authorized Security Configuration Assessment on an explicitly authorized target "
                    "if this check area must be evaluated."
                ),
                category=mod_short,
                findings_count=0,
            )
            check_results.append(cr.to_dict())
            continue

        try:
            findings, passed = check_mod.run(ctx)
            mod_findings = list(findings or [])
            mod_passed = list(passed or [])
            raw_findings.extend(mod_findings)
            raw_passed_checks.extend(mod_passed)
        except Exception as exc:
            exec_exception = str(exc)
            err_msg = f"Check '{mod_name}' encountered an error: {exc}"
            errors.append(err_msg)
            try:
                ctx.errors.append(err_msg)
            except Exception:
                pass
            print(f"[!] Warning: {err_msg}")

        after_errors = list(getattr(ctx, "errors", []))
        # Capture only new errors likely related to this module run (best-effort)
        new_errors = after_errors[before_err_count:] if len(after_errors) >= before_err_count else []
        if exec_exception and err_msg not in new_errors:
            new_errors = [err_msg] + new_errors

        cr = _build_check_result(mod_short, mod_findings, mod_passed, new_errors, ctx, execution_exception=exec_exception)
        check_results.append(cr.to_dict())

    # De-duplicate findings by unique ID (preserve existing behavior)
    deduped_map = {}
    for finding in raw_findings:
        fid = finding.id
        if fid not in deduped_map:
            deduped_map[fid] = finding
        else:
            existing = deduped_map[fid]
            # Merge evidence if different
            if finding.evidence and finding.evidence not in existing.evidence:
                merged_ev = f"{existing.evidence}; {finding.evidence}"
                existing.evidence = merged_ev[:300]
            # Merge URLs
            if finding.url and finding.url not in existing.url:
                existing.url = f"{existing.url}, {finding.url}" if existing.url else finding.url

    unique_passed = list(dict.fromkeys(raw_passed_checks))
    # Keep errors unique but preserve order
    unique_errors = list(dict.fromkeys([e for e in errors if str(e).strip()]))

    # Derive scan limitations and checks-not-performed for downstream consumers
    scan_limitations: List[str] = []
    if is_passive:
        scan_limitations.append(
            "Passive Public Inspection mode: minimal, non-intrusive, publicly observable checks only. "
            "Active probing (CORS/method probes), sensitive-path enumeration, and exhaustive crawling were not performed."
        )
        scan_limitations.append("Passive Public Inspection is not a complete security audit.")
    for e in unique_errors:
        scan_limitations.append(str(e))
    if getattr(ctx, "cancelled", False):
        scan_limitations.append("Scan was cancelled by user; results may be incomplete.")
    if getattr(ctx, "request_count", 0) >= getattr(ctx, "max_requests", 10**9):
        scan_limitations.append(f"Request budget limit reached ({getattr(ctx, 'max_requests', 0)} requests); some checks may be incomplete.")
    if getattr(ctx, "stop_requests_reason", "") == "http_429_rate_limited":
        scan_limitations.append(
            "HTTP 429 rate-limited response encountered; further requests were stopped conservatively (no retries/bypass). "
            "Some checks may be NOT TESTED."
        )
    waf_indicators = getattr(ctx, "waf_indicators", []) or []
    if waf_indicators:
        wi = waf_indicators[0] if isinstance(waf_indicators[0], dict) else {}
        prov = wi.get("provider", "intermediary")
        conf = wi.get("confidence", "suspected")
        scan_limitations.append(
            f"{conf.capitalize()} {prov} CDN/WAF/challenge response indicators observed; "
            "origin behavior may not be fully observable and affected checks may be NOT TESTED."
        )
    tls_obs = getattr(ctx, "tls_observations", {}) or {}
    if tls_obs.get("applicable") and not getattr(ctx, "verify_ssl", True):
        scan_limitations.append("TLS certificate verification was disabled for this scan; certificate validation results are not authoritative.")
    scan_limitations = list(dict.fromkeys([s for s in scan_limitations if str(s).strip()]))

    checks_not_performed = [cr for cr in check_results if cr.get("status") == "NOT TESTED"]

    # Attach structured data for scanner/report layers (additive/backward-compatible)
    try:
        ctx.check_results = check_results
        ctx.scan_limitations = scan_limitations
        ctx.checks_not_performed = checks_not_performed
        ctx.errors = unique_errors
    except Exception:
        pass

    return list(deduped_map.values()), unique_passed, unique_errors
