"""
reports/html_report.py - HTML Report Generator for Security Misconfigurations

Generates a standalone, self-contained HTML report with a cyber theme.
Works completely offline without external CDNs, scripts, or fonts.
"""

import os
from datetime import datetime
from typing import List, Dict, Any, Union, Optional
import jinja2

# Severity order for sorting findings (Critical highest, down to Info)
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

CATEGORY_IMPACTS = {
    "headers": "Missing or weak response headers reduce browser-side protections for the affected pages.",
    "cookies": "Insecure cookie attributes can expose session data or increase cross-site request risks.",
    "cors": "An overly permissive cross-origin policy can allow untrusted sites to read responses.",
    "methods": "Unexpectedly available HTTP methods can expose unintended server capabilities.",
    "paths": "Exposed files or directory listings can disclose sensitive application or configuration data.",
    "info_leaks": "Disclosed implementation or diagnostic details can help target the application.",
    "general": "The observed misconfiguration may weaken security controls for the affected component.",
}


def _normalize_finding(item: Any) -> Dict[str, Any]:
    """
    Ensure each finding is a dictionary with standardized field names, confidence, and URL.
    Accepts a dictionary or a Finding dataclass instance, handling None/missing fields gracefully.
    """
    if hasattr(item, "to_dict") and callable(item.to_dict):
        d = item.to_dict()
    elif isinstance(item, dict):
        d = dict(item)
    else:
        d = {
            "id": getattr(item, "id", "MISC-000"),
            "title": getattr(item, "title", "Misconfiguration Finding"),
            "category": getattr(item, "category", "general"),
            "severity": getattr(item, "severity", "Info"),
            "evidence": getattr(item, "evidence", "N/A"),
            "fix": getattr(item, "fix", "N/A"),
            "confidence": getattr(item, "confidence", "Confirmed"),
            "url": getattr(item, "url", ""),
            "description": getattr(item, "description", ""),
            "impact": getattr(item, "impact", ""),
        }

    # Ensure required string fields exist and handle None
    fid = d.get("id")
    d["id"] = "MISC-000" if fid is None or str(fid).strip() == "" else str(fid).strip()

    title = d.get("title")
    d["title"] = "Misconfiguration Finding" if title is None or str(title).strip() == "" else str(title).strip()

    cat = d.get("category")
    d["category"] = "general" if cat is None or str(cat).strip() == "" else str(cat).strip()

    sev = d.get("severity")
    if sev is None or str(sev).strip().lower() in ("", "none"):
        d["severity"] = "Info"
    else:
        d["severity"] = str(sev).strip().capitalize()

    conf = d.get("confidence")
    if conf is None or str(conf).strip().lower() in ("", "none"):
        d["confidence"] = "Confirmed"
    else:
        d["confidence"] = str(conf).strip().capitalize()

    url = d.get("url")
    if url is None or str(url).strip().lower() in ("", "none"):
        d["url"] = ""
    else:
        d["url"] = str(url).strip()

    ev = d.get("evidence")
    d["evidence"] = "" if ev is None else str(ev)

    fix = d.get("fix")
    d["fix"] = "" if fix is None else str(fix)

    description = d.get("description")
    d["description"] = (
        str(description).strip()
        if description is not None and str(description).strip()
        else d["title"]
    )

    impact = d.get("impact")
    d["impact"] = (
        str(impact).strip()
        if impact is not None and str(impact).strip()
        else CATEGORY_IMPACTS.get(d["category"].lower(), CATEGORY_IMPACTS["general"])
    )

    return d


def generate_report(
    target_url: str,
    findings: List[Union[Dict[str, Any], Any]],
    grade: str,
    score: Union[int, float],
    output_path: str,
    passed_checks: Optional[List[str]] = None,
    comparison: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    check_results: Optional[List[Dict[str, Any]]] = None,
    checks_not_performed: Optional[List[Any]] = None,
    scan_limitations: Optional[List[str]] = None,
    observations: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Render and write a self-contained cybersecurity scan report.

    Args:
        target_url: Scanned URL (e.g. 'http://localhost:3000')
        findings: List of finding dicts or Finding objects from Finding.to_dict()
        grade: Letter grade ('A', 'B', 'C', 'D', 'E', 'F')
        score: Numeric score between 0 and 100
        output_path: Destination path for the generated HTML file
        passed_checks: Optional list of passed check descriptions
        comparison: Optional dictionary of comparison metrics against previous scan
        metadata: Optional scan ID, scanner version, target IP, timing, mode, and outcome details
        check_results: Optional structured per-check results for transparency
        checks_not_performed: Optional list of checks not performed (or derived from check_results)
        scan_limitations: Optional list of scan limitations/caveats
        observations: Optional TLS/WAF-CDN/rate-limit observation details

    Returns:
        The resolved absolute path of the generated HTML file.
    """
    # 1. Normalize findings into dictionaries
    normalized_findings = [_normalize_finding(f) for f in findings]

    # 2. Sort findings: Critical -> High -> Medium -> Low -> Info
    sorted_findings = sorted(
        normalized_findings,
        key=lambda f: SEVERITY_ORDER.get(f["severity"].upper(), 99),
    )

    # 3. Calculate severity tile counts
    counts = {
        "critical": sum(1 for f in sorted_findings if f["severity"].upper() == "CRITICAL"),
        "high": sum(1 for f in sorted_findings if f["severity"].upper() == "HIGH"),
        "medium": sum(1 for f in sorted_findings if f["severity"].upper() == "MEDIUM"),
        "low": sum(1 for f in sorted_findings if f["severity"].upper() == "LOW"),
        "info": sum(1 for f in sorted_findings if f["severity"].upper() == "INFO"),
    }

    # 4. Formatted hero findings text (e.g., "1 finding on this target", "6 findings on this target")
    n_findings = len(sorted_findings)
    if n_findings == 1:
        hero_findings_text = "1 finding on this target"
    else:
        hero_findings_text = f"{n_findings} findings on this target"

    # 5. Format scan date/time and metadata
    scan_metadata = dict(metadata or {})
    scan_datetime_str = scan_metadata.get("scan_time") or datetime.now().strftime("%b %d, %Y %H:%M:%S")

    # Normalize check results / not-performed / limitations (backward compatible)
    normalized_check_results = []
    if isinstance(check_results, list):
        for cr in check_results:
            if isinstance(cr, dict):
                normalized_check_results.append(dict(cr))
            else:
                normalized_check_results.append({"name": str(cr), "status": "NOT TESTED"})
    if checks_not_performed is None:
        normalized_checks_not_performed = [cr for cr in normalized_check_results if str(cr.get("status", "")).upper() == "NOT TESTED"]
    else:
        normalized_checks_not_performed = []
        for item in (checks_not_performed or []):
            if isinstance(item, dict):
                normalized_checks_not_performed.append(dict(item))
            else:
                normalized_checks_not_performed.append({"name": str(item), "status": "NOT TESTED", "explanation": "", "evidence": ""})
    normalized_scan_limitations = [str(x) for x in (scan_limitations or []) if str(x).strip()]

    # 6. Determine grade color and padlock status based on grade letter
    clean_grade = str(grade).strip().upper()
    if clean_grade in ("A", "B"):
        grade_color = "#22ff66"
        padlock_state = "closed"
    elif clean_grade == "C":
        grade_color = "#ff7a1a"
        padlock_state = "closed"
    else:  # D, E, F or others
        grade_color = "#ff2d3d"
        padlock_state = "open"

    # Safely compute grade ring dashoffset (0.0 for 100%, 289.026 for 0%)
    try:
        numeric_score = float(score)
    except (ValueError, TypeError):
        numeric_score = 0.0
    dashoffset = round(max(0.0, min(289.026, 289.026 - ((numeric_score / 100.0) * 289.026))), 3)

    # Normalize comparison dict if provided
    normalized_comparison = None
    if comparison is not None and isinstance(comparison, dict):
        comp = dict(comparison)
        comp_counts = comp.get("counts", {})
        if not isinstance(comp_counts, dict):
            comp_counts = {}
        comp["counts"] = {
            "fixed": comp_counts.get("fixed", len(comp.get("fixed", []))),
            "still_open": comp_counts.get("still_open", len(comp.get("still_open", []))),
            "new": comp_counts.get("new", len(comp.get("new", []))),
        }
        comp["score_delta"] = comp.get("score_delta", 0)
        comp["prev_score"] = comp.get("prev_score", score)
        comp["prev_grade"] = comp.get("prev_grade", clean_grade)
        normalized_comparison = comp

    # 7. Setup Jinja2 Environment with autoescape=True for security
    base_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(base_dir, "templates")

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(templates_dir),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html")

    # 8. Render the template
    rendered_html = template.render(
        target_url=target_url,
        findings=sorted_findings,
        grade=clean_grade,
        score=score,
        dashoffset=dashoffset,
        grade_color=grade_color,
        padlock_state=padlock_state,
        counts=counts,
        hero_findings_text=hero_findings_text,
        scan_time=scan_datetime_str,
        metadata=scan_metadata,
        passed_checks=passed_checks if passed_checks else [],
        comparison=normalized_comparison,
        check_results=normalized_check_results,
        checks_not_performed=normalized_checks_not_performed,
        scan_limitations=normalized_scan_limitations,
        observations=observations or {},
    )

    # 9. Create output directory if missing
    abs_output_path = os.path.abspath(output_path)
    output_dir = os.path.dirname(abs_output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # 10. Write the single self-contained HTML file
    with open(abs_output_path, "w", encoding="utf-8") as file:
        file.write(rendered_html)

    return abs_output_path
