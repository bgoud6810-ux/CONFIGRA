"""
tests/test_report.py - Comprehensive Test Suite for HTML Security Report Generator

Verifies:
  1. HTML Autoescaping & Injection / XSS Protection in all fields
  2. All 5 severity levels (Critical, High, Medium, Low, Info) & sorting
  3. Both confidence levels (Confirmed, Likely)
  4. Clean scan (0 findings, Grade A, Score 100) handling
  5. Large report stress test (60+ findings)
  6. Missing / None / Empty fields handled without crashing
  7. Long unbroken strings and CSS overflow handling
  8. Scan comparison panel rendered when comparison dict is provided
  9. Scan comparison panel omitted when comparison is None
  10. 100% Offline independence (no external CDNs, fonts, or scripts)
  11. File written to disk and readable as UTF-8
  12. Sample reports generation (sample_report_bad.html, sample_report_good.html)

Run with:
    python -m tests.test_report
"""

import os
import re
import sys
import tempfile

# Ensure workspace root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.models import Finding
from reports.html_report import generate_report, SEVERITY_ORDER


def build_sample_findings():
    """
    Build 6 sample findings matching scanner checks:
    - 1 Critical (paths)
    - 1 High (headers)
    - 2 Medium (headers)
    - 2 Low (cookies, info_leaks)
    """
    return [
        Finding(
            id="PTH-001",
            title=".env file exposed",
            category="paths",
            severity="Critical",
            evidence="GET /.env returned 200 OK",
            fix="Block access to dotfiles in the web server config",
            confidence="Confirmed",
            url="http://localhost:3000/.env",
        ).to_dict(),
        Finding(
            id="HDR-001",
            title="Missing X-Frame-Options",
            category="headers",
            severity="High",
            evidence="X-Frame-Options header not set",
            fix="Add X-Frame-Options: DENY",
            confidence="Confirmed",
            url="http://localhost:3000/",
        ).to_dict(),
        Finding(
            id="HDR-002",
            title="HSTS header missing",
            category="headers",
            severity="Medium",
            evidence="Strict-Transport-Security not in response",
            fix="Add Strict-Transport-Security: max-age=31536000",
            confidence="Confirmed",
            url="http://localhost:3000/",
        ).to_dict(),
        Finding(
            id="HDR-003",
            title="Content Security Policy missing",
            category="headers",
            severity="Medium",
            evidence="Content-Security-Policy header not set",
            fix="Add a Content-Security-Policy header",
            confidence="Confirmed",
            url="http://localhost:3000/",
        ).to_dict(),
        Finding(
            id="CK-001",
            title="Cookie missing HttpOnly flag",
            category="cookies",
            severity="Low",
            evidence="Set-Cookie has no HttpOnly",
            fix="Set the HttpOnly flag on cookies",
            confidence="Confirmed",
            url="http://localhost:3000/",
        ).to_dict(),
        Finding(
            id="INF-001",
            title="Server exposes version",
            category="info_leaks",
            severity="Low",
            evidence="Server header reveals version information",
            fix="Hide the server version banner",
            confidence="Confirmed",
            url="http://localhost:3000/",
        ).to_dict(),
    ]


def test_xss_autoescaping_in_report():
    """Verify that malicious HTML and JS in all fields are escaped and never rendered raw."""
    xss_payloads = [
        "<script>alert('XSS_TITLE')</script>",
        "<img src=x onerror=alert('XSS_EVIDENCE')>",
        "javascript:alert('XSS_URL')",
        "\"><svg onload=alert('XSS_FIX')>",
        "'><script>alert('XSS_CATEGORY')</script>",
        "<iframe src='evil.html'></iframe>",
    ]

    xss_finding = {
        "id": "XSS-001<script>",
        "title": xss_payloads[0],
        "evidence": xss_payloads[1],
        "url": xss_payloads[2],
        "fix": xss_payloads[3],
        "category": xss_payloads[4],
        "severity": "High",
        "confidence": "Confirmed",
    }

    xss_comp = {
        "prev_score": 50,
        "prev_grade": "D",
        "score_delta": 20,
        "counts": {"fixed": 1, "still_open": 0, "new": 0},
        "fixed": [{"id": "FIX-<script>", "title": xss_payloads[5]}],
    }

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as tf:
        temp_path = tf.name

    try:
        generate_report(
            target_url="http://localhost:3000/<script>alert(1)</script>",
            findings=[xss_finding],
            grade="D",
            score=45,
            output_path=temp_path,
            passed_checks=["Check <script>safe</script>"],
            comparison=xss_comp,
        )

        with open(temp_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Raw executable script / iframe / svg handlers must NEVER appear
        assert "<script>alert" not in html, "Raw <script> tag leaked into HTML report!"
        assert "<img src=x onerror" not in html, "Raw <img> onerror handler leaked into HTML report!"
        assert "<svg onload" not in html, "Raw <svg> onload handler leaked into HTML report!"
        assert "<iframe" not in html, "Raw <iframe> leaked into HTML report!"

        # Escaped entities must be present
        assert "&lt;script&gt;alert" in html, "Expected entity-escaped script tag in HTML report"
        assert "&lt;img src=x" in html, "Expected entity-escaped img tag in HTML report"
        assert "&lt;svg" in html, "Expected entity-escaped svg tag in HTML report"
        assert "&lt;iframe" in html, "Expected entity-escaped iframe tag in HTML report"

        print("  [PASS] test_xss_autoescaping_in_report")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_all_severity_and_confidence_badges():
    """Verify that all 5 severities and both confidences are rendered and sorted properly."""
    findings = [
        Finding(id="F-INFO", title="Info finding", category="info_leaks", severity="Info", confidence="Likely", evidence="info ev", fix="info fix"),
        Finding(id="F-CRIT", title="Crit finding", category="paths", severity="Critical", confidence="Confirmed", evidence="crit ev", fix="crit fix"),
        Finding(id="F-MED", title="Med finding", category="headers", severity="Medium", confidence="Likely", evidence="med ev", fix="med fix"),
        Finding(id="F-LOW", title="Low finding", category="cookies", severity="Low", confidence="Confirmed", evidence="low ev", fix="low fix"),
        Finding(id="F-HIGH", title="High finding", category="headers", severity="High", confidence="Confirmed", evidence="high ev", fix="high fix"),
    ]

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as tf:
        temp_path = tf.name

    try:
        generate_report(
            target_url="http://localhost:8000",
            findings=findings,
            grade="F",
            score=20,
            output_path=temp_path,
        )

        with open(temp_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Check all severity badges rendered
        for sev in ["critical", "high", "medium", "low", "info"]:
            assert f"badge-{sev}" in html, f"Missing badge-{sev} in rendered HTML"
            assert f"finding-{sev}" in html, f"Missing finding-{sev} in rendered HTML"

        # Check confidence badges
        assert "confidence-confirmed" in html, "Missing confidence-confirmed in rendered HTML"
        assert "confidence-likely" in html, "Missing confidence-likely in rendered HTML"

        # Check sorting order: Critical must appear before High, High before Medium, etc.
        pos_crit = html.find("Crit finding")
        pos_high = html.find("High finding")
        pos_med = html.find("Med finding")
        pos_low = html.find("Low finding")
        pos_info = html.find("Info finding")

        assert pos_crit != -1 and pos_high != -1 and pos_med != -1 and pos_low != -1 and pos_info != -1
        assert pos_crit < pos_high < pos_med < pos_low < pos_info, "Findings are not sorted by severity!"

        # Check Info tile is rendered
        assert "severity-tile-info" in html, "Info tile not rendered when Info findings present"

        print("  [PASS] test_all_severity_and_confidence_badges")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_all_findings_details_counts_and_scan_metadata_rendered():
    findings = build_sample_findings()
    metadata = {
        "scan_id": "scan-metadata-test",
        "scanner_version": "1.0.0",
        "target_ip": "127.0.0.1",
        "scan_started_at": "2026-11-18T10:00:00+05:30",
        "scan_completed_at": "2026-11-18T10:00:02+05:30",
        "duration_seconds": 2.0,
    }

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as tf:
        temp_path = tf.name

    try:
        generate_report(
            target_url="http://localhost:3000",
            findings=findings,
            grade="D",
            score=41,
            output_path=temp_path,
            metadata=metadata,
        )

        with open(temp_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert html.count('class="finding-row') == len(findings)
        for finding in findings:
            assert html.count(f'data-id="{finding["id"]}"') == 1
            assert finding["title"] in html
        for label in ["Description:", "Security impact:", "Evidence / observed configuration:", "Recommended remediation:"]:
            assert label in html
        for value in metadata.values():
            assert str(value) in html
        assert "Affected URL / component:" in html

        expected_counts = {"Critical": 1, "High": 1, "Medium": 2, "Low": 2, "Informational": 0}
        for severity, expected in expected_counts.items():
            assert f'<span class="tile-number">{expected}</span>\n          <span class="tile-word">{severity}</span>' in html

        print("  [PASS] test_all_findings_details_counts_and_scan_metadata_rendered")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_empty_findings_clean_scan():
    """Verify that a clean scan (0 findings) produces a valid Grade A report with green padlock."""
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as tf:
        temp_path = tf.name

    try:
        generate_report(
            target_url="https://secure-target.local",
            findings=[],
            grade="A",
            score=100,
            output_path=temp_path,
            passed_checks=["HSTS present", "All cookies secure", "No directory listing"],
        )

        with open(temp_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert "no-findings-panel" in html, "Expected .no-findings-panel for 0 findings"
        assert "No security misconfigurations detected." in html
        assert "hero-padlock padlock-green" in html, "Expected green padlock element for Grade A scan"
        assert "hero-padlock padlock-red" not in html, "Red padlock element found on Grade A clean scan!"
        assert "0 findings on this target" in html, "Expected '0 findings on this target' text"

        # Passed checks section present
        assert "Passed checks" in html
        assert "All cookies secure" in html

        print("  [PASS] test_empty_findings_clean_scan")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_large_report_50_plus_findings():
    """Verify report generation handles large volumes of findings (60+) without slowdown or layout breakage."""
    large_findings = []
    for i in range(60):
        sev = ["Critical", "High", "Medium", "Low", "Info"][i % 5]
        large_findings.append({
            "id": f"TEST-{i:03d}",
            "title": f"Security Misconfiguration Check #{i}",
            "category": "headers" if i % 2 == 0 else "paths",
            "severity": sev,
            "evidence": f"GET /test/{i} returned unexpected response code 200",
            "fix": f"Apply security patch #{i}",
            "confidence": "Confirmed" if i % 2 == 0 else "Likely",
            "url": f"http://localhost:8000/test/{i}",
        })

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as tf:
        temp_path = tf.name

    try:
        generate_report(
            target_url="http://localhost:8000",
            findings=large_findings,
            grade="F",
            score=5,
            output_path=temp_path,
        )

        with open(temp_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert "60 findings on this target" in html
        assert html.count('class="finding-row') == 60
        assert "TEST-059" in html

        print("  [PASS] test_large_report_50_plus_findings")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_missing_and_none_fields_handled_safely():
    """Verify that None values or completely missing fields do not crash the generator or print 'None'."""
    broken_findings = [
        # Dataclass with None optional fields (evidence, fix, url)
        Finding(
            id="NONE-001",
            title="Finding with None fields",
            category="general",
            severity="Info",
            evidence=None,
            fix=None,
            confidence="Confirmed",
            url=None,
        ),
        # Raw dict with empty values and None keys
        {
            "id": None,
            "title": None,
            "category": None,
            "severity": None,
            "evidence": None,
            "fix": None,
            "confidence": None,
            "url": None,
        },
        # Empty dict
        {},
    ]

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as tf:
        temp_path = tf.name

    try:
        generate_report(
            target_url="http://localhost:8000",
            findings=broken_findings,
            grade="C",
            score=70,
            output_path=temp_path,
        )

        with open(temp_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Ensure literal "Endpoint: None" or "Evidence:None" does not appear
        assert "Endpoint:None" not in html
        assert "Endpoint: None" not in html
        assert "Evidence:None" not in html
        assert "Fix:None" not in html

        # Report was written and contains findings
        assert "3 findings on this target" in html

        print("  [PASS] test_missing_and_none_fields_handled_safely")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_long_unbroken_strings_overflow_check():
    """Verify that 2000+ character continuous strings are wrapped with overflow-wrap/word-break rules."""
    long_str = "A" * 2500
    long_finding = Finding(
        id="LONG-001",
        title=f"Very long title {long_str[:200]}",
        category="overflow",
        severity="Medium",
        evidence=f"Token: {long_str}",
        fix=f"Rotate token: {long_str}",
        confidence="Confirmed",
        url=f"http://localhost:8000/{long_str[:300]}",
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as tf:
        temp_path = tf.name

    try:
        generate_report(
            target_url="http://localhost:8000",
            findings=[long_finding],
            grade="C",
            score=75,
            output_path=temp_path,
        )

        with open(temp_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Check CSS contains overflow-wrap and word-break rules
        assert "overflow-wrap: anywhere;" in html
        assert "word-break: break-word;" in html
        assert "word-break: break-all;" in html

        # Evidence is present in report
        assert long_str in html

        print("  [PASS] test_long_unbroken_strings_overflow_check")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_comparison_panel_rendered_when_provided():
    """Verify scan comparison section is rendered with correct diff stats and fixed list."""
    comp_data = {
        "prev_score": 55,
        "prev_grade": "D",
        "score_delta": 30,
        "counts": {"fixed": 2, "still_open": 1, "new": 0},
        "fixed": [
            {"id": "PTH-001", "title": "Resolved .env exposure"},
            {"id": "HDR-001", "title": "Resolved missing X-Frame-Options"},
        ],
    }

    sample = build_sample_findings()[:1]

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as tf:
        temp_path = tf.name

    try:
        generate_report(
            target_url="http://localhost:3000",
            findings=sample,
            grade="B",
            score=85,
            output_path=temp_path,
            comparison=comp_data,
        )

        with open(temp_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert '<section class="comparison-panel"' in html, "Comparison panel not rendered when comparison dict provided"
        assert "Changes since last scan" in html
        assert "2 Fixed" in html
        assert "1 Still Open" in html
        assert "0 New" in html
        assert "+30 pts" in html
        assert "Score: 55" in html
        assert "Grade: D" in html
        assert "Resolved .env exposure" in html
        assert "Resolved missing X-Frame-Options" in html

        print("  [PASS] test_comparison_panel_rendered_when_provided")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_comparison_panel_omitted_when_none():
    """Verify scan comparison section is cleanly omitted when comparison=None."""
    sample = build_sample_findings()[:1]

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as tf:
        temp_path = tf.name

    try:
        generate_report(
            target_url="http://localhost:3000",
            findings=sample,
            grade="B",
            score=85,
            output_path=temp_path,
            comparison=None,
        )

        with open(temp_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert '<section class="comparison-panel"' not in html, "Comparison panel rendered when comparison=None!"
        assert "Changes since last scan" not in html

        print("  [PASS] test_comparison_panel_omitted_when_none")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_offline_independence():
    """Verify that the generated report has zero external CDN links, script tags, or font downloads."""
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".html") as tf:
        temp_path = tf.name

    try:
        generate_report(
            target_url="http://localhost:3000",
            findings=build_sample_findings(),
            grade="D",
            score=41,
            output_path=temp_path,
        )

        with open(temp_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Check for external stylesheet links
        assert not re.search(r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']http', html, re.I), \
            "Found external stylesheet <link>!"

        # Check for external script tags
        assert not re.search(r'<script[^>]+src=["\']http', html, re.I), \
            "Found external script tag!"

        # Check for CSS @import http
        assert not re.search(r'@import\s+url\(["\']?http', html, re.I), \
            "Found external CSS @import!"

        # Check for known CDN domains
        for cdn in ["cdnjs.cloudflare.com", "cdn.jsdelivr.net", "fonts.googleapis.com", "unpkg.com"]:
            assert cdn not in html, f"Found external CDN reference: {cdn}"

        print("  [PASS] test_offline_independence")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_file_written_to_disk_and_readable():
    """Verify that the file is written to the destination path, is non-empty, and valid UTF-8."""
    out_dir = os.path.join(PROJECT_ROOT, "output")
    test_out = os.path.join(out_dir, "test_write_verification.html")

    try:
        resolved = generate_report(
            target_url="http://localhost:3000",
            findings=build_sample_findings()[:2],
            grade="B",
            score=82,
            output_path=test_out,
        )

        assert os.path.isfile(resolved), f"Report file does not exist at {resolved}"
        assert os.path.getsize(resolved) > 3000, "Report file is suspiciously small"

        with open(resolved, "r", encoding="utf-8") as f:
            content = f.read()

        assert content.strip().startswith("<!DOCTYPE html>")
        assert content.strip().endswith("</html>")

        print("  [PASS] test_file_written_to_disk_and_readable")
    finally:
        if os.path.exists(test_out):
            os.remove(test_out)


def test_sample_reports_good_and_bad():
    """Generate and verify the standard sample bad and good reports in output/ directory."""
    target_url = "http://localhost:3000"
    passed_checks = [
        "No .git exposure",
        "X-Content-Type-Options present",
        "No directory listing",
    ]

    all_findings = build_sample_findings()
    low_findings = [f for f in all_findings if f["severity"].lower() == "low"]

    bad_report_path = os.path.join(PROJECT_ROOT, "output", "sample_report_bad.html")
    generate_report(
        target_url=target_url,
        findings=all_findings,
        grade="D",
        score=41,
        output_path=bad_report_path,
        passed_checks=passed_checks,
    )
    assert os.path.isfile(bad_report_path)

    good_report_path = os.path.join(PROJECT_ROOT, "output", "sample_report_good.html")
    generate_report(
        target_url=target_url,
        findings=low_findings,
        grade="B",
        score=86,
        output_path=good_report_path,
        passed_checks=passed_checks,
    )
    assert os.path.isfile(good_report_path)

    print("  [PASS] test_sample_reports_good_and_bad")


def run_all_tests():
    print("=" * 60)
    print("Running Member 3 - HTML Report Test Suite")
    print("=" * 60)

    test_xss_autoescaping_in_report()
    test_all_severity_and_confidence_badges()
    test_empty_findings_clean_scan()
    test_large_report_50_plus_findings()
    test_missing_and_none_fields_handled_safely()
    test_long_unbroken_strings_overflow_check()
    test_comparison_panel_rendered_when_provided()
    test_comparison_panel_omitted_when_none()
    test_offline_independence()
    test_file_written_to_disk_and_readable()
    test_sample_reports_good_and_bad()

    print("=" * 60)
    print("ALL 11 HTML REPORT TESTS PASSED SUCCESSFULLY! (EXIT 0)")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
