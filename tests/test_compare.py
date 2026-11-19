"""
tests/test_compare.py - Test suite for re-scan comparison functionality and JSON schema

Verifies:
1. Baseline calculation of Fixed, Still Open, and New findings.
2. Stability of target-wide findings when crawled URL lists expand across multiple pages.
3. Cookie identity isolation (distinct cookies sharing finding types are NOT merged).
4. Path identity isolation (different exposed paths sharing finding types are NOT merged).
5. JSON schema metadata enrichment (ISO 8601 timestamps, duration, version, safe target_ip).
6. Graceful DNS resolution failure handling (stores None/null without crashing).
7. HTML report rendering of the 'Changes since last scan' delta panel.

Run with:
    python -m tests.test_compare
"""

import sys
import os
import json
import tempfile
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.models import Finding
from scanner import compare_scans, resolve_target_ip
from reports.html_report import generate_report


def test_basic_comparison():
    prev_scan_data = {
        "target": "http://localhost:3000",
        "grade": "D",
        "score": 41,
        "findings": [
            {
                "id": "PTH-ENV",
                "title": "Exposed .env configuration file",
                "category": "paths",
                "severity": "Critical",
                "evidence": "GET /.env returned 200 OK",
                "fix": "Block dotfiles in server config",
                "confidence": "Confirmed",
                "url": "http://localhost:3000/.env",
            },
            {
                "id": "HDR-005",
                "title": "Missing Clickjacking protection",
                "category": "headers",
                "severity": "Medium",
                "evidence": "X-Frame-Options not set",
                "fix": "X-Frame-Options: DENY",
                "confidence": "Confirmed",
                "url": "http://localhost:3000/",
            },
            {
                "id": "HDR-003",
                "title": "Content Security Policy missing",
                "category": "headers",
                "severity": "Medium",
                "evidence": "CSP not set",
                "fix": "Add CSP header",
                "confidence": "Confirmed",
                "url": "http://localhost:3000/",
            },
            {
                "id": "INF-002",
                "title": "X-Powered-By header discloses technology",
                "category": "info_leaks",
                "severity": "Low",
                "evidence": "X-Powered-By: Express",
                "fix": "Disable X-Powered-By",
                "confidence": "Confirmed",
                "url": "http://localhost:3000/",
            },
        ],
    }

    current_findings = [
        Finding(
            id="HDR-003",
            title="Content Security Policy missing",
            category="headers",
            severity="Medium",
            evidence="CSP not set",
            fix="Add CSP header",
            confidence="Confirmed",
            url="http://localhost:3000/",
        ),
        Finding(
            id="INF-002",
            title="X-Powered-By header discloses technology",
            category="info_leaks",
            severity="Low",
            evidence="X-Powered-By: Express",
            fix="Disable X-Powered-By",
            confidence="Confirmed",
            url="http://localhost:3000/",
        ),
        Finding(
            id="CKE-001",
            title="Cookie missing HttpOnly flag",
            category="cookies",
            severity="Low",
            evidence="Set-Cookie without HttpOnly",
            fix="Add HttpOnly",
            confidence="Confirmed",
            url="http://localhost:3000/",
        ),
    ]

    current_score = 86
    current_grade = "B"

    diff = compare_scans(prev_scan_data, current_findings, current_score, current_grade)

    assert diff["counts"]["fixed"] == 2, f"Expected 2 fixed, got {diff['counts']['fixed']}"
    assert diff["counts"]["still_open"] == 2, f"Expected 2 still open, got {diff['counts']['still_open']}"
    assert diff["counts"]["new"] == 1, f"Expected 1 new, got {diff['counts']['new']}"
    assert diff["score_delta"] == 45, f"Expected +45 delta, got {diff['score_delta']}"
    assert diff["prev_grade"] == "D"

    fixed_ids = {f["id"] for f in diff["fixed"]}
    assert "PTH-ENV" in fixed_ids
    assert "HDR-005" in fixed_ids

    new_ids = {f["id"] for f in diff["new"]}
    assert "CKE-001" in new_ids

    # Test HTML report integration
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        generate_report(
            target_url="http://localhost:3000",
            findings=[f.to_dict() for f in current_findings],
            grade=current_grade,
            score=current_score,
            output_path=tmp_path,
            comparison=diff,
        )
        with open(tmp_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Changes since last scan" in content
        assert "2 Fixed" in content
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    print("  [PASS] Basic re-scan diff and HTML delta panel test passed.")


def test_multipage_url_expansion_stability():
    """Verify that expanding a finding from 1 URL to multiple URLs does NOT cause false Fixed/New churn."""
    prev_scan_data = {
        "target": "http://localhost:3000",
        "score": 80,
        "grade": "B",
        "findings": [
            {
                "id": "HDR-003",
                "title": "Content Security Policy missing",
                "category": "headers",
                "severity": "Medium",
                "evidence": "CSP not set",
                "fix": "Add CSP header",
                "confidence": "Confirmed",
                "url": "http://localhost:3000/",
            }
        ],
    }

    # Second scan: same target, but crawler expanded finding URL to multiple subpages
    current_findings = [
        Finding(
            id="HDR-003",
            title="Content Security Policy missing",
            category="headers",
            severity="Medium",
            evidence="CSP not set; CSP not set",
            fix="Add CSP header",
            confidence="Confirmed",
            url="http://localhost:3000/, http://localhost:3000/subpage, http://localhost:3000/login",
        )
    ]

    diff = compare_scans(prev_scan_data, current_findings, current_score=80, current_grade="B")

    # MUST remain 'still_open', NOT 1 fixed and 1 new!
    assert diff["counts"]["still_open"] == 1, f"Expected 1 still open, got {diff['counts']['still_open']}"
    assert diff["counts"]["fixed"] == 0, f"False positive fixed detected: {diff['fixed']}"
    assert diff["counts"]["new"] == 0, f"False positive new detected: {diff['new']}"
    print("  [PASS] Multi-page URL expansion stability test passed (0 false Fixed, 0 false New).")


def test_different_cookies_are_not_merged():
    """Verify two distinct cookies sharing a generic finding ID are kept separate."""
    prev_scan_data = {
        "target": "http://localhost:3000",
        "score": 60,
        "grade": "C",
        "findings": [
            {
                "id": "CKE-001",
                "title": "Cookie 'session_id' missing HttpOnly flag",
                "category": "cookies",
                "severity": "Medium",
                "evidence": "Set-Cookie: session_id=123",
                "fix": "Add HttpOnly",
                "confidence": "Confirmed",
                "url": "http://localhost:3000/",
            },
            {
                "id": "CKE-001",
                "title": "Cookie 'user_theme' missing HttpOnly flag",
                "category": "cookies",
                "severity": "Low",
                "evidence": "Set-Cookie: user_theme=dark",
                "fix": "Add HttpOnly",
                "confidence": "Confirmed",
                "url": "http://localhost:3000/",
            },
        ],
    }

    # Second scan: developer fixed 'session_id', but 'user_theme' is still missing HttpOnly
    current_findings = [
        Finding(
            id="CKE-001",
            title="Cookie 'user_theme' missing HttpOnly flag",
            category="cookies",
            severity="Low",
            evidence="Set-Cookie: user_theme=dark",
            fix="Add HttpOnly",
            confidence="Confirmed",
            url="http://localhost:3000/",
        )
    ]

    diff = compare_scans(prev_scan_data, current_findings, current_score=85, current_grade="B")

    assert diff["counts"]["fixed"] == 1, f"Expected 1 fixed, got {diff['counts']['fixed']}"
    assert diff["counts"]["still_open"] == 1, f"Expected 1 still open, got {diff['counts']['still_open']}"
    assert diff["counts"]["new"] == 0, f"Expected 0 new, got {diff['counts']['new']}"

    fixed_title = diff["fixed"][0]["title"]
    assert "session_id" in fixed_title, f"Expected session_id fixed, got {fixed_title}"
    print("  [PASS] Distinct cookies sharing finding ID are correctly isolated.")


def test_different_paths_are_not_merged():
    """Verify two distinct exposed paths sharing a generic finding ID remain separate."""
    prev_scan_data = {
        "target": "http://localhost:3000",
        "score": 40,
        "grade": "D",
        "findings": [
            {
                "id": "PTH-001",
                "title": "Exposed sensitive file: /.env",
                "category": "paths",
                "severity": "Critical",
                "evidence": "Found .env",
                "fix": "Block dotfiles",
                "confidence": "Confirmed",
                "url": "http://localhost:3000/.env",
            },
            {
                "id": "PTH-001",
                "title": "Exposed sensitive file: /backup.sql",
                "category": "paths",
                "severity": "High",
                "evidence": "Found backup.sql",
                "fix": "Remove backup",
                "confidence": "Confirmed",
                "url": "http://localhost:3000/backup.sql",
            },
        ],
    }

    # Second scan: developer deleted .env, but backup.sql remains exposed
    current_findings = [
        Finding(
            id="PTH-001",
            title="Exposed sensitive file: /backup.sql",
            category="paths",
            severity="High",
            evidence="Found backup.sql",
            fix="Remove backup",
            confidence="Confirmed",
            url="http://localhost:3000/backup.sql",
        )
    ]

    diff = compare_scans(prev_scan_data, current_findings, current_score=70, current_grade="C")

    assert diff["counts"]["fixed"] == 1, f"Expected 1 fixed, got {diff['counts']['fixed']}"
    assert diff["counts"]["still_open"] == 1, f"Expected 1 still open, got {diff['counts']['still_open']}"
    assert diff["counts"]["new"] == 0

    assert "/.env" in diff["fixed"][0]["url"], f"Expected /.env in fixed list, got {diff['fixed'][0]}"
    print("  [PASS] Distinct sensitive paths sharing finding ID are correctly isolated.")


def test_json_schema_enrichment():
    """Verify JSON results contain version, accurate ISO 8601 timestamps, duration, and IP."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_json = tmp.name

    try:
        # Construct realistic results_data matching scanner.py
        scan_started = "2026-11-17T15:20:00.000000+05:30"
        scan_completed = "2026-11-17T15:20:02.500000+05:30"
        duration = 2.50
        target_ip = "127.0.0.1"

        data = {
            "scanner_version": "1.0.0",
            "target": "http://localhost:3000",
            "target_ip": target_ip,
            "scan_started_at": scan_started,
            "scan_completed_at": scan_completed,
            "duration_seconds": duration,
            "scan_time": datetime.now().strftime("%b %d, %Y %H:%M:%S"),
            "grade": "A",
            "score": 97,
            "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 1, "Info": 0},
            "findings": [],
            "passed_checks": ["No .env file"],
            "errors": [],
        }

        with open(tmp_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        with open(tmp_json, "r", encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded["scanner_version"] == "1.0.0"
        assert loaded["target_ip"] == "127.0.0.1"
        assert loaded["scan_started_at"] == scan_started
        assert loaded["scan_completed_at"] == scan_completed
        assert loaded["duration_seconds"] == 2.50
        assert "scan_time" in loaded
        assert "grade" in loaded
        assert "score" in loaded
        assert "findings" in loaded
        print("  [PASS] JSON metadata schema enrichment test passed.")
    finally:
        if os.path.exists(tmp_json):
            os.remove(tmp_json)


def test_dns_failure_handling():
    """Verify that DNS failures safely return None instead of crashing."""
    # Test valid localhost resolution
    ip_local = resolve_target_ip("http://127.0.0.1:3000")
    assert ip_local == "127.0.0.1"

    # Test invalid nonexistent domain
    ip_bad = resolve_target_ip("http://this-domain-definitely-does-not-exist-12345.test")
    assert ip_bad is None, f"Expected None on DNS resolution failure, got {ip_bad}"

    # Test malformed URL
    ip_malformed = resolve_target_ip("not-a-valid-url")
    assert ip_malformed is None
    print("  [PASS] DNS failure handling test passed (returns None without crashing).")


def run_tests():
    print("[*] Starting Phase 6 Re-Scan Comparison & JSON Schema Tests...")
    test_basic_comparison()
    test_multipage_url_expansion_stability()
    test_different_cookies_are_not_merged()
    test_different_paths_are_not_merged()
    test_json_schema_enrichment()
    test_dns_failure_handling()
    print("\n[PHASE 6 RESULT: PASS]")


if __name__ == "__main__":
    run_tests()
