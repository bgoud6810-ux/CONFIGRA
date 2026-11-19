#!/usr/bin/env python3
"""
tests/test_webapp.py — Integration and Unit Tests for Flask SOC Interface (Page 1 & Page 2)
"""

import os
import sys
import json
import re
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app, OUTPUT_DIR, ACTIVE_SCANS


class TestWebApp(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_scanner_page_1_routes(self):
        """Test Page 1: / and /scan render the Scanner interface."""
        for route in ["/", "/scan"]:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200)
            html = res.data.decode("utf-8")
            self.assertIn("CONFIGRA", html)
            self.assertIn("targetUrl", html)
            self.assertIn("startScanBtn", html)
            self.assertIn("scanningLivePanel", html)
            self.assertIn("Passive Public Inspection", html)
            self.assertIn("Authorized Security Configuration Assessment", html)
            self.assertIn("cfgScanMode", html)

    def test_results_page_2_seeded(self):
        """Test Page 2: /results/<scan_id> renders the CONFIGRA results dashboard."""
        scan_id = "test_unit_scan"
        sample_data = {
            "scanner_version": "1.0.0",
            "target": "http://127.0.0.1:3000",
            "target_ip": "127.0.0.1",
            "scan_time": "Nov 17, 2026 21:00:00",
            "scan_completed_at": "2026-11-17T21:00:00Z",
            "duration_seconds": 1.45,
            "score": 82,
            "grade": "B",
            "counts": {"Critical": 0, "High": 1, "Medium": 1, "Low": 0, "Info": 0},
            "findings": [
                {
                    "id": "HDR-001",
                    "category": "headers",
                    "title": "Missing Content-Security-Policy",
                    "severity": "High",
                    "confidence": "Certain",
                    "evidence": "Header absent",
                    "remediation": "Add CSP header to all responses.",
                    "url": "http://127.0.0.1:3000",
                },
                {
                    "id": "CKE-001-SESSIONID",
                    "category": "cookies",
                    "title": "Cookie 'sessionid' missing HttpOnly flag",
                    "severity": "Medium",
                    "confidence": "Certain",
                    "evidence": "Set-Cookie: sessionid=xyz",
                    "remediation": "Set HttpOnly flag on session cookies.",
                    "url": "http://127.0.0.1:3000",
                },
            ],
            "passed_checks": ["Strict-Transport-Security verified", "CORS policy secure"],
        }

        json_path = os.path.join(OUTPUT_DIR, f"scan_{scan_id}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(sample_data, f)

        try:
            res = self.client.get(f"/results/{scan_id}")
            self.assertEqual(res.status_code, 200)
            html = res.data.decode("utf-8")
            self.assertIn("Scan Results Dashboard", html)
            self.assertIn("Missing Content-Security-Policy", html)
            self.assertTrue(
                "Cookie &#39;sessionid&#39; missing HttpOnly flag" in html
                or "Cookie 'sessionid' missing HttpOnly flag" in html
            )
            self.assertIn("82", html)
            self.assertIn("Strong configuration", html)
            self.assertIn("HDR-001", html)
            self.assertIn("Add CSP header to all responses.", html)
            self.assertIn("Strict-Transport-Security verified", html)
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

    def test_api_scan_missing_url(self):
        """Test API rejects empty target URL with HTTP 400."""
        res = self.client.post("/api/scan", json={"target_url": ""})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_api_scan_safety_unauthorized(self):
        """Test API refuses public target when i_have_permission is false."""
        res = self.client.post(
            "/api/scan",
            json={"target_url": "http://8.8.8.8", "i_have_permission": False},
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("authorized testing permission", data["error"].lower())

    def test_api_scan_status_not_found(self):
        """Test querying non-existent scan ID returns HTTP 404."""
        res = self.client.get("/api/scan/non_existent_id/status")
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertEqual(data["status"], "not_found")

    def test_end_to_end_scan_execution(self):
        """Test full scan dispatch, background execution, polling, and results rendering."""
        import time
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import threading

        # Spin up lightweight mock HTTP server
        class MockHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                # Send response with misconfiguration (missing security headers)
                self.send_header("Content-Type", "text/html")
                self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Test Target App</h1></body></html>")

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 8998), MockHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        scan_id = None

        try:
            # 1. Dispatch scan
            res = self.client.post(
                "/api/scan",
                json={
                    "target_url": "http://127.0.0.1:8998",
                    "delay": 0.0,
                    "timeout": 2.0,
                    "insecure": True,
                    "i_have_permission": True,
                },
            )
            self.assertEqual(res.status_code, 202)
            data = res.get_json()
            scan_id = data["scan_id"]
            self.assertTrue(scan_id)
            self.assertEqual(data.get("scan_mode"), "authorized_assessment")

            # 2. Poll until completed (timeout 15s)
            start_poll = time.time()
            completed = False
            while time.time() - start_poll < 15:
                status_res = self.client.get(f"/api/scan/{scan_id}/status")
                self.assertEqual(status_res.status_code, 200)
                status_data = status_res.get_json()
                if status_data["status"] == "completed":
                    completed = True
                    break
                elif status_data["status"] == "failed":
                    self.fail(f"Scan failed: {status_data.get('error')}")
                time.sleep(0.3)

            self.assertTrue(completed, "Scan did not complete within timeout")

            # 3. Retrieve Page 2 results
            results_res = self.client.get(f"/results/{scan_id}")
            self.assertEqual(results_res.status_code, 200)
            results_html = results_res.data.decode("utf-8")
            self.assertIn("Scan Results Dashboard", results_html)
            self.assertIn("http://127.0.0.1:8998", results_html)
            # Should have detected missing headers / server info leak
            self.assertTrue(
                "Apache" in results_html or "HDR-" in results_html or "INF-" in results_html
            )

            report_res = self.client.get(f"/report/{scan_id}")
            self.assertEqual(report_res.status_code, 200)
            report_html = report_res.data.decode("utf-8")
            report_res.close()
            with open(os.path.join(OUTPUT_DIR, f"scan_{scan_id}.json"), "r", encoding="utf-8") as f:
                scan_data = json.load(f)
            self.assertGreater(len(scan_data["findings"]), 1)
            self.assertIn(f"Scan ID:</strong> {scan_id}", report_html)
            for finding in scan_data["findings"]:
                self.assertEqual(report_html.count(f'data-id="{finding["id"]}"'), 1)

            displayed_counts = {
                label: int(count)
                for count, label in re.findall(
                    r'<span class="tile-number">(\d+)</span>\s*<span class="tile-word">([^<]+)</span>',
                    report_html,
                )
            }
            expected_counts = {
                label: sum(1 for finding in scan_data["findings"] if finding["severity"] == severity)
                for severity, label in [
                    ("Critical", "Critical"),
                    ("High", "High"),
                    ("Medium", "Medium"),
                    ("Low", "Low"),
                    ("Info", "Informational"),
                ]
            }
            self.assertEqual(displayed_counts, expected_counts)
        finally:
            server.shutdown()
            server.server_close()
            if scan_id:
                for artifact in [
                    os.path.join(OUTPUT_DIR, f"scan_{scan_id}.json"),
                    os.path.join(OUTPUT_DIR, f"report_{scan_id}.html"),
                ]:
                    if os.path.exists(artifact):
                        os.remove(artifact)

    def test_report_downloads(self):
        """Test HTML view and JSON download endpoints."""
        scan_id = "test_download_scan"
        json_path = os.path.join(OUTPUT_DIR, f"scan_{scan_id}.json")
        html_path = os.path.join(OUTPUT_DIR, f"report_{scan_id}.html")

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"target": "http://127.0.0.1", "score": 100}, f)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write("<!DOCTYPE html><html><body>Test Report</body></html>")

        try:
            # 1. Download JSON
            res_json = self.client.get(f"/api/report/json/{scan_id}")
            self.assertEqual(res_json.status_code, 200)
            self.assertIn("application/json", res_json.content_type)
            res_json.close()

            # 2. View HTML
            res_html = self.client.get(f"/report/{scan_id}")
            self.assertEqual(res_html.status_code, 200)
            self.assertIn("text/html", res_html.content_type)
            self.assertIn("Test Report", res_html.data.decode("utf-8"))
            res_html.close()
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)
            if os.path.exists(html_path):
                os.remove(html_path)

    def test_html_report_does_not_fall_back_to_another_scan(self):
        response = self.client.get("/report/unknown_scan_id")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
