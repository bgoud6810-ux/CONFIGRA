import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import OUTPUT_DIR, app
from core.models import SCAN_MODE_AUTHORIZED_ASSESSMENT
from core.safety import validate_url_target
from scanner import run_scan


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _send(self, code=200, headers=None, body=b"ok"):
        headers = headers or {}
        body = body if isinstance(body, (bytes, bytearray)) else str(body).encode()
        self.send_response(code)
        headers.setdefault("Content-Type", "text/html; charset=utf-8")
        headers.setdefault("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass


class H403(_Base):
    def do_GET(self):
        self._send(403, {}, b"<html><body>Forbidden</body></html>")


class H429(_Base):
    def do_GET(self):
        self._send(429, {"Retry-After": "5"}, b"rate limited")


class H500(_Base):
    def do_GET(self):
        self._send(500, {"Server": "origin"}, b"<html><body>Internal Server Error</body></html>")


class Slow(_Base):
    def do_GET(self):
        time.sleep(3)
        self._send(200, {}, b"late")


class Ok(_Base):
    def do_GET(self):
        self._send(
            200,
            {
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            },
            b"<html><body>ok</body></html>",
        )


def _start(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", _free_port()), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, httpd.server_address[1]


def _assert_all_not_tested(result, test):
    check_results = result.get("check_results") or []
    test.assertTrue(check_results, "expected check_results")
    test.assertTrue(all((c.get("status") or "").upper() == "NOT TESTED" for c in check_results))
    test.assertEqual(result.get("findings"), [])


class RealtimeIntegrityTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_dns_invalid_prevalidation_refused_without_persisted_scan(self):
        before = set(os.listdir(OUTPUT_DIR)) if os.path.isdir(OUTPUT_DIR) else set()
        import core.safety as safety

        original_gai = socket.getaddrinfo

        def fail_gai(host, *a, **k):
            if host == "dns-invalid.test":
                raise socket.gaierror("simulated dns failure")
            return original_gai(host, *a, **k)

        with mock.patch("core.safety.socket.getaddrinfo", side_effect=fail_gai):
            v = safety.validate_url_target("http://dns-invalid.test/", True, scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT)
            self.assertFalse(v.ok)
            self.assertIn("Failed to resolve hostname", v.reason)
            with self.assertRaises(PermissionError):
                run_scan(
                    target_url="http://dns-invalid.test/",
                    output_html=None,
                    output_json=None,
                    i_have_permission=True,
                    scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                    verbose=False,
                )
            resp = self.client.post(
                "/api/scan",
                json={
                    "target_url": "http://dns-invalid.test/",
                    "scan_mode": SCAN_MODE_AUTHORIZED_ASSESSMENT,
                    "i_have_permission": True,
                },
            )
            self.assertEqual(resp.status_code, 400)
            body = resp.get_json() or {}
            error_text = body.get("error", "")
            # The API now gives a responsible existence answer (NXDOMAIN confirmed by
            # public DNS) or the underlying resolution failure, depending on provider state.
            self.assertTrue(
                "Failed to resolve hostname" in error_text
                or "NXDOMAIN" in error_text
                or "does not exist" in error_text,
                f"Unexpected refusal message: {error_text!r}",
            )

        after = set(os.listdir(OUTPUT_DIR)) if os.path.isdir(OUTPUT_DIR) else set()
        self.assertEqual(before, after)

    def test_resolvable_but_unreachable_connection_failure_is_failed_not_success(self):
        # Use a likely closed local port; DNS/connectivity to 127.0.0.1 is local and genuine.
        result = run_scan(
            target_url="http://127.0.0.1:1/",
            output_html=None,
            output_json=None,
            delay=0.0,
            timeout=1.0,
            i_have_permission=True,
            scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
            verbose=False,
        )
        self.assertEqual(result.get("status"), "failed")
        self.assertEqual(result.get("grade"), "N/A")
        self.assertEqual(result.get("score"), 0)
        self.assertEqual(result.get("dns_outcome"), "resolved")
        self.assertIn(result.get("connection_outcome"), ("failed", "attempted", "unknown"))
        self.assertIn(result.get("http_outcome"), ("request_failed", "no_response", "unknown", "not_attempted"))
        _assert_all_not_tested(result, self)

    def test_timeout_is_failed_or_incomplete_not_success(self):
        httpd, port = _start(Slow)
        try:
            result = run_scan(
                target_url=f"http://127.0.0.1:{port}/",
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=0.5,
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                verbose=False,
            )
            self.assertIn(result.get("status"), ("failed", "cancelled"))
            self.assertNotEqual(result.get("status"), "completed")
            self.assertEqual(result.get("grade"), "N/A")
            self.assertEqual(result.get("score"), 0)
            _assert_all_not_tested(result, self)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_http_403_is_observed_restricted_not_tested(self):
        httpd, port = _start(H403)
        try:
            result = run_scan(
                target_url=f"http://127.0.0.1:{port}/",
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=2.0,
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                verbose=False,
            )
            self.assertEqual(result.get("status"), "failed")
            self.assertEqual(result.get("http_outcome"), "http_403")
            self.assertEqual(result.get("grade"), "N/A")
            _assert_all_not_tested(result, self)
            blob = " ".join((result.get("errors") or []) + (result.get("scan_limitations") or [])).lower()
            self.assertTrue("403" in blob or "forbidden" in blob or "restricted" in blob)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_http_429_is_rate_limited_not_tested(self):
        httpd, port = _start(H429)
        try:
            result = run_scan(
                target_url=f"http://127.0.0.1:{port}/",
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=2.0,
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                verbose=False,
            )
            self.assertEqual(result.get("status"), "failed")
            self.assertEqual(result.get("grade"), "N/A")
            _assert_all_not_tested(result, self)
            events = result.get("rate_limit_events") or []
            self.assertTrue(events)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_http_500_is_observed_with_limited_origin_checks(self):
        httpd, port = _start(H500)
        try:
            result = run_scan(
                target_url=f"http://127.0.0.1:{port}/",
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=2.0,
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                verbose=False,
            )
            self.assertEqual(result.get("status"), "failed")
            self.assertEqual(result.get("http_outcome"), "http_500")
            self.assertEqual(result.get("grade"), "N/A")
            _assert_all_not_tested(result, self)
            blob = " ".join((result.get("errors") or []) + (result.get("scan_limitations") or [])).lower()
            self.assertTrue("500" in blob or "error state" in blob or "not reliably testable" in blob)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_valid_reachable_target_produces_genuine_completed_scan(self):
        httpd, port = _start(Ok)
        try:
            result = run_scan(
                target_url=f"http://127.0.0.1:{port}/",
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=2.0,
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                verbose=False,
            )
            self.assertEqual(result.get("status"), "completed")
            self.assertEqual(result.get("dns_outcome"), "resolved")
            self.assertIn(result.get("http_outcome"), ("http_200",))
            self.assertIsInstance(result.get("check_results"), list)
            self.assertTrue(any(c.get("status") in ("PASS", "FAIL", "WARNING", "NOT TESTED") for c in result.get("check_results") or []))
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_json_and_html_reports_match_failed_scan_state(self):
        httpd, port = _start(H403)
        json_path = os.path.join(OUTPUT_DIR, "scan_integrity_failed.json")
        html_path = os.path.join(OUTPUT_DIR, "report_integrity_failed.html")
        try:
            result = run_scan(
                target_url=f"http://127.0.0.1:{port}/",
                output_html=html_path,
                output_json=json_path,
                delay=0.0,
                timeout=2.0,
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                verbose=False,
                scan_id="integrity_failed",
            )
            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(html_path))
            with open(json_path, "r", encoding="utf-8") as f:
                disk = json.load(f)
            with open(html_path, "r", encoding="utf-8") as f:
                html = f.read()
            self.assertEqual(disk.get("status"), "failed")
            self.assertEqual(disk.get("grade"), "N/A")
            self.assertEqual(disk.get("scan_id"), "integrity_failed")
            self.assertIn("integrity_failed", html)
            self.assertIn("N/A", html)
            self.assertIn("DNS outcome", html)
            self.assertIn("HTTP 403", html)
            self.assertNotIn("Strong configuration", html)
        finally:
            httpd.shutdown()
            httpd.server_close()
            for p in (json_path, html_path):
                try:
                    os.remove(p)
                except Exception:
                    pass

    def test_results_and_json_download_do_not_reuse_other_scan(self):
        # Missing scan should not fall back to another report.
        r = self.client.get("/report/no_such_scan_id")
        self.assertEqual(r.status_code, 404)
        r2 = self.client.get("/api/report/json/no_such_scan_id")
        self.assertEqual(r2.status_code, 404)
        r3 = self.client.get("/results/definitely_missing_scan")
        self.assertEqual(r3.status_code, 200)
        html = r3.data.decode("utf-8", "ignore")
        self.assertIn("not found", html.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
