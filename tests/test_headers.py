"""
tests/test_headers.py - Dedicated test suite for checks/headers.py

Tests:
1. Missing security headers detection on plain HTTP target.
2. Weak security headers detection (unsafe-inline, unsafe-eval, standalone wildcard, deprecated ALLOW-FROM, unsafe-url).
3. Strong security headers validation (including subdomain wildcards like *.example.com) ensuring ZERO false positives.
4. CSP Report-Only mode detection.
5. Multi-page header inspection across crawled pages.
"""

import sys
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.context import ScanContext
from checks import headers as headers_check


class MockHeaderServerHandler(BaseHTTPRequestHandler):
    """Configurable handler to test headers."""
    headers_to_send = {}
    extra_page_headers = {}

    def do_GET(self):
        self.send_response(200)
        if self.path == "/subpage" and self.extra_page_headers:
            for k, v in self.extra_page_headers.items():
                self.send_header(k, v)
        else:
            for k, v in self.headers_to_send.items():
                self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><a href='/subpage'>Subpage</a></body></html>")

    def log_message(self, format, *args):
        pass


def test_missing_headers():
    MockHeaderServerHandler.headers_to_send = {}
    MockHeaderServerHandler.extra_page_headers = {}
    server = HTTPServer(("127.0.0.1", 0), MockHeaderServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = headers_check.run(ctx)

        ids = [f.id for f in findings]
        assert "HDR-003" in ids, "Expected HDR-003 (Missing CSP)"
        assert "HDR-005" in ids, "Expected HDR-005 (Missing Clickjacking protection)"
        assert "HDR-006" in ids, "Expected HDR-006 (Missing X-Content-Type-Options)"
        assert "HDR-007" in ids, "Expected HDR-007 (Missing Referrer-Policy)"
        assert "HDR-008" in ids, "Expected HDR-008 (Missing Permissions-Policy)"
        assert "HSTS not applicable on HTTP" in passed, "Expected HTTP HSTS exemption in passed checks"
        print("  [PASS] Missing headers test passed.")
    finally:
        server.shutdown()


def test_weak_headers():
    MockHeaderServerHandler.headers_to_send = {
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'; script-src * 'unsafe-eval'",
        "X-Frame-Options": "ALLOW-FROM https://trusted.com",
        "X-Content-Type-Options": "sniff",
        "Referrer-Policy": "unsafe-url",
        "Permissions-Policy": "geolocation=*"
    }
    MockHeaderServerHandler.extra_page_headers = {}
    server = HTTPServer(("127.0.0.1", 0), MockHeaderServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = headers_check.run(ctx)

        ids = [f.id for f in findings]
        assert "HDR-004" in ids, "Expected HDR-004 (Weak CSP due to unsafe-inline and wildcard)"
        csp_finding = next(f for f in findings if f.id == "HDR-004")
        assert "unsafe-inline" in csp_finding.evidence
        assert "unsafe-eval" in csp_finding.evidence
        assert "standalone wildcard '*'" in csp_finding.evidence

        assert "HDR-005" in ids, "Expected HDR-005 (Obsolete ALLOW-FROM)"
        assert "HDR-006" in ids, "Expected HDR-006 (Invalid X-Content-Type-Options)"
        assert "HDR-007" in ids, "Expected HDR-007 (Insecure Referrer-Policy)"
        print("  [PASS] Weak headers detection test passed.")
    finally:
        server.shutdown()


def test_strong_headers_and_subdomain_wildcard():
    """Verify that legitimate subdomain wildcards (*.example.com) do NOT cause false positives."""
    MockHeaderServerHandler.headers_to_send = {
        "Content-Security-Policy": "default-src 'self' *.example.com; script-src 'self' *.cdn.net; object-src 'none'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
    }
    MockHeaderServerHandler.extra_page_headers = {}
    server = HTTPServer(("127.0.0.1", 0), MockHeaderServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = headers_check.run(ctx)

        assert len(findings) == 0, f"Expected 0 findings on strong headers, got: {[f.id for f in findings]}"
        assert "Content Security Policy active" in passed
        assert "Clickjacking protection enabled" in passed
        assert "X-Content-Type-Options present" in passed
        assert "Referrer-Policy configured" in passed
        assert "Permissions-Policy present" in passed
        print("  [PASS] Strong headers & subdomain wildcard test passed (Zero false positives).")
    finally:
        server.shutdown()


def test_csp_report_only():
    MockHeaderServerHandler.headers_to_send = {
        "Content-Security-Policy-Report-Only": "default-src 'self'",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()"
    }
    MockHeaderServerHandler.extra_page_headers = {}
    server = HTTPServer(("127.0.0.1", 0), MockHeaderServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = headers_check.run(ctx)

        ids = [f.id for f in findings]
        assert "HDR-003" in ids, "Expected HDR-003 for Report-Only CSP"
        report_finding = next(f for f in findings if f.id == "HDR-003")
        assert "Report-Only" in report_finding.title
        print("  [PASS] CSP Report-Only detection test passed.")
    finally:
        server.shutdown()


def test_multi_page_headers():
    """Verify that header flaws on crawled subpages are identified."""
    # Home has strong headers, but /subpage is missing X-Content-Type-Options
    MockHeaderServerHandler.headers_to_send = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()"
    }
    MockHeaderServerHandler.extra_page_headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()"
    }
    server = HTTPServer(("127.0.0.1", 0), MockHeaderServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = headers_check.run(ctx)

        subpage_findings = [f for f in findings if "/subpage" in f.url]
        assert any(f.id == "HDR-006" for f in subpage_findings), "Expected HDR-006 on /subpage"
        print("  [PASS] Multi-page crawled header inspection test passed.")
    finally:
        server.shutdown()


if __name__ == "__main__":
    print("====================================================================")
    print(" RUNNING DEDICATED HEADER TESTS (checks/headers.py)")
    print("====================================================================")
    test_missing_headers()
    test_weak_headers()
    test_strong_headers_and_subdomain_wildcard()
    test_csp_report_only()
    test_multi_page_headers()
    print("====================================================================")
    print(" ALL HEADER TESTS PASSED!")
    print("====================================================================")
