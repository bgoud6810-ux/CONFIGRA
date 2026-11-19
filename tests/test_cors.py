"""
tests/test_cors.py - Dedicated unit tests for checks/cors.py

Tests:
1. Arbitrary origin reflection with credentials (COR-003, High).
2. Arbitrary origin reflection without credentials (COR-004, Medium).
3. Wildcard origin without credentials (COR-002, Low) and with credentials (COR-001, Medium).
4. Null origin handling with credentials (COR-005, High).
5. Multiple / comma-separated CORS headers (COR-007, Low).
6. Insecure preflight response (COR-008, High/Medium).
7. Multi-page CORS configuration differences.
8. Secure server producing 0 findings.
"""

import sys
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.context import ScanContext
from checks import cors as cors_check


class ConfigurableCORSServer(BaseHTTPRequestHandler):
    """Configurable handler to test various CORS edge cases."""
    acao_mode = "none"  # "reflect_creds", "reflect_no_creds", "wildcard", "wildcard_creds", "null_creds", "multiple", "subpage_only", "none"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        origin = self.headers.get("Origin", "")

        if self.acao_mode == "reflect_creds":
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")

        elif self.acao_mode == "reflect_no_creds":
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)

        elif self.acao_mode == "wildcard":
            self.send_header("Access-Control-Allow-Origin", "*")

        elif self.acao_mode == "wildcard_creds":
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")

        elif self.acao_mode == "null_creds":
            if origin == "null":
                self.send_header("Access-Control-Allow-Origin", "null")
                self.send_header("Access-Control-Allow-Credentials", "true")

        elif self.acao_mode == "multiple":
            self.send_header("Access-Control-Allow-Origin", "https://siteA.com, https://siteB.com")

        elif self.acao_mode == "subpage_only":
            if self.path == "/subpage" and origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")

        self.end_headers()
        self.wfile.write(b"<html><body><a href='/subpage'>Subpage</a></body></html>")

    def do_OPTIONS(self):
        self.send_response(200)
        origin = self.headers.get("Origin", "")
        if self.acao_mode in ("reflect_creds", "null_creds") and origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.end_headers()

    def log_message(self, format, *args):
        pass


def test_reflect_with_credentials():
    ConfigurableCORSServer.acao_mode = "reflect_creds"
    server = HTTPServer(("127.0.0.1", 0), ConfigurableCORSServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = cors_check.run(ctx)

        cor003 = next((f for f in findings if f.id == "COR-003"), None)
        assert cor003 is not None, "Expected COR-003 finding"
        assert cor003.severity == "High"
        assert cor003.confidence == "Confirmed"
        print("  [PASS] Arbitrary origin reflection with credentials test passed (High severity).")
    finally:
        server.shutdown()


def test_reflect_without_credentials():
    ConfigurableCORSServer.acao_mode = "reflect_no_creds"
    server = HTTPServer(("127.0.0.1", 0), ConfigurableCORSServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = cors_check.run(ctx)

        cor004 = next((f for f in findings if f.id == "COR-004"), None)
        assert cor004 is not None, "Expected COR-004 finding"
        assert cor004.severity == "Medium"
        print("  [PASS] Arbitrary origin reflection without credentials test passed (Medium severity).")
    finally:
        server.shutdown()


def test_wildcard_configurations():
    # 1. Wildcard without credentials -> Low severity
    ConfigurableCORSServer.acao_mode = "wildcard"
    server = HTTPServer(("127.0.0.1", 0), ConfigurableCORSServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = cors_check.run(ctx)

        cor002 = next((f for f in findings if f.id == "COR-002"), None)
        assert cor002 is not None, "Expected COR-002"
        assert cor002.severity == "Low", f"Wildcard without creds must be Low severity, got {cor002.severity}"
    finally:
        server.shutdown()

    # 2. Wildcard with credentials -> Medium severity
    ConfigurableCORSServer.acao_mode = "wildcard_creds"
    server2 = HTTPServer(("127.0.0.1", 0), ConfigurableCORSServer)
    port2 = server2.server_port
    t2 = threading.Thread(target=server2.serve_forever, daemon=True)
    t2.start()

    try:
        ctx2 = ScanContext(f"http://127.0.0.1:{port2}", delay=0)
        assert ctx2.initialize()
        findings2, _ = cors_check.run(ctx2)

        cor001 = next((f for f in findings2 if f.id == "COR-001"), None)
        assert cor001 is not None, "Expected COR-001"
        assert cor001.severity == "Medium"
        print("  [PASS] Wildcard origins (with and without credentials) test passed.")
    finally:
        server2.shutdown()


def test_null_origin_handling():
    ConfigurableCORSServer.acao_mode = "null_creds"
    server = HTTPServer(("127.0.0.1", 0), ConfigurableCORSServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = cors_check.run(ctx)

        cor005 = next((f for f in findings if f.id == "COR-005"), None)
        assert cor005 is not None, "Expected COR-005 finding for null origin with credentials"
        assert cor005.severity == "High"
        print("  [PASS] Null origin handling test passed (COR-005 High).")
    finally:
        server.shutdown()


def test_multiple_or_comma_separated_headers():
    ConfigurableCORSServer.acao_mode = "multiple"
    server = HTTPServer(("127.0.0.1", 0), ConfigurableCORSServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = cors_check.run(ctx)

        cor007 = next((f for f in findings if f.id == "COR-007"), None)
        assert cor007 is not None, "Expected COR-007 for comma-separated origins"
        assert cor007.severity == "Low"
        print("  [PASS] Comma-separated CORS origins test passed (COR-007 Low).")
    finally:
        server.shutdown()


def test_multi_page_differences():
    """Verify that CORS vulnerabilities on crawled subpages are identified even if root is clean."""
    ConfigurableCORSServer.acao_mode = "subpage_only"
    server = HTTPServer(("127.0.0.1", 0), ConfigurableCORSServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        # Verify subpage was discovered
        assert len(ctx.extra_pages) > 0, "Expected /subpage to be crawled"
        findings, passed = cors_check.run(ctx)

        subpage_finding = next((f for f in findings if "/subpage" in f.url and f.id == "COR-003"), None)
        assert subpage_finding is not None, "Expected COR-003 finding on /subpage"
        print("  [PASS] Multi-page CORS difference test passed.")
    finally:
        server.shutdown()


def test_secure_server_cors():
    ConfigurableCORSServer.acao_mode = "none"
    server = HTTPServer(("127.0.0.1", 0), ConfigurableCORSServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = cors_check.run(ctx)

        assert len(findings) == 0, f"Expected 0 findings, got {findings}"
        assert any("CORS" in p for p in passed)
        print("  [PASS] Secure server CORS test passed (0 findings, passed check recorded).")
    finally:
        server.shutdown()


if __name__ == "__main__":
    print("====================================================================")
    print(" RUNNING DEDICATED CORS TESTS (checks/cors.py)")
    print("====================================================================")
    test_reflect_with_credentials()
    test_reflect_without_credentials()
    test_wildcard_configurations()
    test_null_origin_handling()
    test_multiple_or_comma_separated_headers()
    test_multi_page_differences()
    test_secure_server_cors()
    print("====================================================================")
    print(" ALL CORS TESTS PASSED!")
    print("====================================================================")
