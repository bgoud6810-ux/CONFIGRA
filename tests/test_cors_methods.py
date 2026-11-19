"""
tests/test_cors_methods.py - Verification of CORS and HTTP Methods checks

Tests against local HTTP servers to verify detection of:
  1. Arbitrary Origin reflection with credentials.
  2. Enabled TRACE method and advertised dangerous methods (PUT/DELETE).
  3. Proper pass behavior on secure servers.

Run with:
    python -m tests.test_cors_methods
"""

import sys
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.context import ScanContext
from checks import cors, methods


class InsecureServerHandler(BaseHTTPRequestHandler):
    """Server with vulnerable CORS and dangerous methods enabled."""

    def do_GET(self):
        self.send_response(200)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Insecure Server Response")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS, TRACE")
        self.end_headers()

    def do_TRACE(self):
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.end_headers()
        self.wfile.write(b"TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n")

    def log_message(self, format, *args):
        pass


class SecureServerHandler(BaseHTTPRequestHandler):
    """Server with restricted methods and no CORS exposure."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Secure Server Response")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.end_headers()

    def do_TRACE(self):
        self.send_response(405)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def run_tests():
    print("[*] Starting Phase 3 CORS & HTTP Methods Tests...")

    # Test 1: Insecure Server
    server_bad = HTTPServer(("127.0.0.1", 0), InsecureServerHandler)
    port_bad = server_bad.server_port
    t1 = threading.Thread(target=server_bad.serve_forever, daemon=True)
    t1.start()

    ctx_bad = ScanContext(f"http://127.0.0.1:{port_bad}", delay=0)
    ctx_bad.initialize()

    cors_bad, _ = cors.run(ctx_bad)
    methods_bad, _ = methods.run(ctx_bad)
    server_bad.shutdown()

    # Assert CORS reflected origin + credentials
    cor_finding = next((f for f in cors_bad if f.id == "COR-003"), None)
    assert cor_finding is not None, "FAIL: Expected COR-003 finding on insecure server"
    assert cor_finding.severity == "High", f"FAIL: Expected High severity, got {cor_finding.severity}"
    print("  [PASS] Insecure server correctly triggered High-severity CORS reflection finding.")

    # Assert TRACE and PUT/DELETE detection
    trace_finding = next((f for f in methods_bad if f.id == "MTH-001"), None)
    assert trace_finding is not None, "FAIL: Expected MTH-001 (TRACE enabled) finding"
    assert trace_finding.confidence == "Confirmed", f"FAIL: Expected Confirmed confidence, got {trace_finding.confidence}"
    print("  [PASS] Insecure server correctly triggered Confirmed TRACE method finding.")

    methods_finding = next((f for f in methods_bad if f.id == "MTH-002"), None)
    assert methods_finding is not None, "FAIL: Expected MTH-002 (PUT/DELETE in Allow) finding"
    assert methods_finding.confidence == "Likely", f"FAIL: Expected Likely confidence, got {methods_finding.confidence}"
    print("  [PASS] Insecure server correctly flagged PUT/DELETE in Allow header with Likely confidence.")

    # Test 2: Secure Server
    server_good = HTTPServer(("127.0.0.1", 0), SecureServerHandler)
    port_good = server_good.server_port
    t2 = threading.Thread(target=server_good.serve_forever, daemon=True)
    t2.start()

    ctx_good = ScanContext(f"http://127.0.0.1:{port_good}", delay=0)
    ctx_good.initialize()

    cors_good, passed_cors = cors.run(ctx_good)
    methods_good, passed_methods = methods.run(ctx_good)
    server_good.shutdown()

    assert len(cors_good) == 0, f"FAIL: Secure server generated unexpected CORS findings: {cors_good}"
    assert len(methods_good) == 0, f"FAIL: Secure server generated unexpected method findings: {methods_good}"
    assert any("CORS" in p for p in passed_cors), "FAIL: Expected CORS passed check"
    assert any("TRACE" in p for p in passed_methods), "FAIL: Expected TRACE passed check"
    print("  [PASS] Secure server generated 0 false positives for CORS and HTTP methods.")

    print("\n[PHASE 3 RESULT: PASS]")


if __name__ == "__main__":
    run_tests()
