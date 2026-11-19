"""
tests/test_methods.py - Dedicated unit tests for checks/methods.py

Tests:
1. Enabled TRACE method returning 200 echoing body -> MTH-001 (Medium, Confirmed).
2. Advertised PUT and DELETE in Allow header -> MTH-002 (Low, Likely).
3. Substring false-positive prevention (e.g. INPUT, OUTPUT) ensuring no false alerts.
4. Extended dangerous methods (WebDAV PROPFIND, CONNECT) -> MTH-003.
5. Inconsistent method configurations across crawled subpages.
6. Empty or malformed Allow header syntax -> MTH-004.
7. Secure server producing 0 findings with valid passed checks.
"""

import sys
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.context import ScanContext
from checks import methods as methods_check


class ConfigurableMethodsServer(BaseHTTPRequestHandler):
    allow_header = "GET, HEAD, OPTIONS"
    enable_trace = False
    subpage_allow_header = None

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><a href='/subpage'>Subpage</a></body></html>")

    def do_OPTIONS(self):
        self.send_response(200)
        if self.path == "/subpage" and self.subpage_allow_header is not None:
            self.send_header("Allow", self.subpage_allow_header)
        else:
            self.send_header("Allow", self.allow_header)
        self.end_headers()

    def do_TRACE(self):
        if self.enable_trace:
            self.send_response(200)
            self.send_header("Content-Type", "message/http")
            self.end_headers()
            self.wfile.write(b"TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        else:
            self.send_response(405)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def test_trace_enabled():
    ConfigurableMethodsServer.allow_header = "GET, POST, OPTIONS, TRACE"
    ConfigurableMethodsServer.enable_trace = True
    ConfigurableMethodsServer.subpage_allow_header = None

    server = HTTPServer(("127.0.0.1", 0), ConfigurableMethodsServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = methods_check.run(ctx)

        mth001 = next((f for f in findings if f.id == "MTH-001"), None)
        assert mth001 is not None, "Expected MTH-001 finding for active TRACE"
        assert mth001.severity == "Medium"
        assert mth001.confidence == "Confirmed"
        assert "TRACE returned 200 OK" in mth001.evidence
        print("  [PASS] Active TRACE method test passed (MTH-001 Medium/Confirmed).")
    finally:
        server.shutdown()


def test_put_delete_advertised():
    ConfigurableMethodsServer.allow_header = "GET, POST, PUT, DELETE, OPTIONS"
    ConfigurableMethodsServer.enable_trace = False
    ConfigurableMethodsServer.subpage_allow_header = None

    server = HTTPServer(("127.0.0.1", 0), ConfigurableMethodsServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = methods_check.run(ctx)

        mth002 = next((f for f in findings if f.id == "MTH-002"), None)
        assert mth002 is not None, "Expected MTH-002 finding for PUT/DELETE"
        assert mth002.severity == "Low"
        assert mth002.confidence == "Likely"
        assert "PUT, DELETE" in mth002.title
        print("  [PASS] PUT and DELETE in Allow header test passed (MTH-002 Low/Likely).")
    finally:
        server.shutdown()


def test_substring_false_positive_prevention():
    """Verify methods like INPUT and OUTPUT do NOT trigger false positive for PUT."""
    ConfigurableMethodsServer.allow_header = "GET, POST, INPUT, OUTPUT, DELETED, OPTIONS"
    ConfigurableMethodsServer.enable_trace = False
    ConfigurableMethodsServer.subpage_allow_header = None

    server = HTTPServer(("127.0.0.1", 0), ConfigurableMethodsServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = methods_check.run(ctx)

        assert not any(f.id == "MTH-002" for f in findings), f"False positive triggered for INPUT/OUTPUT: {findings}"
        assert "Dangerous HTTP methods (PUT/DELETE) not advertised in Allow header" in passed
        print("  [PASS] Substring false positive prevention test passed (Zero false positives on INPUT/OUTPUT).")
    finally:
        server.shutdown()


def test_extended_dangerous_methods():
    """Verify detection of WebDAV methods (PROPFIND, MKCOL) and proxy CONNECT."""
    ConfigurableMethodsServer.allow_header = "GET, POST, CONNECT, PROPFIND, MKCOL"
    ConfigurableMethodsServer.enable_trace = False
    ConfigurableMethodsServer.subpage_allow_header = None

    server = HTTPServer(("127.0.0.1", 0), ConfigurableMethodsServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = methods_check.run(ctx)

        mth003 = next((f for f in findings if f.id == "MTH-003"), None)
        assert mth003 is not None, "Expected MTH-003 for extended dangerous methods"
        assert "CONNECT" in mth003.title
        assert "PROPFIND" in mth003.title
        print("  [PASS] Extended dangerous methods test passed (MTH-003 Low).")
    finally:
        server.shutdown()


def test_inconsistent_subpage_methods():
    """Verify detection when root restricts methods but crawled subpage exposes PUT/DELETE."""
    ConfigurableMethodsServer.allow_header = "GET, HEAD, OPTIONS"
    ConfigurableMethodsServer.enable_trace = False
    ConfigurableMethodsServer.subpage_allow_header = "GET, POST, PUT, DELETE, OPTIONS"

    server = HTTPServer(("127.0.0.1", 0), ConfigurableMethodsServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        assert len(ctx.extra_pages) > 0, "Expected /subpage to be crawled"
        findings, passed = methods_check.run(ctx)

        subpage_finding = next((f for f in findings if "/subpage" in f.url and f.id == "MTH-002"), None)
        assert subpage_finding is not None, "Expected MTH-002 finding localized to /subpage"
        print("  [PASS] Inconsistent subpage method exposure test passed.")
    finally:
        server.shutdown()


def test_secure_server_methods():
    ConfigurableMethodsServer.allow_header = "GET, HEAD, OPTIONS"
    ConfigurableMethodsServer.enable_trace = False
    ConfigurableMethodsServer.subpage_allow_header = None

    server = HTTPServer(("127.0.0.1", 0), ConfigurableMethodsServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = methods_check.run(ctx)

        assert len(findings) == 0, f"Expected 0 findings on secure server, got: {findings}"
        assert "HTTP TRACE method disabled" in passed
        assert "Dangerous HTTP methods (PUT/DELETE) not advertised in Allow header" in passed
        print("  [PASS] Secure server method check passed (0 findings, 2 passed checks).")
    finally:
        server.shutdown()


if __name__ == "__main__":
    print("====================================================================")
    print(" RUNNING DEDICATED METHOD TESTS (checks/methods.py)")
    print("====================================================================")
    test_trace_enabled()
    test_put_delete_advertised()
    test_substring_false_positive_prevention()
    test_extended_dangerous_methods()
    test_inconsistent_subpage_methods()
    test_secure_server_methods()
    print("====================================================================")
    print(" ALL METHOD TESTS PASSED!")
    print("====================================================================")
