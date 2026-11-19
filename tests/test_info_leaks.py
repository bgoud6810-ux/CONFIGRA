"""
tests/test_info_leaks.py - Dedicated unit tests for checks/info_leaks.py

Tests:
1. Server version disclosure (Server: Apache/2.4.52) -> INF-001 (Low).
2. Clean server banner (Server: Apache) -> Suppressed, 0 findings, passed check.
3. Technology disclosure (X-Powered-By: PHP/8.1) -> INF-002 (Low).
4. ASP.NET version headers (X-AspNet-Version) -> INF-003 (Low).
5. Internal hostname disclosure (X-Backend-Server) -> INF-005 (Low).
6. Debug header disclosure (X-Debug-Token) -> INF-007 (Medium).
7. Stack trace / detailed error disclosure in body -> INF-008 (Medium) with password redaction.
8. False-positive resistance: standard prose mentioning 'error' or 'python' not flagged.
9. Multi-page crawled page information leak detection.
10. Hardened server -> 0 findings, all passed checks recorded.
"""

import sys
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.context import ScanContext
from checks import info_leaks as info_leaks_check


class ConfigurableInfoLeakServer(BaseHTTPRequestHandler):
    server_version = "Apache"
    sys_version = ""
    headers_to_send = {}
    subpage_headers = {}
    body_to_send = b"<html><body>Hello World <a href='/subpage'>Subpage</a></body></html>"
    subpage_body = b"<html><body>Subpage content</body></html>"

    def version_string(self):
        # Override BaseHTTPRequestHandler default which injects BaseHTTP/0.6 Python/3.x
        val = self.headers_to_send.get("Server", "Apache")
        return val

    def send_response(self, code, message=None):
        # Prevent default Server and Date injection from overwriting custom test headers
        self.log_request(code)
        self.send_response_only(code, message)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        if self.path == "/subpage" and self.subpage_headers:
            for k, v in self.subpage_headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(self.subpage_body)
        else:
            for k, v in self.headers_to_send.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(self.body_to_send)

    def log_message(self, format, *args):
        pass


def test_server_version_disclosure():
    ConfigurableInfoLeakServer.headers_to_send = {"Server": "Apache/2.4.52 (Ubuntu)"}
    ConfigurableInfoLeakServer.subpage_headers = {}
    ConfigurableInfoLeakServer.body_to_send = b"OK"

    server = HTTPServer(("127.0.0.1", 0), ConfigurableInfoLeakServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = info_leaks_check.run(ctx)

        inf001 = next((f for f in findings if f.id == "INF-001"), None)
        assert inf001 is not None, "Expected INF-001 for version disclosure"
        assert inf001.severity == "Low"
        assert "Apache/2.4.52" in inf001.evidence
        print("  [PASS] Server version disclosure test passed (INF-001 Low).")
    finally:
        server.shutdown()


def test_server_banner_without_version_is_safe():
    ConfigurableInfoLeakServer.headers_to_send = {"Server": "Apache"}
    ConfigurableInfoLeakServer.subpage_headers = {}
    ConfigurableInfoLeakServer.body_to_send = b"OK"

    server = HTTPServer(("127.0.0.1", 0), ConfigurableInfoLeakServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = info_leaks_check.run(ctx)

        assert not any(f.id == "INF-001" for f in findings), "Server banner without version must not be flagged"
        assert "Server header does not expose software version" in passed
        print("  [PASS] Server banner without version treated as safe passed.")
    finally:
        server.shutdown()


def test_technology_and_internal_headers():
    ConfigurableInfoLeakServer.headers_to_send = {
        "X-Powered-By": "PHP/8.1.2",
        "X-AspNet-Version": "4.0.30319",
        "X-Backend-Server": "prod-web-node03.internal",
        "X-Generator": "WordPress 6.4.2",
        "X-Debug-Token": "ab9012ff"
    }
    ConfigurableInfoLeakServer.subpage_headers = {}
    ConfigurableInfoLeakServer.body_to_send = b"OK"

    server = HTTPServer(("127.0.0.1", 0), ConfigurableInfoLeakServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = info_leaks_check.run(ctx)

        ids = {f.id for f in findings}
        assert "INF-002" in ids, "Expected INF-002 (X-Powered-By)"
        assert "INF-003" in ids, "Expected INF-003 (X-AspNet-Version)"
        assert "INF-005" in ids, "Expected INF-005 (X-Backend-Server)"
        assert "INF-006" in ids, "Expected INF-006 (X-Generator)"
        assert "INF-007" in ids, "Expected INF-007 (X-Debug-Token)"

        debug_finding = next(f for f in findings if f.id == "INF-007")
        assert debug_finding.severity == "Medium"
        print("  [PASS] Technology, internal headers, and debug headers test passed.")
    finally:
        server.shutdown()


def test_stack_trace_and_secret_redaction():
    ConfigurableInfoLeakServer.headers_to_send = {}
    ConfigurableInfoLeakServer.subpage_headers = {}
    # Simulate a Python stack trace containing a sensitive database password
    ConfigurableInfoLeakServer.body_to_send = (
        b"<html><body><h1>Internal Server Error</h1>"
        b"<pre>Traceback (most recent call last):\n"
        b"  File \"/app/controllers/user.py\", line 124, in login\n"
        b"    db.connect(user='admin', password='SuperSecretPassword123!')\n"
        b"ValueError: connection refused</pre></body></html>"
    )

    server = HTTPServer(("127.0.0.1", 0), ConfigurableInfoLeakServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = info_leaks_check.run(ctx)

        inf008 = next((f for f in findings if f.id == "INF-008"), None)
        assert inf008 is not None, "Expected INF-008 for stack trace disclosure"
        assert inf008.severity == "Medium"
        assert "Python stack trace" in inf008.title
        # Verify secret was redacted
        assert "SuperSecretPassword123!" not in inf008.evidence, "FAIL: Secret password was not redacted!"
        assert "***REDACTED***" in inf008.evidence
        print("  [PASS] Stack trace disclosure and secret redaction test passed (INF-008 Medium).")
    finally:
        server.shutdown()


def test_false_positive_resistance():
    """Verify normal prose discussing errors is NOT flagged as stack trace."""
    ConfigurableInfoLeakServer.headers_to_send = {}
    ConfigurableInfoLeakServer.subpage_headers = {}
    ConfigurableInfoLeakServer.body_to_send = (
        b"<html><body><p>Welcome to our tech blog. Today we discuss Python error handling and how to catch exceptions cleanly.</p></body></html>"
    )

    server = HTTPServer(("127.0.0.1", 0), ConfigurableInfoLeakServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = info_leaks_check.run(ctx)

        assert not any(f.id == "INF-008" for f in findings), f"False positive triggered for normal prose: {findings}"
        print("  [PASS] False-positive resistance on normal prose test passed.")
    finally:
        server.shutdown()


def test_multi_page_info_leak():
    """Verify leaks on crawled subpages are identified even if root is clean."""
    ConfigurableInfoLeakServer.headers_to_send = {}  # Root is clean
    ConfigurableInfoLeakServer.body_to_send = b"<html><body><a href='/subpage'>Subpage</a></body></html>"
    ConfigurableInfoLeakServer.subpage_headers = {"X-Powered-By": "Express"}
    ConfigurableInfoLeakServer.subpage_body = b"Subpage"

    server = HTTPServer(("127.0.0.1", 0), ConfigurableInfoLeakServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        assert len(ctx.extra_pages) > 0, "Expected /subpage to be crawled"
        findings, passed = info_leaks_check.run(ctx)

        subpage_finding = next((f for f in findings if "/subpage" in f.url and f.id == "INF-002"), None)
        assert subpage_finding is not None, "Expected INF-002 localized to /subpage"
        print("  [PASS] Multi-page crawled information leak test passed.")
    finally:
        server.shutdown()


def test_hardened_server_info_leaks():
    ConfigurableInfoLeakServer.headers_to_send = {"Server": "SecureApp"}
    ConfigurableInfoLeakServer.subpage_headers = {}
    ConfigurableInfoLeakServer.body_to_send = b"<!DOCTYPE html><html><body>Secure App</body></html>"

    server = HTTPServer(("127.0.0.1", 0), ConfigurableInfoLeakServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = info_leaks_check.run(ctx)

        assert len(findings) == 0, f"Expected 0 findings on hardened server, got: {findings}"
        assert "Server header does not expose software version" in passed
        assert "X-Powered-By header suppressed" in passed
        assert "ASP.NET version headers suppressed" in passed
        assert "No debug headers or stack traces exposed" in passed
        print("  [PASS] Hardened server info leaks test passed (0 findings, 4 passed checks).")
    finally:
        server.shutdown()


if __name__ == "__main__":
    print("====================================================================")
    print(" RUNNING DEDICATED INFO LEAKS TESTS (checks/info_leaks.py)")
    print("====================================================================")
    test_server_version_disclosure()
    test_server_banner_without_version_is_safe()
    test_technology_and_internal_headers()
    test_stack_trace_and_secret_redaction()
    test_false_positive_resistance()
    test_multi_page_info_leak()
    test_hardened_server_info_leaks()
    print("====================================================================")
    print(" ALL INFO LEAKS TESTS PASSED!")
    print("====================================================================")
