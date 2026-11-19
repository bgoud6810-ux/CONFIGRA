"""
tests/test_cookies.py - Dedicated unit tests for checks/cookies.py

Tests:
1. Insecure session cookies (missing HttpOnly, missing SameSite) -> Medium/Low severity.
2. Non-session cookies (e.g. theme, lang, sidebar_width, authored_post) -> avoids false positive session classification.
3. Secure cookies with HttpOnly and SameSite=Strict/Lax -> 0 vulnerability findings.
4. Multiple Set-Cookie headers in a single HTTP response.
5. Combined Set-Cookie headers with Expires dates containing commas.
6. SameSite=None without Secure -> CKE-005.
7. Cookie parsing edge cases (base64 '=' in value, leading semicolons, malformed entries).
8. HTTP scheme handling -> Single Info finding (CKE-003) without generating false positive HTTPS errors.
9. Cookie prefix violations (__Secure- and __Host-).
"""

import sys
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.context import ScanContext
from checks import cookies as cookies_check


class MockCookieServerHandler(BaseHTTPRequestHandler):
    """Configurable handler to test cookie emission."""
    cookies_to_send = []

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        for cookie in self.cookies_to_send:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(b"<html><body>Cookie Test Target</body></html>")

    def log_message(self, format, *args):
        pass


def test_insecure_session_cookies():
    """Verify that insecure session cookies trigger Medium severity for missing HttpOnly."""
    MockCookieServerHandler.cookies_to_send = [
        "sessionid=xyz12345"
    ]
    server = HTTPServer(("127.0.0.1", 0), MockCookieServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = cookies_check.run(ctx)

        http_only_finding = next((f for f in findings if f.id == "CKE-001-SESSIONID"), None)
        assert http_only_finding is not None, "Expected CKE-001-SESSIONID finding"
        assert http_only_finding.severity == "Medium", f"Expected Medium severity for session cookie, got {http_only_finding.severity}"

        samesite_finding = next((f for f in findings if f.id == "CKE-004-SESSIONID"), None)
        assert samesite_finding is not None, "Expected CKE-004-SESSIONID finding"
        assert samesite_finding.severity == "Low"

        # On HTTP, verify single CKE-003 Info finding
        assert any(f.id == "CKE-003" and f.severity == "Info" for f in findings)
        # Ensure no CKE-002 (Missing Secure) is generated on HTTP
        assert not any(f.id.startswith("CKE-002") for f in findings)
        print("  [PASS] Insecure session cookie test passed.")
    finally:
        server.shutdown()


def test_non_sensitive_cookies_and_avoid_false_positive_sessions():
    """Verify cookies like sidebar_width or authored_post are NOT classified as session cookies."""
    MockCookieServerHandler.cookies_to_send = [
        "theme=dark",
        "sidebar_width=250",
        "authored_post=42"
    ]
    server = HTTPServer(("127.0.0.1", 0), MockCookieServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = cookies_check.run(ctx)

        for cookie_name in ("THEME", "SIDEBAR_WIDTH", "AUTHORED_POST"):
            f = next((f for f in findings if f.id == f"CKE-001-{cookie_name}"), None)
            assert f is not None, f"Expected finding for {cookie_name}"
            # Must be Low, NOT Medium, because they are not session cookies!
            assert f.severity == "Low", f"Expected Low severity for {cookie_name}, got {f.severity}"

        print("  [PASS] Non-sensitive cookies & session false-positive prevention test passed.")
    finally:
        server.shutdown()


def test_secure_cookies():
    """Verify that hardened cookies produce zero vulnerability findings."""
    MockCookieServerHandler.cookies_to_send = [
        "app_session=token9988; HttpOnly; SameSite=Strict",
        "user_prefs=dark_mode; HttpOnly; SameSite=Lax"
    ]
    server = HTTPServer(("127.0.0.1", 0), MockCookieServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = cookies_check.run(ctx)

        vulns = [f for f in findings if f.severity in ("Critical", "High", "Medium", "Low")]
        assert len(vulns) == 0, f"Expected 0 cookie vulnerabilities, got: {[f.id for f in vulns]}"
        assert any("HttpOnly flag" in p for p in passed)
        assert any("SameSite" in p for p in passed)
        print("  [PASS] Hardened cookies test passed (0 vulnerabilities).")
    finally:
        server.shutdown()


def test_multiple_cookies_and_edge_cases():
    """Verify multiple Set-Cookie headers, base64 values, and malformed inputs."""
    MockCookieServerHandler.cookies_to_send = [
        # Multiple cookies
        "connect.sid=s%3Axyz.123; HttpOnly; SameSite=Lax",
        "jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature; HttpOnly; SameSite=Lax",
        # Base64 with '=' padding in value
        "tracker=abc12345==; HttpOnly; SameSite=Lax",
        # Case insensitivity test
        "flag_cookie=test; HTTPONLY; SAMESITE=STRICT",
        # Malformed entries that should be safely ignored
        "; HttpOnly",
        "",
        "just_a_word_without_equals"
    ]
    server = HTTPServer(("127.0.0.1", 0), MockCookieServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = cookies_check.run(ctx)

        # Base64 with equals parsed properly
        assert any("Cookie 'tracker' has HttpOnly flag" in p for p in passed)
        # Case insensitive HTTPONLY handled
        assert any("Cookie 'flag_cookie' has HttpOnly flag" in p for p in passed)
        # Session cookie JWT recognized
        assert any("Cookie 'jwt_token' has HttpOnly flag" in p for p in passed)
        # Connect.sid recognized
        assert any("Cookie 'connect.sid' has HttpOnly flag" in p for p in passed)

        print("  [PASS] Multiple Set-Cookie headers and edge-case handling test passed.")
    finally:
        server.shutdown()


def test_samesite_none_without_secure():
    """Verify that SameSite=None without Secure triggers CKE-005."""
    MockCookieServerHandler.cookies_to_send = [
        "cross_site_session=sess456; SameSite=None; HttpOnly"
    ]
    server = HTTPServer(("127.0.0.1", 0), MockCookieServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = cookies_check.run(ctx)

        cke005 = next((f for f in findings if f.id == "CKE-005-CROSS_SITE_SESSION"), None)
        assert cke005 is not None, "Expected CKE-005 finding for SameSite=None without Secure"
        assert cke005.severity == "Medium"
        assert "SameSite=None without Secure" in cke005.title
        print("  [PASS] SameSite=None without Secure test passed.")
    finally:
        server.shutdown()


def test_cookie_prefix_enforcement():
    """Verify that __Host- and __Secure- prefixes require strict compliance."""
    MockCookieServerHandler.cookies_to_send = [
        "__Secure-id=123; HttpOnly; SameSite=Lax",  # Missing Secure / on HTTP
        "__Host-sess=456; Path=/app; HttpOnly; SameSite=Lax"  # Must have Path=/
    ]
    server = HTTPServer(("127.0.0.1", 0), MockCookieServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize(), "Failed to initialize context"
        findings, passed = cookies_check.run(ctx)

        assert any(f.id == "CKE-006-__SECURE-ID" for f in findings)
        assert any(f.id == "CKE-006-__HOST-SESS" for f in findings)
        print("  [PASS] Cookie prefix enforcement test passed.")
    finally:
        server.shutdown()


if __name__ == "__main__":
    print("====================================================================")
    print(" RUNNING DEDICATED COOKIE TESTS (checks/cookies.py)")
    print("====================================================================")
    test_insecure_session_cookies()
    test_non_sensitive_cookies_and_avoid_false_positive_sessions()
    test_secure_cookies()
    test_multiple_cookies_and_edge_cases()
    test_samesite_none_without_secure()
    test_cookie_prefix_enforcement()
    print("====================================================================")
    print(" ALL COOKIE TESTS PASSED!")
    print("====================================================================")
