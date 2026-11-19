"""
tests/test_accuracy.py - End-to-end accuracy and false-positive proof test

Launches two real HTTP servers in background threads:
  1. BAD Server: Missing security headers, version disclosure, vulnerable cookie,
     exposed .env, directory listing, and dangerous HTTP methods.
     -> Expects: Extensive findings and a failing grade (D or F).
  2. GOOD Server: Fully hardened security headers, clean Server banner, secure cookies,
     and a Single Page App catch-all router.
     -> Expects: ZERO path findings, ZERO cookie flaws, and a passing grade (A or B).

Run with:
    python -m tests.test_accuracy
"""

import sys
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.context import ScanContext
from core.runner import run_all
from core.scoring import score_and_grade


class BadServerHandler(BaseHTTPRequestHandler):
    """Vulnerable web server misconfigured across multiple domains."""

    def do_GET(self):
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=test123\nJWT_SECRET=supersecret\n")
        elif self.path == "/ftp":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Index of /ftp</title></head><body>Index of /ftp</body></html>")
        elif self.path == "/":
            self.send_response(200)
            # Leaky headers and vulnerable cookie
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("X-Powered-By", "Express")
            self.send_header("Set-Cookie", "sessionid=abc12345")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Vulnerable Target</h1></body></html>")
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

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


class GoodServerHandler(BaseHTTPRequestHandler):
    """Hardened web server with Single Page Application catch-all routing."""

    def _send_hardened_headers(self):
        # All recommended defense headers with strong values
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        # Server header without version number
        self.send_header("Server", "Apache")
        # Hardened session cookie with HttpOnly and SameSite
        self.send_header("Set-Cookie", "app_session=token998877; HttpOnly; SameSite=Lax")
        self.send_header("Content-Type", "text/html")

    def do_GET(self):
        # Catch-all: answers EVERY path with HTTP 200 and identical home page HTML
        self.send_response(200)
        self._send_hardened_headers()
        self.end_headers()
        self.wfile.write(b"<!DOCTYPE html><html><head><title>Secure SPA</title></head><body>App Body</body></html>")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.end_headers()

    def do_TRACE(self):
        self.send_response(405)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def run_accuracy_tests():
    print("====================================================================")
    print(" STARTING ACCURACY & CONTROL SERVER TESTS (PHASE 4)")
    print("====================================================================")

    # -------------------------------------------------------------
    # 1. Test BAD Server
    # -------------------------------------------------------------
    server_bad = HTTPServer(("127.0.0.1", 0), BadServerHandler)
    port_bad = server_bad.server_port
    t_bad = threading.Thread(target=server_bad.serve_forever, daemon=True)
    t_bad.start()

    ctx_bad = ScanContext(f"http://127.0.0.1:{port_bad}", delay=0)
    assert ctx_bad.initialize(), "FAIL: Bad server failed to initialize"

    findings_bad, passed_bad, errors_bad = run_all(ctx_bad)
    score_bad, grade_bad = score_and_grade(findings_bad)
    server_bad.shutdown()

    print(f"\n[*] BAD Server Results: Grade {grade_bad}, Score {score_bad}/100, Findings: {len(findings_bad)}")

    finding_ids_bad = {f.id for f in findings_bad}
    assert "PTH-ENV" in finding_ids_bad, "FAIL: Expected exposed .env finding (PTH-ENV)"
    assert "DIR-001-FTP" in finding_ids_bad, "FAIL: Expected directory listing finding (DIR-001-FTP)"
    assert "INF-001" in finding_ids_bad, "FAIL: Expected Apache version disclosure (INF-001)"
    assert any(f.category == "cookies" and f.severity in ("Medium", "Low") for f in findings_bad), "FAIL: Expected cookie finding"
    assert any("Clickjacking" in f.title for f in findings_bad), "FAIL: Expected clickjacking protection finding"
    assert grade_bad in ("D", "F"), f"FAIL: Expected Bad server grade D or F, got {grade_bad} (Score: {score_bad})"
    print("  [PASS] BAD server produced all expected findings and received failing grade D/F.")

    # -------------------------------------------------------------
    # 2. Test GOOD Server
    # -------------------------------------------------------------
    server_good = HTTPServer(("127.0.0.1", 0), GoodServerHandler)
    port_good = server_good.server_port
    t_good = threading.Thread(target=server_good.serve_forever, daemon=True)
    t_good.start()

    ctx_good = ScanContext(f"http://127.0.0.1:{port_good}", delay=0)
    assert ctx_good.initialize(), "FAIL: Good server failed to initialize"

    findings_good, passed_good, errors_good = run_all(ctx_good)
    score_good, grade_good = score_and_grade(findings_good)
    server_good.shutdown()

    print(f"\n[*] GOOD Server Results: Grade {grade_good}, Score {score_good}/100, Findings: {len(findings_good)}")

    # Verify ZERO false-positive path findings despite catch-all HTTP 200 responses
    pth_findings_good = [f for f in findings_good if f.category == "paths"]
    assert len(pth_findings_good) == 0, f"FAIL: Expected 0 path findings on Good server, got {pth_findings_good}"
    print("  [PASS] GOOD server produced 0 path findings (catch-all baseline prevented false positives).")

    # Verify ZERO security cookie findings (HttpOnly and SameSite configured)
    cookie_vulns = [f for f in findings_good if f.category == "cookies" and f.severity in ("Critical", "High", "Medium", "Low")]
    assert len(cookie_vulns) == 0, f"FAIL: Expected 0 cookie vulnerabilities on Good server, got {cookie_vulns}"
    print("  [PASS] GOOD server produced 0 cookie vulnerability findings.")

    # Verify high grade (A or B)
    assert grade_good in ("A", "B"), f"FAIL: Expected Good server grade A or B, got {grade_good} (Score: {score_good})"
    print(f"  [PASS] GOOD server achieved passing grade {grade_good} ({score_good}/100).")

    print("\n====================================================================")
    print(" [PHASE 4 RESULT: PASS]")
    print("====================================================================")


if __name__ == "__main__":
    run_accuracy_tests()
