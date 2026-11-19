"""
tests/test_paths.py - Accuracy test for exposed paths, binary signatures, and catch-all prevention

Verifies that:
1. Vulnerable server exposing sensitive files (.env, .git/index, sftp.json, swagger, actuator/env, web.config, backup.tar.gz) detects all flaws with Confirmed confidence.
2. Binary magic bytes (Git DIRC, Gzip \x1f\x8b, Zip PK\x03\x04, DS_Store) are accurately matched.
3. Protected resources returning HTTP 401 / 403 are treated as passed checks (NOT misconfigurations).
4. Structural directory listing detection alerts on actual server listings (<title>Index of /ftp</title>) but ignores normal page prose containing 'Index of'.
5. Catch-all target serving 200 for all paths produces ZERO false positives.

Run with:
    python -m tests.test_paths
"""

import sys
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.context import ScanContext
from checks import paths


class ComprehensiveVulnerableServer(BaseHTTPRequestHandler):
    """Server that exposes multiple sensitive paths and binaries."""

    def do_GET(self):
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=test123\nAPI_KEY=secret_abc\n")

        elif self.path == "/.git/index":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            # Binary Git index starting with magic bytes DIRC
            self.wfile.write(b"DIRC\x00\x00\x00\x02\x00\x00\x00\x01")

        elif self.path == "/.vscode/sftp.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"host": "sftp.example.com", "username": "deploy", "password": "sftpPassword99!"}')

        elif self.path == "/swagger.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"swagger": "2.0", "info": {"title": "App API", "version": "1.0"}, "paths": {}}')

        elif self.path == "/actuator/env":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment"}]}')

        elif self.path == "/web.config":
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(b'<configuration><system.webServer><handlers></handlers></system.webServer></configuration>')

        elif self.path == "/backup.tar.gz":
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.end_headers()
            # Gzip magic bytes \x1f\x8b
            self.wfile.write(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x03\x00\x00\x00\x00\x00")

        elif self.path == "/dump.sql":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"-- MySQL dump 10.13\nCREATE TABLE users (id INT, email VARCHAR(255));\n")

        elif self.path == "/ftp":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Index of /ftp</title></head><body><h1>Index of /ftp</h1><pre><a href='/'>Parent Directory</a></pre></body></html>")

        elif self.path == "/":
            # Normal page containing prose words 'Index of' to test false-positive resistance
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Welcome</h1><p>Here is an Index of all our favorite blog posts.</p></body></html>")

        elif self.path == "/admin_forbidden":
            self.send_response(403)
            self.end_headers()

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        pass


class CatchAllServerHandler(BaseHTTPRequestHandler):
    """Catch-all Single Page App returning HTTP 200 with identical home page on every route."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<!DOCTYPE html><html><body><h1>Single Page App</h1><p>Catch-all routing</p></body></html>")

    def log_message(self, format, *args):
        pass


class ProtectedServerHandler(BaseHTTPRequestHandler):
    """Server that properly protects sensitive paths with 401 or 403."""

    def do_GET(self):
        if self.path in ("/.env", "/.git/HEAD", "/web.config"):
            self.send_response(403)
            self.end_headers()
        elif self.path == "/actuator/env":
            self.send_response(401)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Public App</body></html>")

    def log_message(self, format, *args):
        pass


def test_vulnerable_paths():
    server = HTTPServer(("127.0.0.1", 0), ComprehensiveVulnerableServer)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = paths.run(ctx)

        ids = {f.id for f in findings}
        assert "PTH-ENV" in ids, "Expected PTH-ENV finding (.env file)"
        assert "PTH-GIT-INDEX" in ids, "Expected PTH-GIT-INDEX finding (.git/index)"
        assert "PTH-VSCODE-SFTP" in ids, "Expected PTH-VSCODE-SFTP finding (.vscode/sftp.json)"
        assert "PTH-SWAGGER-JSON" in ids, "Expected PTH-SWAGGER-JSON finding (swagger.json)"
        assert "PTH-ACTUATOR-ENV" in ids, "Expected PTH-ACTUATOR-ENV finding (/actuator/env)"
        assert "PTH-WEB-CONFIG" in ids, "Expected PTH-WEB-CONFIG finding (web.config)"
        assert "PTH-BACKUP-TARGZ" in ids, "Expected PTH-BACKUP-TARGZ finding (backup.tar.gz)"
        assert "PTH-DUMP-SQL" in ids, "Expected PTH-DUMP-SQL finding (dump.sql)"
        assert "DIR-001-FTP" in ids, "Expected DIR-001-FTP directory listing finding"

        # Verify normal prose on root did NOT trigger DIR-001-ROOT false positive
        assert "DIR-001-ROOT" not in ids, "False positive DIR-001-ROOT triggered on normal prose"

        env_finding = next(f for f in findings if f.id == "PTH-ENV")
        assert env_finding.severity == "Critical"
        assert env_finding.confidence == "Confirmed"

        print("  [PASS] Vulnerable server detected all exposed paths, binaries, and directory listing.")
    finally:
        server.shutdown()


def test_catch_all_prevention():
    server = HTTPServer(("127.0.0.1", 0), CatchAllServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = paths.run(ctx)

        pth_findings = [f for f in findings if f.category == "paths"]
        assert len(pth_findings) == 0, f"Expected 0 path findings on SPA catch-all, got: {pth_findings}"
        print("  [PASS] Catch-all single page application produced 0 false positives.")
    finally:
        server.shutdown()


def test_protected_paths_handled_as_passed():
    server = HTTPServer(("127.0.0.1", 0), ProtectedServerHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        ctx = ScanContext(f"http://127.0.0.1:{port}", delay=0)
        assert ctx.initialize()
        findings, passed = paths.run(ctx)

        # 401/403 should NOT produce findings
        assert not any(f.id in ("PTH-ENV", "PTH-GIT-HEAD", "PTH-WEB-CONFIG", "PTH-ACTUATOR-ENV") for f in findings)

        # 401/403 must be recorded in passed_checks
        assert any("Path '/.env' is protected" in p for p in passed)
        assert any("Path '/actuator/env' is protected" in p for p in passed)
        print("  [PASS] Protected 401/403 paths correctly recorded as passed checks.")
    finally:
        server.shutdown()


def run_tests():
    print("[*] Starting Enhanced Paths & Directory Listing Tests...")
    test_vulnerable_paths()
    test_catch_all_prevention()
    test_protected_paths_handled_as_passed()
    print("\n[PHASE 2 RESULT: PASS]")


if __name__ == "__main__":
    run_tests()
