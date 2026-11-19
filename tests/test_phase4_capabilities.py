"""
Controlled fixture tests for Phase 4 capabilities:
- scan_mode integration (passive vs authorized)
- HTTP 429 / Retry-After conservative handling
- WAF/CDN/challenge classification (fixture-based, no bypass claims)
- TLS certificate observation (local fixtures)
- JSON/HTML/dashboard/report consistency for new fields
- unique scan IDs and cancellation behavior
- passive mode excludes active probes; authorized mode preserves behavior

All tests use local/controlled fixtures only.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import ACTIVE_SCANS, OUTPUT_DIR, SCANS_LOCK, app
from core.context import ScanContext
from core.models import SCAN_MODE_AUTHORIZED_ASSESSMENT, SCAN_MODE_PASSIVE_PUBLIC
from core.runner import PASSIVE_EXCLUDED_MODULES
from core.safety import validate_url_target
from scanner import run_scan


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_http_server(handler_cls, host="127.0.0.1", port=None):
    if port is None:
        port = _free_port()
    httpd = ThreadingHTTPServer((host, port), handler_cls)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


def _wait_for_scan(client, scan_id, timeout=15.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        res = client.get(f"/api/scan/{scan_id}/status")
        if res.status_code == 200:
            last = res.get_json()
            if (last or {}).get("status") in ("completed", "failed", "cancelled"):
                return last
        time.sleep(0.05)
    return last


class _BaseHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _send(self, code=200, headers=None, body=b"<html><body>ok</body></html>"):
        headers = headers or {}
        body = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8")
        self.send_response(code)
        if "Content-Type" not in headers:
            headers["Content-Type"] = "text/html; charset=utf-8"
        headers.setdefault("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self._send(200, {"Allow": "GET, HEAD, OPTIONS"}, b"")

    def do_TRACE(self):
        body = f"TRACE {self.path} HTTP/1.1\r\nHost: {self.headers.get('Host','')}\r\n".encode("utf-8")
        self._send(200, {"Content-Type": "message/http"}, body)


class PassiveProbeTrapHandler(_BaseHandler):
    """Records requests to prove passive mode does not perform active probing."""
    seen_paths = []
    seen_methods = []
    seen_origins = []

    @classmethod
    def reset(cls):
        cls.seen_paths = []
        cls.seen_methods = []
        cls.seen_origins = []

    def _record(self, method):
        type(self).seen_paths.append(self.path)
        type(self).seen_methods.append(method)
        origin = self.headers.get("Origin")
        if origin:
            type(self).seen_origins.append(origin)

    def do_GET(self):
        self._record("GET")
        if self.path == "/":
            body = b'<html><body><a href="/page2">next</a><a href="/.env">env</a></body></html>'
            self._send(200, {"Server": "nginx/1.20.1", "X-Powered-By": "PHP/8.1"}, body)
        elif self.path == "/page2":
            self._send(200, {}, b"<html><body>page2</body></html>")
        elif self.path == "/.env":
            self._send(200, {"Content-Type": "text/plain"}, b"SECRET=1\n")
        else:
            self._send(404, {}, b"not found")

    def do_OPTIONS(self):
        self._record("OPTIONS")
        super().do_OPTIONS()

    def do_TRACE(self):
        self._record("TRACE")
        super().do_TRACE()


class RateLimit429Handler(_BaseHandler):
    def do_GET(self):
        retry_after = getattr(self.server, "retry_after_value", "7")
        self._send(
            429,
            {
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": "60",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "9999999999",
                "Content-Type": "text/plain",
            },
            b"rate limited",
        )


class CloudflareChallengeHandler(_BaseHandler):
    def do_GET(self):
        body = (
            "<html><head><title>Just a moment...</title></head>"
            "<body>Checking your browser before accessing the site. "
            "cf-challenge __cf_chl captcha</body></html>"
        )
        self._send(
            403,
            {
                "Server": "cloudflare",
                "CF-RAY": "7abc1234def56789-ABC",
                "CF-Cache-Status": "DYNAMIC",
                "Content-Type": "text/html",
            },
            body,
        )


class SuspectedCdnHeaderHandler(_BaseHandler):
    def do_GET(self):
        self._send(
            403,
            {"Server": "AkamaiGHost", "Content-Type": "text/html"},
            b"<html><body>Access denied</body></html>",
        )


class RedirectToMetadataHandler(_BaseHandler):
    def do_GET(self):
        if self.path == "/":
            self._send(302, {"Location": "http://169.254.169.254/latest/meta-data/"}, b"")
        else:
            self._send(200, {}, b"ok")


class NormalAuthorizedHandler(_BaseHandler):
    def do_GET(self):
        if self.path == "/":
            body = b'<html><body><a href="/page2">p2</a></body></html>'
            self._send(
                200,
                {
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "Permissions-Policy": "geolocation=()",
                    "Content-Security-Policy": "default-src 'self'",
                },
                body,
            )
        elif self.path == "/page2":
            self._send(200, {"X-Content-Type-Options": "nosniff"}, b"<html><body>p2</body></html>")
        else:
            self._send(404, {}, b"not found")

    def do_OPTIONS(self):
        self._send(200, {"Allow": "GET, HEAD, OPTIONS"}, b"")


def _make_self_signed_cert(cert_path, key_path, common_name="localhost", san_dns=("localhost",), san_ip=("127.0.0.1",)):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    alt_names = [x509.DNSName(d) for d in san_dns]
    for ip in san_ip:
        alt_names.append(x509.IPAddress(ipaddress.ip_address(ip)))
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert


class Phase4CapabilitiesTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_passive_mode_excludes_active_probes_and_records_limitations(self):
        PassiveProbeTrapHandler.reset()
        httpd, port = _start_http_server(PassiveProbeTrapHandler)
        try:
            url = f"http://127.0.0.1:{port}/"
            result = run_scan(
                target_url=url,
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=2.0,
                insecure=True,
                i_have_permission=True,
                verbose=False,
                scan_mode=SCAN_MODE_PASSIVE_PUBLIC,
            )
        finally:
            httpd.shutdown()
            httpd.server_close()

        self.assertEqual(result.get("scan_mode"), SCAN_MODE_PASSIVE_PUBLIC)
        self.assertIn("Passive Public Inspection", result.get("scan_mode_label", ""))

        # Passive mode must not crawl linked pages or probe sensitive paths/active methods/CORS origins.
        self.assertEqual(PassiveProbeTrapHandler.seen_methods.count("GET"), 1)
        self.assertIn("/", PassiveProbeTrapHandler.seen_paths)
        self.assertNotIn("/.env", PassiveProbeTrapHandler.seen_paths)
        self.assertNotIn("/page2", PassiveProbeTrapHandler.seen_paths)
        self.assertNotIn("OPTIONS", PassiveProbeTrapHandler.seen_methods)
        self.assertNotIn("TRACE", PassiveProbeTrapHandler.seen_methods)
        self.assertEqual(PassiveProbeTrapHandler.seen_origins, [])

        cr_by_cat = {c.get("category"): c for c in result.get("check_results", [])}
        for cat in PASSIVE_EXCLUDED_MODULES:
            self.assertIn(cat, cr_by_cat)
            self.assertEqual(cr_by_cat[cat].get("status"), "NOT TESTED")
            self.assertIn("Excluded in Passive Public Inspection", cr_by_cat[cat].get("evidence", ""))

        lims = " \n ".join(result.get("scan_limitations", []))
        self.assertIn("not a complete security audit", lims.lower())
        self.assertIn("Passive Public Inspection", lims)

    def test_authorized_mode_preserves_active_safe_checks(self):
        httpd, port = _start_http_server(NormalAuthorizedHandler)
        try:
            url = f"http://127.0.0.1:{port}/"
            result = run_scan(
                target_url=url,
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=2.0,
                insecure=True,
                i_have_permission=True,
                verbose=False,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
            )
        finally:
            httpd.shutdown()
            httpd.server_close()

        self.assertEqual(result.get("scan_mode"), SCAN_MODE_AUTHORIZED_ASSESSMENT)
        cr_by_cat = {c.get("category"): c for c in result.get("check_results", [])}
        # Authorized mode must not exclude active safe modules (they should execute, not be mode-excluded).
        for cat in ("cors", "methods", "paths"):
            self.assertIn(cat, cr_by_cat)
            self.assertNotIn("Excluded in Passive Public Inspection", cr_by_cat[cat].get("evidence", ""))
            self.assertNotEqual(cr_by_cat[cat].get("status"), "NOT TESTED")
        self.assertIn(result.get("status"), ("completed", "cancelled", "failed"))

    def test_http_429_retry_after_recorded_and_conservative(self):
        httpd, port = _start_http_server(RateLimit429Handler)
        httpd.retry_after_value = "7"
        try:
            url = f"http://127.0.0.1:{port}/"
            result = run_scan(
                target_url=url,
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=2.0,
                insecure=True,
                i_have_permission=True,
                verbose=False,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
            )
        finally:
            httpd.shutdown()
            httpd.server_close()

        events = result.get("rate_limit_events", [])
        self.assertTrue(events, "Expected rate_limit_events for HTTP 429")
        ev = events[0]
        self.assertEqual(ev.get("status"), 429)
        self.assertEqual((ev.get("retry_after") or {}).get("raw"), "7")
        self.assertEqual((ev.get("retry_after") or {}).get("seconds"), 7)
        self.assertIn("Retry-After", ev.get("headers", {}))

        lims = " \n ".join(result.get("scan_limitations", []))
        self.assertIn("429", lims)
        self.assertTrue(
            "stopped conservatively" in lims.lower() or "stopping further requests conservatively" in lims.lower(),
            msg=f"Expected conservative stop message in limitations: {lims}",
        )

        statuses = [c.get("status") for c in result.get("check_results", []) if c.get("category") in ("headers", "cookies", "info_leaks", "paths", "methods", "cors")]
        self.assertTrue(statuses)
        self.assertTrue(all(s == "NOT TESTED" for s in statuses))
        self.assertEqual(result.get("findings", []), [])

    def test_cloudflare_challenge_classification_and_not_tested(self):
        httpd, port = _start_http_server(CloudflareChallengeHandler)
        try:
            url = f"http://127.0.0.1:{port}/"
            result = run_scan(
                target_url=url,
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=2.0,
                insecure=True,
                i_have_permission=True,
                verbose=False,
                scan_mode=SCAN_MODE_PASSIVE_PUBLIC,
            )
        finally:
            httpd.shutdown()
            httpd.server_close()

        waf = result.get("waf_indicators", [])
        self.assertTrue(waf, "Expected WAF/CDN indicators")
        self.assertTrue(any(w.get("provider") == "cloudflare" for w in waf))
        self.assertTrue(any(w.get("confidence") == "confirmed" for w in waf))
        indicators_blob = " ".join(" ".join(w.get("indicators", [])) for w in waf).lower()
        self.assertTrue("cf-ray" in indicators_blob or "challenge" in indicators_blob or "cloudflare" in indicators_blob)

        lims = " \n ".join(result.get("scan_limitations", []))
        self.assertTrue(
            "cdn/waf/challenge" in lims.lower()
            or "intermediary challenge" in lims.lower()
            or "intermediary/cdn/waf" in lims.lower(),
            msg=f"Expected intermediary/challenge limitation in: {lims}",
        )
        self.assertEqual(result.get("findings", []), [])
        statuses = [c.get("status") for c in result.get("check_results", []) if c.get("category") in ("headers", "cookies", "info_leaks")]
        self.assertTrue(statuses and all(s == "NOT TESTED" for s in statuses))

    def test_suspected_cdn_header_classification(self):
        httpd, port = _start_http_server(SuspectedCdnHeaderHandler)
        try:
            url = f"http://127.0.0.1:{port}/"
            result = run_scan(
                target_url=url,
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=2.0,
                insecure=True,
                i_have_permission=True,
                verbose=False,
                scan_mode=SCAN_MODE_PASSIVE_PUBLIC,
            )
        finally:
            httpd.shutdown()
            httpd.server_close()

        waf = result.get("waf_indicators", [])
        self.assertTrue(waf)
        self.assertIn(waf[0].get("confidence"), ("confirmed", "suspected"))
        self.assertTrue(waf[0].get("provider"))

    def test_tls_observation_https_self_signed_and_http_not_applicable(self):
        # HTTP target: TLS not applicable
        httpd, port = _start_http_server(NormalAuthorizedHandler)
        try:
            ctx = ScanContext(f"http://127.0.0.1:{port}/", delay=0, timeout=2, i_have_permission=True, verify_ssl=True)
            obs = ctx.observe_tls()
            self.assertFalse(obs.get("applicable"))
            self.assertEqual(obs.get("status"), "not_applicable")
        finally:
            httpd.shutdown()
            httpd.server_close()

        # HTTPS self-signed fixture
        with tempfile.TemporaryDirectory() as td:
            cert_path = os.path.join(td, "cert.pem")
            key_path = os.path.join(td, "key.pem")
            _make_self_signed_cert(cert_path, key_path)

            # Verification enabled (default) -> should observe cert and record verification failure for self-signed
            httpsd = ThreadingHTTPServer(("127.0.0.1", _free_port()), NormalAuthorizedHandler)
            port_tls = httpsd.server_address[1]
            sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sslctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            httpsd.socket = sslctx.wrap_socket(httpsd.socket, server_side=True)
            # TLS observation may open/close sockets abruptly; suppress noisy server-thread tracebacks.
            httpsd.handle_error = lambda request, client_address: None
            t = threading.Thread(target=httpsd.serve_forever, daemon=True)
            t.start()
            try:
                url = f"https://127.0.0.1:{port_tls}/"
                result = run_scan(
                    target_url=url,
                    output_html=None,
                    output_json=None,
                    delay=0.0,
                    timeout=3.0,
                    insecure=False,
                    i_have_permission=True,
                    verbose=False,
                    scan_mode=SCAN_MODE_PASSIVE_PUBLIC,
                )
                tls = result.get("tls_observations", {})
                self.assertTrue(tls.get("applicable"))
                self.assertEqual(tls.get("status"), "observed")
                self.assertTrue(tls.get("verification_enabled"))
                self.assertIsNotNone(tls.get("verification_ok"))
                self.assertFalse(tls.get("verification_ok"))
                self.assertTrue(tls.get("certificate"))
                cert = tls.get("certificate") or {}
                self.assertTrue(cert.get("notBefore") or cert.get("subject") or cert.get("issuer"))
                self.assertTrue(cert.get("notAfter") or cert.get("subject") or cert.get("issuer"))
                lim_blob = " ".join(tls.get("limitations", []) or []).lower()
                err_blob = str(tls.get("verification_error", "")).lower()
                self.assertTrue("self-signed" in err_blob or "self signed" in err_blob or "self-signed" in lim_blob or "self signed" in lim_blob or tls.get("verification_ok") is False)
            finally:
                httpsd.shutdown()
                httpsd.server_close()
                try:
                    httpsd.socket.close()
                except Exception:
                    pass

            # Explicit insecure mode -> verification disabled must be recorded
            httpsd2 = ThreadingHTTPServer(("127.0.0.1", _free_port()), NormalAuthorizedHandler)
            port_tls2 = httpsd2.server_address[1]
            sslctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sslctx2.load_cert_chain(certfile=cert_path, keyfile=key_path)
            httpsd2.socket = sslctx2.wrap_socket(httpsd2.socket, server_side=True)
            httpsd2.handle_error = lambda request, client_address: None
            t2 = threading.Thread(target=httpsd2.serve_forever, daemon=True)
            t2.start()
            try:
                url2 = f"https://127.0.0.1:{port_tls2}/"
                result2 = run_scan(
                    target_url=url2,
                    output_html=None,
                    output_json=None,
                    delay=0.0,
                    timeout=3.0,
                    insecure=True,
                    i_have_permission=True,
                    verbose=False,
                    scan_mode=SCAN_MODE_PASSIVE_PUBLIC,
                )
                tls2 = result2.get("tls_observations", {})
                self.assertTrue(tls2.get("applicable"))
                self.assertFalse(tls2.get("verification_enabled", True))
                lims = " \n ".join(result2.get("scan_limitations", []))
                self.assertIn("verification was disabled", lims.lower())
            finally:
                httpsd2.shutdown()
                httpsd2.server_close()
                try:
                    httpsd2.socket.close()
                except Exception:
                    pass

    def test_redirect_to_blocked_destination_refused(self):
        httpd, port = _start_http_server(RedirectToMetadataHandler)
        try:
            url = f"http://127.0.0.1:{port}/"
            result = run_scan(
                target_url=url,
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=2.0,
                insecure=True,
                i_have_permission=True,
                verbose=False,
                scan_mode=SCAN_MODE_PASSIVE_PUBLIC,
            )
            self.assertEqual(result.get("status"), "failed")
            self.assertEqual(result.get("grade"), "N/A")
            self.assertEqual(result.get("findings", []), [])
            statuses = [c.get("status") for c in result.get("check_results", [])]
            self.assertTrue(statuses and all(s == "NOT TESTED" for s in statuses))
            err_blob = " ".join(result.get("errors", []) + result.get("scan_limitations", [])).lower()
            self.assertIn("blocked unsafe redirect", err_blob)
            self.assertIn("169.254.169.254", err_blob)
        finally:
            httpd.shutdown()
            httpd.server_close()

        v = validate_url_target("http://169.254.169.254/", True, scan_mode=SCAN_MODE_PASSIVE_PUBLIC)
        self.assertFalse(v.ok)

    def test_json_html_consistency_includes_new_fields(self):
        httpd, port = _start_http_server(NormalAuthorizedHandler)
        scan_id = "phase4_consistency_test"
        json_path = os.path.join(OUTPUT_DIR, f"scan_{scan_id}.json")
        html_path = os.path.join(OUTPUT_DIR, f"report_{scan_id}.html")
        try:
            url = f"http://127.0.0.1:{port}/"
            result = run_scan(
                target_url=url,
                output_html=html_path,
                output_json=json_path,
                delay=0.0,
                timeout=2.0,
                insecure=True,
                i_have_permission=True,
                verbose=False,
                scan_mode=SCAN_MODE_PASSIVE_PUBLIC,
                scan_id=scan_id,
            )
            for key in [
                "scan_id", "scan_mode", "scan_mode_label", "dns_outcome",
                "connection_outcome", "http_outcome", "tls_observations",
                "waf_indicators", "rate_limit_events", "check_results",
                "checks_not_performed", "scan_limitations", "resolved_ips",
                "scan_started_at", "scan_completed_at",
            ]:
                self.assertIn(key, result)
            self.assertEqual(result["scan_id"], scan_id)

            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(html_path))
            with open(json_path, "r", encoding="utf-8") as f:
                disk = json.load(f)
            self.assertEqual(disk.get("scan_mode"), SCAN_MODE_PASSIVE_PUBLIC)
            self.assertIn("dns_outcome", disk)
            self.assertIn("tls_observations", disk)
            self.assertIn("waf_indicators", disk)
            self.assertIn("rate_limit_events", disk)

            with open(html_path, "r", encoding="utf-8") as f:
                html = f.read()
            self.assertIn("Passive Public Inspection", html)
            self.assertIn(scan_id, html)
            self.assertIn("DNS outcome", html)
            self.assertIn("Connection outcome", html)
            self.assertIn("HTTP(S) outcome", html)
            self.assertIn("Scan observations", html)
        finally:
            httpd.shutdown()
            httpd.server_close()
            for p in (json_path, html_path):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except Exception:
                    pass

    def test_unique_scan_ids_and_cancel_endpoint(self):
        httpd, port = _start_http_server(NormalAuthorizedHandler)
        id1 = id2 = None
        try:
            payload = {
                "target_url": f"http://127.0.0.1:{port}/",
                "scan_mode": SCAN_MODE_AUTHORIZED_ASSESSMENT,
                "delay": 0.0,
                "timeout": 2.0,
                "i_have_permission": True,
                "insecure": True,
            }
            r1 = self.client.post("/api/scan", json=dict(payload))
            r2 = self.client.post("/api/scan", json=dict(payload))
            self.assertEqual(r1.status_code, 202)
            self.assertEqual(r2.status_code, 202)
            id1 = (r1.get_json() or {}).get("scan_id")
            id2 = (r2.get_json() or {}).get("scan_id")
            self.assertTrue(id1 and id2)
            self.assertNotEqual(id1, id2)

            s1 = _wait_for_scan(self.client, id1)
            s2 = _wait_for_scan(self.client, id2)
            self.assertIn((s1 or {}).get("status"), ("completed", "failed", "cancelled"))
            self.assertIn((s2 or {}).get("status"), ("completed", "failed", "cancelled"))
        finally:
            httpd.shutdown()
            httpd.server_close()
            for sid in (id1, id2):
                if not sid:
                    continue
                for p in (os.path.join(OUTPUT_DIR, f"scan_{sid}.json"), os.path.join(OUTPUT_DIR, f"report_{sid}.html")):
                    try:
                        if os.path.exists(p):
                            os.remove(p)
                    except Exception:
                        pass
                with SCANS_LOCK:
                    ACTIVE_SCANS.pop(sid, None)

        rnf = self.client.post("/api/scan/does_not_exist_cancel/cancel")
        self.assertIn(rnf.status_code, (404, 409))


if __name__ == "__main__":
    unittest.main(verbosity=2)
