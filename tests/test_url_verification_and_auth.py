import os
import socket
import sys
import unittest
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app
from core.dns_verification import preflight_verify_target
from core.models import SCAN_MODE_AUTHORIZED_ASSESSMENT


def _raw_dns(google_status="NOERROR", cf_status="NOERROR", google_addrs=None, cf_addrs=None):
    """Shape returned by verify_hostname_dns_sync (before perform_dns_verification post-processing)."""
    google_addrs = list(google_addrs or [])
    cf_addrs = list(cf_addrs or [])
    all_addrs = []
    for addr in google_addrs + cf_addrs:
        if addr not in all_addrs:
            all_addrs.append(addr)

    def prov(name, status, addrs):
        return {
            "provider": name,
            "status": status,
            "a": {"status": status, "addresses": addrs, "error": None},
            "aaaa": {"status": status, "addresses": [], "error": None},
            "addresses": addrs,
            "error": None,
        }

    return {
        "hostname": "",
        "queried": True,
        "providers": {
            "google": prov("google", google_status, google_addrs),
            "cloudflare": prov("cloudflare", cf_status, cf_addrs),
        },
        "comparison": {
            "match": google_addrs == cf_addrs,
            "summary": "test",
            "common_addresses": [],
            "all_addresses": all_addrs,
        },
        "all_addresses": all_addrs,
    }


def _gai(ip, port=80):
    def _side_effect(host, *args, **kwargs):
        if ":" in ip:
            sockaddr = (ip, port or 80, 0, 0)
            family = socket.AF_INET6
        else:
            sockaddr = (ip, port or 80)
            family = socket.AF_INET
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]

    return _side_effect


class UrlVerificationTests(unittest.TestCase):
    def test_nonexistent_domain_nxdomain_is_responsible(self):
        with mock.patch(
            "core.dns_verification.verify_hostname_dns_sync",
            return_value=_raw_dns("NXDOMAIN", "NXDOMAIN"),
        ), mock.patch("core.safety.socket.getaddrinfo", side_effect=socket.gaierror("simulated dns failure")):
            result = preflight_verify_target(
                "http://nope.invalid/",
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
            )

        self.assertFalse(result["ok"])
        self.assertFalse(result["exists"])
        self.assertEqual(result["outcome"], "nxdomain")
        self.assertIn("NXDOMAIN", result["message"])
        self.assertIn("does not exist", result["message"])

    def test_existing_domain_resolves_and_is_allowed(self):
        with mock.patch(
            "core.dns_verification.verify_hostname_dns_sync",
            return_value=_raw_dns("NOERROR", "NOERROR", ["93.184.216.34"], ["93.184.216.34"]),
        ), mock.patch("core.safety.socket.getaddrinfo", side_effect=_gai("93.184.216.34")):
            result = preflight_verify_target(
                "http://example.com/",
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
            )

        self.assertTrue(result["ok"])
        self.assertTrue(result["exists"])
        self.assertEqual(result["outcome"], "resolved")
        self.assertEqual(result["system_validation_ok"], True)

    def test_one_or_both_providers_unavailable_falls_back_to_system_dns(self):
        with mock.patch(
            "core.dns_verification.verify_hostname_dns_sync",
            return_value=_raw_dns("TIMEOUT", "ERROR"),
        ), mock.patch("core.safety.socket.getaddrinfo", side_effect=_gai("93.184.216.34")):
            result = preflight_verify_target(
                "http://example.com/",
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
            )

        self.assertTrue(result["ok"])
        self.assertIsNone(result["exists"])
        self.assertEqual(result["outcome"], "providers_unavailable")

    def test_both_providers_unavailable_and_system_dns_fails(self):
        with mock.patch(
            "core.dns_verification.verify_hostname_dns_sync",
            return_value=_raw_dns("TIMEOUT", "ERROR"),
        ), mock.patch("core.safety.socket.getaddrinfo", side_effect=socket.gaierror("simulated dns failure")):
            result = preflight_verify_target(
                "http://example.com/",
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
            )

        self.assertFalse(result["ok"])
        self.assertIsNone(result["exists"])
        self.assertIn("Failed to resolve", result["message"])

    def test_public_nxdomain_does_not_override_local_split_horizon_resolution(self):
        # Public DoH says NXDOMAIN, but the host resolves locally (private/split-horizon DNS).
        # Local resolution must remain authoritative so real targets are not refused.
        with mock.patch(
            "core.dns_verification.verify_hostname_dns_sync",
            return_value=_raw_dns("NXDOMAIN", "NXDOMAIN"),
        ), mock.patch("core.safety.socket.getaddrinfo", side_effect=_gai("192.168.1.10")):
            result = preflight_verify_target(
                "http://internal.example/",
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
            )

        self.assertTrue(result["ok"])
        self.assertFalse(result["exists"])
        self.assertIn("split-horizon", result["message"])

    def test_blocked_destination_ip_is_refused(self):
        with mock.patch(
            "core.dns_verification.verify_hostname_dns_sync",
            return_value=_raw_dns("NOERROR", "NOERROR", ["169.254.169.254"], ["169.254.169.254"]),
        ), mock.patch("core.safety.socket.getaddrinfo", side_effect=_gai("169.254.169.254")):
            result = preflight_verify_target(
                "http://metadata.example/",
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
            )

        self.assertFalse(result["ok"])
        self.assertTrue(result["exists"])
        self.assertEqual(result["outcome"], "resolved_but_blocked")
        self.assertIn("blocked destination", result["message"])


class ApiVerificationAndAuthTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_api_nonexistent_domain_returns_responsible_400(self):
        with mock.patch(
            "core.dns_verification.verify_hostname_dns_sync",
            return_value=_raw_dns("NXDOMAIN", "NXDOMAIN"),
        ), mock.patch("core.safety.socket.getaddrinfo", side_effect=socket.gaierror("simulated dns failure")):
            res = self.client.post(
                "/api/scan",
                json={
                    "target_url": "http://nope.invalid/",
                    "scan_mode": "authorized_assessment",
                    "i_have_permission": True,
                },
            )

        self.assertEqual(res.status_code, 400)
        body = res.get_json()
        self.assertIn("NXDOMAIN", body["error"])
        self.assertIn("verification", body)
        self.assertFalse(body["verification"]["exists"])

    def test_api_valid_local_target_dispatches_with_verification(self):
        def fake_run_scan(**kwargs):
            return {
                "status": "completed",
                "grade": "A",
                "score": 100,
                "findings": [],
                "check_results": [],
                "errors": [],
                "target": kwargs.get("target_url"),
                "scan_id": kwargs.get("scan_id"),
            }

        with mock.patch("app.run_scan", side_effect=fake_run_scan):
            res = self.client.post(
                "/api/scan",
                json={
                    "target_url": "http://127.0.0.1:3000",
                    "scan_mode": "authorized_assessment",
                    "i_have_permission": True,
                },
            )

        self.assertEqual(res.status_code, 202)
        body = res.get_json()
        self.assertIn("scan_id", body)
        self.assertEqual(body["verification"]["outcome"], "ip_literal")

    def test_api_key_auth_required_when_configured(self):
        payload = {
            "target_url": "http://127.0.0.1:3000",
            "scan_mode": "authorized_assessment",
            "i_have_permission": True,
        }
        with mock.patch.dict(app.config, {"TESTING": False}), mock.patch("app.CONFIGRA_API_KEY", "test-secret"), mock.patch(
            "app.CONFIGRA_ACCESS_PASSWORD", ""
        ):
            missing = self.client.post("/api/scan", json=payload)
            self.assertEqual(missing.status_code, 401)
            self.assertIn("Authentication required", missing.get_json()["error"])

            bad = self.client.post("/api/scan", json=payload, headers={"X-API-Key": "wrong"})
            self.assertEqual(bad.status_code, 401)

            cancel = self.client.post("/api/scan/whatever/cancel")
            self.assertEqual(cancel.status_code, 401)

            def fake_run_scan(**kwargs):
                return {"status": "completed", "findings": [], "check_results": [], "errors": []}

            with mock.patch("app.run_scan", side_effect=fake_run_scan):
                ok = self.client.post("/api/scan", json=payload, headers={"X-API-Key": "test-secret"})
            self.assertEqual(ok.status_code, 202)

    def test_scanner_page_injects_api_key_meta_only_when_auth_enabled(self):
        with mock.patch.dict(app.config, {"TESTING": False}), mock.patch("app.CONFIGRA_API_KEY", "test-secret"), mock.patch(
            "app.CONFIGRA_ACCESS_PASSWORD", ""
        ):
            res = self.client.get("/scan")
            html = res.data.decode("utf-8", "ignore")
            self.assertIn('name="configra-api-key"', html)
            self.assertIn("test-secret", html)

        with mock.patch.dict(app.config, {"TESTING": True}):
            res = self.client.get("/scan")
            html = res.data.decode("utf-8", "ignore")
            self.assertNotIn('name="configra-api-key"', html)

    def test_access_password_gate_protects_whole_ui(self):
        import base64

        remote = {"REMOTE_ADDR": "203.0.113.9"}
        with mock.patch.dict(app.config, {"TESTING": False}), mock.patch(
            "app.CONFIGRA_ACCESS_PASSWORD", "s3cret"
        ):
            blocked = self.client.get("/scan", environ_base=remote)
            self.assertEqual(blocked.status_code, 401)
            self.assertIn("Basic", blocked.headers.get("WWW-Authenticate", ""))
            self.assertNotIn(b"CONFIGRA", blocked.data)

            token = base64.b64encode(b"anyuser:s3cret").decode("ascii")
            allowed = self.client.get(
                "/scan", headers={"Authorization": f"Basic {token}"}, environ_base=remote
            )
            self.assertEqual(allowed.status_code, 200)
            self.assertIn(b"CONFIGRA", allowed.data)

            wrong = base64.b64encode(b"anyuser:nope").decode("ascii")
            denied = self.client.get(
                "/scan", headers={"Authorization": f"Basic {wrong}"}, environ_base=remote
            )
            self.assertEqual(denied.status_code, 401)

            # A local browser on this PC is never prompted.
            local = self.client.get("/scan", environ_base={"REMOTE_ADDR": "127.0.0.1"})
            self.assertEqual(local.status_code, 200)
            self.assertIn(b"CONFIGRA", local.data)

            # Tunnel traffic arrives from loopback but carries Cloudflare headers,
            # so it must still be challenged.
            tunnelled = self.client.get(
                "/scan",
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
                headers={"CF-Connecting-IP": "198.51.100.7"},
            )
            self.assertEqual(tunnelled.status_code, 401)

        # Disabled when unset, so local development is unaffected.
        with mock.patch.dict(app.config, {"TESTING": False}), mock.patch(
            "app.CONFIGRA_ACCESS_PASSWORD", ""
        ):
            self.assertEqual(self.client.get("/scan", environ_base=remote).status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
