import os
import socket
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.dns_verification import (
    perform_dns_verification,
    verify_hostname_dns_async,
    verify_hostname_dns_sync,
)
from core.models import SCAN_MODE_AUTHORIZED_ASSESSMENT
from scanner import run_scan


class _FakeResponse:
    def __init__(self, status_code=200, payload=None, json_exc=None):
        self.status_code = status_code
        self._payload = payload or {}
        self._json_exc = json_exc

    def json(self):
        if self._json_exc:
            raise self._json_exc
        return self._payload


def _doh_payload(status=0, answers=None):
    return {"Status": status, "Answer": answers or []}


def _answers(records):
    # records: list of (type_num, data)
    return [{"type": t, "data": d} for t, d in records]


class _FakeAsyncClient:
    def __init__(self, responder, *a, **k):
        self._responder = responder

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, params=None, headers=None):
        return self._responder(url, params=params, headers=headers)


def _patch_httpx(responder):
    return mock.patch("core.dns_verification.httpx.AsyncClient", side_effect=lambda *a, **k: _FakeAsyncClient(responder, *a, **k))


class DualDnsIntegrationTests(unittest.TestCase):
    def test_valid_domain_ipv4_and_ipv6_records(self):
        def responder(url, params=None, headers=None):
            qtype = (params or {}).get("type")
            if "dns.google" in url:
                if qtype == "A":
                    return _FakeResponse(200, _doh_payload(0, _answers([(1, "93.184.216.34")])))
                if qtype == "AAAA":
                    return _FakeResponse(200, _doh_payload(0, _answers([(28, "2606:2800:220:1:248:1893:25c8:1946")])))
            if "cloudflare-dns.com" in url:
                if qtype == "A":
                    return _FakeResponse(200, _doh_payload(0, _answers([(1, "93.184.216.34")])))
                if qtype == "AAAA":
                    return _FakeResponse(200, _doh_payload(0, _answers([(28, "2606:2800:220:1:248:1893:25c8:1946")])))
            return _FakeResponse(200, _doh_payload(2, []))

        with _patch_httpx(responder):
            result = verify_hostname_dns_sync("example.com", timeout=2.0)

        self.assertEqual(result["providers"]["google"]["status"], "NOERROR")
        self.assertEqual(result["providers"]["cloudflare"]["status"], "NOERROR")
        self.assertIn("93.184.216.34", result["providers"]["google"]["a"]["addresses"])
        self.assertIn("2606:2800:220:1:248:1893:25c8:1946", result["providers"]["google"]["aaaa"]["addresses"])
        self.assertIn("93.184.216.34", result["providers"]["cloudflare"]["addresses"])
        self.assertIn("2606:2800:220:1:248:1893:25c8:1946", result["providers"]["cloudflare"]["addresses"])
        self.assertTrue(result["comparison"]["match"])
        self.assertIn("93.184.216.34", result["all_addresses"])
        self.assertIn("2606:2800:220:1:248:1893:25c8:1946", result["all_addresses"])

    def test_nonexistent_invalid_domain_nxdomain(self):
        def responder(url, params=None, headers=None):
            # NXDOMAIN for all A/AAAA queries
            return _FakeResponse(200, _doh_payload(3, []))

        with _patch_httpx(responder):
            result = perform_dns_verification(
                "nonexistent.invalid",
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                timeout=2.0,
            )

        self.assertEqual(result["providers"]["google"]["status"], "NXDOMAIN")
        self.assertEqual(result["providers"]["cloudflare"]["status"], "NXDOMAIN")
        self.assertEqual(result["outcome"], "nxdomain")
        self.assertEqual(result["all_addresses"], [])
        self.assertTrue(result["comparison"]["match"])  # both agree NXDOMAIN

    def test_one_dns_provider_unavailable(self):
        def responder(url, params=None, headers=None):
            qtype = (params or {}).get("type")
            if "dns.google" in url:
                raise TimeoutError("simulated timeout")
            if "cloudflare-dns.com" in url:
                if qtype == "A":
                    return _FakeResponse(200, _doh_payload(0, _answers([(1, "93.184.216.34")])))
                return _FakeResponse(200, _doh_payload(0, []))
            return _FakeResponse(500, {})

        with _patch_httpx(responder):
            result = perform_dns_verification(
                "example.com",
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                timeout=2.0,
            )

        self.assertEqual(result["providers"]["google"]["status"], "TIMEOUT")
        self.assertEqual(result["providers"]["cloudflare"]["status"], "NOERROR")
        self.assertIn("93.184.216.34", result["all_addresses"])
        self.assertFalse(result["comparison"]["match"])
        self.assertEqual(result["outcome"], "resolved")
        self.assertTrue(result["safety"]["ok"])

    def test_both_dns_providers_unavailable_no_fabricated_success(self):
        def responder(url, params=None, headers=None):
            if "dns.google" in url:
                raise TimeoutError("google timeout")
            if "cloudflare-dns.com" in url:
                return _FakeResponse(503, {})
            return _FakeResponse(500, {})

        with _patch_httpx(responder):
            result = perform_dns_verification(
                "example.com",
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                timeout=2.0,
            )

        self.assertIn(result["providers"]["google"]["status"], ("TIMEOUT", "ERROR"))
        self.assertIn(result["providers"]["cloudflare"]["status"], ("TIMEOUT", "ERROR"))
        self.assertEqual(result["all_addresses"], [])
        self.assertEqual(result["outcome"], "providers_unavailable")
        self.assertFalse(result["comparison"]["match"])
        # Provider failure must not create a fabricated successful scan/result.
        self.assertNotEqual(result["outcome"], "resolved")

    def test_unsafe_destination_ip_blocked_by_ssrf_protections(self):
        def responder(url, params=None, headers=None):
            qtype = (params or {}).get("type")
            # Both providers resolve to cloud-metadata/link-local unsafe destination (blocked by existing SSRF protections)
            if qtype == "A":
                return _FakeResponse(200, _doh_payload(0, _answers([(1, "169.254.169.254")])))
            if qtype == "AAAA":
                return _FakeResponse(200, _doh_payload(0, _answers([(28, "fe80::1")])))
            return _FakeResponse(200, _doh_payload(0, []))

        with _patch_httpx(responder):
            result = perform_dns_verification(
                "evil.example",
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                timeout=2.0,
            )

        self.assertIn("169.254.169.254", result["all_addresses"])
        self.assertEqual(result["outcome"], "resolved_but_blocked")
        self.assertFalse(result["safety"]["ok"])
        self.assertTrue(result["safety"]["reason"])

    def test_existing_local_juice_shop_target_connection_preserved(self):
        # Uses existing authorized local target. If Juice Shop is not running, skip honestly.
        url = "http://127.0.0.1:3000"
        try:
            s = socket.create_connection(("127.0.0.1", 3000), timeout=0.5)
            s.close()
        except Exception:
            self.skipTest("Local Juice Shop target http://127.0.0.1:3000 is not reachable in this environment")

        # Mock DoH to "both unavailable" to ensure provider failure does not fabricate success
        # and does not break existing local authorized scan behavior (IP literal/local resolution path).
        def responder(url, params=None, headers=None):
            raise TimeoutError("providers unavailable")

        with _patch_httpx(responder):
            result = run_scan(
                target_url=url,
                output_html=None,
                output_json=None,
                delay=0.0,
                timeout=5.0,
                i_have_permission=True,
                scan_mode=SCAN_MODE_AUTHORIZED_ASSESSMENT,
                verbose=False,
            )

        self.assertIn("dns_verification", result)
        self.assertIsInstance(result.get("dns_verification"), dict)
        # Genuine scan result must come from real target connectivity, not DNS providers.
        self.assertIn(result.get("status"), ("completed", "failed", "cancelled"))
        if result.get("status") == "completed":
            self.assertEqual(result.get("http_outcome"), "http_200")
        else:
            # If it failed, it must be a genuine recorded failure, not fabricated success.
            self.assertNotEqual(result.get("grade"), "A")
        # For IP literal target, external DoH lookup is intentionally skipped; verification remains transparent.
        self.assertIn(result["dns_verification"].get("outcome"), ("ip_literal", "providers_unavailable", "unresolved", "verification_error", "localhost"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
