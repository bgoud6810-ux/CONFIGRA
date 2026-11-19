import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.safety import validate_url_target, validate_redirect_location, resolve_hostname_ips


class TestSafetyValidation(unittest.TestCase):
    def test_ipv4_loopback_allowed_for_authorized_local_testing(self):
        for permission in (False, True):
            with self.subTest(i_have_permission=permission):
                result = validate_url_target(
                    "http://127.0.0.1:8000/",
                    i_have_permission=permission,
                    scan_mode="authorized_assessment",
                )
                self.assertTrue(result.ok, msg=result.reason)
                self.assertIn("127.0.0.1", result.resolved_ips)

    def test_ipv6_loopback_allowed_for_authorized_local_testing(self):
        for permission in (False, True):
            with self.subTest(i_have_permission=permission):
                result = validate_url_target(
                    "http://[::1]:8000/",
                    i_have_permission=permission,
                    scan_mode="authorized_assessment",
                )
                self.assertTrue(result.ok, msg=result.reason)
                self.assertIn("::1", result.resolved_ips)
                self.assertNotIn("blocked destination", (result.reason or "").lower())

    def test_localhost_allowed_when_resolving_to_ipv4_and_ipv6_loopback(self):
        # Regression for: "Target 'localhost' resolves to blocked destination ::1 (reserved)."
        original_resolver = resolve_hostname_ips
        try:
            import core.safety as safety

            safety.resolve_hostname_ips = lambda hostname, port=None: ["127.0.0.1", "::1"]
            for mode in ("authorized_assessment", "passive_public"):
                for permission in (False, True):
                    with self.subTest(scan_mode=mode, i_have_permission=permission):
                        result = safety.validate_url_target(
                            "http://localhost:3000/",
                            i_have_permission=permission,
                            scan_mode=mode,
                        )
                        self.assertTrue(result.ok, msg=result.reason)
                        self.assertEqual(set(result.resolved_ips), {"127.0.0.1", "::1"})
        finally:
            import core.safety as safety
            safety.resolve_hostname_ips = original_resolver

    def test_ipv6_bracketed_url_parsing_and_validation_regressions(self):
        # Ensure bracketed IPv6 authorities (with port/path/fragment) are parsed and
        # validated correctly: brackets preserved in URL authority/normalization, while
        # validation/connection use the unbracketed hostname/IP (::1).
        from urllib.parse import urlparse

        cases = [
            ("http://localhost:3000", {"127.0.0.1", "::1"}, None),
            ("http://127.0.0.1:3000", {"127.0.0.1"}, None),
            ("http://[::1]:3000", {"::1"}, "[::1]:3000"),
            ("http://[::1]:3000/#/", {"::1"}, "[::1]:3000"),
            ("http://[::1]:3000/path?q=1#frag", {"::1"}, "[::1]:3000"),
            ("https://[::1]:8443/path", {"::1"}, "[::1]:8443"),
        ]
        for url, expected_ip_subset, expected_netloc in cases:
            with self.subTest(url=url):
                result = validate_url_target(url, i_have_permission=True, scan_mode="authorized_assessment")
                self.assertTrue(result.ok, msg=f"{url} => {result.reason}")
                self.assertTrue(expected_ip_subset.issubset(set(result.resolved_ips)), msg=result.resolved_ips)
                self.assertNotEqual((result.resolved_ips or [""])[0], "-1", msg=result.resolved_ips)
                parsed = urlparse(result.normalized_url or url)
                self.assertNotEqual(parsed.hostname, "-1")
                if expected_netloc:
                    self.assertEqual(parsed.netloc, expected_netloc)
                    self.assertIn("[::1]", (result.normalized_url or ""))
                if parsed.hostname and ":" in parsed.hostname:
                    # IPv6 hostname as seen by validators/socket must be unbracketed
                    self.assertEqual(parsed.hostname, "::1")
                self.assertNotIn("blocked destination", (result.reason or "").lower())

    def test_ipv6_redirect_with_path_and_fragment_revalidated(self):
        result = validate_redirect_location(
            "http://localhost:3000/start",
            "http://[::1]:3000/callback?ok=1#frag",
            i_have_permission=True,
            scan_mode="authorized_assessment",
        )
        self.assertTrue(result.ok, msg=result.reason)
        self.assertIn("::1", result.resolved_ips)
        self.assertIn("[::1]:3000", (result.normalized_url or ""))

    def test_passive_public_allows_loopback_for_local_inspection(self):
        result = validate_url_target(
            "http://[::1]/",
            i_have_permission=True,
            scan_mode="passive_public",
        )
        self.assertTrue(result.ok, msg=result.reason)
        self.assertIn("::1", result.resolved_ips)

    def test_redirect_to_ipv6_loopback_revalidated_and_allowed(self):
        result = validate_redirect_location(
            "http://localhost:3000/",
            "http://[::1]:3000/callback",
            i_have_permission=True,
            scan_mode="authorized_assessment",
        )
        self.assertTrue(result.ok, msg=result.reason)
        self.assertIn("::1", result.resolved_ips)

    def test_redirect_to_metadata_blocked(self):
        result = validate_redirect_location(
            "http://localhost:3000/",
            "http://169.254.169.254/latest/meta-data/",
            i_have_permission=True,
            scan_mode="authorized_assessment",
        )
        self.assertFalse(result.ok)
        self.assertIn("blocked", (result.reason or "").lower())

    def test_ssrf_dangerous_destinations_remain_blocked(self):
        cases = [
            ("http://169.254.169.254/", "metadata", True),
            ("http://[fe80::1]/", "link-local", True),
            ("http://224.0.0.1/", "multicast", True),
            ("http://0.0.0.0/", "unspecified", True),
            ("http://240.0.0.1/", "reserved", True),
        ]
        for url, label, permission in cases:
            with self.subTest(target=url, label=label):
                result = validate_url_target(
                    url,
                    i_have_permission=permission,
                    scan_mode="authorized_assessment",
                )
                self.assertFalse(result.ok, msg=f"Expected blocked for {url}, got ok")
                reason = (result.reason or "").lower()
                self.assertTrue(
                    "blocked destination" in reason or "disallowed" in reason or "blocked cloud-metadata" in reason,
                    msg=f"Unexpected reason for {url}: {result.reason}",
                )

    def test_public_target_still_requires_explicit_confirmation_in_authorized_mode(self):
        # Preserve public-target safety controls (no weakening).
        original_resolver = resolve_hostname_ips
        try:
            import core.safety as safety

            safety.resolve_hostname_ips = lambda hostname, port=None: ["93.184.216.34"]
            denied = safety.validate_url_target(
                "http://example.com/",
                i_have_permission=False,
                scan_mode="authorized_assessment",
            )
            self.assertFalse(denied.ok)
            self.assertIn("explicit authorized testing confirmation", denied.reason)

            allowed = safety.validate_url_target(
                "http://example.com/",
                i_have_permission=True,
                scan_mode="authorized_assessment",
            )
            self.assertTrue(allowed.ok, msg=allowed.reason)
            self.assertIn("93.184.216.34", allowed.resolved_ips)
        finally:
            import core.safety as safety
            safety.resolve_hostname_ips = original_resolver

    def test_public_target_blocked_destination_still_enforced_even_with_permission(self):
        # Dangerous destinations must remain blocked regardless of permission.
        result = validate_url_target(
            "http://169.254.169.254/",
            i_have_permission=True,
            scan_mode="authorized_assessment",
        )
        self.assertFalse(result.ok)
        self.assertIn("blocked", (result.reason or "").lower())
