"""
core/context.py - Scan execution context and SSRF-safe polite HTTP client wrapper

Manages scan configuration, HTTP session state, request budgeting,
rate-limiting delays, redirect/destination validation, cancellation, and
home page / extra page discovery.
"""

from __future__ import annotations

import re
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from core.models import (
    SCAN_MODE_AUTHORIZED_ASSESSMENT,
    SCAN_MODE_LABELS,
    SCAN_MODE_PASSIVE_PUBLIC,
    VALID_SCAN_MODES,
)
from core.safety import (
    ALLOWED_SCHEMES,
    ValidationResult,
    normalize_target_url,
    validate_redirect_location,
    validate_url_target,
)


class ScanCancelled(Exception):
    """Raised when a scan is cancelled cooperatively."""


class ScanContext:
    """
    Maintains state, SSRF-safe request handling, rate limiting, and HTTP session
    for a single non-destructive security scan.
    """

    def __init__(
        self,
        base_url: str,
        delay: float = 0.3,
        timeout: float = 10.0,
        max_requests: int = 60,
        verify_ssl: bool = True,
        i_have_permission: bool = False,
        max_redirects: int = 3,
        cancel_event: Optional[threading.Event] = None,
        allow_private_targets: Optional[bool] = None,
        scan_mode: str = SCAN_MODE_AUTHORIZED_ASSESSMENT,
    ):
        normalized_mode = (scan_mode or SCAN_MODE_AUTHORIZED_ASSESSMENT).strip().lower()
        if normalized_mode not in VALID_SCAN_MODES:
            normalized_mode = SCAN_MODE_AUTHORIZED_ASSESSMENT
        self.scan_mode = normalized_mode
        self.scan_mode_label = SCAN_MODE_LABELS.get(self.scan_mode, SCAN_MODE_LABELS[SCAN_MODE_AUTHORIZED_ASSESSMENT])

        normalized = normalize_target_url(base_url).rstrip("/")
        self.base_url = normalized
        parsed = urlparse(self.base_url)
        self.scheme = (parsed.scheme or "http").lower()
        self.netloc = parsed.netloc
        self.hostname = parsed.hostname or ""

        # Conservative defaults for passive public inspection
        if self.scan_mode == SCAN_MODE_PASSIVE_PUBLIC:
            delay = max(float(delay), 0.5)
            timeout = min(max(0.1, float(timeout)), 10.0)
            max_requests = min(max(1, int(max_requests)), 6)
            max_redirects = min(max(0, int(max_redirects)), 3)

        self.delay = max(0.0, float(delay))
        self.timeout = max(0.1, float(timeout))
        self.max_requests = max(1, int(max_requests))
        self.verify_ssl = bool(verify_ssl)
        self.i_have_permission = bool(i_have_permission)
        # Backward-compat hint used by some callers/tests; authorization is primary control.
        self.allow_private_targets = allow_private_targets
        self.max_redirects = max(0, int(max_redirects))
        self.cancel_event = cancel_event

        self.request_count = 0
        self.errors: List[str] = []
        self.notices: List[str] = []

        # Scan/runtime metadata for transparent reporting
        self.rate_limit_events: List[Dict[str, Any]] = []
        self.waf_indicators: List[Dict[str, Any]] = []
        self.tls_observations: Dict[str, Any] = {}
        self.stop_requests_reason: str = ""
        self.connection_outcome: str = "not_attempted"
        self.http_outcome: str = "not_attempted"
        self.dns_outcome: str = "unknown"

        self.session = requests.Session()
        ua_mode = "passive-public-inspection" if self.scan_mode == SCAN_MODE_PASSIVE_PUBLIC else "authorized-security-assessment"
        self.session.headers["User-Agent"] = f"CONFIGRA/1.0 ({ua_mode}; non-destructive)"
        self.session.verify = self.verify_ssl

        self.home_response: Optional[requests.Response] = None
        self.home_url: str = self.base_url
        self.resolved_ips: List[str] = []
        self.extra_pages: List[requests.Response] = []
        self.all_pages: List[requests.Response] = []
        self.home_unobservable: bool = False
        self.home_unobservable_reason: str = ""
        self._blocking_response: Optional[requests.Response] = None

    @property
    def cancelled(self) -> bool:
        return bool(self.cancel_event and self.cancel_event.is_set())

    @property
    def is_passive_public(self) -> bool:
        return self.scan_mode == SCAN_MODE_PASSIVE_PUBLIC

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise ScanCancelled("Scan cancelled by user.")

    def _record_error(self, msg: str) -> None:
        msg = str(msg)
        if msg and msg not in self.errors:
            self.errors.append(msg)

    def _record_notice(self, msg: str) -> None:
        msg = str(msg)
        if msg and msg not in self.notices:
            self.notices.append(msg)

    def _sleep_politely(self) -> None:
        if self.request_count > 0 and self.delay > 0:
            # Sleep in short chunks to remain responsive to cancellation.
            end = time.monotonic() + self.delay
            while time.monotonic() < end:
                if self.cancelled:
                    break
                remaining = end - time.monotonic()
                time.sleep(min(0.05, max(0.0, remaining)))

    def _resolve_url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        base = (getattr(self, "home_url", None) or self.base_url).rstrip("/") + "/"
        return urljoin(base, str(path_or_url).lstrip("/"))

    def _validate_destination(self, url: str) -> ValidationResult:
        return validate_url_target(url, self.i_have_permission, scan_mode=self.scan_mode)

    def _parse_retry_after(self, value: Optional[str]) -> Dict[str, Any]:
        if not value:
            return {"raw": None, "seconds": None, "date": None}
        raw = str(value).strip()
        if not raw:
            return {"raw": None, "seconds": None, "date": None}
        # Seconds form
        if raw.isdigit():
            return {"raw": raw, "seconds": int(raw), "date": None}
        # HTTP-date form
        try:
            dt = parsedate_to_datetime(raw)
            if dt is not None:
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = max(0, int((dt - now).total_seconds()))
                return {"raw": raw, "seconds": delta, "date": dt.isoformat()}
        except Exception:
            pass
        return {"raw": raw, "seconds": None, "date": None}

    def _classify_intermediary(self, response: Optional[requests.Response]) -> Optional[Dict[str, Any]]:
        if response is None:
            return None
        headers = response.headers or {}
        status = getattr(response, "status_code", None)
        server = str(headers.get("Server", "") or "")
        cf_ray = headers.get("CF-RAY") or headers.get("Cf-Ray")
        cf_cache = headers.get("CF-Cache-Status") or headers.get("Cf-Cache-Status")
        cf_chl = headers.get("CF-CHL-Bypass") or headers.get("Cf-Chl-Bypass")
        body = ""
        try:
            body = (response.text or "")[:4000]
        except Exception:
            body = ""
        body_lower = body.lower()
        indicators: List[str] = []
        confidence = "suspected"
        provider = "unknown"

        if cf_ray:
            indicators.append("cf-ray header present")
            provider = "cloudflare"
            confidence = "confirmed"
        if cf_cache:
            indicators.append("cf-cache-status header present")
            provider = "cloudflare"
            confidence = "confirmed"
        if cf_chl:
            indicators.append("cf-chl-bypass header present")
            provider = "cloudflare"
            confidence = "confirmed"
        if "cloudflare" in server.lower():
            indicators.append(f"server header indicates Cloudflare ({server[:120]})")
            provider = "cloudflare"
            confidence = "confirmed"
        elif any(tok in server.lower() for tok in ("akamai", "akamaighost", "fastly", "sucuri", "imperva", "incapsula", "cloudfront", "varnish")):
            indicators.append(f"server/CDN header observed: {server[:120]}")
            provider = server.split("/")[0][:40] or "cdn"
            confidence = "confirmed" if server else "suspected"

        challenge_markers = [
            ("just a moment", "challenge page text"),
            ("checking your browser", "browser challenge text"),
            ("attention required", "interstitial/challenge text"),
            ("cf-challenge", "cloudflare challenge marker"),
            ("captcha", "captcha marker"),
            ("__cf_chl", "cloudflare challenge token marker"),
        ]
        for token, label in challenge_markers:
            if token in body_lower:
                indicators.append(label)
                if provider == "unknown":
                    provider = "cloudflare" if "cf" in token or "cloudflare" in body_lower else "intermediary"
                confidence = "confirmed" if (cf_ray or cf_cache or "cloudflare" in body_lower or provider == "cloudflare") else "suspected"
                break

        if status in (403, 429, 503) and indicators and confidence != "confirmed":
            confidence = "suspected"

        if not indicators:
            return None

        result = {
            "provider": provider,
            "confidence": confidence,
            "status": status,
            "url": getattr(response, "url", ""),
            "indicators": indicators[:8],
            "server": server[:120],
        }
        # De-duplicate similar observations
        key = (result["provider"], result["confidence"], result["status"], tuple(result["indicators"]))
        existing_keys = {
            (e.get("provider"), e.get("confidence"), e.get("status"), tuple(e.get("indicators", [])))
            for e in self.waf_indicators
        }
        if key not in existing_keys:
            self.waf_indicators.append(result)
            level = "confirmed" if confidence == "confirmed" else "suspected"
            self._record_notice(
                f"Intermediary/WAF/CDN response {level} ({provider}) at {result['url']} "
                f"(HTTP {status}): {', '.join(indicators[:3])}"
            )
        return result

    def is_intermediary_challenge(self, response: Optional[requests.Response]) -> bool:
        if response is None:
            return False
        cls = self._classify_intermediary(response)
        if not cls:
            return False
        # Treat as challenge/interstitial when explicit challenge markers observed or 403/503 with strong indicators.
        inds = " ".join(cls.get("indicators", [])).lower()
        status = cls.get("status")
        challenge_terms = ("challenge", "captcha", "interstitial", "token marker", "checking your browser", "just a moment")
        if any(t in inds for t in challenge_terms):
            return True
        if status in (403, 503) and cls.get("confidence") == "confirmed":
            return True
        return False

    def request(self, method: str, path_or_url: str, **kwargs) -> Optional[requests.Response]:
        """
        Perform an SSRF-safe, non-destructive HTTP request with rate limiting,
        request budgeting, redirect revalidation, and cancellation checks.
        Returns None on failure/cancellation and records a contextual error.
        """
        method_u = (method or "GET").upper()
        if self.cancelled:
            self._record_error(f"Scan cancelled before request: {method_u} {path_or_url}")
            return None
        if self.stop_requests_reason:
            self._record_error(
                f"Request skipped due to prior scan constraint ({self.stop_requests_reason}): {method_u} {path_or_url}"
            )
            return None
        if self.request_count >= self.max_requests:
            self._record_error(f"Request budget limit of {self.max_requests} reached. Skipped {method_u} {path_or_url}")
            return None

        current_url = self._resolve_url(path_or_url)
        timeout = kwargs.pop("timeout", self.timeout)
        allow_redirects = bool(kwargs.pop("allow_redirects", True))
        max_redirects = int(kwargs.pop("max_redirects", self.max_redirects))
        headers = kwargs.pop("headers", None)
        req_kwargs = dict(kwargs)

        # Validate initial destination (and re-resolve DNS) before sending.
        v = self._validate_destination(current_url)
        if not v.ok:
            self._record_error(f"Blocked unsafe destination for {method_u} {current_url}: {v.reason}")
            return None
        current_url = v.normalized_url or current_url
        if not self.resolved_ips and v.resolved_ips:
            self.resolved_ips = list(v.resolved_ips)

        for _ in range(max_redirects + 1):
            if self.cancelled:
                self._record_error(f"Scan cancelled before request: {method_u} {current_url}")
                return None
            if self.stop_requests_reason:
                self._record_error(
                    f"Request skipped due to prior scan constraint ({self.stop_requests_reason}): {method_u} {current_url}"
                )
                return None
            if self.request_count >= self.max_requests:
                self._record_error(f"Request budget limit of {self.max_requests} reached. Skipped {method_u} {current_url}")
                return None

            self._sleep_politely()
            if self.cancelled:
                self._record_error(f"Scan cancelled before request: {method_u} {current_url}")
                return None

            # Revalidate destination immediately before request to reduce DNS rebinding risk.
            v = self._validate_destination(current_url)
            if not v.ok:
                self._record_error(f"Blocked unsafe destination for {method_u} {current_url}: {v.reason}")
                return None
            current_url = v.normalized_url or current_url

            try:
                self.request_count += 1
                self.connection_outcome = "attempted"
                response = self.session.request(
                    method_u,
                    current_url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                    **req_kwargs,
                )
                self.connection_outcome = "connected"
            except requests.exceptions.RequestException as exc:
                self.connection_outcome = "failed"
                self.http_outcome = "request_failed"
                self._record_error(f"Request failed for {current_url}: {exc}")
                return None

            self.http_outcome = f"http_{response.status_code}"
            self._classify_intermediary(response)

            # Conservative HTTP 429 / Retry-After handling: never retry/bypass.
            if response.status_code == 429:
                ra_raw = response.headers.get("Retry-After")
                ra = self._parse_retry_after(ra_raw)
                ev = {
                    "url": getattr(response, "url", current_url),
                    "status": 429,
                    "retry_after": ra,
                    "headers": {
                        k: v
                        for k, v in {
                            "Retry-After": ra_raw,
                            "X-RateLimit-Limit": response.headers.get("X-RateLimit-Limit"),
                            "X-RateLimit-Remaining": response.headers.get("X-RateLimit-Remaining"),
                            "X-RateLimit-Reset": response.headers.get("X-RateLimit-Reset"),
                        }.items()
                        if v is not None
                    },
                }
                self.rate_limit_events.append(ev)
                self.stop_requests_reason = "http_429_rate_limited"
                wait_msg = ""
                if ra.get("seconds") is not None:
                    wait_msg = f" Retry-After suggests waiting ~{ra['seconds']}s."
                elif ra.get("raw"):
                    wait_msg = f" Retry-After: {ra['raw']}."
                self._record_error(
                    f"HTTP 429 rate-limited response received for {ev['url']}.{wait_msg} "
                    "Stopping further requests conservatively (no retries, no bypass)."
                )
                # Preserve evidence but do not treat as normal origin content.
                self._blocking_response = response
                return None

            # Intermediary challenge/captcha responses may prevent origin observation.
            if self.is_intermediary_challenge(response):
                self.stop_requests_reason = self.stop_requests_reason or "intermediary_challenge"
                self._record_error(
                    f"Intermediary challenge/interstitial response observed for {getattr(response, 'url', current_url)} "
                    f"(HTTP {response.status_code}); origin security posture may not be fully observable."
                )
                # Preserve evidence but do not analyze as origin configuration.
                self._blocking_response = response
                return None

            if allow_redirects and response.is_redirect:
                location = response.headers.get("Location", "")
                if not location:
                    self._record_error(f"Redirect response missing Location header for {current_url}")
                    return None
                rv = validate_redirect_location(current_url, location, self.i_have_permission, scan_mode=self.scan_mode)
                if not rv.ok:
                    self._record_error(f"Blocked unsafe redirect from {current_url} -> {location}: {rv.reason}")
                    return None
                # Follow redirect with GET/HEAD semantics not changed here except preserving method by default;
                # callers needing specific behavior can disable redirects.
                current_url = rv.normalized_url or urljoin(current_url, location)
                # Do not let response bodies accumulate for redirect hops; continue.
                response.close()
                continue

            return response

        self._record_error(f"Exceeded maximum redirects ({max_redirects}) while requesting {path_or_url}")
        return None

    def get(self, path_or_url: str, **kwargs) -> Optional[requests.Response]:
        """
        Polite safe GET request. Returns None on failure and records the error.
        Signature/behavior kept compatible with existing callers.
        """
        return self.request("GET", path_or_url, **kwargs)

    def observe_tls(self) -> Dict[str, Any]:
        """Non-intrusive TLS certificate/config observation for HTTPS targets."""
        if self.scheme != "https":
            self.tls_observations = {
                "applicable": False,
                "status": "not_applicable",
                "note": "Target is not HTTPS; TLS certificate observation not applicable.",
            }
            return self.tls_observations

        host = self.hostname or urlparse(self.base_url).hostname or ""
        port = urlparse(self.base_url).port or 443
        obs: Dict[str, Any] = {
            "applicable": True,
            "hostname": host,
            "port": port,
            "sni_hostname": host,
            "verification_enabled": bool(self.verify_ssl),
            "status": "not_observed",
            "certificate": None,
            "protocol": None,
            "cipher": None,
            "error": None,
            "limitations": [],
        }
        if not host:
            obs["status"] = "error"
            obs["error"] = "Missing hostname for TLS observation."
            self.tls_observations = obs
            return obs

        if not self.verify_ssl:
            obs["limitations"].append(
                "Certificate verification was disabled (--insecure/insecure=true); TLS certificate validation result is not authoritative."
            )

        try:
            raw_ctx = ssl.create_default_context()
            raw_ctx.check_hostname = False
            raw_ctx.verify_mode = ssl.CERT_NONE
            cert_dict = None
            negotiated_protocol = None
            cipher = None
            der_cert = None
            with socket.create_connection((host, port), timeout=min(self.timeout, 10.0)) as sock:
                with raw_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    try:
                        cert_dict = ssock.getpeercert()
                    except Exception:
                        cert_dict = None
                    try:
                        der_cert = ssock.getpeercert(binary_form=True)
                    except Exception:
                        der_cert = None
                    try:
                        negotiated_protocol = ssock.version()
                    except Exception:
                        negotiated_protocol = None
                    try:
                        c = ssock.cipher()
                        if c:
                            cipher = {"name": c[0], "protocol": c[1], "bits": c[2]}
                    except Exception:
                        cipher = None
            obs["protocol"] = negotiated_protocol
            obs["cipher"] = cipher
            if cert_dict:
                subject = {}
                for rdn in cert_dict.get("subject", []):
                    for k, v in rdn:
                        subject[k] = v
                issuer = {}
                for rdn in cert_dict.get("issuer", []):
                    for k, v in rdn:
                        issuer[k] = v
                sans = [v for (k, v) in cert_dict.get("subjectAltName", []) if k.lower() in ("dns", "ip address")]
                obs["certificate"] = {
                    "subject": subject,
                    "issuer": issuer,
                    "notBefore": cert_dict.get("notBefore"),
                    "notAfter": cert_dict.get("notAfter"),
                    "serialNumber": cert_dict.get("serialNumber"),
                    "version": cert_dict.get("version"),
                    "subjectAltName": sans,
                }
                # Hostname match check (best-effort)
                try:
                    ssl.match_hostname(cert_dict, host)
                    obs["hostname_match"] = True
                except Exception as me:
                    obs["hostname_match"] = False
                    obs["hostname_match_error"] = str(me)
            else:
                # Some runtimes return limited/no dict in unverified handshakes; parse DER cert if available.
                parsed_der = False
                if der_cert:
                    try:
                        from cryptography import x509 as _x509
                        from cryptography.hazmat.backends import default_backend as _default_backend

                        cert_obj = _x509.load_der_x509_certificate(der_cert, _default_backend())
                        subj = {}
                        iss = {}
                        for attr in cert_obj.subject:
                            try:
                                subj[attr.oid._name] = attr.value
                            except Exception:
                                subj[getattr(attr.oid, "dotted_string", "attr")] = attr.value
                        for attr in cert_obj.issuer:
                            try:
                                iss[attr.oid._name] = attr.value
                            except Exception:
                                iss[getattr(attr.oid, "dotted_string", "attr")] = attr.value
                        try:
                            san_ext = cert_obj.extensions.get_extension_for_class(_x509.SubjectAlternativeName).value
                            sans = []
                            for n in san_ext:
                                try:
                                    sans.append(str(n.value))
                                except Exception:
                                    pass
                        except Exception:
                            sans = []
                        not_before = (
                            cert_obj.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT")
                            if hasattr(cert_obj, "not_valid_before_utc")
                            else str(cert_obj.not_valid_before)
                        )
                        not_after = (
                            cert_obj.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
                            if hasattr(cert_obj, "not_valid_after_utc")
                            else str(cert_obj.not_valid_after)
                        )
                        obs["certificate"] = {
                            "subject": subj,
                            "issuer": iss,
                            "notBefore": not_before,
                            "notAfter": not_after,
                            "serialNumber": format(cert_obj.serial_number, "X"),
                            "version": getattr(getattr(cert_obj, "version", None), "name", None),
                            "subjectAltName": sans,
                        }
                        # Best-effort hostname match from parsed certificate info
                        try:
                            import ipaddress as _ipaddress

                            host_is_ip = False
                            try:
                                _ipaddress.ip_address(host)
                                host_is_ip = True
                            except Exception:
                                host_is_ip = False
                            host_l = host.lower()
                            cn = str(subj.get("commonName") or subj.get("CN") or "")
                            cn_l = cn.lower()
                            matched = False
                            if sans:
                                for san in sans:
                                    s_l = str(san).lower()
                                    if host_is_ip:
                                        if s_l == host_l:
                                            matched = True
                                            break
                                    else:
                                        if s_l.startswith("*."):
                                            suffix = s_l[1:]  # ".example.com"
                                            if host_l.endswith(suffix) and host_l.count(".") >= suffix.count("."):
                                                matched = True
                                                break
                                        elif s_l == host_l:
                                            matched = True
                                            break
                            if not matched and not host_is_ip and cn_l:
                                if cn_l.startswith("*."):
                                    suffix = cn_l[1:]
                                    matched = host_l.endswith(suffix) and host_l.count(".") >= suffix.count(".")
                                else:
                                    matched = cn_l == host_l
                            obs["hostname_match"] = matched
                            if not matched:
                                obs["hostname_match_error"] = "Hostname does not match presented certificate subject/SANs (best-effort check)."
                        except Exception:
                            obs.setdefault("hostname_match", None)
                        parsed_der = True
                    except Exception:
                        parsed_der = False
                if not parsed_der:
                    obs["limitations"].append("Peer certificate details were not available from the TLS handshake.")

            # Verification outcome using validating context
            if self.verify_ssl:
                try:
                    verify_ctx = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=min(self.timeout, 10.0)) as vsock:
                        with verify_ctx.wrap_socket(vsock, server_hostname=host) as vssock:
                            _ = vssock.version()
                    obs["verification_ok"] = True
                    obs["verification_error"] = None
                except Exception as ve:
                    obs["verification_ok"] = False
                    obs["verification_error"] = str(ve)
            else:
                obs["verification_ok"] = None
                obs["verification_error"] = "Verification disabled by scan configuration."

            obs["status"] = "observed"
        except Exception as exc:
            obs["status"] = "error"
            obs["error"] = str(exc)
            # Attempt verification-only classification if not already known
            if self.verify_ssl and obs.get("verification_ok") is None:
                try:
                    verify_ctx = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=min(self.timeout, 10.0)) as vsock:
                        with verify_ctx.wrap_socket(vsock, server_hostname=host):
                            pass
                    obs["verification_ok"] = True
                except Exception as ve:
                    obs["verification_ok"] = False
                    obs["verification_error"] = str(ve)

        self.tls_observations = obs
        return obs

    def initialize(self) -> bool:
        """
        Fetches the target home page and discovers extra same-origin pages
        (authorized mode only, bounded). Returns False if the home page is
        unreachable or blocked.
        """
        # Dual DNS-over-HTTPS verification (Google + Cloudflare) for transparency/safety checks.
        # Provider failures must not fabricate scan success; existing SSRF-safe validation/scan
        # behavior remains authoritative for actual connectivity.
        try:
            from core.dns_verification import perform_dns_verification

            self.dns_verification = perform_dns_verification(
                self.hostname or "",
                i_have_permission=self.i_have_permission,
                scan_mode=self.scan_mode,
            )
            # Record provider-level issues as diagnostics (not fabricated results)
            providers = (self.dns_verification or {}).get("providers", {}) or {}
            for pname, pdata in providers.items():
                pst = (pdata or {}).get("status")
                perr = (pdata or {}).get("error")
                if pst in ("TIMEOUT", "ERROR"):
                    msg = f"DNS provider {pname} unavailable/failed during verification"
                    if perr:
                        msg += f": {perr}"
                    self._record_error(msg)
            # Public DoH results are advisory here: local/system DNS resolution remains
            # authoritative for actual connectivity (split-horizon/private DNS). The
            # destination validation below and the request pipeline enforce SSRF safety
            # on the addresses that will actually be contacted.
            outcome = (self.dns_verification or {}).get("outcome")
            if outcome == "nxdomain":
                self._record_notice(
                    f"Public DNS providers report NXDOMAIN for '{self.hostname}'; local/system DNS "
                    "resolution remains authoritative (possible split-horizon/private DNS)."
                )
            safety = (self.dns_verification or {}).get("safety") or {}
            if outcome == "resolved_but_blocked" or (safety and not safety.get("ok", True)):
                reason = safety.get("reason") or "DNS-resolved destination blocked by SSRF protections."
                self._record_notice(
                    f"Public DNS verification flagged resolved destination(s) as blocked ({reason}); "
                    "local/system destination validation remains authoritative and will block unsafe connections."
                )
        except Exception as exc:
            # Do not fail closed on verification subsystem errors; existing validation still applies.
            self.dns_verification = {
                "hostname": self.hostname or "",
                "queried": False,
                "providers": {},
                "comparison": {"match": False, "summary": f"DNS verification error: {exc}", "common_addresses": [], "all_addresses": []},
                "all_addresses": [],
                "outcome": "verification_error",
                "error": str(exc),
            }
            self._record_error(f"DNS verification error: {exc}")

        # Validate base target once up front for clear early failure.
        base_validation = self._validate_destination(self.base_url)
        if not base_validation.ok:
            if self.dns_outcome not in ("failed", "blocked"):
                self.dns_outcome = "resolution_or_validation_failed"
            self._record_error(f"Target validation failed for {self.base_url}: {base_validation.reason}")
            return False
        self.dns_outcome = "resolved"
        if base_validation.resolved_ips:
            self.resolved_ips = list(base_validation.resolved_ips)
        if base_validation.normalized_url:
            self.base_url = base_validation.normalized_url.rstrip("/")
            self.home_url = self.base_url

        self.home_response = self.get(self.base_url)
        if self.home_response is None:
            blocking = getattr(self, "_blocking_response", None)
            if blocking is not None and (
                getattr(blocking, "status_code", None) == 429
                or self.is_intermediary_challenge(blocking)
                or self.stop_requests_reason in ("http_429_rate_limited", "intermediary_challenge")
            ):
                # Rate-limited/challenge responses are observed for metadata but not as origin content.
                self.home_response = blocking
                self.home_unobservable = True
                bstatus = getattr(blocking, "status_code", None)
                if bstatus == 429 or self.stop_requests_reason == "http_429_rate_limited":
                    self.home_unobservable_reason = "HTTP 429 rate-limited response prevented origin observation."
                elif bstatus == 403:
                    self.home_unobservable_reason = "HTTP 403 Forbidden observed; access restricted so origin security configuration checks are not reliably testable."
                elif isinstance(bstatus, int) and bstatus >= 500:
                    self.home_unobservable_reason = f"HTTP {bstatus} observed; origin/application response is in an error state so configuration checks are limited and not reliably testable."
                else:
                    self.home_unobservable_reason = "Intermediary/CDN/WAF challenge or interstitial prevented origin observation."
                try:
                    final_url = getattr(blocking, "url", None) or self.base_url
                    parsed_final = urlparse(final_url)
                    if parsed_final.scheme and parsed_final.netloc:
                        self.home_url = final_url
                        self.scheme = parsed_final.scheme.lower()
                        self.netloc = parsed_final.netloc
                        self.hostname = parsed_final.hostname or self.hostname
                except Exception:
                    pass
                self.all_pages = []
                return True

            if self.cancelled:
                self.dns_outcome = self.dns_outcome or "cancelled"
            return False

        # Use final URL after safe redirects as canonical page base for discovery.
        try:
            final_url = getattr(self.home_response, "url", None) or self.base_url
            parsed_final = urlparse(final_url)
            if parsed_final.scheme and parsed_final.netloc:
                self.home_url = final_url
                self.scheme = parsed_final.scheme.lower()
                self.netloc = parsed_final.netloc
                self.hostname = parsed_final.hostname or self.hostname
        except Exception:
            pass

        # If the initial observable response is rate-limited, access-restricted, an error-state page,
        # or an intermediary challenge, do not treat it as reliable origin content for misconfiguration checks.
        status_code = getattr(self.home_response, "status_code", None)
        if status_code == 429 or status_code == 403 or (isinstance(status_code, int) and status_code >= 500) or self.is_intermediary_challenge(self.home_response):
            self.home_unobservable = True
            if status_code == 429:
                self.home_unobservable_reason = "HTTP 429 rate-limited response prevented origin observation."
            elif status_code == 403:
                self.home_unobservable_reason = "HTTP 403 Forbidden observed; access restricted so origin security configuration checks are not reliably testable."
            elif isinstance(status_code, int) and status_code >= 500:
                self.home_unobservable_reason = f"HTTP {status_code} observed; origin/application response is in an error state so configuration checks are limited and not reliably testable."
            else:
                self.home_unobservable_reason = "Intermediary/CDN/WAF challenge or interstitial prevented origin observation."
            self.all_pages = []
            return True

        self.all_pages = [self.home_response]

        # Passive public inspection must remain minimal: no extra page crawling.
        if self.is_passive_public:
            return True

        # Discover up to 3 extra same-origin pages linked from home page HTML
        try:
            self.raise_if_cancelled()
            html = self.home_response.text or ""
            raw_links = re.findall(r'href=["\']([^"\'#\s>]+)["\']', html, re.IGNORECASE)
            candidates = []
            excluded_exts = (
                ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                ".css", ".js", ".map", ".woff", ".woff2", ".ttf",
                ".pdf", ".zip", ".tar", ".gz",
            )

            base_for_join = self.home_url.rstrip("/") + "/"
            for link in raw_links:
                if self.cancelled:
                    break
                if link.startswith("javascript:") or link.startswith("mailto:") or link.startswith("#"):
                    continue

                full_link = urljoin(base_for_join, link)
                parsed_link = urlparse(full_link)

                if (parsed_link.scheme or "").lower() not in ALLOWED_SCHEMES:
                    continue
                # Same-origin check (scheme + host + port/netloc)
                if parsed_link.netloc == self.netloc and (parsed_link.scheme or "").lower() == self.scheme:
                    path = parsed_link.path or "/"
                    if path not in ("/", "") and not any(path.lower().endswith(ext) for ext in excluded_exts):
                        # Keep full URL for validation/redirect safety; dedupe by path+query
                        key = (parsed_link.path, parsed_link.query)
                        if all((urlparse(c).path, urlparse(c).query) != key for c in candidates) and full_link.rstrip("/") != self.base_url.rstrip("/"):
                            candidates.append(full_link)
                            if len(candidates) >= 3:
                                break

            for extra_url in candidates:
                if self.cancelled:
                    self._record_error("Scan cancelled during page discovery.")
                    break
                if self.stop_requests_reason:
                    self._record_error(f"Page discovery stopped due to {self.stop_requests_reason}.")
                    break
                resp = self.get(extra_url)
                if resp is not None:
                    self.extra_pages.append(resp)
                    self.all_pages.append(resp)

        except ScanCancelled:
            self._record_error("Scan cancelled during initialization.")
        except Exception as exc:
            self._record_error(f"Error discovering additional pages: {exc}")

        return True
