"""
core/safety.py - Target validation and SSRF-safe network checks for CONFIGRA.

Provides hostname resolution, IP classification, and URL/destination validation
for authorized, non-destructive scanning. All destination checks are intended
to be re-applied on redirects and before requests to reduce DNS rebinding risk.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse, urlunparse

ALLOWED_SCHEMES = {"http", "https"}

# Common cloud metadata hostnames (best-effort; IP-range checks are primary).
CLOUD_METADATA_HOSTNAMES = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "metadata.azure.com",
    "169.254.169.254",
    "100.100.100.200",  # Alibaba metadata (also reserved/link-local-like handling varies)
}

# Explicit cloud metadata IPs (covered by link-local/reserved checks as well).
CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
}


@dataclass
class ValidationResult:
    ok: bool
    reason: str = ""
    resolved_ips: List[str] = None
    normalized_url: str = ""

    def __post_init__(self):
        if self.resolved_ips is None:
            self.resolved_ips = []


def normalize_target_url(target_url: str) -> str:
    target_url = (target_url or "").strip()
    if not target_url:
        return target_url
    if "://" not in target_url:
        target_url = "http://" + target_url
    return target_url


def _is_cloud_metadata_ip(ip_obj: ipaddress._BaseAddress) -> bool:
    if ip_obj in CLOUD_METADATA_IPS:
        return True
    # AWS/Azure/GCP IMDS IPv4 link-local endpoint range equivalent checks
    if ip_obj.version == 4 and str(ip_obj) == "169.254.169.254":
        return True
    return False


def classify_ip(ip_obj: ipaddress._BaseAddress) -> Set[str]:
    labels: Set[str] = set()
    if ip_obj.is_loopback:
        labels.add("loopback")
    if ip_obj.is_private:
        labels.add("private")
    if ip_obj.is_link_local:
        labels.add("link_local")
    if ip_obj.is_multicast:
        labels.add("multicast")
    if ip_obj.is_reserved:
        labels.add("reserved")
    if ip_obj.is_unspecified:
        labels.add("unspecified")
    if _is_cloud_metadata_ip(ip_obj):
        labels.add("cloud_metadata")
    # Treat IPv6 unique-local as private/internal for SSRF safety
    try:
        if getattr(ip_obj, "is_private", False):
            labels.add("private")
    except Exception:
        pass
    return labels


def is_disallowed_for_authorized_scan(ip_obj: ipaddress._BaseAddress) -> Tuple[bool, str]:
    """
    For authorized scans, allow legitimate public targets and safe local-lab
    targets (loopback/private RFC1918/ULA) while blocking high-risk destinations:
    link-local, multicast, unspecified, cloud-metadata endpoints, and other
    dangerous reserved/non-global destinations.
    """
    labels = classify_ip(ip_obj)

    # Always block explicitly dangerous destination classes.
    blocked = {"link_local", "multicast", "unspecified", "cloud_metadata"}
    hit = sorted(labels & blocked)
    if hit:
        return True, ",".join(hit)

    # Explicitly allow loopback for authorized local testing, including IPv4/IPv6
    # loopback (127.0.0.1, ::1), even if a platform IP classifier also marks
    # loopback with an additional flag (e.g. reserved).
    if ip_obj.is_loopback:
        return False, ""

    # Block other dangerous reserved / special-use destinations (excluding
    # loopback handled above). Defense-in-depth for ranges that may be classified
    # inconsistently across runtimes.
    if ip_obj.is_reserved:
        return True, "reserved"
    try:
        if ip_obj.version == 4 and ip_obj in ipaddress.ip_network("240.0.0.0/4"):
            return True, "reserved"
        if ip_obj.version == 4 and ip_obj in ipaddress.ip_network("192.0.0.0/29"):
            return True, "reserved"
        if ip_obj.version == 6 and ip_obj in ipaddress.ip_network("2001:db8::/32"):
            return True, "reserved"
    except Exception:
        pass

    # Allow safe private/local-lab ranges (RFC1918, IPv6 ULA) as authorized
    # local targets, but never override the dangerous classes/ranges above.
    if ip_obj.is_private:
        return False, ""

    # Allow normal global/public destinations.
    if ip_obj.is_global:
        return False, ""

    # Block other non-global/non-lab ranges (e.g. carrier-grade NAT treated cautiously).
    return True, "non_global"


def is_disallowed_for_passive_public_scan(ip_obj: ipaddress._BaseAddress) -> Tuple[bool, str]:
    """
    For Passive Public Inspection, allow safe public/global and local-lab destinations
    for non-intrusive, publicly observable inspection while preserving SSRF protections.
    Blocks link-local, reserved, multicast, unspecified, cloud-metadata, and other
    non-global/non-lab ranges.
    """
    # Same destination safety envelope as authorized scans, but caller/mode enforces
    # passive-only request behavior and public-target confirmation semantics.
    return is_disallowed_for_authorized_scan(ip_obj)


def is_allowed_without_permission(ip_obj: ipaddress._BaseAddress) -> bool:
    # Default mode: restrict to loopback and RFC1918/private network targets.
    labels = classify_ip(ip_obj)
    # Block high-risk destinations first.
    if "cloud_metadata" in labels or "link_local" in labels or "multicast" in labels or "unspecified" in labels:
        return False
    # Explicitly allow loopback for local testing (including IPv6 ::1) even if a
    # platform IP classifier also marks it with an additional flag (e.g. reserved).
    if ip_obj.is_loopback:
        return True
    # Block other dangerous reserved / special-use destinations (excluding loopback).
    if ip_obj.is_reserved:
        return False
    try:
        if ip_obj.version == 4 and ip_obj in ipaddress.ip_network("240.0.0.0/4"):
            return False
        if ip_obj.version == 4 and ip_obj in ipaddress.ip_network("192.0.0.0/29"):
            return False
        if ip_obj.version == 6 and ip_obj in ipaddress.ip_network("2001:db8::/32"):
            return False
    except Exception:
        pass
    # Allow explicit safe private/local-lab targets.
    if ip_obj.is_private:
        return True
    return False


def resolve_hostname_ips(hostname: str, port: Optional[int] = None) -> List[str]:
    if not hostname:
        raise ValueError("Missing hostname")
    infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    ips: List[str] = []
    seen: Set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = sockaddr[0]
        if ip_str not in seen:
            seen.add(ip_str)
            ips.append(ip_str)
    if not ips:
        raise ValueError("No IP addresses resolved")
    return ips


def validate_url_target(
    url: str,
    i_have_permission: bool,
    *,
    require_scheme: bool = True,
    allow_default_port_resolution: bool = True,
    scan_mode: str = "authorized_assessment",
) -> ValidationResult:
    normalized = normalize_target_url(url)
    parsed = urlparse(normalized)
    scheme = (parsed.scheme or "").lower()
    hostname = parsed.hostname
    scan_mode = (scan_mode or "authorized_assessment").strip().lower()

    if require_scheme and scheme not in ALLOWED_SCHEMES:
        return ValidationResult(False, f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed.", normalized_url=normalized)
    if scheme and scheme not in ALLOWED_SCHEMES:
        return ValidationResult(False, f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed.", normalized_url=normalized)
    if not hostname:
        return ValidationResult(False, "Could not determine a valid hostname from the target URL.", normalized_url=normalized)

    if hostname.lower() in CLOUD_METADATA_HOSTNAMES:
        return ValidationResult(False, "Target hostname is a blocked cloud-metadata endpoint.", normalized_url=normalized)

    try:
        port = parsed.port
        if port is None and allow_default_port_resolution:
            port = 443 if scheme == "https" else 80
        ip_strings = resolve_hostname_ips(hostname, port)
    except Exception as exc:
        return ValidationResult(False, f"Failed to resolve hostname '{hostname}': {exc}", normalized_url=normalized)

    resolved_ips: List[str] = []
    for ip_str in ip_strings:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return ValidationResult(False, f"Resolved invalid IP address '{ip_str}' for host '{hostname}'.", normalized_url=normalized)
        resolved_ips.append(str(ip_obj))

        if scan_mode == "passive_public":
            disallowed, why = is_disallowed_for_passive_public_scan(ip_obj)
            if disallowed:
                return ValidationResult(
                    False,
                    (
                        f"Target '{hostname}' resolves to blocked destination {ip_obj} ({why}). "
                        "Link-local, reserved, multicast, unspecified, and cloud-metadata destinations are not allowed."
                    ),
                    resolved_ips=resolved_ips,
                    normalized_url=normalized,
                )
            continue

        if not i_have_permission:
            if not is_allowed_without_permission(ip_obj):
                labels = ",".join(sorted(classify_ip(ip_obj))) or "public"
                return ValidationResult(
                    False,
                    (
                        f"Target '{hostname}' resolves to disallowed/public IP {ip_obj} ({labels}). "
                        "Public or non-private targets require explicit authorized testing confirmation."
                    ),
                    resolved_ips=resolved_ips,
                    normalized_url=normalized,
                )
        else:
            disallowed, why = is_disallowed_for_authorized_scan(ip_obj)
            if disallowed:
                return ValidationResult(
                    False,
                    (
                        f"Target '{hostname}' resolves to blocked destination {ip_obj} ({why}). "
                        "Link-local, reserved, multicast, unspecified, and cloud-metadata destinations are not allowed."
                    ),
                    resolved_ips=resolved_ips,
                    normalized_url=normalized,
                )

    return ValidationResult(True, "", resolved_ips=resolved_ips, normalized_url=normalized)


def validate_redirect_location(
    current_url: str,
    location: str,
    i_have_permission: bool,
    scan_mode: str = "authorized_assessment",
) -> ValidationResult:
    if not location:
        return ValidationResult(False, "Redirect response missing Location header.")
    # Resolve relative redirects against current URL
    parsed_loc = urlparse(location)
    if not parsed_loc.scheme:
        # relative URL
        from urllib.parse import urljoin
        absolute = urljoin(current_url, location)
    else:
        absolute = location
    return validate_url_target(absolute, i_have_permission, require_scheme=True, scan_mode=scan_mode)
