"""
core/dns_verification.py - Dual DNS-over-HTTPS verification for CONFIGRA.

Queries Google Public DNS and Cloudflare DNS-over-HTTPS for A/AAAA records,
records per-provider status/addresses, compares responses, and reports
verification details. Actual HTTP/HTTPS communication remains in the scanner.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any, Dict, List, Optional, Tuple

try:
    import httpx
except Exception:  # pragma: no cover - runtime/dependency guard
    httpx = None  # type: ignore

from core.safety import (
    classify_ip,
    is_allowed_without_permission,
    is_disallowed_for_authorized_scan,
    is_disallowed_for_passive_public_scan,
)

GOOGLE_DOH_URL = "https://dns.google/resolve"
CLOUDFLARE_DOH_URL = "https://cloudflare-dns.com/dns-query"
PROVIDERS = ("google", "cloudflare")
RECORD_TYPES = {"A": 1, "AAAA": 28}
STATUS_NAMES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False


def _normalize_ip(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip().strip('"').rstrip(".")
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        return None


def validate_resolved_ips_for_scan(
    ips: List[str],
    hostname: str,
    i_have_permission: bool,
    scan_mode: str,
) -> Tuple[bool, str, List[str]]:
    """Validate resolved IPs using existing SSRF protections. Returns (ok, reason, normalized_ips)."""
    normalized: List[str] = []
    seen = set()
    scan_mode = (scan_mode or "authorized_assessment").strip().lower()
    for ip_str in ips or []:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except Exception:
            return False, f"Resolved invalid IP address '{ip_str}' for host '{hostname}'.", normalized
        nip = str(ip_obj)
        if nip in seen:
            continue
        seen.add(nip)
        normalized.append(nip)

        if scan_mode == "passive_public":
            disallowed, why = is_disallowed_for_passive_public_scan(ip_obj)
            if disallowed:
                return (
                    False,
                    (
                        f"Target '{hostname}' resolves to blocked destination {ip_obj} ({why}). "
                        "Link-local, reserved, multicast, unspecified, and cloud-metadata destinations are not allowed."
                    ),
                    normalized,
                )
            continue

        if not i_have_permission:
            if not is_allowed_without_permission(ip_obj):
                labels = ",".join(sorted(classify_ip(ip_obj))) or "public"
                return (
                    False,
                    (
                        f"Target '{hostname}' resolves to disallowed/public IP {ip_obj} ({labels}). "
                        "Public or non-private targets require explicit authorized testing confirmation."
                    ),
                    normalized,
                )
        else:
            disallowed, why = is_disallowed_for_authorized_scan(ip_obj)
            if disallowed:
                return (
                    False,
                    (
                        f"Target '{hostname}' resolves to blocked destination {ip_obj} ({why}). "
                        "Link-local, reserved, multicast, unspecified, and cloud-metadata destinations are not allowed."
                    ),
                    normalized,
                )
    return True, "", normalized


async def _query_provider_record(
    client: "httpx.AsyncClient",
    provider: str,
    hostname: str,
    rrtype: str,
) -> Dict[str, Any]:
    type_num = RECORD_TYPES.get(rrtype)
    params = {"name": hostname, "type": rrtype}
    headers: Dict[str, str] = {}
    if provider == "google":
        url = GOOGLE_DOH_URL
    elif provider == "cloudflare":
        url = CLOUDFLARE_DOH_URL
        headers["accept"] = "application/dns-json"
    else:
        return {"status": "ERROR", "addresses": [], "error": f"Unknown provider '{provider}'"}

    try:
        resp = await client.get(url, params=params, headers=headers)
    except Exception as exc:
        msg = str(exc) or exc.__class__.__name__
        low = msg.lower()
        name = exc.__class__.__name__.lower()
        if "timeout" in low or "timed out" in low or "timeout" in name:
            return {"status": "TIMEOUT", "addresses": [], "error": msg}
        return {"status": "ERROR", "addresses": [], "error": msg}

    try:
        if resp.status_code != 200:
            return {"status": "ERROR", "addresses": [], "error": f"HTTP {resp.status_code} from provider"}
        data = resp.json()
    except Exception as exc:
        return {"status": "ERROR", "addresses": [], "error": f"Invalid provider response: {exc}"}

    rcode = data.get("Status")
    try:
        rcode_int = int(rcode) if rcode is not None else None
    except Exception:
        rcode_int = None
    status = STATUS_NAMES.get(rcode_int, f"RCODE_{rcode_int}" if rcode_int is not None else "ERROR")

    addresses: List[str] = []
    for ans in (data.get("Answer") or []):
        try:
            if ans.get("type") != type_num:
                continue
            addr = _normalize_ip(ans.get("data"))
            if addr:
                addresses.append(addr)
        except Exception:
            continue
    # dedupe preserve order
    seen = set()
    uniq = []
    for a in addresses:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return {"status": status, "addresses": uniq, "error": None, "rcode": rcode_int}


async def _query_provider(client: "httpx.AsyncClient", provider: str, hostname: str) -> Dict[str, Any]:
    a_res, aaaa_res = await asyncio.gather(
        _query_provider_record(client, provider, hostname, "A"),
        _query_provider_record(client, provider, hostname, "AAAA"),
    )
    combined: List[str] = []
    seen = set()
    for addr in (a_res.get("addresses") or []) + (aaaa_res.get("addresses") or []):
        if addr not in seen:
            seen.add(addr)
            combined.append(addr)

    statuses = [a_res.get("status"), aaaa_res.get("status")]
    if "NOERROR" in statuses:
        overall = "NOERROR"
    elif "NXDOMAIN" in statuses:
        overall = "NXDOMAIN"
    elif "SERVFAIL" in statuses:
        overall = "SERVFAIL"
    elif "REFUSED" in statuses:
        overall = "REFUSED"
    elif "TIMEOUT" in statuses:
        overall = "TIMEOUT"
    else:
        overall = next((s for s in statuses if s), "ERROR")

    errs = [e for e in [a_res.get("error"), aaaa_res.get("error")] if e]
    return {
        "provider": provider,
        "status": overall,
        "a": {"status": a_res.get("status"), "addresses": list(a_res.get("addresses") or []), "error": a_res.get("error")},
        "aaaa": {"status": aaaa_res.get("status"), "addresses": list(aaaa_res.get("addresses") or []), "error": aaaa_res.get("error")},
        "addresses": combined,
        "error": "; ".join(errs) if errs else None,
    }


async def verify_hostname_dns_async(hostname: str, timeout: float = 5.0) -> Dict[str, Any]:
    hostname = (hostname or "").strip().strip(".")
    result: Dict[str, Any] = {
        "hostname": hostname,
        "queried": False,
        "providers": {},
        "comparison": {},
        "all_addresses": [],
        "error": None,
    }
    if not hostname:
        result["comparison"] = {"match": False, "summary": "Missing hostname.", "common_addresses": [], "all_addresses": []}
        result["error"] = "Missing hostname."
        return result

    if _is_ip_literal(hostname):
        ip_norm = str(ipaddress.ip_address(hostname))
        prov = {
            "provider": "literal",
            "status": "SKIPPED",
            "a": {"status": "SKIPPED", "addresses": [ip_norm] if ":" not in ip_norm else [], "error": None},
            "aaaa": {"status": "SKIPPED", "addresses": [ip_norm] if ":" in ip_norm else [], "error": None},
            "addresses": [ip_norm],
            "error": "IP literal target; DNS-over-HTTPS lookup not required.",
        }
        result["providers"] = {"google": dict(prov, provider="google"), "cloudflare": dict(prov, provider="cloudflare")}
        result["comparison"] = {
            "match": True,
            "summary": "Target is an IP literal; DNS provider lookup skipped.",
            "common_addresses": [ip_norm],
            "all_addresses": [ip_norm],
            "statuses": {"google": "SKIPPED", "cloudflare": "SKIPPED"},
        }
        result["all_addresses"] = [ip_norm]
        return result

    if hostname.lower() == "localhost":
        # Localhost is commonly not present in public DoH resolvers; skip external lookup
        # to preserve existing local scan behavior while keeping verification transparent.
        prov = {
            "provider": "localhost",
            "status": "SKIPPED",
            "a": {"status": "SKIPPED", "addresses": [], "error": None},
            "aaaa": {"status": "SKIPPED", "addresses": [], "error": None},
            "addresses": [],
            "error": "Localhost target; public DNS-over-HTTPS verification skipped.",
        }
        result["providers"] = {"google": dict(prov, provider="google"), "cloudflare": dict(prov, provider="cloudflare")}
        result["comparison"] = {
            "match": True,
            "summary": "Localhost target; public DNS-over-HTTPS verification skipped (system resolution remains authoritative).",
            "common_addresses": [],
            "all_addresses": [],
            "statuses": {"google": "SKIPPED", "cloudflare": "SKIPPED"},
        }
        result["all_addresses"] = []
        return result

    if httpx is None:
        err = "DNS verification unavailable: httpx is not installed."
        for p in PROVIDERS:
            result["providers"][p] = {"provider": p, "status": "ERROR", "a": {"status": "ERROR", "addresses": [], "error": err}, "aaaa": {"status": "ERROR", "addresses": [], "error": err}, "addresses": [], "error": err}
        result["comparison"] = {"match": False, "summary": err, "common_addresses": [], "all_addresses": [], "statuses": {p: "ERROR" for p in PROVIDERS}}
        result["error"] = err
        return result

    result["queried"] = True
    try:
        timeout_cfg = httpx.Timeout(timeout)
        async with httpx.AsyncClient(timeout=timeout_cfg, follow_redirects=False, trust_env=False) as client:
            gathered = await asyncio.gather(*[_query_provider(client, p, hostname) for p in PROVIDERS], return_exceptions=True)
    except Exception as exc:
        msg = str(exc) or exc.__class__.__name__
        for p in PROVIDERS:
            result["providers"][p] = {"provider": p, "status": "ERROR", "a": {"status": "ERROR", "addresses": [], "error": msg}, "aaaa": {"status": "ERROR", "addresses": [], "error": msg}, "addresses": [], "error": msg}
        result["comparison"] = {"match": False, "summary": f"DNS verification failed: {msg}", "common_addresses": [], "all_addresses": [], "statuses": {p: "ERROR" for p in PROVIDERS}}
        result["error"] = msg
        return result

    providers: Dict[str, Dict[str, Any]] = {}
    for p, item in zip(PROVIDERS, gathered):
        if isinstance(item, Exception):
            msg = str(item) or item.__class__.__name__
            st = "TIMEOUT" if "timeout" in msg.lower() or "timeout" in item.__class__.__name__.lower() else "ERROR"
            providers[p] = {"provider": p, "status": st, "a": {"status": st, "addresses": [], "error": msg}, "aaaa": {"status": st, "addresses": [], "error": msg}, "addresses": [], "error": msg}
        else:
            providers[p] = item
    result["providers"] = providers

    sets = {p: set((providers.get(p) or {}).get("addresses") or []) for p in PROVIDERS}
    statuses = {p: (providers.get(p) or {}).get("status") for p in PROVIDERS}
    common = set.intersection(*(sets[p] for p in PROVIDERS)) if PROVIDERS else set()
    union: List[str] = []
    seen = set()
    for p in PROVIDERS:
        for a in (providers.get(p) or {}).get("addresses") or []:
            if a not in seen:
                seen.add(a)
                union.append(a)

    all_noerror = all(statuses.get(p) == "NOERROR" for p in PROVIDERS)
    any_noerror = any(statuses.get(p) == "NOERROR" for p in PROVIDERS)
    all_unavailable = all(statuses.get(p) in {"TIMEOUT", "ERROR"} for p in PROVIDERS)
    all_nxdomain = all(statuses.get(p) == "NXDOMAIN" for p in PROVIDERS)
    any_nxdomain = any(statuses.get(p) == "NXDOMAIN" for p in PROVIDERS)
    all_servfail = all(statuses.get(p) == "SERVFAIL" for p in PROVIDERS)
    any_servfail = any(statuses.get(p) == "SERVFAIL" for p in PROVIDERS)

    if all_unavailable:
        summary = "Both DNS providers unavailable or failed."
        match = False
    elif all_nxdomain:
        summary = "Domain does not exist (NXDOMAIN reported by both providers)."
        match = True
    elif any_nxdomain and not any_noerror:
        summary = "Domain reported as NXDOMAIN by provider(s) with no successful answers."
        match = False
    elif all_servfail:
        summary = "DNS server failure (SERVFAIL) reported by both providers."
        match = True
    elif any_servfail and not any_noerror:
        summary = "SERVFAIL reported by provider(s) with no successful answers."
        match = False
    elif all_noerror and sets["google"] == sets["cloudflare"]:
        summary = "Provider DNS responses match."
        match = True
    elif sets["google"] == sets["cloudflare"] and (sets["google"] or sets["cloudflare"]):
        summary = "Provider address sets match."
        match = True
    elif any_noerror:
        summary = "Provider responses differ or one or more providers unavailable/failed."
        match = False
    else:
        summary = "No successful DNS answers from providers."
        match = False

    result["comparison"] = {
        "match": bool(match),
        "summary": summary,
        "common_addresses": sorted(common),
        "all_addresses": union,
        "statuses": statuses,
        "address_sets_equal": sets["google"] == sets["cloudflare"],
    }
    result["all_addresses"] = union
    return result


def verify_hostname_dns_sync(hostname: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Synchronous wrapper for dual DNS-over-HTTPS verification."""
    try:
        return asyncio.run(verify_hostname_dns_async(hostname, timeout=timeout))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(verify_hostname_dns_async(hostname, timeout=timeout))
        finally:
            try:
                loop.close()
            except Exception:
                pass


def perform_dns_verification(
    hostname: str,
    i_have_permission: bool,
    scan_mode: str,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Run dual DNS verification and validate any resolved IPs with existing SSRF protections."""
    hostname = (hostname or "").strip().strip(".")
    verification = verify_hostname_dns_sync(hostname, timeout=timeout)
    verification["hostname"] = hostname
    verification["safety"] = {"ok": True, "reason": "", "checked_ips": []}

    all_ips = list(verification.get("all_addresses") or [])
    if all_ips:
        ok, reason, normalized = validate_resolved_ips_for_scan(all_ips, hostname, i_have_permission, scan_mode)
        verification["safety"] = {"ok": ok, "reason": reason, "checked_ips": normalized}
        if not ok:
            # Keep addresses recorded for transparency but mark blocked.
            verification["comparison"] = dict(verification.get("comparison") or {})
            verification["comparison"]["safety_blocked"] = True

    # Derive a high-level outcome useful for scan flow decisions
    providers = verification.get("providers") or {}
    statuses = [((providers.get(p) or {}).get("status")) for p in PROVIDERS]
    any_noerror_addrs = bool(all_ips)
    all_nxdomain = all(s == "NXDOMAIN" for s in statuses) if statuses else False
    all_unavailable = all(s in {"TIMEOUT", "ERROR"} for s in statuses) if statuses else False

    if _is_ip_literal(hostname):
        outcome = "ip_literal"
    elif hostname.lower() == "localhost":
        outcome = "localhost"
    elif all_nxdomain:
        outcome = "nxdomain"
    elif any_noerror_addrs:
        outcome = "resolved" if verification.get("safety", {}).get("ok", True) else "resolved_but_blocked"
    elif all_unavailable:
        outcome = "providers_unavailable"
    else:
        # e.g. SERVFAIL/no answers/mixed failures
        outcome = "unresolved"

    verification["outcome"] = outcome
    return verification


def preflight_verify_target(
    url: str,
    i_have_permission: bool,
    scan_mode: str,
    timeout: float = 4.0,
    validation: Any = None,
) -> Dict[str, Any]:
    """Verify a target before scan dispatch using dual DNS + existing SSRF validation.

    Returns a structured decision used by the web layer to give a responsible,
    accurate answer for nonexistent/unresolvable targets. Local/system DNS
    resolution remains authoritative for actual connectivity (split-horizon or
    private DNS is not overridden by public DoH results).
    """
    from urllib.parse import urlparse

    from core.safety import normalize_target_url, validate_url_target

    normalized = normalize_target_url(url)
    hostname = (urlparse(normalized).hostname or "").strip()

    if validation is None:
        validation = validate_url_target(
            normalized,
            i_have_permission=i_have_permission,
            scan_mode=scan_mode,
        )

    system_ok = bool(getattr(validation, "ok", False))
    system_reason = getattr(validation, "reason", "") or ""

    if hostname:
        dns_verification = perform_dns_verification(
            hostname,
            i_have_permission=i_have_permission,
            scan_mode=scan_mode,
            timeout=timeout,
        )
    else:
        dns_verification = {
            "hostname": "",
            "queried": False,
            "providers": {},
            "comparison": {"match": False, "summary": "Missing hostname.", "common_addresses": [], "all_addresses": []},
            "all_addresses": [],
            "outcome": "unresolved",
            "error": "Missing hostname.",
        }

    outcome = (dns_verification or {}).get("outcome")
    if outcome in ("resolved", "ip_literal", "localhost", "resolved_but_blocked"):
        exists: Optional[bool] = True
    elif outcome == "nxdomain":
        exists = False
    else:
        # providers_unavailable / unresolved / verification_error -> unknown
        exists = None

    ok = system_ok
    message = ""
    if system_ok:
        if exists is False:
            message = (
                f"Local/system DNS resolved '{hostname}', but Google and Cloudflare public DNS "
                "report NXDOMAIN (possible split-horizon/private DNS). Proceeding based on local resolution."
            )
    else:
        if exists is False:
            message = (
                f"Target domain '{hostname}' does not exist: NXDOMAIN confirmed by Google and "
                "Cloudflare public DNS providers. Check the URL/domain spelling and try again."
            )
        elif exists is True and "Failed to resolve hostname" in system_reason:
            message = (
                f"Target host '{hostname}' exists according to public DNS (Google/Cloudflare), but local "
                f"system DNS resolution failed. Check your network/DNS configuration and retry. ({system_reason})"
            )
        else:
            message = system_reason or "Target verification failed."

    return {
        "ok": ok,
        "exists": exists,
        "outcome": outcome,
        "message": message,
        "hostname": hostname,
        "normalized_url": getattr(validation, "normalized_url", None) or normalized,
        "system_validation_ok": system_ok,
        "system_reason": system_reason,
        "dns_verification": dns_verification,
    }
