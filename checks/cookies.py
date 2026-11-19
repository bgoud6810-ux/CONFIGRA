"""
checks/cookies.py - Cookie security attributes analysis

Inspects Set-Cookie headers across fetched pages for HttpOnly, Secure,
and SameSite flags with context-aware session severity rating and edge-case handling.
"""

import re
from typing import List, Tuple, Set, Dict, Any, Optional
from core.models import Finding
from core.context import ScanContext

# Common framework & standard session cookie names (exact matches, lowercase)
KNOWN_SESSION_NAMES = {
    "phpsessid", "jsessionid", "aspsessionid", "asp.net_sessionid",
    "connect.sid", "laravel_session", "ci_session", "session",
    "sessionid", "sessid", "sess_id", "session_id", "user_session",
    "app_session", "auth_token", "authtoken", "access_token",
    "id_token", "jwt", "remember_token", "remember_me", "logged_in",
    "csrftoken", "xsrf-token", "csrf_token"
}

# Delimited keyword tokens for session identification
SESSION_NAME_TOKENS = {"session", "sess", "sid", "auth", "token", "jwt"}

# Common non-sensitive cookie names
NON_SENSITIVE_NAMES = {
    "theme", "dark_mode", "lang", "language", "locale", "tz", "timezone",
    "cookie_consent", "gdpr", "consent", "view_mode", "sidebar", "banner_dismissed"
}


def _is_session_cookie(cookie_name: str, cookie_value: str = "") -> bool:
    """
    Determine if a cookie is an authentication/session token without false positives.
    Uses tokenization instead of naive substring matching (e.g. avoids flagging 'sidebar' or 'author').
    """
    name_clean = cookie_name.strip().lower()

    # 1. Exact match against known framework session names
    if name_clean in KNOWN_SESSION_NAMES:
        return True

    # 2. Known non-sensitive cookies
    if name_clean in NON_SENSITIVE_NAMES:
        return False

    # 3. Tokenize by common delimiters (_, -, ., or camelCase)
    tokens = set(re.split(r"[_\-.]+", name_clean))
    camel_tokens = set(re.findall(r"[a-z]+|[A-Z][a-z]*", cookie_name))
    camel_tokens_lower = {t.lower() for t in camel_tokens}
    all_tokens = tokens | camel_tokens_lower

    if any(t in SESSION_NAME_TOKENS for t in all_tokens):
        return True

    # 4. Check if the value itself looks like a JWT token (eyJ...)
    val_clean = cookie_value.strip().strip("'\"")
    if val_clean.startswith("eyJ") and val_clean.count(".") == 2:
        return True

    return False


def _get_set_cookie_headers(response) -> List[str]:
    """
    Extract all raw Set-Cookie header lines from response.
    Supports raw HTTPHeaderDict (urllib3 v1/v2), getlist, get_all,
    and falls back to regex-aware comma splitting for combined headers.
    """
    cookies: List[str] = []

    # 1. Check raw headers from urllib3 response
    raw = getattr(response, "raw", None)
    if raw and hasattr(raw, "headers"):
        raw_headers = raw.headers
        if hasattr(raw_headers, "getlist"):
            try:
                vals = raw_headers.getlist("set-cookie")
                if vals:
                    cookies.extend(vals)
            except Exception:
                pass
        elif hasattr(raw_headers, "get_all"):
            try:
                vals = raw_headers.get_all("Set-Cookie", [])
                if vals:
                    cookies.extend(vals)
            except Exception:
                pass

    # 2. Fallback to response.headers
    if not cookies and "Set-Cookie" in response.headers:
        raw_val = response.headers.get("Set-Cookie", "")
        if raw_val:
            # Safely split combined Set-Cookie headers:
            # Only split at a comma followed by 'name=' (ignoring commas inside Expires=...)
            split_cookies = re.split(r",\s*(?=[a-zA-Z0-9_\-]+=)", raw_val)
            cookies.extend(split_cookies)

    return [c.strip() for c in cookies if c and c.strip()]


def _parse_cookie(raw_cookie: str) -> Optional[Dict[str, Any]]:
    """
    Parse a Set-Cookie header line into its name, value, attributes, and flags.
    Handles edge cases like leading semicolons, base64 values with '=', etc.
    """
    parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
    if not parts:
        return None

    # First part should be the cookie name=value pair
    cookie_pair = parts[0]
    if "=" not in cookie_pair:
        return None

    name, _, val = cookie_pair.partition("=")
    name = name.strip()
    val = val.strip()

    # Attribute keys that must not be mistaken for cookie names
    known_attr_keys = {"path", "domain", "expires", "max-age", "samesite", "httponly", "secure"}
    if name.lower() in known_attr_keys:
        return None

    attrs: Dict[str, Optional[str]] = {}
    flags: Set[str] = set()

    for part in parts[1:]:
        if "=" in part:
            k, _, v = part.partition("=")
            attrs[k.strip().lower()] = v.strip()
        else:
            flags.add(part.strip().lower())

    return {
        "name": name,
        "value": val,
        "attrs": attrs,
        "flags": flags,
        "raw": raw_cookie,
    }


def run(ctx: ScanContext) -> Tuple[List[Finding], List[str]]:
    """
    Evaluate cookie attributes across all fetched pages.
    Returns:
        (findings, passed_checks)
    """
    findings: List[Finding] = []
    passed_checks: List[str] = []

    pages_to_check = ctx.all_pages if ctx.all_pages else ([ctx.home_response] if ctx.home_response else [])
    seen_finding_keys: Set[Tuple[str, str]] = set()
    total_cookies_found = 0
    http_secure_reported = False

    def add_finding(f: Finding):
        key = (f.id, f.url)
        if key not in seen_finding_keys:
            seen_finding_keys.add(key)
            findings.append(f)

    for page in pages_to_check:
        cookie_headers = _get_set_cookie_headers(page)
        for raw_cookie in cookie_headers:
            parsed = _parse_cookie(raw_cookie)
            if not parsed:
                continue

            total_cookies_found += 1
            cookie_name = parsed["name"]
            cookie_val = parsed["value"]
            attrs = parsed["attrs"]
            flags = parsed["flags"]

            has_httponly = "httponly" in flags
            has_secure = "secure" in flags
            has_samesite = "samesite" in attrs
            samesite_val = attrs.get("samesite", "").lower()

            is_session = _is_session_cookie(cookie_name, cookie_val)

            # Mask evidence if cookie value is sensitive or long
            safe_raw = raw_cookie
            if len(cookie_val) > 30:
                masked_val = cookie_val[:8] + "..." + cookie_val[-4:]
                safe_raw = raw_cookie.replace(cookie_val, masked_val, 1)
            safe_evidence = f"Set-Cookie: {safe_raw[:200]}"

            # 1. HttpOnly check
            if not has_httponly:
                sev = "Medium" if is_session else "Low"
                add_finding(Finding(
                    id=f"CKE-001-{cookie_name.upper()}",
                    title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                    category="cookies",
                    severity=sev,
                    evidence=safe_evidence,
                    fix=f"Add 'HttpOnly' attribute to '{cookie_name}' cookie header to prevent access via client-side script",
                    confidence="Confirmed",
                    url=page.url,
                ))
            else:
                passed_checks.append(f"Cookie '{cookie_name}' has HttpOnly flag")

            # 2. Secure flag check
            if ctx.scheme == "https":
                if not has_secure:
                    sev = "Medium" if is_session else "Low"
                    add_finding(Finding(
                        id=f"CKE-002-{cookie_name.upper()}",
                        title=f"Cookie '{cookie_name}' missing Secure flag",
                        category="cookies",
                        severity=sev,
                        evidence=safe_evidence,
                        fix=f"Add 'Secure' attribute to '{cookie_name}' cookie header to prevent transmission over unencrypted connections",
                        confidence="Confirmed",
                        url=page.url,
                    ))
                else:
                    passed_checks.append(f"Cookie '{cookie_name}' has Secure flag")
            else:
                # Target is HTTP: only add single Info finding once
                if not http_secure_reported:
                    add_finding(Finding(
                        id="CKE-003",
                        title="Secure flag cannot be assessed on HTTP",
                        category="cookies",
                        severity="Info",
                        evidence="Target scheme is HTTP. Browsers only enforce Secure cookies over HTTPS connections.",
                        fix="Enable HTTPS on the target server and add the 'Secure' flag to all cookies",
                        confidence="Confirmed",
                        url=page.url,
                    ))
                    http_secure_reported = True

            # 3. SameSite check
            if not has_samesite:
                add_finding(Finding(
                    id=f"CKE-004-{cookie_name.upper()}",
                    title=f"Cookie '{cookie_name}' missing SameSite attribute",
                    category="cookies",
                    severity="Low",
                    evidence=safe_evidence,
                    fix=f"Add 'SameSite=Lax' (or Strict) to '{cookie_name}' cookie header to protect against CSRF attacks",
                    confidence="Confirmed",
                    url=page.url,
                ))
            elif samesite_val == "none":
                # In modern browsers, SameSite=None REQUIRES Secure
                if not has_secure:
                    add_finding(Finding(
                        id=f"CKE-005-{cookie_name.upper()}",
                        title=f"Cookie '{cookie_name}' specifies SameSite=None without Secure flag",
                        category="cookies",
                        severity="Medium" if is_session else "Low",
                        evidence=safe_evidence,
                        fix=f"Add 'Secure' flag to '{cookie_name}'. Modern browsers reject cookies with SameSite=None unless Secure is present.",
                        confidence="Confirmed",
                        url=page.url,
                    ))
                else:
                    passed_checks.append(f"Cookie '{cookie_name}' has SameSite=None with Secure")
            elif samesite_val in ("strict", "lax"):
                passed_checks.append(f"Cookie '{cookie_name}' has SameSite={samesite_val.title()} attribute")
            else:
                # Invalid or unrecognized SameSite value
                add_finding(Finding(
                    id=f"CKE-004-{cookie_name.upper()}",
                    title=f"Cookie '{cookie_name}' has unrecognized SameSite value",
                    category="cookies",
                    severity="Low",
                    evidence=f"Set-Cookie specifies invalid SameSite='{samesite_val}': {safe_raw[:200]}",
                    fix=f"Set 'SameSite=Lax' or 'SameSite=Strict' on '{cookie_name}' cookie header",
                    confidence="Confirmed",
                    url=page.url,
                ))

            # 4. Cookie prefix checks (__Secure- and __Host-)
            if cookie_name.startswith("__Secure-"):
                if not has_secure or ctx.scheme != "https":
                    add_finding(Finding(
                        id=f"CKE-006-{cookie_name.upper()}",
                        title=f"Cookie '{cookie_name}' violates __Secure- prefix requirements",
                        category="cookies",
                        severity="Medium",
                        evidence=f"Cookie uses '__Secure-' prefix but lacks Secure flag or is sent over HTTP: {safe_raw[:200]}",
                        fix=f"Ensure '{cookie_name}' is transmitted over HTTPS and includes the 'Secure' attribute",
                        confidence="Confirmed",
                        url=page.url,
                    ))
            elif cookie_name.startswith("__Host-"):
                has_domain = "domain" in attrs
                has_path_root = attrs.get("path") == "/"
                if not has_secure or ctx.scheme != "https" or has_domain or not has_path_root:
                    add_finding(Finding(
                        id=f"CKE-006-{cookie_name.upper()}",
                        title=f"Cookie '{cookie_name}' violates __Host- prefix requirements",
                        category="cookies",
                        severity="Medium",
                        evidence=f"Cookie uses '__Host-' prefix but violates requirements (Must have Secure, Path=/, no Domain, and be over HTTPS): {safe_raw[:200]}",
                        fix=f"Configure '{cookie_name}' with Secure, Path=/, no Domain attribute, and serve over HTTPS",
                        confidence="Confirmed",
                        url=page.url,
                    ))

    if total_cookies_found == 0:
        passed_checks.append("No cookies set by server")

    return findings, passed_checks
