#!/usr/bin/env python3
"""
app.py — CONFIGRA Web Interface
Automated Security Misconfiguration Detector

EXACTLY TWO USER-FACING APPLICATION PAGES:
  Page 1: Scanner Launchpad & Live Telemetry (/ or /scan)
  Page 2: Security Operations Dashboard & Scan Results (/results/<scan_id>)

Theme: CONFIGRA charcoal and crimson interface (Background #08090D, Accent #FF1744)
"""

import os
import sys
import json
import uuid
import hmac
import threading
from datetime import datetime
from typing import Dict, Any, Optional

from flask import (
    Flask,
    Response,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    send_file,
    abort,
)

# Import existing scanner backend directly
from scanner import run_scan
from core.safety import validate_url_target, normalize_target_url
from core.config import load_dotenv, get_api_key
from core.dns_verification import preflight_verify_target
from core.models import (
    SCAN_MODE_AUTHORIZED_ASSESSMENT,
    SCAN_MODE_LABELS,
    SCAN_MODE_PASSIVE_PUBLIC,
    VALID_SCAN_MODES,
)

# Load local .env (if present) before reading configuration values.
load_dotenv()
CONFIGRA_API_KEY = get_api_key()
# Optional shared password that gates the whole web UI (used when the app is
# exposed through a public tunnel). Empty = disabled.
CONFIGRA_ACCESS_PASSWORD = (os.environ.get("CONFIGRA_ACCESS_PASSWORD") or "").strip()

# Initialize Flask App
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.urandom(24)


def _env_flag(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return str(val).strip().lower() not in {"0", "false", "no", "off", ""}


def _api_auth_enabled() -> bool:
    """API-key authentication is active only when configured (and not under tests)."""
    return bool(CONFIGRA_API_KEY) and not app.config.get("TESTING")


def _extract_api_key() -> str:
    provided = (request.headers.get("X-API-Key") or "").strip()
    if provided:
        return provided
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return ""


def _api_auth_error():
    """Return a Flask response tuple when authentication is required but missing/invalid."""
    if not _api_auth_enabled():
        return None
    try:
        if hmac.compare_digest(_extract_api_key(), CONFIGRA_API_KEY):
            return None
    except Exception:
        pass
    return (
        jsonify(
            {
                "error": (
                    "Authentication required. Provide a valid API key via the "
                    "X-API-Key header (or Authorization: Bearer <key>)."
                )
            }
        ),
        401,
    )


@app.context_processor
def _inject_auth_context():
    """Expose the API key to the scanner UI only when authentication is enabled."""
    return {"api_key": CONFIGRA_API_KEY if _api_auth_enabled() else ""}


def _access_password_enabled() -> bool:
    """UI password gate is active only when configured (and not under tests)."""
    return bool(CONFIGRA_ACCESS_PASSWORD) and not app.config.get("TESTING")


def _is_local_request() -> bool:
    """True for requests that originate on this machine (no password needed).

    Tunnel traffic also arrives from 127.0.0.1, so Cloudflare's proxy headers
    (which a browser on localhost does not send) force the password gate on.
    """
    if request.headers.get("CF-Connecting-IP") or request.headers.get("CF-Ray"):
        return False
    return (request.remote_addr or "") in {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


@app.before_request
def _require_access_password():
    """HTTP Basic gate for the UI when it is reachable from another machine.

    Local requests (this PC) are never prompted. Enabled only when
    CONFIGRA_ACCESS_PASSWORD is set, so local development and the existing test
    suite behave exactly as before.
    """
    if not _access_password_enabled():
        return None
    if _is_local_request():
        return None
    auth = request.authorization
    password = (auth.password or "") if auth else ""
    try:
        if password and hmac.compare_digest(str(password), CONFIGRA_ACCESS_PASSWORD):
            return None
    except Exception:
        pass
    return Response(
        "Authentication required.",
        401,
        {"WWW-Authenticate": 'Basic realm="CONFIGRA"'},
        mimetype="text/plain",
    )


def _verification_summary(preflight: Dict[str, Any]) -> Dict[str, Any]:
    """Public-safe DNS verification summary (never includes credentials)."""
    dv = (preflight or {}).get("dns_verification") or {}
    providers = dv.get("providers") or {}
    return {
        "hostname": (preflight or {}).get("hostname"),
        "exists": (preflight or {}).get("exists"),
        "outcome": (preflight or {}).get("outcome"),
        "system_validation_ok": (preflight or {}).get("system_validation_ok"),
        "message": (preflight or {}).get("message"),
        "providers": {
            name: {
                "status": (pdata or {}).get("status"),
                "addresses": (pdata or {}).get("addresses") or [],
                "error": (pdata or {}).get("error"),
            }
            for name, pdata in providers.items()
        },
        "comparison": dv.get("comparison") or {},
        "all_addresses": dv.get("all_addresses") or [],
        "safety": dv.get("safety") or {},
    }


def _is_dev_reload_enabled() -> bool:
    # Local development convenience: reload latest saved Python/templates/static by default
    # when running the dev server directly, without enabling Flask debug mode/debugger.
    return _env_flag("CONFIGRA_DEV_RELOAD", True)


_DEV_RELOAD = _is_dev_reload_enabled()
if _DEV_RELOAD:
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.jinja_env.auto_reload = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.after_request
def _dev_no_cache(response):
    if not _DEV_RELOAD:
        return response
    try:
        path = (request.path or "").lower()
        if path.startswith("/static/") or response.mimetype in {"text/html", "text/css", "application/javascript"}:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
    except Exception:
        pass
    return response

# Ensure output directory exists
OUTPUT_DIR = os.path.abspath("output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Thread-safe in-memory scan tracker
ACTIVE_SCANS: Dict[str, Dict[str, Any]] = {}
SCANS_LOCK = threading.Lock()


def _scan_json_path(scan_id: str) -> str:
    if scan_id == "results":
        return os.path.join(OUTPUT_DIR, "results.json")
    return os.path.join(OUTPUT_DIR, f"scan_{scan_id}.json")


def _scan_html_path(scan_id: str) -> str:
    if scan_id == "results":
        legacy = os.path.join(OUTPUT_DIR, "report.html")
        if os.path.exists(legacy):
            return legacy
    return os.path.join(OUTPUT_DIR, f"report_{scan_id}.html")


def _load_scan_data(scan_id: str) -> Optional[Dict[str, Any]]:
    with SCANS_LOCK:
        entry = ACTIVE_SCANS.get(scan_id)
        if entry and entry.get("results"):
            return entry.get("results")

    json_file_path = _scan_json_path(scan_id)
    if not os.path.exists(json_file_path) and scan_id == "results":
        json_file_path = os.path.join(OUTPUT_DIR, "results.json")
    if os.path.exists(json_file_path):
        try:
            with open(json_file_path, "r", encoding="utf-8") as jf:
                return json.load(jf)
        except Exception as exc:
            app.logger.error("Failed to read scan file %s: %s", json_file_path, exc)
    return None


def get_latest_scan_id() -> Optional[str]:
    """Find the most recent scan JSON file in output directory."""
    if not os.path.exists(OUTPUT_DIR):
        return None
    files = [f for f in os.listdir(OUTPUT_DIR) if f.startswith("scan_") and f.endswith(".json")]
    if not files:
        if os.path.exists(os.path.join(OUTPUT_DIR, "results.json")):
            return "results"
        return None
    files.sort(key=lambda x: os.path.getmtime(os.path.join(OUTPUT_DIR, x)), reverse=True)
    latest_file = files[0]
    return latest_file[len("scan_") : -len(".json")]


# ==============================================================================
# EXACTLY TWO USER-FACING ROUTES
# ==============================================================================


@app.route("/", methods=["GET"])
@app.route("/scan", methods=["GET"])
def scanner_page():
    """
    PAGE 1: SCANNER
    Target URL input, preset profiles, advanced configuration drawer,
    testing authorization warning, and live progress terminal.
    """
    return render_template("scanner.html", active_page="scanner")


@app.route("/results", methods=["GET"])
def results_redirect():
    """Redirect /results to the latest scan if available, otherwise show no-scan state."""
    latest = get_latest_scan_id()
    if latest:
        return redirect(url_for("results_page", scan_id=latest))
    return render_template(
        "scanner.html",
        active_page="scanner",
        initial_error="No scan data available. Start a new scan.",
    )


@app.route("/results/<scan_id>", methods=["GET"])
def results_page(scan_id: str):
    """
    PAGE 2: DASHBOARD & SCAN RESULTS
    Security findings, score, severity distribution, scan metadata,
    category analytics, and actionable remediation guidance.
    """
    scan_data: Optional[Dict[str, Any]] = None

    with SCANS_LOCK:
        entry = ACTIVE_SCANS.get(scan_id)
        if entry:
            if entry.get("status") == "running":
                return render_template(
                    "scanner.html",
                    active_page="scanner",
                    active_scan_id=scan_id,
                    active_target_url=entry.get("target_url", ""),
                )
            scan_data = entry.get("results")

    if not scan_data:
        scan_data = _load_scan_data(scan_id)

    if not scan_data:
        return render_template(
            "scanner.html",
            active_page="scanner",
            initial_error=f"Scan ID '{scan_id}' not found. Please initiate a new scan.",
        )

    score = scan_data.get("score", 0)
    grade = scan_data.get("grade", "N/A")
    counts = scan_data.get("counts", {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0})
    findings = scan_data.get("findings", [])
    passed_checks = scan_data.get("passed_checks", [])
    target_url = scan_data.get("target", "")
    target_ip = scan_data.get("target_ip") or "N/A"
    scan_time = scan_data.get("scan_time") or scan_data.get("scan_completed_at", "Just now")
    scan_duration = scan_data.get("duration_seconds", 0)
    comparison = scan_data.get("comparison")
    scan_status = scan_data.get("status", "completed")
    checks_not_performed = scan_data.get("checks_not_performed", [])
    scan_limitations = scan_data.get("scan_limitations", [])
    check_results = scan_data.get("check_results", [])
    errors = scan_data.get("errors", [])
    scan_mode = scan_data.get("scan_mode", SCAN_MODE_AUTHORIZED_ASSESSMENT)
    scan_mode_label = scan_data.get("scan_mode_label", SCAN_MODE_LABELS.get(scan_mode, scan_mode))
    dns_outcome = scan_data.get("dns_outcome", "unknown")
    connection_outcome = scan_data.get("connection_outcome", "unknown")
    http_outcome = scan_data.get("http_outcome", "unknown")
    tls_observations = scan_data.get("tls_observations", {})
    waf_indicators = scan_data.get("waf_indicators", [])
    rate_limit_events = scan_data.get("rate_limit_events", [])
    resolved_ips = scan_data.get("resolved_ips", [])
    dns_verification = scan_data.get("dns_verification", {})

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        scan_id=scan_id,
        score=score,
        grade=grade,
        counts=counts,
        findings=findings,
        passed_checks=passed_checks,
        target_url=target_url,
        target_ip=target_ip,
        scan_time=scan_time,
        scan_duration=scan_duration,
        comparison=comparison,
        scan_status=scan_status,
        checks_not_performed=checks_not_performed,
        scan_limitations=scan_limitations,
        check_results=check_results,
        errors=errors,
        scan_mode=scan_mode,
        scan_mode_label=scan_mode_label,
        dns_outcome=dns_outcome,
        connection_outcome=connection_outcome,
        http_outcome=http_outcome,
        tls_observations=tls_observations,
        waf_indicators=waf_indicators,
        rate_limit_events=rate_limit_events,
        resolved_ips=resolved_ips,
        dns_verification=dns_verification,
    )


# ==============================================================================
# API ENDPOINTS (SCAN DISPATCH, STATUS POLLING & REPORTS)
# ==============================================================================


@app.route("/api/scan", methods=["POST"])
def api_start_scan():
    """
    Dispatch a new scan execution in a non-blocking background worker thread.
    Validates target URL and safety before queueing.
    """
    auth_error = _api_auth_error()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True) or {}
    target_url = (data.get("target_url") or "").strip()

    if not target_url:
        return jsonify({"error": "Target URL is required."}), 400

    target_url = normalize_target_url(target_url)

    try:
        delay = float(data.get("delay", 0.3))
        timeout = float(data.get("timeout", 10.0))
    except Exception:
        return jsonify({"error": "Invalid delay or timeout value."}), 400
    insecure = bool(data.get("insecure", False))
    i_have_permission = bool(data.get("i_have_permission", False))
    compare_scan_id = (data.get("compare_scan_id") or "").strip()
    scan_mode = (data.get("scan_mode") or SCAN_MODE_AUTHORIZED_ASSESSMENT).strip().lower()
    if scan_mode not in VALID_SCAN_MODES:
        return jsonify({"error": f"Invalid scan_mode '{scan_mode}'. Must be one of: {sorted(VALID_SCAN_MODES)}"}), 400

    delay = max(0.0, min(delay, 5.0))
    timeout = max(1.0, min(timeout, 30.0))

    # Pre-validate safety + verify target existence with dual DNS before background execution.
    # Local/system DNS resolution remains authoritative for actual connectivity; public DoH
    # results provide confirmation/diagnostics for responsible answers (e.g. NXDOMAIN).
    validation = validate_url_target(target_url, i_have_permission=i_have_permission, scan_mode=scan_mode)
    preflight = preflight_verify_target(
        target_url,
        i_have_permission=i_have_permission,
        scan_mode=scan_mode,
        timeout=min(timeout, 4.0),
        validation=validation,
    )
    if not preflight.get("ok"):
        reason = preflight.get("message") or validation.reason or "Target validation failed."
        if (
            scan_mode == SCAN_MODE_AUTHORIZED_ASSESSMENT
            and not i_have_permission
            and "require explicit authorized testing confirmation" in reason
        ):
            msg = (
                "Target resolves to a public or non-private IP address. "
                "Authorized Security Configuration Assessment requires explicit authorized testing permission and confirmation."
            )
        else:
            msg = reason
        return jsonify({"error": msg, "verification": _verification_summary(preflight)}), 400
    target_url = preflight.get("normalized_url") or validation.normalized_url or target_url

    # Determine compare path if specified
    compare_path = None
    if compare_scan_id:
        cand_path = os.path.join(OUTPUT_DIR, f"scan_{compare_scan_id}.json")
        if os.path.exists(cand_path):
            compare_path = cand_path
        elif compare_scan_id == "results" and os.path.exists(os.path.join(OUTPUT_DIR, "results.json")):
            compare_path = os.path.join(OUTPUT_DIR, "results.json")

    # Generate unique scan ID
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    rand_suffix = uuid.uuid4().hex[:6]
    scan_id = f"{timestamp_str}_{rand_suffix}"

    output_json = os.path.join(OUTPUT_DIR, f"scan_{scan_id}.json")
    output_html = os.path.join(OUTPUT_DIR, f"report_{scan_id}.html")

    cancel_event = threading.Event()

    with SCANS_LOCK:
        ACTIVE_SCANS[scan_id] = {
            "status": "running",
            "progress": 10,
            "step": "Establishing secure scan context...",
            "target_url": target_url,
            "scan_mode": scan_mode,
            "results": None,
            "error": None,
            "cancel_event": cancel_event,
        }

    def on_progress(step_text: str, pct: int):
        with SCANS_LOCK:
            entry = ACTIVE_SCANS.get(scan_id)
            if entry and entry.get("status") == "running":
                entry["step"] = step_text
                entry["progress"] = pct

    def worker():
        try:
            results = run_scan(
                target_url=target_url,
                output_html=output_html,
                output_json=output_json,
                compare_path=compare_path,
                delay=delay,
                timeout=timeout,
                insecure=insecure,
                i_have_permission=i_have_permission,
                progress_callback=on_progress,
                verbose=False,
                scan_id=scan_id,
                cancel_event=cancel_event,
                scan_mode=scan_mode,
            )
            final_status = (results or {}).get("status", "completed")
            with SCANS_LOCK:
                if scan_id in ACTIVE_SCANS:
                    ACTIVE_SCANS[scan_id]["results"] = results
                    ACTIVE_SCANS[scan_id]["progress"] = 100
                    if final_status == "cancelled":
                        ACTIVE_SCANS[scan_id]["status"] = "cancelled"
                        ACTIVE_SCANS[scan_id]["step"] = "Scan cancelled."
                        ACTIVE_SCANS[scan_id]["error"] = None
                    elif final_status == "failed":
                        ACTIVE_SCANS[scan_id]["status"] = "failed"
                        ACTIVE_SCANS[scan_id]["step"] = "Scan failed."
                        errs = (results or {}).get("errors") or []
                        ACTIVE_SCANS[scan_id]["error"] = "; ".join(errs[:2]) if errs else "Scan failed."
                    else:
                        ACTIVE_SCANS[scan_id]["status"] = "completed"
                        ACTIVE_SCANS[scan_id]["step"] = "Scan completed successfully."
                        ACTIVE_SCANS[scan_id]["error"] = None
        except PermissionError as exc:
            app.logger.warning("Scan %s refused: %s", scan_id, exc)
            with SCANS_LOCK:
                if scan_id in ACTIVE_SCANS:
                    ACTIVE_SCANS[scan_id]["status"] = "failed"
                    ACTIVE_SCANS[scan_id]["progress"] = 100
                    ACTIVE_SCANS[scan_id]["error"] = str(exc)
                    ACTIVE_SCANS[scan_id]["step"] = "Target validation failed."
        except ConnectionError as exc:
            app.logger.warning("Scan %s connection issue: %s", scan_id, exc)
            with SCANS_LOCK:
                if scan_id in ACTIVE_SCANS:
                    ACTIVE_SCANS[scan_id]["status"] = "failed"
                    ACTIVE_SCANS[scan_id]["progress"] = 100
                    ACTIVE_SCANS[scan_id]["error"] = str(exc)
                    ACTIVE_SCANS[scan_id]["step"] = "Target unreachable or blocked."
        except Exception as exc:
            app.logger.exception("Scan %s failed: %s", scan_id, exc)
            with SCANS_LOCK:
                if scan_id in ACTIVE_SCANS:
                    ACTIVE_SCANS[scan_id]["status"] = "failed"
                    ACTIVE_SCANS[scan_id]["progress"] = 100
                    ACTIVE_SCANS[scan_id]["error"] = str(exc)
                    ACTIVE_SCANS[scan_id]["step"] = "Scan failed."

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    return jsonify(
        {
            "scan_id": scan_id,
            "status": "running",
            "scan_mode": scan_mode,
            "verification": _verification_summary(preflight),
        }
    ), 202


@app.route("/api/scan/<scan_id>/status", methods=["GET"])
def api_scan_status(scan_id: str):
    """Poll live progress percentage, current probe step, or failure message."""
    with SCANS_LOCK:
        entry = ACTIVE_SCANS.get(scan_id)
        if entry:
            resp = {
                "status": entry.get("status", "running"),
                "progress": entry.get("progress", 10),
                "step": entry.get("step", ""),
                "error": entry.get("error"),
                "scan_mode": entry.get("scan_mode"),
            }
            results = entry.get("results") or {}
            if results:
                resp["target"] = results.get("target")
                resp["findings_count"] = len(results.get("findings", []) or [])
                resp["scan_mode"] = results.get("scan_mode", resp.get("scan_mode"))
            return jsonify(resp)

    scan_data = _load_scan_data(scan_id)
    if scan_data:
        status = scan_data.get("status", "completed")
        step = "Scan completed."
        if status == "cancelled":
            step = "Scan cancelled."
        elif status == "failed":
            step = "Scan failed."
        return jsonify(
            {
                "status": status,
                "progress": 100,
                "step": step,
                "error": "; ".join((scan_data.get("errors") or [])[:2]) or None,
                "target": scan_data.get("target"),
                "findings_count": len(scan_data.get("findings", []) or []),
                "scan_mode": scan_data.get("scan_mode"),
            }
        )

    return jsonify({"status": "not_found", "error": "Scan ID not found."}), 404


@app.route("/api/scan/<scan_id>/cancel", methods=["POST"])
def api_cancel_scan(scan_id: str):
    """Request cooperative cancellation for a running scan."""
    auth_error = _api_auth_error()
    if auth_error:
        return auth_error

    with SCANS_LOCK:
        entry = ACTIVE_SCANS.get(scan_id)
        if not entry:
            # If already completed/cancelled on disk, report state
            scan_data = _load_scan_data(scan_id)
            if scan_data:
                status = scan_data.get("status", "completed")
                if status == "cancelled":
                    return jsonify({"scan_id": scan_id, "status": "cancelled", "message": "Scan already cancelled."})
                return jsonify({"scan_id": scan_id, "status": status, "message": "Scan is not running."}), 409
            return jsonify({"error": "Scan ID not found."}), 404

        status = entry.get("status")
        if status != "running":
            return jsonify({"scan_id": scan_id, "status": status, "message": "Scan is not running."}), 409

        cancel_event = entry.get("cancel_event")
        if cancel_event:
            cancel_event.set()
        entry["step"] = "Cancellation requested..."
        entry["error"] = None
        return jsonify({"scan_id": scan_id, "status": "cancelling", "message": "Cancellation requested."}), 202


@app.route("/report/<scan_id>", methods=["GET"])
def view_html_report(scan_id: str):
    """Render or stream the standalone self-contained HTML report."""
    html_path = _scan_html_path(scan_id)
    if os.path.exists(html_path):
        return send_file(html_path, mimetype="text/html")

    abort(404, description=f"HTML report for scan '{scan_id}' not found.")


@app.route("/api/report/json/<scan_id>", methods=["GET"])
def download_json_report(scan_id: str):
    """Download the raw structured JSON scan findings for the exact scan ID."""
    json_path = _scan_json_path(scan_id)
    if os.path.exists(json_path):
        return send_file(
            json_path,
            as_attachment=True,
            download_name=f"security_scan_{scan_id}.json",
            mimetype="application/json",
        )

    abort(404, description=f"JSON report for scan '{scan_id}' not found.")


# ==============================================================================
# MAIN ENTRYPOINT
# ==============================================================================

if __name__ == "__main__":
    import socket

    port = int(os.environ.get("PORT", 5000))
    # Default remains loopback-only. Set HOST=0.0.0.0 to allow other devices on
    # your local network to reach CONFIGRA (see START_LINKS.md).
    host = (os.environ.get("HOST") or "127.0.0.1").strip()
    use_reloader = _DEV_RELOAD

    # Prevent duplicate serving processes on the same local port.
    # For Werkzeug's reloader, only perform this check in the serving process.
    should_check_port = (not use_reloader) or (os.environ.get("WERKZEUG_RUN_MAIN") == "true")
    if should_check_port:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
        except OSError:
            print(f"\n[!] Port {port} is already in use on {host}.")
            print("[!] Stop the existing CONFIGRA server process on that port before starting a new one to avoid duplicates.")
            sys.exit(1)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    print(f"\n[+] Starting CONFIGRA on http://{host}:{port}")
    print("[!] EXACTLY TWO PAGES: Page 1 (/) & Page 2 (/results/<scan_id>)")
    if use_reloader:
        print("[+] Local development auto-reload enabled (debugger disabled). Save Python files to reload; templates/static served without browser caching in dev mode.")
    # use_reloader for local dev code reloads without enabling Flask's interactive debugger.
    app.run(host=host, port=port, debug=False, use_debugger=False, use_reloader=use_reloader)
