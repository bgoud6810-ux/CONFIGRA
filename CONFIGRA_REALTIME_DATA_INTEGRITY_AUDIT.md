# CONFIGRA Real-Time Data Integrity Audit

**Project:** `C:\path\to\cyber-spl-project`  
**Audit date:** 2026-11-19  
**Scope:** Enforce genuine real-time target observations only (no fabricated/stale/demo runtime scan results), correct handling for invalid/unreachable/unobservable targets, scan/report/dashboard integrity, preservation of SSRF protections and existing functionality.

> **Evidence status:** This audit includes verified local/fixture and direct local-runtime evidence captured during this session. Public-target behavior, real Cloudflare/WAF/challenge handling, real public `429`/`Retry-After`, and public CA-trusted HTTPS behaviors remain **NOT VERIFIED** (local fixture evidence only) unless explicitly stated otherwise.

## 1. Root cause and reproduction

### 1.1 Issues identified (from prior state/checkpoint and verification)
1. **Risk of cross-scan/stale JSON artifact reuse in web API**
   - `GET /api/report/json/<scan_id>` previously fell back to `output/results.json` when the requested scan-specific JSON file was missing (for non-`results` IDs). This could return a different scan’s data than the requested ID, violating scan-ID-specific report integrity.
   - **Reproduction (prior behavior):** request `/api/report/json/<missing_or_mismatched_id>` while `output/results.json` exists -> would serve `results.json` instead of 404 for that exact ID.
   - **Fixed:** endpoint now serves only the exact scan’s JSON artifact (`_scan_json_path(scan_id)`) or returns 404.

2. **Invalid/unreachable/unobservable targets must not produce fabricated successful scans**
   - **DNS-invalid targets:** refused during prevalidation/dispatch (`core/safety.py` resolution failure, `scanner.run_scan` raises `PermissionError`, `/api/scan` returns 400). No scan execution, no persisted fabricated success record.
   - **Resolvable-but-unreachable/connection failures/timeouts before observable origin:** handled as genuine failed scans with recorded diagnostics/outcomes, all required checks `NOT TESTED`, `grade="N/A"`, `score=0` (no fabricated findings/pass states).
   - **Unobservable origin responses (HTTP 403, 429, >=500, intermediary/CDN/WAF challenge/interstitial, blocked-redirect outcomes):** treated as not reliably observable for origin misconfiguration checks; scan recorded as failed with `NOT TESTED` required checks and recorded HTTP/limitation/WAF/rate-limit context. Prevents false clean/success results from restricted/error/challenge pages.

3. **UI/report consistency and no-scan state**
   - `/results` with no available latest scan renders scanner with: `No scan data available. Start a new scan.`
   - `/results/<scan_id>` loads only that scan’s recorded data (in-memory completed result or exact `scan_<id>.json`/legacy `results.json` only when `scan_id == "results"`), or shows scan-not-found state (no reuse of another scan’s result).
   - Failed/cancelled scans navigate to `/results/<scan_id>` for the exact scan ID so recorded failed/incomplete state is shown (not older successful results).
   - HTML report and JSON results are generated from the same genuine scan result payload/metadata for that scan.

### 1.2 Verified reproductions/evidence (this session)
- **DNS-invalid:** `core.safety.validate_url_target("http://dns-invalid.test/", ...)` with simulated DNS failure -> refused (`Failed to resolve hostname ...`). `scanner.run_scan(...)` -> `PermissionError` (no persisted scan). Flask `/api/scan` -> HTTP 400 with resolution error. No `output/` artifact changes observed for this case in regression test.
- **Resolvable but unreachable (local closed port):** `run_scan('http://127.0.0.1:6553'/'127.0.0.1:1', authorized_assessment)` -> `status=failed`, `grade=N/A`, `score=0`, `dns_outcome=resolved`, `connection_outcome=failed`, `http_outcome=request_failed`, all required checks `NOT TESTED`.
- **Timeout (controlled local slow server):** request times out -> failed/incomplete (not successful), `N/A`/0, checks `NOT TESTED`.
- **HTTP 403 observed/restricted:** `status=failed`, `http_outcome=http_403`, `N/A`, all checks `NOT TESTED`, limitations/errors indicate restricted/unreliable observation.
- **HTTP 429 rate-limited:** `status=failed`, `N/A`, all checks `NOT TESTED`, `rate_limit_events` recorded (Retry-After/headers as observed), conservative stop/no fabricated success.
- **HTTP 500 error-state origin:** `status=failed`, `http_outcome=http_500`, `N/A`, all checks `NOT TESTED`, limitations indicate error-state/unreliable origin checks.
- **Blocked redirect (to metadata destination):** recorded as failed scan with `NOT TESTED` checks and blocked-redirect/SSRF-safe diagnostics (no fabricated successful scan).
- **Valid reachable local target:** completed genuine scan with real `check_results` (no fabricated pass when unobservable; outcomes reflect actual responses).
- **JSON/HTML consistency (failed scan):** generated artifacts for exact scan ID match failed state (`status`, `grade=N/A`, scan ID, DNS/HTTP outcome/diagnostics) with no “clean/success” misrepresentation.
- **Report/download integrity:** missing exact HTML/JSON report IDs return 404 (no fallback to another scan); `/results/<missing>` renders scan-not-found state.

## 2. Files inspected and changed

### Inspected (key)
- `scanner.py` — scan orchestration, validation/init failure handling, result assembly, scoring/status semantics, persistence/report generation.
- `app.py` — scan dispatch/validation, background execution, status/cancel polling, result/report/download routes, no-scan/latest behavior, dev reload behavior.
- `core/context.py` — URL normalization/validation integration, SSRF-safe request pipeline, DNS/redirect revalidation, timeout/connect behavior, response observability/classification (403/429/5xx/challenge/WAF/TLS), request budgeting/cancellation.
- `core/safety.py` — scheme/hostname resolution, IP classification, SSRF destination blocking (link-local/metadata/multicast/unspecified/reserved/dangerous ranges as applicable), loopback/private handling per mode, redirect target validation.
- `core/runner.py` — check execution, `PASS/FAIL/WARNING/NOT TESTED` synthesis, passive/authorized behavior, unobservable-origin handling.
- `core/models.py` — scan modes/labels, finding and check result structures/status normalization.
- `core/scoring.py` — score/grade computation.
- `reports/html_report.py`, `reports/templates/report.html` — report generation/rendering from actual scan data.
- `templates/scanner.html`, `templates/dashboard.html`, `static/js/cyber_scanner.js`, `static/js/cyber_dashboard.js` — scan initiation/polling/cancel, navigation by exact scan ID, rendering of recorded results/empty/failure states.
- `tests/test_safety.py`, `tests/test_webapp.py`, `tests/test_phase4_capabilities.py` — SSRF/safety, web/API/UI, and Phase 4/integrity coverage.
- Other unit/accuracy tests present under `tests/` were considered for full-suite execution (see test results).

### Changed in this audit/fix session
- `app.py`
  - **Change:** Removed JSON download fallback to `output/results.json` for non-`results` scan IDs in `GET /api/report/json/<scan_id>`.
  - **Why:** Prevent returning a different/stale scan’s JSON when an exact scan-specific artifact is missing; enforce scan-ID-specific integrity (404 for missing exact scan artifact).
- `tests/test_realtime_integrity.py` (new)
  - **Change:** Added regression tests covering required real-time data integrity cases: DNS-invalid prevalidation refusal with no persisted scan, resolvable-but-unreachable connection failure, timeout behavior, HTTP 403/429/500 unobservable handling, valid reachable genuine scan, JSON/HTML consistency for failed scan state, and no reuse/fallback for missing scan reports/results.
  - **Why:** Prove no fabricated/stale/successful results for invalid/unreachable/unobservable cases and verify scan-ID-specific artifact/report behavior.

> Note: The repository already contained prior integrity/Phase 4 hardening in `scanner.py`, `core/context.py`, `core/runner.py`, `app.py`, UI templates/scripts, and tests per checkpoint/history; this session verified and made a targeted additional integrity fix plus added focused regression coverage.

## 3. Runtime mock/fallback/fabrication audit

- **Search/audit performed:** scanned core/app/scanner/runner/reports/templates/static/tests for `demo`, `mock`, `dummy`, `fake`, `sample`, `stale`, `fallback` patterns (case-insensitive/contextual).
- **Findings:**
  - No runtime fabricated/default/demo scan payloads used for scan execution results, dashboard rendering, or HTML/JSON report content were identified in production paths.
  - Matches observed were non-fabrication cases (e.g. comments like “Fallback for custom plugins”, benign “sample” naming in test/data helpers or variable names) and a legitimate UI placeholder in `templates/scanner.html`.
  - **Removed:** API JSON download fallback that could serve `output/results.json` for a different requested scan ID (`app.py`), eliminating a potential stale/cross-scan artifact path.
- **UI empty state:** `/results` without an available latest scan displays `No scan data available. Start a new scan.` (no seeded/fake data).
- **Latest scan resolution:** `get_latest_scan_id()` may return legacy `results` only if the actual `output/results.json` artifact exists; this references a real previously persisted scan artifact (not mock data). Exact `/results/<scan_id>` loading remains scan-ID-specific.

## 4. Before/after scan flow (integrity-relevant)

### Before (problematic/risk areas)
- Invalid/unreachable/unobservable scenarios could risk being misrepresented if not consistently classified; restricted/error/challenge responses could be misread as origin content in naive handling.
- JSON report download could fall back to `output/results.json` for a missing requested scan ID, risking stale/cross-scan reuse.

### After (current intended behavior)
1. **Validation/dispatch:** normalize URL and validate per scan mode/authorization (`core/safety.py`, `scanner.run_scan`, `/api/scan`). DNS/target validation failures are refused before scan execution; web API returns 400 with reason (no running scan state created, no fabricated persisted scan result for refused prevalidation).
2. **SSRF-safe execution:** every destination/redirect is revalidated; blocked/dangerous destinations (including metadata/link-local/etc. per policy) are refused/recorded safely. Passive public and authorized modes remain separated; local loopback `127.0.0.1`/`::1` (incl. bracketed IPv6) supported for authorized local testing without weakening public-target controls.
3. **Live observation:** genuine HTTP(S) requests with timeout/budget/rate-limit awareness. DNS resolved does **not** imply connectivity/HTTP success; outcomes are recorded separately (`dns_outcome`, `connection_outcome`, `http_outcome`).
4. **Classification/outcomes:**
   - **DNS/refusal/prevalidation failure:** refused (no fabricated successful scan record).
   - **Connection failure/timeout/unreachable before observable origin:** persisted `failed` scan, `grade=N/A`, `score=0`, required checks `NOT TESTED`, diagnostics recorded.
   - **403:** observed/restricted, failed/unreliable for origin checks, required checks `NOT TESTED`.
   - **429:** rate-limited, `rate_limit_events` recorded, conservative handling, affected checks `NOT TESTED`, no fabricated success.
   - **5xx/challenge/intermediary-unobservable:** observed but origin checks limited/unreliable, failed with `NOT TESTED` checks and recorded limitations/WAF indicators where applicable.
   - **Blocked redirect:** recorded failed scan with `NOT TESTED` checks and blocked-redirect diagnostics.
   - **Valid reachable observable target:** genuine scan with real check execution/results.
5. **Reporting/UI:** results persisted per scan ID; `/api/scan/<id>/status`, `/results/<id>`, `/report/<id>`, `/api/report/json/<id>` operate on that exact scan’s recorded data (or 404/not-found as appropriate). `/results` shows no-scan message when no latest scan is available. Dashboard/HTML/JSON reflect only real backend data for the scan.

## 5. Test results

### Executed and captured (complete outputs summarized)
- `python -m py_compile scanner.py app.py core/context.py core/runner.py core/models.py core/safety.py reports/html_report.py tests/test_phase4_capabilities.py tests/test_realtime_integrity.py`  
  - **Result:** PASS (exit code 0)
- `python -m unittest -v tests.test_safety tests.test_webapp`  
  - **Result:** PASS — **Ran 19 tests**, `OK` (PowerShell emitted unittest output on stderr and a non-zero wrapper in this environment despite `OK`; test summary indicates all passed)
- `python -m unittest -v tests.test_realtime_integrity`  
  - **Result:** PASS — **Ran 9 tests in 4.706s**, `OK` (PowerShell wrapper non-zero despite `OK`; includes expected catch-all matching notice in output)

### Executed but not fully captured in-session (background/incomplete capture)
- `python -m unittest tests.test_phase4_capabilities` — started during session; final summary **not captured** here (background execution/output not fully retrieved in-session). Reconciliation may be required for expectations impacted by corrected 403/429/5xx/unobservable/failure semantics.
- `python -m unittest -v tests.test_accuracy tests.test_compare tests.test_cookies tests.test_cors tests.test_cors_methods tests.test_headers tests.test_info_leaks tests.test_methods tests.test_paths tests.test_report` — attempted but runner reported `NO TESTS RAN` for that invocation form (modules use script-style/unittest-main patterns in places); requires appropriate invocation/capture.
- Full discovery `python -m unittest discover -s tests -p "test*.py"` — started during session; final summary **not captured** here.

**Action required to claim complete suite status:** rerun `tests.test_phase4_capabilities`, any script-style test modules with their correct invocation, and full discovery/all required existing+new tests, capturing complete pass/fail output after this change set.

## 6. Genuine connectivity/runtime evidence

- **Local loopback unreachable port (genuine connect failure):** `http://127.0.0.1:6553` and `http://127.0.0.1:1` -> failed scan, DNS resolved, connection failed/request failed, all checks `NOT TESTED`, `N/A`/0.
- **DNS-invalid:** `http://configra-test.invalid` (and simulated `dns-invalid.test`) -> refused at prevalidation (no persisted fabricated scan).
- **Controlled local fixtures (real HTTP servers on localhost):** 403, 429 (+Retry-After), 500, slow/timeout, blocked redirect target, and valid 200 responses all exercised with genuine request/response behavior and correct integrity outcomes.
- **Local reachable target:** `http://127.0.0.1:3000` responded `HTTP 200` during session (live reachability probe). A full recorded Juice Shop scan result artifact was **not captured** in this audit write-up.

## 7. Limitations and NOT VERIFIED items

- **NOT VERIFIED:** Public-target behavior against real internet hosts.
- **NOT VERIFIED:** Real Cloudflare/WAF/CDN challenge/interstitial handling on live infrastructure (only local fixture simulations verified).
- **NOT VERIFIED:** Real public `429`/`Retry-After` behavior from production services.
- **NOT VERIFIED:** Public CA-trusted HTTPS certificate validation/chain behavior on real public endpoints (local TLS fixture evidence only where covered by existing tests).
- **NOT VERIFIED:** Complete post-change results for `tests.test_phase4_capabilities`, script-style test modules invoked individually as needed, and full `unittest discover` suite (not fully captured in-session).
- Dev server/Juice Shop availability can vary by environment/session; scans against them are genuine only when the target is actually reachable at scan time.

## 8. SSRF and security controls preservation (confirmation)

- **Preserved/confirmed in inspected implementation:** HTTP/HTTPS-only targets; hostname resolution and destination validation applied; redirect locations revalidated (SSRF/DNS-rebinding-aware flow); dangerous destinations (including metadata, link-local, multicast, unspecified, and reserved/special-use ranges as enforced by `core/safety.py`) remain blocked per policy/mode.
- **Authorized local testing:** loopback targets (`127.0.0.1`, `::1`, bracketed IPv6 forms) remain allowed for authorized/local scenarios as designed, without weakening public-target controls.
- **Scan behavior constraints preserved:** non-destructive, no exploitation/WAF bypass/brute force/auth bypass/DoS/aggressive crawling/intrusive probing beyond existing safe checks; passive vs authorized modes remain distinct.
- **Integrity fix impact:** JSON download exact-scan enforcement does not alter scan execution or SSRF validation logic.

## 9. Dashboard/HTML/JSON integrity status

- **Per-scan identity:** scan results/reports are keyed and served by exact scan ID (with legacy `results` mapping only to its corresponding artifact).
- **No fabricated success for failed/unobservable/invalid flows:** failed/refused/unobservable cases produce no clean successful misconfiguration assessment; UI/report must show recorded failed/incomplete/not-assessed states and limitations.
- **Consistency:** HTML and JSON reports generated from the same genuine scan result data for a given scan; regression coverage added for failed-scan JSON/HTML consistency.
- **No-scan state:** explicit “No scan data available. Start a new scan.” when no latest scan is available.

## 10. Remaining recommended actions

1. Run and capture complete results for `tests.test_phase4_capabilities`, reconcile any assertion mismatches due to corrected integrity semantics, and rerun until clean.
2. Run all existing test modules (using correct invocation for script-style tests where applicable) and full `python -m unittest discover -s tests -p "test*.py"`; capture complete pass/fail output.
3. Capture a recorded, genuine scan against a reachable local authorized target (e.g. Juice Shop on `127.0.0.1:3000`) showing completed results and matching JSON/HTML/dashboard state, if required for final evidence.
4. Update `PHASE4_IMPLEMENTATION_REPORT.md` only after clean Phase 4 suite evidence is obtained.