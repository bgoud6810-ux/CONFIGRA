# REAL_WORLD_COMPATIBILITY_REPORT

**Project:** CONFIGRA (Automated Security Misconfiguration Detector)  
**Report date:** 2026-11-18 (local)  
**Environment:** Windows (`win32`), Python 3.13.14, Flask/Jinja2/requests per `requirements.txt`  
**Scope:** Real-world compatibility and backend accuracy audit (no UI redesign). Validation performed with existing automated suites (unchanged) and controlled local HTTP/HTTPS test servers + Flask test client. No unauthorized public websites were scanned.

## 1. Executive summary
- **Overall:** CONFIGRA demonstrates real end-to-end backend scanning behavior for supported misconfiguration categories on controlled local targets: URL normalization/validation, authorization/safety checks, live non-destructive HTTP(S) requests, check execution, evidence-based findings, scoring/grading, and per-scan dashboard/HTML/JSON outputs with unique scan IDs and no observed cross-scan result reuse.
- **Confirmed backend issues fixed (evidence-based):** `localhost`/loopback target handling without explicit permission in this environment (DNS resolution to `::1` classified with `reserved` flag caused false rejection), incomplete finding-field serialization in JSON/report outputs (`description/impact/remediation` not guaranteed in `Finding.to_dict()`), and a mojibake separator in the standalone HTML report per-check status line.
- **Validation status:** All existing automated suites passed (11/11 suites; `tests.test_report` 11/11, `tests/test_webapp.py` 8/8, others reported all tests passed). Controlled compatibility audit script (`_rw_final_check.py`) passed **25/25 checks, 0 failed**. Earlier controlled audit run (`_rw_compat_audit.py`) had **29 passed, 1 failed** due to a test-harness `Server` header artifact (`BaseHTTP/0.6 Python/...`) triggering `INF-001`; harness corrected and final controlled audit passed.
- **Claim boundary:** Passing local controlled tests confirms behavior for tested scenarios/configurations only. It does **not** prove complete real-world security coverage for all websites, frameworks, CDNs/WAFs, TLS deployments, or misconfiguration variants.

## 2. Features verified (evidence-based)

### 2.1 End-to-end scan flow
- **Scanner/API/engine integration:** `app.py` validates/normalizes targets, enforces authorization and safety, creates per-scan jobs/status, and runs `scanner.run_scan(...)` (same backend engine path). `scanner.run_scan(...)` builds scan context, executes checks, computes score/grade/counts, and generates unified JSON/HTML-compatible results.
- **Real HTTP response inspection:** `core.context.ScanContext` performs live requests (home + limited same-origin discovered pages), stores actual responses, and passes them to checks. Controlled scans produced findings/evidence matching server responses.
- **Unique scan IDs & no stale reuse:** Repeated scans produced distinct scan IDs and separate result objects/files; scan-specific dashboard/report/JSON routes returned data for the requested ID only (controlled evidence: `rw-a` vs `rw-b`, per-scan output files, route checks).
- **Fresh responses:** Consecutive scans against a changing local server observed multiple request hits across scans (controlled evidence: 66 requests observed across two scans), indicating fresh requests per scan.

### 2.2 Safety/validation (preserved and verified)
- **URL/target validation:** HTTP/HTTPS normalization and rejection of unsupported schemes/invalid targets (e.g. `ftp://...` rejected).
- **Authorization policy:** Public/non-private targets require explicit permission; rejected without it in controlled checks.
- **Local/private target handling:** Loopback/private-lab targets allowed subject to safety checks (including `localhost`/`127.0.0.1` after fix).
- **SSRF/destination protections:** Blocked cloud-metadata/link-local/reserved/multicast/unspecified/high-risk destinations as implemented; redirect targets revalidated before follow; redirect to `169.254.169.254` blocked in controlled test.
- **Non-destructive behavior:** Observed checks used safe/observational requests and controlled probes only (headers, cookies, OPTIONS/TRACE/method probing, limited path checks, body/header inspection). No exploitation, brute force, auth bypass, DoS, or intrusive port scanning observed.
- **Cancellation:** Cooperative cancellation supported; cancelled scan returned `status=cancelled` with no crash/fabricated findings and scan limitations recorded.
- **Timeouts/errors:** Unreachable/timeout cases failed clearly (e.g. `ConnectionError` / unreachable-or-blocked message) without fabricated vulnerability findings.

### 2.3 Supported checks and evidence semantics (as implemented/exercised)
- **Checks exercised:** Security headers/CSP/clickjacking/MIME/referrer/permissions/HSTS-related behavior (`checks/headers.py`), cookies (`checks/cookies.py`), CORS (`checks/cors.py`), HTTP methods (`checks/methods.py`), information disclosure (`checks/info_leaks.py`), sensitive paths/exposures (`checks/paths.py`).
- **Result semantics present:** Per-check structured statuses include `PASS`, `FAIL`, `WARNING`, and `NOT TESTED` where applicable (e.g. cancellation/budget/not-performed conditions surfaced via check results/limitations/not-performed structures).
- **Finding fields:** Findings include title, severity, category/url context, observed evidence, remediation/fix, impact, and description in engine/report/JSON flows (serialization fix applied; controlled misconfigured scan validated required fields for 17 findings).
- **Scoring/counts:** Severity counts summed to total findings and score/grade derived from findings in controlled scans (e.g. misconfigured HTTP: 17 findings, counts `Critical:1, High:3, Medium:5, Low:6, Info:2`, score 0 / grade F).

### 2.4 Dashboard / HTML / JSON consistency
- **Per-scan outputs:** `GET /results/<scan_id>` (dashboard), `GET /report/<scan_id>` (standalone HTML), and `GET /api/report/json/<scan_id>` returned correct data for requested scan IDs.
- **Consistency (controlled):** Target, scan ID, score, grade, counts, and findings count/content fields matched between scan result, saved JSON, and route-served JSON/dashboard/report artifacts for tested scans.

## 3. Controlled local test cases (expected vs actual)

| Test case | Target/setup | Expected | Actual | Result |
|---|---|---|---|---|
| URL/safety: localhost without explicit permission | `http://localhost` | Accepted as local-lab target (if safe) | Accepted (`ok=True`, resolved `['::1','127.0.0.1']`) after fix | **PASS** |
| URL/safety: unsupported scheme | `ftp://localhost` | Rejected | Rejected: unsupported scheme | **PASS** |
| URL/safety: public target without permission | `http://8.8.8.8` | Rejected (authorization required) | Rejected: public/non-private requires explicit confirmation | **PASS** |
| SSRF safety: cloud-metadata target | `http://169.254.169.254` with permission flag | Blocked | Blocked as cloud-metadata endpoint | **PASS** |
| SSRF safety: redirect to metadata | `http://127.0.0.1/ -> http://169.254.169.254/...` | Redirect blocked/revalidated | Blocked before follow | **PASS** |
| Secure-like HTTP (correctly configured baseline) | Local HTTP server with CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, non-versioned `Server: nginx`, limited methods | Scan completes, no false HDR/CKE/COR/MTH/PTH/DIR/INF misconfig findings, consistent outputs | Completed, `score=100 grade=A`, 0 HDR/CKE/COR/MTH/PTH/DIR/INF findings, valid per-check statuses, JSON/HTML consistent | **PASS** |
| Intentionally misconfigured HTTP | Local server missing/weak headers, insecure cookie, permissive CORS reflection w/ credentials, TRACE/PUT/DELETE allowed/advertised, server+tech version disclosure, stack trace endpoint, exposed `/.env` | Scan completes, detects evidenced misconfigurations across categories, accurate counts/score/grade, consistent outputs | Completed, `score=0 grade=F`, 17 findings (`HDR/CKE/COR/MTH/INF/PTH` evidenced), required fields present, counts sum matched, JSON/HTML consistent | **PASS** |
| Redirect handling | Local `302 / -> /final` | Follow safely and complete | Completed | **PASS** |
| Status codes + malformed/weak headers | Local 200/500 pages with weak CSP, deprecated `ALLOW-FROM`, invalid XCTO, weak referrer policy, versioned server, stack trace | Handled without crash; evidenced findings where applicable | Completed; findings included `HDR-004,HDR-005,HDR-006,HDR-007,HDR-008,INF-001,INF-008` | **PASS** |
| HTTPS (self-signed, authorized lab context) | Local HTTPS server with valid security headers incl. HSTS, scanned with `insecure=True` | Completes; HTTPS handled; no false missing-HSTS when HSTS present | Completed, `score=100 grade=A`, `HDR-001/HDR-002` absent | **PASS** |
| Scan independence / no reuse | Two scans against changing local server (`rw-a`, `rw-b`) | Unique IDs, separate results, fresh responses | Unique IDs, separate results, 66 requests observed across scans | **PASS** |
| Unavailable target | `http://127.0.0.1:1` | Clear connection failure; no fabricated vulnerability findings | `ConnectionError` raised with unreachable/blocked message | **PASS** |
| Timeout/unresponsive target | Slow local HTTP endpoint with short timeout | Handled safely without fabricated findings | Raised connection/timeout-style failure (`ConnectionError` in this run) without fabricated findings | **PASS** |
| Dashboard/HTML/JSON routes (per-scan) | Saved misconfigured scan `rwcompatdash` served via Flask routes | 200 responses and matching per-scan/core fields | `/results`, `/report`, `/api/report/json` all 200; matching `scan_id/target/score/grade/counts/findings` | **PASS** |
| Cancelled scan | Pre-cancelled scan (`cancel_event` set) | Marked cancelled, no crash/fabrication, limitations recorded | `status=cancelled`, 0 findings, 2 limitations recorded | **PASS** |

**Notes:** HTTPS self-signed scan emitted urllib3 `InsecureRequestWarning` (expected with `insecure=True`); scan completed and results were valid. Timeout test on Windows local server produced a `ConnectionAbortedError` trace from the test server handler after client timeout/disconnect; scanner behavior remained correct (no fabricated findings, error surfaced).

## 4. Checks executed / not supported / not tested

### Executed (with local evidence)
- **URL/target validation & normalization:** HTTP/HTTPS handling, unsupported scheme rejection, hostname resolution/IP classification checks.
- **Authorization/safety controls:** public-target permission enforcement, localhost/private-lab allowance (after fix), cloud-metadata/redirect blocking.
- **Security headers/CSP:** presence/value/weakness/misconfiguration detection on controlled targets (including malformed/weak values and HTTPS+HSTS case).
- **Cookies:** insecure session cookie attribute detection on misconfigured target.
- **CORS:** permissive reflection/credential-related misconfiguration detection on misconfigured target.
- **HTTP methods:** TRACE/unsafe/disallowed method exposure detection on misconfigured target.
- **Information disclosure:** server/technology/version disclosure and stack-trace/error exposure detection on controlled targets.
- **Sensitive paths/exposures:** exposed sensitive file detection (e.g. `/.env`) in controlled misconfigured target.
- **Redirect/status/error handling:** 302 redirect follow (validated), 200/500 handling, unreachable and timeout/unresponsive handling.
- **Result semantics & reporting:** per-check `PASS/FAIL/WARNING/NOT TESTED` semantics present; JSON/HTML/dashboard consistency; unique scan IDs; cancellation handling.

### Not supported or limited by design (current implementation)
- **Deep TLS/certificate/cipher/protocol analysis:** not a full TLS assessment engine; observations limited to supported HTTP(S) behavior/headers (e.g. HSTS presence/value on HTTPS responses) and connection success/failure with given verification settings.
- **Authenticated scanning / logged-in surface coverage:** no credentialed session crawling/auth flows; checks limited to anonymously reachable responses/pages.
- **Exhaustive content discovery:** bounded/same-origin discovery and request budgets/timeouts by design (non-destructive, conservative).
- **Active exploitation or intrusive testing:** intentionally excluded (no exploitation, brute force, auth bypass, DoS, intrusive port scanning).
- **Framework/platform-specific deep config audits:** only generic, response-observable misconfigurations covered by implemented checks.
- **Broad WAF/CDN/edge behavior emulation:** not specifically tested against diverse real-world edge infrastructures in this audit.

### Not tested in this audit
- **Live public internet targets:** excluded to comply with authorization/safety constraints.
- **Real browser UI automation (interactive Playwright/manual click-through):** not executed in this run; route/template/JS behavior was inspected and Flask/API/report flows were validated programmatically.
- **Large-scale performance/load/concurrency stress beyond basic behavior:** not performed.

## 5. Accuracy issues found (confirmed) and fixes applied

| # | Area | Confirmed issue / evidence | Fix applied | Files changed | Verification after fix |
|---|---|---|---|---|---|
| 1 | Target validation / real-world compatibility | `http://localhost` was rejected without permission when DNS resolved to `::1` because classifier included `reserved`, despite being loopback/local-lab (evidence: safety probe showed `OK False ... IP ::1 (loopback,private,reserved)` and controlled audit failed "Accepts localhost HTTP URL" initially). | Adjusted `is_allowed_without_permission` to explicitly allow loopback/private local-lab targets before generic `reserved` rejection, while preserving blocks for cloud-metadata/link-local/multicast/unspecified and non-permitted public targets. | `core/safety.py` | Localhost accepted in probes and controlled audit (`PASS | Localhost HTTP accepted without permission`); `python -m py_compile core/safety.py` PASS; `tests/test_webapp.py` 8/8 PASS. |
| 2 | Finding/report/JSON field completeness | `Finding.to_dict()` returned dataclass fields but did not guarantee `remediation`, `description`, and `impact` keys expected/needed for consistent reporting across dashboard/HTML/JSON. This risked missing required finding content in outputs. | Updated `Finding.to_dict()` to always include `remediation` (alias of `fix`) and provide safe defaults for missing `description`/`impact` based on title/severity while preserving existing values. | `core/models.py` | `python -m py_compile core/models.py` PASS; `tests.test_headers/cookies/paths/info_leaks/report` and full existing suites PASS; controlled misconfigured scan confirmed required fields present for all findings (17/17). |
| 3 | Standalone HTML report rendering | Mojibake separator in per-check status line (`check.status is defined` line rendered as `�`) reduced output clarity/correctness in generated report template. | Replaced mojibake with HTML entity `&mdash;` in report template. | `reports/templates/report.html` | Template inspected (correct `&mdash;`), `tests.test_report` 11/11 PASS. |

**Not treated as backend bugs (documented):** urllib3 `InsecureRequestWarning` during `insecure=True` HTTPS self-signed test is expected; local slow-server `ConnectionAbortedError` traceback from test harness on client timeout is an environment/harness-side socket behavior, while scanner correctly surfaced timeout/unreachable handling without fabricated findings.

## 6. Bugs fixed (summary)
- **Fixed:** `localhost` false rejection without permission on systems where loopback resolves with additional `reserved` classification (`core/safety.py`).
- **Fixed:** missing guaranteed `description/impact/remediation` fields in serialized findings (`core/models.py`).
- **Fixed:** mojibake per-check status separator in HTML report template (`reports/templates/report.html`).

No other confirmed backend correctness bugs requiring code changes were identified in the inspected/tested paths during this audit.

## 7. Tests executed (exact counts/results)

### 7.1 Existing automated suites (unchanged test files)
Executed in this audit session/environment (`python -m pytest` unavailable):

| Command | Result | Exact reported outcome |
|---|---:|---|
| `python -m tests.test_headers` | PASS | `ALL HEADER TESTS PASSED!` |
| `python -m tests.test_cookies` | PASS | `ALL COOKIE TESTS PASSED!` |
| `python -m tests.test_paths` | PASS | `[PHASE 2 RESULT: PASS]` |
| `python -m tests.test_info_leaks` | PASS | `ALL INFO LEAKS TESTS PASSED!` |
| `python -m tests.test_methods` | PASS | `ALL METHOD TESTS PASSED!` |
| `python -m tests.test_cors` | PASS | `ALL CORS TESTS PASSED!` |
| `python -m tests.test_cors_methods` | PASS | `[PHASE 3 RESULT: PASS]` |
| `python -m tests.test_compare` | PASS | `[PHASE 6 RESULT: PASS]` |
| `python -m tests.test_accuracy` | PASS | `[PHASE 4 RESULT: PASS]` |
| `python -m tests.test_report` | PASS | `ALL 11 HTML REPORT TESTS PASSED SUCCESSFULLY! (EXIT 0)` |
| `python tests/test_webapp.py` | PASS | `Ran 8 tests ... OK` (exit 0) |

**Totals:** 11 suites executed, **11 passed, 0 failed**. Explicit per-case counts emitted: `tests.test_report` = **11/11 passed**, `tests/test_webapp.py` = **8/8 passed**; other suites reported pass via module banners/results.

### 7.2 Compile/syntax checks (post-fix)
| Command | Result |
|---|---:|
| `python -m py_compile core/safety.py core/models.py scanner.py app.py core/context.py core/runner.py core/scoring.py checks/headers.py checks/cookies.py checks/cors.py checks/methods.py checks/info_leaks.py checks/paths.py reports/html_report.py` | PASS (exit 0) |

### 7.3 Controlled local integration/e2e compatibility audits (temporary scripts)
| Script/run | Purpose | Result | Exact counts |
|---|---|---:|---|
| `_rw_compat_audit.py` | Broad controlled HTTP/HTTPS/redirect/status/SSRF/routes/cancel/independence audit (initial run) | FAIL (harness artifact) | **29 passed, 1 failed**. Failure: `Secure HTTP has no header/cookie/cors/method/path/leak misconfig findings` due to `INF-001` from default `BaseHTTP/0.6 Python/3.13.14` server banner in harness (not scanner logic). |
| `_rw_audit_quick.py` | Quick controlled audit (first attempt) | FAIL (script bug) | `passed: 4, failed: 2` including script exception `NameError: name 'b' is not defined` and localhost case failed before safety fix; not used as product evidence. |
| `_rw_final_check.py` | Final corrected controlled audit covering validation/safety, secure+misconfigured HTTP, redirect/status/malformed headers, HTTPS self-signed (`insecure=True`), independence/freshness, unreachable/timeout, dashboard/HTML/JSON route consistency, cancellation | PASS | **25 passed, 0 failed** (`RWF_EXIT:0`, summary `{"passed":25,"failed":0,...}`) |

## 8. Real-world compatibility limitations
- **Coverage is response-observable and check-specific:** only misconfigurations detectable by implemented, non-destructive checks from available anonymous responses/pages are reported.
- **Environment diversity not fully represented:** local controlled servers cannot replicate all CDN/WAF/proxy/load-balancer behaviors, bot protections, challenge pages, geo/rate restrictions, or framework-specific edge cases seen on the public internet.
- **HTTPS/TLS depth limited:** no deep certificate-chain, cipher-suite, protocol-version, or TLS posture analysis beyond supported HTTPS request handling/header observations.
- **Discovery and budgets are bounded:** conservative timeouts, request/rate limits, redirect limits, and limited crawling can leave reachable pages/conditions untested (reported as limitations/NOT TESTED where applicable).
- **No authenticated or stateful workflow testing:** login-protected areas, multi-step flows, and role-specific misconfigurations are out of scope.
- **Local test confidence vs internet reality:** controlled passing results do not guarantee identical behavior on arbitrary third-party targets with custom server stacks, dynamic defenses, or intermittent network conditions.

## 9. Remaining work
- **Broaden controlled test matrix:** add more local fixtures for diverse CSP/header edge cases, cookie prefix/attribute combinations, CORS preflight/origin variants, additional HTTP status/redirect chains, and content-type/body parsing edge cases to further reduce false-positive/negative risk.
- **Improve observability for NOT TESTED/limitations:** ensure every partial-skip scenario consistently surfaces actionable limitation details in dashboard/HTML/JSON (where safe and available).
- **Optional authenticated scanning mode (future, safety-gated):** design-only consideration; would require explicit user-provided credentials/scope controls and strict non-destructive constraints (not implemented).
- **External validation on explicitly authorized targets:** to assess real-world compatibility beyond local labs, run scans only against targets with documented permission and compare findings manually; not performed in this audit.

## 10. Evidence artifacts (local, generated during audit)
- Per-scan outputs written to `output/` during controlled runs (examples): `scan_rw-sec.json`, `report_rw-sec.html`, `scan_rw-mis.json`, `report_rw-mis.html`, `scan_rwcompatdash.json`, `report_rwcompatdash.html`, and other scan-specific files.
- Temporary audit harness scripts and summaries used during this session were removed after execution except where not needed; controlled audit results are captured in this report and command outputs above.
