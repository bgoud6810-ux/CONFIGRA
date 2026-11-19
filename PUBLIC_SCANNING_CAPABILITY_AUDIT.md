# PUBLIC_SCANNING_CAPABILITY_AUDIT

**Project:** CONFIGRA – Automated Security Misconfiguration Detector  
**Audit date:** 2026-11-18 (local)  
**Audit type:** Phase 3 capability audit (inspection-only; **no code changes made**)  
**Scope inspected:** `scanner.py`, `app.py`, `core/safety.py`, `core/context.py`, `core/models.py`, `core/runner.py`, `core/scoring.py`, `checks/headers.py`, `checks/cookies.py`, `checks/cors.py`, `checks/methods.py`, `checks/info_leaks.py`, `checks/paths.py`, `reports/html_report.py`, `reports/templates/report.html`, `templates/scanner.html`, `requirements.txt`, prior Phase 2 evidence in `REAL_WORLD_COMPATIBILITY_REPORT.md`.

**Evidence boundary:** Findings below are based on source inspection and previously executed local/lab tests documented in this workspace. **No authorized public-target scans were executed in this audit.** Public website compatibility is **not claimed**.

---

## 1. Existing capabilities

### 1.1 URL validation, normalization, DNS/IP safety (SSRF-oriented)
- **Normalization and scheme enforcement:** `normalize_target_url()` prepends `http://` when missing; `validate_url_target()` accepts only `http`/`https` (`core/safety.py`, `ALLOWED_SCHEMES`).
- **DNS resolution:** `resolve_hostname_ips()` via `socket.getaddrinfo(..., proto=IPPROTO_TCP)`; resolved IPs recorded in `ValidationResult` (`core/safety.py`).
- **IP classification/blocking:** flags `loopback`, `private`, `link_local`, `multicast`, `reserved`, `unspecified`, and cloud-metadata indicators (`classify_ip`, `CLOUD_METADATA_IPS`, `CLOUD_METADATA_HOSTNAMES`) (`core/safety.py`).
- **Authorization-aware destination policy:**
  - **Without explicit permission (`i_have_permission=False`):** allows loopback/private local-lab targets (after Phase 2 fix allowing loopback/private before generic `reserved` rejection for local-lab cases); blocks high-risk labels (`cloud_metadata`, `link_local`, `multicast`, `unspecified`) and other non-allowed targets including public/non-private destinations with clear rejection reason requiring explicit authorized confirmation (`core/safety.py:is_allowed_without_permission`, `validate_url_target`).
  - **With explicit permission (`i_have_permission=True`):** allows legitimate global/public targets and loopback/private lab targets; blocks `link_local`, `reserved`, `multicast`, `unspecified`, `cloud_metadata`, and other non-global/non-lab ranges (`core/safety.py:is_disallowed_for_authorized_scan`).
- **Redirect destination validation:** `validate_redirect_location()` resolves relative redirects and revalidates absolute destination via `validate_url_target()`; `ScanContext.request()` manually handles redirects (disables auto-redirect), revalidates each `Location`, enforces same-origin/allowed-scheme and `max_redirects` (`core/safety.py`, `core/context.py`).
- **Per-request revalidation:** `ScanContext.request()` resolves/validates scheme/hostname, checks destination safety, and revalidates each redirect hop before following (`core/context.py`). This supports SSRF reduction and re-checking destinations (including on redirect changes).

### 1.2 HTTP(S) client and scan execution controls
- **Request pipeline:** `requests.Session` with bounded timeouts, explicit `allow_redirects=False`, custom `User-Agent` (`Mozilla/5.0 (compatible; Configra-Scanner/1.0; ...)`), optional response decompression (`Accept-Encoding` conditional), and request budget/rate limiting (`max_requests`, delay/rate controls) (`core/context.py`).
- **Non-destructive intent in checks:** existing checks primarily use observational requests and limited safe probes (GET/HEAD discovery, OPTIONS/TRACE/method parsing, controlled CORS origin probes, bounded sensitive-path checks with baseline/signature matching). No exploitation/brute-force/auth-bypass code observed in inspected modules (`checks/*`, `core/context.py`, `scanner.py`).
- **Cancellation and budgets:** cooperative `cancel_event` handling, request budget exhaustion detection, and scan limitations/error recording (`core/context.py`, `core/runner.py`, `scanner.py`, `app.py`).
- **TLS verification toggle:** `ScanContext` supports `verify_ssl`; CLI `--insecure` and API `insecure` disable certificate verification (`requests.Session.verify=False`) (`core/context.py`, `scanner.py`, `app.py`).

### 1.3 Scan orchestration, checks, scoring, and reporting
- **End-to-end engine:** `scanner.run_scan()` normalizes/validates target, builds context, fetches home (+ bounded extra pages), runs registered checks, deduplicates findings, computes score/grade/counts, records timing/metadata, and writes unified JSON/HTML outputs (`scanner.py`, `core/context.py`, `core/runner.py`, `core/scoring.py`).
- **Implemented check modules (6):** security headers/CSP/HSTS/clickjacking/MIME/referrer/permissions (`checks/headers.py`), cookie attributes/prefixes (`checks/cookies.py`), CORS passive+active probes (`checks/cors.py`), HTTP methods/TRACE and Allow-header analysis (`checks/methods.py`), information disclosure in headers/body stack traces (`checks/info_leaks.py`), sensitive paths/directory listing with baseline-aware signatures (`checks/paths.py`).
- **Result semantics:** per-check structured statuses `PASS/FAIL/WARNING/NOT TESTED` via `core.runner`/`core.models.CheckResult`; findings include evidence and remediation/fix fields; score/grade derived from findings/severity/confidence (`core/scoring.py`); JSON/HTML include findings, counts, passed checks, check results, checks not performed, and scan limitations.
- **Consistency artifacts:** same scan result object drives JSON and HTML generation; Flask routes serve per-scan dashboard/report/JSON (`scanner.py`, `app.py`, `reports/html_report.py`, `templates/dashboard.html` path implied by app).

### 1.4 Interfaces and authorization gating
- **CLI:** requires `--i-have-permission` for public/non-private targets (enforced via `validate_url_target` in `run_scan`); prints authorization banner; supports `--delay`, `--timeout`, `--insecure`, `--compare` (`scanner.py`).
- **Web API/UI flow:** `/api/scan` validates target with `i_have_permission` and rejects disallowed/public targets with authorization message; scanner page includes authorized-testing notice and permission checkbox wiring (`app.py`, `templates/scanner.html`).

---

## 2. Confirmed defects

| # | Defect (confirmed by inspection/evidence) | Evidence | Impact |
|---|---|---|---|
| 1 | **No explicit handling/classification for HTTP `429` / `Retry-After` rate-limiting responses.** | No `429`, `Retry-After`, retry/backoff logic found in `core/context.py`, `checks/*`, `scanner.py`, or `app.py` (code search over relevant modules). `ScanContext.request()` returns/records responses/errors generically; checks interpret status/content ad hoc. | Scanner may misclassify rate-limited responses as generic errors, incomplete observations, or check-specific outcomes without transparent rate-limit reporting; cannot reliably distinguish throttling/defensive blocking from target behavior. |
| 2 | **No WAF/Cloudflare/challenge-page classification logic.** | No detection for Cloudflare/WAF/challenge/captcha indicators (e.g. `cf-ray`, `__cf*`, challenge titles/bodies, managed challenge patterns) in request pipeline/checks/reports. | WAF/CDN challenge or interstitial responses can be mistaken for origin behavior or produce misleading/incomplete results; scanner cannot report "WAF/challenge encountered" as a limitation/NOT TESTED condition with evidence. |
| 3 | **No TLS certificate validity/observable TLS configuration assessment.** | `insecure` only toggles `requests.Session.verify` (`core/context.py`, `scanner.py`); no certificate chain/expiry/hostname/SAN/protocol/cipher inspection or reporting. HTTPS header checks (e.g. HSTS in `checks/headers.py`) depend on successful responses but do not assess TLS posture. | Mandatory capability "TLS certificate validity and observable configuration" is not implemented; HTTPS scans may fail opaquely on cert issues (or bypass validation with `--insecure`) without evidenced TLS findings/NOT TESTED reporting. |
| 4 | **No scan-mode separation (Passive Public Inspection vs Authorized Security Configuration Assessment).** | Single execution path always runs registered checks/modules with current probe behavior (`scanner.py` -> `run_all`, `checks/__init__`/discovery implied); `app.py`/CLI expose only permission/delay/timeout/insecure/compare controls. No mode flag to restrict to passive/low-impact observation set. | Cannot satisfy Mode A/Mode B design or enforce "minimal, low-impact requests" and "no intrusive tests" for passive public inspection while preserving existing authorized assessment behavior. |
| 5 | **Public/non-private targets are rejected without explicit permission by policy, but there is no supported passive-public mode for publicly observable inspection.** | `validate_url_target()`/`app.py`/CLI require `i_have_permission` for public/non-private targets and return authorization-gating errors; UI text states public targets require explicit authorization flag. This is **intentional safety behavior**, but combined with defect #4 it prevents legitimate passive public inspection workflows unless treated as authorized assessment. | Users cannot perform constrained, low-impact public observation scans without asserting full authorized-assessment permission; capability gap manifests as hard rejection in default mode. |

**Notes:** Phase 2 fixed localhost/IPv6 loopback handling, finding field serialization, and report separator (evidenced in `REAL_WORLD_COMPATIBILITY_REPORT.md`); these are not reclassified as current defects. No additional confirmed code defects were identified from this inspection pass without executed public-target evidence.

---

## 3. Missing capabilities

- **Passive Public Inspection mode (Mode A):** bounded, low-impact, publicly observable checks only (headers/cookies/redirects/TLS-observable info) with no intrusive probes.
- **Authorized Security Configuration Assessment mode (Mode B):** explicit mode distinction preserving current safe checks for explicitly authorized targets.
- **HTTP 429 / `Retry-After` detection and handling:** recognize throttling responses, capture evidence, avoid retry loops/bypass attempts, and report as limitation/NOT TESTED or warning as appropriate.
- **WAF/Cloudflare/challenge classification:** detect and report interstitial/challenge/managed-defense responses with evidence; avoid attributing them to origin misconfigurations.
- **TLS certificate and observable TLS configuration reporting:** certificate validity/chain/hostname match/expiry/issuer/SAN (where observable), and clear handling/reporting for verification failures and `--insecure` usage.
- **Public-website-safe request minimization controls:** configurable profile to disable/limit path probing, active CORS/method preflight probes, and other non-essential requests for passive observation.
- **Target-specific authorization/scope metadata for public scans:** explicit recording of scan mode/authorization context in results/reports (beyond current boolean) to distinguish passive inspection from authorized assessment.
- **Granular per-check NOT TESTED reasons for edge/WAF/rate-limit/TLS cases:** current runner marks NOT TESTED mainly for execution errors, cancellation, budget/connectivity, or missing modules; it does not classify defensive intermediaries or rate limiting.

---

## 4. Security risks

- **Misinterpretation risk (accuracy/integrity):** without WAF/challenge and 429/Retry-After classification, responses from CDNs, bot protections, or rate limiters may be misread, causing misleading findings, false negatives, or incomplete conclusions.
- **TLS assurance gap:** absence of certificate/TLS reporting can lead to false confidence in HTTPS posture or unclassified failures; `--insecure` bypasses verification without structured risk disclosure beyond current behavior.
- **Authorization/scope ambiguity:** no mode separation means public-target scans (when permitted) may run active probes intended for authorized assessments; conversely, legitimate passive inspection is blocked without asserting broader permission.
- **Operational blocking/rate-limit side effects:** current pipeline does not adapt/report on 429/Retry-After; repeated scans/probes against protected public endpoints could trigger defensive controls (scanner must not increase volume to bypass limits).
- **SSRF protections must remain intact during changes:** any future public-scan support must preserve DNS/IP revalidation, redirect validation, and blocks for metadata/link-local/reserved/multicast/unspecified/high-risk destinations (currently present and must not be removed).

---

## 5. Recommended changes (minimal, no implementation in this audit)

### 5.1 Introduce explicit scan modes (without redesigning UI or replacing architecture)
- Add a `scan_mode` parameter end-to-end (`CLI`, `app.py` API, `scanner.run_scan`, `ScanContext`/runner config) with two values:
  - **`passive_public` (Mode A):** accepts public `http/https` URLs only when an explicit "passive public inspection" confirmation is provided (separate from intrusive/authorized assessment intent). Execute minimal, low-impact requests (e.g. initial GET/HEAD as needed, follow validated redirects within strict cap, optional one-time OPTIONS/header fetch only if strictly non-intrusive by design) and inspect **publicly observable** headers, cookies, redirects, and TLS-observable metadata. **Do not run** intrusive/active checks: sensitive path probing (`checks/paths.py`), TRACE/CORS arbitrary-origin/null/preflight probing beyond passive observation, or other high-volume probes. Unsupported/inapplicable checks must return `NOT TESTED` with clear reasons.
  - **`authorized_assessment` (Mode B):** preserve existing safe configuration checks for explicitly authorized targets; keep current budgets/timeouts/redirect validation/SSRF protections. No exploitation/brute force/DoS/destructive requests.
- Record `scan_mode`, authorization flags, and effective limits in JSON/HTML/dashboard metadata for transparency.

### 5.2 Public-target handling and safety-preserving validation
- Keep `core/safety.py` SSRF protections and redirect revalidation unchanged in intent; continue blocking cloud metadata and dangerous internal destinations in all modes.
- Refine authorization policy to allow **Mode A** for public targets under passive-only constraints without requiring the same "authorized security assessment" assertion as Mode B, while still requiring explicit user confirmation/scope acknowledgment and enforcing strict rate/request/redirect caps.
- Do **not** automatically scan arbitrary public targets; require explicit user action/confirmation per scan.

### 5.3 HTTP client/response classification (low-risk additions)
- In `core/context.py` (and/or lightweight classification helpers), detect and surface:
  - **HTTP 429 / `Retry-After`:** record as scan limitation and/or per-check `NOT TESTED`/`WARNING` with observed evidence; **do not retry to bypass limits** and do not increase request volume.
  - **Likely WAF/CDN/challenge responses:** heuristic, evidence-based classification (status, headers like `cf-ray`, `server`, challenge markers/body signatures where safe/available) reported as "intermediary/challenge response observed; origin security posture NOT TESTED" — never as proof of origin vulnerability.
- Add bounded handling for non-HTML/error/challenge pages so checks do not fabricate findings.

### 5.4 TLS certificate/observable TLS checks (scoped)
- Add a non-intrusive TLS observation step/module for `https` targets (e.g. certificate validity/expiry/hostname, basic negotiated info available via stdlib/`ssl` where feasible) that:
  - reports evidenced findings/warnings for clear certificate issues in appropriate mode,
  - reports `NOT TESTED`/limitations when verification is disabled (`--insecure`) or when connection fails before observation,
  - never claims deep cipher/protocol audit beyond observed evidence.

### 5.5 Runner/reporting alignment
- Ensure `core/runner.py` and reports clearly propagate mode-specific `NOT TESTED` reasons (rate-limited, WAF/challenge, TLS-unverifiable, passive-mode excluded checks) and keep findings/risk score/dashboard/HTML/JSON consistent.
- Maintain backward compatibility for existing authorized local/lab workflows and current result schema where possible (additive fields).

### 5.6 Tests (future, when implementing; not executed now)
- Add/extend tests for: public-target permission/mode gating, redirect revalidation to blocked destinations, 429/Retry-After classification, WAF/challenge classification, TLS cert observation/error cases, and passive-mode probe suppression. Run existing suites after any change.

---

## 6. Test evidence

### 6.1 Executed in this environment (prior Phase 2, documented and verified in `REAL_WORLD_COMPATIBILITY_REPORT.md`)
- **Existing automated suites (unchanged):** 11/11 suites passed, 0 failed.
  - `python -m tests.test_headers` — PASS (`ALL HEADER TESTS PASSED!`)
  - `python -m tests.test_cookies` — PASS (`ALL COOKIE TESTS PASSED!`)
  - `python -m tests.test_paths` — PASS (`[PHASE 2 RESULT: PASS]`)
  - `python -m tests.test_info_leaks` — PASS (`ALL INFO LEAKS TESTS PASSED!`)
  - `python -m tests.test_methods` — PASS (`ALL METHOD TESTS PASSED!`)
  - `python -m tests.test_cors` — PASS (`ALL CORS TESTS PASSED!`)
  - `python -m tests.test_cors_methods` — PASS (`[PHASE 3 RESULT: PASS]`)
  - `python -m tests.test_compare` — PASS (`[PHASE 6 RESULT: PASS]`)
  - `python -m tests.test_accuracy` — PASS (`[PHASE 4 RESULT: PASS]`)
  - `python -m tests.test_report` — PASS (**11/11**, `ALL 11 HTML REPORT TESTS PASSED SUCCESSFULLY! (EXIT 0)`)
  - `python tests/test_webapp.py` — PASS (**8/8**, `Ran 8 tests ... OK`)
- **Compile checks (post Phase 2 fixes):** `python -m py_compile core/safety.py core/models.py scanner.py app.py core/context.py core/runner.py core/scoring.py checks/headers.py checks/cookies.py checks/cors.py checks/methods.py checks/info_leaks.py checks/paths.py reports/html_report.py` — PASS.
- **Controlled local integration/e2e audits (temporary scripts, local `http.server` + Flask `test_client`):**
  - `_rw_compat_audit.py`: **29 passed, 1 failed** (single harness artifact: default `BaseHTTP/0.6 Python/...` `Server` header triggered `INF-001` on secure fixture; not scanner logic).
  - `_rw_audit_quick.py`: **4 passed, 2 failed** (script bug + pre-fix localhost case; not used as product evidence).
  - `_rw_final_check.py` (corrected): **25 passed, 0 failed** (`RWF_EXIT:0`) covering local validation/safety, secure/misconfigured HTTP, redirect/status/malformed headers, **local self-signed HTTPS with `insecure=True`**, independence/freshness, unreachable/timeout, dashboard/HTML/JSON route consistency, and cancellation.

### 6.2 Executed in this Phase 3 audit
- **Static/behavioral inspection only:** source review of safety, context/request pipeline, runner/checks, scoring, scanner/app interfaces, and report generation. Targeted code searches confirmed absence of `429`/`Retry-After` handling and WAF/Cloudflare/challenge classification in inspected modules.
- **Ad-hoc safety probe (local, non-scanning):** `core.safety.validate_url_target('http://localhost', False)` returned `ok=True` with resolved `['::1','127.0.0.1']` in this environment (consistent with Phase 2 fix). *(No public targets contacted.)*

### 6.3 Not executed (important)
- **No authorized public-target scans/tests.**
- **No Cloudflare/WAF/challenge, public rate-limiting (`429`/`Retry-After`), or public CA-trusted HTTPS compatibility tests.**
- **No browser/UI interactive automation.**

---

## 7. Remaining limitations

- **Public website compatibility unverified:** no evidence from authorized public targets; compatibility with real-world public servers, CDNs/WAFs, bot protections, and internet conditions must not be claimed.
- **Mode A / Mode B not implemented:** passive public inspection and authorized assessment are not separated; public targets are policy-gated by explicit permission without a passive-only mode.
- **No 429/Retry-After handling:** rate-limited responses cannot be reliably classified/reported and must not be bypassed.
- **No WAF/Cloudflare/challenge classification:** intermediary defenses may confound observations; origin-vs-edge attribution is unsupported.
- **TLS assessment incomplete:** no certificate validity/observable TLS configuration reporting; HTTPS checks are limited to response-level observations and connection success/failure under current verification settings.
- **Bounded/non-exhaustive checks:** same-origin limited discovery, request budgets/timeouts, and check-specific probe coverage apply; response-observable, non-destructive checks only.
- **No authenticated/stateful scanning:** login flows and protected areas not covered.
- **Existing local-lab evidence does not generalize:** controlled `http.server` and local self-signed HTTPS results do not represent public CA chains, diverse hosting stacks, or defensive edge behavior.
- **Any future implementation must preserve safety controls:** SSRF protections, per-redirect destination validation, blocks for cloud-metadata/dangerous internal destinations, explicit authorization/scope confirmation, and conservative request volume. No exploitation, brute force, DoS, or destructive requests.