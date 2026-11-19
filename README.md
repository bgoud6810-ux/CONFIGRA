# Automated Security Misconfiguration Detector

> **A high-precision, non-destructive security misconfiguration scanner and reporting tool designed for authorized web applications.** Features differential baseline analysis to eliminate false positives on Single Page Applications (SPAs), plug-in check architecture, before-and-after re-scan comparisons, and standalone cyber-themed HTML security reports.

---

## 📋 Table of Contents
1. [Project Overview & Purpose](#-project-overview--purpose)
2. [Core Architecture & Workflow](#-core-architecture--workflow)
3. [The Six Detection Modules](#-the-six-detection-modules)
4. [Differential Baseline & Accuracy Approach](#-differential-baseline--accuracy-approach)
5. [Risk Scoring & Grading System](#-risk-scoring--grading-system)
6. [Scan Comparison Engine (Before & After)](#-scan-comparison-engine-before--after)
7. [Safety Guardrails & Ethical Scope](#-safety-guardrails--ethical-scope)
8. [Installation & Windows Setup](#-installation--windows-setup)
9. [CLI Usage & Argument Reference](#-cli-usage--argument-reference)
10. [Reports: HTML & JSON Formats](#-reports-html--json-formats)
11. [Running the Test Suites](#-running-the-test-suites)
12. [Troubleshooting](#-troubleshooting)
13. [Limitations & Ethical Notice](#-limitations--ethical-notice)

---

## 🎯 Project Overview & Purpose

Web application misconfigurations represent one of the most common and dangerous vulnerability classes in modern systems (**OWASP Top 10 - A05:2021 Security Misconfiguration**). Unintended debug banners, missing security headers, insecure session cookies, permissive CORS policies, and exposed administrative files frequently allow attackers to execute clickjacking, session hijacking, cross-site scripting (XSS), cross-origin data theft, or system takeover.

Most commercial security scanners suffer from two major flaws:
1. **Aggressive, Destructive Probes**: Dispatching heavy payloads and destructive HTTP methods (`PUT`, `DELETE`) that can corrupt test environments or knock servers offline.
2. **High False-Positive Rates on Modern SPAs**: Modern Single Page Applications (React, Vue, Angular) and catch-all servers return `HTTP 200 OK` with the home page HTML for *any* requested path. Traditional scanners blindly report every probed path (such as `/.env` or `/admin`) as exposed, flooding reports with false alarms.

### Solution
The **Automated Security Misconfiguration Detector** solves these challenges by combining:
- **Strictly Non-Destructive Probes**: Passive header inspection and safe, read-only requests (`GET`, `HEAD`, `OPTIONS`, and non-destructive `TRACE`).
- **Differential Baseline Analysis**: Dynamically probes a randomized canary path (`/zz-{random8}`) to establish a baseline status code, body length, and content hash, eliminating catch-all false positives.
- **Deep Value Inspection**: Checks actual header directives and token values rather than simple header presence (e.g., verifying `max-age` in HSTS, tokenized CSP directives, and SameSite/Secure cookie combinations).
- **Executive & Developer Reports**: Outputs actionable terminal summaries, structured JSON results, and self-contained, offline-compatible cyber-themed HTML reports with remediation guidance.
- **Before-and-After Remediation Tracking**: Automatically tracks fixed, still-open, and newly introduced issues between scans using `--compare`.

---

## 🏗️ Core Architecture & Workflow

The scanner follows a modular, pluggable architecture where the core engine manages HTTP communications, safety controls, and multi-page discovery, while individual detection modules focus exclusively on vulnerability logic.

```
                          +-------------------------+
                          |   CLI / User Input      |
                          | (scanner.py [arguments])|
                          +------------+------------+
                                       |
                                       v
                    +-------------------------------------+
                    | Safety Scope Check                  |
                    | (Localhost / Private RFC1918 check) |
                    +------------------+------------------+
                                       | Valid Target
                                       v
                    +-------------------------------------+
                    | ScanContext Initialization          |
                    | - Fetch Home Page (HTTP GET)        |
                    | - Discover Linked Subpages (max 3)  |
                    | - Polite Rate Limiting & Budget     |
                    +------------------+------------------+
                                       |
                                       v
                    +-------------------------------------+
                    | Plug-in Check Runner (run_all)      |
                    | Dynamically loads checks/*.py       |
                    | Runs checks in isolated try/except  |
                    +------------------+------------------+
                                       |
        +-------------+-------------+--+-----------+-------------+-------------+
        |             |             |              |             |             |
        v             v             v              v             v             v
  +-----------+ +-----------+ +-----------+  +-----------+ +-----------+ +-----------+
  |  headers  | |  cookies  | |   cors    |  |  methods  | |info_leaks | |   paths   |
  +-----+-----+ +-----+-----+ +-----+-----+  +-----+-----+ +-----+-----+ +-----+-----+
        |             |             |              |             |             |
        +-------------+-------------+--+-----------+-------------+-------------+
                                       | Raw Findings & Passed Checks
                                       v
                    +-------------------------------------+
                    | Finding Deduplication & Aggregator  |
                    | Merges duplicate IDs & URLs         |
                    +------------------+------------------+
                                       |
                                       v
                    +-------------------------------------+
                    | Scoring Engine (core/scoring.py)    |
                    | Calculates Score (0-100) & Grade A-F|
                    +------------------+------------------+
                                       |
                 +---------------------+---------------------+
                 |                                           |
                 v (if --compare)                            v
  +-------------------------------+           +-------------------------------+
  | Re-Scan Comparison Engine     |           | Report Generation             |
  | - Fixed Findings              |           | - Terminal Summary Table      |
  | - Still Open Findings         |           | - JSON Results (results.json) |
  | - New Findings                |           | - Cyber HTML (report.html)    |
  | - Score & Grade Delta         |           +-------------------------------+
  +-------------------------------+
```

### Request-Response Life Cycle
1. **Safety Verification**: Checks hostname resolution against loopback and RFC 1918 addresses before dispatching requests.
2. **Context Setup (`core/context.py`)**: Initializes `ScanContext` with custom User-Agent, max redirect limit (3), timeout (`10s`), request budget (cap 60), and polite delay (`0.3s`).
3. **Crawl & Discovery**: Fetches the base URL and passively extracts up to 3 internal same-origin links to ensure crawled subpages are analyzed alongside the home page.
4. **Execution & Isolation (`core/runner.py`)**: Dynamically invokes each check module's `run(ctx)` interface inside dedicated `try/except` wrappers so an error in one check cannot abort the scan.
5. **Deduplication**: Merges multi-page evidence and endpoints into unified finding instances.
6. **Scoring & Report Delivery**: Computes score and grade, generates JSON output, and renders the self-contained HTML report.

---

## 🔍 The Six Detection Modules

All detection modules reside in the `checks/` directory and implement the standard `run(ctx: ScanContext) -> Tuple[List[Finding], List[str]]` signature.

### 1. HTTP Security Headers (`checks/headers.py`)
Evaluates defensive response headers across all crawled pages using deep value parsing:
- `HDR-001` (**High**, *Confirmed*): **Missing X-Frame-Options / Clickjacking Protection**. Flags missing `X-Frame-Options` and verifies CSP `frame-ancestors` directive.
- `HDR-002` (**Medium**, *Confirmed*): **Missing or Weak HSTS**. Flags missing `Strict-Transport-Security` on HTTPS connections, or weak configurations (e.g., `max-age=0`).
- `HDR-003` (**Medium**, *Confirmed*): **Missing Content Security Policy (CSP)**. Flags endpoints completely lacking CSP.
- `HDR-004` (**Medium**, *Confirmed*): **Weak Content Security Policy**. Inspects directive tokens for unsafe keywords (`unsafe-inline`, `unsafe-eval`, or bare `*` wildcards).
- `HDR-005` (**Low**, *Confirmed*): **CSP Report-Only Mode**. Detects CSP deployed in advisory reporting mode rather than enforcing restrictions.
- `HDR-006` (**Low**, *Confirmed*): **Missing X-Content-Type-Options**. Flags missing `nosniff` MIME-type sniffing protection.
- `HDR-007` (**Low**, *Confirmed*): **Missing or Insecure Referrer-Policy**. Detects missing policy or leaky policies (`unsafe-url`, `no-referrer-when-downgrade`).
- `HDR-008` (**Low**, *Confirmed*): **Missing Permissions-Policy**. Flags missing restriction controls for browser features (camera, microphone, geolocation).

### 2. Cookie Security (`checks/cookies.py`)
Analyzes all `Set-Cookie` headers returned across crawled endpoints:
- `CKE-001` (**High**, *Confirmed*): **Session Cookie Missing HttpOnly**. Identifies authentication/session tokens (e.g., `session`, `token`, `auth`, `sid`, `connect.sid`) lacking `HttpOnly`, exposing them to JavaScript XSS theft.
- `CKE-002` (**Low**, *Confirmed*): **Non-Sensitive Cookie Missing HttpOnly**. Flags non-session tracking or preference cookies lacking `HttpOnly`.
- `CKE-003` (**Medium**, *Confirmed*): **Cookie Missing Secure Flag**. Flags cookies transmitted over HTTPS without the `Secure` attribute.
- `CKE-004` (**Low**, *Confirmed*): **Cookie Missing SameSite Attribute**. Flags cookies vulnerable to cross-site request forgery (CSRF) without explicit `SameSite` flags.
- `CKE-005` (**Medium**, *Confirmed*): **SameSite=None Without Secure Attribute**. Flags illegal and insecure third-party cookie configurations.
- `CKE-006` (**Low**, *Confirmed*): **Cookie Prefix Violation**. Detects cookies using `__Host-` or `__Secure-` prefixes that fail to enforce required `Secure` and `Path=/` flags.

### 3. Cross-Origin Resource Sharing (`checks/cors.py`)
Performs passive header inspection and non-destructive active CORS probing (`Origin: https://evil.com`, `Origin: null`):
- `COR-001` (**High**, *Confirmed*): **Arbitrary Origin Reflection with Credentials**. Target reflects attacker origin and enables `Access-Control-Allow-Credentials: true`, permitting cross-origin credentialed data theft.
- `COR-002` (**Medium**, *Confirmed*): **Arbitrary Origin Reflection Without Credentials**. Target reflects unvalidated origins without credentials.
- `COR-003` (**High**, *Confirmed*): **Wildcard Origin (`*`) with Credentials**. Insecure or malformed CORS policy combining wildcards with credential access.
- `COR-004` (**Low**, *Confirmed*): **Wildcard Origin Without Credentials**. Target exposes resources globally via `Access-Control-Allow-Origin: *`.
- `COR-005` (**High**, *Confirmed*): **Null Origin Reflection with Credentials**. Server accepts `Origin: null` (triggerable from sandboxed iframes or local files) with credentials enabled.
- `COR-006` (**Medium**, *Confirmed*): **Null Origin Reflection Without Credentials**. Server reflects `Origin: null` without credentials.
- `COR-007` (**Low**, *Confirmed*): **Malformed / Comma-Separated Origins**. Flags invalid CORS headers with multiple space- or comma-separated origins.
- `COR-008` (**Low**, *Confirmed*): **Insecure Preflight CORS Configuration**. Detects excessively permissive `Access-Control-Allow-Methods` or caching directives.

### 4. HTTP Methods Configuration (`checks/methods.py`)
Inspects advertised methods in `OPTIONS` / `Allow` headers and safely verifies dangerous method handling:
- `MTH-001` (**Medium**, *Confirmed*): **Active TRACE Method Allowed (XST Risk)**. Dispatches a harmless `TRACE` probe with a benign header; flags when the request is echoed in the response body.
- `MTH-002` (**Low**, *Likely*): **PUT / DELETE Advertised in Allow Header**. Identifies modifying methods advertised in the `Allow` header without executing destructive requests.
- `MTH-003` (**Low**, *Likely*): **Extended Dangerous Methods Advertised**. Detects WebDAV and tunneling verbs (`CONNECT`, `PROPFIND`, `LOCK`) advertised in `Allow`.
- `MTH-004` (**Low**, *Likely*): **Inconsistent HTTP Method Configuration**. Identifies method configurations that differ between the home page and crawled subpages.

### 5. Information Disclosure (`checks/info_leaks.py`)
Passively searches HTTP response headers and body content for leaked diagnostic information:
- `INF-001` (**Low**, *Confirmed*): **Server Version Disclosure**. Flags software version numbers exposed in the `Server` header (e.g., `Apache/2.4.41`, `nginx/1.18.0`). Generic banners without versions (`Apache`, `nginx`) are safely passed.
- `INF-002` (**Low**, *Confirmed*): **Technology Banner Disclosure**. Flags runtime disclosures in `X-Powered-By` (e.g., `Express`, `PHP/8.1.0`).
- `INF-003` (**Low**, *Confirmed*): **ASP.NET Version Disclosure**. Detects `X-AspNet-Version` headers.
- `INF-004` (**Low**, *Confirmed*): **ASP.NET MVC Version Disclosure**. Detects `X-AspNetMvc-Version` headers.
- `INF-005` (**Low**, *Confirmed*): **Internal Hostname / IP Disclosure**. Detects RFC 1918 private IPs or internal server hostnames leaked in headers.
- `INF-006` (**Info**, *Confirmed*): **Infrastructure / Diagnostic Header Disclosure**. Detects reverse-proxy, CDN, or cache headers (`X-Backend-Server`, `X-Cache-Hits`).
- `INF-007` (**Low**, *Confirmed*): **Debug / Diagnostic Headers Active**. Identifies active development headers (`X-Debug-Token`, `X-Profiling`).
- `INF-008` (**Medium**, *Confirmed*): **Stack Trace / Unhandled Exception Leaked**. Detects multiline stack traces (Python, Java, PHP, Node.js) exposed in response bodies. Automatically sanitizes and redacts passwords, tokens, and secrets from evidence.

### 6. Sensitive Files & Directory Browsing (`checks/paths.py`)
Inspects 24 high-risk files and directory listing vectors using content-based signatures and differential baselines:
- **Exposed Sensitive Files (`PTH-001` through `PTH-024`)**:
  - *Version Control*: `/.git/HEAD`, `/.git/config`, `/.git/index` (verifies `DIRC` binary header)
  - *Configuration & Secrets*: `/.env`, `/web.config`, `/.htaccess`
  - *IDE & Editor Configurations*: `/.vscode/sftp.json`, `/.idea/workspace.xml`
  - *Database & Backup Archives*: `/dump.sql`, `/backup.sql`, `/backup.tar.gz` (verifies gzip magic bytes `\x1f\x8b`), `/backup.zip` (verifies PK zip magic bytes)
  - *API & Documentation*: `/swagger.json`, `/swagger/v1/swagger.json`, `/openapi.json`, `/api-docs`
  - *Actuators & Diagnostics*: `/actuator`, `/actuator/health`, `/actuator/env`, `/phpinfo.php`, `/server-status`
  - *Metadata & Crawler Directives*: `/.DS_Store`, `/robots.txt`, `/metrics`
- **Structural Directory Listing Detection (`PTH-009`)**:
  - Probes `/`, `/ftp`, `/images`, `/assets`, `/uploads`.
  - Analyzes HTML structural tags (`<title>Index of`, `<h1>Index of`, `<a href="...">Parent Directory</a>`) rather than plain text to avoid false positives on normal article prose.
- **Safe 401 / 403 Handling**:
  - Endpoints returning HTTP 401 or 403 are treated as protected resources and recorded under `passed_checks`, not as vulnerabilities.

---

## 🎯 Differential Baseline & Accuracy Approach

Traditional scanners flag paths based purely on `HTTP 200 OK`. However, modern Single Page Applications (e.g., OWASP Juice Shop, Angular/React applications) use catch-all routing where **every requested path returns HTTP 200 with the application home page HTML**.

### How Our Differential Baseline Works
1. Before checking sensitive files, the scanner requests a randomized canary path:
   ```
   GET /zz-a1b2c3d4
   ```
2. The scanner records the baseline response:
   - Status code
   - Response body byte length
   - Response body SHA-256 hash
3. When testing a sensitive path (e.g., `/.env` or `/dump.sql`):
   - If the response matches the baseline body length (within ±50 bytes) or has an identical SHA-256 hash, **the path is recognized as a catch-all route and discarded**.
   - If the response differs from the baseline, the scanner applies **strict content signature matching** (e.g., checking for `ref: refs/heads` in `.git/HEAD`, `DIRC` binary header in `.git/index`, or gzip magic bytes `\x1f\x8b` in `/backup.tar.gz`).
   - A finding is reported **only** when both differential comparison and signature validation succeed.

---

## 📊 Risk Scoring & Grading System

The scoring engine (`core/scoring.py`) calculates an overall security score (0 to 100) and letter grade (A through F).

### Severity Penalties
Every scan starts at **100 points**. Penalties are deducted based on finding severity:

| Severity | Penalty | Description |
| :--- | :---: | :--- |
| **Critical** | **-25 pts** | Direct compromise vector (e.g., exposed `.env` file, database dump) |
| **High** | **-15 pts** | High exploitability (e.g., Session cookie missing HttpOnly, credentialed CORS reflection) |
| **Medium** | **-8 pts** | Security deficiency (e.g., Missing HSTS, missing CSP, active TRACE method) |
| **Low** | **-3 pts** | Hardening misconfiguration (e.g., Server banner version disclosure, missing X-Content-Type-Options) |
| **Info** | **0 pts** | Informational observation (e.g., Diagnostic cache headers) |

### Confidence Weighting
Findings include an explicit confidence level:
- **Confirmed**: Directly verified with definitive proof. Incurs **100%** of the severity penalty.
- **Likely**: Strong indicator requiring manual verification (e.g., modifying methods advertised in `Allow` header). Incurs **50%** of the severity penalty.

### Grade Boundaries

$$\text{Final Score} = \max\left(0, \; 100 - \sum \text{Penalties}\right)$$

| Letter Grade | Score Range | Status Indicator | Padlock Visual in Report |
| :---: | :---: | :--- | :--- |
| **A** | **90 – 100** | Excellent security posture | Closed Green Padlock |
| **B** | **75 – 89** | Good posture; minor hardening recommended | Closed Green Padlock |
| **C** | **60 – 74** | Moderate risk; multiple misconfigurations | Closed Orange Padlock |
| **D** | **40 – 59** | High risk; serious vulnerabilities present | Open Red Padlock |
| **F** | **0 – 39** | Critical failure; immediate remediation required | Open Pulsing Red Padlock |

---

## 🔄 Scan Comparison Engine (Before & After)

When remediating security issues, teams need to verify fixes without re-auditing existing findings manually. The detector provides automated before-and-after re-scan comparisons via `--compare`.

```powershell
python scanner.py http://localhost:3000 --compare output/initial_scan.json --out output/re_scan.html
```

### Finding Categorization
The comparison engine inspects the previous scan's JSON data and partitions findings into three distinct states:
1. **Fixed**: Present in the previous scan but no longer detected in the current scan.
2. **Still Open**: Present in both scans.
3. **New**: Newly introduced misconfiguration not present in the earlier scan.

### Resource-Aware Stable Keys
To prevent false "Fixed" or "New" churn when page crawl orders or URLs change:
- **Target-wide checks** (Headers, CORS, Methods, Info Leaks) compare using finding IDs (e.g., `HDR-001`).
- **Cookie checks** isolate cookie names so that fixing `session` while leaving `tracking` open reports accurately.
- **Path checks** isolate normalized paths so that resolving `/.env` while `/robots.txt` remains open does not conflate findings.
- **Multi-page findings** normalize comma-separated URLs so discovering a finding on an additional subpage does not mark the original finding as Fixed.

---

## 🛡️ Safety Guardrails & Ethical Scope

1. **URL validation and controlled targets**: Accepts valid `http://`/`https://` targets only. Targets are normalized, DNS-resolved, and validated before requests; every redirect destination is revalidated.
2. **SSRF and rebinding protections**: Blocks link-local, reserved, multicast, unspecified, and cloud-metadata destinations. Re-resolves hostnames during request/redirect handling to reduce DNS rebinding risk. Public/non-private targets require explicit authorization confirmation (`--i-have-permission` in CLI, permission checkbox in web UI).
3. **Safe local-lab support**: Loopback and private RFC1918 targets remain usable for local testing; authorized scans are still subject to destination safety checks.
4. **Non-destructive, rate-limited scanning**: No exploitation, brute force, credential/auth bypass attempts, destructive requests, intrusive port scanning, or intentional DoS behavior. Uses conservative timeouts, redirect caps, request budgets, and polite delays.
5. **Cancellation and resilience**: Scans can be cancelled cooperatively (web UI). Connection/validation failures are reported clearly; checks that cannot run are marked **NOT TESTED** rather than producing false findings. No sample/hardcoded findings are returned on failure.

---

## 💻 Installation & Windows Setup

### Prerequisites
- **Python 3.10+** (Python 3.11, 3.12, or 3.13 supported)
- **Windows PowerShell** or Command Prompt

### Step 1: Clone or Navigate to the Workspace
```powershell
cd "C:\path\to\cyber-spl-project"
```

### Step 2: Create and Activate Virtual Environment (Recommended)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
The scanner relies strictly on two standard, well-maintained libraries:
```powershell
pip install -r requirements.txt
```
*(Dependencies: `requests>=2.28.0`, `jinja2>=3.1.0`)*

---

## Interactive Web Interface (CONFIGRA)

The Flask application has **exactly two user-facing pages** and preserves the CONFIGRA black/charcoal/crimson-red/neon-pink visual identity:

- **Page 1: Scanner** — `/` or `/scan`
  - Target URL input, quick presets, advanced configuration, and explicit authorization confirmation for public/non-private targets.
  - Live scan status/progress polling with cancellation support and clear error feedback.
  - Automatic navigation to results when a scan completes (or shows available results if cancelled).
- **Page 2: Results Dashboard** — `/results/<scan_id>`
  - Real per-scan score/grade/counts, findings with evidence/endpoint/remediation, passed checks, per-check results, checks not performed, and scan limitations.
  - Links to standalone HTML report and JSON report for the same scan ID (no stale/sample data reused).

### Launching the Web Application
```powershell
python app.py
```
Open: **`http://127.0.0.1:5000`**

### Scan flow
1. Enter a valid `http://` or `https://` target URL.
2. For public/non-private targets, enable the authorization/permission checkbox (explicit confirmation required).
3. Start scan, monitor live progress (or cancel cooperatively).
4. Review dashboard and download/view the HTML/JSON reports generated for that specific scan.

---

### Syntax
```powershell
python scanner.py <url> [options]
```

### Positional Arguments
- `url`: Target URL to scan (e.g., `http://localhost:3000` or `http://localhost:8000`). If the protocol scheme is omitted, `http://` is assumed.

### Optional Arguments
| Argument | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--out` | string | `output/report.html` | Destination filepath for the generated self-contained HTML report |
| `--json` | string | `output/results.json` | Destination filepath for structured JSON scan results |
| `--compare` | string | `None` | Path to a previous `results.json` to compute diffs (Fixed, Still Open, New) |
| `--delay` | float | `0.3` | Polite delay in seconds between consecutive HTTP requests |
| `--timeout` | float | `10.0` | Network request timeout in seconds |
| `--insecure` | flag | `False` | Disable TLS/SSL certificate verification (useful for self-signed test certs) |
| `--i-have-permission` | flag | `False` | Acknowledge legal authorization to scan public/external IP targets |

### Example Commands

#### 1. Basic Local Scan
```powershell
python scanner.py http://localhost:3000
```

#### 2. Custom Output Locations
```powershell
python scanner.py http://localhost:3000 --out output/scan_v1.html --json output/scan_v1.json
```

#### 3. Tuning Request Delay and Timeout
```powershell
python scanner.py http://localhost:3000 --delay 0.5 --timeout 15.0
```

#### 4. Scanning an Authorized Self-Signed HTTPS Target
```powershell
python scanner.py https://localhost:8443 --insecure
```

#### 5. Re-Scan Comparison Against Baseline
```powershell
python scanner.py http://localhost:3000 --compare output/scan_v1.json --out output/scan_v2.html --json output/scan_v2.json
```

---

## 📑 Reports: HTML & JSON Formats

### 1. Cyber Dark HTML Report (`output/report.html`)
The HTML report is a standalone, single-file document featuring a cyber dark aesthetic:
- **Interactive Hero Row**: Circular SVG grade ring showing letter grade (A–F) and score (0–100) alongside a dynamic glowing status padlock (Green for A/B, Orange for C, Red for D/F).
- **Severity Tiles Grid**: Summary cards with counts for Critical, High, Medium, Low, and Info findings.
- **Detailed Findings List**: Each finding row features:
  - Severity badge and confidence tag (`CONFIRMED` / `LIKELY`)
  - Finding title, category, and unique finding ID (`data-id`)
  - Observed evidence and affected endpoint URL
  - High-visibility green remediation box detailing exact configuration fixes
- **Changes Since Last Scan Panel**: When `--compare` is used, renders score deltas, grade changes, stat badges (Fixed, Still Open, New), and lists resolved misconfigurations.
- **Passed Checks Grid**: Lists all verified configurations that were inspected and determined to be secure.
- **100% Offline Independence**: Contains zero external fonts, stylesheet links, or CDN scripts. All vector artwork and icons are embedded inline SVGs. Safe for air-gapped security audits.
- **Hardened XSS Protection**: All user-controlled fields, URLs, and proof evidence are strictly autoescaped by Jinja2 with zero raw HTML execution.

### 2. Structured JSON Results (`output/results.json`)
Ideal for CI/CD pipeline integration, security dashboards, and SIEM consumption:
```json
{
  "scanner_version": "1.0.0",
  "target": "http://localhost:3000",
  "target_ip": "127.0.0.1",
  "scan_started_at": "2026-11-17T15:40:00.123456+05:30",
  "scan_completed_at": "2026-11-17T15:40:02.789012+05:30",
  "duration_seconds": 2.67,
  "scan_time": "Nov 17, 2026 15:40:02",
  "grade": "F",
  "score": 18,
  "counts": {
    "Critical": 1,
    "High": 3,
    "Medium": 4,
    "Low": 6,
    "Info": 0
  },
  "findings": [
    {
      "id": "HDR-001",
      "title": "Missing X-Frame-Options",
      "category": "headers",
      "severity": "High",
      "evidence": "X-Frame-Options header not present",
      "fix": "Add X-Frame-Options: DENY or SAMEORIGIN in your web server configuration",
      "confidence": "Confirmed",
      "url": "http://localhost:3000/"
    }
  ],
  "passed_checks": [
    "X-Content-Type-Options present",
    "No directory listing on /"
  ],
  "errors": []
}
```

---

## 🧪 Running the Test Suites

The project features 10 test suites covering unit tests, false-positive resistance, integration checks, and end-to-end scanner accuracy.

### Master Regression Test Commands
Run each command from the project root:

```powershell
# 1. HTTP Security Headers
python -m tests.test_headers

# 2. Cookie Security & Prefixes
python -m tests.test_cookies

# 3. Cross-Origin Resource Sharing (CORS)
python -m tests.test_cors

# 4. HTTP Methods & TRACE Handling
python -m tests.test_methods

# 5. Information Disclosure & Stack Traces
python -m tests.test_info_leaks

# 6. Sensitive Paths & Differential Baseline
python -m tests.test_paths

# 7. CORS & Methods Integration
python -m tests.test_cors_methods

# 8. Re-Scan Comparison & JSON Metadata
python -m tests.test_compare

# 9. Control Server Scanner Accuracy Verification
python -m tests.test_accuracy

# 10. HTML Report Generation & XSS Hardening
python -m tests.test_report

# 11. CONFIGRA Flask Web Interface (Page 1 & Page 2)
python tests/test_webapp.py
```

### Test Suite Summary

| Test Module | Coverage | Expected Result |
| :--- | :--- | :---: |
| `tests/test_headers.py` | Tokenized CSP, HSTS max-age=0, Clickjacking, Referrers, Permissions | **5/5 PASS** |
| `tests/test_cookies.py` | Session cookie identification, SameSite=None, prefixes (`__Host-`) | **6/6 PASS** |
| `tests/test_cors.py` | Arbitrary origins, credentials, null origins, comma-separated lists | **7/7 PASS** |
| `tests/test_methods.py` | Active TRACE probe, Allow parsing without substring false positives | **6/6 PASS** |
| `tests/test_info_leaks.py` | Server versions, X-Powered-By, ASP.NET, stack traces, secret redaction | **7/7 PASS** |
| `tests/test_paths.py` | 24 sensitive files, binary magic bytes, structural directory listings | **3/3 PASS** |
| `tests/test_cors_methods.py`| Cross-check integration of CORS and HTTP methods | **4/4 PASS** |
| `tests/test_compare.py` | Resource-aware comparison keys, multi-page URL stability, JSON schema | **6/6 PASS** |
| `tests/test_accuracy.py` | End-to-end scanner test against vulnerable and hardened control servers | **3/3 PASS** |
| `tests/test_report.py` | Jinja2 autoescaping/XSS, severity ordering, offline assets, empty scans | **11/11 PASS** |
| `tests/test_webapp.py` | Two-page interface, background runner, progress polling, report downloads | **7/7 PASS** |

---

## 🔧 Troubleshooting

### 1. "Target is unreachable or failed to respond"
- **Cause**: Target web server is not running or port is blocked by a firewall.
- **Remedy**: Verify the service is active using `curl` or browser (`http://localhost:3000`). Confirm the port number.

### 2. "Refused: Target resolves to a non-private IP address"
- **Cause**: The safety guardrail blocked a public or external domain.
- **Remedy**: Scans against non-local targets require explicit authorization. Pass `--i-have-permission` if you are authorized to test the target.

### 3. "Request budget limit reached"
- **Cause**: The target has extensive links and reached the 60-request safety ceiling.
- **Remedy**: The safety ceiling prevents denial-of-service conditions. Scans prioritize high-impact checks before the budget is exhausted.

### 4. PowerShell Script Execution Restrictions
- **Cause**: Windows PowerShell execution policy blocks `Activate.ps1`.
- **Remedy**: Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` or execute Python directly via `python scanner.py ...`.

---

## ⚠️ Limitations & Ethical Notice

### Limitations
1. **Not a complete penetration test**: This tool performs non-destructive security misconfiguration checks only. It does not claim full security coverage, exploit vulnerabilities, bypass authentication, brute-force credentials, or perform intrusive port/service enumeration.
2. **Black-box HTTP/HTTPS observations**: Checks are based on live HTTP(S) responses (headers, cookies, redirects/status/metadata, safe probes, and limited path/method/CORS observations). It does not perform SAST, access internal systems/databases/filesystems, or perform deep TLS/certificate/cipher analysis beyond basic HTTPS reachability and observable response behavior.
3. **Safety constraints affect coverage**: Request budgets, timeouts, redirect limits, polite delays, DNS/redirect revalidation, and SSRF protections (blocking link-local/reserved/multicast/unspecified/cloud-metadata destinations) can limit what is tested. Checks that cannot be completed are reported as **NOT TESTED** with reasons/limitations.
4. **Result interpretation**: Findings require evidence and context. A scan with no findings (or a high grade) does **not** guarantee the target is secure or free of other vulnerabilities/misconfigurations.

### Ethical Testing Notice
This tool is for **authorized** educational, defensive, and diagnostic testing only.
- Scan only systems you own or have explicit, documented permission to test.
- Public/non-private targets require explicit authorization confirmation in the UI/CLI flow.
- Unauthorized testing may be illegal and unethical. Use responsibly and within approved scope.