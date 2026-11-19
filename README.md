# Automated Security Misconfiguration Detector

> **A high-precision, non-destructive security misconfiguration scanner and reporting tool designed for authorized web applications.** 
## 🎯 Project Overview 
Web application misconfigurations represent one of the most common and dangerous vulnerability classes in modern systems (**OWASP Top 10 - A05:2021 Security Misconfiguration**). Unintended debug banners, missing security headers, insecure session cookies, permissive CORS policies, and exposed administrative files frequently allow attackers to execute clickjacking, session hijacking, cross-site scripting (XSS), cross-origin data theft, or system takeover.



### Solution
The **Automated Security Misconfiguration Detector** solves these challenges by combining:
- **Strictly Non-Destructive Probes**: Passive header inspection and safe, read-only requests (`GET`, `HEAD`, `OPTIONS`, and non-destructive `TRACE`).
- **Differential Baseline Analysis**: Dynamically probes a randomized canary path (`/zz-{random8}`) to establish a baseline status code, body length, and content hash, eliminating catch-all false positives.
- **Deep Value Inspection**: Checks actual header directives and token values rather than simple header presence (e.g., verifying `max-age` in HSTS, tokenized CSP directives, and SameSite/Secure cookie combinations).
- **Executive & Developer Reports**: Outputs actionable terminal summaries, structured JSON results, and self-contained, offline-compatible cyber-themed HTML reports with remediation guidance.
- **Before-and-After Remediation Tracking**: Automatically tracks fixed, still-open, and newly introduced issues between scans using `--compare`.
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

### Grade Boundaries

$$\text{Final Score} = \max\left(0, \; 100 - \sum \text{Penalties}\right)$$

| Letter Grade | Score Range | Status Indicator | Padlock Visual in Report |
| :---: | :---: | :--- | :--- |
| **A** | **90 – 100** | Excellent security posture | Closed Green Padlock |
| **B** | **75 – 89** | Good posture; minor hardening recommended | Closed Green Padlock |
| **C** | **60 – 74** | Moderate risk; multiple misconfigurations | Closed Orange Padlock |
| **D** | **40 – 59** | High risk; serious vulnerabilities present | Open Red Padlock |
| **F** | **0 – 39** | Critical failure; immediate remediation required | Open Pulsing Red Padlock |

### Resource-Aware Stable Keys
To prevent false "Fixed" or "New" churn when page crawl orders or URLs change:
- **Target-wide checks** (Headers, CORS, Methods, Info Leaks) compare using finding IDs (e.g., `HDR-001`).
- **Cookie checks** isolate cookie names so that fixing `session` while leaving `tracking` open reports accurately.
- **Path checks** isolate normalized paths so that resolving `/.env` while `/robots.txt` remains open does not conflate findings.
- **Multi-page findings** normalize comma-separated URLs so discovering a finding on an additional subpage does not mark the original finding as Fixed.

## 📑 Reports: HTML & JSON Formats

### Ethical Testing Notice
This tool is for **authorized** educational, defensive, and diagnostic testing only.
- Scan only systems you own or have explicit, documented permission to test.
- Public/non-private targets require explicit authorization confirmation in the UI/CLI flow.
- Unauthorized testing may be illegal and unethical. Use responsibly and within approved scope.
