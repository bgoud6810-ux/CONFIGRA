# Automated Security Misconfiguration Detector – Live Demonstration Guide

> **Official demonstration script and walkthrough for hackathon judges and B.Tech project evaluation.**
> Contains exact Windows PowerShell commands, step-by-step presentation scripts, and fallbacks.

---

## ⏱️ The 30-Second Elevator Pitch (For Judges)

> *"Security misconfigurations represent the #5 vulnerability category in the OWASP Top 10. While traditional scanners blast servers with destructive payloads or generate dozens of false alarms on modern Single Page Applications (SPAs), our **Automated Security Misconfiguration Detector** uses **differential canary baselines** to eliminate SPA false positives, strictly enforces non-destructive testing, generates offline cyber-themed reports with actionable remediation advice, and features an automated before-and-after comparison engine that quantifies security posture improvements."*

---

## 🎯 Demonstration Scenarios Overview

Choose the scenario that matches your live setup:

| Scenario | Target Environment | Best For | Time Required |
| :--- | :--- | :--- | :---: |
| **Scenario 0** *(Interactive Web App)* | CONFIGRA Flask app (`http://127.0.0.1:5000`) | Visual UI presentation with a live local scan | **3 minutes** |
| **Scenario A** *(CLI Live Demo)* | Standalone Local Test Server (`localhost:8000`) | Self-contained, zero-dependency live CLI demo | **3 minutes** |
| **Scenario B** | Running OWASP Juice Shop (`localhost:3000`) | Demonstrating differential baseline on modern SPAs | **4 minutes** |
| **Scenario C** | Automated Accuracy Proof (`test_accuracy.py`) | Rapid technical verification for code evaluators | **1 minute** |

---

## 🌟 Scenario 0: Interactive Web Interface (CONFIGRA)

Demonstrate the CONFIGRA interface with **EXACTLY TWO PAGES**: the scanner and its results dashboard.

### Step 1: Start the Web Server
In your terminal, start the Flask web application:
```powershell
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

### Step 2: Demonstrate Page 1 (Scanner Launchpad)
1. Point out the dark crimson-red CONFIGRA theme, shield/server logo, and four-element sidebar.
2. Click the **"OWASP Juice Shop (:3000)"** or **"Local Web Server (:8000)"** preset pill.
3. Toggle the **"Advanced Scan Configuration"** drawer to show the polite rate limiting (delay/timeout) and safety authorization checkbox.
4. Highlight the **"Authorized Testing Scope Notice"** (strict RFC1918 loopback enforcement).
5. Click **"Start Scan"**.
6. Watch the live scanning radar spinner and real-time terminal log stream probes.
7. Upon scan completion, the interface automatically navigates to **Page 2**.

### Step 3: Demonstrate Page 2 (CONFIGRA Results Dashboard)
1. Review the actual scan score, grade, scan date/time, severity donut, and category analytics.
2. Expand a priority finding to view its evidence, affected endpoint, and remediation.
3. **Interactive Findings List**:
   - Filter findings by clicking severity pills (**Critical**, **High**, **Medium**, **Low**).
   - Review passed checks and detailed remediation recommendations below the dashboard cards.
4. **Report Actions**:
   - Click **"View HTML"** to open the self-contained offline report.
   - Click **"Download JSON"** to download the structured findings.
   - Click **"New Scan"** to return to the scanner.

---

---

## 🚀 Scenario A: Complete Live Demo on Standalone Local Server

This scenario sets up an authorized local server, runs an initial audit, fixes an exposed file, and executes a re-scan comparison.

### Step 1: Open Terminal 1 – Launch Target Server
Open a Windows PowerShell terminal to create a temporary test directory with an intentional misconfiguration and start a server:

```powershell
# Create temporary demo target folder
mkdir C:\temp\demo_target -Force
Set-Content -Path "C:\temp\demo_target\index.html" -Value "<html><body><h1>Internal Portal</h1></body></html>"
Set-Content -Path "C:\temp\demo_target\.env" -Value "DATABASE_URL=postgres://admin:EXAMPLE_PASSWORD@10.0.0.5/prod`nAPI_KEY=EXAMPLE_DEMO_KEY_NOT_REAL"

# Start Python HTTP test server on port 8000
python -m http.server 8000 --directory C:\temp\demo_target
```
*(Leave Terminal 1 running in the background).*

---

### Step 2: Open Terminal 2 – Run Initial Security Scan
Open a second Windows PowerShell terminal and navigate to your project directory:

```powershell
cd "C:\path\to\cyber-spl-project"

# Run initial security scan
python scanner.py http://localhost:8000 --out output/scan_v1.html --json output/scan_v1.json
```

#### Expected Terminal Output:
```text
[!] Authorized testing only

[*] Initializing scan against target: http://localhost:8000
[*] Target responded (HTTP 200). Running security checks...

======================================================================
 SCAN RESULTS SUMMARY
======================================================================
 Target:       http://localhost:8000
 Target IP:    127.0.0.1
 Score:        34 / 100
 Grade:        F
 Duration:     1.85s
 Findings:     7 total
   - Critical: 1
   - High:     1
   - Medium:   2
   - Low:      3
   - Info:     0

 CRITICAL FINDINGS:
   [CRITICAL] .env file exposed (PTH-001)
     URL:      http://localhost:8000/.env
     Evidence: Matched signature in 200 OK: DATABASE_URL=
     Fix:      Block direct web access to sensitive dotfiles (.env) in server configuration

 HIGH FINDINGS:
   [HIGH] Missing X-Frame-Options (HDR-001)
     URL:      http://localhost:8000/
     Evidence: X-Frame-Options header not set
     Fix:      Add 'X-Frame-Options: DENY' or use CSP 'frame-ancestors'

 PASSED CHECKS:
   - No .git repository exposure
   - No directory listing on /

[+] JSON results saved to: C:\path\to\cyber-spl-project\output\scan_v1.json
[+] HTML report saved to:  C:\path\to\cyber-spl-project\output\scan_v1.html
```

---

### Step 3: Open & Present the HTML Report
Open the cyber-themed HTML report in your default web browser:

```powershell
start output/scan_v1.html
```

#### Key Highlights to Point Out to Judges:
1. **Interactive Hero Status**: Shows **Grade F** with an **Open Red Padlock** and **34 / 100** score.
2. **Severity Tiles**: Color-coded breakdown of Critical, High, Medium, and Low counts.
3. **Evidence & Remediation Boxes**: Each finding displays the exact evidence observed and a dedicated green remediation box with actionable fix instructions.
4. **100% Offline Capability**: Emphasize that all SVG art and styles are self-contained without external CDN dependencies.

---

### Step 4: Simulate Vulnerability Remediation
In Terminal 1 (or PowerShell), simulate fixing the critical `.env` vulnerability by deleting or securing the file:

```powershell
# Remove the exposed .env file
Remove-Item -Path "C:\temp\demo_target\.env" -Force
```

---

### Step 5: Execute Re-Scan with `--compare`
In Terminal 2, run a second scan using `--compare` referencing the previous `scan_v1.json`:

```powershell
python scanner.py http://localhost:8000 --compare output/scan_v1.json --out output/scan_v2.html --json output/scan_v2.json
```

#### Expected Terminal Output:
```text
[!] Authorized testing only

[*] Initializing scan against target: http://localhost:8000
[*] Target responded (HTTP 200). Running security checks...

======================================================================
 SCAN RESULTS SUMMARY
======================================================================
 Target:       http://localhost:8000
 Target IP:    127.0.0.1
 Score:        59 / 100
 Grade:        D
 Duration:     1.72s
 Findings:     6 total

======================================================================
 RE-SCAN COMPARISON (Changes since last scan)
======================================================================
 Score Change:  34 -> 59 (+25 pts)
 Grade Change:  F -> D
 Summary:       Fixed: 1, Still open: 6, New: 0

 Fixed Findings:
   [FIXED] .env file exposed (PTH-001)
======================================================================

[+] JSON results saved to: C:\path\to\cyber-spl-project\output\scan_v2.json
[+] HTML report saved to:  C:\path\to\cyber-spl-project\output\scan_v2.html
```

---

### Step 6: Present the Comparison Panel in the Report
Open the updated report in your browser:

```powershell
start output/scan_v2.html
```

#### Key Highlights to Point Out:
1. **"Changes Since Last Scan" Panel**:
   - Score increased from **34 &rarr; 59 (+25 pts)**.
   - Badges indicate **1 Fixed**, **6 Still Open**, **0 New**.
   - Explicitly lists `[FIXED] .env file exposed (PTH-001)`.
2. **Grade Improvement**: Upgraded from **Grade F** to **Grade D**.

---

## 🛡️ Scenario B: Scanning OWASP Juice Shop (`http://localhost:3000`)

If OWASP Juice Shop is running on `http://localhost:3000`, use this scenario to prove differential baseline accuracy against Single Page Applications.

### Step 1: Execute Scan
```powershell
python scanner.py http://localhost:3000 --out output/juiceshop_report.html --json output/juiceshop_results.json
```

### Step 2: Open Report
```powershell
start output/juiceshop_report.html
```

### Step 3: Key Talking Point for Judges
> *"OWASP Juice Shop is an Angular SPA where every unknown route returns HTTP 200 with the index HTML. Other scanners report 50+ false positives on Juice Shop. Notice our scanner detected the catch-all baseline and reported **zero false positives**, while correctly isolating real issues like missing CSP, missing HSTS, and exposed directory indexes."*

---

## 🔬 Scenario C: The Technical Proof Test (1-Minute Judge Verification)

When evaluators ask for proof of accuracy and test coverage, run the automated control server test suite:

```powershell
python -m tests.test_accuracy
```

#### Actual Execution Output:
```text
====================================================================
 STARTING ACCURACY & CONTROL SERVER TESTS (PHASE 4)
====================================================================

[*] BAD Server Results: Grade F, Score 18/100, Findings: 14
  [PASS] BAD server produced all expected findings and received failing grade D/F.
[!] Target is a catch-all application (unknown paths return HTTP 200); strict signature matching applied.

[*] GOOD Server Results: Grade A, Score 97/100, Findings: 2
  [PASS] GOOD server produced 0 path findings (catch-all baseline prevented false positives).
  [PASS] GOOD server produced 0 cookie vulnerability findings.
  [PASS] GOOD server achieved passing grade A (97/100).

====================================================================
 [PHASE 4 RESULT: PASS]
====================================================================
```

---

## 🏆 Top Commands for Demo Day

```powershell
# 1. Launch the CONFIGRA Web Interface (Exactly 2 Pages)
python app.py
# (Open http://127.0.0.1:5000 in your browser)

# 2. Run the CLI Scanner directly against target
python scanner.py http://localhost:8000

# 3. View the Generated HTML Security Report
start output/report.html

# 4. Prove Accuracy with the Master Test Suite
python -m unittest tests/test_webapp.py
```

---

## 🔍 Troubleshooting Demo Issues

| Issue | Quick Fix During Presentation |
| :--- | :--- |
| **Port 8000 already in use** | Change port to 8080: `python -m http.server 8080 --directory C:\temp\demo_target` and scan `http://localhost:8080` |
| **Browser doesn't open** | Navigate manually in Chrome/Edge: open `file:///C:/path/to/cyber-spl-project/output/scan_v1.html` |
| **Target shows unreachable** | Confirm Python server in Terminal 1 is still running and not suspended |
| **Need fresh output** | Delete previous files in `output/` or use `--out output/test.html` |

---

## ⚠️ Ethical & Safety Boundaries Statement

Always conclude your demonstration by addressing scanner safety:
- **Scope Restriction**: Emphasize that the scanner enforces private/local scope by default, refusing external targets without `--i-have-permission`.
- **Non-Destructive Testing**: Clarify that no state-changing payloads (`POST`, `PUT`, `DELETE`) are sent.
- **Authorization**: Testing is conducted strictly against authorized local targets under controlled conditions.