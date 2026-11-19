"""
checks/paths.py - Exposed paths and directory listing security checks

Performs baseline-aware signature scanning for sensitive files and directory listings.
Prevents false positives on single-page applications and catch-all web servers.
"""

import re
import random
import string
import hashlib
from typing import List, Tuple
from core.models import Finding
from core.context import ScanContext

# High-accuracy signature definitions for sensitive paths
PATH_CHECKS = [
    # 1. Environment & Secrets
    {
        "path": "/.env",
        "id": "PTH-ENV",
        "title": "Exposed .env configuration file",
        "severity": "Critical",
        "fix": "Block access to dotfiles in the web server config",
        "matcher": lambda text, raw: bool(re.search(r"(?m)^[A-Z0-9_]+=", text)),
        "snippet": lambda text, raw: "Matched key=value configuration pattern in response body",
    },
    # 2. Git Repository Internals
    {
        "path": "/.git/HEAD",
        "id": "PTH-GIT-HEAD",
        "title": "Exposed Git repository HEAD file",
        "severity": "Critical",
        "fix": "Block access to .git directory in the web server config",
        "matcher": lambda text, raw: text.strip().startswith("ref:"),
        "snippet": lambda text, raw: f"Body starts with: '{text.strip()[:60]}'",
    },
    {
        "path": "/.git/config",
        "id": "PTH-GIT-CONFIG",
        "title": "Exposed Git repository config file",
        "severity": "Critical",
        "fix": "Block access to .git directory in the web server config",
        "matcher": lambda text, raw: "[core]" in text,
        "snippet": lambda text, raw: "Contains '[core]' section from Git configuration",
    },
    {
        "path": "/.git/index",
        "id": "PTH-GIT-INDEX",
        "title": "Exposed Git repository index file",
        "severity": "Critical",
        "fix": "Block access to .git directory in the web server config",
        "matcher": lambda text, raw: raw.startswith(b"DIRC"),
        "snippet": lambda text, raw: "Response matches Git binary index magic bytes (DIRC)",
    },
    # 3. IDE & Workspace Configurations
    {
        "path": "/.vscode/sftp.json",
        "id": "PTH-VSCODE-SFTP",
        "title": "Exposed VS Code SFTP configuration file",
        "severity": "Critical",
        "fix": "Block access to dotfiles and remove .vscode configuration from web root",
        "matcher": lambda text, raw: bool(re.search(r'"(?:host|username|password|remotePath|uploadOnSave)"\s*:', text, re.IGNORECASE)),
        "snippet": lambda text, raw: "Contains VS Code SFTP connection parameters (host/username/password)",
    },
    {
        "path": "/.idea/workspace.xml",
        "id": "PTH-IDEA-WORKSPACE",
        "title": "Exposed JetBrains .idea workspace configuration file",
        "severity": "Medium",
        "fix": "Block access to .idea directory in the web server config",
        "matcher": lambda text, raw: ("<project version=" in text.lower() or "component name=" in text.lower()) and "<?xml" in text.lower()[:100],
        "snippet": lambda text, raw: "Contains JetBrains project workspace XML configuration",
    },
    # 4. API Documentation & Schemas
    {
        "path": "/swagger.json",
        "id": "PTH-SWAGGER-JSON",
        "title": "Exposed Swagger API documentation schema",
        "severity": "Medium",
        "fix": "Restrict access to Swagger schema definitions in production",
        "matcher": lambda text, raw: '"swagger"' in text.lower() and ('"info"' in text.lower() or '"paths"' in text.lower()),
        "snippet": lambda text, raw: "Contains Swagger 2.0 API specification schema",
    },
    {
        "path": "/swagger/v1/swagger.json",
        "id": "PTH-SWAGGER-V1",
        "title": "Exposed Swagger v1 API documentation schema",
        "severity": "Medium",
        "fix": "Restrict access to Swagger schema definitions in production",
        "matcher": lambda text, raw: '"swagger"' in text.lower() and ('"info"' in text.lower() or '"paths"' in text.lower()),
        "snippet": lambda text, raw: "Contains Swagger v1 API specification schema",
    },
    {
        "path": "/openapi.json",
        "id": "PTH-OPENAPI-JSON",
        "title": "Exposed OpenAPI 3.0 specification schema",
        "severity": "Medium",
        "fix": "Restrict access to OpenAPI specification definitions in production",
        "matcher": lambda text, raw: '"openapi"' in text.lower() and ('"paths"' in text.lower() or '"components"' in text.lower()),
        "snippet": lambda text, raw: "Contains OpenAPI 3.x specification schema",
    },
    {
        "path": "/api-docs",
        "id": "PTH-API-DOCS",
        "title": "Exposed Springfox/OpenAPI api-docs schema",
        "severity": "Medium",
        "fix": "Restrict access to /api-docs in production environments",
        "matcher": lambda text, raw: ('"swagger"' in text.lower() or '"openapi"' in text.lower()) and '"paths"' in text.lower(),
        "snippet": lambda text, raw: "Contains API documentation schema definition",
    },
    # 5. Spring Boot Actuators
    {
        "path": "/actuator",
        "id": "PTH-ACTUATOR-ROOT",
        "title": "Exposed Spring Boot Actuator discovery endpoint",
        "severity": "Medium",
        "fix": "Restrict management endpoints via 'management.endpoints.web.exposure.exclude=*' in application.properties",
        "matcher": lambda text, raw: '"_links"' in text.lower() and ('"self"' in text.lower() or '"health"' in text.lower()),
        "snippet": lambda text, raw: "Contains Spring Boot Actuator HAL _links navigation schema",
    },
    {
        "path": "/actuator/health",
        "id": "PTH-ACTUATOR-HEALTH",
        "title": "Exposed Spring Boot Actuator health endpoint",
        "severity": "Low",
        "fix": "Restrict /actuator/health endpoint with authentication or reverse proxy rules",
        "matcher": lambda text, raw: bool(re.search(r'"status"\s*:\s*"(?:UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"', text, re.IGNORECASE)),
        "snippet": lambda text, raw: "Contains Spring Boot health status indicator (UP/DOWN)",
    },
    {
        "path": "/actuator/env",
        "id": "PTH-ACTUATOR-ENV",
        "title": "Exposed Spring Boot Actuator environment configuration",
        "severity": "Critical",
        "fix": "Disable /actuator/env endpoint immediately. It exposes active environment variables and secrets.",
        "matcher": lambda text, raw: ('"propertySources"' in text or '"activeProfiles"' in text) and '"name"' in text,
        "snippet": lambda text, raw: "Contains Spring Boot environment propertySources and active profiles",
    },
    # 6. Web Server Configuration Files
    {
        "path": "/web.config",
        "id": "PTH-WEB-CONFIG",
        "title": "Exposed IIS web.config file",
        "severity": "Critical",
        "fix": "Block access to web.config in IIS request filtering or web server configuration",
        "matcher": lambda text, raw: ("<configuration>" in text.lower() and "<system.web" in text.lower()) or "<system.webserver>" in text.lower(),
        "snippet": lambda text, raw: "Contains IIS configuration directives (<configuration> / <system.webServer>)",
    },
    {
        "path": "/.htaccess",
        "id": "PTH-HTACCESS",
        "title": "Exposed Apache .htaccess configuration file",
        "severity": "High",
        "fix": "Ensure AllowOverride and file protection rules prevent serving .htaccess files",
        "matcher": lambda text, raw: bool(re.search(r"(?im)^\s*(?:RewriteEngine|RewriteRule|RewriteCond|AuthType|Order\s+allow,deny|Deny\s+from|Header\s+set|Options\s+[+\-]?Indexes)", text)),
        "snippet": lambda text, raw: "Contains Apache server configuration directives (RewriteRule / AuthType / Options)",
    },
    # 7. Backup Archives & Database Dumps
    {
        "path": "/backup.zip",
        "id": "PTH-BACKUP-ZIP",
        "title": "Exposed zip backup archive",
        "severity": "High",
        "fix": "Remove archive backups from web-accessible directories",
        "matcher": lambda text, raw: raw.startswith(b"PK\x03\x04"),
        "snippet": lambda text, raw: "Response matches PK zip archive magic bytes",
    },
    {
        "path": "/backup.tar.gz",
        "id": "PTH-BACKUP-TARGZ",
        "title": "Exposed tar.gz backup archive",
        "severity": "High",
        "fix": "Remove compressed archive backups from web-accessible directories",
        "matcher": lambda text, raw: raw.startswith(b"\x1f\x8b"),
        "snippet": lambda text, raw: "Response matches Gzip compressed archive magic bytes (\\x1f\\x8b)",
    },
    {
        "path": "/backup.sql",
        "id": "PTH-BACKUP-SQL",
        "title": "Exposed SQL database backup file",
        "severity": "High",
        "fix": "Remove SQL database backups from web-accessible directories",
        "matcher": lambda text, raw: ("CREATE TABLE" in text.upper()) or ("INSERT INTO" in text.upper()),
        "snippet": lambda text, raw: "Contains SQL schema DDL statements (CREATE TABLE / INSERT INTO)",
    },
    {
        "path": "/dump.sql",
        "id": "PTH-DUMP-SQL",
        "title": "Exposed database dump file",
        "severity": "High",
        "fix": "Remove database dump files from web-accessible directories",
        "matcher": lambda text, raw: ("CREATE TABLE" in text.upper()) or ("INSERT INTO" in text.upper()) or ("-- MYSQL DUMP" in text.upper()) or ("-- POSTGRESQL DATABASE DUMP" in text.upper()),
        "snippet": lambda text, raw: "Contains SQL schema definition or table data statements",
    },
    # 8. Diagnostics & Administrative Pages
    {
        "path": "/phpinfo.php",
        "id": "PTH-PHPINFO",
        "title": "Exposed phpinfo diagnostic page",
        "severity": "High",
        "fix": "Remove phpinfo diagnostic scripts from production server",
        "matcher": lambda text, raw: "phpinfo()" in text,
        "snippet": lambda text, raw: "Body contains 'phpinfo()' function execution banner",
    },
    {
        "path": "/server-status",
        "id": "PTH-SERVER-STATUS",
        "title": "Exposed Apache server-status page",
        "severity": "Medium",
        "fix": "Restrict /server-status access to localhost in server configuration",
        "matcher": lambda text, raw: "Apache Server Status" in text,
        "snippet": lambda text, raw: "Body contains 'Apache Server Status' administrative title",
    },
    {
        "path": "/metrics",
        "id": "PTH-METRICS",
        "title": "Exposed Prometheus metrics endpoint",
        "severity": "Medium",
        "fix": "Restrict /metrics endpoint with network firewall or authentication",
        "matcher": lambda text, raw: "# HELP" in text,
        "snippet": lambda text, raw: "Contains '# HELP' metric definition lines",
    },
    {
        "path": "/.DS_Store",
        "id": "PTH-DS-STORE",
        "title": "Exposed macOS .DS_Store file",
        "severity": "Low",
        "fix": "Block access to .DS_Store files in web server config",
        "matcher": lambda text, raw: raw.startswith(b"\x00\x00\x00\x01Bud1"),
        "snippet": lambda text, raw: "Response matches macOS .DS_Store header bytes",
    },
    {
        "path": "/robots.txt",
        "id": "PTH-ROBOTS-TXT",
        "title": "robots.txt exposes disallowed paths",
        "severity": "Info",
        "fix": "Verify that disallowed paths in robots.txt have strict authentication",
        "matcher": lambda text, raw: bool(re.search(r"(?im)^\s*Disallow:\s*\S+", text)),
        "snippet": lambda text, raw: (
            "Disallowed paths: "
            + ", ".join(re.findall(r"(?im)^\s*Disallow:\s*(\S+)", text)[:5])
        ),
    },
]

DIRECTORY_LISTING_PATHS = ["/", "/ftp", "/images", "/assets", "/uploads"]


def _is_directory_listing(html_text: str) -> bool:
    """
    Determine if an HTML response represents an active web server directory listing.
    Uses HTML structural elements (title, h1, parent directory links) to prevent
    false positives from prose content containing the phrase 'index of'.
    """
    if not html_text:
        return False

    # 1. Structural title or h1 tag checks (Apache, Nginx, Python http.server, IIS)
    if re.search(r"(?i)<title>\s*(?:Index of|Directory listing for|Directory:)\s+[^<]+</title>", html_text):
        return True

    if re.search(r"(?i)<h1[^>]*>\s*(?:Index of|Directory listing for|Directory:)\s+[^<]+</h1>", html_text):
        return True

    # 2. Apache / Nginx / Lighttpd table elements with Parent Directory links
    if re.search(r'(?i)<a\s+href=["\'][^"\']*["\']>\s*Parent Directory\s*</a>', html_text):
        return True

    # 3. Python http.server directory listing format
    if "Directory listing for" in html_text and "<hr>" in html_text and "<ul>" in html_text:
        return True

    return False


def run(ctx: ScanContext) -> Tuple[List[Finding], List[str]]:
    """
    Execute exposed path and directory listing checks.
    Returns:
        (findings, passed_checks)
    """
    findings: List[Finding] = []
    passed_checks: List[str] = []

    # Step 1: Establish baseline on a random non-existent path
    random_token = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    baseline_path = f"/zz-{random_token}"
    baseline_resp = ctx.get(baseline_path)

    if baseline_resp is not None:
        baseline_status = baseline_resp.status_code
        baseline_hash = hashlib.sha256(baseline_resp.content).hexdigest()
    else:
        baseline_status = 404
        baseline_hash = ""

    # Check for Single Page App catch-all routing (unknown URLs returning HTTP 200)
    if baseline_status == 200:
        print("[!] Target is a catch-all application (unknown paths return HTTP 200); strict signature matching applied.")

    # Step 2: Test each sensitive path using differential signature matching
    for item in PATH_CHECKS:
        if getattr(ctx, "cancelled", False):
            break
        target_path = item["path"]
        resp = ctx.get(target_path)

        if resp is None:
            continue

        # Status 401 and 403 indicate proper restriction, NOT a misconfiguration
        if resp.status_code in (401, 403):
            passed_checks.append(f"Path '{target_path}' is protected (HTTP {resp.status_code})")
            continue

        if resp.status_code == 200:
            current_hash = hashlib.sha256(resp.content).hexdigest()

            # Must differ from baseline (avoids false positives on catch-all servers)
            if current_hash != baseline_hash:
                raw_bytes = resp.content
                text_content = resp.text

                # Must match strict signature for that path
                if item["matcher"](text_content, raw_bytes):
                    proof = item["snippet"](text_content, raw_bytes)
                    findings.append(Finding(
                        id=item["id"],
                        title=item["title"],
                        category="paths",
                        severity=item["severity"],
                        evidence=f"GET {target_path} returned 200 OK. Evidence: {proof}"[:200],
                        fix=item["fix"],
                        confidence="Confirmed",
                        url=resp.url,
                    ))

    # Step 3: Check for directory listing on common directories using structural checks
    for dir_path in DIRECTORY_LISTING_PATHS:
        if getattr(ctx, "cancelled", False):
            break
        dir_resp = ctx.get(dir_path)
        if dir_resp is not None and dir_resp.status_code == 200:
            dir_text = dir_resp.text
            if _is_directory_listing(dir_text):
                target_label = "root" if dir_path == "/" else dir_path.strip("/")
                findings.append(Finding(
                    id=f"DIR-001-{target_label.upper()}",
                    title=f"Directory listing enabled on {dir_path}",
                    category="paths",
                    severity="Medium",
                    evidence=f"Directory listing banner detected on '{dir_path}'"[:200],
                    fix="Disable directory indexing (e.g., 'Options -Indexes' in Apache, 'autoindex off' in Nginx)",
                    confidence="Confirmed",
                    url=dir_resp.url,
                ))

    return findings, passed_checks
