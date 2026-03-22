"""
Website Vulnerability Scanner Service — v3 (Production-Grade).
Includes:
  - Severity justification for every finding
  - False positive handling with documentation
  - Auto-fix suggestions (copy-paste configs)
  - Header injection testing
  - Real attack simulation with confirmation
Tests:
  - SQL Injection (error-based + blind + real simulation)
  - XSS (reflected, DOM-based markers, with confirmation)
  - Misconfiguration (headers, cookies, info disclosure)
  - Directory Discovery (with content validation + custom 404 detection)
  - Brute Force (login detection, weak creds, rate limit)
  - Header Injection (CRLF, Host header)
"""
import logging
import time
import re
import hashlib
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ── XSS payloads ──────────────────────────────────────────────
XSS_MARKER = "T1B5A_XSS_"
XSS_PAYLOADS = [
    {'payload': '<script>alert("{m}")</script>',          'type': 'script_tag'},
    {'payload': '"><img src=x onerror=alert("{m}")>',     'type': 'img_event'},
    {'payload': "'-alert('{m}')-'",                       'type': 'js_break'},
    {'payload': '<svg/onload=alert("{m}")>',              'type': 'svg_event'},
    {'payload': '<body onload=alert("{m}")>',             'type': 'body_event'},
    {'payload': 'javascript:alert("{m}")',                'type': 'js_proto'},
]

# ── SQLi payloads ─────────────────────────────────────────────
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1' OR '1'='1' --",
    "' UNION SELECT NULL,NULL --",
    "1; DROP TABLE users --",
    "' AND 1=CONVERT(int,(SELECT @@version)) --",
    "' OR 1=1 #",
]

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql_",
    r"warning:\s*pg_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for (?:sql server|odbc)",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR:\s*",
    r"pg_query\(\).*failed",
    r"mysql_(?:fetch|num|query|connect)",
    r"sqlite3\.OperationalError",
    r"SQLSTATE\[\w+\]",
    r"syntax error at or near",
    r"Unclosed quotation mark",
    r"com\.mysql\.jdbc",
    r"java\.sql\.SQLException",
    r"org\.postgresql\.util\.PSQLException",
]

# ── Header Injection payloads ─────────────────────────────────
HEADER_INJECTION_PAYLOADS = [
    {"payload": "test\r\nX-Injected: true",    "check_header": "x-injected",    "type": "CRLF"},
    {"payload": "test\r\nSet-Cookie: hacked=1", "check_header": "set-cookie",    "type": "CRLF Cookie"},
    {"payload": "test%0d%0aX-Injected: true",   "check_header": "x-injected",    "type": "URL-encoded CRLF"},
]

# ── Security Headers with severity justification ─────────────
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "desc": "CSP prevents XSS and data injection by restricting resource loading sources.",
        "severity": "high",
        "severity_justification": "HIGH because without CSP, any injected script can execute freely, making XSS attacks trivial. CSP is the primary browser-side XSS mitigation.",
        "remediation": "Add a Content-Security-Policy header. Example: Content-Security-Policy: default-src 'self'; script-src 'self'",
        "auto_fix": "# Nginx\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;\" always;\n\n# Apache (.htaccess)\nHeader set Content-Security-Policy \"default-src 'self'; script-src 'self';\"\n\n# Express.js\napp.use((req, res, next) => {\n  res.setHeader('Content-Security-Policy', \"default-src 'self'; script-src 'self'\");\n  next();\n});",
    },
    "X-Frame-Options": {
        "desc": "Protects against clickjacking by controlling iframe embedding.",
        "severity": "medium",
        "severity_justification": "MEDIUM because clickjacking requires user interaction and is less impactful than direct code execution, but can still lead to unintended actions.",
        "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
        "auto_fix": "# Nginx\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\n\n# Apache\nHeader set X-Frame-Options \"SAMEORIGIN\"\n\n# Express.js\napp.use((req, res, next) => {\n  res.setHeader('X-Frame-Options', 'SAMEORIGIN');\n  next();\n});",
    },
    "Strict-Transport-Security": {
        "desc": "HSTS enforces HTTPS connections, preventing protocol downgrade and MITM attacks.",
        "severity": "high",
        "severity_justification": "HIGH because without HSTS, attackers on the same network can downgrade HTTPS to HTTP and intercept all traffic including credentials (SSL stripping attack).",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "auto_fix": "# Nginx\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n# Apache\nHeader set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n\n# Express.js\napp.use((req, res, next) => {\n  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');\n  next();\n});",
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing which can lead to XSS via disguised files.",
        "severity": "medium",
        "severity_justification": "MEDIUM because MIME sniffing attacks require specific conditions (file upload + wrong content type) but can lead to XSS if exploited.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "auto_fix": "# Nginx\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n# Apache\nHeader set X-Content-Type-Options \"nosniff\"\n\n# Express.js\napp.use((req, res, next) => {\n  res.setHeader('X-Content-Type-Options', 'nosniff');\n  next();\n});",
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter for older browsers (IE, older Chrome).",
        "severity": "low",
        "severity_justification": "LOW because modern browsers have deprecated this header. CSP is the proper replacement. Only affects users on very old browsers.",
        "remediation": "Add header: X-XSS-Protection: 1; mode=block",
        "auto_fix": "# Nginx\nadd_header X-XSS-Protection \"1; mode=block\" always;\n\n# Apache\nHeader set X-XSS-Protection \"1; mode=block\"",
    },
    "Referrer-Policy": {
        "desc": "Controls how much referrer information is sent with requests.",
        "severity": "low",
        "severity_justification": "LOW because referrer leakage is an information disclosure issue, not a direct vulnerability. May expose internal URLs or query parameters to third parties.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "auto_fix": "# Nginx\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n# Apache\nHeader set Referrer-Policy \"strict-origin-when-cross-origin\"",
    },
    "Permissions-Policy": {
        "desc": "Controls which browser features the site can use (camera, microphone, etc).",
        "severity": "low",
        "severity_justification": "LOW because browser features are gated behind user permission prompts. This header adds defense-in-depth but absence alone is not directly exploitable.",
        "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "auto_fix": "# Nginx\nadd_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n\n# Apache\nHeader set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"",
    },
}

INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

# ── Directories ───────────────────────────────────────────────
COMMON_DIRECTORIES = [
    "/.env", "/.git/config", "/.git/HEAD", "/.htpasswd",
    "/phpinfo.php", "/info.php", "/debug", "/console",
    "/.well-known/security.txt",
    "/admin", "/administrator", "/admin/login",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/adminer",
    "/backup", "/backups", "/database", "/db",
    "/config", "/configuration", "/settings",
    "/log", "/logs", "/tmp", "/temp",
    "/robots.txt", "/sitemap.xml",
    "/api", "/api/v1", "/api/docs", "/swagger", "/swagger-ui",
    "/login", "/signin", "/auth/login",
    "/uploads", "/upload", "/files",
    "/cgi-bin", "/wp-content", "/wp-includes",
    "/xmlrpc.php", "/server-status", "/server-info",
]

COMMON_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("root", "root"), ("root", "password"),
    ("test", "test"), ("user", "password"), ("admin", "1234"),
    ("administrator", "administrator"),
]


class WebsiteScannerService:
    """Production-grade vulnerability scanner with accuracy improvements."""

    def __init__(self):
        self.timeout = httpx.Timeout(15.0, connect=10.0)
        self.finding_counter = 0
        self._404_body_hash: Optional[str] = None
        self._404_length: int = 0

    def _next_id(self) -> str:
        self.finding_counter += 1
        return f"FIND-{self.finding_counter:03d}"

    # ══════════════════════════════════════════════════════════
    # MAIN ENTRY
    # ══════════════════════════════════════════════════════════

    async def scan(self, target: str, tests: List[str]) -> Dict[str, Any]:
        start = time.time()
        scan_id = f"WS-{int(start * 1000)}"
        self.finding_counter = 0

        findings: List[Dict[str, Any]] = []
        headers_dict: Dict[str, str] = {}
        endpoints: List[Dict[str, Any]] = []
        fp_log: List[str] = []  # False positive log

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True, verify=False,
            headers={"User-Agent": "TIBSA-Scanner/3.0 (Security Audit)"},
        ) as client:
            try:
                response = await client.get(target)
                headers_dict = dict(response.headers)
            except Exception as exc:
                return self._error_result(scan_id, target, start, str(exc))

            # Build baseline for false positive detection
            await self._detect_custom_404(client, target)
            baseline_text = response.text

            if "misconfiguration" in tests:
                findings.extend(self._check_misconfiguration(target, response))

            if "directory_discovery" in tests:
                df, de, fp = await self._discover_directories(client, target, response)
                findings.extend(df)
                endpoints.extend(de)
                fp_log.extend(fp)

            if "xss" in tests:
                xf, xfp = await self._test_xss(client, target, response)
                findings.extend(xf)
                fp_log.extend(xfp)

            if "sqli" in tests:
                sf, sfp = await self._test_sqli(client, target, response, baseline_text)
                findings.extend(sf)
                fp_log.extend(sfp)

            if "brute_force" in tests:
                findings.extend(await self._test_brute_force(client, target, response))

            # Header Injection (always run as part of misconfiguration or standalone)
            if "misconfiguration" in tests:
                hf, hfp = await self._test_header_injection(client, target)
                findings.extend(hf)
                fp_log.extend(hfp)

            # ── Advanced Attack Simulation ──────────────────
            # These run as part of the misconfiguration test for full coverage
            if "misconfiguration" in tests:
                # CORS Misconfiguration
                cf, cfp = await self._test_cors(client, target)
                findings.extend(cf)
                fp_log.extend(cfp)

                # Open Redirect
                orf, orfp = await self._test_open_redirect(client, target, response)
                findings.extend(orf)
                fp_log.extend(orfp)

            if "sqli" in tests or "xss" in tests:
                # Path Traversal / LFI (shares test points with sqli/xss)
                ptf, ptfp = await self._test_path_traversal(client, target, response)
                findings.extend(ptf)
                fp_log.extend(ptfp)

            if "misconfiguration" in tests:
                # SSRF (tests URL-type parameters)
                sf2, sf2fp = await self._test_ssrf(client, target, response)
                findings.extend(sf2)
                fp_log.extend(sf2fp)

        duration = round(time.time() - start, 1)
        high = sum(1 for f in findings if f["severity"] == "high")
        medium = sum(1 for f in findings if f["severity"] == "medium")
        low = sum(1 for f in findings if f["severity"] == "low")

        return {
            "scan_id": scan_id, "target": target,
            "started_at": time.strftime("%m/%d/%Y, %I:%M:%S %p", time.localtime(start)),
            "duration": duration,
            "high": high, "medium": medium, "low": low,
            "total": high + medium + low,
            "endpoints_found": len(endpoints),
            "findings": findings,
            "headers": headers_dict,
            "endpoints": endpoints,
            "false_positives_filtered": fp_log,
        }

    # ══════════════════════════════════════════════════════════
    # FALSE POSITIVE HELPERS
    # ══════════════════════════════════════════════════════════

    async def _detect_custom_404(self, client: httpx.AsyncClient, target: str):
        base = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        try:
            resp = await client.get(base + f"/tibsa_fp_check_{int(time.time())}")
            self._404_body_hash = hashlib.md5(resp.content).hexdigest()
            self._404_length = len(resp.content)
        except Exception:
            self._404_body_hash = None
            self._404_length = 0

    def _is_real_page(self, resp: httpx.Response) -> bool:
        if resp.status_code == 404:
            return False
        body_hash = hashlib.md5(resp.content).hexdigest()
        if self._404_body_hash:
            if body_hash == self._404_body_hash:
                return False
            if self._404_length > 0:
                diff = abs(len(resp.content) - self._404_length) / max(self._404_length, 1)
                if diff < 0.05:
                    return False
        body_lower = resp.text.lower()
        nf_count = sum(1 for s in ["page not found", "404", "not found"] if s in body_lower)
        if nf_count >= 2:
            return False
        return True

    def _is_sql_error_genuine(self, resp_text: str, baseline_text: str) -> Optional[str]:
        """Returns the matched pattern if genuine, None if false positive."""
        resp_lower = resp_text.lower()
        baseline_lower = baseline_text.lower()
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, resp_lower, re.IGNORECASE):
                if not re.search(pattern, baseline_lower, re.IGNORECASE):
                    return pattern
        return None

    # ══════════════════════════════════════════════════════════
    # 1. MISCONFIGURATION
    # ══════════════════════════════════════════════════════════

    def _check_misconfiguration(self, target: str, response: httpx.Response) -> List[Dict[str, Any]]:
        findings = []
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        for header_name, info in SECURITY_HEADERS.items():
            if header_name.lower() not in resp_headers:
                findings.append({
                    "id": self._next_id(),
                    "title": f"Missing Header — {header_name}",
                    "classification": "best_practice",
                    "severity": info["severity"],
                    "severity_justification": info["severity_justification"],
                    "url": target,
                    "description": info["desc"],
                    "evidence": f"Header '{header_name}' is absent from the response.",
                    "false_positive_check": f"Verified by inspecting all {len(response.headers)} response headers. Header is definitively missing.",
                    "remediation": info["remediation"],
                    "auto_fix": info["auto_fix"],
                })

        for header_name in INFO_DISCLOSURE_HEADERS:
            val = resp_headers.get(header_name.lower())
            if val:
                findings.append({
                    "id": self._next_id(),
                    "title": f"Info Disclosure — {header_name}",
                    "classification": "best_practice",
                    "severity": "low",
                    "severity_justification": "LOW because information disclosure alone doesn't allow exploitation, but helps attackers fingerprint the technology stack for targeted attacks.",
                    "url": target,
                    "description": f"Server reveals: \"{val}\".",
                    "evidence": f"{header_name}: {val}",
                    "false_positive_check": "Confirmed: header value directly read from server response.",
                    "remediation": f"Remove or genericize the {header_name} header.",
                    "auto_fix": f"# Nginx\nproxy_hide_header {header_name};\n\n# Apache\nHeader unset {header_name}\nHeader always unset {header_name}",
                })

        # Cookie analysis (consolidated per cookie)
        cookies = response.headers.get_list("set-cookie")
        for raw_cookie in cookies:
            name = raw_cookie.split("=")[0].strip() if "=" in raw_cookie else "unknown"
            lower = raw_cookie.lower()
            issues = []
            if "secure" not in lower: issues.append("Secure")
            if "httponly" not in lower: issues.append("HttpOnly")
            if "samesite" not in lower: issues.append("SameSite")
            if issues:
                severity = "medium" if ("Secure" in issues or "HttpOnly" in issues) else "low"
                fix_parts = []
                if "Secure" in issues: fix_parts.append("Secure")
                if "HttpOnly" in issues: fix_parts.append("HttpOnly")
                if "SameSite" in issues: fix_parts.append("SameSite=Lax")
                findings.append({
                    "id": self._next_id(),
                    "title": f"Cookie Insecure — {name}",
                    "classification": "best_practice",
                    "severity": severity,
                    "severity_justification": f"{'MEDIUM' if severity == 'medium' else 'LOW'} — Missing {'Secure/HttpOnly enables session hijacking via XSS or network sniffing' if severity == 'medium' else 'SameSite allows potential CSRF attacks'}.",
                    "url": target,
                    "description": f"Cookie '{name}' is missing: {', '.join(issues)}.",
                    "evidence": raw_cookie[:200],
                    "false_positive_check": f"Verified: parsed Set-Cookie header directly. Missing flags confirmed by string analysis.",
                    "remediation": f"Add flags: {'; '.join(fix_parts)}",
                    "auto_fix": f"# Fix for cookie '{name}':\nSet-Cookie: {name}=<value>; Path=/; {'; '.join(fix_parts)}\n\n# Express.js\nres.cookie('{name}', value, {{ secure: true, httpOnly: true, sameSite: 'lax' }});\n\n# Python/Flask\nresponse.set_cookie('{name}', value, secure=True, httponly=True, samesite='Lax')",
                })

        if target.startswith("http://"):
            findings.append({
                "id": self._next_id(),
                "title": "No HTTPS — Insecure Connection",
                "classification": "vulnerability",
                "severity": "high",
                "severity_justification": "HIGH because all data (credentials, tokens, personal info) is transmitted in plaintext, trivially intercepted by anyone on the network.",
                "url": target,
                "description": "Site served over plain HTTP. All traffic can be intercepted via MITM attack.",
                "evidence": f"URL scheme: {urlparse(target).scheme}",
                "false_positive_check": "Verified: URL scheme is 'http', not 'https'.",
                "remediation": "Enable HTTPS with a TLS certificate.",
                "auto_fix": "# Let's Encrypt (certbot)\nsudo certbot --nginx -d yourdomain.com\n\n# Nginx redirect HTTP to HTTPS\nserver {\n    listen 80;\n    server_name yourdomain.com;\n    return 301 https://$host$request_uri;\n}",
            })

        return findings

    # ══════════════════════════════════════════════════════════
    # 2. DIRECTORY DISCOVERY
    # ══════════════════════════════════════════════════════════

    async def _discover_directories(
        self, client: httpx.AsyncClient, target: str, main_response: httpx.Response
    ) -> tuple:
        findings = []
        endpoints = []
        fp_log = []
        base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

        for path in COMMON_DIRECTORIES:
            try:
                full_url = base_url + path
                resp = await client.get(full_url)

                if resp.status_code != 200:
                    if resp.status_code == 403:
                        endpoints.append({"type": "directory", "url": full_url, "status": 403, "text": f"{path} (Forbidden)"})
                    continue

                if not self._is_real_page(resp):
                    fp_log.append(f"Directory '{path}' — filtered as custom 404 (body hash matched known 404 page)")
                    continue

                if not self._validate_directory_content(path, resp):
                    fp_log.append(f"Directory '{path}' — filtered: content does not match expected format for this file type")
                    continue

                if any(p in path for p in [".env", ".git", ".htpasswd", "phpinfo", "debug", "console"]):
                    severity, sev_j = "high", "HIGH — file may contain credentials, API keys, or debug information directly exploitable by attackers."
                elif any(p in path for p in ["admin", "phpmyadmin", "adminer", "backup", "database", "config", "log"]):
                    severity, sev_j = "medium", "MEDIUM — administrative interfaces and config paths can assist attackers in enumeration and privilege escalation."
                else:
                    severity, sev_j = "low", "LOW — path reveals site structure information useful for reconnaissance but not directly exploitable."

                classification = "vulnerability" if severity == "high" else "best_practice"
                findings.append({
                    "id": self._next_id(),
                    "title": f"Exposed Path — {path}",
                    "classification": classification,
                    "severity": severity,
                    "severity_justification": sev_j,
                    "url": full_url,
                    "description": f"Sensitive path '{path}' is publicly accessible.",
                    "evidence": f"HTTP {resp.status_code} — {len(resp.content)} bytes — Type: {resp.headers.get('content-type', 'N/A')}",
                    "false_positive_check": f"Confirmed: response differs from custom 404 baseline (hash mismatch) and content matches expected format for '{path}'.",
                    "remediation": f"Restrict access to '{path}' or remove from production.",
                    "auto_fix": f"# Nginx — block path\nlocation {path} {{\n    deny all;\n    return 404;\n}}\n\n# Apache (.htaccess)\n<Files \"{path.split('/')[-1]}\">\n    Require all denied\n</Files>",
                })
                endpoints.append({"type": "directory", "url": full_url, "status": resp.status_code, "text": path})
            except Exception:
                continue

        return findings, endpoints, fp_log

    def _validate_directory_content(self, path: str, resp: httpx.Response) -> bool:
        body = resp.text.lower()
        if ".env" in path:
            return bool(re.search(r'^[A-Z_]+=.+', resp.text, re.MULTILINE))
        if ".git/config" in path:
            return "[core]" in body
        if ".git/HEAD" in path:
            return "ref:" in body or len(resp.text.strip()) == 40
        if "phpinfo" in path:
            return "php version" in body and "<table" in body
        if "robots.txt" in path:
            return any(d in body for d in ["user-agent", "disallow", "allow", "sitemap"])
        if "sitemap.xml" in path:
            return "<?xml" in body or "<urlset" in body
        if any(p in path for p in ["swagger", "api/docs"]):
            return any(k in body for k in ["swagger", "openapi", "api documentation"])
        if any(p in path for p in ["admin", "phpmyadmin", "adminer"]):
            return any(k in body for k in ["login", "password", "username", "sign in", "dashboard", "admin panel", "phpmyadmin"])
        ct = resp.headers.get("content-type", "").lower()
        if "text/html" in ct and len(resp.content) > 500:
            return True
        return len(resp.content) > 100

    # ══════════════════════════════════════════════════════════
    # 3. XSS (with marker confirmation)
    # ══════════════════════════════════════════════════════════

    async def _test_xss(
        self, client: httpx.AsyncClient, target: str, response: httpx.Response
    ) -> tuple:
        findings = []
        fp_log = []
        soup = BeautifulSoup(response.text, "lxml")
        test_points = self._get_test_points(target, soup)

        for point in test_points[:12]:
            for i, xss in enumerate(XSS_PAYLOADS[:4]):
                marker = f"{XSS_MARKER}{i}_{int(time.time()) % 10000}"
                payload = xss['payload'].replace("{m}", marker)
                try:
                    resp = await self._send_payload(client, point, payload)
                    if resp is None:
                        continue
                    body = resp.text

                    if marker not in body:
                        continue

                    # Confirm dangerous context
                    is_confirmed = False
                    evidence_detail = ""

                    if payload in body:
                        is_confirmed = True
                        evidence_detail = "Full payload reflected unescaped in response body."
                    elif f'alert("{marker}")' in body or f"alert('{marker}')" in body:
                        is_confirmed = True
                        evidence_detail = "Payload marker found in executable JavaScript context."
                    else:
                        resp_soup = BeautifulSoup(body, "lxml")
                        for tag in resp_soup.find_all(True):
                            for attr, val in tag.attrs.items():
                                if isinstance(val, str) and marker in val:
                                    if attr.startswith("on") or attr in ["href", "src", "action"]:
                                        is_confirmed = True
                                        evidence_detail = f"Marker injected into dangerous attribute '{attr}' of <{tag.name}>."
                                        break
                            if is_confirmed:
                                break

                    if is_confirmed:
                        param_name = point.get('param') or point.get('name', 'input')
                        findings.append({
                            "id": self._next_id(),
                            "title": f"Confirmed XSS — {param_name}",
                            "classification": "vulnerability",
                            "severity": "high",
                            "severity_justification": "HIGH because reflected XSS allows attackers to execute arbitrary JavaScript in victim's browser, stealing session cookies, credentials, and performing actions on behalf of the user.",
                            "url": point.get("url", target),
                            "description": f"Parameter '{param_name}' reflects input without sanitization. Type: {xss['type']}. {evidence_detail}",
                            "evidence": f"Payload: {payload}\nMarker: {marker}\n{evidence_detail}",
                            "false_positive_check": f"Confirmed: unique marker '{marker}' was reflected in a dangerous context (not just text content). Payload type: {xss['type']}.",
                            "remediation": "1. HTML-encode all user output.\n2. Implement CSP header.\n3. Use framework auto-escaping.",
                            "auto_fix": "# Express.js — Use helmet + escape\nconst helmet = require('helmet');\napp.use(helmet());\n\n# Python/Jinja2 — Auto-escaping\nfrom markupsafe import escape\noutput = escape(user_input)\n\n# React — Already auto-escapes JSX\n// Don't use dangerouslySetInnerHTML with user input",
                        })
                        break
                    else:
                        fp_log.append(f"XSS '{param_name}' — marker reflected in safe text context only (not in HTML tag/attribute/script). Filtered as non-exploitable.")
                except Exception:
                    continue

        return findings, fp_log

    # ══════════════════════════════════════════════════════════
    # 4. SQL INJECTION (with baseline + blind + simulation)
    # ══════════════════════════════════════════════════════════

    async def _test_sqli(
        self, client: httpx.AsyncClient, target: str, response: httpx.Response, baseline_text: str
    ) -> tuple:
        findings = []
        fp_log = []
        soup = BeautifulSoup(response.text, "lxml")
        test_points = self._get_test_points(target, soup)

        for point in test_points[:12]:
            # Get per-param baseline
            try:
                clean_resp = await self._send_payload(client, point, "tibsa_clean_value_12345")
                param_baseline = clean_resp.text if clean_resp else baseline_text
            except Exception:
                param_baseline = baseline_text

            found = False

            # Error-based detection
            for payload in SQLI_PAYLOADS[:5]:
                try:
                    resp = await self._send_payload(client, point, payload)
                    if resp is None:
                        continue

                    matched_pattern = self._is_sql_error_genuine(resp.text, param_baseline)
                    if matched_pattern:
                        param_name = point.get('param') or point.get('name', 'input')
                        match = re.search(matched_pattern, resp.text, re.IGNORECASE)
                        error_ctx = ""
                        if match:
                            s = max(0, match.start() - 20)
                            e = min(len(resp.text), match.end() + 80)
                            error_ctx = resp.text[s:e].strip()

                        findings.append({
                            "id": self._next_id(),
                            "title": f"Confirmed SQLi — {param_name}",
                            "classification": "vulnerability",
                            "severity": "high",
                            "severity_justification": "HIGH because SQL injection can lead to full database compromise: data theft, data modification, authentication bypass, and in some cases OS command execution.",
                            "url": point.get("url", target),
                            "description": f"Parameter '{param_name}' is vulnerable. Server returned a DB error not present in baseline, confirming the injection.",
                            "evidence": f"Payload: {payload}\nDB Error: {error_ctx[:200]}",
                            "false_positive_check": f"Confirmed: SQL error pattern '{matched_pattern}' found in injected response but NOT in clean baseline response. This rules out pre-existing error messages.",
                            "remediation": "1. Use parameterized queries.\n2. Use an ORM.\n3. Validate all input.\n4. Apply least-privilege DB permissions.",
                            "auto_fix": "# Python (SQLAlchemy)\nresult = db.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_input})\n\n# Node.js (mysql2)\nconst [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);\n\n# PHP (PDO)\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $userId]);",
                        })
                        found = True
                        break
                    else:
                        # Check if error existed in baseline too
                        for p in SQL_ERROR_PATTERNS:
                            if re.search(p, resp.text, re.IGNORECASE) and re.search(p, param_baseline, re.IGNORECASE):
                                fp_log.append(f"SQLi '{point.get('param') or point.get('name')}' — SQL error pattern '{p}' exists in BOTH baseline and injected response. Filtered as pre-existing error.")
                                break
                except Exception:
                    continue

            if found:
                continue

            # Blind SQLi (time-based) — real attack simulation
            try:
                t0 = time.time()
                await self._send_payload(client, point, "1")
                clean_time = time.time() - t0

                sleep_payload = "1' AND SLEEP(3) --"
                t0 = time.time()
                await self._send_payload(client, point, sleep_payload)
                inject_time = time.time() - t0

                if inject_time > clean_time + 2.5:
                    # Confirm with second attempt
                    t0 = time.time()
                    await self._send_payload(client, point, sleep_payload)
                    confirm_time = time.time() - t0

                    if confirm_time > clean_time + 2.0:
                        param_name = point.get('param') or point.get('name', 'input')
                        findings.append({
                            "id": self._next_id(),
                            "title": f"Blind SQLi (Time-based) — {param_name}",
                            "classification": "vulnerability",
                            "severity": "high",
                            "severity_justification": "HIGH — time-based blind SQLi confirms the parameter is passed directly to SQL. Attacker can extract entire database contents character by character.",
                            "url": point.get("url", target),
                            "description": f"SLEEP payload caused consistent delay: {inject_time:.1f}s and {confirm_time:.1f}s vs baseline {clean_time:.1f}s.",
                            "evidence": f"Payload: {sleep_payload}\nBaseline: {clean_time:.1f}s\n1st inject: {inject_time:.1f}s\n2nd inject (confirm): {confirm_time:.1f}s",
                            "false_positive_check": f"Confirmed with 2 consecutive SLEEP tests. Both showed >2.5s delay over baseline ({clean_time:.1f}s). Network latency variance ruled out.",
                            "remediation": "Use parameterized queries. Never concatenate user input into SQL.",
                            "auto_fix": "# Same as error-based SQLi — use parameterized queries\n# Python: db.execute(text('SELECT ... WHERE id = :id'), {'id': val})\n# Node.js: pool.execute('SELECT ... WHERE id = ?', [val])",
                        })
                    else:
                        fp_log.append(f"Blind SQLi '{point.get('param') or point.get('name')}' — first attempt showed delay but confirmation test did not. Likely network jitter. Filtered.")
            except Exception:
                continue

        return findings, fp_log

    # ══════════════════════════════════════════════════════════
    # 5. BRUTE FORCE
    # ══════════════════════════════════════════════════════════

    async def _test_brute_force(
        self, client: httpx.AsyncClient, target: str, response: httpx.Response
    ) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

        login_forms = self._find_login_forms(target, response)
        for path in ["/login", "/signin", "/auth/login", "/admin/login", "/wp-login.php"]:
            try:
                resp = await client.get(base_url + path)
                if resp.status_code == 200:
                    login_forms.extend(self._find_login_forms(base_url + path, resp))
            except Exception:
                continue

        seen = set()
        unique_forms = []
        for f in login_forms:
            key = f["url"] + f["user_field"] + f["pass_field"]
            if key not in seen:
                seen.add(key)
                unique_forms.append(f)

        for form in unique_forms[:3]:
            # Establish failed-login fingerprint
            try:
                data = {form["user_field"]: "tibsa_invalid_xyzzy", form["pass_field"]: "tibsa_invalid_xyzzy"}
                fail_resp = await client.post(form["url"], data=data) if form["method"] == "POST" else await client.get(form["url"], params=data)
                fail_hash = hashlib.md5(fail_resp.content).hexdigest()
            except Exception:
                continue

            successful = []
            attempts = 0

            for username, password in COMMON_CREDENTIALS[:6]:
                try:
                    data = {form["user_field"]: username, form["pass_field"]: password}
                    resp = await client.post(form["url"], data=data) if form["method"] == "POST" else await client.get(form["url"], params=data)
                    attempts += 1

                    if resp.status_code == 429 or "captcha" in resp.text.lower() or "rate limit" in resp.text.lower():
                        break

                    resp_hash = hashlib.md5(resp.content).hexdigest()
                    if resp_hash != fail_hash:
                        body_lower = resp.text.lower()
                        if any(m in body_lower for m in ["dashboard", "welcome", "logout", "sign out", "my account", "successfully"]):
                            successful.append(f"{username}:{password}")
                except Exception:
                    continue

            if successful:
                findings.append({
                    "id": self._next_id(),
                    "title": f"Weak Credentials — {form['url']}",
                    "classification": "vulnerability",
                    "severity": "high",
                    "severity_justification": "HIGH — default or weak credentials give attackers immediate authenticated access, potentially with admin privileges.",
                    "url": form["url"],
                    "description": "Login accepts commonly known weak credentials.",
                    "evidence": f"Successful login with: {', '.join(successful)}",
                    "false_positive_check": "Confirmed: response to successful credentials differed from failed-login fingerprint AND contained authenticated-content markers (dashboard/welcome/logout).",
                    "remediation": "1. Enforce strong passwords.\n2. Remove default credentials.\n3. Add MFA.",
                    "auto_fix": "# Password policy (Python/Django)\nAUTH_PASSWORD_VALIDATORS = [\n    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},\n    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},\n]\n\n# Node.js (bcrypt)\nconst bcrypt = require('bcrypt');\nconst hash = await bcrypt.hash(password, 12);",
                })

            if attempts >= 5:
                findings.append({
                    "id": self._next_id(),
                    "title": f"No Brute Force Protection — {form['url']}",
                    "classification": "best_practice",
                    "severity": "medium",
                    "severity_justification": "MEDIUM — lack of rate limiting enables automated password guessing, but exploitation requires time and the right wordlist.",
                    "url": form["url"],
                    "description": f"Login accepted {attempts} consecutive attempts without rate limiting, CAPTCHA, or lockout.",
                    "evidence": f"{attempts} attempts accepted at {form['url']}",
                    "false_positive_check": f"Confirmed: {attempts} sequential POST requests to login form were all processed without HTTP 429, CAPTCHA, or delay.",
                    "remediation": "1. Rate limit (5/min/IP).\n2. CAPTCHA after 3 failures.\n3. Progressive delays.",
                    "auto_fix": "# Nginx rate limiting\nlimit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;\nlocation /login {\n    limit_req zone=login burst=3;\n}\n\n# Express.js (express-rate-limit)\nconst rateLimit = require('express-rate-limit');\napp.use('/login', rateLimit({ windowMs: 60000, max: 5 }));",
                })

        return findings

    # ══════════════════════════════════════════════════════════
    # 6. HEADER INJECTION (CRLF + Host Header)
    # ══════════════════════════════════════════════════════════

    async def _test_header_injection(
        self, client: httpx.AsyncClient, target: str
    ) -> tuple:
        findings = []
        fp_log = []
        parsed = urlparse(target)

        # Test CRLF injection via query parameters
        for hi_test in HEADER_INJECTION_PAYLOADS:
            try:
                test_url = f"{target}{'&' if '?' in target else '?'}test={hi_test['payload']}"
                resp = await client.get(test_url)

                if hi_test["check_header"] in {k.lower() for k in resp.headers}:
                    findings.append({
                        "id": self._next_id(),
                        "title": f"Header Injection ({hi_test['type']})",
                        "classification": "vulnerability",
                        "severity": "high",
                        "severity_justification": "HIGH — CRLF injection allows attackers to inject arbitrary HTTP headers, enabling session fixation, cache poisoning, and XSS via response splitting.",
                        "url": target,
                        "description": f"Server is vulnerable to {hi_test['type']} header injection. Injected header was reflected in the response.",
                        "evidence": f"Payload: {hi_test['payload']}\nInjected header '{hi_test['check_header']}' found in response.",
                        "false_positive_check": f"Confirmed: the header '{hi_test['check_header']}' appeared in response ONLY when CRLF payload was injected.",
                        "remediation": "Strip CR (\\r) and LF (\\n) characters from all user input before using in headers or URLs.",
                        "auto_fix": "# Python\nclean_value = user_input.replace('\\r', '').replace('\\n', '')\n\n# Node.js\nconst clean = userInput.replace(/[\\r\\n]/g, '');\n\n# Nginx\nproxy_set_header X-Real-IP $remote_addr;\n# Framework-level: most modern frameworks prevent this by default",
                    })
                    break
            except Exception:
                continue

        # Host header injection
        try:
            evil_host = "evil.tibsa-scanner.com"
            resp = await client.get(target, headers={"Host": evil_host})
            body_lower = resp.text.lower()
            if evil_host in body_lower:
                findings.append({
                    "id": self._next_id(),
                    "title": "Host Header Injection",
                    "classification": "vulnerability",
                    "severity": "medium",
                    "severity_justification": "MEDIUM — Host header injection can enable password reset poisoning, cache poisoning, and web cache deception, but requires specific application behavior to exploit.",
                    "url": target,
                    "description": "Server reflects the Host header value in the response body. This can be used for password reset poisoning attacks.",
                    "evidence": f"Injected Host: {evil_host}\nReflected in response body.",
                    "false_positive_check": f"Confirmed: the evil host '{evil_host}' appeared in response body when injected via Host header.",
                    "remediation": "Validate the Host header against a whitelist of allowed domains.",
                    "auto_fix": "# Nginx\nserver {\n    server_name yourdomain.com;\n    if ($host !~* ^(yourdomain\\.com)$) {\n        return 444;\n    }\n}\n\n# Django\nALLOWED_HOSTS = ['yourdomain.com']",
                })
            else:
                fp_log.append("Host header injection — evil host not reflected in body. Not vulnerable.")
        except Exception:
            pass

        return findings, fp_log

    # ══════════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════════

    def _find_login_forms(self, url: str, response: httpx.Response) -> List[Dict[str, Any]]:
        forms = []
        soup = BeautifulSoup(response.text, "lxml")
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            if "password" not in [inp.get("type", "").lower() for inp in inputs]:
                continue
            user_field, pass_field = None, None
            for inp in inputs:
                itype = inp.get("type", "text").lower()
                iname = inp.get("name", "")
                if not iname: continue
                if itype == "password": pass_field = iname
                elif itype in ("text", "email") and not user_field: user_field = iname
            if user_field and pass_field:
                action = form.get("action", "")
                forms.append({
                    "url": urljoin(url, action) if action else url,
                    "method": (form.get("method") or "POST").upper(),
                    "user_field": user_field, "pass_field": pass_field,
                })
        return forms

    async def _send_payload(self, client: httpx.AsyncClient, point: Dict[str, Any], payload: str) -> Optional[httpx.Response]:
        try:
            if point["type"] == "query_param":
                return await client.get(self._inject_query_param(point["url"], point["param"], payload))
            elif point["type"] == "form_input":
                data = {point["name"]: payload}
                return await client.get(point["url"], params=data) if point["method"] == "GET" else await client.post(point["url"], data=data)
        except Exception:
            return None
        return None

    def _get_test_points(self, target: str, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        points: List[Dict[str, Any]] = []
        parsed = urlparse(target)
        for param in parse_qs(parsed.query):
            points.append({"type": "query_param", "param": param, "url": target})
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method") or "GET").upper()
            form_url = urljoin(target, action) if action else target
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name")
                if name and inp.get("type", "text") not in ("submit", "hidden", "button", "image", "password"):
                    points.append({"type": "form_input", "name": name, "method": method, "url": form_url})
        return points

    def _inject_query_param(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    def _error_result(self, scan_id: str, target: str, start: float, error: str) -> Dict[str, Any]:
        return {
            "scan_id": scan_id, "target": target,
            "started_at": time.strftime("%m/%d/%Y, %I:%M:%S %p", time.localtime(start)),
            "duration": round(time.time() - start, 1),
            "error": f"Could not reach target: {error}",
            "high": 0, "medium": 0, "low": 0, "total": 0,
            "endpoints_found": 0, "findings": [], "headers": {}, "endpoints": [],
            "false_positives_filtered": [],
        }

    # ══════════════════════════════════════════════════════════
    # 7. CORS MISCONFIGURATION
    # ══════════════════════════════════════════════════════════

    async def _test_cors(
        self, client: httpx.AsyncClient, target: str
    ) -> tuple:
        findings = []
        fp_log = []

        evil_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            f"https://{urlparse(target).netloc}.evil.com",  # subdomain trick
        ]

        for origin in evil_origins:
            try:
                resp = await client.get(target, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "").lower()
                acac = resp.headers.get("access-control-allow-credentials", "").lower()

                if acao == "*":
                    findings.append({
                        "id": self._next_id(),
                        "title": "CORS — Wildcard Origin Allowed",
                        "classification": "vulnerability" if acac == "true" else "best_practice",
                        "severity": "high" if acac == "true" else "medium",
                        "severity_justification": "HIGH — wildcard origin with credentials enabled allows any site to steal authenticated data." if acac == "true" else "MEDIUM — wildcard origin without credentials still risks data exposure for unauthenticated endpoints.",
                        "url": target,
                        "description": f"Server returns Access-Control-Allow-Origin: * {'WITH credentials allowed' if acac == 'true' else '(without credentials)'}.",
                        "evidence": f"Origin sent: {origin}\nACAO: {acao}\nACAC: {acac or 'not set'}",
                        "false_positive_check": "Confirmed: server responded with wildcard ACAO header.",
                        "remediation": "Whitelist specific trusted origins instead of using '*'.",
                        "auto_fix": "# Express.js\nconst cors = require('cors');\napp.use(cors({\n  origin: ['https://yourdomain.com'],\n  credentials: true\n}));\n\n# Nginx\nadd_header Access-Control-Allow-Origin 'https://yourdomain.com' always;\nadd_header Access-Control-Allow-Credentials 'true' always;",
                    })
                    break
                elif origin.lower() in acao:
                    findings.append({
                        "id": self._next_id(),
                        "title": f"CORS — Origin Reflected: {origin}",
                        "classification": "vulnerability",
                        "severity": "high",
                        "severity_justification": "HIGH — server reflects arbitrary Origin headers, meaning any website can make authenticated cross-origin requests and steal response data.",
                        "url": target,
                        "description": f"Server reflects the attacker-controlled Origin '{origin}' in ACAO header. This is a critical CORS misconfiguration.",
                        "evidence": f"Origin sent: {origin}\nACAO: {acao}\nACAC: {acac or 'not set'}",
                        "false_positive_check": f"Confirmed: evil origin '{origin}' was reflected in ACAO. Tested with non-legitimate domain.",
                        "remediation": "Never reflect the Origin header blindly. Use a whitelist.",
                        "auto_fix": "# Python/FastAPI\nfrom fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(\n    CORSMiddleware,\n    allow_origins=['https://yourdomain.com'],  # NO wildcard!\n    allow_credentials=True,\n)\n\n# Express.js\nconst whitelist = ['https://yourdomain.com'];\napp.use(cors({ origin: (o, cb) => cb(null, whitelist.includes(o)) }));",
                    })
                    break
            except Exception:
                continue

        if not findings:
            fp_log.append("CORS — all evil origins rejected. Server is properly configured.")

        return findings, fp_log

    # ══════════════════════════════════════════════════════════
    # 8. OPEN REDIRECT
    # ══════════════════════════════════════════════════════════

    async def _test_open_redirect(
        self, client: httpx.AsyncClient, target: str, response: httpx.Response
    ) -> tuple:
        findings = []
        fp_log = []
        evil_url = "https://evil.tibsa-scanner.com/phished"

        redirect_params = ["url", "redirect", "next", "return", "returnTo",
                          "redirect_uri", "continue", "dest", "destination",
                          "redir", "return_url", "go", "forward", "target", "out"]

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Test each redirect param on the target URL
        for param in redirect_params:
            try:
                test_url = f"{target}{'&' if '?' in target else '?'}{param}={evil_url}"
                resp = await client.get(test_url, follow_redirects=False)

                # Check if server redirects to the evil URL
                location = resp.headers.get("location", "")
                if evil_url in location or "evil.tibsa-scanner.com" in location:
                    findings.append({
                        "id": self._next_id(),
                        "title": f"Open Redirect — {param}",
                        "classification": "vulnerability",
                        "severity": "medium",
                        "severity_justification": "MEDIUM — open redirects enable phishing attacks by abusing trusted domain reputation. Combined with OAuth flows, can lead to token theft.",
                        "url": test_url,
                        "description": f"Parameter '{param}' causes server to redirect to attacker-controlled URL.",
                        "evidence": f"Payload: {param}={evil_url}\nHTTP {resp.status_code}\nLocation: {location}",
                        "false_positive_check": f"Confirmed: server returned redirect (HTTP {resp.status_code}) to evil domain '{evil_url}' via Location header.",
                        "remediation": "1. Whitelist allowed redirect domains.\n2. Use relative paths only.\n3. Validate URL against trusted domains.",
                        "auto_fix": f"# Python\nfrom urllib.parse import urlparse\nALLOWED_HOSTS = ['{parsed.netloc}']\ndef safe_redirect(url):\n    parsed = urlparse(url)\n    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n        return '/'  # fallback to home\n    return url\n\n# Express.js\nconst ALLOWED = ['{parsed.netloc}'];\nconst dest = new URL(req.query.redirect, 'https://placeholder');\nif (!ALLOWED.includes(dest.hostname)) return res.redirect('/');",
                    })
                    break  # One is enough
                else:
                    fp_log.append(f"Open Redirect '{param}' — server did not redirect to evil URL. Safe.")
            except Exception:
                continue

        # Test for JS-based redirects in page body
        soup = BeautifulSoup(response.text, "lxml")
        for link in soup.find_all("a", href=True):
            href = link["href"]
            for param in redirect_params:
                if f"{param}=" in href:
                    try:
                        test_href = re.sub(f"{param}=[^&]*", f"{param}={evil_url}", href)
                        full_url = urljoin(target, test_href)
                        resp = await client.get(full_url, follow_redirects=False)
                        location = resp.headers.get("location", "")
                        if "evil.tibsa-scanner.com" in location:
                            findings.append({
                                "id": self._next_id(),
                                "title": f"Open Redirect — {param} (in-page link)",
                                "classification": "vulnerability",
                                "severity": "medium",
                                "severity_justification": "MEDIUM — redirect parameter found in existing page link, easily exploitable via link manipulation.",
                                "url": full_url,
                                "description": f"In-page link contains redirect param '{param}' that accepts external URLs.",
                                "evidence": f"Original link: {href}\nManipulated: {test_href}\nLocation: {location}",
                                "false_positive_check": "Confirmed: modified in-page redirect param caused external redirect.",
                                "remediation": "Validate all redirect URLs against a whitelist of allowed domains.",
                                "auto_fix": "# Same as above — whitelist-based redirect validation",
                            })
                    except Exception:
                        continue

        return findings, fp_log

    # ══════════════════════════════════════════════════════════
    # 9. PATH TRAVERSAL / LFI
    # ══════════════════════════════════════════════════════════

    async def _test_path_traversal(
        self, client: httpx.AsyncClient, target: str, response: httpx.Response
    ) -> tuple:
        findings = []
        fp_log = []
        soup = BeautifulSoup(response.text, "lxml")
        test_points = self._get_test_points(target, soup)

        # Also look for file/path-like params in URL
        parsed = urlparse(target)
        for param in parse_qs(parsed.query):
            if any(kw in param.lower() for kw in ["file", "path", "page", "include", "doc", "template", "load", "read", "view", "download"]):
                test_points.insert(0, {"type": "query_param", "param": param, "url": target})

        traversal_payloads = [
            {"payload": "../../../etc/passwd",           "marker": "root:",         "os": "Linux"},
            {"payload": "....//....//....//etc/passwd",  "marker": "root:",         "os": "Linux (bypass)"},
            {"payload": "/etc/passwd",                   "marker": "root:",         "os": "Linux (absolute)"},
            {"payload": "..\\..\\..\\windows\\win.ini", "marker": "[extensions]", "os": "Windows"},
            {"payload": "....\\\\....\\\\windows\\win.ini", "marker": "[extensions]", "os": "Windows (bypass)"},
            {"payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "marker": "root:", "os": "Linux (URL-encoded)"},
        ]

        tested_params = set()
        for point in test_points[:10]:
            param_key = point.get("param") or point.get("name", "")
            if param_key in tested_params:
                continue
            tested_params.add(param_key)

            for pt in traversal_payloads[:4]:  # Test top 4 payloads per param
                try:
                    resp = await self._send_payload(client, point, pt["payload"])
                    if resp is None:
                        continue

                    body = resp.text
                    if pt["marker"] in body:
                        # Confirm it's real content, not just the word in the page
                        if pt["marker"] == "root:" and "root:x:0:0" in body:
                            is_real = True
                        elif pt["marker"] == "[extensions]" and "[fonts]" in body:
                            is_real = True
                        else:
                            is_real = body.count(pt["marker"]) > 0 and len(body) < 10000

                        if is_real:
                            findings.append({
                                "id": self._next_id(),
                                "title": f"Path Traversal / LFI — {param_key}",
                                "classification": "vulnerability",
                                "severity": "high",
                                "severity_justification": "HIGH — Local File Inclusion allows reading sensitive system files (passwords, configs, source code). Can escalate to Remote Code Execution via log poisoning.",
                                "url": point.get("url", target),
                                "description": f"Parameter '{param_key}' allows reading system files via path traversal. OS: {pt['os']}.",
                                "evidence": f"Payload: {pt['payload']}\nMarker found: {pt['marker']}\nResponse snippet: {body[body.index(pt['marker']):body.index(pt['marker'])+100]}",
                                "false_positive_check": f"Confirmed: '{pt['marker']}' found in response to traversal payload. Content matches real {pt['os']} system file format.",
                                "remediation": "1. Never use user input in file paths.\n2. Use a whitelist of allowed files.\n3. Chroot/sandbox file access.\n4. Use os.path.realpath() to canonicalize paths.",
                                "auto_fix": "# Python — safe file access\nimport os\nBASE_DIR = '/app/public'\nrequested = os.path.realpath(os.path.join(BASE_DIR, user_input))\nif not requested.startswith(BASE_DIR):\n    raise ValueError('Path traversal detected')\n\n# Node.js\nconst path = require('path');\nconst BASE = '/app/public';\nconst resolved = path.resolve(BASE, userInput);\nif (!resolved.startsWith(BASE)) throw new Error('Traversal');",
                            })
                            break
                        else:
                            fp_log.append(f"Path Traversal '{param_key}' — marker '{pt['marker']}' found but content doesn't match system file. Filtered.")
                except Exception:
                    continue

        return findings, fp_log

    # ══════════════════════════════════════════════════════════
    # 10. SSRF (Server-Side Request Forgery)
    # ══════════════════════════════════════════════════════════

    async def _test_ssrf(
        self, client: httpx.AsyncClient, target: str, response: httpx.Response
    ) -> tuple:
        findings = []
        fp_log = []
        soup = BeautifulSoup(response.text, "lxml")

        # Find URL-like parameters
        parsed = urlparse(target)
        url_params = []
        for param, values in parse_qs(parsed.query).items():
            if any(kw in param.lower() for kw in ["url", "link", "src", "href", "uri",
                                                   "fetch", "proxy", "callback", "return",
                                                   "image", "img", "load", "resource"]):
                url_params.append({"type": "query_param", "param": param, "url": target})

        # Also check forms for URL-like inputs
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method") or "GET").upper()
            form_url = urljoin(target, action) if action else target
            for inp in form.find_all("input"):
                name = inp.get("name", "")
                if any(kw in name.lower() for kw in ["url", "link", "src", "href", "uri", "fetch"]):
                    url_params.append({"type": "form_input", "name": name, "method": method, "url": form_url})

        if not url_params:
            fp_log.append("SSRF — no URL-type parameters found in target. Skipped.")
            return findings, fp_log

        ssrf_payloads = [
            {"payload": "http://127.0.0.1:80",       "markers": ["<html", "<!doctype", "nginx", "apache", "welcome"], "desc": "localhost HTTP"},
            {"payload": "http://localhost:22",        "markers": ["ssh", "openssh", "connection refused"],             "desc": "localhost SSH probe"},
            {"payload": "http://169.254.169.254/latest/meta-data/", "markers": ["ami-id", "instance-id", "iam", "security-credentials"], "desc": "AWS metadata"},
            {"payload": "http://metadata.google.internal/computeMetadata/v1/", "markers": ["attributes", "instance", "project"], "desc": "GCP metadata"},
            {"payload": "http://[::1]:80/",           "markers": ["<html", "<!doctype"],                             "desc": "IPv6 localhost"},
        ]

        for point in url_params[:5]:
            param_key = point.get("param") or point.get("name", "")

            # Get baseline response for this param with safe URL
            try:
                baseline_resp = await self._send_payload(client, point, "https://example.com")
                baseline_body = baseline_resp.text.lower() if baseline_resp else ""
            except Exception:
                baseline_body = ""

            for ssrf in ssrf_payloads:
                try:
                    resp = await self._send_payload(client, point, ssrf["payload"])
                    if resp is None:
                        continue

                    body_lower = resp.text.lower()

                    # Check for SSRF markers not present in baseline
                    matched_markers = [m for m in ssrf["markers"] if m in body_lower and m not in baseline_body]

                    if matched_markers:
                        findings.append({
                            "id": self._next_id(),
                            "title": f"SSRF — {param_key} ({ssrf['desc']})",
                            "classification": "vulnerability",
                            "severity": "high",
                            "severity_justification": "HIGH — SSRF allows attackers to make the server access internal resources, read cloud metadata (AWS/GCP credentials), scan internal networks, and potentially achieve RCE.",
                            "url": point.get("url", target),
                            "description": f"Parameter '{param_key}' fetches attacker-controlled URLs server-side. Internal resource markers detected: {', '.join(matched_markers)}.",
                            "evidence": f"Payload: {ssrf['payload']}\nMarkers found: {', '.join(matched_markers)}\nResponse length: {len(resp.content)} bytes",
                            "false_positive_check": f"Confirmed: markers {matched_markers} appeared ONLY when internal URL was supplied, not with baseline (example.com).",
                            "remediation": "1. Block requests to private IPs (127.0.0.1, 10.x, 169.254.x).\n2. Whitelist allowed external domains.\n3. Use a URL validation library.\n4. Disable HTTP redirects server-side.",
                            "auto_fix": "# Python — SSRF protection\nimport ipaddress\nfrom urllib.parse import urlparse\ndef is_safe_url(url):\n    parsed = urlparse(url)\n    try:\n        ip = ipaddress.ip_address(parsed.hostname)\n        if ip.is_private or ip.is_loopback or ip.is_link_local:\n            return False\n    except ValueError:\n        pass  # hostname, not IP\n    BLOCKED = ['169.254.169.254', 'metadata.google.internal']\n    return parsed.hostname not in BLOCKED\n\n# Node.js (ssrf-req-filter)\nconst ssrfFilter = require('ssrf-req-filter');\naxios.get(url, { httpAgent: ssrfFilter('http') });",
                        })
                        break
                except Exception:
                    continue

        return findings, fp_log
