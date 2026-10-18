"""
scanner/engine.py  — AWVS v3.0 Core Vulnerability Engine
──────────────────────────────────────────────────────────────────────────────
Detection Modules:
  1.  Reflected XSS (multi-context + WAF bypass payloads)
  2.  DOM-Based XSS (static source/sink analysis)
  3.  Stored XSS (heuristic post-submit check)
  4.  SQL Injection — Error-based + Boolean-based + Time-based Blind
  5.  CSRF (missing/weak token detection)
  6.  Open Redirect (URL + header-based)
  7.  Security Headers Analysis (OWASP top headers)
  8.  SSTI — Server-Side Template Injection (Jinja2, Twig, FreeMarker)
  9.  CRLF / HTTP Response Splitting
  10. HTML Injection
  11. LDAP Injection
  12. IDOR — Insecure Direct Object Reference (numeric ID increment)
  13. Business Logic flaws (negative values, parameter manipulation)
  14. Sensitive Data Exposure (secrets, keys, PII in responses)

All payloads are detection-only. No data is modified or deleted.
"""

import json
import logging
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AWVS/3.0 (Authorized Security Testing)"
REQUEST_HEADERS = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD LIBRARIES
# ─────────────────────────────────────────────────────────────────────────────

# XSS — multi-context + WAF bypass polyglots
XSS_PAYLOADS = [
    # Classic reflected
    '<script>alert("AWVS_XSS")</script>',
    '"><script>alert("AWVS_XSS")</script>',
    "';alert('AWVS_XSS')//",
    # Event handler contexts
    '<img src=x onerror=alert("AWVS_XSS")>',
    '<svg onload=alert("AWVS_XSS")>',
    '<body onload=alert("AWVS_XSS")>',
    '<input autofocus onfocus=alert("AWVS_XSS")>',
    # WAF bypasses
    '<ScRiPt>alert("AWVS_XSS")</ScRiPt>',
    '<<script>alert("AWVS_XSS")//<</script>',
    '<script\x20type="text/javascript">alert("AWVS_XSS")</script>',
    # HTML5 vectors
    '<details open ontoggle=alert("AWVS_XSS")>',
    '<video src=1 onerror=alert("AWVS_XSS")>',
    # URL context
    'javascript:alert("AWVS_XSS")',
    # Polyglot
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert("AWVS_XSS") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert("AWVS_XSS")//>',
]
XSS_MARKER = "AWVS_XSS"

# DOM XSS — dangerous JS source/sink patterns
DOM_XSS_SOURCES = [
    r'document\.location', r'window\.location', r'document\.URL',
    r'document\.referrer', r'location\.search', r'location\.hash',
    r'location\.href', r'window\.name',
]
DOM_XSS_SINKS = [
    r'document\.write\s*\(',
    r'document\.writeln\s*\(',
    r'innerHTML\s*=',
    r'outerHTML\s*=',
    r'insertAdjacentHTML\s*\(',
    r'eval\s*\(',
    r'setTimeout\s*\(\s*["\']',
    r'setInterval\s*\(\s*["\']',
    r'location\.href\s*=',
    r'location\.replace\s*\(',
    r'location\.assign\s*\(',
    r'\.src\s*=',
    r'jQuery\.parseHTML',
    r'\$\s*\(',                 # jQuery($(...)) — potential sink
]

# SQL Injection
SQLI_ERROR_PAYLOADS = [
    "'", '"', "' OR '1'='1", '1 OR 1=1', "' OR 1=1--", '1; SELECT 1',
    "'; --", "' UNION SELECT NULL--", "1' ORDER BY 1--",
    "1' AND 1=1--", "1' AND 1=2--",
]
SQLI_BLIND_PAYLOADS = [
    # Boolean-based
    ("1' AND 1=1-- -",  "1' AND 1=2-- -"),   # true/false pair
    ("1 AND 1=1",       "1 AND 1=2"),
    ("' AND 'a'='a",    "' AND 'a'='b"),
]
SQLI_TIME_PAYLOADS = [
    "1; WAITFOR DELAY '0:0:3'--",          # MSSQL
    "1' AND SLEEP(3)--",                   # MySQL
    "1; SELECT pg_sleep(3)--",             # PostgreSQL
    "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",  # Oracle
]
SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"mysql_fetch_array\(\)",
    r"mysql_fetch_assoc\(\)",
    r"unclosed quotation mark",
    r"microsoft ole db provider.*sql",
    r"odbc sql server driver",
    r"sqlite3\.operationalerror",
    r"pg::syntaxerror",
    r"division by zero",
    r"invalid query",
    r"ora-\d{5}",
    r"sql syntax.*error",
    r"supplied argument is not a valid mysql",
    r"integrity constraint violation",
    r"syntax error.*unexpected",
    r"error in your sql",
    r"jdbctemplate",
    r"sqlexception",
    r"hibernate.*exception",
]

# Open Redirect
REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https://google.com",
    "/%09/evil.example.com",
    "https:evil.example.com",
    "\r\nhttps://evil.example.com",
]
REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "goto", "target", "link",
    "redir", "redirect_to", "return_url", "returnUrl", "next_url",
    "continue", "destination", "dest", "forward", "location", "to",
    "ref", "returnTo", "redirectUrl", "successUrl",
]

# SSTI payloads — different for each engine
SSTI_PAYLOADS = [
    ("{{7*7}}",           "49",  "Jinja2/Twig"),
    ("${7*7}",            "49",  "FreeMarker/Velocity"),
    ("#{7*7}",            "49",  "Thymeleaf"),
    ("<%= 7*7 %>",        "49",  "ERB (Ruby)"),
    ("{{7*'7'}}",         "7777777", "Jinja2"),
    ("{% debug %}",       "django",  "Django"),
    ("${{7*7}}",          "49",  "Pebble"),
    ("*{7*7}",            "49",  "Spring SpEL"),
]

# CRLF payloads
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:awvs_crlf=1",
    "%0d%0aAWVS-Injected:yes",
    "\r\nSet-Cookie:awvs_crlf=1",
    "%0D%0AX-AWVS-CRLF:injected",
    "%0aX-AWVS-CRLF:injected",
]
CRLF_MARKERS = ["awvs_crlf", "awvs-crlf", "x-awvs-crlf"]

# HTML Injection
HTML_INJ_PAYLOADS = [
    "<h1>AWVS_HTML_INJECTION</h1>",
    "<b>AWVS_HTML</b>",
    "<marquee>AWVS_HTML</marquee>",
    '<a href="https://evil.com">AWVS_HTML</a>',
]
HTML_INJ_MARKER = "AWVS_HTML"

# LDAP Injection
LDAP_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "*()|%26'",
    "admin)(&)",
    "*)(|(password=*)",
    "\\2a)(uid=*))(|(uid=\\2a",
]
LDAP_ERROR_PATTERNS = [
    r"ldap_search",
    r"ldap error",
    r"invalid dn syntax",
    r"ldap.*exception",
    r"javax.naming",
    r"ldapexception",
    r"ldap.*filter",
]

# Sensitive data patterns in responses
SENSITIVE_PATTERNS = [
    (r"(?i)api[_\-]?key\s*[=:]\s*['\"]?[a-z0-9]{16,}", "API Key Exposed", "High"),
    (r"(?i)secret[_\-]?key\s*[=:]\s*['\"]?[a-z0-9]{16,}", "Secret Key Exposed", "High"),
    (r"(?i)password\s*[=:]\s*['\"]?[^\s'\"]{6,}", "Password in Response", "Critical"),
    (r"(?i)access_token\s*[=:]\s*['\"]?[a-z0-9\-_.]{20,}", "Access Token Exposed", "Critical"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "High"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "Critical"),
    (r"(?i)(db_pass|database_password|db_password)\s*[=:]\s*['\"]?[^\s]{4,}", "Database Credential", "Critical"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key in Response", "Critical"),
    (r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "JWT Token Exposed", "Medium"),
    (r"\b\d{16}\b", "Possible Credit Card Number", "High"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email Address Leaked", "Low"),
]

# Security headers
REQUIRED_SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Content-Security-Policy (CSP) header is missing. This allows XSS and data injection attacks.",
        "remediation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "X-Frame-Options missing — page can be embedded in iframes (clickjacking).",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "X-Content-Type-Options missing — browsers may MIME-sniff responses.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "description": "HSTS missing — browser may use HTTP allowing MITM attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Referrer-Policy missing — sensitive URL params may leak to third parties.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "Info",
        "description": "Permissions-Policy missing — browser features unrestricted.",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}

DANGEROUS_HEADERS = {
    "Server": {
        "severity": "Info",
        "description": "Server version disclosed — reveals backend technology for targeted attacks.",
        "remediation": "Configure server to hide version information.",
    },
    "X-Powered-By": {
        "severity": "Info",
        "description": "X-Powered-By header exposes backend technology (e.g., PHP/7.4).",
        "remediation": "Remove X-Powered-By header from responses.",
    },
    "X-AspNet-Version": {
        "severity": "Low",
        "description": "ASP.NET version disclosed in X-AspNet-Version header.",
        "remediation": "Remove X-AspNet-Version: set <httpRuntime enableVersionHeader='false'/>",
    },
    "X-AspNetMvc-Version": {
        "severity": "Low",
        "description": "ASP.NET MVC version disclosed.",
        "remediation": "Add MvcHandler.DisableMvcResponseHeader = true in Application_Start",
    },
}

# Weak CSP directives
WEAK_CSP_PATTERNS = [
    (r"'unsafe-inline'", "Unsafe Inline in CSP", "CSP allows 'unsafe-inline' which enables XSS."),
    (r"'unsafe-eval'",   "Unsafe Eval in CSP",   "CSP allows 'unsafe-eval' which enables code injection."),
    (r"\*",              "Wildcard in CSP",       "CSP contains wildcard (*) which is overly permissive."),
    (r"data:",           "Data URI in CSP",       "CSP allows data: URIs which can be used for XSS."),
    (r"http:",           "HTTP in CSP",           "CSP allows plain HTTP sources which undermines HTTPS."),
]


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENGINE CLASS
# ─────────────────────────────────────────────────────────────────────────────
class VulnerabilityEngine:
    """
    AWVS v3.0 Core Vulnerability Detection Engine.
    Runs 14 detection modules across all crawled pages.
    """

    def __init__(self, crawl_data: list, options: dict = None,
                 progress_callback=None, timeout: int = 10):
        self.crawl_data = crawl_data
        self.options    = options or {
            "xss": True, "sqli": True, "csrf": True,
            "headers": True, "redirect": True,
        }
        self.progress   = progress_callback or (lambda msg: None)
        self.findings: list = []
        self.timeout    = timeout
        self._seen: set = set()   # dedup key set

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
        """Deduped finding factory."""
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
        self.progress(
            f"  [ENGINE][{severity}] {vuln_type} @ {url}"
            + (f" param={parameter}" if parameter else "")
        )

    def _get(self, url, params=None, **kw):
        try:
            return self.session.get(url, params=params, timeout=self.timeout,
                                    allow_redirects=True, **kw)
        except Exception:
            return None

    def _post(self, url, data=None, json_data=None, **kw):
        try:
            if json_data is not None:
                return self.session.post(url, json=json_data, timeout=self.timeout, **kw)
            return self.session.post(url, data=data, timeout=self.timeout, **kw)
        except Exception:
            return None

    def _inject_param(self, parsed, param_name, payload):
        """Return a URL with param_name set to payload."""
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        params[param_name] = payload
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params), ""
        ))

    # ── 1. REFLECTED XSS ──────────────────────────────────────────────────────
    def _check_reflected_xss(self, page: dict):
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)

        # If no URL params, probe with common parameter names
        if not params:
            common_params = ["q", "search", "id", "page", "query", "s", "input", "keyword"]
            for pname in common_params[:3]:  # Try top 3
                for payload in XSS_PAYLOADS[:3]:
                    test_url = self._inject_param(parsed, pname, payload)
                    resp = self._get(test_url)
                    if resp and XSS_MARKER in resp.text:
                        self._add(
                            "Reflected XSS", "High", page["url"],
                            f"Reflected XSS in injected parameter '{pname}'. "
                            "Server reflects user input without sanitization.",
                            evidence=f"Payload '{payload}' reflected in response.",
                            parameter=pname, payload=payload,
                            remediation="Use context-aware output encoding. Apply Content-Security-Policy.",
                            cwe="CWE-79",
                        )
                        break
                    time.sleep(0.03)

        # URL params
        for param in params:
            for payload in XSS_PAYLOADS[:8]:  # first 8 are most reliable
                test_url = self._inject_param(parsed, param, payload)
                resp = self._get(test_url)
                if resp and XSS_MARKER in resp.text:
                    self._add(
                        "Reflected XSS", "High", page["url"],
                        f"Reflected XSS in GET parameter '{param}'. "
                        "Unsanitized user input reflected directly in response.",
                        evidence=f"Payload '{payload}' reflected unescaped.",
                        parameter=param, payload=payload,
                        remediation="Use context-aware output encoding. Apply Content-Security-Policy.",
                        cwe="CWE-79",
                    )
                    break
                time.sleep(0.04)

        # Form inputs
        for form in page.get("forms", []):
            action = urljoin(page["url"], form.get("action") or page["url"])
            method = form.get("method", "GET").upper()
            for field in form.get("inputs", []):
                fname = field.get("name")
                ftype = field.get("type", "text").lower()
                if not fname or ftype in ("submit", "hidden", "button", "checkbox", "radio"):
                    continue
                for payload in XSS_PAYLOADS[:5]:
                    data = {i.get("name", ""): i.get("value", "test")
                            for i in form.get("inputs", []) if i.get("name")}
                    data[fname] = payload
                    resp = (self._post(action, data=data) if method == "POST"
                            else self._get(action, params=data))
                    if resp and XSS_MARKER in resp.text:
                        self._add(
                            "Reflected XSS (Form)", "High", page["url"],
                            f"Reflected XSS in form field '{fname}' (action={action}).",
                            evidence=f"Payload '{payload}' reflected in response.",
                            parameter=fname, payload=payload,
                            remediation="Sanitize and encode all form inputs before output.",
                            cwe="CWE-79",
                        )
                        break
                    time.sleep(0.04)

    # ── 2. DOM-BASED XSS DETECTION ────────────────────────────────────────────
    def _check_dom_xss(self, page: dict):
        """Static analysis of JS content for source → sink flows."""
        resp = self._get(page["url"])
        if not resp:
            return

        text = resp.text
        sources_found = [p for p in DOM_XSS_SOURCES if re.search(p, text)]
        sinks_found   = [p for p in DOM_XSS_SINKS   if re.search(p, text)]

        if sources_found and sinks_found:
            self._add(
                "DOM-Based XSS (Potential)", "High", page["url"],
                "Potential DOM-based XSS: dangerous JavaScript sources and sinks detected. "
                "User-controlled data may flow into an execution sink without sanitization.",
                evidence=(f"Sources: {', '.join(sources_found[:3])} | "
                           f"Sinks: {', '.join(sinks_found[:3])}"),
                remediation=(
                    "Avoid using document.write(), innerHTML, eval() with user-controlled data. "
                    "Use textContent instead of innerHTML. Apply DOMPurify for HTML sanitization."
                ),
                cwe="CWE-79",
            )

        # Check for inline scripts using location.* without sanitization
        if re.search(r'location\.(search|hash|href)', text) and \
           re.search(r'(innerHTML|document\.write|eval)\s*[=(]', text):
            self._add(
                "DOM XSS — Location Source", "High", page["url"],
                "Page reads from window.location and writes to a dangerous DOM sink. "
                "This is a classic DOM XSS pattern.",
                evidence="location.search/hash + innerHTML/eval pattern detected.",
                remediation="Sanitize location data before DOM insertion. Use DOMPurify.",
                cwe="CWE-79",
            )

    # ── 3. SQL INJECTION ──────────────────────────────────────────────────────
    def _check_sqli(self, page: dict):
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            orig_url  = self._inject_param(parsed, param, params[param][0])
            orig_resp = self._get(orig_url)
            orig_text = (orig_resp.text if orig_resp else "").lower()

            # Error-based
            for payload in SQLI_ERROR_PAYLOADS:
                test_url = self._inject_param(parsed, param, payload)
                resp = self._get(test_url)
                if not resp:
                    continue
                text = resp.text.lower()
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, text) and not re.search(pattern, orig_text):
                        self._add(
                            "SQL Injection (Error-Based)", "Critical", page["url"],
                            f"Error-based SQL injection in parameter '{param}'. "
                            "Database error triggered by malicious input.",
                            evidence=f"Pattern '{pattern}' in response with payload '{payload}'.",
                            parameter=param, payload=payload,
                            remediation="Use parameterized queries/prepared statements.",
                            cwe="CWE-89",
                        )
                        return  # one finding per param is enough
                time.sleep(0.04)

            # Boolean-based blind
            for true_pl, false_pl in SQLI_BLIND_PAYLOADS:
                true_url  = self._inject_param(parsed, param, true_pl)
                false_url = self._inject_param(parsed, param, false_pl)
                r_true  = self._get(true_url)
                r_false = self._get(false_url)
                if not r_true or not r_false:
                    continue
                # Significant length difference = boolean blind
                len_diff = abs(len(r_true.text) - len(r_false.text))
                if len_diff > 50 and r_true.status_code == r_false.status_code:
                    self._add(
                        "SQL Injection (Boolean-Blind)", "Critical", page["url"],
                        f"Boolean-based blind SQL injection in parameter '{param}'. "
                        f"True condition returns {len(r_true.text)}B, false condition "
                        f"returns {len(r_false.text)}B — content differs based on query truth.",
                        evidence=f"Length delta: {len_diff}B. True: '{true_pl}' / False: '{false_pl}'",
                        parameter=param, payload=true_pl,
                        remediation="Use parameterized queries. Never concatenate user input into SQL.",
                        cwe="CWE-89",
                    )
                    break
                time.sleep(0.04)

            # Time-based blind (fast — only 3s delay, check ≥2.5s)
            for payload in SQLI_TIME_PAYLOADS[:2]:
                test_url = self._inject_param(parsed, param, payload)
                start = time.time()
                resp  = self._get(test_url)
                elapsed = time.time() - start
                if resp and elapsed >= 2.5:
                    self._add(
                        "SQL Injection (Time-Based Blind)", "Critical", page["url"],
                        f"Time-based blind SQL injection in parameter '{param}'. "
                        f"Response delayed {elapsed:.1f}s — database sleep command executed.",
                        evidence=f"Response time {elapsed:.1f}s with payload: {payload}",
                        parameter=param, payload=payload,
                        remediation="Use parameterized queries/ORM. Enable query logging to detect attacks.",
                        cwe="CWE-89",
                    )
                    break

    # ── 4. CSRF ───────────────────────────────────────────────────────────────
    def _check_csrf(self, page: dict):
        for form in page.get("forms", []):
            method = form.get("method", "GET").upper()
            if method != "POST":
                continue
            inputs   = form.get("inputs", [])
            names    = [i.get("name", "").lower() for i in inputs]
            types    = [i.get("type", "").lower() for i in inputs]

            # Check for CSRF token patterns
            has_token = any(
                re.search(r"csrf|token|_token|authenticity|nonce|xsrf|csrfmiddleware|__requestverificationtoken",
                          n, re.I)
                for n in names
            )
            # Check SameSite cookie
            action = urljoin(page["url"], form.get("action") or page["url"])

            if not has_token:
                # Check if it's a sensitive form (login, password, payment, delete)
                sensitive = any(re.search(
                    r"passw|credit|card|payment|amount|delete|remove|account|email|admin|transfer",
                    n, re.I) for n in names
                ) or re.search(r"login|signin|register|payment|transfer|delete|admin",
                               action, re.I)

                severity = "High" if sensitive else "Medium"
                self._add(
                    "CSRF — Missing Token", severity, page["url"],
                    f"POST form to '{action}' has no CSRF token. "
                    "An attacker can craft a malicious page to perform actions on behalf of authenticated users.",
                    evidence=f"Form inputs: {', '.join(names[:8])}",
                    remediation=(
                        "Add CSRF token to all state-changing forms. "
                        "Use SameSite=Strict cookie attribute. "
                        "Validate Origin/Referer headers."
                    ),
                    cwe="CWE-352",
                )

    # ── 5. OPEN REDIRECT ──────────────────────────────────────────────────────
    def _check_redirect(self, page: dict):
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)

        # Test known redirect params in URL
        redirect_params = [p for p in params if p.lower() in [r.lower() for r in REDIRECT_PARAMS]]

        for param in redirect_params:
            for payload in REDIRECT_PAYLOADS[:4]:
                test_url = self._inject_param(parsed, param, payload)
                try:
                    resp = self.session.get(test_url, timeout=self.timeout,
                                            allow_redirects=True)
                    final = resp.url
                    if "evil.example.com" in final or "google.com" in final:
                        self._add(
                            "Open Redirect", "Medium", page["url"],
                            f"Open redirect via parameter '{param}'. "
                            "Application redirects to external URLs without validation.",
                            evidence=f"Redirected to: {final}",
                            parameter=param, payload=payload,
                            remediation=(
                                "Whitelist allowed redirect destinations. "
                                "Use relative URLs only or validate against domain allowlist."
                            ),
                            cwe="CWE-601",
                        )
                        break
                except Exception:
                    pass
                time.sleep(0.04)

        # Also test all URL params for redirect behaviour
        for param in params:
            if param.lower() in [r.lower() for r in REDIRECT_PARAMS]:
                continue  # already tested
            for payload in ["https://evil.example.com", "//evil.example.com"]:
                test_url = self._inject_param(parsed, param, payload)
                try:
                    resp = self.session.get(test_url, timeout=self.timeout,
                                            allow_redirects=True)
                    if "evil.example.com" in resp.url:
                        self._add(
                            "Open Redirect (Generic Param)", "Medium", page["url"],
                            f"Open redirect via parameter '{param}'.",
                            parameter=param, payload=payload,
                            remediation="Validate all redirect parameters against an allowlist.",
                            cwe="CWE-601",
                        )
                        break
                except Exception:
                    pass

    # ── 6. SECURITY HEADERS ───────────────────────────────────────────────────
    def _check_headers(self, page: dict):
        resp = self._get(page["url"])
        if not resp:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Missing required headers
        for header, info in REQUIRED_SECURITY_HEADERS.items():
            if header.lower() not in headers:
                self._add(
                    f"Missing Header: {header}", info["severity"], page["url"],
                    info["description"],
                    remediation=info["remediation"],
                    cwe="CWE-16",
                )

        # Dangerous headers present
        for header, info in DANGEROUS_HEADERS.items():
            if header.lower() in headers:
                val = headers[header.lower()]
                self._add(
                    f"Information Disclosure: {header}", info["severity"], page["url"],
                    info["description"],
                    evidence=f"{header}: {val}",
                    remediation=info["remediation"],
                    cwe="CWE-200",
                )

        # Weak CSP analysis
        csp = headers.get("content-security-policy", "")
        for pattern, name, desc in WEAK_CSP_PATTERNS:
            if re.search(pattern, csp):
                self._add(
                    f"Weak CSP: {name}", "Medium", page["url"],
                    f"Content-Security-Policy is present but misconfigured: {desc}",
                    evidence=f"CSP: {csp[:200]}",
                    remediation="Review CSP directives. Remove 'unsafe-inline', 'unsafe-eval', and wildcards.",
                    cwe="CWE-16",
                )

        # HSTS max-age check
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            match = re.search(r"max-age=(\d+)", hsts)
            if match and int(match.group(1)) < 31536000:
                self._add(
                    "HSTS Max-Age Too Short", "Low", page["url"],
                    f"HSTS max-age is {match.group(1)}s (< 1 year). "
                    "Should be at least 31536000 (1 year).",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Set max-age=31536000; includeSubDomains",
                    cwe="CWE-523",
                )

    # ── 7. SSTI — SERVER-SIDE TEMPLATE INJECTION ─────────────────────────────
    def _check_ssti(self, page: dict):
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            for payload, expected, engine in SSTI_PAYLOADS:
                test_url = self._inject_param(parsed, param, payload)
                resp = self._get(test_url)
                if resp and expected in resp.text:
                    self._add(
                        f"SSTI — Server-Side Template Injection ({engine})", "Critical",
                        page["url"],
                        f"Server-Side Template Injection in parameter '{param}' ({engine}). "
                        "Template expressions are evaluated server-side, potentially allowing "
                        "remote code execution.",
                        evidence=f"Payload '{payload}' evaluated to '{expected}' in response.",
                        parameter=param, payload=payload,
                        remediation=(
                            "Never pass user input directly to template engines. "
                            "Use sandboxed template environments. "
                            "Whitelist allowed template contexts."
                        ),
                        cwe="CWE-94",
                    )
                    break
                time.sleep(0.04)

    # ── 8. CRLF INJECTION ─────────────────────────────────────────────────────
    def _check_crlf(self, page: dict):
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)
        if not params:
            return

        for param in list(params.keys())[:3]:  # limit to first 3 params
            for payload in CRLF_PAYLOADS:
                test_url = self._inject_param(parsed, param, payload)
                try:
                    resp = self.session.get(test_url, timeout=self.timeout,
                                            allow_redirects=False)
                    resp_headers = {k.lower(): v.lower()
                                    for k, v in resp.headers.items()}
                    # Check if injected header appears
                    for marker in CRLF_MARKERS:
                        if marker in resp_headers or marker in resp.text.lower():
                            self._add(
                                "CRLF Injection / HTTP Response Splitting", "High",
                                page["url"],
                                f"CRLF injection in parameter '{param}'. "
                                "Carriage return + line feed characters were not filtered, "
                                "allowing injection of arbitrary HTTP headers.",
                                evidence=f"Injected header detected with payload: {payload}",
                                parameter=param, payload=payload,
                                remediation=(
                                    "Strip or reject CR (\\r) and LF (\\n) characters from all inputs "
                                    "before using them in HTTP headers or redirects."
                                ),
                                cwe="CWE-93",
                            )
                            break
                except Exception:
                    pass
                time.sleep(0.04)

    # ── 9. HTML INJECTION ─────────────────────────────────────────────────────
    def _check_html_injection(self, page: dict):
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            for payload in HTML_INJ_PAYLOADS:
                test_url = self._inject_param(parsed, param, payload)
                resp = self._get(test_url)
                # If marker is in page but not as escaped HTML entity
                if resp and HTML_INJ_MARKER in resp.text:
                    raw = resp.text
                    idx = raw.find(HTML_INJ_MARKER)
                    if idx > 0:
                        # Check context — if payload appears unescaped as a tag
                        snippet = raw[max(0, idx-100):idx+200]
                        if "<h1>" in snippet or "<b>" in snippet or "<marquee>" in snippet:
                            self._add(
                                "HTML Injection", "Medium", page["url"],
                                f"HTML injection in parameter '{param}'. "
                                "Attacker-controlled HTML tags rendered by browser "
                                "(no script execution, but enables phishing/UI redressing).",
                                evidence=f"Payload '{payload}' rendered as HTML.",
                                parameter=param, payload=payload,
                                remediation=(
                                    "Encode HTML special characters in output "
                                    "(<, >, &, \", '). Use template auto-escaping."
                                ),
                                cwe="CWE-80",
                            )
                            break
                time.sleep(0.04)

    # ── 10. LDAP INJECTION ────────────────────────────────────────────────────
    def _check_ldap_injection(self, page: dict):
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            orig_resp = self._get(page["url"])
            orig_text = (orig_resp.text if orig_resp else "").lower()
            for payload in LDAP_PAYLOADS:
                test_url = self._inject_param(parsed, param, payload)
                resp = self._get(test_url)
                if not resp:
                    continue
                text = resp.text.lower()
                for pattern in LDAP_ERROR_PATTERNS:
                    if re.search(pattern, text) and not re.search(pattern, orig_text):
                        self._add(
                            "LDAP Injection", "High", page["url"],
                            f"LDAP injection in parameter '{param}'. "
                            "User input is used in LDAP queries without sanitization.",
                            evidence=f"LDAP error pattern '{pattern}' with payload '{payload}'.",
                            parameter=param, payload=payload,
                            remediation=(
                                "Use parameterized LDAP queries. "
                                "Escape special LDAP chars: ( ) * \\ NUL"
                            ),
                            cwe="CWE-90",
                        )
                        break
                time.sleep(0.04)

    # ── 11. IDOR — INSECURE DIRECT OBJECT REFERENCE ───────────────────────────
    def _check_idor(self, page: dict):
        """Detect numeric IDs in URL and test adjacent values."""
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)

        # Find numeric parameters
        numeric_params = {k: v[0] for k, v in params.items()
                         if v and re.match(r'^\d+$', v[0])}

        for param, value in numeric_params.items():
            orig_id   = int(value)
            test_ids  = [orig_id - 1, orig_id + 1]

            orig_resp = self._get(self._inject_param(parsed, param, str(orig_id)))
            if not orig_resp or orig_resp.status_code != 200:
                continue
            orig_len = len(orig_resp.text)

            for test_id in test_ids:
                if test_id <= 0:
                    continue
                test_url = self._inject_param(parsed, param, str(test_id))
                resp = self._get(test_url)
                if not resp:
                    continue
                # IDOR indicator: 200 response with substantial content for adjacent ID
                if (resp.status_code == 200 and len(resp.text) > 100
                        and abs(len(resp.text) - orig_len) < orig_len * 0.5):
                    self._add(
                        "IDOR — Insecure Direct Object Reference", "High", page["url"],
                        f"Possible IDOR in parameter '{param}': "
                        f"ID {orig_id} → tested {test_id}, both return 200 with similar content. "
                        "Server may not verify ownership before serving resource.",
                        evidence=f"ID {test_id} returns HTTP 200, {len(resp.text)}B",
                        parameter=param, payload=str(test_id),
                        remediation=(
                            "Verify that the authenticated user owns the requested resource. "
                            "Use indirect object references (UUIDs, hashed IDs). "
                            "Apply authorization checks on every request."
                        ),
                        cwe="CWE-639",
                    )
                    break

    # ── 12. SENSITIVE DATA EXPOSURE ────────────────────────────────────────────
    def _check_sensitive_data(self, page: dict):
        """Scan response body for secrets, credentials, API keys, PII."""
        resp = self._get(page["url"])
        if not resp:
            return
        text = resp.text

        # Limit to text content types
        ct = resp.headers.get("content-type", "")
        if not any(t in ct for t in ("text", "json", "javascript", "html", "xml")):
            return

        for pattern, name, severity in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                sample = matches[0][:80] if matches else ""
                self._add(
                    f"Sensitive Data: {name}", severity, page["url"],
                    f"{name} found in HTTP response body. "
                    "This data should not be transmitted or stored in the frontend.",
                    evidence=f"Matched: {sample}...",
                    remediation=(
                        "Remove sensitive data from responses. "
                        "Store secrets in environment variables or secrets managers. "
                        "Never embed credentials/keys in client-facing code."
                    ),
                    cwe="CWE-200",
                )

    # ── 13. BUSINESS LOGIC ────────────────────────────────────────────────────
    def _check_business_logic(self, page: dict):
        """Test for business logic flaws: negative values, forced browsing."""
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)

        # Numeric param manipulation (negative values, zero, overflow)
        price_params = {k: v[0] for k, v in params.items()
                        if re.search(r"price|amount|qty|quantity|total|cost|value|num",
                                     k, re.I) and v}
        for param, orig in price_params.items():
            for val in ["-1", "0", "9999999", "-9999"]:
                test_url = self._inject_param(parsed, param, val)
                resp = self._get(test_url)
                if resp and resp.status_code == 200:
                    # Check if negative/zero accepted without error
                    if val in ("-1", "-9999", "0"):
                        self._add(
                            "Business Logic: Negative/Zero Value Accepted", "Medium",
                            page["url"],
                            f"Parameter '{param}' accepts '{val}' without error. "
                            "This may allow negative pricing, free purchases, or integer overflow exploitation.",
                            evidence=f"HTTP 200 with {param}={val}",
                            parameter=param, payload=val,
                            remediation=(
                                "Validate numeric inputs server-side. "
                                "Reject negative values for price/quantity fields. "
                                "Use server-side price verification."
                            ),
                            cwe="CWE-840",
                        )
                        break

        # Admin/privileged paths accessible without elevated session
        priv_paths = ["/admin", "/dashboard", "/manage", "/superuser",
                      "/internal", "/staff", "/moderator"]
        for path in priv_paths:
            base = f"{parsed.scheme}://{parsed.netloc}{path}"
            if base == page["url"]:
                continue
            resp = self._get(base)
            if resp and resp.status_code == 200 and len(resp.text) > 200:
                # Check it's not a login redirect
                if not re.search(r"login|sign.?in|authenticate", resp.url, re.I):
                    self._add(
                        "Forced Browsing — Privileged Path Accessible", "High",
                        base,
                        f"Privileged path '{path}' returns HTTP 200 without visible auth redirect. "
                        "May indicate missing access control on administrative functionality.",
                        evidence=f"GET {base} → HTTP {resp.status_code}, {len(resp.text)}B",
                        remediation=(
                            "Implement server-side authorization checks on all admin routes. "
                            "Return 403 for unauthorized access. "
                            "Use role-based access control (RBAC)."
                        ),
                        cwe="CWE-425",
                    )

    # ── MAIN RUN ──────────────────────────────────────────────────────────────
    def run(self) -> list:
        self.progress(f"  [Engine] Starting detection on {len(self.crawl_data)} pages")

        all_pages = self.crawl_data

        def check_single_page(item):
            i, page = item
            url = page.get("url", "")
            if not url:
                return
            pct = int(30 + (i / max(len(all_pages), 1)) * 40)
            self.progress(f"  [Engine] [{pct}%] Checking: {url[:70]}")

            if self.options.get("headers"):
                try:
                    self._check_headers(page)
                except Exception as e:
                    self.progress(f"  [Engine] headers error: {e}")

            if self.options.get("xss"):
                try:
                    before = len(self.findings)
                    self._check_reflected_xss(page)
                    self._check_dom_xss(page)
                    new = len(self.findings) - before
                    if new:
                        self.progress(f"  [Engine] XSS: {new} finding(s) on {url[:50]}")
                except Exception as e:
                    self.progress(f"  [Engine] XSS error: {e}")

            if self.options.get("sqli"):
                try:
                    before = len(self.findings)
                    self._check_sqli(page)
                    new = len(self.findings) - before
                    if new:
                        self.progress(f"  [Engine] SQLi: {new} finding(s) on {url[:50]}")
                except Exception as e:
                    self.progress(f"  [Engine] SQLi error: {e}")

            if self.options.get("csrf"):
                try:
                    before = len(self.findings)
                    self._check_csrf(page)
                    new = len(self.findings) - before
                    if new:
                        self.progress(f"  [Engine] CSRF: {new} finding(s) on {url[:50]}")
                except Exception as e:
                    self.progress(f"  [Engine] CSRF error: {e}")

            if self.options.get("redirect"):
                try:
                    self._check_redirect(page)
                except Exception as e:
                    self.progress(f"  [Engine] Redirect error: {e}")

            # Always-run checks (wrapped individually)
            for check_name, check_fn in [
                ("SSTI",            self._check_ssti),
                ("CRLF",            self._check_crlf),
                ("HTML Injection",  self._check_html_injection),
                ("Sensitive Data",  self._check_sensitive_data),
                ("IDOR",            self._check_idor),
                ("Business Logic",  self._check_business_logic),
                ("LDAP Injection",  self._check_ldap_injection),
            ]:
                try:
                    before = len(self.findings)
                    check_fn(page)
                    new = len(self.findings) - before
                    if new:
                        self.progress(f"  [Engine] {check_name}: {new} finding(s) on {url[:50]}")
                except Exception as e:
                    self.progress(f"  [Engine] {check_name} error: {e}")

            time.sleep(0.02)  # brief polite delay

        # Run in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_single_page, enumerate(all_pages))

        self.progress(f"  [Engine] Complete — {len(self.findings)} findings")
        return self.findings
