"""
scanner/fuzzer.py — AWVS v3.0 Parameter Fuzzer & Discovery Engine
──────────────────────────────────────────────────────────────────────────────
Modules:
  1. Hidden Parameter Discovery  — fuzz common param names on each page
  2. HTTP Verb Tampering          — test method override headers
  3. Content-Type Confusion       — switch content-type and observe behaviour
  4. JSON Injection               — inject into JSON-accepting endpoints
  5. Header Injection Fuzzing     — X-Forwarded-For, X-Real-IP, X-Custom-IP
  6. Prototype Pollution          — __proto__, constructor.prototype
  7. Integer/Type Confusion       — boundary values, type coercion
  8. Mass Assignment Probe        — extra fields in POST bodies
"""

import json
import logging
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AWVS/3.0 (Authorized Security Testing)"
REQUEST_HEADERS = {"User-Agent": UA}

# ─────────────────────────────────────────────────────────────────────────────
# WORDLISTS
# ─────────────────────────────────────────────────────────────────────────────

# Common hidden parameters to fuzz for
HIDDEN_PARAMS = [
    "debug", "test", "admin", "internal", "dev", "preview", "beta",
    "id", "user_id", "uid", "account_id", "token", "key", "api_key",
    "secret", "password", "pass", "pwd", "auth", "session", "sid",
    "role", "is_admin", "isAdmin", "admin_mode", "superuser",
    "redirect", "url", "next", "return_to", "callback",
    "file", "path", "page", "include", "template", "view",
    "format", "output", "type", "mode", "action", "cmd",
    "query", "search", "q", "term", "filter", "sort", "order",
    "limit", "offset", "page_size", "per_page", "count",
    "verbose", "trace", "log", "lang", "locale", "country",
    "currency", "amount", "price", "qty", "quantity",
    "override", "bypass", "force", "raw",
]

# HTTP method override headers
METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
    "_method",
]

# Content-type confusion
CONTENT_TYPES = [
    "application/json",
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "application/octet-stream",
]

# IP override headers (bypass IP-based restrictions)
IP_OVERRIDE_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Originating-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Cluster-Client-IP",
    "Forwarded",
]

# Prototype pollution payloads
PROTOTYPE_PAYLOADS = [
    "__proto__[admin]=1",
    "__proto__[isAdmin]=true",
    "constructor[prototype][admin]=1",
    "__proto__.admin=1",
    "constructor.prototype.admin=1",
]

# Mass assignment extra fields
MASS_ASSIGN_FIELDS = [
    ("role",     "admin"),
    ("isAdmin",  "true"),
    ("is_admin", "1"),
    ("admin",    "true"),
    ("verified", "true"),
    ("active",   "true"),
    ("premium",  "true"),
    ("user_type","admin"),
    ("account_type", "premium"),
    ("price",    "0"),
    ("discount", "100"),
]


# ─────────────────────────────────────────────────────────────────────────────
class FuzzerModule:
    """
    AWVS v3.0 Parameter Fuzzer — discovers hidden params and tests logic flaws.
    """

    def __init__(self, base_url: str, crawl_data: list,
                 progress_callback=None, timeout: int = 10):
        self.base_url   = base_url
        self.crawl_data = crawl_data
        self.progress   = progress_callback or (lambda msg: None)
        self.timeout    = timeout
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
            self._local.session = sess
        return self._local.session

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
        self.progress(f"  [FUZZ][{severity}] {vuln_type} @ {url}")

    def _get(self, url, params=None, headers=None, **kw):
        try:
            h = dict(REQUEST_HEADERS)
            if headers:
                h.update(headers)
            return self.session.get(url, params=params, headers=h,
                                     timeout=self.timeout, allow_redirects=True, **kw)
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

    # ── 1. HIDDEN PARAMETER DISCOVERY ─────────────────────────────────────────
    def fuzz_hidden_params(self):
        """Probe each page for hidden parameters that change response behaviour."""
        self.progress("  [FUZZ] Discovering hidden parameters...")
        tested_bases = set()

        for page in self.crawl_data[:20]:  # limit scope
            url    = page.get("url", "")
            parsed = urlparse(url)
            base   = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if base in tested_bases:
                continue
            tested_bases.add(base)

            orig_resp = self._get(url)
            if not orig_resp or orig_resp.status_code not in (200, 301, 302):
                continue
            orig_len    = len(orig_resp.text)
            orig_status = orig_resp.status_code

            def test_single_param(param):
                test_resp = self._get(url, params={param: "1"})
                if not test_resp:
                    return
                len_diff = abs(len(test_resp.text) - orig_len)
                status_changed = test_resp.status_code != orig_status
                if len_diff > 200 or status_changed:
                    sev = "Medium" if re.search(
                        r"admin|debug|internal|role|is_admin|isAdmin|admin_mode|superuser",
                        param, re.I) else "Low"
                    self._add(
                        "Hidden Parameter Discovered", sev, url,
                        f"Parameter '{param}' causes significantly different response. "
                        "This may be an undocumented feature, debug mode, or privilege escalation vector.",
                        evidence=(f"Without param: {orig_len}B / HTTP {orig_status}. "
                                  f"With ?{param}=1: {len(test_resp.text)}B / HTTP {test_resp.status_code}"),
                        parameter=param, payload="1",
                        remediation=(
                            "Audit all server-side parameters. "
                            "Remove debug/internal params from production code. "
                            "Apply authorization checks regardless of how parameters are supplied."
                        ),
                        cwe="CWE-472",
                    )
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                executor.map(test_single_param, HIDDEN_PARAMS)

    # ── 2. HTTP VERB TAMPERING ────────────────────────────────────────────────
    def fuzz_verb_tampering(self):
        """Test method override headers to bypass access controls."""
        self.progress("  [FUZZ] Testing HTTP verb tampering...")
        # Look for restricted pages (403)
        restricted = []
        for page in self.crawl_data[:10]:
            resp = self._get(page.get("url", ""))
            if resp and resp.status_code == 403:
                restricted.append(page["url"])

        for url in restricted[:5]:
            for header in METHOD_OVERRIDE_HEADERS:
                for override_method in ["GET", "PATCH", "HEAD"]:
                    resp = self._post(url, data={}, headers={header: override_method})
                    if resp and resp.status_code == 200:
                        self._add(
                            "HTTP Verb Tampering", "High", url,
                            f"Method override via '{header}: {override_method}' bypasses 403. "
                            "Access control is checked on HTTP method but not override header.",
                            evidence=f"POST with {header}: {override_method} → HTTP 200",
                            parameter=header, payload=override_method,
                            remediation=(
                                "Do not trust X-HTTP-Method-Override in security decisions. "
                                "Apply authorization based on logical action, not HTTP method."
                            ),
                            cwe="CWE-863",
                        )
                    time.sleep(0.04)

    # ── 3. IP RESTRICTION BYPASS ──────────────────────────────────────────────
    def fuzz_ip_bypass(self):
        """Test IP override headers to bypass IP-based restrictions."""
        self.progress("  [FUZZ] Testing IP restriction bypass headers...")
        bypass_ips = ["127.0.0.1", "localhost", "10.0.0.1", "192.168.1.1", "::1"]

        for page in self.crawl_data[:5]:
            url  = page.get("url", "")
            orig = self._get(url)
            if not orig:
                continue

            for header in IP_OVERRIDE_HEADERS[:5]:
                for ip in bypass_ips[:3]:
                    resp = self._get(url, headers={header: ip})
                    if not resp:
                        continue
                    # If forbidden becomes accessible
                    if orig.status_code == 403 and resp.status_code == 200:
                        self._add(
                            "IP Restriction Bypass via Header", "High", url,
                            f"IP restriction bypassed using '{header}: {ip}'. "
                            "Server trusts client-supplied IP headers for access control.",
                            evidence=f"{header}: {ip} → HTTP 200 (was 403)",
                            parameter=header, payload=ip,
                            remediation=(
                                "Never trust client-supplied IP headers for security decisions. "
                                "Use server-side IP via reverse proxy trusted headers only."
                            ),
                            cwe="CWE-290",
                        )
                    time.sleep(0.03)

    # ── 4. JSON INJECTION ─────────────────────────────────────────────────────
    def fuzz_json_injection(self):
        """Test JSON-accepting endpoints for injection."""
        self.progress("  [FUZZ] Testing JSON endpoint injection...")
        json_payloads = [
            {"role": "admin"},
            {"admin": True},
            {"id": {"$ne": None}},
            {"price": -1},
            {"__proto__": {"admin": True}},
        ]

        for page in self.crawl_data:
            for form in page.get("forms", []):
                if form.get("method", "GET").upper() != "POST":
                    continue
                action = urljoin(page.get("url", ""), form.get("action") or page.get("url", ""))
                inputs = form.get("inputs", [])

                # Build base payload from form fields
                base_data = {i.get("name", ""): i.get("value", "test")
                             for i in inputs if i.get("name")}
                if not base_data:
                    continue

                orig_resp = self._post(action, json_data=base_data)
                if not orig_resp:
                    continue

                for extra_fields in json_payloads[:3]:
                    merged = {**base_data, **extra_fields}
                    resp   = self._post(action, json_data=merged)
                    if not resp:
                        continue

                    # Check if extra field changed the response significantly
                    if (abs(len(resp.text) - len(orig_resp.text)) > 100
                            or resp.status_code != orig_resp.status_code):
                        extra_str = json.dumps(extra_fields)
                        self._add(
                            "JSON Mass Assignment / Injection", "High", action,
                            f"Extra JSON field(s) {extra_str} caused response change. "
                            "Server may accept unintended fields (mass assignment) or inject into query.",
                            evidence=f"With {extra_str}: HTTP {resp.status_code}, {len(resp.text)}B",
                            payload=extra_str,
                            remediation=(
                                "Use an allowlist of accepted JSON keys. "
                                "Validate JSON schema on all endpoints. "
                                "Do not auto-bind JSON properties to database models."
                            ),
                            cwe="CWE-915",
                        )
                    time.sleep(0.04)

    # ── 5. PROTOTYPE POLLUTION ────────────────────────────────────────────────
    def fuzz_prototype_pollution(self):
        """Test for client-side and server-side prototype pollution."""
        self.progress("  [FUZZ] Testing prototype pollution...")
        for page in self.crawl_data[:10]:
            url    = page.get("url", "")
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Get baseline response
            baseline = self._get(url)
            baseline_text = baseline.text[:1000] if baseline else ""

            for payload_str in PROTOTYPE_PAYLOADS[:3]:
                # URL-based prototype pollution
                test_url = url + ("&" if "?" in url else "?") + payload_str
                resp = self._get(test_url)
                if resp and resp.status_code == 200:
                    resp_text = resp.text[:1000]
                    if re.search(r"admin|privilege|true|1|success", resp_text, re.I):
                        if not re.search(r"admin|privilege|true|1|success", baseline_text, re.I):
                            self._add(
                                "Prototype Pollution (Potential)", "High", url,
                                f"Prototype pollution payload '{payload_str}' returned 200 with "
                                "possible privilege escalation indicators in response.",
                                evidence=f"Response snippet: {resp.text[:200]}",
                                payload=payload_str,
                                remediation=(
                                    "Freeze Object.prototype. "
                                    "Use Object.create(null) for data objects. "
                                    "Sanitize keys — reject __proto__ and constructor."
                                ),
                                cwe="CWE-1321",
                            )
                            break
                time.sleep(0.04)

    # ── 6. MASS ASSIGNMENT ────────────────────────────────────────────────────
    def fuzz_mass_assignment(self):
        """Test POST forms for mass assignment vulnerabilities."""
        self.progress("  [FUZZ] Testing mass assignment...")
        for page in self.crawl_data:
            for form in page.get("forms", []):
                if form.get("method", "GET").upper() != "POST":
                    continue
                action = urljoin(page.get("url", ""), form.get("action") or page.get("url", ""))
                inputs = form.get("inputs", [])
                existing_names = {i.get("name", "").lower() for i in inputs}

                base_data = {i.get("name",""): i.get("value","test")
                             for i in inputs if i.get("name")}
                if not base_data:
                    continue

                orig_resp = self._post(action, data=base_data)
                if not orig_resp:
                    continue

                for extra_field, extra_val in MASS_ASSIGN_FIELDS:
                    if extra_field.lower() in existing_names:
                        continue
                    test_data = {**base_data, extra_field: extra_val}
                    resp = self._post(action, data=test_data)
                    if not resp:
                        continue

                    if (abs(len(resp.text) - len(orig_resp.text)) > 80
                            or resp.status_code != orig_resp.status_code):
                        self._add(
                            "Mass Assignment Vulnerability", "High", action,
                            f"Extra POST field '{extra_field}={extra_val}' changed server response. "
                            "Server may bind arbitrary fields to model — enabling privilege escalation.",
                            evidence=f"Extra: {extra_field}={extra_val} → HTTP {resp.status_code}",
                            parameter=extra_field, payload=extra_val,
                            remediation=(
                                "Use explicit field whitelisting (Strong Parameters, DTO pattern). "
                                "Never auto-bind request body to ORM models without validation."
                            ),
                            cwe="CWE-915",
                        )
                    time.sleep(0.04)

    # ── 7. INTEGER / TYPE CONFUSION ───────────────────────────────────────────
    def fuzz_type_confusion(self):
        """Test numeric params with boundary/type values."""
        self.progress("  [FUZZ] Testing type confusion & boundary values...")
        boundary_values = [
            "0", "-1", "2147483647", "2147483648",  # INT_MAX / overflow
            "9999999999", "-9999999999",
            "NaN", "Infinity", "-Infinity",
            "null", "undefined", "true", "false",
            "[]", "{}", "''", '""',
            "1e308",     # float overflow
        ]

        for page in self.crawl_data[:10]:
            url    = page.get("url", "")
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            num_params = {k: v[0] for k, v in params.items()
                          if v and re.match(r'^-?\d+$', v[0])}

            for param, orig_val in num_params.items():
                orig_resp = self._get(url)
                orig_len  = len(orig_resp.text) if orig_resp else 0

                for bv in boundary_values[:8]:
                    parsed_q = {k: v[0] for k, v in params.items()}
                    parsed_q[param] = bv
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(parsed_q), ""
                    ))
                    resp = self._get(test_url)
                    if not resp:
                        continue

                    # 500 = type error exposed, or unexpected content
                    if resp.status_code == 500:
                        self._add(
                            "Type Confusion — Server Error", "Medium", url,
                            f"Parameter '{param}' with value '{bv}' caused HTTP 500 (server error). "
                            "Application may be vulnerable to type confusion or integer overflow.",
                            evidence=f"{param}={bv} → HTTP 500",
                            parameter=param, payload=bv,
                            remediation=(
                                "Validate and type-cast all numeric inputs before use. "
                                "Handle exceptions gracefully — do not return stack traces."
                            ),
                            cwe="CWE-704",
                        )
                    time.sleep(0.03)

    # ── MAIN RUN ──────────────────────────────────────────────────────────────
    def run(self) -> list:
        self.progress(f"  [FUZZ] === Parameter Fuzzer Starting ===")

        steps = [
            ("Hidden Params",      self.fuzz_hidden_params),
            ("Verb Tampering",     self.fuzz_verb_tampering),
            ("IP Bypass",          self.fuzz_ip_bypass),
            ("JSON Injection",     self.fuzz_json_injection),
            ("Prototype Pollution",self.fuzz_prototype_pollution),
            ("Mass Assignment",    self.fuzz_mass_assignment),
            ("Type Confusion",     self.fuzz_type_confusion),
        ]

        for name, fn in steps:
            try:
                before = len(self.findings)
                fn()
                new = len(self.findings) - before
                if new:
                    self.progress(f"  [FUZZ] {name}: {new} finding(s)")
            except Exception as e:
                logger.debug(f"[FUZZ] {name} error: {e}")

        self.progress(f"  [FUZZ] === Fuzzer Complete: {len(self.findings)} findings ===")
        return self.findings
