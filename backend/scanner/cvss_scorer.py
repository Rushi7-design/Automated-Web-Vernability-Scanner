"""
scanner/cvss_scorer.py
──────────────────────────────────────────────────────────────────────────────
CVSS v3-inspired scoring and vulnerability metadata enrichment.

Maps vulnerability types to:
  • CVSS base score (0.0 – 10.0)
  • Severity label (Critical / High / Medium / Low / Info)
  • CWE ID
  • OWASP Top 10 2021 category
  • Recommended remediation priority

Reference: https://nvd.nist.gov/vuln-metrics/cvss
"""

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY METADATA MAP
# ─────────────────────────────────────────────────────────────────────────────
VULN_METADATA = {
    # XSS
    "Reflected XSS": {
        "cvss": 8.8, "severity": "High",
        "cwe": "CWE-79", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    },
    "Reflected XSS (POST)": {
        "cvss": 8.8, "severity": "High",
        "cwe": "CWE-79", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    },
    "Stored XSS": {
        "cvss": 9.6, "severity": "Critical",
        "cwe": "CWE-79", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    },
    "DOM-Based XSS": {
        "cvss": 8.1, "severity": "High",
        "cwe": "CWE-79", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    },

    # SQL Injection
    "SQL Injection": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-89", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },

    # Command Injection
    "Command Injection": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-78", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },

    # Path Traversal
    "Path Traversal": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-22", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },

    # CSRF
    "CSRF — Missing Token": {
        "cvss": 6.5, "severity": "Medium",
        "cwe": "CWE-352", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    },

    # Open Redirect
    "Open Redirect": {
        "cvss": 6.1, "severity": "Medium",
        "cwe": "CWE-601", "owasp": "A10:2021 — Server-Side Request Forgery",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },

    # Security Headers
    "Missing Security Header: Content-Security-Policy": {
        "cvss": 6.1, "severity": "High",
        "cwe": "CWE-693", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "Missing Security Header: Strict-Transport-Security": {
        "cvss": 5.9, "severity": "High",
        "cwe": "CWE-319", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "Missing Security Header: X-Frame-Options": {
        "cvss": 4.3, "severity": "Medium",
        "cwe": "CWE-1021", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    },
    "Missing Security Header: X-Content-Type-Options": {
        "cvss": 3.7, "severity": "Low",
        "cwe": "CWE-693", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "Missing Security Header: Referrer-Policy": {
        "cvss": 3.1, "severity": "Low",
        "cwe": "CWE-200", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    },
    "Missing Security Header: Permissions-Policy": {
        "cvss": 2.6, "severity": "Info",
        "cwe": "CWE-693", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
    },

    # Info Disclosure
    "Information Disclosure: Server": {
        "cvss": 2.3, "severity": "Info",
        "cwe": "CWE-200", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    },
    "Information Disclosure: X-Powered-By": {
        "cvss": 2.3, "severity": "Info",
        "cwe": "CWE-200", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    },

    # Sensitive Data
    "Sensitive Data Exposure: AWS Key": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-200", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "Sensitive Data Exposure: Private Key": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-321", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "Sensitive Data Exposure: Stack Trace": {
        "cvss": 5.3, "severity": "Medium",
        "cwe": "CWE-209", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "Sensitive Data Exposure: Password in source": {
        "cvss": 8.2, "severity": "High",
        "cwe": "CWE-312", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "Sensitive Data Exposure: Directory Listing": {
        "cvss": 5.3, "severity": "Medium",
        "cwe": "CWE-548", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },

    # Cookie Security
    "Insecure Cookie: Missing HttpOnly": {
        "cvss": 4.3, "severity": "Medium",
        "cwe": "CWE-1004", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    },
    "Insecure Cookie: Missing Secure Flag": {
        "cvss": 5.9, "severity": "High",
        "cwe": "CWE-614", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "Insecure Cookie: Missing SameSite": {
        "cvss": 4.3, "severity": "Medium",
        "cwe": "CWE-352", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    },

    # HTTP Methods
    "Dangerous HTTP Method Enabled: TRACE": {
        "cvss": 6.5, "severity": "Medium",
        "cwe": "CWE-16", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    },
    "Dangerous HTTP Method Enabled: PUT": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-650", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "Dangerous HTTP Method Enabled: DELETE": {
        "cvss": 9.1, "severity": "Critical",
        "cwe": "CWE-650", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
    },

    # SSL
    "SSL/TLS: Expired Certificate": {
        "cvss": 7.4, "severity": "High",
        "cwe": "CWE-298", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "SSL/TLS: Certificate Expiring Soon": {
        "cvss": 4.0, "severity": "Medium",
        "cwe": "CWE-298", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    },
    "SSL/TLS: Self-Signed Certificate": {
        "cvss": 6.5, "severity": "Medium",
        "cwe": "CWE-295", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    },

    # Sensitive Files
    "Sensitive File Exposed": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-538", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },

    # Broken Auth
    "Broken Authentication: No Rate Limiting": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-307", "owasp": "A07:2021 — Identification and Authentication Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "Broken Authentication: Weak Session Token": {
        "cvss": 8.1, "severity": "High",
        "cwe": "CWE-330", "owasp": "A07:2021 — Identification and Authentication Failures",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },

    # XXE
    "XML External Entity (XXE)": {
        "cvss": 8.2, "severity": "High",
        "cwe": "CWE-611", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    },
    "XXE — XML External Entity Injection": {
        "cvss": 9.1, "severity": "Critical",
        "cwe": "CWE-611", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },

    # ── NEW v3.0 TYPES ─────────────────────────────────────────────────────────
    # SSTI
    "SSTI — Server-Side Template Injection": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-94", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },

    # CRLF
    "CRLF Injection / HTTP Response Splitting": {
        "cvss": 6.1, "severity": "High",
        "cwe": "CWE-93", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },

    # HTML Injection
    "HTML Injection": {
        "cvss": 4.6, "severity": "Medium",
        "cwe": "CWE-80", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    },

    # LDAP
    "LDAP Injection": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-90", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },

    # IDOR
    "IDOR — Insecure Direct Object Reference": {
        "cvss": 8.1, "severity": "High",
        "cwe": "CWE-639", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    },

    # Sensitive Data — all subtypes
    "Sensitive Data: API Key Exposed": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-200", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "Sensitive Data: Secret Key Exposed": {
        "cvss": 9.1, "severity": "Critical",
        "cwe": "CWE-321", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "Sensitive Data: Password in Response": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-312", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "Sensitive Data: Access Token Exposed": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-200", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "Sensitive Data: Google API Key": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-200", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "Sensitive Data: AWS Access Key ID": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-200", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "Sensitive Data: Database Credential": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-312", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "Sensitive Data: Private Key in Response": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-321", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "Sensitive Data: JWT Token Exposed": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-200", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "Sensitive Data: Email Address Leaked": {
        "cvss": 3.5, "severity": "Low",
        "cwe": "CWE-200", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    },

    # Business Logic
    "Business Logic: Negative/Zero Value Accepted": {
        "cvss": 5.4, "severity": "Medium",
        "cwe": "CWE-840", "owasp": "A04:2021 — Insecure Design",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
    },
    "Forced Browsing — Privileged Path Accessible": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-425", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },

    # CORS
    "CORS: Wildcard Origin Allowed": {
        "cvss": 6.5, "severity": "High",
        "cwe": "CWE-942", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    },
    "CORS: Arbitrary Origin Reflected with Credentials": {
        "cvss": 9.1, "severity": "Critical",
        "cwe": "CWE-942", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "CORS: Origin Reflection": {
        "cvss": 5.4, "severity": "Medium",
        "cwe": "CWE-942", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    },
    "CORS: Null Origin Allowed": {
        "cvss": 6.5, "severity": "High",
        "cwe": "CWE-942", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    },

    # JWT
    "JWT: Algorithm 'none' Accepted": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-345", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "JWT: No Expiry Claim": {
        "cvss": 5.3, "severity": "Medium",
        "cwe": "CWE-613", "owasp": "A07:2021 — Identification and Authentication Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "JWT: Expired Token Accepted": {
        "cvss": 8.1, "severity": "High",
        "cwe": "CWE-613", "owasp": "A07:2021 — Identification and Authentication Failures",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "JWT: Symmetric Algorithm (HS256)": {
        "cvss": 3.7, "severity": "Low",
        "cwe": "CWE-327", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },

    # SSRF
    "SSRF — Server-Side Request Forgery": {
        "cvss": 9.3, "severity": "Critical",
        "cwe": "CWE-918", "owasp": "A10:2021 — Server-Side Request Forgery",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    },

    # Host Header
    "Host Header Injection": {
        "cvss": 6.5, "severity": "High",
        "cwe": "CWE-20", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    },

    # NoSQL
    "NoSQL Injection": {
        "cvss": 9.8, "severity": "High",
        "cwe": "CWE-943", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },

    # Log4j
    "Log4Shell / JNDI Injection (Potential)": {
        "cvss": 10.0, "severity": "Critical",
        "cwe": "CWE-502", "owasp": "A06:2021 — Vulnerable Components",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },

    # GraphQL
    "GraphQL Introspection Enabled": {
        "cvss": 5.3, "severity": "Medium",
        "cwe": "CWE-200", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },

    # WAF / Info
    "WAF / CDN Detected": {
        "cvss": 0.0, "severity": "Info",
        "cwe": "CWE-16", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "",
    },

    # Subdomain Takeover
    "Subdomain Takeover Risk": {
        "cvss": 9.3, "severity": "Critical",
        "cwe": "CWE-350", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    },

    # Clickjacking
    "Clickjacking Vulnerability": {
        "cvss": 4.3, "severity": "Medium",
        "cwe": "CWE-1021", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    },

    # Fuzzer findings
    "Hidden Parameter Discovered": {
        "cvss": 4.3, "severity": "Medium",
        "cwe": "CWE-472", "owasp": "A04:2021 — Insecure Design",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "HTTP Verb Tampering": {
        "cvss": 8.1, "severity": "High",
        "cwe": "CWE-863", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    },
    "IP Restriction Bypass via Header": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-290", "owasp": "A01:2021 — Broken Access Control",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "JSON Mass Assignment / Injection": {
        "cvss": 8.8, "severity": "High",
        "cwe": "CWE-915", "owasp": "A04:2021 — Insecure Design",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    },
    "Prototype Pollution (Potential)": {
        "cvss": 8.1, "severity": "High",
        "cwe": "CWE-1321", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "Mass Assignment Vulnerability": {
        "cvss": 8.8, "severity": "High",
        "cwe": "CWE-915", "owasp": "A04:2021 — Insecure Design",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    },
    "Type Confusion — Server Error": {
        "cvss": 5.3, "severity": "Medium",
        "cwe": "CWE-704", "owasp": "A04:2021 — Insecure Design",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },

    # SQL Injection subtypes
    "SQL Injection (Error-Based)": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-89", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "SQL Injection (Boolean-Blind)": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-89", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "SQL Injection (Time-Based Blind)": {
        "cvss": 9.8, "severity": "Critical",
        "cwe": "CWE-89", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },

    # DOM XSS subtypes
    "DOM-Based XSS (Potential)": {
        "cvss": 8.1, "severity": "High",
        "cwe": "CWE-79", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    },
    "DOM XSS — Location Source": {
        "cvss": 8.8, "severity": "High",
        "cwe": "CWE-79", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    },
    "Reflected XSS (Form)": {
        "cvss": 8.8, "severity": "High",
        "cwe": "CWE-79", "owasp": "A03:2021 — Injection",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    },

    # Weak CSP
    "Weak CSP: Unsafe Inline in CSP": {
        "cvss": 6.1, "severity": "Medium",
        "cwe": "CWE-16", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },

    # TLS / cipher
    "Weak TLS Version": {
        "cvss": 7.4, "severity": "High",
        "cwe": "CWE-326", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "Weak SSL Cipher": {
        "cvss": 7.4, "severity": "High",
        "cwe": "CWE-326", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "No HTTPS": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-319", "owasp": "A02:2021 — Cryptographic Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },

    # Rate limiting
    "Missing Rate Limiting on Login": {
        "cvss": 7.5, "severity": "High",
        "cwe": "CWE-307", "owasp": "A07:2021 — Identification and Authentication Failures",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },

    # HTTP method
    "HTTP Method Allowed": {
        "cvss": 6.5, "severity": "Medium",
        "cwe": "CWE-16", "owasp": "A05:2021 — Security Misconfiguration",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
    },
}


# Default for unrecognized types
DEFAULT_META = {
    "cvss": 2.0, "severity": "Info",
    "cwe": "CWE-Unknown", "owasp": "Unknown",
    "cvss_vector": "",
}


def get_metadata(vuln_type: str) -> dict:
    """Return CVSS score, severity, CWE, and OWASP category for a vuln type."""
    # Exact match first
    if vuln_type in VULN_METADATA:
        return VULN_METADATA[vuln_type]

    # Partial match (e.g. "Missing Security Header: CSP" → generic header entry)
    for key, meta in VULN_METADATA.items():
        if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
            return meta

    return DEFAULT_META.copy()


def enrich_finding(finding: dict) -> dict:
    """Enrich a finding dict with CVSS, CWE, OWASP metadata."""
    meta = get_metadata(finding.get("vuln_type", ""))
    finding["cvss_score"]      = meta["cvss"]
    finding["cwe_id"]          = meta["cwe"]
    finding["owasp_category"]  = meta["owasp"]
    finding["cvss_vector"]     = meta.get("cvss_vector", "")
    # Override severity from metadata if not already set
    if not finding.get("severity"):
        finding["severity"] = meta["severity"]
    return finding


def calculate_risk_score(findings: list) -> tuple:
    """
    Calculate an overall risk score (0–100) for a set of findings.
    Returns (score: float, level: str)

    Weighting:
      Critical = 25 pts each (capped at 100)
      High     = 10 pts each
      Medium   =  5 pts each
      Low      =  2 pts each
      Info     =  0.5 pts each
    """
    WEIGHTS = {"Critical": 25, "High": 10, "Medium": 5, "Low": 2, "Info": 0.5}
    score = sum(WEIGHTS.get(f.get("severity", "Info"), 0) for f in findings)
    score = min(100.0, round(score, 1))

    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "None"

    return score, level
