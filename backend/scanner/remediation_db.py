"""
scanner/remediation_db.py
─────────────────────────────────────────────────────────────────────────────
Comprehensive Vulnerability Remediation Knowledge Base

For every vulnerability type, this database provides:
  • Full description (what it is)
  • Business impact (why it matters)
  • Step-by-step fix instructions
  • Vulnerable code example (before)
  • Fixed code example (after)
  • OWASP category, CWE ID, references
"""

REMEDIATION_DB = {

    # ─── XSS ─────────────────────────────────────────────────────────────────
    "xss": {
        "title":       "Cross-Site Scripting (XSS)",
        "short":       "Malicious scripts are injected into web pages and executed in victims' browsers.",
        "description": (
            "XSS occurs when an application includes untrusted data in a web page without proper "
            "validation or escaping. Attackers inject client-side scripts that execute in the victim's "
            "browser, allowing them to steal session cookies, deface the page, redirect users, or "
            "perform actions on behalf of the victim."
        ),
        "impact": (
            "• Session hijacking — steal authentication cookies\n"
            "• Account takeover without password\n"
            "• Credential harvesting via fake login forms\n"
            "• Malware distribution to site visitors\n"
            "• Defacement and reputation damage\n"
            "• Data exfiltration from the DOM"
        ),
        "owasp":   "A03:2021 – Injection",
        "cwe":     "CWE-79",
        "cvss":    7.4,
        "fix_steps": [
            "1. ENCODE all user-supplied output using context-aware encoding (HTML, JS, URL, CSS)",
            "2. VALIDATE input — reject or sanitize unexpected characters",
            "3. Implement a strict Content-Security-Policy (CSP) header",
            "4. Set the HttpOnly flag on session cookies",
            "5. Use modern templating engines that auto-escape by default (Jinja2, React JSX)",
            "6. Apply DOMPurify or similar when inserting HTML dynamically via JavaScript",
        ],
        "code_vulnerable": """\
# VULNERABLE — Python/Flask
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f'<h1>Results for: {query}</h1>'  # XSS!""",
        "code_fixed": """\
# FIXED — use Jinja2 auto-escaping (always use render_template)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template('search.html', query=query)
# search.html: <h1>Results for: {{ query }}</h1>  ← auto-escaped""",
        "code_lang": "python",
        "references": [
            ("OWASP XSS Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
            ("CWE-79 Definition", "https://cwe.mitre.org/data/definitions/79.html"),
            ("PortSwigger XSS Labs", "https://portswigger.net/web-security/cross-site-scripting"),
        ],
    },

    # ─── SQL INJECTION ────────────────────────────────────────────────────────
    "sqli": {
        "title":       "SQL Injection (SQLi)",
        "short":       "User-supplied input is inserted directly into SQL queries without sanitization.",
        "description": (
            "SQL Injection allows attackers to interfere with the queries that an application makes "
            "to its database. This can allow attackers to view, modify, or delete data, bypass "
            "authentication, extract the entire database, or in some cases execute OS commands "
            "on the database server."
        ),
        "impact": (
            "• Authentication bypass (login as any user)\n"
            "• Full database dump — all user data, passwords, PII\n"
            "• Data manipulation — insert, update, delete records\n"
            "• Remote code execution via xp_cmdshell or similar\n"
            "• Lateral movement to internal systems\n"
            "• GDPR/compliance violations with massive fines"
        ),
        "owasp":   "A03:2021 – Injection",
        "cwe":     "CWE-89",
        "cvss":    9.8,
        "fix_steps": [
            "1. Use PARAMETERIZED QUERIES / prepared statements — the #1 fix",
            "2. Use an ORM (SQLAlchemy, Django ORM, Hibernate) which handles escaping",
            "3. Apply WHITELIST input validation — reject unexpected characters",
            "4. Grant database accounts minimum required privileges (least privilege)",
            "5. Enable WAF rules to block common SQLi payloads",
            "6. Use stored procedures with proper parameterization",
        ],
        "code_vulnerable": """\
# VULNERABLE — string concatenation = SQLi
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return db.execute(query)
# Payload: admin' OR '1'='1 — dumps all users""",
        "code_fixed": """\
# FIXED — parameterized query (no injection possible)
def get_user(username):
    query = "SELECT * FROM users WHERE name = ?"
    return db.execute(query, (username,))

# Even better — use SQLAlchemy ORM:
user = User.query.filter_by(username=username).first()""",
        "code_lang": "python",
        "references": [
            ("OWASP SQL Injection Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
            ("CWE-89 Definition", "https://cwe.mitre.org/data/definitions/89.html"),
            ("PortSwigger SQLi Labs", "https://portswigger.net/web-security/sql-injection"),
        ],
    },

    # ─── CSRF ─────────────────────────────────────────────────────────────────
    "csrf": {
        "title":       "Cross-Site Request Forgery (CSRF)",
        "short":       "Forged requests trick authenticated users into performing unintended actions.",
        "description": (
            "CSRF attacks force authenticated users to unknowingly submit requests. Since the browser "
            "automatically includes session cookies, the server cannot distinguish legitimate from "
            "forged requests. Attackers can make victims change passwords, transfer funds, or modify "
            "account settings."
        ),
        "impact": (
            "• Unauthorized actions on behalf of logged-in users\n"
            "• Account takeover via password/email change\n"
            "• Financial fraud in banking applications\n"
            "• Data modification or deletion\n"
            "• Admin-level actions if admin is targeted"
        ),
        "owasp":   "A01:2021 – Broken Access Control",
        "cwe":     "CWE-352",
        "cvss":    6.5,
        "fix_steps": [
            "1. Generate a unique, unpredictable CSRF TOKEN per session and embed in every form",
            "2. Validate the CSRF token on every state-changing request (POST, PUT, DELETE)",
            "3. Set SameSite=Strict or SameSite=Lax on session cookies",
            "4. Use the Synchronizer Token Pattern or Double Submit Cookie pattern",
            "5. Verify Origin/Referer headers as secondary defense",
            "6. Use framework-built-in CSRF protection (Flask-WTF, Django CSRF middleware)",
        ],
        "code_vulnerable": """\
# VULNERABLE — form with no CSRF protection
<form method="POST" action="/change-password">
  <input name="new_password" type="password">
  <button type="submit">Change Password</button>
</form>""",
        "code_fixed": """\
# FIXED — Flask-WTF with CSRF token
from flask_wtf import FlaskForm
from wtforms import PasswordField

class ChangePasswordForm(FlaskForm):
    new_password = PasswordField('New Password')

# Template:
<form method="POST">
  {{ form.hidden_tag() }}  {# ← CSRF token automatically inserted #}
  {{ form.new_password() }}
  <button type="submit">Change Password</button>
</form>""",
        "code_lang": "python",
        "references": [
            ("OWASP CSRF Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"),
            ("CWE-352 Definition", "https://cwe.mitre.org/data/definitions/352.html"),
        ],
    },

    # ─── SECURITY HEADERS ─────────────────────────────────────────────────────
    "headers": {
        "title":       "Missing Security HTTP Headers",
        "short":       "Critical security headers are absent, enabling browser-based attacks.",
        "description": (
            "HTTP security headers instruct browsers on how to behave when handling your site's content. "
            "Missing headers enable clickjacking, XSS, MIME-type sniffing attacks, and force users to "
            "use insecure HTTP connections."
        ),
        "impact": (
            "• Clickjacking via missing X-Frame-Options\n"
            "• XSS amplified by missing Content-Security-Policy\n"
            "• MIME sniffing attacks without X-Content-Type-Options\n"
            "• Downgrade attacks without HSTS\n"
            "• Information leakage via Referrer-Policy"
        ),
        "owasp":   "A05:2021 – Security Misconfiguration",
        "cwe":     "CWE-16",
        "cvss":    5.3,
        "fix_steps": [
            "1. Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
            "2. Add Content-Security-Policy header to restrict allowed content sources",
            "3. Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "4. Add X-Content-Type-Options: nosniff",
            "5. Add Referrer-Policy: strict-origin-when-cross-origin",
            "6. Add Permissions-Policy to restrict browser features",
        ],
        "code_vulnerable": """\
# VULNERABLE — no security headers set
@app.after_request
def add_headers(response):
    return response  # Missing all security headers!""",
        "code_fixed": """\
# FIXED — all critical security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains; preload'
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=()'
    )
    return response""",
        "code_lang": "python",
        "references": [
            ("OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/"),
            ("MDN HTTP Security Headers", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security"),
            ("SecurityHeaders.com Scanner", "https://securityheaders.com"),
        ],
    },

    # ─── OPEN REDIRECT ────────────────────────────────────────────────────────
    "redirect": {
        "title":       "Open Redirect",
        "short":       "The application redirects users to attacker-controlled external URLs.",
        "description": (
            "An open redirect occurs when an application uses user-controlled data to redirect to "
            "another URL without validation. Attackers use this to trick users into clicking "
            "legitimate-looking links that redirect to phishing/malware sites."
        ),
        "impact": (
            "• Phishing campaigns using trusted domain as cover\n"
            "• OAuth/SSO token theft via redirect_uri manipulation\n"
            "• Malware distribution via drive-by downloads\n"
            "• Bypass security filters that whitelist your domain"
        ),
        "owasp":   "A01:2021 – Broken Access Control",
        "cwe":     "CWE-601",
        "cvss":    6.1,
        "fix_steps": [
            "1. AVOID using user input in redirect destinations entirely",
            "2. Use an ALLOWLIST of permitted redirect URLs",
            "3. Map redirect targets to internal identifiers (e.g., ?next=dashboard not ?next=https://evil.com)",
            "4. Validate the URL is relative or belongs to your domain",
            "5. Show a warning page before redirecting to external URLs",
        ],
        "code_vulnerable": """\
# VULNERABLE — redirect to any URL from parameter
@app.route('/login')
def login():
    next_url = request.args.get('next', '/')
    # After login:
    return redirect(next_url)  # Redirects to anything!""",
        "code_fixed": """\
# FIXED — validate redirect URL
from urllib.parse import urlparse, urljoin

ALLOWED_HOSTS = {'myapp.com', 'www.myapp.com'}

def is_safe_redirect(url):
    try:
        parsed = urlparse(url)
        # Allow relative URLs or same-host URLs
        return not parsed.netloc or parsed.netloc in ALLOWED_HOSTS
    except Exception:
        return False

@app.route('/login')
def login():
    next_url = request.args.get('next', '/')
    if not is_safe_redirect(next_url):
        next_url = '/'  # Fall back to safe default
    return redirect(next_url)""",
        "code_lang": "python",
        "references": [
            ("OWASP Unvalidated Redirects", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
            ("CWE-601 Definition", "https://cwe.mitre.org/data/definitions/601.html"),
        ],
    },

    # ─── COMMAND INJECTION ────────────────────────────────────────────────────
    "command_injection": {
        "title":       "Command Injection (OS Command Injection)",
        "short":       "User input is passed to system shell commands, enabling OS-level code execution.",
        "description": (
            "Command injection occurs when an application passes unsafe user data to a system shell. "
            "An attacker can execute arbitrary operating system commands, potentially gaining full "
            "control of the server, reading sensitive files, or pivoting to internal networks."
        ),
        "impact": (
            "• Full server compromise and root/SYSTEM access\n"
            "• Reading /etc/passwd, SSH keys, database credentials\n"
            "• Reverse shell — persistent backdoor access\n"
            "• Lateral movement to internal network\n"
            "• Ransomware deployment or data destruction"
        ),
        "owasp":   "A03:2021 – Injection",
        "cwe":     "CWE-78",
        "cvss":    9.8,
        "fix_steps": [
            "1. NEVER pass user input to shell commands — this is the golden rule",
            "2. Use language-native APIs instead of shell (e.g., Python's os.listdir() not ls)",
            "3. If shell is unavoidable, use subprocess with a LIST (not string) and shell=False",
            "4. Whitelist allowed characters — reject anything not alphanumeric",
            "5. Run the application with minimal OS privileges (not root)",
            "6. Use containers/sandboxes to limit blast radius",
        ],
        "code_vulnerable": """\
# VULNERABLE — user input directly in shell
import subprocess
def ping_host(host):
    # Payload: 8.8.8.8; cat /etc/passwd
    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)
    return result.stdout""",
        "code_fixed": """\
# FIXED — use list form, shell=False, whitelist input
import subprocess, re

def ping_host(host):
    # Strict whitelist: only valid hostname/IP characters
    if not re.match(r'^[a-zA-Z0-9.\-]{1,255}$', host):
        raise ValueError("Invalid hostname")
    # List form + shell=False = injection impossible
    result = subprocess.run(
        ['ping', '-c', '1', host],
        shell=False,           # ← critical
        capture_output=True,
        timeout=5
    )
    return result.stdout""",
        "code_lang": "python",
        "references": [
            ("OWASP Command Injection", "https://owasp.org/www-community/attacks/Command_Injection"),
            ("CWE-78 Definition", "https://cwe.mitre.org/data/definitions/78.html"),
        ],
    },

    # ─── PATH TRAVERSAL ───────────────────────────────────────────────────────
    "path_traversal": {
        "title":       "Path Traversal (Directory Traversal)",
        "short":       "../../ sequences in file paths allow reading files outside the intended directory.",
        "description": (
            "Path traversal attacks allow attackers to access files and directories stored outside "
            "the web root folder by manipulating file path variables with ../ sequences. This can "
            "expose sensitive configuration files, source code, passwords, and system files."
        ),
        "impact": (
            "• Reading /etc/passwd, /etc/shadow (password hashes)\n"
            "• Accessing application source code and config files\n"
            "• Reading database connection strings and API keys\n"
            "• Accessing .env, config.py, web.config files\n"
            "• AWS metadata endpoint access"
        ),
        "owasp":   "A01:2021 – Broken Access Control",
        "cwe":     "CWE-22",
        "cvss":    7.5,
        "fix_steps": [
            "1. Resolve paths to absolute and verify they are within the allowed base directory",
            "2. Use os.path.realpath() and check the result starts with the expected prefix",
            "3. Whitelist allowed filenames — reject any path containing ../ or encoded variants",
            "4. Use framework static file serving rather than custom file-serving code",
            "5. Run the web server as a low-privilege user with minimal file system access",
        ],
        "code_vulnerable": """\
# VULNERABLE — path traversal possible
@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = os.path.join('/var/www/files/', filename)
    return send_file(filepath)
    # Payload: ?file=../../etc/passwd""",
        "code_fixed": """\
# FIXED — realpath check prevents traversal
import os

BASE_DIR = '/var/www/files'

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # Resolve to absolute path
    filepath = os.path.realpath(os.path.join(BASE_DIR, filename))
    # Critical check: must start with base directory
    if not filepath.startswith(os.path.realpath(BASE_DIR) + os.sep):
        abort(403)  # Traversal attempt blocked
    if not os.path.isfile(filepath):
        abort(404)
    return send_file(filepath)""",
        "code_lang": "python",
        "references": [
            ("OWASP Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
            ("CWE-22 Definition", "https://cwe.mitre.org/data/definitions/22.html"),
        ],
    },

    # ─── COOKIE SECURITY ──────────────────────────────────────────────────────
    "cookie_security": {
        "title":       "Insecure Cookie Configuration",
        "short":       "Session cookies are missing security flags, enabling theft or manipulation.",
        "description": (
            "Cookies that lack the HttpOnly, Secure, and SameSite flags can be stolen via XSS, "
            "transmitted over insecure HTTP, or used in CSRF attacks. Session cookies are the keys "
            "to authenticated sessions and must be protected."
        ),
        "impact": (
            "• Session hijacking via JavaScript (missing HttpOnly)\n"
            "• Cookie interception on HTTP networks (missing Secure flag)\n"
            "• CSRF attacks via missing SameSite attribute\n"
            "• Session fixation attacks"
        ),
        "owasp":   "A02:2021 – Cryptographic Failures",
        "cwe":     "CWE-614",
        "cvss":    6.5,
        "fix_steps": [
            "1. Set HttpOnly=True — prevents JavaScript from accessing the cookie",
            "2. Set Secure=True — cookie only sent over HTTPS",
            "3. Set SameSite=Strict or Lax — prevents CSRF",
            "4. Set appropriate Expires/Max-Age — don't use persistent sessions unnecessarily",
            "5. Set Domain and Path as restrictively as possible",
            "6. Regenerate session ID after login (prevent session fixation)",
        ],
        "code_vulnerable": """\
# VULNERABLE — basic cookie with no security flags
resp.set_cookie('session_id', token)
# Can be stolen by XSS, sent over HTTP, used in CSRF""",
        "code_fixed": """\
# FIXED — all security flags set
resp.set_cookie(
    'session_id',
    value=token,
    httponly=True,          # No JS access
    secure=True,            # HTTPS only
    samesite='Strict',      # No CSRF
    max_age=3600,           # 1 hour expiry
    domain='myapp.com',
    path='/',
)

# Flask-wide config:
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
)""",
        "code_lang": "python",
        "references": [
            ("OWASP Session Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
            ("CWE-614 Definition", "https://cwe.mitre.org/data/definitions/614.html"),
        ],
    },

    # ─── SSL/TLS ──────────────────────────────────────────────────────────────
    "ssl": {
        "title":       "SSL/TLS Misconfiguration",
        "short":       "Weak or expired SSL/TLS certificates expose traffic to interception.",
        "description": (
            "SSL/TLS issues include expired certificates, weak cipher suites, outdated protocol "
            "versions (SSLv2, SSLv3, TLS 1.0/1.1), missing HSTS, and self-signed certificates. "
            "These issues allow man-in-the-middle attacks and traffic decryption."
        ),
        "impact": (
            "• MITM attacks — decrypt and read all traffic\n"
            "• Credential and session token theft\n"
            "• Data tampering during transmission\n"
            "• Browser security warnings that damage user trust\n"
            "• Non-compliance with PCI-DSS, HIPAA"
        ),
        "owasp":   "A02:2021 – Cryptographic Failures",
        "cwe":     "CWE-295",
        "cvss":    7.4,
        "fix_steps": [
            "1. Renew your SSL certificate before expiry — use Let's Encrypt for free auto-renewal",
            "2. Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1 — only allow TLS 1.2 and TLS 1.3",
            "3. Use strong cipher suites — disable RC4, DES, 3DES, MD5",
            "4. Enable HSTS with a long max-age (minimum 1 year = 31536000)",
            "5. Add HSTS preloading for maximum protection",
            "6. Use trusted CA-signed certificates, not self-signed",
        ],
        "code_vulnerable": """\
# VULNERABLE nginx.conf — weak SSL config
ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;  # Old protocols!
ssl_ciphers RC4:HIGH:!aNULL:!MD5;  # Weak ciphers!""",
        "code_fixed": """\
# FIXED nginx.conf — modern secure SSL
ssl_protocols TLSv1.2 TLSv1.3;  # Only modern protocols
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;  # Let client choose for TLS 1.3
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;

# HSTS — force HTTPS for 1 year
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Let's Encrypt auto-renewal (certbot):
# certbot certonly --nginx -d yourdomain.com --non-interactive --agree-tos""",
        "code_lang": "nginx",
        "references": [
            ("Mozilla SSL Configuration Generator", "https://ssl-config.mozilla.org/"),
            ("Let's Encrypt — Free SSL", "https://letsencrypt.org/getting-started/"),
            ("SSL Labs Test", "https://www.ssllabs.com/ssltest/"),
        ],
    },

    # ─── SENSITIVE FILES ──────────────────────────────────────────────────────
    "sensitive_files": {
        "title":       "Sensitive File Exposure",
        "short":       "Backup files, config files, or admin panels are publicly accessible.",
        "description": (
            "Sensitive files such as .env, config.php, .git directories, backup.zip, phpinfo.php, "
            "and wp-admin panels are publicly accessible. These expose source code, credentials, "
            "database connection strings, and internal architecture."
        ),
        "impact": (
            "• Leaked database credentials, API keys, secret keys\n"
            "• Full source code disclosure\n"
            "• Password hashes from database backups\n"
            "• Internal network mapping from config files"
        ),
        "owasp":   "A05:2021 – Security Misconfiguration",
        "cwe":     "CWE-200",
        "cvss":    7.5,
        "fix_steps": [
            "1. NEVER deploy .env, config files, or backups into the web root",
            "2. Configure your web server to deny access to sensitive file extensions",
            "3. Add .env, *.bak, *.sql to .gitignore — never commit secrets",
            "4. Move configuration files outside the document root",
            "5. Regularly audit publicly accessible directories",
            "6. Use secrets managers (AWS Secrets Manager, HashiCorp Vault) for credentials",
        ],
        "code_vulnerable": """\
# VULNERABLE nginx — no restriction on sensitive files
location / {
    try_files $uri $uri/ =404;
}
# .env, config.php, .git accessible at /.env""",
        "code_fixed": """\
# FIXED nginx — block sensitive file access
location ~ /\\. {
    deny all;  # Block all dotfiles (.env, .git, etc.)
    return 404;
}
location ~* \\.(bak|backup|sql|tar|gz|zip|log|conf|ini)$ {
    deny all;
    return 404;
}
location ~ /(phpinfo|phpmyadmin|adminer)\\.php$ {
    deny all;
}

# Apache .htaccess equivalent:
# <FilesMatch "\\.(env|bak|sql|log|conf)$">
#   Order allow,deny
#   Deny from all
# </FilesMatch>""",
        "code_lang": "nginx",
        "references": [
            ("OWASP Information Disclosure", "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_an_error_message"),
            ("CWE-200 Definition", "https://cwe.mitre.org/data/definitions/200.html"),
        ],
    },

    # ─── BROKEN AUTH ─────────────────────────────────────────────────────────
    "broken_auth": {
        "title":       "Broken Authentication / Missing Rate Limiting",
        "short":       "Login endpoints lack brute-force protection, enabling password attacks.",
        "description": (
            "Applications without rate limiting allow unlimited login attempts. Attackers can "
            "use automated tools to try thousands of password combinations (brute force) or "
            "use credential stuffing with leaked password databases."
        ),
        "impact": (
            "• Account takeover via brute-force attacks\n"
            "• Credential stuffing using leaked password lists\n"
            "• Password spraying against weak passwords\n"
            "• Admin account compromise"
        ),
        "owasp":   "A07:2021 – Identification and Authentication Failures",
        "cwe":     "CWE-307",
        "cvss":    7.5,
        "fix_steps": [
            "1. Implement RATE LIMITING — e.g., max 5 failed attempts per IP per 15 minutes",
            "2. Add exponential ACCOUNT LOCKOUT after N failed attempts",
            "3. Require strong passwords (minimum 8 chars, complexity rules)",
            "4. Implement MULTI-FACTOR AUTHENTICATION (MFA/2FA)",
            "5. Use CAPTCHA after 3 failed login attempts",
            "6. Log and alert on abnormal authentication patterns",
        ],
        "code_vulnerable": """\
# VULNERABLE — unlimited login attempts
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
    return redirect('/')  # No rate limit!""",
        "code_fixed": """\
# FIXED — Flask-Limiter for rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Max 5 attempts/minute
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        # Track failed attempts
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
        flash('Invalid credentials', 'error')
        return redirect('/login')
    login_user(user)
    user.failed_attempts = 0
    db.session.commit()""",
        "code_lang": "python",
        "references": [
            ("OWASP Authentication Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"),
            ("CWE-307 Definition", "https://cwe.mitre.org/data/definitions/307.html"),
        ],
    },

    # ─── XXE ─────────────────────────────────────────────────────────────────
    "xxe": {
        "title":       "XML External Entity Injection (XXE)",
        "short":       "XML parsers process external entity references, enabling file read and SSRF.",
        "description": (
            "XXE attacks exploit vulnerable XML parsers that process external entity references. "
            "Attackers can read local files, perform SSRF attacks against internal services, "
            "or cause denial of service via entity expansion (Billion Laughs attack)."
        ),
        "impact": (
            "• Reading arbitrary files (/etc/passwd, config files)\n"
            "• SSRF — access to internal services and metadata endpoints\n"
            "• Denial of service via entity expansion\n"
            "• Data exfiltration from isolated networks"
        ),
        "owasp":   "A05:2021 – Security Misconfiguration",
        "cwe":     "CWE-611",
        "cvss":    9.1,
        "fix_steps": [
            "1. DISABLE external entity processing in the XML parser — this is the primary fix",
            "2. Use a simple data format like JSON instead of XML where possible",
            "3. Upgrade to latest XML library versions with XXE disabled by default",
            "4. Validate and sanitize all XML input before parsing",
            "5. Implement XML schema validation (XSD) to reject unexpected structures",
        ],
        "code_vulnerable": """\
# VULNERABLE — default Python lxml parser (XXE enabled)
from lxml import etree
def parse_xml(xml_string):
    tree = etree.fromstring(xml_string)  # XXE possible!
    return tree""",
        "code_fixed": """\
# FIXED — disable entity resolution
from lxml import etree

def parse_xml(xml_string):
    # Create a secure parser with all entity processing disabled
    parser = etree.XMLParser(
        resolve_entities=False,   # Disable external entities
        no_network=True,          # No network access
        dtd_validation=False,     # Disable DTD
        load_dtd=False,           # Don't load external DTDs
    )
    tree = etree.fromstring(xml_string.encode(), parser)
    return tree

# Using defusedxml (recommended library):
import defusedxml.ElementTree as ET
tree = ET.fromstring(xml_string)  # Safe by default""",
        "code_lang": "python",
        "references": [
            ("OWASP XXE Prevention Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"),
            ("CWE-611 Definition", "https://cwe.mitre.org/data/definitions/611.html"),
        ],
    },

    # ── SSTI ──────────────────────────────────────────────────────────────────
    "ssti": {
        "title": "Server-Side Template Injection (SSTI)",
        "short": "User input is embedded in a server-side template and executed as code.",
        "description": (
            "SSTI occurs when user-supplied data is embedded directly into a template engine "
            "(Jinja2, Twig, Freemarker) and interpreted as template syntax. Attackers can "
            "execute arbitrary code on the server, leading to full Remote Code Execution."
        ),
        "impact": (
            "Full Remote Code Execution on the web server.\n"
            "Extract environment variables, secrets, and credentials.\n"
            "Complete server compromise."
        ),
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-94",
        "cvss": 9.8,
        "fix_steps": [
            "1. NEVER pass user input directly to a template engine render function",
            "2. Pass user data as template variables, not as part of the template string",
            "3. Use logic-less template engines (Mustache) where complex logic is unnecessary",
            "4. Sandbox the template engine with a restricted execution environment",
        ],
        "code_vulnerable": "# VULNERABLE\nreturn render_template_string(f'Hello {user_input}')",
        "code_fixed": "# FIXED\nreturn render_template_string('Hello {{ name }}', name=user_input)",
        "code_lang": "python",
        "references": [
            ("PortSwigger SSTI", "https://portswigger.net/web-security/server-side-template-injection"),
            ("CWE-94", "https://cwe.mitre.org/data/definitions/94.html"),
        ],
    },

    # ── CRLF ──────────────────────────────────────────────────────────────────
    "crlf": {
        "title": "CRLF Injection / HTTP Response Splitting",
        "short": "Carriage-return and line-feed characters injected into HTTP headers.",
        "description": (
            "CRLF Injection occurs when user input with CR/LF chars is placed in HTTP response "
            "headers. Attackers inject arbitrary headers or split the response, enabling "
            "XSS or cache poisoning."
        ),
        "impact": (
            "HTTP Response Splitting - inject fake response content.\n"
            "XSS via injected headers.\n"
            "Cache poisoning and session fixation attacks."
        ),
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-93",
        "cvss": 6.1,
        "fix_steps": [
            "1. Strip or reject CR (0x0D) and LF (0x0A) from all data placed in HTTP headers",
            "2. URL-encode values placed in the Location redirect header",
            "3. Use a web framework that handles header encoding automatically",
        ],
        "code_vulnerable": "resp.headers['Location'] = user_input  # CRLF injectable",
        "code_fixed": "import re\nclean = re.sub(r'[\r\n]', '', user_input)\nreturn redirect(clean)",
        "code_lang": "python",
        "references": [
            ("OWASP CRLF Injection", "https://owasp.org/www-community/vulnerabilities/CRLF_Injection"),
            ("CWE-93", "https://cwe.mitre.org/data/definitions/93.html"),
        ],
    },

    # ── HOST HEADER ────────────────────────────────────────────────────────────
    "host_header": {
        "title": "Host Header Injection",
        "short": "The application trusts the attacker-controlled Host header.",
        "description": (
            "Host Header Injection occurs when the HTTP Host header is used in password reset "
            "links or redirects without validation. Attackers forge the Host header to redirect "
            "reset emails to their server, enabling account takeover."
        ),
        "impact": (
            "Password reset link hijacking.\n"
            "Web cache poisoning.\n"
            "Account takeover."
        ),
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-20",
        "cvss": 6.5,
        "fix_steps": [
            "1. Maintain a whitelist of allowed Host header values and reject others",
            "2. Configure the web server with a hardcoded base URL for link generation",
            "3. Never use request.host directly in password reset URLs",
        ],
        "code_vulnerable": "reset_url = f'http://{request.host}/reset?token={token}'",
        "code_fixed": "BASE_URL = app.config['BASE_URL']\nreset_url = f'{BASE_URL}/reset?token={token}'",
        "code_lang": "python",
        "references": [
            ("PortSwigger Host Header Attacks", "https://portswigger.net/web-security/host-header"),
            ("CWE-20", "https://cwe.mitre.org/data/definitions/20.html"),
        ],
    },

    # ── CORS ──────────────────────────────────────────────────────────────────
    "cors": {
        "title": "CORS Misconfiguration",
        "short": "Cross-Origin Resource Sharing policy allows unauthorized origins.",
        "description": (
            "CORS misconfigurations allow malicious websites to make cross-origin requests and "
            "read responses. When any origin is reflected with credentials enabled, attackers "
            "can steal sensitive data from authenticated sessions."
        ),
        "impact": (
            "Steal authenticated API responses.\n"
            "Perform actions on behalf of authenticated victims.\n"
            "Account takeover."
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-942",
        "cvss": 8.1,
        "fix_steps": [
            "1. Maintain an explicit whitelist of allowed origins - never wildcard with credentials",
            "2. Validate the Origin header against the whitelist before reflecting it",
            "3. Never combine Access-Control-Allow-Credentials: true with wildcard origin",
        ],
        "code_vulnerable": "response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')",
        "code_fixed": "ALLOWED = {'https://app.example.com'}\nif origin in ALLOWED:\n    response.headers['Access-Control-Allow-Origin'] = origin",
        "code_lang": "python",
        "references": [
            ("OWASP CORS Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html"),
            ("CWE-942", "https://cwe.mitre.org/data/definitions/942.html"),
        ],
    },

    # ── JWT ────────────────────────────────────────────────────────────────────
    "jwt": {
        "title": "JWT Vulnerability",
        "short": "JSON Web Token has cryptographic or validation weaknesses.",
        "description": (
            "JWT vulnerabilities arise from accepting the none algorithm, improper signature "
            "verification, or missing expiry claims. Attackers can forge tokens to bypass "
            "authentication or escalate privileges."
        ),
        "impact": (
            "Authentication bypass.\n"
            "Privilege escalation to admin.\n"
            "Account takeover."
        ),
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-345",
        "cvss": 9.8,
        "fix_steps": [
            "1. Always specify and enforce the expected algorithm - never allow none",
            "2. Always include and validate the exp (expiry) claim",
            "3. Use asymmetric algorithms (RS256, ES256) for externally consumed tokens",
            "4. Use a maintained JWT library and never implement from scratch",
        ],
        "code_vulnerable": "payload = jwt.decode(token, key, algorithms=['HS256', 'none'])",
        "code_fixed": "payload = jwt.decode(token, SECRET, algorithms=['HS256'],\n                     options={'require': ['exp', 'iat']})",
        "code_lang": "python",
        "references": [
            ("PortSwigger JWT Attacks", "https://portswigger.net/web-security/jwt"),
            ("CWE-345", "https://cwe.mitre.org/data/definitions/345.html"),
        ],
    },

    # ── SSRF ──────────────────────────────────────────────────────────────────
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF)",
        "short": "The server makes HTTP requests to attacker-controlled URLs.",
        "description": (
            "SSRF allows attackers to induce the server to fetch arbitrary URLs, "
            "exposing internal cloud metadata APIs, databases, and admin interfaces "
            "behind firewalls."
        ),
        "impact": (
            "Steal cloud IAM credentials (AWS/GCP/Azure metadata).\n"
            "Attack internal services.\n"
            "Bypass firewalls and access controls."
        ),
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "cwe": "CWE-918",
        "cvss": 9.3,
        "fix_steps": [
            "1. Implement an allowlist of permitted domains/IPs - reject all others",
            "2. Block requests to private IP ranges (10.x, 172.16.x, 169.254.x, 127.x)",
            "3. Block dangerous URL schemes: file, gopher, dict, ftp",
            "4. Use a dedicated egress proxy that enforces the allowlist",
        ],
        "code_vulnerable": "resp = requests.get(request.args.get('url'))  # SSRF",
        "code_fixed": "ALLOWED = {'api.example.com'}\nif urlparse(url).hostname not in ALLOWED:\n    abort(400)",
        "code_lang": "python",
        "references": [
            ("OWASP SSRF Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"),
            ("CWE-918", "https://cwe.mitre.org/data/definitions/918.html"),
        ],
    },

    # ── LOG4SHELL ──────────────────────────────────────────────────────────────
    "log4shell": {
        "title": "Log4Shell / Log4j RCE (CVE-2021-44228)",
        "short": "Critical Java Log4j vulnerability allowing Remote Code Execution via JNDI.",
        "description": (
            "Log4Shell is a critical zero-day in Apache Log4j 2.x. Logging user-supplied "
            "data containing a JNDI lookup causes the server to fetch and execute remote code. "
            "CVSS 10.0 - the highest possible severity."
        ),
        "impact": (
            "Unauthenticated Remote Code Execution.\n"
            "Complete server compromise.\n"
            "Ransomware deployment and lateral movement."
        ),
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "cwe": "CWE-502",
        "cvss": 10.0,
        "fix_steps": [
            "1. IMMEDIATELY upgrade Log4j to 2.17.1+ (Java 8) or 2.12.4+ (Java 7)",
            "2. Set LOG4J_FORMAT_MSG_NO_LOOKUPS=true as temporary mitigation",
            "3. Block outbound LDAP/RMI at the firewall",
            "4. Monitor logs for JNDI lookup patterns and alert immediately",
        ],
        "code_vulnerable": "<!-- pom.xml VULNERABLE -->\n<log4j-core.version>2.14.0</log4j-core.version>",
        "code_fixed": "<!-- pom.xml PATCHED -->\n<log4j-core.version>2.17.1</log4j-core.version>",
        "code_lang": "xml",
        "references": [
            ("CVE-2021-44228 NVD", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
            ("Apache Log4j Security", "https://logging.apache.org/log4j/2.x/security.html"),
        ],
    },

    # ── NOSQL ──────────────────────────────────────────────────────────────────
    "nosql": {
        "title": "NoSQL Injection",
        "short": "Unsanitized input manipulates NoSQL database queries.",
        "description": (
            "NoSQL Injection allows attackers to manipulate MongoDB/CouchDB queries via "
            "operator injection. Attackers bypass authentication or extract full collections "
            "by injecting query operators into user-supplied JSON input."
        ),
        "impact": (
            "Authentication bypass without valid credentials.\n"
            "Full data collection dump.\n"
            "Data modification and deletion."
        ),
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-943",
        "cvss": 9.8,
        "fix_steps": [
            "1. Never pass raw user input directly as a query object",
            "2. Cast and validate types - IDs must be strings, not objects",
            "3. Use an ODM with strict schema validation",
            "4. Reject requests where JSON body contains MongoDB operator keys",
        ],
        "code_vulnerable": "user = db.users.find_one({'user': request.json['user']})",
        "code_fixed": "username = str(request.json.get('user', ''))\nif '$' in username: abort(400)\nuser = db.users.find_one({'user': username})",
        "code_lang": "python",
        "references": [
            ("OWASP NoSQL Injection", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"),
            ("CWE-943", "https://cwe.mitre.org/data/definitions/943.html"),
        ],
    },

    # ── CLICKJACKING ────────────────────────────────────────────────────────────
    "clickjacking": {
        "title": "Clickjacking Vulnerability",
        "short": "Page can be framed in iframes, enabling UI redress attacks.",
        "description": (
            "Clickjacking allows attackers to overlay a legitimate page in a transparent iframe. "
            "Victims perform unintended actions (transfers, setting changes) without knowledge."
        ),
        "impact": (
            "Trick users into performing unintended actions.\n"
            "Force social media actions.\n"
            "Account setting changes without user consent."
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1021",
        "cvss": 4.3,
        "fix_steps": [
            "1. Add X-Frame-Options: DENY or SAMEORIGIN header",
            "2. Add Content-Security-Policy: frame-ancestors none directive",
            "3. Set both headers for maximum browser compatibility",
        ],
        "code_vulnerable": "# No X-Frame-Options header set on responses",
        "code_fixed": "r.headers['X-Frame-Options'] = 'DENY'\\nr.headers['Content-Security-Policy'] = 'frame-ancestors none'",
        "code_lang": "python",
        "references": [
            ("OWASP Clickjacking Defense", "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"),
            ("CWE-1021", "https://cwe.mitre.org/data/definitions/1021.html"),
        ],
    },

    # ── GRAPHQL ────────────────────────────────────────────────────────────────
    "graphql": {
        "title": "GraphQL Introspection Enabled",
        "short": "GraphQL introspection exposes the full API schema in production.",
        "description": (
            "GraphQL introspection allows any client to query the complete API schema. "
            "In production this gives attackers a full map of all types, fields, and mutations, "
            "making it easier to discover hidden endpoints and attack vectors."
        ),
        "impact": (
            "Full API schema disclosure to attackers.\n"
            "Discovery of hidden internal API fields.\n"
            "Information that aids targeted exploitation."
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200",
        "cvss": 5.3,
        "fix_steps": [
            "1. Disable introspection in production (introspection=False)",
            "2. Implement query depth limiting",
            "3. Add query complexity analysis to prevent resource exhaustion",
            "4. Use query allowlisting in production",
        ],
        "code_vulnerable": "# GraphQL introspection ON by default",
        "code_fixed": "# Set GRAPHQL_INTROSPECTION=false in production environment",
        "code_lang": "python",
        "references": [
            ("OWASP GraphQL Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"),
            ("PortSwigger GraphQL", "https://portswigger.net/web-security/graphql"),
        ],
    },

    # ── SUBDOMAIN TAKEOVER ────────────────────────────────────────────────────
    "subdomain": {
        "title": "Subdomain Takeover Risk",
        "short": "DNS record points to an unclaimed or deleted cloud service.",
        "description": (
            "A CNAME DNS record points to an external service that no longer exists. "
            "Attackers can register the service and serve malicious content from your "
            "legitimate subdomain, including phishing pages or malware."
        ),
        "impact": (
            "Serve phishing pages from your trusted domain.\n"
            "Steal session cookies scoped to the parent domain.\n"
            "Brand reputation damage."
        ),
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-350",
        "cvss": 9.3,
        "fix_steps": [
            "1. Audit all DNS CNAME records and remove entries for decommissioned services",
            "2. Before deleting a cloud service, FIRST remove the DNS record",
            "3. Regularly scan DNS records for dangling entries (subjack, nuclei)",
        ],
        "code_vulnerable": "# staging.example.com CNAME deleted-app.azurewebsites.net",
        "code_fixed": "# Remove CNAME or redirect to active service\n# staging.example.com CNAME www.example.com",
        "code_lang": "text",
        "references": [
            ("HackerOne Subdomain Takeover", "https://www.hackerone.com/blog/Guide-Subdomain-Takeovers"),
            ("CWE-350", "https://cwe.mitre.org/data/definitions/350.html"),
        ],
    },

    # ── SENSITIVE FILE ────────────────────────────────────────────────────────
    "sensitive_file": {
        "title": "Sensitive File Exposed",
        "short": "Configuration files or backups are publicly accessible.",
        "description": (
            "Sensitive files such as .env, .git directories, config files, or backup archives "
            "are accessible via direct URL, containing database credentials, API keys, "
            "or source code that enables further attacks."
        ),
        "impact": (
            "Database credential exposure - full database compromise.\n"
            "API key theft.\n"
            "Secret key exposure - forge authentication tokens.\n"
            "Source code disclosure."
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200",
        "cvss": 7.5,
        "fix_steps": [
            "1. Move sensitive files OUTSIDE the web root directory",
            "2. Configure web server to deny access to sensitive file patterns",
            "3. Remove .git, .env, and backup files from production deployments",
            "4. Use environment variables or secrets management instead of config files",
        ],
        "code_vulnerable": "# .env file in webroot contains: DB_PASSWORD=secret123",
        "code_fixed": "# nginx config:\nlocation ~* /\\.(env|git|htaccess) { deny all; return 404; }\nlocation ~* \\.(bak|sql|tar|gz)$ { deny all; return 404; }",
        "code_lang": "nginx",
        "references": [
            ("OWASP Configuration Testing", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"),
            ("CWE-200", "https://cwe.mitre.org/data/definitions/200.html"),
        ],
    },

    # ── RATE LIMITING ──────────────────────────────────────────────────────────
    "rate_limiting": {
        "title": "Missing Rate Limiting",
        "short": "Authentication endpoints have no rate limiting, enabling brute force.",
        "description": (
            "Absence of rate limiting on login, password reset, or OTP endpoints allows "
            "automated brute force attacks. Attackers systematically try millions of password "
            "combinations without being blocked."
        ),
        "impact": (
            "Brute force attacks against user passwords.\n"
            "OTP and 2FA bypass via rapid enumeration.\n"
            "Credential stuffing from leaked databases."
        ),
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "cwe": "CWE-307",
        "cvss": 7.5,
        "fix_steps": [
            "1. Implement rate limiting: max 10 failed attempts per IP per 15 minutes",
            "2. Use progressive delays after failed attempts",
            "3. Add account lockout with email-based unlock",
            "4. Use flask-limiter or django-ratelimit",
        ],
        "code_vulnerable": "@app.route('/login', methods=['POST'])\ndef login(): ...  # No rate limiting",
        "code_fixed": "@app.route('/login', methods=['POST'])\n@limiter.limit('10 per minute')\ndef login(): ...",
        "code_lang": "python",
        "references": [
            ("OWASP Authentication Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"),
            ("CWE-307", "https://cwe.mitre.org/data/definitions/307.html"),
        ],
    },

    # ── WAF ──────────────────────────────────────────────────────────────────
    "waf": {
        "title": "WAF / CDN Detected",
        "short": "A Web Application Firewall or CDN is protecting this application.",
        "description": (
            "A WAF or CDN (Cloudflare, Akamai, AWS WAF) has been detected. This is a positive "
            "security control but should not be the only defence. WAFs can be bypassed and "
            "should complement, not replace, secure coding practices."
        ),
        "impact": (
            "Informational - WAF provides some protection but can be bypassed.\n"
            "Over-reliance on WAF leads to neglecting code-level security."
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-16",
        "cvss": 0.0,
        "fix_steps": [
            "1. Treat WAF as one defence layer - also fix vulnerabilities at the code level",
            "2. Keep WAF rules updated and in blocking (not detection-only) mode",
            "3. Ensure the real origin IP is not exposed directly",
        ],
        "code_vulnerable": "",
        "code_fixed": "",
        "code_lang": "text",
        "references": [
            ("OWASP WAF", "https://owasp.org/www-project-web-application-firewall-evaluation-criteria/"),
        ],
    },

    # ── HTTP METHOD ────────────────────────────────────────────────────────────
    "http_method": {
        "title": "Dangerous HTTP Method Enabled",
        "short": "PUT, DELETE, or PATCH methods enabled where they should not be.",
        "description": (
            "HTTP methods such as PUT, DELETE, PATCH, and TRACE are enabled on endpoints "
            "that should not support them, potentially allowing file uploads, content deletion, "
            "or XST (Cross-Site Tracing) attacks."
        ),
        "impact": (
            "File upload via PUT to web-accessible directories.\n"
            "Content deletion or modification.\n"
            "XST attacks via TRACE method."
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-16",
        "cvss": 6.5,
        "fix_steps": [
            "1. Disable TRACE and TRACK methods on the web server",
            "2. Only allow HTTP methods required by the application (GET and POST)",
            "3. Configure web server to return 405 for unneeded methods",
        ],
        "code_vulnerable": "# nginx: all methods allowed by default",
        "code_fixed": "location / {\n    limit_except GET POST { deny all; }\n}",
        "code_lang": "nginx",
        "references": [
            ("OWASP Testing HTTP Methods", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"),
            ("CWE-16", "https://cwe.mitre.org/data/definitions/16.html"),
        ],
    },

    # ── HTTP VERB TAMPERING ────────────────────────────────────────────────────
    "http_verb": {
        "title": "HTTP Verb Tampering",
        "short": "Changing the HTTP method bypasses authorization controls.",
        "description": (
            "HTTP Verb Tampering exploits apps that check authorization based on HTTP method. "
            "Using unexpected methods (PUT, DELETE, PATCH) can bypass access controls or "
            "trigger unintended server behaviour."
        ),
        "impact": (
            "Bypass authentication checks on protected endpoints.\n"
            "Delete or modify data without authorization.\n"
            "Access admin functions with unprivileged accounts."
        ),
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-863",
        "cvss": 8.1,
        "fix_steps": [
            "1. Check authorization on every request regardless of HTTP method",
            "2. Restrict routes to only required HTTP methods",
            "3. Return 405 Method Not Allowed for unsupported methods",
            "4. Disable TRACE and TRACK at the web server level",
        ],
        "code_vulnerable": "@app.route('/admin', methods=['GET', 'POST'])\ndef admin(): check_if_post()  # GET bypasses",
        "code_fixed": "@app.route('/admin', methods=['POST'])\n@login_required\n@admin_required\ndef admin(): ...",
        "code_lang": "python",
        "references": [
            ("OWASP HTTP Verb Tampering", "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering"),
            ("CWE-863", "https://cwe.mitre.org/data/definitions/863.html"),
        ],
    },

    # ── MASS ASSIGNMENT ────────────────────────────────────────────────────────
    "mass_assignment": {
        "title": "Mass Assignment Vulnerability",
        "short": "User-supplied data is bound directly to models without field whitelisting.",
        "description": (
            "Mass Assignment occurs when HTTP request parameters are automatically bound to "
            "model objects without restricting which fields can be set. Attackers can set "
            "privileged fields (isAdmin, role, balance) by including them in the request."
        ),
        "impact": (
            "Privilege escalation - set isAdmin=true or role=admin.\n"
            "Account balance manipulation.\n"
            "Override security fields such as verified or mfa_enabled."
        ),
        "owasp": "A04:2021 - Insecure Design",
        "cwe": "CWE-915",
        "cvss": 8.8,
        "fix_steps": [
            "1. Use explicit field whitelisting - only bind expected user-controllable fields",
            "2. Use serializer classes that declare allowed fields",
            "3. Never pass request.json directly to model constructors",
        ],
        "code_vulnerable": "user.__dict__.update(request.json)  # Attacker sets role=admin",
        "code_fixed": "ALLOWED = {'username', 'email', 'bio'}\ndata = {k: v for k, v in request.json.items() if k in ALLOWED}",
        "code_lang": "python",
        "references": [
            ("OWASP Mass Assignment Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"),
            ("CWE-915", "https://cwe.mitre.org/data/definitions/915.html"),
        ],
    },
}


def get_remediation(vuln_type: str) -> dict:
    """
    Get remediation data for a vulnerability type.
    Falls back to a generic entry if the type is not in the DB.
    """
    # Normalize the type string
    key = vuln_type.lower().strip().replace(" ", "_").replace("-", "_")

    # Direct lookup
    if key in REMEDIATION_DB:
        return REMEDIATION_DB[key]

    # Fuzzy match
    for db_key in REMEDIATION_DB:
        if db_key in key or key in db_key:
            return REMEDIATION_DB[db_key]

    # Generic fallback
    return {
        "title":       vuln_type,
        "short":       "Security vulnerability requiring remediation.",
        "description": "Review the vulnerability evidence and apply appropriate security controls.",
        "impact":      "Potential unauthorized access, data exposure, or system compromise.",
        "owasp":       "OWASP Top 10",
        "cwe":         "See finding details",
        "cvss":        5.0,
        "fix_steps":   [
            "1. Review the vulnerability details and evidence provided",
            "2. Apply input validation and output encoding",
            "3. Follow the principle of least privilege",
            "4. Implement defense-in-depth controls",
            "5. Test the fix with automated scanning",
        ],
        "code_vulnerable": "",
        "code_fixed":      "",
        "code_lang":       "text",
        "references":      [
            ("OWASP Top 10", "https://owasp.org/www-project-top-ten/"),
            ("NVD Vulnerability Database", "https://nvd.nist.gov/"),
        ],
    }
