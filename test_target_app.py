"""
test_target_app.py
──────────────────────────────────────────────────────────────────────────────
Deliberately vulnerable Flask app for testing the AWVS scanner.
Run on port 8888:  python test_target_app.py

⚠️  FOR LOCAL TESTING ONLY — DO NOT DEPLOY PUBLICLY ⚠️

Contains controlled, intentional vulnerabilities:
  1. Reflected XSS in /search
  2. SQL error disclosure in /user
  3. Missing CSRF token in /contact
  4. Missing security headers
  5. Open redirect in /redirect
  6. Directory listing hint in /files
"""

from flask import Flask, request, redirect

app = Flask(__name__)


@app.after_request
def remove_security_headers(response):
    """Deliberately remove security headers for testing."""
    response.headers.pop("X-Content-Type-Options", None)
    # No CSP, no HSTS, no X-Frame-Options
    return response


# ── 1. REFLECTED XSS ─────────────────────────────────────────
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Vulnerable: directly injects user input into HTML response
    return f"""
    <html><body>
      <h1>Search Results</h1>
      <p>You searched for: {query}</p>
      <form action="/search">
        <input name="q" value="{query}">
        <button>Search</button>
      </form>
    </body></html>
    """, 200, {"Content-Type": "text/html"}


# ── 2. SQL ERROR DISCLOSURE ───────────────────────────────────
@app.route("/user")
def user():
    user_id = request.args.get("id", "1")
    # Simulates SQL error message in response
    if "'" in user_id or '"' in user_id:
        return (
            "You have an error in your SQL syntax; "
            "check the manual that corresponds to your MySQL server version "
            f"for the right syntax to use near '{user_id}' at line 1"
        ), 500
    return f"<html><body><h1>User {user_id}</h1><p>Profile page</p></body></html>"


# ── 3. MISSING CSRF TOKEN ─────────────────────────────────────
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        msg = request.form.get("message", "")
        return f"<p>Message received: {msg}</p>"
    # No CSRF token in this form
    return """
    <html><body>
      <h1>Contact Us</h1>
      <form method="POST" action="/contact">
        <input name="name" placeholder="Name">
        <textarea name="message" placeholder="Message"></textarea>
        <button type="submit">Send</button>
      </form>
    </body></html>
    """


# ── 4. OPEN REDIRECT ──────────────────────────────────────────
@app.route("/redirect")
def open_redirect():
    target = request.args.get("url", "/")
    return redirect(target)


# ── 5. HOME PAGE ──────────────────────────────────────────────
@app.route("/")
def home():
    return """
    <html><body>
      <h1>Test Vulnerable App</h1>
      <p>This app is intentionally vulnerable for AWVS testing.</p>
      <ul>
        <li><a href="/search?q=hello">Search (XSS)</a></li>
        <li><a href="/user?id=1">User Profile (SQLi)</a></li>
        <li><a href="/contact">Contact Form (CSRF)</a></li>
        <li><a href="/redirect?url=https://google.com">Redirect (Open Redirect)</a></li>
      </ul>
    </body></html>
    """


if __name__ == "__main__":
    print("=" * 60)
    print("[!] DELIBERATELY VULNERABLE TEST APP")
    print("[!] FOR LOCAL AWVS TESTING ONLY")
    print("=" * 60)
    print("Running on http://127.0.0.1:8888")
    app.run(host="127.0.0.1", port=8888, debug=False)
