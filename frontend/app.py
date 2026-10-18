"""
app.py — Flask Application Factory (v4 — Industry-Grade — MongoDB)
"""
import os
import logging
from flask import Flask, render_template
from flask_login import LoginManager
from config import Config
from database import init_db, User

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)

    # Initialize MongoDB connection
    init_db(app.config["MONGO_URI"])

    # ── LOGIN MANAGER ─────────────────────────────────────────────────────────
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access the scanner."
    login_manager.login_message_category = "info"

    @login_manager.user_loader
    def load_user(user_id):
        return User.get(user_id)

    # ── BLUEPRINTS ────────────────────────────────────────────────────────────
    from routes.auth   import auth_bp
    from routes.scan   import scan_bp
    from routes.report import report_bp
    from routes.admin  import admin_bp
    from routes.export import export_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(export_bp)

    # ── JINJA2 CUSTOM FILTERS ─────────────────────────────────────────────────
    import json as _json
    @app.template_filter('from_json')
    def from_json_filter(val):
        if not val:
            return []
        try:
            if isinstance(val, str):
                return _json.loads(val)
            return val
        except Exception:
            return []

    # ── ERROR HANDLERS ────────────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("errors/500.html"), 500

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    # ── RATE LIMITING & CSRF PROTECTION ───────────────────────────────────────
    from collections import defaultdict
    import time
    import threading
    
    login_attempts = defaultdict(list)
    rate_limit_lock = threading.Lock()

    @app.before_request
    def validate_csrf_and_rate_limit():
        from flask import request, session, abort
        import os
        
        # 1. Ensure CSRF token exists
        if "csrf_token" not in session:
            session["csrf_token"] = os.urandom(24).hex()
            
        # 2. Login Rate Limiting (CWE-307)
        if request.path == "/login" and request.method == "POST":
            ip = request.remote_addr or "127.0.0.1"
            now = time.time()
            with rate_limit_lock:
                login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 60]
                if len(login_attempts[ip]) >= 5:
                    abort(429, "Too many login attempts. Please wait 1 minute before retrying.")
                login_attempts[ip].append(now)

        # 3. CSRF Validation (CWE-352)
        if request.method in ("POST", "PUT", "DELETE"):
            if request.path.startswith("/api/") or request.path.startswith("/auto"):
                return
            csrf_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            session_token = session.get("csrf_token")
            if not session_token or csrf_token != session_token:
                abort(400, "CSRF token missing or invalid")

    @app.context_processor
    def inject_csrf():
        from flask import session
        return dict(csrf_token=lambda: session.get("csrf_token", ""))

    # ── CORS & SECURITY HEADERS ────────────────────────────────────────────────
    @app.before_request
    def handle_preflight():
        from flask import request, make_response
        if request.method == "OPTIONS":
            response = make_response()
            origin = request.headers.get("Origin")
            if origin:
                if "localhost" in origin or "127.0.0.1" in origin or origin.startswith("chrome-extension://") or "trycloudflare.com" in origin:
                    response.headers["Access-Control-Allow-Origin"] = origin
                    response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, Authorization"
            response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
            return response

    @app.after_request
    def set_security_headers(response):
        from flask import request, session
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]          = "SAMEORIGIN"
        response.headers["X-XSS-Protection"]         = "1; mode=block"
        response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
        
        # 2. Content-Security-Policy (CSP)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' https://*.trycloudflare.com http://127.0.0.1:5000 http://localhost:5000;"
        )
        
        # 3. Strict-Transport-Security (HSTS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        # 4. Permissions-Policy
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # 5. Restrict CORS (No Wildcard ACAO)
        origin = request.headers.get("Origin")
        if origin:
            if "localhost" in origin or "127.0.0.1" in origin or origin.startswith("chrome-extension://") or "trycloudflare.com" in origin:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, Authorization"
                response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
        
        if "Server" in response.headers:
            del response.headers["Server"]
            
        # 6. Auto-Inject CSRF hidden input into HTML POST forms
        # Skip passthrough/streaming responses (e.g. send_file) — they cannot be buffered.
        is_download = bool(response.headers.get("Content-Disposition"))
        is_streaming = response.direct_passthrough
        if (
            response.headers.get("Content-Type", "").startswith("text/html")
            and not is_download
            and not is_streaming
        ):
            csrf_token = session.get("csrf_token")
            if csrf_token:
                try:
                    html = response.get_data(as_text=True)
                    import re
                    csrf_input = f'\n<input type="hidden" name="csrf_token" value="{csrf_token}">'
                    pattern = re.compile(r'(<form[^>]*method=["\']post["\'][^>]*>)', re.IGNORECASE)
                    modified_html = pattern.sub(rf'\1{csrf_input}', html)
                    response.set_data(modified_html)
                except RuntimeError:
                    pass  # Passthrough response — skip injection
                
        return response



    # ── START AUTOMATION DAEMON ───────────────────────────────────────────────
    try:
        from scanner.automation_daemon import start_automation_daemon
        start_automation_daemon(app)
    except Exception as ae:
        app.logger.error(f"Failed to start automation daemon: {ae}")

    return app
