"""routes/admin.py — Admin panel: user management, system stats."""

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from bson.objectid import ObjectId
from database import db, User, Scan, Vulnerability

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


@admin_bp.route("/")
@login_required
@admin_required
def dashboard():
    from collections import Counter
    from datetime import datetime, timedelta

    users = [User(u) for u in db.users.find().sort("created_at", -1)]
    all_scans = [Scan(s) for s in db.scans.find()]
    
    # Aggregate vulnerabilities of all scans
    pipeline = [
        {"$unwind": "$vulnerabilities"},
        {"$replaceRoot": {"newRoot": "$vulnerabilities"}}
    ]
    try:
        all_vulns = [Vulnerability(v) for v in db.scans.aggregate(pipeline)]
    except Exception:
        # Fallback for mongomock which might not fully support MongoDB aggregations
        all_vulns = []
        for s in all_scans:
            all_vulns.extend(s.vulnerabilities)

    total_users    = len(users)
    total_scans    = len(all_scans)
    total_vulns    = len(all_vulns)
    total_high     = sum(1 for v in all_vulns if v.severity == "High")
    total_critical = sum(1 for v in all_vulns if v.severity == "Critical")
    total_medium   = sum(1 for v in all_vulns if v.severity == "Medium")
    total_low      = sum(1 for v in all_vulns if v.severity == "Low")
    active_users   = sum(1 for u in users if getattr(u, "is_active", True))
    admin_count    = sum(1 for u in users if u.role == "admin")
    analyst_count  = sum(1 for u in users if u.role == "analyst")

    # Per-user scan and vulnerability counts
    scans_by_user = Counter(s.user_id for s in all_scans)
    vulns_by_user = Counter()
    for s in all_scans:
        vulns_by_user[s.user_id] += len(s.vulnerabilities)

    user_stats = []
    for u in users:
        user_stats.append({
            "user": u,
            "scan_count": scans_by_user.get(u.id, 0),
            "vuln_count": vulns_by_user.get(u.id, 0),
        })

    # Top 5 scanners
    top_scanners = sorted(user_stats, key=lambda x: x["scan_count"], reverse=True)[:5]

    # Registration timeline — last 7 days
    today = datetime.utcnow().date()
    reg_dates = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    reg_labels = [d.strftime("%m/%d") for d in reg_dates]
    reg_counts = []
    for d in reg_dates:
        c = sum(1 for u in users if u.created_at and u.created_at.date() == d)
        reg_counts.append(c)

    # Scans per day — last 7 days
    scan_labels = reg_labels
    scan_counts = []
    for d in reg_dates:
        c = sum(1 for s in all_scans if s.start_time and s.start_time.date() == d)
        scan_counts.append(c)

    # Running scans
    running_scans = [s for s in all_scans if s.status == "running"]
    completed_scans = sum(1 for s in all_scans if s.status == "completed")
    failed_scans = sum(1 for s in all_scans if s.status == "failed")

    # Recent scans limit 15
    recent_cursor = db.scans.find().sort("_id", -1).limit(15)
    recent_scans = [Scan(s) for s in recent_cursor]

    return render_template(
        "admin/dashboard.html",
        users=users,
        user_stats=user_stats,
        top_scanners=top_scanners,
        total_users=total_users,
        active_users=active_users,
        admin_count=admin_count,
        analyst_count=analyst_count,
        total_scans=total_scans,
        total_vulns=total_vulns,
        total_high=total_high,
        total_critical=total_critical,
        total_medium=total_medium,
        total_low=total_low,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        running_scans=running_scans,
        reg_labels=reg_labels,
        reg_counts=reg_counts,
        scan_labels=scan_labels,
        scan_counts=scan_counts,
        recent_scans=recent_scans,
    )


@admin_bp.route("/users/<user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_user(user_id):
    user = User.get(user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash("Cannot deactivate yourself.", "error")
    else:
        new_status = not getattr(user, "is_active", True)
        db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"is_active": new_status}})
        flash(f"User {user.username} {'activated' if new_status else 'deactivated'}.", "success")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/users/<user_id>/role", methods=["POST"])
@login_required
@admin_required
def change_role(user_id):
    user = User.get(user_id)
    if not user:
        abort(404)
    new_role = request.form.get("role", "analyst")
    if new_role in ("admin", "analyst"):
        db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": new_role}})
        flash(f"Role updated to {new_role} for {user.username}.", "success")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/users/<user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = User.get(user_id)
    if not user or user.id == current_user.id:
        flash("Cannot delete yourself.", "error")
        return redirect(url_for("admin.dashboard"))
    
    # Delete user
    db.users.delete_one({"_id": ObjectId(user_id)})
    # Delete user's scans
    db.scans.delete_many({"user_id": ObjectId(user_id)})
    
    flash(f"User {user.username} deleted.", "info")
    return redirect(url_for("admin.dashboard"))


# ── DATABASE VIEWER / INSPECTOR ROUTE ─────────────────────────────────────────
@admin_bp.route("/db-viewer")
@login_required
@admin_required
def db_viewer():
    # 1. Fetch available collections & document counts
    col_names = sorted(db.list_collection_names())
    collections = []
    for name in col_names:
        collections.append({
            "name": name,
            "count": db[name].count_documents({})
        })

    # 2. Get active collection documents
    active_col = request.args.get("col", "scans")
    if active_col not in col_names and col_names:
        active_col = col_names[0]

    documents = []
    if active_col in col_names:
        cursor = db[active_col].find().sort("_id", -1).limit(100)
        documents = list(cursor)

    return render_template(
        "admin/db_viewer.html",
        collections=collections,
        active_col=active_col,
        documents=documents
    )


@admin_bp.route("/db-viewer/doc")
@login_required
@admin_required
def db_viewer_doc():
    from datetime import datetime
    col_name = request.args.get("col", "")
    doc_id = request.args.get("id", "")
    
    if not col_name or not doc_id:
        return {"error": "Missing params"}, 400

    try:
        doc = db[col_name].find_one({"_id": ObjectId(doc_id)})
    except Exception as e:
        return {"error": str(e)}, 400

    if not doc:
        return {"error": "Document not found"}, 404

    # Helper to serialize MongoDB documents to JSON
    def serialize(v):
        if isinstance(v, ObjectId):
            return str(v)
        if isinstance(v, datetime):
            return v.isoformat()
        if isinstance(v, list):
            return [serialize(item) for item in v]
        if isinstance(v, dict):
            return {key: serialize(val) for key, val in v.items()}
        return v

    return serialize(doc)


# ── SYSTEM MONITOR & CONFIGURATION EDITOR ─────────────────────────────────────
@admin_bp.route("/system")
@login_required
@admin_required
def system_dashboard():
    import platform
    import sys
    import threading
    from flask import current_app
    from scanner.scan_controller import _active_scans

    # 1. Gather System Metrics
    system_stats = {
        "os":             platform.system(),
        "release":        platform.release(),
        "python":         sys.version.split()[0],
        "threads":        threading.active_count(),
        "active_scans":   len(_active_scans) if '_active_scans' in globals() or _active_scans is not None else 0,
        "cpu_percent":    None,
        "memory_percent": None
    }
    try:
        import psutil
        system_stats["cpu_percent"] = psutil.cpu_percent()
        system_stats["memory_percent"] = psutil.virtual_memory().percent
    except ImportError:
        pass

    # 2. Gather MongoDB stats
    db_stats = {
        "db":           db.name,
        "collections":  len(db.list_collection_names()),
        "objects":      0,
        "avg_obj_size": 0.0,
        "data_size":    0.0,
        "storage_size": 0.0
    }
    try:
        raw_stats = db.command("dbstats")
        db_stats["objects"] = raw_stats.get("objects", 0)
        db_stats["avg_obj_size"] = round(raw_stats.get("avgObjSize", 0) / 1024, 2)
        db_stats["data_size"] = round(raw_stats.get("dataSize", 0) / (1024 * 1024), 2)
        db_stats["storage_size"] = round(raw_stats.get("storageSize", 0) / (1024 * 1024), 2)
    except Exception:
        # Fallback if command fails (e.g. in test/mongomock environment)
        pass

    # 3. Pull Current Configurations
    config_data = {
        "MAX_CRAWL_DEPTH": current_app.config.get("MAX_CRAWL_DEPTH", 3),
        "MAX_CRAWL_PAGES": current_app.config.get("MAX_CRAWL_PAGES", 100),
        "REQUEST_TIMEOUT": current_app.config.get("REQUEST_TIMEOUT", 10),
        "DEFAULT_SCAN_PORTS": ", ".join(map(str, current_app.config.get("DEFAULT_SCAN_PORTS", [80, 443]))),
        "API_KEY":            current_app.config.get("API_KEY", "awvs_secret_api_key_2026")
    }

    return render_template(
        "admin/system.html",
        system_stats=system_stats,
        db_stats=db_stats,
        config_data=config_data
    )


@admin_bp.route("/system/save", methods=["POST"])
@login_required
@admin_required
def save_system_config():
    import os
    from flask import current_app

    # 1. Parse parameters
    try:
        max_depth = int(request.form.get("max_crawl_depth", 3))
        max_pages = int(request.form.get("max_crawl_pages", 100))
        timeout = int(request.form.get("request_timeout", 10))
        ports_str = request.form.get("default_scan_ports", "80,443")
        api_key = request.form.get("api_key", "awvs_secret_api_key_2026").strip()

        # Parse ports array
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip().isdigit()]
    except Exception as e:
        flash(f"Invalid input formats: {e}", "error")
        return redirect(url_for("admin.system_dashboard"))

    # 2. Update config in memory
    current_app.config["MAX_CRAWL_DEPTH"] = max_depth
    current_app.config["MAX_CRAWL_PAGES"] = max_pages
    current_app.config["REQUEST_TIMEOUT"] = timeout
    current_app.config["DEFAULT_SCAN_PORTS"] = ports
    current_app.config["API_KEY"] = api_key

    # 3. Persist to .env file
    def update_env(key, val):
        env_path = ".env"
        if not os.path.exists(env_path):
            return
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        found = False
        for idx, line in enumerate(lines):
            if line.strip().startswith(f"{key}="):
                lines[idx] = f"{key}={val}\n"
                found = True
                break
        if not found:
            lines.append(f"{key}={val}\n")
        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

    try:
        update_env("MAX_CRAWL_DEPTH", max_depth)
        update_env("MAX_CRAWL_PAGES", max_pages)
        update_env("REQUEST_TIMEOUT", timeout)
        update_env("AWVS_API_KEY", api_key)
        flash("System configurations updated and saved to disk.", "success")
    except Exception as err:
        flash(f"Updated in memory, but failed to write to .env: {err}", "warning")

    return redirect(url_for("admin.system_dashboard"))


