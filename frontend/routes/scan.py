"""routes/scan.py — Scan management routes and real-time status API."""

import json
import time
from datetime import datetime, timedelta
from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, jsonify, current_app, abort, Response, stream_with_context)
from flask_login import login_required, current_user
from bson.objectid import ObjectId

import requests as _requests
from database import db, Scan, User, Vulnerability
from scanner.scan_controller import get_scan_state


def _trigger_backend_scan(scan_id, cfg):
    """Delegate scan execution to the FastAPI backend (fully decoupled)."""
    from config import Config
    url = f"http://127.0.0.1:8000/api/v1/scans/{scan_id}/start"
    headers = {"X-API-Key": Config.API_KEY, "Content-Type": "application/json"}
    try:
        _requests.post(url, json={"config": cfg}, headers=headers, timeout=5)
    except Exception as e:
        print(f"[-] Could not reach FastAPI backend to start scan: {e}")

scan_bp = Blueprint("scan", __name__)


# Helpers for nested classes wrapper
class ReconResultWrapper:
    def __init__(self, data):
        self.open_ports = data.get("open_ports", "[]")
        self.detected_tech = data.get("detected_tech", "[]")
        self.server_banner = data.get("server_banner", "")
        self.whois_info = data.get("whois_info", "")
        self.ssl_info = data.get("ssl_info", "{}")
        self.http_headers = data.get("http_headers", "{}")
        self.ip_address = data.get("ip_address", "")


class CrawledPageWrapper:
    def __init__(self, data):
        self.page_id = data.get("page_id")
        self.url = data.get("url")
        self.method = data.get("method", "GET")
        self.params = data.get("params")
        self.status_code = data.get("status_code")
        self.content_type = data.get("content_type")
        self.depth = data.get("depth", 0)


class NoteAuthorWrapper:
    def __init__(self, name):
        self.username = name


class NoteWrapper:
    def __init__(self, data):
        self.note_id = data.get("note_id")
        self.content = data.get("content")
        self.created_at = data.get("created_at")
        self.author = NoteAuthorWrapper(data.get("author_name", "Analyst"))


# ── DASHBOARD ─────────────────────────────────────────────────────────────────
@scan_bp.route("/dashboard")
@login_required
def dashboard():
    from collections import Counter

    cursor = db.scans.find({"user_id": ObjectId(current_user.id)}).sort("_id", -1)
    scans = [Scan(s) for s in cursor]

    # Aggregate vulnerabilities of user scans
    pipeline = [
        {"$match": {"user_id": ObjectId(current_user.id)}},
        {"$unwind": "$vulnerabilities"},
        {"$replaceRoot": {"newRoot": "$vulnerabilities"}}
    ]
    try:
        all_vulns = [Vulnerability(v) for v in db.scans.aggregate(pipeline)]
    except Exception:
        # Fallback for mongomock which might not fully support MongoDB aggregations
        all_vulns = []
        for s in scans:
            all_vulns.extend(s.vulnerabilities)

    # Stats
    total_vulns    = len(all_vulns)
    total_critical = sum(1 for v in all_vulns if v.severity == "Critical")
    total_high     = sum(1 for v in all_vulns if v.severity == "High")
    total_medium   = sum(1 for v in all_vulns if v.severity == "Medium")
    total_low      = sum(1 for v in all_vulns if v.severity == "Low")
    total_scans    = len(scans)

    # Chart data: top vuln types
    type_counter = Counter(v.vuln_type for v in all_vulns)
    top_types    = dict(type_counter.most_common(6))

    # Chart data: last 7 days scan activity
    today = datetime.utcnow().date()
    dates = [(today - timedelta(days=i)) for i in range(6, -1, -1)]
    scan_dates  = [d.strftime("%m/%d") for d in dates]
    scan_counts = []
    for d in dates:
        count = sum(
            1 for s in scans
            if s.start_time and s.start_time.date() == d
        )
        scan_counts.append(count)

    return render_template(
        "dashboard.html",
        scans=scans,
        total_scans=total_scans,
        total_vulns=total_vulns,
        total_critical=total_critical,
        total_high=total_high,
        total_medium=total_medium,
        total_low=total_low,
        vuln_type_counts=top_types,
        scan_dates=scan_dates,
        scan_counts=scan_counts,
    )


# ── AUTO ROUTE (Bookmarklet Entry Point) ─────────────────────────────────────
@scan_bp.route("/auto")
@login_required
def auto_scan_entry():
    target = request.args.get("url", "").strip()
    if not target:
        return redirect(url_for("scan.dashboard"))
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return redirect(url_for("scan.dashboard") + "?url=" + target)


@scan_bp.route("/scan/new", methods=["GET", "POST"])
@login_required
def new_scan():
    if request.method == "POST":
        target_url = request.form.get("target_url", "").strip()
        if not target_url:
            flash("Target URL is required.", "error")
            return render_template("scan/new_scan.html")

        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url

        scan_doc = {
            "user_id":        ObjectId(current_user.id),
            "target_url":     target_url,
            "scope":          request.form.get("scope", target_url),
            "status":         "pending",
            "check_xss":      "check_xss"      in request.form,
            "check_sqli":     "check_sqli"     in request.form,
            "check_csrf":     "check_csrf"     in request.form,
            "check_headers":  "check_headers"  in request.form,
            "check_redirect": "check_redirect" in request.form,
            "enable_recon":   "enable_recon"   in request.form,
            "check_advanced": "check_advanced" in request.form,
            "risk_score":     0.0,
            "risk_level":     "Unknown",
            "recon_results":  [],
            "crawled_pages":  [],
            "vulnerabilities": [],
            "notes":          [],
            "reports":        []
        }
        res = db.scans.insert_one(scan_doc)
        scan_id = str(res.inserted_id)

        # Build config
        cfg = {
            "target_url":     target_url,
            "check_xss":      scan_doc["check_xss"],
            "check_sqli":     scan_doc["check_sqli"],
            "check_csrf":     scan_doc["check_csrf"],
            "check_headers":  scan_doc["check_headers"],
            "check_redirect": scan_doc["check_redirect"],
            "enable_recon":   scan_doc["enable_recon"],
            "check_advanced": scan_doc["check_advanced"],
            "max_depth":      int(request.form.get("max_depth", 3)),
            "max_pages":      int(request.form.get("max_pages", 100)),
            "timeout":        int(request.form.get("timeout", 10)),
            "reports_dir":    current_app.config["REPORTS_DIR"],
        }

        _trigger_backend_scan(scan_id, cfg)
        flash(f"Scan #{scan_id} started against {target_url}.", "success")
        return redirect(url_for("scan.scan_detail", scan_id=scan_id))

    return render_template("scan/new_scan.html")


# ── SCAN LIST ─────────────────────────────────────────────────────────────────
@scan_bp.route("/scans")
@login_required
def scan_list():
    cursor = db.scans.find({"user_id": ObjectId(current_user.id)}).sort("_id", -1)
    scans = [Scan(s) for s in cursor]
    return render_template("scan/scan_list.html", scans=scans)


# ── SCAN DETAIL ───────────────────────────────────────────────────────────────
@scan_bp.route("/scan/<scan_id>")
@login_required
def scan_detail(scan_id):
    scan = Scan.get(scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)

    raw_recon = scan.recon_results[0] if scan.recon_results else {}
    recon = ReconResultWrapper(raw_recon) if raw_recon else None
    
    open_ports   = json.loads(recon.open_ports)   if recon and recon.open_ports   else []
    detected_tech = json.loads(recon.detected_tech) if recon and recon.detected_tech else []

    pages = [CrawledPageWrapper(p) for p in scan.crawled_pages]

    # Sort vulns: Critical → High → Medium → Low → Info, then by CVSS desc
    SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    vulns = sorted(
        scan.vulnerabilities,
        key=lambda v: (SEV_ORDER.get(v.severity, 9), -(v.cvss_score or 0))
    )

    # Inject remediation data
    from scanner.remediation_db import get_remediation
    for v in vulns:
        v.remediation_data = get_remediation(v.vuln_type or "")

    # Severity buckets
    critical_vulns = [v for v in vulns if v.severity == "Critical"]
    high_vulns     = [v for v in vulns if v.severity == "High"]
    medium_vulns   = [v for v in vulns if v.severity == "Medium"]
    low_vulns      = [v for v in vulns if v.severity == "Low"]
    info_vulns     = [v for v in vulns if v.severity == "Info"]

    ssl_info = {}
    if recon and recon.ssl_info:
        try:
            ssl_info = json.loads(recon.ssl_info)
        except Exception:
            ssl_info = {}

    # Map notes
    notes = [NoteWrapper(n) for n in scan.notes]

    return render_template(
        "scan/scan_detail.html",
        scan          = scan,
        recon         = recon,
        open_ports    = open_ports,
        detected_tech = detected_tech,
        ssl_info      = ssl_info,
        pages         = pages,
        vulns         = vulns,
        critical_vulns= critical_vulns,
        high_vulns    = high_vulns,
        medium_vulns  = medium_vulns,
        low_vulns     = low_vulns,
        info_vulns    = info_vulns,
        notes         = notes,
    )


# ── SCAN DELETE ───────────────────────────────────────────────────────────────
@scan_bp.route("/scan/<scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    scan = Scan.get(scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)
    db.scans.delete_one({"_id": ObjectId(scan_id)})
    flash(f"Scan #{scan_id} deleted.", "info")
    return redirect(url_for("scan.scan_list"))


# ── API: REAL-TIME STATUS ─────────────────────────────────────────────────────
@scan_bp.route("/api/scan/<scan_id>/status")
@login_required
def api_scan_status(scan_id):
    scan = Scan.get(scan_id)
    if not scan or scan.user_id != current_user.id:
        return jsonify({"error": "Not found"}), 404

    state = get_scan_state(scan_id)
    vulns = scan.vulnerabilities

    return jsonify({
        "status":      scan.status,
        "log":         state.get("log", []),
        "vuln_count":  len(vulns),
        "high":        sum(1 for v in vulns if v.severity == "High"),
        "medium":      sum(1 for v in vulns if v.severity == "Medium"),
        "low":         sum(1 for v in vulns if v.severity == "Low"),
        "info":        sum(1 for v in vulns if v.severity == "Info"),
        "pages":       len(scan.crawled_pages),
    })


# ── API: VULNERABILITIES JSON ─────────────────────────────────────────────────
@scan_bp.route("/api/scan/<scan_id>/vulns")
@login_required
def api_scan_vulns(scan_id):
    scan = Scan.get(scan_id)
    if not scan or scan.user_id != current_user.id:
        return jsonify({"error": "Not found"}), 404
    return jsonify([v.to_dict() for v in scan.vulnerabilities])


# ── SSE: LIVE LOG STREAM ──────────────────────────────────────────────────────
@scan_bp.route("/api/scan/<scan_id>/stream")
@login_required
def api_scan_stream(scan_id):
    scan = Scan.get(scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)

    def event_stream():
        sent_lines = 0
        while True:
            # Query status from database dynamically to allow exiting early if completed/failed
            db_scan = Scan.get(scan_id)
            if not db_scan:
                break
            
            state = get_scan_state(scan_id)
            log   = state.get("log", [])
            new_lines = log[sent_lines:]
            for line in new_lines:
                yield f"data: {json.dumps({'log': line})}\n\n"
            sent_lines += len(new_lines)

            # Exit if state or database record is completed/failed
            status = state.get("status") or db_scan.status
            if status in ("completed", "failed"):
                yield f"data: {json.dumps({'done': True, 'status': status})}\n\n"
                break
            time.sleep(1.5)

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── API: ADD ANALYST NOTE ─────────────────────────────────────────────────────
@scan_bp.route("/api/scan/<scan_id>/note", methods=["POST"])
@login_required
def add_note(scan_id):
    scan = Scan.get(scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)
    content = request.json.get("content", "").strip()
    if not content:
        return jsonify({"error": "Empty note"}), 400
    
    note_id = str(ObjectId())
    note_doc = {
        "note_id": note_id,
        "author_name": current_user.username,
        "content": content,
        "created_at": datetime.utcnow()
    }
    db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$push": {"notes": note_doc}}
    )
    return jsonify({"ok": True, "note_id": note_id})


# ── API: TOGGLE FALSE POSITIVE ────────────────────────────────────────────────
@scan_bp.route("/api/vuln/<vuln_id>/fp", methods=["POST"])
@login_required
def toggle_false_positive(vuln_id):
    # Find scan that contains this vulnerability
    scan_data = db.scans.find_one({"vulnerabilities.vuln_id": vuln_id})
    if not scan_data:
        abort(404)
    
    scan = Scan(scan_data)
    if scan.user_id != current_user.id:
        abort(403)
        
    current_fp = next(v.false_positive for v in scan.vulnerabilities if v.vuln_id == vuln_id)
    db.scans.update_one(
        {"_id": ObjectId(scan.scan_id), "vulnerabilities.vuln_id": vuln_id},
        {"$set": {"vulnerabilities.$.false_positive": not current_fp}}
    )
    return jsonify({"ok": True, "false_positive": not current_fp})


# ── API: IP INTELLIGENCE PREVIEW ─────────────────────────────────────────────
@scan_bp.route("/api/ip-intel")
@login_required
def api_ip_intel():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        from scanner.ip_intel import run_ip_intel
        data = run_ip_intel(url)
        return jsonify({
            "hostname":          data.get("hostname"),
            "primary_ip":        data.get("primary_ip"),
            "ipv4":              data.get("ipv4"),
            "ipv6":              data.get("ipv6"),
            "ip_version":        data.get("ip_version"),
            "ptr_record":        data.get("ptr_record"),
            "country":           data.get("country"),
            "country_code":      data.get("country_code"),
            "country_flag":      data.get("country_flag"),
            "region":            data.get("region"),
            "city":              data.get("city"),
            "timezone":          data.get("timezone"),
            "isp":               data.get("isp"),
            "org":               data.get("org"),
            "asn":               data.get("asn"),
            "hosting_provider":  data.get("hosting_provider"),
            "hosting_icon":      data.get("hosting_icon"),
            "is_hosting":        data.get("is_hosting"),
            "is_proxy":          data.get("is_proxy"),
            "ssl_days_left":     data.get("ssl", {}).get("ssl_days_left"),
            "ssl_expired":       data.get("ssl", {}).get("ssl_expired"),
            "ssl_version":       data.get("ssl", {}).get("ssl_version"),
            "dns_a":             data.get("dns", {}).get("a", []),
            "dns_aaaa":          data.get("dns", {}).get("aaaa", []),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── API: AUTO QUICK SCAN ──────────────────────────────────────────────────────
@scan_bp.route("/api/auto-scan", methods=["POST"])
@login_required
def api_auto_scan():
    data       = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "").strip()

    if not target_url:
        return jsonify({"error": "No target URL"}), 400
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    scan_doc = {
        "user_id":        ObjectId(current_user.id),
        "target_url":     target_url,
        "scope":          target_url,
        "status":         "pending",
        "check_xss":      True,
        "check_sqli":     True,
        "check_csrf":     True,
        "check_headers":  True,
        "check_redirect": True,
        "enable_recon":   True,
        "check_advanced": data.get("full", False),
        "risk_score":     0.0,
        "risk_level":     "Unknown",
        "recon_results":  [],
        "crawled_pages":  [],
        "vulnerabilities": [],
        "notes":          [],
        "reports":        []
    }
    res = db.scans.insert_one(scan_doc)
    scan_id = str(res.inserted_id)

    cfg = {
        "target_url":     target_url,
        "check_xss":      True,
        "check_sqli":     True,
        "check_csrf":     True,
        "check_headers":  True,
        "check_redirect": True,
        "enable_recon":   True,
        "check_advanced": data.get("full", False),
        "max_depth":      5 if data.get("full") else 2,
        "max_pages":      200 if data.get("full") else 50,
        "timeout":        15 if data.get("full") else 10,
        "reports_dir":    current_app.config["REPORTS_DIR"],
    }
    _trigger_backend_scan(scan_id, cfg)

    return jsonify({
        "ok":           True,
        "scan_id":      scan_id,
        "redirect_url": url_for("scan.scan_detail", scan_id=scan_id),
    })


# ── API: TOKEN-AUTHENTICATED AUTOMATIC SCAN (CI/CD PIPELINES) ────────────────
@scan_bp.route("/api/v1/auto-scan", methods=["POST"])
def api_v1_auto_scan():
    # 1. Verify API Key
    auth_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    expected_key = current_app.config.get("API_KEY")
    
    if not auth_key or auth_key != expected_key:
        return jsonify({"error": "Unauthorized: Invalid or missing API Key"}), 401

    # 2. Parse input data
    data       = request.get_json(silent=True) or {}
    target_url = data.get("target_url", "").strip()

    if not target_url:
        return jsonify({"error": "Missing required field: target_url"}), 400
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    # Find default administrator or system user to assign the scan ownership
    user = db.users.find_one({"role": "admin"})
    user_id = user["_id"] if user else ObjectId()

    # Parse configurations & presets
    profile = data.get("profile", "custom")
    if profile == "quick":
        check_xss      = False
        check_sqli     = False
        check_csrf     = False
        check_headers  = True
        check_redirect = False
        enable_recon   = True
        check_advanced = False
        max_depth      = 1
        max_pages      = 25
        timeout        = 5
    elif profile == "standard":
        check_xss      = True
        check_sqli     = True
        check_csrf     = True
        check_headers  = True
        check_redirect = True
        enable_recon   = True
        check_advanced = False
        max_depth      = 3
        max_pages      = 100
        timeout        = 10
    elif profile == "full":
        check_xss      = True
        check_sqli     = True
        check_csrf     = True
        check_headers  = True
        check_redirect = True
        enable_recon   = True
        check_advanced = True
        max_depth      = 5
        max_pages      = 200
        timeout        = 20
    else:
        # Custom profiles
        check_xss      = data.get("check_xss", True)
        check_sqli     = data.get("check_sqli", True)
        check_csrf     = data.get("check_csrf", True)
        check_headers  = data.get("check_headers", True)
        check_redirect = data.get("check_redirect", True)
        enable_recon   = data.get("enable_recon", True)
        check_advanced = data.get("check_advanced", False)
        max_depth      = int(data.get("max_depth", 3))
        max_pages      = int(data.get("max_pages", 100))
        timeout        = int(data.get("timeout", 10))

    scan_doc = {
        "user_id":        user_id,
        "target_url":     target_url,
        "scope":          target_url,
        "status":         "pending",
        "check_xss":      check_xss,
        "check_sqli":     check_sqli,
        "check_csrf":     check_csrf,
        "check_headers":  check_headers,
        "check_redirect": check_redirect,
        "enable_recon":   enable_recon,
        "check_advanced": check_advanced,
        "risk_score":     0.0,
        "risk_level":     "Unknown",
        "recon_results":  [],
        "crawled_pages":  [],
        "vulnerabilities": [],
        "notes":          [],
        "reports":        []
    }
    res = db.scans.insert_one(scan_doc)
    scan_id = str(res.inserted_id)

    cfg = {
        "target_url":     target_url,
        "check_xss":      check_xss,
        "check_sqli":     check_sqli,
        "check_csrf":     check_csrf,
        "check_headers":  check_headers,
        "check_redirect": check_redirect,
        "enable_recon":   enable_recon,
        "check_advanced": check_advanced,
        "max_depth":      max_depth,
        "max_pages":      max_pages,
        "timeout":        timeout,
        "reports_dir":    current_app.config["REPORTS_DIR"],
    }
    
    # Launch scan thread asynchronously
    _trigger_backend_scan(scan_id, cfg)

    return jsonify({
        "ok":           True,
        "scan_id":      scan_id,
        "status":       "pending",
        "redirect_url": url_for("scan.scan_detail", scan_id=scan_id, _external=True),
        "api_status_url": url_for("scan.api_v1_scan_status", scan_id=scan_id, _external=True)
    })


# ── API: TOKEN-AUTHENTICATED SCAN STATUS ──────────────────────────────────────
@scan_bp.route("/api/v1/scan/<scan_id>/status", methods=["GET"])
def api_v1_scan_status(scan_id):
    # 1. Verify API Key
    auth_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    expected_key = current_app.config.get("API_KEY")
    
    if not auth_key or auth_key != expected_key:
        return jsonify({"error": "Unauthorized: Invalid or missing API Key"}), 401

    # 2. Get Scan Details
    scan = Scan.get(scan_id)
    if not scan:
        return jsonify({"error": f"Scan #{scan_id} not found"}), 404

    state = get_scan_state(scan_id)
    vulns = scan.vulnerabilities

    return jsonify({
        "scan_id":     scan_id,
        "target_url":  scan.target_url,
        "status":      scan.status,
        "risk_score":  scan.risk_score,
        "risk_level":  scan.risk_level,
        "log":         state.get("log", []),
        "vuln_count":  len(vulns),
        "vulnerabilities": [v.to_dict() for v in vulns],
        "pages_crawled": len(scan.crawled_pages)
    })


