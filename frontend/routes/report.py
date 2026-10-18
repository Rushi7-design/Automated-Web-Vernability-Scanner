"""routes/report.py — Report generation and download routes."""

import os
from datetime import datetime
from flask import Blueprint, send_file, abort, flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from bson.objectid import ObjectId
from database import db, Scan, Vulnerability, Report

report_bp = Blueprint("report", __name__)


@report_bp.route("/scan/<scan_id>/report/<string:fmt>")
@login_required
def download_report(scan_id, fmt):
    """Generate (if needed) and download a PDF or HTML report for a completed scan."""
    scan = Scan.get(scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)

    if scan.status != "completed":
        flash("Report is only available for completed scans.", "warning")
        return redirect(url_for("scan.scan_detail", scan_id=scan_id))

    fmt = fmt.lower()
    if fmt not in ("pdf", "html"):
        abort(400)

    # Check if report already exists in embedded subdocuments
    report = next((r for r in scan.reports if r.format == fmt), None)

    # Regenerate if missing or file deleted
    if not report or not os.path.exists(report.file_path or ""):
        report = _generate_report(scan, fmt)
        if not report:
            flash("Report generation failed. Check server logs.", "error")
            return redirect(url_for("scan.scan_detail", scan_id=scan_id))

    # HTML opens inline in browser; PDF forces a download
    if fmt == "html":
        return send_file(
            report.file_path,
            mimetype="text/html",
            as_attachment=False,
        )
    else:
        return send_file(
            report.file_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"AWVS_Report_Scan{scan_id}.pdf",
        )


def _generate_report(scan: Scan, fmt: str) -> "Report | None":
    """Build scan_data dict, call generator, save Report record."""
    try:
        from scanner.report_gen import generate_pdf_report, generate_html_report

        vulns = scan.vulnerabilities

        # Build duration string
        duration = ""
        if scan.start_time and scan.end_time:
            secs = int((scan.end_time - scan.start_time).total_seconds())
            duration = f"{secs // 60}m {secs % 60}s"

        scan_data = {
            "scan_id":       scan.scan_id,
            "target_url":    scan.target_url,
            "analyst":       scan.owner.username if scan.owner else "Unknown",
            "risk_score":    scan.risk_score or 0,
            "risk_level":    scan.risk_level or "Unknown",
            "started":       scan.start_time.strftime("%Y-%m-%d %H:%M UTC") if scan.start_time else "",
            "duration":      duration,
            "pages_crawled": len(scan.crawled_pages),
            # IP Intelligence fields
            "ip_address":    scan.ip_address or "",
            "ip_version":    scan.ip_version or "",
            "hosting_country": scan.hosting_country or "",
            "hosting_isp":   scan.hosting_isp or "",
            "hosting_org":   scan.hosting_org or "",
            "asn":           scan.asn or "",
        }

        findings = []
        for v in vulns:
            findings.append({
                "vuln_type":  v.vuln_type,
                "severity":   v.severity,
                "cvss_score": v.cvss_score or 0,
                "cwe_id":     v.cwe_id or "",
                "url":        v.url or "",
                "parameter":  v.parameter or "",
                "payload":    v.payload or "",
                "evidence":   v.evidence or "",
            })

        # Output path
        reports_dir = current_app.config.get("REPORTS_DIR", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        out_path = os.path.join(reports_dir, f"scan_{scan.scan_id}_report.{fmt}")

        if fmt == "pdf":
            path = generate_pdf_report(scan_data, findings, out_path)
        else:
            path = generate_html_report(scan_data, findings, out_path)

        # If PDF fallback returned HTML, adjust fmt
        actual_fmt = "html" if path.endswith(".html") else fmt

        report_doc = {
            "report_id": str(ObjectId()),
            "format": actual_fmt,
            "file_path": path,
            "generated_at": datetime.utcnow()
        }

        # Remove old format report if exists
        db.scans.update_one(
            {"_id": ObjectId(scan.scan_id)},
            {"$pull": {"reports": {"format": actual_fmt}}}
        )
        
        # Push new report
        db.scans.update_one(
            {"_id": ObjectId(scan.scan_id)},
            {"$push": {"reports": report_doc}}
        )

        return Report(report_doc, scan)

    except Exception as e:
        import logging
        logging.getLogger(__name__).exception(f"Report generation error: {e}")
        return None
