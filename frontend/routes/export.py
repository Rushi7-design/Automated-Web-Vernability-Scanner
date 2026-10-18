"""routes/export.py — Export scan findings as JSON, CSV, or XML."""

import csv
import io
import json
import xml.etree.ElementTree as ET

from flask import Blueprint, jsonify, make_response, abort
from flask_login import login_required, current_user
from database import db, Scan, Vulnerability

export_bp = Blueprint("export", __name__)


def _get_scan_or_404(scan_id):
    scan = Scan.get(scan_id)
    if not scan or scan.user_id != current_user.id:
        abort(404)
    return scan


@export_bp.route("/scan/<scan_id>/export/json")
@login_required
def export_json(scan_id):
    scan  = _get_scan_or_404(scan_id)
    vulns = scan.vulnerabilities
    data  = {
        "scan_id":     scan_id,
        "target_url":  scan.target_url,
        "status":      scan.status,
        "risk_score":  scan.risk_score,
        "risk_level":  scan.risk_level,
        "start_time":  scan.start_time.isoformat() if scan.start_time else None,
        "end_time":    scan.end_time.isoformat()   if scan.end_time   else None,
        "findings":    [v.to_dict() for v in vulns],
    }
    resp = make_response(json.dumps(data, indent=2))
    resp.headers["Content-Type"]        = "application/json"
    resp.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.json"'
    return resp


@export_bp.route("/scan/<scan_id>/export/csv")
@login_required
def export_csv(scan_id):
    scan  = _get_scan_or_404(scan_id)
    vulns = scan.vulnerabilities

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Type", "Severity", "CVSS", "CWE", "OWASP",
        "URL", "Parameter", "Payload", "Description", "Evidence", "Remediation"
    ])
    for v in vulns:
        writer.writerow([
            v.vuln_id, v.vuln_type, v.severity, v.cvss_score,
            v.cwe_id, v.owasp_category, v.url, v.parameter,
            v.payload, v.description, v.evidence, v.remediation,
        ])

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"]        = "text/csv"
    resp.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.csv"'
    return resp


@export_bp.route("/scan/<scan_id>/export/xml")
@login_required
def export_xml(scan_id):
    scan  = _get_scan_or_404(scan_id)
    vulns = scan.vulnerabilities

    root  = ET.Element("ScanReport")
    meta  = ET.SubElement(root, "Metadata")
    ET.SubElement(meta, "ScanId").text      = str(scan_id)
    ET.SubElement(meta, "Target").text      = scan.target_url
    ET.SubElement(meta, "Status").text      = scan.status
    ET.SubElement(meta, "RiskScore").text   = str(scan.risk_score)
    ET.SubElement(meta, "RiskLevel").text   = scan.risk_level or ""
    ET.SubElement(meta, "StartTime").text   = str(scan.start_time)
    ET.SubElement(meta, "EndTime").text     = str(scan.end_time)

    findings_el = ET.SubElement(root, "Findings")
    for v in vulns:
        f_el = ET.SubElement(findings_el, "Finding", id=str(v.vuln_id))
        ET.SubElement(f_el, "Type").text        = v.vuln_type
        ET.SubElement(f_el, "Severity").text    = v.severity
        ET.SubElement(f_el, "CVSS").text        = str(v.cvss_score)
        ET.SubElement(f_el, "CWE").text         = v.cwe_id or ""
        ET.SubElement(f_el, "OWASP").text       = v.owasp_category or ""
        ET.SubElement(f_el, "URL").text         = v.url or ""
        ET.SubElement(f_el, "Parameter").text   = v.parameter or ""
        ET.SubElement(f_el, "Description").text = v.description or ""
        ET.SubElement(f_el, "Evidence").text    = v.evidence or ""
        ET.SubElement(f_el, "Remediation").text = v.remediation or ""

    xml_str = ET.tostring(root, encoding="unicode", xml_declaration=False)
    xml_out = f'<?xml version="1.0" encoding="UTF-8"?>\n{xml_str}'

    resp = make_response(xml_out)
    resp.headers["Content-Type"]        = "application/xml"
    resp.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.xml"'
    return resp
