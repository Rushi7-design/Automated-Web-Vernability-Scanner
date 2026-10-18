"""
scanner/report_gen.py  --  AWVS v4.0 Professional Report Generator
Generates:
  • HTML  -- full-page, print-ready, colour-coded
  • PDF   -- via ReportLab with proper XML escaping
"""

import html as _html_mod
import logging
import os
import re
from datetime import datetime

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_HEX = {
    "Critical": "#dc2626",
    "High":     "#ea580c",
    "Medium":   "#d97706",
    "Low":      "#2563eb",
    "Info":     "#0891b2",
}
SEV_BG = {
    "Critical": "#fef2f2",
    "High":     "#fff7ed",
    "Medium":   "#fffbeb",
    "Low":      "#eff6ff",
    "Info":     "#ecfeff",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _esc(v) -> str:
    """HTML-escape for safe embedding in HTML."""
    return _html_mod.escape(str(v) if v is not None else "", quote=True)


def _pdf(v) -> str:
    """Strip HTML tags + escape XML entities for ReportLab Paragraph text."""
    if v is None:
        return ""
    s = str(v)
    s = re.sub(r"<[^>]+>", "", s)              # strip tags
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace('"', "&quot;")
    s = s.replace("'", "&#39;")
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)  # control chars
    if len(s) > 600:
        s = s[:597] + "..."
    return s


def _sort(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 4))


def _counts(findings):
    c = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        s = f.get("severity", "Info")
        c[s] = c.get(s, 0) + 1
    return c


def _risk_color(score):
    if score >= 75:
        return "#dc2626"
    if score >= 50:
        return "#d97706"
    if score >= 25:
        return "#2563eb"
    return "#059669"


def _badge_html(sev):
    c = SEV_HEX.get(sev, "#666")
    return (
        '<span style="background:' + c + '22;color:' + c
        + ';border:1px solid ' + c + '55;padding:2px 10px;border-radius:20px;'
        'font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;">'
        + _esc(sev) + '</span>'
    )


# ---------------------------------------------------------------------------
# HTML REPORT
# ---------------------------------------------------------------------------
def generate_html_report(scan_data: dict, findings: list, output_path: str) -> str:
    findings  = _sort(findings)
    counts    = _counts(findings)
    now       = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    risk      = float(scan_data.get("risk_score") or 0)
    risk_lv   = scan_data.get("risk_level", "Unknown")
    rc        = _risk_color(risk)

    # severity summary cards
    sev_cards = ""
    for s in ["Critical", "High", "Medium", "Low", "Info"]:
        c = SEV_HEX[s]
        sev_cards += (
            '<div style="text-align:center;background:' + c + '11;border:1px solid ' + c
            + '44;border-radius:8px;padding:14px 8px;">'
            '<div style="font-size:28px;font-weight:900;color:' + c + ';">' + str(counts[s]) + '</div>'
            '<div style="font-size:10px;font-weight:700;color:' + c
            + ';text-transform:uppercase;letter-spacing:.08em;margin-top:2px;">' + s + '</div>'
            '</div>'
        )

    # meta cards
    meta_items = [
        ("Target",    scan_data.get("target_url", "")),
        ("Scan ID",   "#" + str(scan_data.get("scan_id", ""))),
        ("Analyst",   scan_data.get("analyst", "Unknown")),
        ("Date",      now),
        ("Duration",  scan_data.get("duration", "—")),
        ("Pages",     str(scan_data.get("pages_crawled", 0))),
    ]
    meta_cards = ""
    for label, val in meta_items:
        meta_cards += (
            '<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;'
            'padding:10px 14px;min-width:140px;">'
            '<div style="font-size:10px;color:#94a3b8;margin-bottom:2px;">' + _esc(label) + '</div>'
            '<div style="font-size:12px;color:#1e293b;font-weight:600;word-break:break-all;">'
            + _esc(val) + '</div></div>'
        )

    # IP intelligence
    ip_html = ""
    if scan_data.get("ip_address"):
        ip_rows = ""
        for k, v in [
            ("IP Address",       scan_data.get("ip_address", "")),
            ("IP Version",       scan_data.get("ip_version", "")),
            ("Country / City",   scan_data.get("hosting_country", "")),
            ("ISP",              scan_data.get("hosting_isp", "")),
            ("Hosting Provider", scan_data.get("hosting_org", "")),
            ("ASN",              scan_data.get("asn", "")),
        ]:
            if v:
                ip_rows += (
                    '<tr><td style="padding:7px 12px;color:#94a3b8;font-size:11px;'
                    'font-weight:600;white-space:nowrap;width:140px;">' + _esc(k) + '</td>'
                    '<td style="padding:7px 12px;color:#1e293b;font-size:12px;">' + _esc(v) + '</td></tr>'
                )
        ip_html = (
            '<div style="background:white;border:1px solid #e2e8f0;border-radius:10px;'
            'padding:22px 24px;margin-bottom:20px;box-shadow:0 1px 4px rgba(0,0,0,.06);">'
            '<h2 style="font-size:14px;font-weight:700;color:#1e293b;margin-bottom:14px;'
            'padding-bottom:8px;border-bottom:1px solid #e2e8f0;">IP Intelligence</h2>'
            '<table style="width:100%;border-collapse:collapse;">' + ip_rows + '</table>'
            '</div>'
        )

    # individual finding cards
    findings_html = ""
    for idx, f in enumerate(findings, 1):
        try:
            from scanner.remediation_db import get_remediation
            r = get_remediation(f.get("vuln_type", ""))
        except Exception:
            r = {}

        sev   = f.get("severity", "Info")
        color = SEV_HEX.get(sev, "#666")
        bg    = SEV_BG.get(sev, "#fff")
        cvss  = f.get("cvss_score") or 0
        desc  = r.get("description") or f.get("description", "")
        impact = r.get("impact", "")

        # header row
        cvss_badge = ""
        if cvss:
            cvss_badge = (
                '<span style="background:#1f2937;color:#e5e7eb;padding:3px 10px;'
                'border-radius:4px;font-size:11px;font-weight:700;font-family:monospace;">'
                'CVSS ' + str(round(cvss, 1)) + '</span>'
            )
        cwe_badge = ""
        if f.get("cwe_id"):
            cwe_badge = (
                '<span style="font-size:11px;color:#6b7280;font-family:monospace;">'
                + _esc(f.get("cwe_id", "")) + '</span>'
            )

        header = (
            '<div style="background:' + bg + ';padding:12px 16px;display:flex;'
            'align-items:center;gap:10px;flex-wrap:wrap;">'
            + _badge_html(sev)
            + '<span style="font-weight:700;font-size:14px;color:#111827;flex:1;">'
            + str(idx) + '. ' + _esc(f.get("vuln_type", "Unknown")) + '</span>'
            + cvss_badge + cwe_badge
            + '</div>'
        )

        # detail table
        detail_rows = ""
        for label, val in [
            ("URL",       f.get("url")),
            ("Parameter", f.get("parameter")),
            ("Payload",   f.get("payload")),
            ("Evidence",  f.get("evidence")),
            ("OWASP",     f.get("owasp_category") or r.get("owasp", "")),
        ]:
            if val:
                detail_rows += (
                    '<tr><td style="padding:5px 10px;color:#94a3b8;font-size:11px;'
                    'font-weight:600;white-space:nowrap;width:80px;vertical-align:top;">'
                    + _esc(label) + '</td>'
                    '<td style="padding:5px 10px;color:#374151;font-size:11px;'
                    'font-family:monospace;word-break:break-all;">'
                    + _esc(str(val)) + '</td></tr>'
                )
        detail_section = ""
        if detail_rows:
            detail_section = (
                '<div style="background:#f8fafc;border:1px solid #e5e7eb;border-radius:6px;'
                'margin-bottom:12px;overflow:hidden;">'
                '<table style="width:100%;border-collapse:collapse;">'
                + detail_rows + '</table></div>'
            )

        # description
        desc_section = ""
        if desc:
            desc_section = (
                '<div style="margin-bottom:10px;">'
                '<div style="font-size:11px;font-weight:700;color:#374151;'
                'text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;">'
                'Description</div>'
                '<p style="font-size:12px;color:#4b5563;margin:0;line-height:1.6;">'
                + _esc(desc) + '</p></div>'
            )

        # impact
        impact_section = ""
        if impact:
            impact_section = (
                '<div style="background:#fefce8;border:1px solid #fde68a;border-radius:6px;'
                'padding:10px 14px;margin-bottom:10px;">'
                '<div style="font-size:11px;font-weight:700;color:#92400e;margin-bottom:4px;">'
                'Business Impact</div>'
                '<p style="font-size:12px;color:#78350f;margin:0;line-height:1.6;">'
                + _esc(impact) + '</p></div>'
            )

        # fix steps
        fix_items = ""
        for step in r.get("fix_steps", []):
            step = step.lstrip("0123456789. ")
            fix_items += '<li style="padding:4px 0;color:#065f46;font-size:12px;">' + _esc(step) + '</li>'
        fix_section = ""
        if fix_items:
            fix_section = (
                '<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;'
                'padding:10px 14px;margin-bottom:10px;">'
                '<div style="font-size:11px;font-weight:700;color:#065f46;margin-bottom:6px;">'
                'How to Fix</div>'
                '<ul style="margin:0;padding-left:18px;">' + fix_items + '</ul></div>'
            )

        # code examples
        code_section = ""
        vuln_code = r.get("code_vulnerable", "")
        fix_code  = r.get("code_fixed", "")
        if vuln_code or fix_code:
            left = right = ""
            if vuln_code:
                left = (
                    '<div><div style="font-size:10px;font-weight:700;color:#dc2626;margin-bottom:4px;">'
                    'VULNERABLE CODE</div>'
                    '<pre style="background:#0f0f0f;color:#fca5a5;padding:12px;border-radius:6px;'
                    'font-size:11px;overflow-x:auto;white-space:pre-wrap;margin:0;'
                    'border-left:3px solid #dc2626;">' + _esc(vuln_code) + '</pre></div>'
                )
            if fix_code:
                right = (
                    '<div><div style="font-size:10px;font-weight:700;color:#059669;margin-bottom:4px;">'
                    'FIXED CODE</div>'
                    '<pre style="background:#022c22;color:#6ee7b7;padding:12px;border-radius:6px;'
                    'font-size:11px;overflow-x:auto;white-space:pre-wrap;margin:0;'
                    'border-left:3px solid #059669;">' + _esc(fix_code) + '</pre></div>'
                )
            code_section = (
                '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px;">'
                + left + right + '</div>'
            )

        # references
        refs_section = ""
        refs = r.get("references", [])
        if refs:
            links = " &nbsp;|&nbsp; ".join(
                '<a href="' + _esc(url) + '" style="color:#2563eb;">' + _esc(label) + '</a>'
                for label, url in refs
            )
            refs_section = (
                '<div style="margin-top:10px;font-size:11px;color:#6b7280;">'
                'References: ' + links + '</div>'
            )

        finding_card = (
            '<div style="border:1px solid ' + color + '44;border-left:4px solid ' + color
            + ';border-radius:8px;margin-bottom:18px;overflow:hidden;background:white;">'
            + header
            + '<div style="padding:14px 16px;">'
            + detail_section + desc_section + impact_section + fix_section + code_section + refs_section
            + '</div></div>'
        )
        findings_html += finding_card

    # full HTML page – built with list.append to avoid implicit-concat pitfalls
    parts = []
    parts.append('<!DOCTYPE html><html lang="en"><head>')
    parts.append('<meta charset="UTF-8">')
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1.0">')
    parts.append('<title>AWVS Report &mdash; ' + _esc(scan_data.get("target_url", "")) + '</title>')
    parts.append('<style>')
    parts.append('@import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&display=swap");')
    parts.append('*{box-sizing:border-box;margin:0;padding:0;}')
    parts.append('body{font-family:"Inter",sans-serif;background:#f1f5f9;color:#1e293b;}')
    parts.append('@media print{body{background:white;}}')
    parts.append('</style></head><body>')
    parts.append('<div style="max-width:1000px;margin:0 auto;padding:24px 16px;">')

    # header
    parts.append('<div style="background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 60%,#1d4ed8 100%);color:white;padding:32px 36px;border-radius:12px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,0,0,.25);">')
    parts.append('<div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:20px;">')
    parts.append('<div>')
    parts.append('<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.15em;color:#93c5fd;margin-bottom:10px;">AWVS v4.0 &mdash; Security Assessment Report</div>')
    parts.append('<h1 style="font-size:22px;font-weight:900;margin-bottom:6px;word-break:break-all;">' + _esc(scan_data.get("target_url", "")) + '</h1>')
    parts.append('<div style="font-size:12px;color:#93c5fd;">')
    parts.append('Scan #' + _esc(str(scan_data.get("scan_id", ""))))
    parts.append(' &nbsp;|&nbsp; ' + _esc(now))
    parts.append(' &nbsp;|&nbsp; Analyst: ' + _esc(scan_data.get("analyst", "Unknown")))
    parts.append('</div></div>')
    parts.append('<div style="text-align:center;background:rgba(255,255,255,.1);padding:16px 24px;border-radius:10px;border:1px solid rgba(255,255,255,.15);min-width:110px;">')
    parts.append('<div style="font-size:44px;font-weight:900;color:' + rc + ';line-height:1;">' + str(int(risk)) + '</div>')
    parts.append('<div style="font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#cbd5e1;margin-top:4px;">Risk Score</div>')
    parts.append('<div style="font-size:13px;color:#e2e8f0;margin-top:3px;font-weight:700;">' + _esc(risk_lv) + '</div>')
    parts.append('</div></div></div>')

    # executive summary
    parts.append('<div style="background:white;border:1px solid #e2e8f0;border-radius:10px;padding:22px 24px;margin-bottom:20px;box-shadow:0 1px 4px rgba(0,0,0,.06);">')
    parts.append('<h2 style="font-size:14px;font-weight:700;color:#1e293b;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid #e2e8f0;">Executive Summary</h2>')
    parts.append('<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:18px;">' + sev_cards + '</div>')
    parts.append('<div style="display:flex;flex-wrap:wrap;gap:10px;">' + meta_cards + '</div>')
    parts.append('</div>')

    parts.append(ip_html)

    # findings
    parts.append('<div style="background:white;border:1px solid #e2e8f0;border-radius:10px;padding:22px 24px;box-shadow:0 1px 4px rgba(0,0,0,.06);">')
    parts.append('<h2 style="font-size:14px;font-weight:700;color:#1e293b;margin-bottom:18px;padding-bottom:10px;border-bottom:1px solid #e2e8f0;">Detailed Findings (' + str(len(findings)) + ')</h2>')
    if findings:
        parts.append(findings_html)
    else:
        parts.append('<p style="color:#059669;font-size:13px;">No vulnerabilities detected.</p>')
    parts.append('</div>')

    # footer
    parts.append('<div style="text-align:center;margin-top:20px;font-size:11px;color:#94a3b8;padding:12px;">')
    parts.append('Generated by AWVS v4.0 &mdash; Automated Web Vulnerability Scanner &nbsp;|&nbsp; ' + _esc(now))
    parts.append('<br><span style="color:#dc2626;">For authorized security testing only</span>')
    parts.append('</div>')
    parts.append('</div></body></html>')

    page = "".join(parts)

    parent = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(parent, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    logger.info("HTML report: %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# PDF REPORT
# ---------------------------------------------------------------------------
def generate_pdf_report(scan_data: dict, findings: list, output_path: str) -> str:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether,
        )
        from reportlab.lib.enums import TA_LEFT

        findings  = _sort(findings)
        counts    = _counts(findings)
        now       = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        risk      = float(scan_data.get("risk_score") or 0)
        risk_lv   = scan_data.get("risk_level", "Unknown")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            rightMargin=1.8*cm, leftMargin=1.8*cm,
            topMargin=1.8*cm, bottomMargin=1.8*cm,
            title="AWVS Security Report",
            author="AWVS v4.0",
        )

        base = getSampleStyleSheet()
        W = A4[0] - 3.6*cm

        def PS(name, **kw):
            return ParagraphStyle(name, parent=base["Normal"], **kw)

        ST = {
            "h2":   PS("H2", fontSize=12, fontName="Helvetica-Bold",
                        textColor=colors.HexColor("#0f172a"),
                        spaceBefore=12, spaceAfter=5),
            "h3":   PS("H3", fontSize=10, fontName="Helvetica-Bold",
                        textColor=colors.HexColor("#1e3a5f"),
                        spaceBefore=6, spaceAfter=3),
            "body": PS("BD", fontSize=9,  textColor=colors.HexColor("#374151"), leading=13),
            "mono": PS("MN", fontSize=8,  fontName="Courier",
                        textColor=colors.HexColor("#1f2937"), leading=11),
            "fix":  PS("FX", fontSize=9,  textColor=colors.HexColor("#065f46"), leading=13),
            "muted":PS("MT", fontSize=8,  textColor=colors.HexColor("#6b7280")),
        }

        RL_SEV = {
            "Critical": colors.HexColor("#dc2626"),
            "High":     colors.HexColor("#ea580c"),
            "Medium":   colors.HexColor("#d97706"),
            "Low":      colors.HexColor("#2563eb"),
            "Info":     colors.HexColor("#0891b2"),
        }

        def rc_rl(score):
            if score >= 75: return colors.HexColor("#dc2626")
            if score >= 50: return colors.HexColor("#d97706")
            if score >= 25: return colors.HexColor("#2563eb")
            return colors.HexColor("#059669")

        story = []

        # -- cover banner
        banner = Table([[
            Paragraph(
                "<font color='white' size='16'><b>"
                + _pdf(scan_data.get("target_url", ""))
                + "</b></font>", base["Normal"]),
        ]], colWidths=[W])
        banner.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#0f172a")),
            ("PADDING",    (0,0), (-1,-1), 18),
        ]))
        story.append(banner)
        story.append(Spacer(1, 0.3*cm))

        # sub-header
        story.append(Paragraph(
            "<font color='#6b7280'>AWVS v4.0 Security Assessment Report &nbsp;|&nbsp; "
            + _pdf(now) + " &nbsp;|&nbsp; Analyst: "
            + _pdf(scan_data.get("analyst", "")) + "</font>",
            ST["muted"]
        ))
        story.append(Spacer(1, 0.4*cm))

        # metadata table
        story.append(Paragraph("Scan Metadata", ST["h2"]))
        meta_rows = [
            ("Scan ID",       "#" + _pdf(str(scan_data.get("scan_id", "")))),
            ("Target URL",    _pdf(scan_data.get("target_url", ""))),
            ("Analyst",       _pdf(scan_data.get("analyst", ""))),
            ("Report Date",   _pdf(now)),
            ("Duration",      _pdf(scan_data.get("duration", ""))),
            ("Pages Crawled", _pdf(str(scan_data.get("pages_crawled", 0)))),
            ("Risk Score",    _pdf(str(round(risk, 1))) + " / 100"),
            ("Risk Level",    _pdf(risk_lv)),
        ]
        meta_tbl = Table(
            [[Paragraph(k, ST["muted"]), Paragraph(v, ST["body"])] for k, v in meta_rows],
            colWidths=[3.5*cm, W - 3.5*cm]
        )
        meta_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (0,-1), colors.HexColor("#f8fafc")),
            ("INNERGRID",     (0,0), (-1,-1), 0.4, colors.HexColor("#e2e8f0")),
            ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING",       (0,0), (-1,-1), 6),
            ("ROWBACKGROUNDS",(0,0), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(meta_tbl)
        story.append(Spacer(1, 0.5*cm))

        # executive summary
        story.append(Paragraph("Executive Summary", ST["h2"]))
        story.append(HRFlowable(width=W, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.2*cm))

        sev_rows = [["Severity", "Count", "Risk Level"]]
        sev_list = ["Critical", "High", "Medium", "Low", "Info"]
        for s in sev_list:
            sev_rows.append([
                Paragraph("<b>" + s + "</b>", ST["body"]),
                str(counts[s]),
                s.upper(),
            ])
        sev_tbl = Table(sev_rows, colWidths=[4*cm, 3*cm, W - 7*cm])
        rl_sev_colors = [RL_SEV.get(s, colors.grey) for s in sev_list]
        sev_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("INNERGRID",  (0,0), (-1,-1), 0.4, colors.HexColor("#e2e8f0")),
            ("BOX",        (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING",    (0,0), (-1,-1), 7),
            *[("TEXTCOLOR", (0,i+1),(0,i+1), rl_sev_colors[i]) for i in range(5)],
            *[("FONTNAME",  (0,i+1),(0,i+1), "Helvetica-Bold")   for i in range(5)],
        ]))
        story.append(sev_tbl)
        story.append(Spacer(1, 0.5*cm))

        # IP intelligence
        if scan_data.get("ip_address"):
            story.append(Paragraph("IP Intelligence", ST["h2"]))
            ip_fields = [
                ("IP Address",        scan_data.get("ip_address", "")),
                ("IP Version",        scan_data.get("ip_version", "")),
                ("Country / City",    scan_data.get("hosting_country", "")),
                ("ISP",               scan_data.get("hosting_isp", "")),
                ("Hosting Provider",  scan_data.get("hosting_org", "")),
                ("ASN",               scan_data.get("asn", "")),
            ]
            ip_tbl = Table(
                [[Paragraph(_pdf(k), ST["muted"]), Paragraph(_pdf(v) or "&mdash;", ST["body"])]
                 for k, v in ip_fields if v],
                colWidths=[3.5*cm, W - 3.5*cm]
            )
            ip_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#eff6ff")),
                ("INNERGRID",     (0,0), (-1,-1), 0.4, colors.HexColor("#bfdbfe")),
                ("BOX",           (0,0), (-1,-1), 1,   colors.HexColor("#93c5fd")),
                ("PADDING",       (0,0), (-1,-1), 7),
                ("ROWBACKGROUNDS",(0,0), (-1,-1),
                 [colors.HexColor("#eff6ff"), colors.HexColor("#dbeafe")]),
            ]))
            story.append(ip_tbl)
            story.append(Spacer(1, 0.5*cm))

        # findings
        story.append(Paragraph(
            "Detailed Findings (" + str(len(findings)) + ")", ST["h2"]))
        story.append(HRFlowable(width=W, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.3*cm))

        if not findings:
            story.append(Paragraph(
                "No vulnerabilities detected. Target appears secure against tested vectors.",
                ST["body"]))
        else:
            for idx, f in enumerate(findings, 1):
                sev   = f.get("severity", "Info")
                color = RL_SEV.get(sev, colors.grey)
                cvss  = f.get("cvss_score") or 0
                try:
                    from scanner.remediation_db import get_remediation
                    r = get_remediation(f.get("vuln_type", ""))
                except Exception:
                    r = {}

                block = []

                # title bar
                title_tbl = Table([[
                    Paragraph("<b><font color='white'>" + _pdf(sev.upper()) + "</font></b>", base["Normal"]),
                    Paragraph("<b><font color='white'>" + str(idx) + ". " + _pdf(f.get("vuln_type","")) + "</font></b>", base["Normal"]),
                    Paragraph("<font color='#e2e8f0'>CVSS " + str(round(cvss,1)) + "</font>" if cvss else "", base["Normal"]),
                    Paragraph("<font color='#93c5fd'>" + _pdf(f.get("cwe_id","")) + "</font>", base["Normal"]),
                ]], colWidths=[2.2*cm, W-6.5*cm, 1.8*cm, 2.5*cm])
                title_tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,-1), color),
                    ("PADDING",    (0,0), (-1,-1), 8),
                    ("FONTSIZE",   (0,0), (-1,-1), 9),
                ]))
                block.append(title_tbl)

                # evidence
                evid_rows = []
                for label, val in [
                    ("URL",       f.get("url")),
                    ("Parameter", f.get("parameter")),
                    ("Payload",   f.get("payload")),
                    ("Evidence",  f.get("evidence")),
                ]:
                    if val:
                        evid_rows.append([
                            Paragraph(_pdf(label), ST["muted"]),
                            Paragraph(_pdf(str(val)), ST["mono"]),
                        ])
                if evid_rows:
                    evid_tbl = Table(evid_rows, colWidths=[2.2*cm, W-2.2*cm])
                    evid_tbl.setStyle(TableStyle([
                        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f8fafc")),
                        ("INNERGRID",  (0,0), (-1,-1), 0.3, colors.HexColor("#e2e8f0")),
                        ("BOX",        (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
                        ("PADDING",    (0,0), (-1,-1), 5),
                    ]))
                    block.append(evid_tbl)

                # description
                desc = r.get("description") or f.get("description", "")
                if desc:
                    block.append(Spacer(1, 0.1*cm))
                    block.append(Paragraph("<b>Description</b>", ST["h3"]))
                    block.append(Paragraph(_pdf(desc), ST["body"]))

                # impact
                impact = r.get("impact", "")
                if impact:
                    block.append(Spacer(1, 0.1*cm))
                    block.append(Paragraph("<b>Business Impact</b>", ST["h3"]))
                    for line in impact.split("\n"):
                        if line.strip():
                            block.append(Paragraph(_pdf(line.strip()), ST["body"]))

                # fix steps
                fix_steps = r.get("fix_steps", [])
                if fix_steps:
                    block.append(Spacer(1, 0.1*cm))
                    block.append(Paragraph("<b>How to Fix</b>", ST["h3"]))
                    for step in fix_steps:
                        block.append(Paragraph(
                            "&#8226; " + _pdf(step.lstrip("0123456789. ")),
                            ST["fix"]))

                # owasp/cwe footer
                owasp = r.get("owasp") or f.get("owasp_category","")
                cwe   = r.get("cwe")   or f.get("cwe_id","")
                footer_txt = ("OWASP: " + _pdf(owasp)
                              + " | CWE: " + _pdf(cwe)
                              + " | CVSS: " + str(round(cvss, 1)))
                block.append(Spacer(1, 0.1*cm))
                block.append(Paragraph("<font color='#6b7280'>" + footer_txt + "</font>", ST["muted"]))
                block.append(Spacer(1, 0.4*cm))

                story.append(KeepTogether(block[:4]))
                for item in block[4:]:
                    story.append(item)
                story.append(HRFlowable(width=W, color=colors.HexColor("#e2e8f0"), thickness=0.5))
                story.append(Spacer(1, 0.2*cm))

        # footer
        story.append(Spacer(1, 0.8*cm))
        story.append(HRFlowable(width=W, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            "<font color='#6b7280'>AWVS v4.0 &mdash; Automated Web Vulnerability Scanner"
            " | " + _pdf(now) + " | Authorized Security Testing Only</font>",
            ST["muted"]
        ))

        doc.build(story)
        logger.info("PDF report: %s", output_path)
        return output_path

    except ImportError:
        logger.warning("ReportLab not installed — falling back to HTML")
        hp = output_path.replace(".pdf", "_fallback.html")
        return generate_html_report(scan_data, findings, hp)
    except Exception as e:
        logger.exception("PDF generation failed: %s", e)
        hp = output_path.replace(".pdf", "_fallback.html")
        return generate_html_report(scan_data, findings, hp)
