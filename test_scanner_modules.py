"""
test_scanner_modules.py  —  AWVS Scanner Module Diagnostic
Runs an import and smoke-test on every scanner module, reports pass/fail.
"""
import sys, os, traceback, time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "backend"))
sys.path.insert(0, os.path.join(ROOT, "frontend"))

PASS = "\033[92m[PASS]\033[0m"
FAIL = "\033[91m[FAIL]\033[0m"
WARN = "\033[93m[WARN]\033[0m"
INFO = "\033[94m[INFO]\033[0m"

results = []

def test(name, fn):
    try:
        fn()
        print(f"  {PASS} {name}")
        results.append((name, True, None))
    except Exception as e:
        msg = str(e)
        tb  = traceback.format_exc()
        print(f"  {FAIL} {name}")
        print(f"         {msg}")
        results.append((name, False, tb))

# ──────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("  AWVS Scanner Module Diagnostic")
print("="*60)

# ── 1. Core imports ───────────────────────────────────────────────
print(f"\n{INFO} 1. Core Imports")

def chk_crawler():
    from scanner.crawler import crawl
    assert callable(crawl)

def chk_fuzzer():
    from scanner.fuzzer import fuzz_forms
    assert callable(fuzz_forms)

def chk_engine():
    from scanner.engine import run_checks
    assert callable(run_checks)

def chk_advanced():
    from scanner.advanced_checks import run_advanced_checks
    assert callable(run_advanced_checks)

def chk_recon():
    from scanner.recon import run_recon
    assert callable(run_recon)

def chk_cvss():
    from scanner.cvss_scorer import calculate_cvss
    assert callable(calculate_cvss)

def chk_report_gen():
    from scanner.report_gen import generate_html_report, generate_pdf_report
    assert callable(generate_html_report) and callable(generate_pdf_report)

def chk_remediation_db():
    from scanner.remediation_db import get_remediation
    r = get_remediation("XSS")
    assert isinstance(r, dict), "Expected dict from get_remediation"

def chk_scan_controller():
    from scanner.scan_controller import get_scan_state
    assert callable(get_scan_state)

def chk_ip_intel():
    from scanner.ip_intel import get_ip_intel
    assert callable(get_ip_intel)

def chk_automation_daemon():
    from scanner.automation_daemon import start_automation_daemon
    assert callable(start_automation_daemon)

for name, fn in [
    ("crawler.crawl",                       chk_crawler),
    ("fuzzer.fuzz_forms",                   chk_fuzzer),
    ("engine.run_checks",                   chk_engine),
    ("advanced_checks.run_advanced_checks", chk_advanced),
    ("recon.run_recon",                     chk_recon),
    ("cvss_scorer.calculate_cvss",          chk_cvss),
    ("report_gen (html+pdf)",               chk_report_gen),
    ("remediation_db.get_remediation",      chk_remediation_db),
    ("scan_controller.get_scan_state",      chk_scan_controller),
    ("ip_intel.get_ip_intel",               chk_ip_intel),
    ("automation_daemon",                   chk_automation_daemon),
]:
    test(name, fn)

# ── 2. CVSS Scoring ───────────────────────────────────────────────
print(f"\n{INFO} 2. CVSS Scorer Smoke Test")

def chk_cvss_xss():
    from scanner.cvss_scorer import calculate_cvss
    score = calculate_cvss("XSS")
    assert isinstance(score, (int, float)) and 0 <= score <= 10, f"Bad score: {score}"

def chk_cvss_sqli():
    from scanner.cvss_scorer import calculate_cvss
    score = calculate_cvss("SQL Injection")
    assert isinstance(score, (int, float)) and 0 <= score <= 10

def chk_cvss_unknown():
    from scanner.cvss_scorer import calculate_cvss
    score = calculate_cvss("UNKNOWN_VULN_TYPE_XYZ")
    assert isinstance(score, (int, float))

for name, fn in [
    ("CVSS score for XSS",           chk_cvss_xss),
    ("CVSS score for SQL Injection",  chk_cvss_sqli),
    ("CVSS score for unknown type",   chk_cvss_unknown),
]:
    test(name, fn)

# ── 3. Remediation DB ─────────────────────────────────────────────
print(f"\n{INFO} 3. Remediation DB Coverage")

VULN_TYPES = [
    "XSS","SQL Injection","CSRF","Open Redirect","Command Injection",
    "Path Traversal","XXE","Security Headers","Cookie Security","HTTP Methods",
]

def chk_remediation(vtype):
    from scanner.remediation_db import get_remediation
    r = get_remediation(vtype)
    assert isinstance(r, dict), f"Expected dict for {vtype}"
    assert r.get("description"), f"Missing description for {vtype}"

for vt in VULN_TYPES:
    test(f"remediation_db entry: {vt}", lambda v=vt: chk_remediation(v))

# ── 4. HTML Report Generation ─────────────────────────────────────
print(f"\n{INFO} 4. HTML Report Generation")

def chk_html_report():
    from scanner.report_gen import generate_html_report
    import tempfile, os
    scan_data = {
        "scan_id": "TEST001",
        "target_url": "http://example.com",
        "analyst": "tester",
        "risk_score": 72,
        "risk_level": "High",
        "started": "2026-08-10 12:00 UTC",
        "duration": "5m 30s",
        "pages_crawled": 12,
        "ip_address": "93.184.216.34",
        "ip_version": "IPv4",
        "hosting_country": "US",
        "hosting_isp": "Edgecast",
        "hosting_org": "EDGECAST",
        "asn": "AS15133",
    }
    findings = [
        {"vuln_type": "XSS", "severity": "High", "cvss_score": 7.5,
         "cwe_id": "CWE-79", "url": "http://example.com/search",
         "parameter": "q", "payload": "<script>alert(1)</script>", "evidence": "Reflected"},
        {"vuln_type": "SQL Injection", "severity": "Critical", "cvss_score": 9.8,
         "cwe_id": "CWE-89", "url": "http://example.com/login",
         "parameter": "username", "payload": "' OR 1=1--", "evidence": "Error-based"},
    ]
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        path = f.name
    try:
        result = generate_html_report(scan_data, findings, path)
        assert os.path.exists(result), "File not created"
        size = os.path.getsize(result)
        assert size > 1000, f"Report too small: {size} bytes"
        content = open(result, encoding="utf-8").read()
        assert "XSS" in content, "XSS not in report"
        assert "SQL Injection" in content, "SQL Injection not in report"
        assert "AWVS" in content, "AWVS header missing"
        print(f"         Report size: {size:,} bytes  ✓")
    finally:
        os.unlink(path)

test("HTML report generation (with findings)", chk_html_report)

# ── 5. PDF Report Generation ──────────────────────────────────────
print(f"\n{INFO} 5. PDF Report Generation")

def chk_pdf_report():
    from scanner.report_gen import generate_pdf_report
    import tempfile, os
    scan_data = {
        "scan_id": "TEST002", "target_url": "http://example.com",
        "analyst": "tester", "risk_score": 55, "risk_level": "Medium",
        "started": "", "duration": "2m", "pages_crawled": 5,
    }
    findings = [
        {"vuln_type": "CSRF", "severity": "Medium", "cvss_score": 6.5,
         "cwe_id": "CWE-352", "url": "http://example.com/transfer",
         "parameter": "amount", "payload": "", "evidence": "No token"},
    ]
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        path = f.name
    try:
        result = generate_pdf_report(scan_data, findings, path)
        assert os.path.exists(result), "File not created"
        size = os.path.getsize(result)
        assert size > 500, f"Report too small: {size} bytes"
        ext = os.path.splitext(result)[1]
        print(f"         Report format: {ext}, size: {size:,} bytes  ✓")
    finally:
        if os.path.exists(path): os.unlink(path)
        if result != path and os.path.exists(result): os.unlink(result)

test("PDF report generation", chk_pdf_report)

# ── 6. Database Serialization ─────────────────────────────────────
print(f"\n{INFO} 6. Database Serialization")

def chk_serialize_objectid():
    from bson.objectid import ObjectId
    from database import serialize_doc, deserialize_doc
    oid = ObjectId()
    doc = {"_id": oid, "name": "test", "tags": [ObjectId(), ObjectId()]}
    ser = serialize_doc(doc)
    assert isinstance(ser["_id"], dict) and "$oid" in ser["_id"]
    assert all(isinstance(t, dict) and "$oid" in t for t in ser["tags"])
    restored = deserialize_doc(ser)
    assert restored["_id"] == oid

def chk_serialize_list_of_docs():
    from bson.objectid import ObjectId
    from datetime import datetime
    from database import serialize_doc
    docs = [
        {"_id": ObjectId(), "created_at": datetime.utcnow(), "val": 42},
        {"_id": ObjectId(), "status": "completed"},
    ]
    result = serialize_doc(docs)
    assert isinstance(result, list) and len(result) == 2
    assert "$oid" in result[0]["_id"]
    assert "$date" in result[0]["created_at"]

for name, fn in [
    ("serialize ObjectId in doc",     chk_serialize_objectid),
    ("serialize list of docs",        chk_serialize_list_of_docs),
]:
    test(name, fn)

# ── 7. Server Health ──────────────────────────────────────────────
print(f"\n{INFO} 7. Server Health Check")

def chk_flask():
    import requests
    r = requests.get("http://127.0.0.1:5000", timeout=8, allow_redirects=True)
    assert r.status_code in (200, 302), f"Flask returned {r.status_code}"
    print(f"         Flask status: {r.status_code}")

def chk_fastapi():
    import requests
    r = requests.get("http://127.0.0.1:8000", timeout=8)
    assert r.status_code == 200, f"FastAPI returned {r.status_code}"
    data = r.json()
    print(f"         FastAPI: {data.get('service','?')} v{data.get('version','?')}")

def chk_remote_db():
    import requests, importlib.util
    spec = importlib.util.spec_from_file_location("cfg", "backend/config.py")
    cfg = importlib.util.module_from_spec(spec); spec.loader.exec_module(cfg)
    key = cfg.Config.API_KEY
    r = requests.post(
        "http://127.0.0.1:8000/api/v1/remote-db/query",
        json={"collection": "scans", "operation": "find",
              "args": [{}], "kwargs": {"limit": 1, "skip": 0}},
        headers={"X-API-Key": key},
        timeout=8,
    )
    assert r.status_code == 200, f"remote-db returned {r.status_code}: {r.text[:200]}"
    data = r.json()
    assert data.get("ok"), f"Remote DB not OK: {data}"
    print(f"         Remote DB query: OK, {len(data.get('result',[]))} scan(s) found")

for name, fn in [
    ("Flask frontend reachable",  chk_flask),
    ("FastAPI backend reachable", chk_fastapi),
    ("Remote DB proxy query",     chk_remote_db),
]:
    test(name, fn)

# ── 8. app.py security header hook ───────────────────────────────
print(f"\n{INFO} 8. Flask App — after_request passthrough guard")

def chk_report_endpoint():
    """Verify the report endpoint no longer crashes on send_file passthrough."""
    import requests
    # If it's reachable (even redirecting to login) it means no import crash
    r = requests.get("http://127.0.0.1:5000/scan/000000000000/report/html",
                     timeout=8, allow_redirects=False)
    # 302 = redirect to login, 404 = scan not found, both are acceptable (no 500)
    assert r.status_code in (302, 404, 200), f"Unexpected: {r.status_code}"
    print(f"         Report endpoint: {r.status_code} (no 500 crash)")

test("Report endpoint (no passthrough crash)", chk_report_endpoint)

# ── Summary ───────────────────────────────────────────────────────
print("\n" + "="*60)
passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
print(f"  TOTAL: {passed} passed, {failed} failed out of {len(results)} tests")
print("="*60)

if failed:
    print(f"\n{FAIL} FAILED TESTS — details:\n")
    for name, ok, tb in results:
        if not ok:
            print(f"  ── {name}")
            if tb:
                for line in tb.strip().splitlines()[-8:]:
                    print(f"     {line}")
            print()
    sys.exit(1)
else:
    print(f"\n{PASS} All scanner modules operational!\n")
    sys.exit(0)
