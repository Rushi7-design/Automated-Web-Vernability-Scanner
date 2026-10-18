"""
scanner/scan_controller.py  (v4 — Advanced — MongoDB)
Orchestrates full pipeline: Recon → Crawl → Core Engine → Advanced Checks → CVSS → Report → DB
"""

import json
import logging
import os
import threading
from datetime import datetime
from bson.objectid import ObjectId

logger = logging.getLogger(__name__)

_active_scans: dict = {}
_lock = threading.Lock()


def get_scan_state(scan_id) -> dict:
    with _lock:
        return _active_scans.get(str(scan_id), {})


def _run_pipeline(app, scan_id: str, config: dict):
    log_messages = []

    def progress(msg: str):
        ts    = datetime.utcnow().strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        log_messages.append(entry)
        logger.info(f"[Scan-{scan_id}] {msg}")
        with _lock:
            if scan_id in _active_scans:
                _active_scans[scan_id]["log"] = log_messages.copy()

    class NullContext:
        def __enter__(self): return None
        def __exit__(self, exc_type, exc_val, exc_tb): return False

    ctx = app.app_context() if app else NullContext()
    with ctx:
        from database import db, Scan
        from scanner.recon           import ReconModule
        from scanner.crawler         import CrawlerModule
        from scanner.engine          import VulnerabilityEngine
        from scanner.advanced_checks import AdvancedScanner
        from scanner.fuzzer          import FuzzerModule
        from scanner.cvss_scorer     import enrich_finding, calculate_risk_score
        from scanner.report_gen      import generate_pdf_report, generate_html_report

        try:
            scan = Scan.get(scan_id)
            if not scan:
                return

            db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"status": "running", "start_time": datetime.utcnow()}}
            )

            with _lock:
                _active_scans[scan_id]["status"] = "running"

            target_url  = config["target_url"]
            reports_dir = config.get("reports_dir", "reports")
            timeout     = int(config.get("timeout", 10))

            # ── PHASE 0: IP INTELLIGENCE ────────────────────────────────────
            progress(">> Phase 0: IP Intelligence & Geolocation")
            try:
                from scanner.ip_intel import run_ip_intel
                ip_data = run_ip_intel(target_url, progress_callback=progress)
                
                # Persist to scan object in MongoDB
                db.scans.update_one(
                    {"_id": ObjectId(scan_id)},
                    {"$set": {
                        "ip_address": ip_data.get("primary_ip", ""),
                        "ip_version": ip_data.get("ip_version", ""),
                        "hosting_country": f"{ip_data.get('country_flag','')} {ip_data.get('country','')} ({ip_data.get('city','')})".strip(),
                        "hosting_isp": ip_data.get("isp", ""),
                        "hosting_org": ip_data.get("hosting_provider", ""),
                        "asn": ip_data.get("asn", "")
                    }}
                )
                
                progress(
                    f"  [OK] IP: {ip_data.get('primary_ip')} | "
                    f"{ip_data.get('country_flag','')} {ip_data.get('country','')} | "
                    f"{ip_data.get('hosting_provider','?')} | {ip_data.get('isp','?')}"
                )
            except Exception as _e:
                progress(f"  [WARN] IP Intel failed: {_e}")
                ip_data = {}

            # Reload scan status from MongoDB
            scan = Scan.get(scan_id)

            recon_findings = []
            if config.get("enable_recon", True):
                progress(">> Phase 1: Reconnaissance")
                recon_module = ReconModule(
                    target_url       = target_url,
                    timeout          = timeout,
                    progress_callback= progress,
                )
                recon_data = recon_module.run()
                recon_findings = recon_data.get("vulns", [])
                recon_doc = {
                    "recon_id":       str(ObjectId()),
                    "ip_address":    ip_data.get("primary_ip") or recon_data.get("ip_address", ""),
                    "open_ports":    recon_data.get("open_ports", "[]"),
                    "detected_tech": recon_data.get("detected_tech", "[]"),
                    "server_banner": recon_data.get("server_banner", ""),
                    "http_headers":  json.dumps(recon_data.get("all_headers", {})),
                }
                
                db.scans.update_one(
                    {"_id": ObjectId(scan_id)},
                    {"$push": {"recon_results": recon_doc}}
                )
                
                progress(f"  [OK] Recon complete. IP: {recon_data.get('ip_address')}")
            else:
                progress("-- Recon skipped.")


            # ── PHASE 2: CRAWL ───────────────────────────────────────────────
            progress("▶ Phase 2: BFS Web Crawling")
            crawler = CrawlerModule(
                base_url          = target_url,
                max_depth         = int(config.get("max_depth", 3)),
                max_pages         = int(config.get("max_pages", 100)),
                timeout           = timeout,
                respect_robots    = True,
                progress_callback = progress,
            )
            pages = crawler.crawl()

            page_id_map = {}
            crawled_pages_docs = []
            for p in pages:
                page_id = str(ObjectId())
                crawled_pages_docs.append({
                    "page_id":     page_id,
                    "url":         p["url"][:1024],
                    "method":      p.get("method", "GET"),
                    "params":      p.get("params", "{}"),
                    "status_code": p.get("status_code"),
                    "content_type": p.get("content_type", ""),
                    "depth":       p.get("depth", 0),
                })
                page_id_map[p["url"]] = page_id

            db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"crawled_pages": crawled_pages_docs}}
            )
            progress(f"✔ Crawl complete. {len(pages)} pages stored.")

            # ── PHASE 3: CORE VULNERABILITY ENGINE ───────────────────────────
            progress("▶ Phase 3: Core Vulnerability Engine")
            engine_options = {
                "xss":      config.get("check_xss",      True),
                "sqli":     config.get("check_sqli",     True),
                "csrf":     config.get("check_csrf",     True),
                "headers":  config.get("check_headers",  True),
                "redirect": config.get("check_redirect", True),
            }
            engine = VulnerabilityEngine(
                crawl_data        = pages,
                options           = engine_options,
                progress_callback = progress,
                timeout           = timeout,
            )
            core_findings = engine.run()
            progress(f"✔ Core engine: {len(core_findings)} findings.")

            # ── PHASE 3b: ADVANCED CHECKS ─────────────────────────────────────
            adv_findings = []
            full_mode = config.get("check_advanced", False)
            progress(f"▶ Phase 3b: Advanced Checks ({'Full' if full_mode else 'Quick'} mode)")
            try:
                adv_scanner = AdvancedScanner(
                    base_url          = target_url,
                    crawl_data        = pages,
                    progress_callback = progress,
                    timeout           = timeout,
                )
                if full_mode:
                    adv_findings = adv_scanner.run()
                else:
                    quick_steps = [
                        ("Cookie Security",  adv_scanner.scan_cookie_security),
                        ("SSL/TLS",          adv_scanner.scan_ssl),
                        ("HTTP Methods",     adv_scanner.scan_http_methods),
                        ("CORS",             adv_scanner.scan_cors),
                        ("Clickjacking",     adv_scanner.scan_clickjacking),
                        ("Subdomain Takeover", adv_scanner.scan_subdomain_takeover),
                        ("Broken Auth",      adv_scanner.scan_broken_auth),
                    ]
                    for name, fn in quick_steps:
                        try:
                            before = len(adv_scanner.findings)
                            fn()
                            new = len(adv_scanner.findings) - before
                            if new:
                                progress(f"  [ADV] {name}: {new} finding(s)")
                            else:
                                progress(f"  [ADV] {name}: clean")
                        except Exception as e:
                            progress(f"  [ADV] {name}: error — {e}")
                    adv_findings = adv_scanner.findings
                progress(f"✔ Advanced checks: {len(adv_findings)} additional findings.")
            except Exception as e:
                progress(f"⚠ Advanced checks error: {e}")
                logger.error(f"[Scan-{scan_id}] Advanced checks crashed: {e}", exc_info=True)

            # ── PHASE 3c: PARAMETER FUZZER ────────────────────────────────────
            fuzz_findings = []
            progress("▶ Phase 3c: Parameter Fuzzer")
            try:
                fuzz_pages = pages if full_mode else pages[:3]
                fuzzer = FuzzerModule(
                    base_url          = target_url,
                    crawl_data        = fuzz_pages,
                    progress_callback = progress,
                    timeout           = timeout,
                )
                fuzz_findings = fuzzer.run()
                progress(f"✔ Fuzzer: {len(fuzz_findings)} additional findings.")
            except Exception as e:
                progress(f"⚠ Fuzzer error: {e}")
                logger.error(f"[Scan-{scan_id}] Fuzzer crashed: {e}", exc_info=True)

            # ── PHASE 4: CVSS ENRICHMENT ──────────────────────────────────────
            progress("▶ Phase 4: CVSS Scoring & Risk Assessment")
            all_findings = recon_findings + core_findings + adv_findings + fuzz_findings
            enriched = [enrich_finding(f) for f in all_findings]
            risk_score, risk_level = calculate_risk_score(enriched)

            # Persist all vulnerabilities in scans collection
            vuln_docs = []
            for f in enriched:
                page_id = page_id_map.get(f.get("url"))
                vuln_docs.append({
                    "vuln_id":        str(ObjectId()),
                    "page_id":        page_id,
                    "vuln_type":      f.get("vuln_type", ""),
                    "severity":       f.get("severity", "Info"),
                    "description":    f.get("description", ""),
                    "evidence":       f.get("evidence", ""),
                    "url":            f.get("url", ""),
                    "parameter":      f.get("parameter", ""),
                    "payload":        f.get("payload", ""),
                    "remediation":    f.get("remediation", ""),
                    "cvss_score":     f.get("cvss_score", 0.0),
                    "cwe_id":         f.get("cwe_id", ""),
                    "owasp_category": f.get("owasp_category", ""),
                    "false_positive": False,
                    "analyst_note":   "",
                    "detected_at":    datetime.utcnow()
                })

            db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {
                    "vulnerabilities": vuln_docs,
                    "risk_score": risk_score,
                    "risk_level": risk_level
                }}
            )
            progress(f"✔ {len(enriched)} total findings. Risk Score: {risk_score}/100 ({risk_level})")

            # Reload owner details
            scan = Scan.get(scan_id)

            # ── PHASE 5: REPORT GENERATION ───────────────────────────────────
            progress("▶ Phase 5: Generating Professional Reports")
            end_time = datetime.utcnow()
            duration_secs = int((end_time - scan.start_time).total_seconds()) if scan.start_time else 0
            scan_data = {
                "scan_id":          scan_id,
                "target_url":       target_url,
                "analyst":          scan.owner.username if scan.owner else "Unknown",
                "risk_score":       risk_score,
                "risk_level":       risk_level,
                "started":          scan.start_time.strftime("%Y-%m-%d %H:%M UTC") if scan.start_time else "N/A",
                "duration":         f"{duration_secs // 60}m {duration_secs % 60}s",
                "pages_crawled":    len(pages),
                "ip_address":       scan.ip_address or "",
                "ip_version":       scan.ip_version or "",
                "hosting_country":  scan.hosting_country or "",
                "hosting_isp":      scan.hosting_isp or "",
                "hosting_org":      scan.hosting_org or "",
                "asn":              scan.asn or "",
            }

            base_dir = os.path.join(reports_dir, str(scan_id))
            os.makedirs(base_dir, exist_ok=True)

            html_path = os.path.join(base_dir, f"report_{scan_id}.html")
            generate_html_report(scan_data, enriched, html_path)
            
            reports_docs = [
                {
                    "report_id": str(ObjectId()),
                    "file_path": html_path,
                    "format": "html",
                    "generated_at": datetime.utcnow()
                }
            ]

            try:
                pdf_path = os.path.join(base_dir, f"report_{scan_id}.pdf")
                generate_pdf_report(scan_data, enriched, pdf_path)
                reports_docs.append({
                    "report_id": str(ObjectId()),
                    "file_path": pdf_path,
                    "format": "pdf",
                    "generated_at": datetime.utcnow()
                })
                progress("✔ PDF report generated.")
            except Exception as e:
                progress(f"⚠ PDF error: {e}")

            db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {"reports": reports_docs}}
            )

            # ── FINALIZE ──────────────────────────────────────────────────────
            db.scans.update_one(
                {"_id": ObjectId(scan_id)},
                {"$set": {
                    "status": "completed",
                    "end_time": datetime.utcnow()
                }}
            )

            with _lock:
                _active_scans[scan_id]["status"]   = "completed"
                _active_scans[scan_id]["findings"]  = len(enriched)
                _active_scans[scan_id]["risk"]      = risk_score

            progress(
                f"✅ Scan #{scan_id} complete! "
                f"{len(enriched)} findings | Risk: {risk_score}/100 ({risk_level})"
            )

        except Exception as e:
            logger.exception(f"[ScanController] Fatal error scan #{scan_id}: {e}")
            progress(f"❌ Fatal error: {e}")
            try:
                db.scans.update_one(
                    {"_id": ObjectId(scan_id)},
                    {"$set": {
                        "status": "failed",
                        "end_time": datetime.utcnow()
                    }}
                )
            except Exception:
                pass
            with _lock:
                if scan_id in _active_scans:
                    _active_scans[scan_id]["status"] = "failed"


def start_scan(app, scan_id, config: dict):
    scan_id_str = str(scan_id)
    with _lock:
        _active_scans[scan_id_str] = {"status": "starting", "log": [], "findings": 0}

    t = threading.Thread(
        target=_run_pipeline, args=(app, scan_id_str, config),
        name=f"scan-{scan_id_str}", daemon=True
    )
    t.start()
    with _lock:
        _active_scans[scan_id_str]["thread"] = t

    logger.info(f"[ScanController] Scan #{scan_id_str} started.")
    return scan_id_str
