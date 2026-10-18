# scanner/automation_daemon.py
"""
scanner/automation_daemon.py — Background automated scanner thread.
Monitors targets.txt and triggers scans automatically without human intervention.
"""
import os
import time
import logging
import threading
from datetime import datetime
from bson.objectid import ObjectId

logger = logging.getLogger("awvs.automation")

# Track URLs that we have already processed in the current runtime session
_processed_urls = set()

def monitor_targets_file(app):
    """Monitors targets.txt for new URLs and triggers scans automatically."""
    targets_file = "targets.txt"
    
    # Ensure targets.txt exists
    if not os.path.exists(targets_file):
        try:
            with open(targets_file, "w") as f:
                f.write("# AWVS Auto-Scan Target List\n")
                f.write("# Add one target URL per line to scan them automatically.\n")
                f.write("http://127.0.0.1:8888\n")
            logger.info(f"[Automation] Created default {targets_file}")
        except Exception as e:
            logger.error(f"[Automation] Could not create {targets_file}: {e}")
            return

    # Create logs directory if it doesn't exist
    os.makedirs("instance", exist_ok=True)
    auto_log_path = "instance/automation.log"

    def log_auto(msg):
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [AUTOMATED] {msg}\n"
        try:
            with open(auto_log_path, "a") as lf:
                lf.write(entry)
            logger.info(f"[Automation] {msg}")
        except Exception:
            pass

    log_auto("Orchestrator daemon started. Monitoring targets.txt for changes...")

    # Load initial URLs to avoid scanning them again unless changed or forced
    try:
        with open(targets_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    _processed_urls.add(line)
        log_auto(f"Loaded {len(_processed_urls)} initial target(s) from targets.txt.")
    except Exception as e:
        logger.error(f"[Automation] Error reading initial targets: {e}")

    # Main monitoring loop
    while True:
        try:
            time.sleep(10)  # Check file every 10 seconds
            
            if not os.path.exists(targets_file):
                continue
                
            current_targets = []
            with open(targets_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        current_targets.append(line)

            for target in current_targets:
                if target not in _processed_urls:
                    log_auto(f"New target detected: {target}. Triggering autonomous scan...")
                    
                    # Add to processed to avoid double triggers
                    _processed_urls.add(target)
                    
                    # Trigger scan inside flask context
                    with app.app_context():
                        from database import db
                        from scanner.scan_controller import start_scan
                        
                        # Find system user or default user
                        user = db.users.find_one({"role": "admin"})
                        user_id = user["_id"] if user else ObjectId()
                        
                        # Create Scan document in MongoDB
                        scan_doc = {
                            "user_id": user_id,
                            "target_url": target,
                            "status": "pending",
                            "created_at": datetime.utcnow(),
                            "recon_results": [],
                            "crawled_pages": [],
                            "vulnerabilities": [],
                            "reports": [],
                            "notes": [],
                            "risk_score": 0,
                            "risk_level": "Info"
                        }
                        
                        insert_res = db.scans.insert_one(scan_doc)
                        scan_id = insert_res.inserted_id
                        
                        # Configure full scan modules
                        config = {
                            "target_url": target,
                            "max_depth": 3,
                            "max_pages": 100,
                            "timeout": 10,
                            "enable_recon": True,
                            "check_xss": True,
                            "check_sqli": True,
                            "check_csrf": True,
                            "check_headers": True,
                            "check_redirect": True,
                            "check_advanced": True
                        }
                        
                        # Launch async scan pipeline thread
                        start_scan(app, scan_id, config)
                        log_auto(f"Scan #{scan_id} successfully initiated for target {target}")
                        
        except Exception as e:
            logger.error(f"[Automation] Error in monitoring loop: {e}")

def start_automation_daemon(app):
    """Starts the automation daemon in a background daemon thread."""
    t = threading.Thread(target=monitor_targets_file, args=(app,), name="automation-daemon", daemon=True)
    t.start()
    logger.info("[Automation] Automated monitor thread initialized.")
