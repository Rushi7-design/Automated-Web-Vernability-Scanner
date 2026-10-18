"""
backend_server.py — FastAPI Production Backend Server (v4.0)
Exposes High-Performance Security APIs for AWVS Portal and Chrome Extension.
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.dirname(__file__))

import time
import psutil
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from bson.objectid import ObjectId
import uvicorn

# Import database and scanner controller
import database
from database import User
from scanner.scan_controller import start_scan, get_scan_state

# Load config
from config import Config

app = FastAPI(
    title="AWVS v4.0 API Backend",
    description="High-performance vulnerability auditing and systems orchestration backend.",
    version="4.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup DB Connection
@app.on_event("startup")
async def startup_db_client():
    database.init_db(Config.MONGO_URI)
    print(f"[FastAPI] Backend server initialized database connection successfully.")

# API Key Dependency verification
async def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != Config.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key."
        )
    return x_api_key

# --- SCHEMAS ---
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"

class StartScanRequest(BaseModel):
    target_url: str
    profile: str = "full"
    max_depth: Optional[int] = 3
    max_pages: Optional[int] = 100
    timeout: Optional[int] = 10
    check_xss: Optional[bool] = True
    check_sqli: Optional[bool] = True
    check_csrf: Optional[bool] = True
    check_headers: Optional[bool] = True
    check_redirect: Optional[bool] = True
    enable_recon: Optional[bool] = True
    check_advanced: Optional[bool] = True

# --- ROUTES ---

@app.get("/")
def read_root():
    return {
        "status": "healthy",
        "platform": "AWVS v4.0",
        "timestamp": datetime.utcnow().isoformat()
    }

# Auth Routes
@app.post("/api/v1/auth/login")
def api_login(req: LoginRequest):
    user = User.find_by_username(req.username)
    if user and user.check_password(req.password):
        return {
            "ok": True,
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "api_key": Config.API_KEY
        }
    raise HTTPException(status_code=400, detail="Invalid username or password.")

@app.post("/api/v1/auth/register")
def api_register(req: RegisterRequest):
    if len(req.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters.")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    
    existing = User.find_by_username(req.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username is already taken.")

    from werkzeug.security import generate_password_hash
    user_doc = {
        "username": req.username,
        "password_hash": generate_password_hash(req.password),
        "role": req.role,
        "created_at": datetime.utcnow()
    }
    res = database.db.users.insert_one(user_doc)
    return {"ok": True, "user_id": str(res.inserted_id)}

# Scan Routes
@app.post("/api/v1/scans/start", dependencies=[Depends(verify_api_key)])
def api_start_scan(req: StartScanRequest):
    target = req.target_url.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target URL is required.")
    
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    # Setup profile parameters
    check_xss = req.check_xss
    check_sqli = req.check_sqli
    check_csrf = req.check_csrf
    check_headers = req.check_headers
    check_redirect = req.check_redirect
    enable_recon = req.enable_recon
    check_advanced = req.check_advanced
    max_depth = req.max_depth
    max_pages = req.max_pages
    timeout = req.timeout

    if req.profile == "quick":
        check_xss = False
        check_sqli = False
        check_csrf = False
        check_headers = True
        check_redirect = True
        enable_recon = True
        check_advanced = False
        max_depth = 1
        max_pages = 25
    elif req.profile == "standard":
        check_xss = True
        check_sqli = True
        check_csrf = True
        check_headers = True
        check_redirect = True
        enable_recon = True
        check_advanced = False
        max_depth = 3
        max_pages = 100

    scan_doc = {
        "user_id": None, # API triggered scan
        "target_url": target,
        "scope": target,
        "status": "pending",
        "check_xss": check_xss,
        "check_sqli": check_sqli,
        "check_csrf": check_csrf,
        "check_headers": check_headers,
        "check_redirect": check_redirect,
        "enable_recon": enable_recon,
        "check_advanced": check_advanced,
        "risk_score": 0.0,
        "risk_level": "Unknown",
        "recon_results": [],
        "crawled_pages": [],
        "vulnerabilities": [],
        "notes": [],
        "reports": []
    }
    res = database.db.scans.insert_one(scan_doc)
    scan_id = str(res.inserted_id)

    cfg = {
        "target_url": target,
        "check_xss": check_xss,
        "check_sqli": check_sqli,
        "check_csrf": check_csrf,
        "check_headers": check_headers,
        "check_redirect": check_redirect,
        "enable_recon": enable_recon,
        "check_advanced": check_advanced,
        "max_depth": max_depth,
        "max_pages": max_pages,
        "timeout": timeout,
        "reports_dir": Config.REPORTS_DIR,
    }

    start_scan(None, scan_id, cfg)
    return {
        "ok": True,
        "scan_id": scan_id,
        "message": f"Vulnerability audit launched successfully against {target}."
    }

class StartScanExistingRequest(BaseModel):
    config: dict

@app.post("/api/v1/scans/{scan_id}/start", dependencies=[Depends(verify_api_key)])
def api_start_existing_scan(scan_id: str, req: StartScanExistingRequest):
    start_scan(None, scan_id, req.config)
    return {"ok": True, "message": "Scan execution pipeline started on backend."}

@app.get("/api/v1/scans/list")
def api_list_scans():
    cursor = database.db.scans.find().sort("_id", -1)
    scans = []
    for s in cursor:
        scans.append({
            "scan_id": str(s["_id"]),
            "target_url": s["target_url"],
            "status": s["status"],
            "risk_score": s.get("risk_score", 0.0),
            "risk_level": s.get("risk_level", "Unknown"),
            "vulnerabilities_count": len(s.get("vulnerabilities", [])),
            "created_at": str(s["_id"].generation_time)
        })
    return {"ok": True, "scans": scans}

@app.get("/api/v1/scans/{scan_id}")
def api_scan_detail(scan_id: str):
    if not ObjectId.is_valid(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format.")
    s = database.db.scans.find_one({"_id": ObjectId(scan_id)})
    if not s:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    
    # Serialize scan details
    return {
        "ok": True,
        "scan_id": str(s["_id"]),
        "target_url": s["target_url"],
        "status": s["status"],
        "risk_score": s.get("risk_score", 0.0),
        "risk_level": s.get("risk_level", "Unknown"),
        "ip_address": s.get("ip_address", ""),
        "hosting_country": s.get("hosting_country", ""),
        "vulnerabilities": s.get("vulnerabilities", []),
        "crawled_pages_count": len(s.get("crawled_pages", [])),
        "recon_results": s.get("recon_results", [])
    }

@app.get("/api/v1/scans/{scan_id}/status")
def api_scan_status(scan_id: str):
    state = get_scan_state(scan_id)
    if state:
        return {
            "ok": True,
            "status": state.get("status", "running"),
            "logs": state.get("log", [])
        }
    # Fallback to database
    if not ObjectId.is_valid(scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format.")
    s = database.db.scans.find_one({"_id": ObjectId(scan_id)})
    if not s:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return {
        "ok": True,
        "status": s["status"],
        "logs": ["[*] Scan completed. Fetch logs from archives."]
    }

class RemoteDbQuery(BaseModel):
    collection: str
    operation: str
    args: list
    kwargs: dict

@app.post("/api/v1/remote-db/query", dependencies=[Depends(verify_api_key)])
def remote_db_query(req: RemoteDbQuery):
    from database import serialize_doc, deserialize_doc
    try:
        args = [deserialize_doc(arg) for arg in req.args]
        kwargs = {k: deserialize_doc(v) for k, v in req.kwargs.items()}
        
        if req.collection == "__database__":
            op = getattr(database.db, req.operation)
            res = op(*args, **kwargs)
        else:
            col = database.db[req.collection]
            op = getattr(col, req.operation)
            
            if req.operation == "find":
                cursor = op(*args)
                if "sort" in kwargs and kwargs["sort"]:
                    cursor = cursor.sort(*kwargs["sort"])
                if "limit" in kwargs and kwargs["limit"] is not None:
                    cursor = cursor.limit(kwargs["limit"])
                if "skip" in kwargs and kwargs["skip"] is not None:
                    cursor = cursor.skip(kwargs["skip"])
                res = list(cursor)
            elif req.operation == "insert_one":
                res_obj = op(*args, **kwargs)
                res = {"inserted_id": str(res_obj.inserted_id) if res_obj and getattr(res_obj, "inserted_id", None) else None}
            elif req.operation in ("update_one", "update_many"):
                res_obj = op(*args, **kwargs)
                res = {
                    "matched_count": getattr(res_obj, "matched_count", 0),
                    "modified_count": getattr(res_obj, "modified_count", 0)
                }
            elif req.operation in ("delete_one", "delete_many"):
                res_obj = op(*args, **kwargs)
                res = {"deleted_count": getattr(res_obj, "deleted_count", 0)}
            elif req.operation == "aggregate":
                res = list(op(*args))
            else:
                res = op(*args, **kwargs)
            
        return {"ok": True, "result": serialize_doc(res)}
    except Exception as err:
        raise HTTPException(status_code=500, detail=str(err))

# System Info Route
@app.get("/api/v1/system/stats")
def api_system_stats():
    return {
        "cpu_usage": psutil.cpu_percent(interval=None),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage("/").percent if os.path.exists("/") else 0,
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    # Declare context variables
    os.environ["AWVS_BACKEND"] = "true"
    uvicorn.run("backend_server:app", host="0.0.0.0", port=8000, reload=True)
