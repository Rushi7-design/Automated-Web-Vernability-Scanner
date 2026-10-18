from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from pymongo import MongoClient
from bson.objectid import ObjectId

# Global client and db reference
client = None
db = None

import os
import json

DB_FILE = os.path.join("instance", "db.json")

def serialize_doc(obj):
    """Recursively convert MongoDB documents/lists to JSON-safe dicts."""
    if isinstance(obj, ObjectId):
        return {"$oid": str(obj)}
    if isinstance(obj, datetime):
        return {"$date": obj.isoformat()}
    if isinstance(obj, dict):
        return {k: serialize_doc(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [serialize_doc(item) for item in obj]
    return obj

def deserialize_doc(obj):
    """Recursively restore MongoDB documents from JSON-safe dicts."""
    if isinstance(obj, dict):
        if "$oid" in obj:
            return ObjectId(obj["$oid"])
        if "$date" in obj:
            return datetime.fromisoformat(obj["$date"])
        return {k: deserialize_doc(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [deserialize_doc(item) for item in obj]
    return obj


def load_persistent_mock(db_mock):
    if not os.path.exists(DB_FILE):
        return
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for col_name, docs in data.items():
            for doc in docs:
                deserialized = deserialize_doc(doc)
                db_mock[col_name].insert_one(deserialized)
        print(f"[+] Loaded persistent mock database from {DB_FILE}")
    except Exception as err:
        print(f"[-] Failed to load persistent mock: {err}")

def save_persistent_mock(db_mock):
    try:
        os.makedirs("instance", exist_ok=True)
        data = {}
        for col_name in db_mock.list_collection_names():
            docs = list(db_mock[col_name].find())
            data[col_name] = [serialize_doc(doc) for doc in docs]
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Saved database state persistently to {DB_FILE}")
    except Exception as err:
        print(f"[-] Failed to save persistent mock: {err}")

class PersistentCollectionWrapper:
    def __init__(self, collection, db_ref):
        self._collection = collection
        self._db_ref = db_ref

    def __getattr__(self, name):
        attr = getattr(self._collection, name)
        if callable(attr) and name in ("insert_one", "insert_many", "update_one", "update_many", "delete_one", "delete_many", "find_one_and_update", "find_one_and_delete", "replace_one"):
            def wrapper(*args, **kwargs):
                res = attr(*args, **kwargs)
                save_persistent_mock(self._db_ref)
                return res
            return wrapper
        return attr

class PersistentDatabaseWrapper:
    def __init__(self, db_ref):
        self._db = db_ref
        self._wrappers = {}

    def __getattr__(self, name):
        if name.startswith("_"):
            return getattr(self, name)
        attr = getattr(self._db, name)
        from mongomock.collection import Collection
        if isinstance(attr, Collection):
            if name not in self._wrappers:
                self._wrappers[name] = PersistentCollectionWrapper(attr, self._db)
            return self._wrappers[name]
        return attr

    def list_collection_names(self, *args, **kwargs):
        return self._db.list_collection_names(*args, **kwargs)

    def command(self, *args, **kwargs):
        # command is sometimes not supported on mongomock, handle gracefully or pass to db
        try:
            return self._db.command(*args, **kwargs)
        except Exception:
            # return dummy object if stats fails
            if args and args[0] == "dbstats":
                return {
                    "objects": sum(self._db[c].count_documents({}) for c in self._db.list_collection_names()),
                    "avgObjSize": 100,
                    "dataSize": 1024,
                    "storageSize": 1024
                }
            raise

    def __getitem__(self, name):
        item = self._db[name]
        from mongomock.collection import Collection
        if isinstance(item, Collection):
            if name not in self._wrappers:
                self._wrappers[name] = PersistentCollectionWrapper(item, self._db)
            return self._wrappers[name]
        return item


class RemoteCursorProxy:
    def __init__(self, collection_proxy, args, kwargs):
        self._collection_proxy = collection_proxy
        self._args = args
        self._kwargs = kwargs
        self._sort = None
        self._limit = None
        self._skip = None

    def sort(self, *args):
        self._sort = args
        return self

    def limit(self, limit_num):
        self._limit = limit_num
        return self

    def skip(self, skip_num):
        self._skip = skip_num
        return self

    def _execute(self):
        kwargs = self._kwargs.copy()
        if self._sort:
            kwargs["sort"] = self._sort
        if self._limit is not None:
            kwargs["limit"] = self._limit
        if self._skip is not None:
            kwargs["skip"] = self._skip
        return self._collection_proxy._call_remote("find", *self._args, **kwargs)

    def __iter__(self):
        res = self._execute()
        return iter(res)

    def __getitem__(self, index):
        res = self._execute()
        return res[index]

class RemoteCollectionProxy:
    def __init__(self, name):
        self._name = name
        self._url = "http://127.0.0.1:8000/api/v1/remote-db/query"
        from config import Config
        self._headers = {
            "X-API-Key": Config.API_KEY,
            "Content-Type": "application/json"
        }

    def _call_remote(self, operation, *args, **kwargs):
        import requests
        payload = {
            "collection": self._name,
            "operation": operation,
            "args": [serialize_doc(arg) for arg in args],
            "kwargs": {k: serialize_doc(v) for k, v in kwargs.items()}
        }
        try:
            r = requests.post(self._url, json=payload, headers=self._headers, timeout=12)
            if r.status_code == 200:
                res = r.json()
                if "result" in res:
                    return deserialize_doc(res["result"])
            raise Exception(f"Remote db query returned HTTP {r.status_code}: {r.text}")
        except Exception as e:
            print(f"[-] Remote database connection error: {e}")
            raise

    def find(self, *args, **kwargs):
        return RemoteCursorProxy(self, args, kwargs)

    def find_one(self, *args, **kwargs):
        return self._call_remote("find_one", *args, **kwargs)

    def insert_one(self, *args, **kwargs):
        res = self._call_remote("insert_one", *args, **kwargs)
        class DummyResult:
            def __init__(self, inserted_id):
                self.inserted_id = ObjectId(inserted_id) if inserted_id else None
        return DummyResult(res.get("inserted_id")) if res else None

    def update_one(self, *args, **kwargs):
        res = self._call_remote("update_one", *args, **kwargs)
        class DummyResult:
            def __init__(self, data):
                self.matched_count = data.get("matched_count", 0)
                self.modified_count = data.get("modified_count", 0)
        return DummyResult(res) if res else None

    def update_many(self, *args, **kwargs):
        return self._call_remote("update_many", *args, **kwargs)

    def delete_one(self, *args, **kwargs):
        res = self._call_remote("delete_one", *args, **kwargs)
        class DummyResult:
            def __init__(self, data):
                self.deleted_count = data.get("deleted_count", 1)
        return DummyResult(res) if res else None

    def delete_many(self, *args, **kwargs):
        return self._call_remote("delete_many", *args, **kwargs)

    def count_documents(self, *args, **kwargs):
        return self._call_remote("count_documents", *args, **kwargs)

    def distinct(self, *args, **kwargs):
        return self._call_remote("distinct", *args, **kwargs)

    def aggregate(self, *args, **kwargs):
        return self._call_remote("aggregate", *args, **kwargs)

class RemoteDatabaseProxy:
    def __init__(self):
        self._collections = {}
        self._name = "awvs"
        self._url = "http://127.0.0.1:8000/api/v1/remote-db/query"
        from config import Config
        self._headers = {
            "X-API-Key": Config.API_KEY,
            "Content-Type": "application/json"
        }

    @property
    def name(self):
        return self._name

    def _call_remote_db(self, operation, *args, **kwargs):
        import requests
        payload = {
            "collection": "__database__",
            "operation": operation,
            "args": [serialize_doc(arg) for arg in args],
            "kwargs": {k: serialize_doc(v) for k, v in kwargs.items()}
        }
        try:
            r = requests.post(self._url, json=payload, headers=self._headers, timeout=12)
            if r.status_code == 200:
                res = r.json()
                if "result" in res:
                    return deserialize_doc(res["result"])
            raise Exception(f"Remote db query returned HTTP {r.status_code}: {r.text}")
        except Exception as e:
            print(f"[-] Remote database connection error: {e}")
            raise

    def list_collection_names(self, *args, **kwargs):
        return self._call_remote_db("list_collection_names", *args, **kwargs)

    def command(self, *args, **kwargs):
        return self._call_remote_db("command", *args, **kwargs)

    def __getattr__(self, name):
        if name.startswith("_"):
            return getattr(self, name)
        if name in ("list_collection_names", "command", "name"):
            return getattr(self, name)
        if name not in self._collections:
            self._collections[name] = RemoteCollectionProxy(name)
        return self._collections[name]

    def __getitem__(self, name):
        if name in ("list_collection_names", "command", "name"):
            return getattr(self, name)
        if name not in self._collections:
            self._collections[name] = RemoteCollectionProxy(name)
        return self._collections[name]


def init_db(mongo_uri):
    global client, db
    if os.environ.get("AWVS_BACKEND") == "true" or os.environ.get("AWVS_CLI") == "true":
        try:
            # Check connection with a 1.5-second timeout
            client = MongoClient(mongo_uri, serverSelectionTimeoutMS=1500)
            client.server_info()
            
            db_name = mongo_uri.split('/')[-1] if '/' in mongo_uri.split('//')[-1] else 'awvs'
            if '?' in db_name:
                db_name = db_name.split('?')[0]
            db = client[db_name]
            print(f"[+] Connected to live MongoDB at {mongo_uri} (Backend Context)")
        except Exception as e:
            print(f"[-] MongoDB live connection failed: {e}")
            print("[!] Falling back to persistent local file-based database client for this session.")
            import mongomock
            client = mongomock.MongoClient()
            raw_db = client['awvs']
            load_persistent_mock(raw_db)
            db = PersistentDatabaseWrapper(raw_db)
    else:
        print("[+] Decoupled Frontend Context: Initializing remote API Database Proxy on port 8000...")
        db = RemoteDatabaseProxy()
    return db


class User(UserMixin):
    def __init__(self, data):
        self.data = data
        self.id = str(data["_id"])
        self.username = data["username"]
        self.password_hash = data["password_hash"]
        self.role = data.get("role", "analyst")
        self.email = data.get("email")
        self.created_at = data.get("created_at", datetime.utcnow())
        self.last_login = data.get("last_login")

    @property
    def is_active(self):
        return self.data.get("is_active", True)

    @property
    def user_id(self):
        return self.id

    def get_id(self):
        return self.id

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @classmethod
    def get(cls, user_id):
        if not user_id:
            return None
        try:
            user_data = db.users.find_one({"_id": ObjectId(user_id)})
            if user_data:
                return cls(user_data)
        except Exception:
            pass
        return None

    @classmethod
    def find_by_username(cls, username):
        user_data = db.users.find_one({"username": username})
        if user_data:
            return cls(user_data)
        return None

    @classmethod
    def create(cls, username, password, role="analyst", email=None):
        hashed_password = generate_password_hash(password)
        user_doc = {
            "username": username,
            "password_hash": hashed_password,
            "role": role,
            "email": email,
            "is_active": True,
            "created_at": datetime.utcnow(),
            "last_login": None
        }
        res = db.users.insert_one(user_doc)
        user_doc["_id"] = res.inserted_id
        return cls(user_doc)

    @property
    def scans(self):
        cursor = db.scans.find({"user_id": ObjectId(self.id)})
        return [Scan(s) for s in cursor]

# ─── SCAN ─────────────────────────────────────────────────────────────────────
class Scan:
    def __init__(self, data):
        self.data = data
        self.scan_id = str(data["_id"])
        self.user_id = str(data["user_id"])
        self.target_url = data["target_url"]
        self.scope = data.get("scope")
        self.status = data.get("status", "pending")
        self.start_time = data.get("start_time")
        self.end_time = data.get("end_time")
        self.check_xss = data.get("check_xss", True)
        self.check_sqli = data.get("check_sqli", True)
        self.check_csrf = data.get("check_csrf", True)
        self.check_headers = data.get("check_headers", True)
        self.check_redirect = data.get("check_redirect", True)
        self.enable_recon = data.get("enable_recon", True)
        self.check_advanced = data.get("check_advanced", True)
        self.risk_score = data.get("risk_score", 0.0)
        self.risk_level = data.get("risk_level", "Unknown")
        self.ip_address = data.get("ip_address")
        self.ip_version = data.get("ip_version")
        self.hosting_country = data.get("hosting_country")
        self.hosting_isp = data.get("hosting_isp")
        self.hosting_org = data.get("hosting_org")
        self.asn = data.get("asn")

        self.recon_results = data.get("recon_results", [])
        self.crawled_pages = data.get("crawled_pages", [])
        self.vulnerabilities = [Vulnerability(v, self) for v in data.get("vulnerabilities", [])]
        self.notes = data.get("notes", [])
        self.reports = [Report(r, self) for r in data.get("reports", [])]

    @property
    def owner(self):
        return User.get(self.user_id)

    @property
    def duration_seconds(self):
        if self.start_time and self.end_time:
            return int((self.end_time - self.start_time).total_seconds())
        return None

    @property
    def vuln_count(self):
        return len(self.vulnerabilities)

    @property
    def critical_count(self):
        return sum(1 for v in self.vulnerabilities if v.severity == "Critical")

    @property
    def high_count(self):
        return sum(1 for v in self.vulnerabilities if v.severity == "High")

    @property
    def medium_count(self):
        return sum(1 for v in self.vulnerabilities if v.severity == "Medium")

    @property
    def low_count(self):
        return sum(1 for v in self.vulnerabilities if v.severity == "Low")

    @property
    def info_count(self):
        return sum(1 for v in self.vulnerabilities if v.severity == "Info")

    @classmethod
    def get(cls, scan_id):
        try:
            data = db.scans.find_one({"_id": ObjectId(scan_id)})
            if data:
                return cls(data)
        except Exception:
            pass
        return None

# ─── VULNERABILITY ────────────────────────────────────────────────────────────
class Vulnerability:
    def __init__(self, data, scan_obj=None):
        self.data = data
        self.scan_obj = scan_obj
        self.vuln_id = data.get("vuln_id")
        self.vuln_type = data.get("vuln_type")
        self.severity = data.get("severity")
        self.description = data.get("description")
        self.evidence = data.get("evidence")
        self.url = data.get("url")
        self.parameter = data.get("parameter")
        self.payload = data.get("payload")
        self.remediation = data.get("remediation")
        self.cvss_score = data.get("cvss_score", 0.0)
        self.cwe_id = data.get("cwe_id", "")
        self.owasp_category = data.get("owasp_category", "")
        self.false_positive = data.get("false_positive", False)
        self.analyst_note = data.get("analyst_note", "")
        self.detected_at = data.get("detected_at", datetime.utcnow())

    def to_dict(self):
        return {
            "vuln_id": self.vuln_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "false_positive": self.false_positive,
            "analyst_note": self.analyst_note,
        }

# ─── REPORT ───────────────────────────────────────────────────────────────────
class Report:
    def __init__(self, data, scan_obj=None):
        self.data = data
        self.scan_obj = scan_obj
        self.report_id = data.get("report_id")
        self.file_path = data.get("file_path")
        self.format = data.get("format")
        self.generated_at = data.get("generated_at", datetime.utcnow())
