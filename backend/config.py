import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Flask core
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

    # Database
    MONGO_URI = os.environ.get(
        "MONGO_URI", "mongodb://localhost:27017/awvs"
    )

    # Crawler settings
    MAX_CRAWL_DEPTH = int(os.environ.get("MAX_CRAWL_DEPTH", 3))
    MAX_CRAWL_PAGES = int(os.environ.get("MAX_CRAWL_PAGES", 100))
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", 10))

    # Reports
    REPORTS_DIR = os.path.join(BASE_DIR, os.environ.get("REPORTS_DIR", "reports"))

    # Default ports to check during recon
    DEFAULT_SCAN_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 8888]

    # API Security
    API_KEY = os.environ.get("AWVS_API_KEY", "awvs_secret_api_key_2026")

    # Session Cookie Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

