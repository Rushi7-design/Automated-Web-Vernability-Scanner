# setup.py
"""
setup.py — Automated Dependency Installer & Verification Script
"""
import sys
import subprocess
import os

def check_pip_install():
    print("[*] Installing scanner dependencies from requirements.txt...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        print("[+] Dependencies installed successfully.")
    except Exception as e:
        print(f"[-] Error installing dependencies: {e}")

def test_db_connection():
    print("[*] Testing database connectivity...")
    try:
        from pymongo import MongoClient
        import os
        mongo_uri = "mongodb://localhost:27017/awvs"
        # Try to parse from .env if exists
        if os.path.exists(".env"):
            with open(".env", "r") as f:
                for line in f:
                    if line.startswith("MONGO_URI="):
                        mongo_uri = line.split("=", 1)[1].strip()
        
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
        client.admin.command('ping')
        print(f"[+] Successfully connected to MongoDB database at: {mongo_uri}")
        return True
    except Exception as e:
        print("[-] Warning: Failed to connect to MongoDB server.")
        print("    The scanner will run using an IN-MEMORY FALLBACK (mongomock).")
        print("    To save scan configurations persistently, install MongoDB Server.")
        print("    TIP: You can double-click install_mongodb.bat to install it automatically!")
        return False

def main():
    print("=" * 60)
    print("           AWVS v4.0 Environment Installer & Setup")
    print("=" * 60)
    check_pip_install()
    test_db_connection()
    print("[+] Setup verification complete. You can now launch the scanner.")
    print("=" * 60)

if __name__ == "__main__":
    main()
