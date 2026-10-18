# run.py
"""
run.py — Automated Platform Launcher & Orchestrator
"""
import os
import sys
import subprocess
import time
import socket
import webbrowser

def free_port(port):
    """Free a TCP port by finding its owning process and killing it."""
    if sys.platform == "win32":
        try:
            # Run netstat to find the PID using port
            res = subprocess.run("netstat -ano", shell=True, capture_output=True, text=True)
            for line in res.stdout.strip().split("\n"):
                parts = line.strip().split()
                if len(parts) >= 5 and (parts[1].endswith(f":{port}") or parts[1].endswith(f".0.0.0:{port}")):
                    pid = parts[-1]
                    if pid.isdigit() and int(pid) != os.getpid():
                        print(f"[*] Port {port} is occupied by PID {pid}. Cleaning up...")
                        subprocess.run(f"taskkill /f /pid {pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[-] Error freeing port {port}: {e}")

def kill_process_by_name(name):
    """Kill any running processes by binary name (without extension)."""
    if sys.platform == "win32":
        subprocess.run(f"taskkill /f /im {name}.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def find_and_start_mongodb():
    """Attempt to verify MongoDB is running. If not, try to start it."""
    print("[*] Verifying MongoDB database connectivity...")
    # Check if port 27017 is listening
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", 27017))
        s.close()
        print("[+] MongoDB is already running on port 27017.")
        return True
    except Exception:
        s.close()
        print("[-] MongoDB is not running on port 27017.")

    # Try to start MongoDB Windows Service
    if sys.platform == "win32":
        print("[*] Attempting to start MongoDB service...")
        res = subprocess.run("net start MongoDB", shell=True, capture_output=True, text=True)
        if "started successfully" in res.stdout.lower() or res.returncode == 0:
            print("[+] MongoDB service started successfully.")
            return True

    # Search for mongod.exe in Program Files
    import glob
    paths = glob.glob("C:\\Program Files\\MongoDB\\Server\\*\\bin\\mongod.exe")
    if paths:
        mongod_path = paths[0]
        print(f"[*] Found manual MongoDB installation at: {mongod_path}")
        # Verify default DB directory
        db_dir = "C:\\data\\db"
        if not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir)
                print(f"[+] Created manual DB directory: {db_dir}")
            except Exception as e:
                print(f"[-] Could not create DB directory: {e}")
                return False
        
        # Start mongod in background
        try:
            print("[*] Launching MongoDB server manually in the background...")
            subprocess.Popen([mongod_path, "--dbpath", db_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            return True
        except Exception as e:
            print(f"[-] Failed to launch mongod: {e}")
    
    print("[!] Warning: Unable to start MongoDB database server.")
    print("    AWVS will use 'mongomock' (in-memory mock database).")
    print("    To save scans persistently, run install_mongodb.bat as Admin.")
    return False

def start_services():
    print("=" * 60)
    print("           AWVS v4.0 Scanner Platform Launchpad")
    print("=" * 60)

    # 1. Start MongoDB
    find_and_start_mongodb()

    # 2. Port Cleanups
    print("[*] Cleaning up old port listeners...")
    free_port(5000)
    free_port(8888)
    free_port(8000)
    # Clear stale tunnel binaries
    kill_process_by_name("cloudflared")

    # 3. Start Deliberately Vulnerable Test Target App
    print("[*] Starting vulnerable target application on port 8888...")
    subprocess.Popen([sys.executable, "test_target_app.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    # 4. Start Production Web Server (Waitress)
    print("[*] Starting production Flask server on port 5000...")
    os.makedirs("instance", exist_ok=True)
    serve_log = open("instance/serve.log", "w", encoding="utf-8")
    subprocess.Popen([sys.executable, "frontend/serve.py"], stdout=serve_log, stderr=serve_log)
    
    # 4.5. Start FastAPI Backend Server on port 8000
    print("[*] Starting production FastAPI API backend on port 8000...")
    backend_log = open("instance/backend.log", "w", encoding="utf-8")
    subprocess.Popen([sys.executable, "backend/backend_server.py"], stdout=backend_log, stderr=backend_log)
    time.sleep(2.5)

    # 5. Start Cloudflare Tunnel
    tunnel_binary = os.path.join(os.path.dirname(__file__), "bin", "cloudflared.exe")
    if os.path.exists(tunnel_binary):
        print("[*] Starting Cloudflare global public tunnel...")
        tunnel_log = open("tunnel.log", "w")
        subprocess.Popen([tunnel_binary, "tunnel", "--url", "http://127.0.0.1:5000"], stdout=tunnel_log, stderr=tunnel_log)
        time.sleep(2.5)
        # Parse tunnel link from log
        try:
            with open("tunnel.log", "r") as f:
                log_lines = f.read()
                import re
                urls = re.findall(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", log_lines)
                if urls:
                    print("=" * 60)
                    print("  GLOBAL PUBLIC LINK:")
                    print(f"  --> {urls[0]}")
                    print("=" * 60)
                else:
                    print("[!] Tunnel is establishing. Check tunnel.log for the global URL.")
        except Exception:
            pass
    else:
        print("[-] Warning: Cloudflare binary (bin/cloudflared.exe) not found. Global sharing disabled.")

    # 6. Auto-Open Browser to Local Portal
    local_url = "http://127.0.0.1:5000"
    print(f"[+] Opening local portal in browser: {local_url}")
    webbrowser.open(local_url)
    print("=" * 60)
    print("[+] Scanner is fully operational. Press Ctrl+C in this window to exit.")
    print("=" * 60)

    try:
        import signal
        print("[*] Supervisor running. Close this window or press Ctrl+C to stop.")
        # Keep alive indefinitely — works both in interactive terminals and
        # when launched by batch files / launchers with no TTY.
        while True:
            time.sleep(5)
    except (KeyboardInterrupt, SystemExit):
        print("\n[*] Shutting down scanner services...")
        free_port(5000)
        free_port(8888)
        free_port(8000)
        kill_process_by_name("cloudflared")
        print("[+] Goodbye!")

if __name__ == "__main__":
    start_services()
