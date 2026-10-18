# serve.py
"""
serve.py — Production WSGI server using Waitress
"""
import argparse
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("awvs.server")

def get_local_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def main():
    parser = argparse.ArgumentParser(description="AWVS Production Server")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--threads", type=int, default=8, help="Number of worker threads (default: 8)")
    args = parser.parse_args()

    # Import app
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../backend")))
    sys.path.insert(0, os.path.dirname(__file__))
    from app import create_app
    app = create_app()

    local_ip = get_local_ip()
    port     = args.port

    print()
    print("  +----------------------------------------------------------+")
    print("  |   AWVS v4.0 - Automated Web Vulnerability Scanner       |")
    print("  |   Industry-Grade Security Assessment Platform            |")
    print("  +----------------------------------------------------------+")
    print(f"  |   Local URL  :  http://127.0.0.1:{port}                     |")
    print(f"  |   LAN URL    :  http://{local_ip}:{port}                     |")
    print("  |   Server     :  Waitress (production WSGI)               |")
    print(f"  |   Threads    :  {args.threads}                                        |")
    print("  +----------------------------------------------------------+")
    print()

    print(f"  >>> Starting Waitress on http://{args.host}:{port}")
    print("     Press Ctrl+C to stop\n")

    from waitress import serve
    serve(
        app,
        host=args.host,
        port=port,
        threads=args.threads,
        channel_timeout=120,
        asyncore_use_poll=True,
        ident=None,
    )

if __name__ == "__main__":
    main()
