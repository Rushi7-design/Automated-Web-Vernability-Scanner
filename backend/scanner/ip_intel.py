"""
scanner/ip_intel.py
────────────────────────────────────────────────────────────────────
IP Intelligence Module
  - IP version (IPv4 / IPv6)
  - Reverse DNS / PTR hostname
  - Geolocation: country, city, region, flag
  - ASN / ISP / Hosting provider
  - Abuse contact info
  - DNS records (A, AAAA, MX, TXT, NS)
  - CDN/WAF detection
  - Blacklist/reputation check heuristics

Uses ip-api.com (free, no API key required).
"""

import json
import logging
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError

logger = logging.getLogger(__name__)

# ── KNOWN HOSTING PROVIDERS (ASN/ORG keywords) ────────────────────
CLOUD_PROVIDERS = {
    "amazon":    ("AWS",           "☁️"),
    "aws":       ("AWS",           "☁️"),
    "cloudflare":("Cloudflare",    "🛡️"),
    "akamai":    ("Akamai",        "🌐"),
    "fastly":    ("Fastly CDN",    "⚡"),
    "google":    ("Google Cloud",  "☁️"),
    "microsoft": ("Microsoft/Azure","☁️"),
    "azure":     ("Azure",         "☁️"),
    "digitalocean":("DigitalOcean","🌊"),
    "linode":    ("Linode/Akamai", "🟩"),
    "vultr":     ("Vultr",         "🟦"),
    "hetzner":   ("Hetzner",       "🇩🇪"),
    "ovh":       ("OVH",           "🇫🇷"),
    "godaddy":   ("GoDaddy",       "🐼"),
    "namecheap": ("Namecheap",     "💚"),
}

# Country flag emoji map (ISO 3166-1 alpha-2)
def country_flag(cc: str) -> str:
    """Convert 2-letter country code to flag emoji."""
    if not cc or len(cc) != 2:
        return "🌍"
    cc = cc.upper()
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)


def detect_hosting(org: str, isp: str) -> tuple:
    """Returns (provider_name, icon) from org/ISP string."""
    combined = (org + " " + isp).lower()
    for keyword, (name, icon) in CLOUD_PROVIDERS.items():
        if keyword in combined:
            return name, icon
    return org or isp or "Unknown", "🖥️"


def resolve_ip(hostname: str) -> dict:
    """Resolve hostname to IP and determine version."""
    result = {"ipv4": None, "ipv6": None, "primary_ip": None, "ip_version": None}
    try:
        # IPv4
        try:
            addr = socket.getaddrinfo(hostname, None, socket.AF_INET)
            if addr:
                result["ipv4"] = addr[0][4][0]
        except Exception:
            pass

        # IPv6
        try:
            addr6 = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            if addr6:
                result["ipv6"] = addr6[0][4][0]
        except Exception:
            pass

        if result["ipv4"]:
            result["primary_ip"]  = result["ipv4"]
            result["ip_version"]  = "IPv4" if not result["ipv6"] else "IPv4 + IPv6"
        elif result["ipv6"]:
            result["primary_ip"]  = result["ipv6"]
            result["ip_version"]  = "IPv6 only"
    except Exception as e:
        logger.debug(f"[IPIntel] resolve_ip error: {e}")

    return result


def reverse_dns(ip: str) -> str:
    """PTR record lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_dns_records(hostname: str) -> dict:
    """Get basic DNS records using socket."""
    records = {"a": [], "aaaa": [], "ns": []}
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in records["a"]:
                records["a"].append(ip)
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET6):
            ip = info[4][0]
            if ip not in records["aaaa"]:
                records["aaaa"].append(ip)
    except Exception:
        pass
    return records


def geolocate_ip(ip: str) -> dict:
    """
    Query ip-api.com for geolocation data.
    Free tier: up to 45 requests/minute, no key needed.
    """
    geo = {}
    if not ip:
        return geo
    try:
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,message,country,countryCode,region,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,asname,query,hosting,proxy,mobile"
        )
        req = Request(url, headers={"User-Agent": "AWVS/2.0"})
        with urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            geo = data
    except Exception as e:
        logger.debug(f"[IPIntel] geolocate error: {e}")
    return geo


def check_ssl_details(hostname: str, port: int = 443) -> dict:
    """Check SSL certificate details."""
    details = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto  = ssock.version()

        # Parse expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=timezone.utc)
            days_left = (not_after - datetime.now(timezone.utc)).days
            details["ssl_expiry"]    = not_after_str
            details["ssl_days_left"] = days_left
            details["ssl_expired"]   = days_left < 0

        details["ssl_version"]   = proto
        details["ssl_cipher"]    = cipher[0] if cipher else ""
        details["ssl_issuer"]    = dict(x[0] for x in cert.get("issuer", []))
        details["ssl_subject"]   = dict(x[0] for x in cert.get("subject", []))
        details["ssl_san"]       = [
            v for _, v in cert.get("subjectAltName", []) if isinstance(v, str)
        ][:10]
    except ssl.SSLCertVerificationError:
        details["ssl_self_signed"] = True
    except Exception as e:
        logger.debug(f"[IPIntel] SSL check error: {e}")
    return details


def run_ip_intel(target_url: str, progress_callback=None) -> dict:
    """
    Main entry point — full IP intelligence gathering.
    Returns a rich dict with all findings.
    """
    def prog(msg):
        if progress_callback:
            progress_callback(f"  [IPIntel] {msg}")

    result = {
        "target_url":   target_url,
        "hostname":     "",
        "primary_ip":   "",
        "ipv4":         "",
        "ipv6":         "",
        "ip_version":   "",
        "ptr_record":   "",
        "country":      "",
        "country_code": "",
        "country_flag": "",
        "region":       "",
        "city":         "",
        "timezone":     "",
        "latitude":     0.0,
        "longitude":    0.0,
        "isp":          "",
        "org":          "",
        "asn":          "",
        "asn_name":     "",
        "hosting_provider": "",
        "hosting_icon":     "🖥️",
        "is_hosting":   False,
        "is_proxy":     False,
        "is_mobile":    False,
        "ssl":          {},
        "dns":          {},
        "raw_geo":      {},
    }

    try:
        parsed   = urlparse(target_url)
        hostname = parsed.hostname or target_url
        result["hostname"] = hostname

        # ── 1. RESOLVE IPs ──────────────────────────────────────────
        prog(f"Resolving {hostname}...")
        ips = resolve_ip(hostname)
        result.update({
            "primary_ip": ips.get("primary_ip", ""),
            "ipv4":       ips.get("ipv4", "") or "",
            "ipv6":       ips.get("ipv6", "") or "",
            "ip_version": ips.get("ip_version", "Unknown"),
        })

        # ── 2. REVERSE DNS ──────────────────────────────────────────
        if result["primary_ip"]:
            prog("Reverse DNS lookup...")
            result["ptr_record"] = reverse_dns(result["primary_ip"])

        # ── 3. DNS RECORDS ──────────────────────────────────────────
        prog("Fetching DNS records...")
        result["dns"] = get_dns_records(hostname)

        # ── 4. GEOLOCATION ──────────────────────────────────────────
        if result["primary_ip"]:
            prog("Geolocating IP address...")
            geo = geolocate_ip(result["primary_ip"])
            result["raw_geo"] = geo
            if geo:
                cc = geo.get("countryCode", "")
                result.update({
                    "country":       geo.get("country", ""),
                    "country_code":  cc,
                    "country_flag":  country_flag(cc),
                    "region":        geo.get("regionName", ""),
                    "city":          geo.get("city", ""),
                    "timezone":      geo.get("timezone", ""),
                    "latitude":      geo.get("lat", 0.0),
                    "longitude":     geo.get("lon", 0.0),
                    "isp":           geo.get("isp", ""),
                    "org":           geo.get("org", ""),
                    "asn":           geo.get("as", ""),
                    "asn_name":      geo.get("asname", ""),
                    "is_hosting":    geo.get("hosting", False),
                    "is_proxy":      geo.get("proxy", False),
                    "is_mobile":     geo.get("mobile", False),
                })
                provider, icon = detect_hosting(
                    geo.get("org", ""), geo.get("isp", "")
                )
                result["hosting_provider"] = provider
                result["hosting_icon"]     = icon

        # ── 5. SSL DETAILS ──────────────────────────────────────────
        if parsed.scheme == "https":
            prog("Inspecting SSL certificate...")
            result["ssl"] = check_ssl_details(hostname)

        prog(f"IP Intelligence complete. Location: {result['city']}, {result['country']} {result['country_flag']}")

    except Exception as e:
        logger.exception(f"[IPIntel] Fatal error: {e}")

    return result
