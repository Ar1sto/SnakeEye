#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SnakeEye - Network Intelligence & Package Analysis Tool
# Author: 0mniscius & Claude Sonnet 4.6

import sys
import os
import json
import socket
import struct
import time
import argparse
import ipaddress
import hashlib
import math
import re
import threading
from datetime import datetime
from collections import defaultdict, Counter
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

# ─────────────────────────────────────────────
#  DEPENDENCY CHECK & GRACEFUL IMPORT
# ─────────────────────────────────────────────

MISSING_DEPS = []

# ---- Suppress WinPcap deprecation warning and all scapy startup noise ----
import warnings, logging, io as _io
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

# Redirect stderr so scapy print()-based warnings are swallowed
_stderr_saved = sys.stderr
sys.stderr = _io.StringIO()

try:
    # Inject Npcap path BEFORE scapy loads so it picks Npcap over WinPcap
    if sys.platform == "win32":
        _npcap_dir = r"C:\Windows\System32\Npcap"
        if os.path.isdir(_npcap_dir):
            os.environ["PATH"] = _npcap_dir + ";" + os.environ.get("PATH", "")

    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, IPv6, DNS, DNSQR, DNSRR, Raw, Ether, ARP
    from scapy.layers.tls.all import TLS, TLSClientHello
    SCAPY_AVAILABLE = True

    if sys.platform == "win32":
        _npcap_dll = os.path.join(r"C:\Windows\System32\Npcap", "wpcap.dll")
        _USING_NPCAP = os.path.isfile(_npcap_dll)
    else:
        _USING_NPCAP = None  # N/A on Linux/macOS

except ImportError:
    SCAPY_AVAILABLE = False
    _USING_NPCAP = False
    MISSING_DEPS.append("scapy")
finally:
    sys.stderr = _stderr_saved

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    C = True
except ImportError:
    MISSING_DEPS.append("colorama")
    C = False
    class _Fake:
        def __getattr__(self, _): return ""
    Fore = Back = Style = _Fake()

# ─────────────────────────────────────────────
#  COLOR PALETTE (Signal / Recon Aesthetic)
# ─────────────────────────────────────────────

R  = Fore.RED
G  = Fore.GREEN
Y  = Fore.YELLOW
B  = Fore.BLUE
M  = Fore.MAGENTA
C2 = Fore.CYAN
W  = Fore.WHITE
LR = Fore.LIGHTRED_EX
LG = Fore.LIGHTGREEN_EX
LY = Fore.LIGHTYELLOW_EX
LB = Fore.LIGHTBLUE_EX
LM = Fore.LIGHTMAGENTA_EX
LC = Fore.LIGHTCYAN_EX
LW = Fore.LIGHTWHITE_EX
DIM = Style.DIM
BRT = Style.BRIGHT
RST = Style.RESET_ALL

# ─────────────────────────────────────────────
#  KNOWN VPN / PROXY / TOR AS RANGES (partial)
# ─────────────────────────────────────────────

KNOWN_VPN_PROVIDERS = [
    "nordvpn", "expressvpn", "mullvad", "surfshark", "protonvpn",
    "cyberghost", "ipvanish", "purevpn", "hidemyass", "privatevpn",
    "windscribe", "tunnelbear", "torguard", "astrill", "vyprvpn",
    "perfect privacy", "ivpn", "airvpn", "hide.me", "zenmate",
    "hotspot shield", "avast vpn", "norton vpn", "f-secure freedome",
    "opera vpn", "betternet", "hola vpn", "touch vpn", "speedify",
    "privateinternetaccess", "pia vpn", "ovpn", "anonine",
    "digitalocean", "linode", "vultr", "choopa", "constant", "quadranet",
    "leaseweb", "ovh", "hetzner", "m247", "datacamp",
]

KNOWN_TOR_EXIT_KEYWORDS = ["tor", "exit relay", "torproject", "anonymous"]

DATACENTER_KEYWORDS = [
    "digitalocean", "amazon", "amazonaws", "google", "microsoft azure",
    "linode", "vultr", "hetzner", "ovh", "leaseweb", "choopa", "quadranet",
    "serverius", "m247", "datacamp", "packethub", "frantech", "buyvm",
    "cloudflarenet", "fastly", "akamai", "incapsula", "zscaler",
    "ibm cloud", "alibaba cloud", "tencent cloud", "huawei cloud",
]

# ─────────────────────────────────────────────
#  PROTOCOL / PORT REFERENCE
# ─────────────────────────────────────────────

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP-S", 68: "DHCP-C", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DG", 139: "NetBIOS-SS", 143: "IMAP", 161: "SNMP",
    162: "SNMP-T", 179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 500: "IKE/IPSec", 514: "Syslog",
    515: "LPD", 587: "SMTP-S", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 4444: "Meterpreter",
    4500: "IKE-NAT", 5060: "SIP", 5061: "SIP-TLS", 5432: "PostgreSQL",
    5900: "VNC", 6881: "BitTorrent", 6969: "BitTorrent-T", 7001: "WebLogic",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
    9050: "Tor-SOCKS", 9051: "Tor-Control", 9200: "Elasticsearch",
    9300: "Elasticsearch-T", 10000: "Webmin", 27017: "MongoDB",
    51820: "WireGuard",
}

SUSPICIOUS_PORTS = {4444, 1337, 31337, 12345, 54321, 6666, 6667, 8888, 9050, 9051}
TUNNEL_PORTS = {1194, 1723, 4500, 500, 51820, 8388, 1080}

TLS_VERSIONS = {
    0x0300: "SSL 3.0 ⚠️  DEPRECATED",
    0x0301: "TLS 1.0 ⚠️  DEPRECATED",
    0x0302: "TLS 1.1 ⚠️  DEPRECATED",
    0x0303: "TLS 1.2 ✓",
    0x0304: "TLS 1.3 ✓ SECURE",
}

# ─────────────────────────────────────────────
#  ANIMATION & UI HELPERS
# ─────────────────────────────────────────────

SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
SNAKE_FRAMES   = [">=>", " >=>", "  >=>", "   >=>", "    >=>", "   >=>", "  >=>", " >=>"]

def animate_spinner(label, duration=1.5, color=LC):
    frames = SPINNER_FRAMES
    end = time.time() + duration
    i = 0
    while time.time() < end:
        sys.stdout.write(f"\r{color}{frames[i % len(frames)]} {label}{RST}   ")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write(f"\r{LG}✔ {label}{RST}          \n")
    sys.stdout.flush()

def animate_snake(label, duration=1.0):
    end = time.time() + duration
    i = 0
    while time.time() < end:
        frame = SNAKE_FRAMES[i % len(SNAKE_FRAMES)]
        sys.stdout.write(f"\r{LG}{frame}{RST} {LY}{label}{RST}   ")
        sys.stdout.flush()
        time.sleep(0.12)
        i += 1
    sys.stdout.write(f"\r{LG}✔ {label} — DONE{RST}          \n")
    sys.stdout.flush()

def progress_bar(label, steps=30, color=LG, delay=0.04):
    sys.stdout.write(f"\n{LW}{label}{RST}\n")
    for i in range(steps + 1):
        pct = i / steps
        filled = int(pct * 30)
        bar = f"{color}{'█' * filled}{DIM}{'░' * (30 - filled)}{RST}"
        sys.stdout.write(f"\r  [{bar}] {LY}{int(pct*100):3d}%{RST}")
        sys.stdout.flush()
        time.sleep(delay)
    print()

def section(title, color=LM, width=78):
    line = "─" * width
    print(f"\n{color}{line}")
    pad = (width - len(title) - 4) // 2
    print(f"{'─' * pad}[ {BRT}{title}{RST}{color} ]{'─' * (width - pad - len(title) - 4)}")
    print(f"{line}{RST}")

def row(key, val, kw=28, color_v=LW, color_k=LC):
    print(f"  {color_k}{key:<{kw}}{RST}{color_v}{val}{RST}")

def alert(msg, level="INFO"):
    icons = {"INFO": f"{LC}ℹ", "WARN": f"{LY}⚠", "CRIT": f"{LR}✖", "OK": f"{LG}✔", "HUNT": f"{LM}⊕"}
    icon = icons.get(level, "·")
    print(f"  {icon} {msg}{RST}")

def banner():
    B1,T1,T2,SB = LG,LC,LG,LM
    e = " "*78
    print()
    print(B1+"\u2554"+"\u2550"*78+"\u2557"+RST)
    print(B1+"\u2551"+RST+e+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T1+'  ██████╗███╗   ██╗ █████╗ ██╗  ██╗███████╗███████╗██╗   ██╗███████╗          '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T1+'  ██╔════╝████╗  ██║██╔══██╗██║ ██╔╝██╔════╝██╔════╝╚██╗ ██╔╝██╔════╝         '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T1+'  ███████╗██╔██╗ ██║███████║█████╔╝ █████╗  █████╗   ╚████╔╝ █████╗           '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T1+'  ╚════██║██║╚██╗██║██╔══██║██╔═██╗ ██╔══╝  ██╔══╝    ╚██╔╝  ██╔══╝           '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T1+'  ███████║██║ ╚████║██║  ██║██║  ██╗███████╗███████╗   ██║   ███████╗         '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T1+'  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚══════╝         '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+e+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T2+'   █████╗ ███╗   ██╗ █████╗ ██║  ██╗   ██╗███████╗███████╗██████╗             '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T2+'   ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗           '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T2+'   ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝           '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T2+'   ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗           '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T2+'   ██║  ██║██║ ╚████║██║  ██║██████╗██║   ██████╗███████╗██║  ██║             '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+T2+'   ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝╚═╝   ╚═════╝╚══════╝╚═╝  ╚═╝             '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+e+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+e+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+SB+'                  [ NETWORK INTELLIGENCE & THREAT ANALYSIS ]                  '+RST+B1+"\u2551"+RST)
    print(B1+"\u2551"+RST+DIM+'                       v2.0 | SnakeEye Research Edition                       '+RST+B1+"\u2551"+RST)
    print(B1+"\u255a"+"\u2550"*78+"\u255d"+RST)
    print()

def classify_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        flags = []
        if ip.is_private:       flags.append("PRIVATE")
        if ip.is_loopback:      flags.append("LOOPBACK")
        if ip.is_multicast:     flags.append("MULTICAST")
        if ip.is_reserved:      flags.append("RESERVED")
        if ip.is_link_local:    flags.append("LINK-LOCAL")
        if ip.is_global:        flags.append("GLOBAL")
        if ip.version == 6:     flags.append("IPv6")
        else:                   flags.append("IPv4")
        return flags
    except ValueError:
        return ["INVALID"]

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"

def geoip_lookup(ip):
    """Multi-source GeoIP via free APIs."""
    sources = [
        f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting,query",
        f"https://ipinfo.io/{ip}/json",
    ]
    for url in sources:
        try:
            req = Request(url, headers={"User-Agent": "SnakeEye-Analyzer/2.0"})
            with urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
                return data, url
        except Exception:
            continue
    return {}, "offline"

def check_abuseipdb(ip):
    """Query AbuseIPDB (no key needed for basic check via alternative)."""
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        # Public endpoint — will fail without key but we handle gracefully
        req = Request(url, headers={"User-Agent": "SnakeEye/2.0", "Accept": "application/json"})
        with urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None

def check_tor_exit(ip):
    """Check if IP is a known Tor exit node via check.torproject.org."""
    try:
        # Reverse the IP octets for the DNS query format
        rev = ".".join(reversed(ip.split(".")))
        query = f"{rev}.dnsel.torproject.org"
        try:
            socket.gethostbyname(query)
            return True
        except socket.gaierror:
            return False
    except Exception:
        return False

def shodan_free_check(ip):
    """Basic banner grab for common ports."""
    open_ports = []
    test_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 9050]
    for port in test_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports

def detect_vpn_proxy(geo_data):
    """Heuristic VPN/proxy detection."""
    signals = []
    score = 0

    isp = (geo_data.get("isp") or geo_data.get("org") or "").lower()
    org = (geo_data.get("org") or "").lower()
    asname = (geo_data.get("asname") or "").lower()
    combined = f"{isp} {org} {asname}"

    if geo_data.get("proxy") is True:
        signals.append("API flagged as PROXY/VPN")
        score += 40
    if geo_data.get("hosting") is True:
        signals.append("Hosting/Datacenter IP")
        score += 20

    for kw in KNOWN_VPN_PROVIDERS:
        if kw in combined:
            signals.append(f"Matches VPN provider: '{kw}'")
            score += 35

    for kw in DATACENTER_KEYWORDS:
        if kw in combined:
            signals.append(f"Datacenter/Cloud provider: '{kw}'")
            score += 15

    for kw in KNOWN_TOR_EXIT_KEYWORDS:
        if kw in combined:
            signals.append(f"Tor-related keyword: '{kw}'")
            score += 30

    return min(score, 100), signals

def analyze_ip(ip_str, port_scan=False):
    section(f"IP ANALYSIS  ▸  {ip_str}", color=LG)

    # Classification
    flags = classify_ip(ip_str)
    animate_spinner("Classifying IP space", 0.6)
    row("IP Address", ip_str, color_v=LY)
    row("Type", " | ".join(flags), color_v=LC)

    # Reverse DNS
    animate_spinner("Resolving reverse DNS", 0.8)
    rdns = reverse_dns(ip_str)
    row("Reverse DNS", rdns)

    is_private = "PRIVATE" in flags or "LOOPBACK" in flags
    if is_private:
        alert(f"Private/reserved IP — skipping external lookups", "WARN")
        return

    # GeoIP
    animate_spinner("Querying GeoIP databases", 1.2)
    geo, source = geoip_lookup(ip_str)

    if geo:
        section("GEOLOCATION", color=LC, width=60)
        country = geo.get("country") or geo.get("country", "")
        country_code = geo.get("countryCode") or ""
        region = geo.get("regionName") or geo.get("region") or ""
        city = geo.get("city") or ""
        zipcode = geo.get("zip") or ""
        lat = geo.get("lat") or ""
        lon = geo.get("lon") or ""
        tz = geo.get("timezone") or ""
        isp = geo.get("isp") or ""
        org = geo.get("org") or ""
        asn = geo.get("as") or ""
        asname = geo.get("asname") or ""

        row("Country", f"{country} [{country_code}]", color_v=LY)
        row("Region / City", f"{region} / {city} {zipcode}")
        row("Coordinates", f"{lat}, {lon}" if lat else "N/A", color_v=LM)
        row("Timezone", tz)
        row("ISP", isp, color_v=LC)
        row("Organization", org, color_v=LC)
        row("ASN", asn)
        row("AS Name", asname)
        if lat and lon:
            row("Maps Link", f"https://www.google.com/maps?q={lat},{lon}", color_v=LB)
    else:
        alert("GeoIP lookup failed (offline or rate-limited)", "WARN")

    # VPN / Proxy Detection
    section("VPN / PROXY / ANONYMIZER DETECTION", color=LR, width=60)
    animate_spinner("Running anonymizer heuristics", 0.9)
    vpn_score, vpn_signals = detect_vpn_proxy(geo)

    # Tor check
    animate_spinner("Checking Tor exit node list", 1.0)
    is_tor = check_tor_exit(ip_str)
    if is_tor:
        vpn_signals.append("Confirmed Tor EXIT NODE (dnsel.torproject.org)")
        vpn_score = min(vpn_score + 50, 100)

    # Score bar
    bar_filled = int(vpn_score / 100 * 30)
    bar_color = LR if vpn_score > 60 else (LY if vpn_score > 30 else LG)
    bar = f"{bar_color}{'█' * bar_filled}{DIM}{'░' * (30 - bar_filled)}{RST}"
    verdict = "HIGH RISK" if vpn_score > 60 else ("SUSPICIOUS" if vpn_score > 30 else "CLEAN")
    verdict_color = LR if vpn_score > 60 else (LY if vpn_score > 30 else LG)
    print(f"\n  Anonymizer Score: [{bar}] {verdict_color}{vpn_score}/100 — {verdict}{RST}\n")

    for sig in vpn_signals:
        alert(sig, "CRIT" if vpn_score > 60 else "WARN")
    if is_tor:
        print(f"\n  {LR}⊛ TOR EXIT NODE CONFIRMED{RST}")
    if not vpn_signals:
        alert("No anonymizer indicators detected", "OK")

    # Port Scan
    if port_scan:
        section("PORT SCAN (active)", color=LY, width=60)
        animate_spinner("Scanning common ports (0.5s timeout)", 2.0)
        open_ports = shodan_free_check(ip_str)
        if open_ports:
            for p in open_ports:
                service = WELL_KNOWN_PORTS.get(p, "unknown")
                suspicious = "⚠ SUSPICIOUS" if p in SUSPICIOUS_PORTS else ""
                tunnel = "🔒 TUNNEL" if p in TUNNEL_PORTS else ""
                flags_str = f" {LR}{suspicious}{RST}" if suspicious else ""
                flags_str += f" {LM}{tunnel}{RST}" if tunnel else ""
                print(f"  {LG}● {LY}{p:<6}{RST}{LC}{service:<20}{RST}{flags_str}")
        else:
            alert("No open ports found (firewall or unreachable)", "INFO")

    print()

# ─────────────────────────────────────────────
#  PCAP ANALYSIS ENGINE
# ─────────────────────────────────────────────

def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

def classify_entropy(e):
    if e > 7.5:   return f"{LR}Very High (likely encrypted/compressed){RST}"
    if e > 6.0:   return f"{LY}High (possibly encrypted){RST}"
    if e > 4.0:   return f"{LC}Medium{RST}"
    return f"{LG}Low (plaintext){RST}"

def parse_tls_client_hello(payload_bytes):
    """Manual TLS ClientHello parser (fallback when Scapy TLS not available)."""
    result = {}
    try:
        if len(payload_bytes) < 5:
            return result
        content_type = payload_bytes[0]
        if content_type != 0x16:  # Handshake
            return result
        version = struct.unpack(">H", payload_bytes[1:3])[0]
        result["record_version"] = TLS_VERSIONS.get(version, f"Unknown (0x{version:04x})")

        # Handshake type
        if len(payload_bytes) < 6 or payload_bytes[5] != 0x01:
            return result
        result["handshake_type"] = "ClientHello"

        offset = 9  # skip version in handshake
        if offset + 2 > len(payload_bytes):
            return result
        ch_version = struct.unpack(">H", payload_bytes[offset:offset+2])[0]
        result["client_version"] = TLS_VERSIONS.get(ch_version, f"0x{ch_version:04x}")
        offset += 2 + 32  # version + random

        # Session ID
        if offset >= len(payload_bytes):
            return result
        sid_len = payload_bytes[offset]
        offset += 1 + sid_len

        # Cipher suites
        if offset + 2 > len(payload_bytes):
            return result
        cs_len = struct.unpack(">H", payload_bytes[offset:offset+2])[0]
        offset += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if offset + i + 2 <= len(payload_bytes):
                cs = struct.unpack(">H", payload_bytes[offset+i:offset+i+2])[0]
                ciphers.append(f"0x{cs:04x}")
        result["cipher_suites"] = ciphers[:8]  # first 8
        result["cipher_count"] = cs_len // 2
        offset += cs_len

        # SNI via extensions (simplified)
        sni = _extract_sni(payload_bytes, offset)
        if sni:
            result["sni"] = sni

    except Exception:
        pass
    return result

def _extract_sni(data, offset):
    """Extract SNI hostname from TLS extensions."""
    try:
        # Skip compression methods
        if offset >= len(data):
            return None
        comp_len = data[offset]
        offset += 1 + comp_len
        if offset + 2 > len(data):
            return None
        ext_total = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
        end = offset + ext_total
        while offset + 4 <= end and offset + 4 <= len(data):
            ext_type = struct.unpack(">H", data[offset:offset+2])[0]
            ext_len  = struct.unpack(">H", data[offset+2:offset+4])[0]
            offset += 4
            if ext_type == 0:  # SNI
                # list_len(2) + type(1) + name_len(2) + name
                if offset + 5 <= len(data):
                    name_len = struct.unpack(">H", data[offset+3:offset+5])[0]
                    if offset + 5 + name_len <= len(data):
                        return data[offset+5:offset+5+name_len].decode("ascii", errors="ignore")
            offset += ext_len
    except Exception:
        pass
    return None

def analyze_pcap(filepath, target_ip=None):
    if not SCAPY_AVAILABLE:
        alert("Scapy not installed — PCAP analysis unavailable. Install: pip install scapy", "CRIT")
        return

    section(f"PCAP ANALYSIS  ▸  {os.path.basename(filepath)}", color=LM)

    animate_snake("Loading capture file", 1.2)
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        alert(f"Failed to load PCAP: {e}", "CRIT")
        return

    total = len(packets)
    alert(f"Loaded {LY}{total}{RST} packets", "OK")
    progress_bar("Parsing packets", steps=40, delay=0.02)

    # ── Statistics Collectors ──
    src_ips    = Counter()
    dst_ips    = Counter()
    protocols  = Counter()
    src_ports  = Counter()
    dst_ports  = Counter()
    dns_queries  = []
    dns_answers  = []
    http_hosts   = []
    tls_infos    = []
    tcp_flags    = Counter()
    total_bytes  = 0
    payloads     = []
    timestamps   = []
    arp_table    = {}
    icmp_types   = Counter()
    conversations = defaultdict(lambda: {"pkts": 0, "bytes": 0})

    # Filter mode
    filter_mode = target_ip is not None

    for pkt in packets:
        try:
            plen = len(pkt)
            total_bytes += plen

            if pkt.time:
                timestamps.append(float(pkt.time))

            # ARP
            if ARP in pkt:
                arp_table[pkt[ARP].psrc] = pkt[ARP].hwsrc
                protocols["ARP"] += 1
                continue

            if IP not in pkt and IPv6 not in pkt:
                continue

            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            src = ip_layer.src
            dst = ip_layer.dst

            if filter_mode and target_ip not in (src, dst):
                continue

            src_ips[src] += 1
            dst_ips[dst] += 1

            conv_key = tuple(sorted([f"{src}", f"{dst}"]))
            conversations[conv_key]["pkts"]  += 1
            conversations[conv_key]["bytes"] += plen

            # Protocol
            if TCP in pkt:
                protocols["TCP"] += 1
                tcp = pkt[TCP]
                src_ports[tcp.sport] += 1
                dst_ports[tcp.dport] += 1
                # Flags
                flags = tcp.flags
                if flags & 0x02: tcp_flags["SYN"] += 1
                if flags & 0x10: tcp_flags["ACK"] += 1
                if flags & 0x01: tcp_flags["FIN"] += 1
                if flags & 0x04: tcp_flags["RST"] += 1
                if flags & 0x08: tcp_flags["PSH"] += 1
                if flags & 0x20: tcp_flags["URG"] += 1

                # TLS detection
                if Raw in pkt:
                    raw = bytes(pkt[Raw])
                    payloads.append(raw)
                    if raw and raw[0] == 0x16 and len(raw) > 5:
                        tls_info = parse_tls_client_hello(raw)
                        if tls_info:
                            tls_info["src"] = src
                            tls_info["dst"] = dst
                            tls_info["port"] = tcp.dport
                            tls_infos.append(tls_info)

                # HTTP Host header extraction
                if Raw in pkt and tcp.dport in (80, 8080, 8888):
                    try:
                        payload = pkt[Raw].load.decode("utf-8", errors="ignore")
                        for line in payload.split("\r\n"):
                            if line.lower().startswith("host:"):
                                http_hosts.append(line.split(":", 1)[1].strip())
                    except Exception:
                        pass

            elif UDP in pkt:
                protocols["UDP"] += 1
                udp = pkt[UDP]
                src_ports[udp.sport] += 1
                dst_ports[udp.dport] += 1
                if Raw in pkt:
                    payloads.append(bytes(pkt[Raw]))

            elif ICMP in pkt:
                protocols["ICMP"] += 1
                icmp_types[pkt[ICMP].type] += 1

            # DNS
            if DNS in pkt:
                protocols["DNS"] += 1
                if pkt[DNS].qd:
                    try:
                        qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        dns_queries.append(qname)
                    except Exception:
                        pass
                if pkt[DNS].an:
                    try:
                        ans = pkt[DNS].an
                        while ans:
                            try:
                                rrname = ans.rrname.decode("utf-8", errors="ignore").rstrip(".")
                                rdata = ans.rdata if hasattr(ans, "rdata") else ""
                                dns_answers.append((rrname, str(rdata)))
                            except Exception:
                                pass
                            ans = ans.payload if hasattr(ans, "payload") and DNS in ans.payload else None
                    except Exception:
                        pass

        except Exception:
            continue

    # ── Duration & Rate ──
    duration = 0
    if len(timestamps) >= 2:
        duration = timestamps[-1] - timestamps[0]
    pps = total / duration if duration > 0 else 0
    bps = total_bytes / duration if duration > 0 else 0

    # ── Entropy over all payloads ──
    all_payload_bytes = b"".join(payloads)
    overall_entropy = entropy(all_payload_bytes)

    # ═══════════════════════ SUMMARY ═══════════════════════
    section("CAPTURE SUMMARY", color=LG, width=60)
    row("Total Packets",   str(total), color_v=LY)
    row("Total Bytes",     f"{total_bytes:,} B  ({total_bytes/1024:.1f} KB  /  {total_bytes/1048576:.2f} MB)")
    row("Duration",        f"{duration:.3f}s" if duration else "N/A")
    row("Avg Packet Rate", f"{pps:.1f} pkt/s" if pps else "N/A")
    row("Avg Throughput",  f"{bps/1024:.2f} KB/s" if bps else "N/A")
    row("Payload Entropy", f"{overall_entropy:.4f} bits/byte → {classify_entropy(overall_entropy)}")

    # ── Protocol Breakdown ──
    section("PROTOCOL DISTRIBUTION", color=LC, width=60)
    for proto, cnt in protocols.most_common():
        pct = cnt / total * 100
        bar_f = int(pct / 100 * 25)
        bar = f"{LG}{'▓' * bar_f}{DIM}{'░' * (25 - bar_f)}{RST}"
        print(f"  {LC}{proto:<10}{RST} [{bar}] {LY}{cnt:>6}{RST} ({pct:5.1f}%)")

    # ── Top Talkers ──
    section("TOP SOURCE IPs", color=LY, width=60)
    for ip, cnt in src_ips.most_common(10):
        rdns_str = ""
        flag_str = ""
        ip_flags = classify_ip(ip)
        if "GLOBAL" in ip_flags:
            flag_str = f" {DIM}[global]{RST}"
        elif "PRIVATE" in ip_flags:
            flag_str = f" {DIM}[private]{RST}"
        print(f"  {LG}●{RST} {LY}{ip:<18}{RST} {LC}{cnt:>6} pkts{RST}{flag_str}")

    section("TOP DESTINATION IPs", color=LY, width=60)
    for ip, cnt in dst_ips.most_common(10):
        ip_flags = classify_ip(ip)
        flag_str = f" {DIM}[private]{RST}" if "PRIVATE" in ip_flags else ""
        print(f"  {LR}●{RST} {LY}{ip:<18}{RST} {LC}{cnt:>6} pkts{RST}{flag_str}")

    # ── Port Analysis ──
    section("TOP DESTINATION PORTS", color=LM, width=60)
    for port, cnt in dst_ports.most_common(15):
        svc = WELL_KNOWN_PORTS.get(port, "?")
        sus = f"  {LR}⚠ SUSPICIOUS{RST}" if port in SUSPICIOUS_PORTS else ""
        tun = f"  {LM}🔒 TUNNEL{RST}" if port in TUNNEL_PORTS else ""
        print(f"  {LM}{port:<8}{RST}{LC}{svc:<18}{RST}{LW}{cnt:>5} pkts{RST}{sus}{tun}")

    # ── TCP Flags ──
    if tcp_flags:
        section("TCP FLAG ANALYSIS", color=LC, width=60)
        for flag, cnt in tcp_flags.most_common():
            # Heuristic: large SYN count without ACK → possible scan
            alert_flag = " ⚠ Possible SYN SCAN/FLOOD" if flag == "SYN" and cnt > 50 and tcp_flags.get("ACK", 0) < cnt * 0.1 else ""
            print(f"  {LC}{flag:<6}{RST} {LY}{cnt:>6}{RST}{LR}{alert_flag}{RST}")

    # ── ICMP ──
    if icmp_types:
        icmp_names = {0:"Echo Reply",3:"Dest Unreachable",5:"Redirect",8:"Echo Request",11:"TTL Exceeded",30:"Traceroute"}
        section("ICMP TYPE BREAKDOWN", color=LC, width=60)
        for t, cnt in icmp_types.most_common():
            name = icmp_names.get(t, f"Type {t}")
            print(f"  {LC}{name:<25}{RST} {LY}{cnt}{RST}")

    # ── DNS Intelligence ──
    if dns_queries:
        section("DNS QUERIES (unique)", color=LY, width=60)
        unique_dns = list(dict.fromkeys(dns_queries))[:30]
        for q in unique_dns:
            suspicious_tld = any(q.endswith(x) for x in [".onion", ".i2p", ".bit"])
            flag_str = f" {LR}⚠ DARKNET TLD{RST}" if suspicious_tld else ""
            # Check for DGA-like patterns (high consonant ratio, long random-looking labels)
            label = q.split(".")[0] if "." in q else q
            consonants = sum(1 for c in label.lower() if c in "bcdfghjklmnpqrstvwxyz")
            dga_flag = ""
            if len(label) > 12 and consonants / max(len(label), 1) > 0.7:
                dga_flag = f" {LR}⊕ Possible DGA{RST}"
            print(f"  {DIM}>{RST} {LW}{q}{RST}{flag_str}{dga_flag}")

    # ── HTTP Hosts ──
    if http_hosts:
        section("HTTP HOST HEADERS (cleartext!)", color=LR, width=60)
        alert("Cleartext HTTP traffic detected — host headers visible!", "WARN")
        for h in list(dict.fromkeys(http_hosts))[:20]:
            print(f"  {LR}●{RST} {LW}{h}{RST}")

    # ── TLS Analysis ──
    if tls_infos:
        section("TLS / ENCRYPTION ANALYSIS", color=LG, width=60)
        for info in tls_infos[:15]:
            print(f"\n  {LM}▸ Connection: {LY}{info.get('src','?')}{RST} → {LY}{info.get('dst','?')}:{info.get('port','?')}{RST}")
            if "record_version"  in info: row("  Record Version",  info["record_version"], kw=22)
            if "client_version"  in info: row("  Client Version",  info["client_version"], kw=22)
            if "sni"             in info: row("  SNI Hostname",    info["sni"], kw=22, color_v=LY)
            if "cipher_count"    in info: row("  Cipher Suites",   f"{info['cipher_count']} offered", kw=22)
            if "cipher_suites"   in info: row("  First Ciphers",   " ".join(info["cipher_suites"][:5]), kw=22, color_v=DIM)
    elif protocols.get("TCP", 0) > 0:
        alert("No TLS ClientHello detected in TCP streams", "INFO")

    # ── ARP Table ──
    if arp_table:
        section("ARP TABLE (IP → MAC)", color=LC, width=60)
        for ip_addr, mac in arp_table.items():
            print(f"  {LC}{ip_addr:<18}{RST} {LW}{mac}{RST}")

    # ── Top Conversations ──
    section("TOP CONVERSATIONS", color=LM, width=60)
    top_convs = sorted(conversations.items(), key=lambda x: x[1]["bytes"], reverse=True)[:8]
    for (a, b), stats in top_convs:
        kb = stats["bytes"] / 1024
        print(f"  {LY}{a}{RST} ↔ {LY}{b}{RST}  {LC}{stats['pkts']} pkts{RST}  {LW}{kb:.1f} KB{RST}")

    # ── Anomaly / Threat Summary ──
    section("THREAT / ANOMALY INDICATORS", color=LR, width=60)
    threats_found = 0

    if tcp_flags.get("SYN", 0) > 100 and tcp_flags.get("ACK", 0) < tcp_flags.get("SYN", 0) * 0.2:
        alert("HIGH SYN count with low ACK — possible SYN SCAN or FLOOD", "CRIT"); threats_found += 1

    for port in dst_ports:
        if port in SUSPICIOUS_PORTS and dst_ports[port] > 5:
            alert(f"Traffic to suspicious port {port} ({WELL_KNOWN_PORTS.get(port,'?')})", "WARN"); threats_found += 1
        if port == 9050 or port == 9051:
            alert("Tor SOCKS proxy traffic detected (port 9050/9051)", "CRIT"); threats_found += 1
        if port in TUNNEL_PORTS and dst_ports[port] > 10:
            alert(f"Tunneling/VPN traffic on port {port} ({WELL_KNOWN_PORTS.get(port,'?')})", "WARN"); threats_found += 1

    if http_hosts:
        alert(f"Cleartext HTTP with {len(http_hosts)} distinct hosts — data exposure risk", "WARN"); threats_found += 1

    if overall_entropy > 7.2 and len(all_payload_bytes) > 1000:
        alert(f"Very high payload entropy ({overall_entropy:.2f}) — encrypted/obfuscated traffic", "WARN"); threats_found += 1

    # DGA-like DNS
    dga_count = 0
    for q in dns_queries:
        label = q.split(".")[0] if "." in q else q
        consonants = sum(1 for c in label.lower() if c in "bcdfghjklmnpqrstvwxyz")
        if len(label) > 12 and consonants / max(len(label), 1) > 0.7:
            dga_count += 1
    if dga_count > 0:
        alert(f"{dga_count} DNS query/queries match DGA heuristics", "CRIT"); threats_found += 1

    if threats_found == 0:
        alert("No critical anomalies detected in this capture", "OK")

    print(f"\n  {LW}Total threat indicators: {LR if threats_found > 0 else LG}{threats_found}{RST}\n")

# ─────────────────────────────────────────────
#  LIVE CAPTURE ENGINE
# ─────────────────────────────────────────────

# Windows: enable VT100 / ANSI escape codes in conhost / Windows Terminal
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004) on stdout
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

def _list_interfaces_windows():
    """Return list of (index, name, description, ip) on Windows via Scapy."""
    ifaces = []
    try:
        from scapy.arch.windows import get_windows_if_list
        for idx, iface in enumerate(get_windows_if_list()):
            name  = iface.get("name", "")
            desc  = iface.get("description", "")
            ips   = iface.get("ips", [])
            ip    = next((x for x in ips if ":" not in x and not x.startswith("169.")), ips[0] if ips else "")
            ifaces.append((idx, name, desc, ip))
    except Exception as e:
        alert(f"Could not enumerate interfaces: {e}", "WARN")
    return ifaces

def _list_interfaces_unix():
    """Return list of (index, name, description, ip) on Linux/macOS via Scapy."""
    ifaces = []
    try:
        from scapy.interfaces import get_if_list
        from scapy.arch import get_if_addr
        for idx, name in enumerate(get_if_list()):
            try:
                ip = get_if_addr(name)
            except Exception:
                ip = ""
            ifaces.append((idx, name, name, ip))
    except Exception as e:
        alert(f"Could not enumerate interfaces: {e}", "WARN")
    return ifaces

def list_interfaces():
    """List available network interfaces and return them."""
    if not SCAPY_AVAILABLE:
        alert("Scapy required for interface listing. Install: pip install scapy", "CRIT")
        return []
    if sys.platform == "win32":
        return _list_interfaces_windows()
    else:
        return _list_interfaces_unix()

def show_interfaces():
    """Print available interfaces in a formatted table."""
    section("AVAILABLE NETWORK INTERFACES", color=LC)
    ifaces = list_interfaces()
    if not ifaces:
        alert("No interfaces found or Scapy unavailable.", "CRIT")
        return ifaces

    print(f"  {LC}{'IDX':<5}{'NAME':<28}{'IP ADDRESS':<18}DESCRIPTION{RST}")
    print(f"  {DIM}{'-'*74}{RST}")
    for idx, name, desc, ip in ifaces:
        ip_str   = ip if ip else "—"
        desc_str = desc if desc != name else ""
        print(f"  {LY}{idx:<5}{RST}{LW}{name:<28}{RST}{LG}{ip_str:<18}{RST}{DIM}{desc_str}{RST}")
    print()
    return ifaces

def _write_pcap_global_header(f):
    """Write libpcap global header (little-endian, link type ETHERNET)."""
    # magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network
    f.write(struct.pack("<IHHiIII",
        0xa1b2c3d4,  # magic
        2, 4,        # version
        0,           # UTC offset
        0,           # timestamp accuracy
        65535,       # snaplen
        1            # LINKTYPE_ETHERNET
    ))

def _write_pcap_packet(f, raw_bytes, ts=None):
    """Write a single packet record to an open pcap file."""
    if ts is None:
        ts = time.time()
    ts_sec  = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    caplen  = len(raw_bytes)
    f.write(struct.pack("<IIII", ts_sec, ts_usec, caplen, caplen))
    f.write(raw_bytes)

class LiveCapture:
    """Thread-safe live packet capture to .pcap file via Scapy sniff()."""

    def __init__(self, iface, outfile, bpf_filter="", max_packets=0, timeout=0):
        self.iface       = iface
        self.outfile     = outfile
        self.bpf_filter  = bpf_filter
        self.max_packets = max_packets   # 0 = unlimited
        self.timeout     = timeout       # 0 = unlimited
        self._stop_flag  = threading.Event()
        self._pkt_count  = 0
        self._byte_count = 0
        self._start_time = None
        self._lock       = threading.Lock()
        self._pcap_file  = None
        self._thread     = None

    def _packet_handler(self, pkt):
        if self._stop_flag.is_set():
            return True  # signals sniff() to stop
        raw = bytes(pkt)
        ts  = float(pkt.time) if hasattr(pkt, "time") else time.time()
        with self._lock:
            _write_pcap_packet(self._pcap_file, raw, ts)
            self._pcap_file.flush()
            self._pkt_count  += 1
            self._byte_count += len(raw)
        if self.max_packets and self._pkt_count >= self.max_packets:
            self._stop_flag.set()
            return True

    def _sniff_thread(self):
        from scapy.all import sniff as scapy_sniff
        kwargs = {
            "iface":   self.iface,
            "prn":     self._packet_handler,
            "store":   False,
            "stop_filter": lambda p: self._stop_flag.is_set(),
        }
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter
        if self.timeout:
            kwargs["timeout"] = self.timeout
        try:
            scapy_sniff(**kwargs)
        except Exception as e:
            with self._lock:
                alert(f"Capture error: {e}", "CRIT")
        finally:
            self._stop_flag.set()

    def start(self):
        self._start_time = time.time()
        self._pcap_file  = open(self.outfile, "wb")
        _write_pcap_global_header(self._pcap_file)
        self._thread = threading.Thread(target=self._sniff_thread, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_flag.set()
        if self._thread:
            self._thread.join(timeout=3)
        if self._pcap_file:
            try:
                self._pcap_file.close()
            except Exception:
                pass

    def stats(self):
        elapsed = time.time() - self._start_time if self._start_time else 0
        with self._lock:
            return {
                "packets": self._pkt_count,
                "bytes":   self._byte_count,
                "elapsed": elapsed,
                "pps":     self._pkt_count / elapsed if elapsed > 0 else 0,
                "kbps":    (self._byte_count / 1024) / elapsed if elapsed > 0 else 0,
            }

    @property
    def done(self):
        return self._stop_flag.is_set()


def _live_status_loop(capture, stop_event):
    """Print a live stats line while capturing; runs in a dedicated thread."""
    spinner = ["[   ]", "[>  ]", "[>> ]", "[>>>]", "[ >>]", "[  >]"]
    i = 0
    while not stop_event.is_set():
        s = capture.stats()
        frame = spinner[i % len(spinner)]
        line = (
            f"\r  {LG}{frame}{RST}  "
            f"{LC}Packets:{RST} {LY}{s['packets']:>6}{RST}  "
            f"{LC}Bytes:{RST} {LY}{s['bytes']/1024:>8.1f} KB{RST}  "
            f"{LC}Rate:{RST} {LY}{s['pps']:>7.1f} pkt/s{RST}  "
            f"{LC}Time:{RST} {LY}{s['elapsed']:>6.1f}s{RST}  "
            f"{DIM}Press Ctrl+C to stop{RST}   "
        )
        sys.stdout.write(line)
        sys.stdout.flush()
        time.sleep(0.25)
        i += 1
    sys.stdout.write("\r" + " " * 100 + "\r")
    sys.stdout.flush()


def capture_live(iface=None, outfile=None, bpf_filter="", max_packets=0,
                 timeout=0, auto_analyze=True):
    """
    Interactive live capture. If iface is None, shows interface selection menu.
    Writes a .pcap file and optionally launches analyze_pcap() on it.
    """
    if not SCAPY_AVAILABLE:
        alert("Scapy is required for live capture. Install: pip install scapy", "CRIT")
        return None

    section("LIVE PACKET CAPTURE", color=LM)

    # ── Interface selection ──
    ifaces = show_interfaces()
    if not ifaces:
        return None

    if iface is None:
        try:
            choice = input(f"  {LC}Select interface index (default 0): {RST}").strip()
            idx = int(choice) if choice else 0
            if idx < 0 or idx >= len(ifaces):
                alert(f"Invalid index {idx}", "CRIT")
                return None
            iface = ifaces[idx][1]  # name field
        except (ValueError, KeyboardInterrupt):
            alert("Cancelled.", "WARN")
            return None

    # ── Output file ──
    if outfile is None:
        ts_str  = datetime.now().strftime("%Y%m%d_%H%M%S")
        outfile = f"snakeeye_capture_{ts_str}.pcap"
        try:
            custom = input(f"  {LC}Output file [{outfile}]: {RST}").strip()
            if custom:
                outfile = custom
        except KeyboardInterrupt:
            alert("Cancelled.", "WARN")
            return None

    # ── BPF filter ──
    if not bpf_filter:
        try:
            bpf_filter = input(f"  {LC}BPF filter (leave empty for all traffic): {RST}").strip()
        except KeyboardInterrupt:
            alert("Cancelled.", "WARN")
            return None

    # ── Packet limit ──
    if max_packets == 0:
        try:
            lim = input(f"  {LC}Max packets (0 = unlimited): {RST}").strip()
            max_packets = int(lim) if lim else 0
        except (ValueError, KeyboardInterrupt):
            max_packets = 0

    # ── Timeout ──
    if timeout == 0:
        try:
            t = input(f"  {LC}Timeout in seconds (0 = unlimited): {RST}").strip()
            timeout = int(t) if t else 0
        except (ValueError, KeyboardInterrupt):
            timeout = 0

    # ── Summary before start ──
    print()
    row("Interface",   iface,                        color_v=LY)
    row("Output file", outfile,                      color_v=LW)
    row("BPF filter",  bpf_filter or "(none — all)", color_v=LC)
    row("Max packets", str(max_packets) if max_packets else "unlimited")
    row("Timeout",     f"{timeout}s" if timeout else "unlimited")
    print()

    try:
        input(f"  {LG}Press ENTER to start capture, Ctrl+C to abort...{RST}")
    except KeyboardInterrupt:
        alert("Aborted.", "WARN")
        return None

    # ── Start capture ──
    cap = LiveCapture(
        iface       = iface,
        outfile     = outfile,
        bpf_filter  = bpf_filter,
        max_packets = max_packets,
        timeout     = timeout,
    )

    print(f"\n  {LG}Capture started on interface: {LY}{iface}{RST}\n")

    stop_display = threading.Event()
    display_thread = threading.Thread(
        target=_live_status_loop,
        args=(cap, stop_display),
        daemon=True
    )

    try:
        cap.start()
        display_thread.start()

        # Block main thread until capture finishes (timeout/limit) or Ctrl+C
        while not cap.done:
            time.sleep(0.1)

    except KeyboardInterrupt:
        pass
    finally:
        cap.stop()
        stop_display.set()
        display_thread.join(timeout=2)

    # ── Final stats ──
    s = cap.stats()
    section("CAPTURE COMPLETE", color=LG, width=60)
    row("Interface",     iface,                   color_v=LY)
    row("Output file",   outfile,                 color_v=LW)
    row("Total packets", f"{s['packets']:,}",     color_v=LY)
    row("Total bytes",   f"{s['bytes']/1024:.1f} KB  ({s['bytes']/1048576:.2f} MB)")
    row("Duration",      f"{s['elapsed']:.2f}s")
    row("Avg rate",      f"{s['pps']:.1f} pkt/s  /  {s['kbps']:.1f} KB/s")

    if s["packets"] == 0:
        alert("No packets captured. Check interface name and permissions.", "WARN")
        return None

    alert(f"Saved to: {outfile}", "OK")

    # ── Optional immediate analysis ──
    if auto_analyze:
        print()
        try:
            ans = input(f"  {LG}Analyze captured file now? [Y/n]: {RST}").strip().lower()
        except KeyboardInterrupt:
            ans = "n"
        if ans in ("", "y", "yes"):
            analyze_pcap(outfile)

    return outfile

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def print_dep_warning():
    if MISSING_DEPS:
        print(f"\n{LY}[!] Missing optional dependencies: {', '.join(MISSING_DEPS)}{RST}")
        print(f"{DIM}    Install with: pip install {' '.join(MISSING_DEPS)}{RST}")
    if sys.platform == "win32":
        if _USING_NPCAP:
            print(f"  {LG}✔ Npcap detected and active{RST}")
        elif SCAPY_AVAILABLE:
            print(f"  {LY}⚠ Npcap not found — install from https://npcap.com (WinPcap is deprecated){RST}")
    print()

def main():
    banner()
    print_dep_warning()

    parser = argparse.ArgumentParser(
        description="SnakeEye Analyzer — Network Intelligence & Packet Forensics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i 8.8.8.8
  %(prog)s -i 8.8.8.8 --portscan
  %(prog)s -p capture.pcap
  %(prog)s -p capture.pcapng -i 192.168.1.100
  %(prog)s -p dump.erf --filter 203.0.113.5
  %(prog)s --capture
  %(prog)s --capture --iface eth0 --out traffic.pcap --bpf "tcp port 443"
  %(prog)s --capture --iface eth0 --count 1000 --timeout 60 --no-analyze
  %(prog)s --list-interfaces
        """
    )
    parser.add_argument("-i", "--ip",        metavar="IP",    help="Target IP address to analyze")
    parser.add_argument("-p", "--pcap",       metavar="FILE",  help="PCAP/PCAPNG/ERF capture file to analyze")
    parser.add_argument("--filter",           metavar="IP",    help="Filter PCAP analysis to specific IP")
    parser.add_argument("--portscan",         action="store_true", help="Active TCP port scan on target IP (noisy!)")
    parser.add_argument("--json",             metavar="FILE",  help="Export results to JSON file (basic)")
    parser.add_argument("--capture",          action="store_true", help="Start interactive live packet capture")
    parser.add_argument("--list-interfaces",  action="store_true", help="List available network interfaces and exit")
    parser.add_argument("--iface",            metavar="IFACE", help="Interface name or index for live capture")
    parser.add_argument("--out",              metavar="FILE",  help="Output .pcap file for live capture")
    parser.add_argument("--bpf",              metavar="FILTER",help="BPF capture filter e.g. \"tcp port 443\"")
    parser.add_argument("--count",            metavar="N",     type=int, default=0, help="Stop capture after N packets (0=unlimited)")
    parser.add_argument("--timeout",          metavar="SEC",   type=int, default=0, help="Stop capture after SEC seconds (0=unlimited)")
    parser.add_argument("--no-analyze",       action="store_true", help="Do not auto-analyze captured file")

    args = parser.parse_args()

    # --list-interfaces: enumerate and exit
    if args.list_interfaces:
        show_interfaces()
        sys.exit(0)

    if not args.ip and not args.pcap and not args.capture:
        parser.print_help()
        print(f"\n{LR}[!] Provide --ip, --pcap, or --capture{RST}\n")
        sys.exit(1)

    print(f"\n{DIM}  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  PID: {os.getpid()}{RST}")
    print(f"  {LG}{'-' * 74}{RST}")

    # --capture: live capture mode
    if args.capture:
        iface_arg = None
        if args.iface is not None:
            ifaces = list_interfaces()
            try:
                idx = int(args.iface)
                if 0 <= idx < len(ifaces):
                    iface_arg = ifaces[idx][1]
                else:
                    alert(f"Interface index {idx} out of range", "CRIT")
                    sys.exit(1)
            except ValueError:
                iface_arg = args.iface
        capture_live(
            iface        = iface_arg,
            outfile      = args.out,
            bpf_filter   = args.bpf or "",
            max_packets  = args.count,
            timeout      = args.timeout,
            auto_analyze = not args.no_analyze,
        )

    if args.ip:
        analyze_ip(args.ip, port_scan=args.portscan)

    if args.pcap:
        if not os.path.isfile(args.pcap):
            alert(f"File not found: {args.pcap}", "CRIT")
            sys.exit(1)
        filter_ip = args.filter or args.ip
        analyze_pcap(args.pcap, target_ip=filter_ip)

    # Footer
    section("ANALYSIS COMPLETE", color=LG)
    print(f"""
  {LG}▸{RST} SnakeEye Analyzer | Research Edition
  {DIM}▸ For authorized security research only
  {DIM}▸ Universität Bochum · Offensive Security{RST}

  {LG}{'─' * 74}{RST}
""")

if __name__ == "__main__":
    main()