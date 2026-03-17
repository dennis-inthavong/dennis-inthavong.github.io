#!/usr/bin/env python3
"""
network_scanner.py — Home Lab Network Scanner
Dennis Inthavong | NAIT IT Systems Administration

Scans a network range for live hosts and resolves their hostnames.
Only use on networks you own or have explicit permission to scan.

Usage:
    python3 network_scanner.py                      # scans default gateway subnet
    python3 network_scanner.py 192.168.1.0/24       # scans a specific subnet
    python3 network_scanner.py 192.168.1.1           # scans a single host

Requirements:
    pip install scapy --break-system-packages
"""

import sys
import socket
import ipaddress
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- try importing scapy, fall back to ICMP via socket if unavailable ---
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import subprocess
import platform


# ── COLOURS ────────────────────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    DIM    = "\033[2m"


# ── BANNER ─────────────────────────────────────────────────────────────────────
def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════╗
║         Home Lab Network Scanner             ║
║         Dennis Inthavong — NAIT IT           ║
╚══════════════════════════════════════════════╝{C.RESET}
{C.YELLOW}  ⚠  Only scan networks you own or have permission to scan.{C.RESET}
""")


# ── GET DEFAULT GATEWAY SUBNET ─────────────────────────────────────────────────
def get_default_subnet():
    """Try to detect the local machine's subnet automatically."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # assume /24 subnet
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


# ── HOSTNAME RESOLUTION ────────────────────────────────────────────────────────
def resolve_hostname(ip):
    """Reverse DNS lookup — returns hostname or empty string if unresolvable."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


# ── PING (fallback when Scapy not available) ───────────────────────────────────
def ping_host(ip):
    """Returns True if the host responds to a ping."""
    system = platform.system().lower()
    flag = "-n" if system == "windows" else "-c"
    timeout_flag = "-w" if system == "windows" else "-W"
    try:
        result = subprocess.run(
            ["ping", flag, "1", timeout_flag, "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        return result.returncode == 0
    except Exception:
        return False


# ── ARP SCAN (Scapy — more reliable on local network) ─────────────────────────
def arp_scan(subnet):
    """
    Uses ARP requests to discover live hosts on the local subnet.
    ARP only works on the local network segment — won't cross routers.
    Returns list of dicts: {ip, mac}
    """
    print(f"{C.DIM}  Running ARP scan (Scapy)...{C.RESET}")
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    try:
        answered, _ = srp(packet, timeout=2, verbose=False)
    except PermissionError:
        print(f"{C.RED}  ARP scan requires root/admin privileges. Falling back to ping scan.{C.RESET}")
        return None

    results = []
    for _, received in answered:
        results.append({
            "ip":  received.psrc,
            "mac": received.hwsrc
        })
    return results


# ── PING SCAN (fallback) ───────────────────────────────────────────────────────
def ping_scan(subnet):
    """
    Pings every host in the subnet concurrently.
    Slower than ARP but works without root privileges.
    Returns list of dicts: {ip, mac}
    """
    print(f"{C.DIM}  Running ping scan (no root required)...{C.RESET}")
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        print(f"{C.RED}  Invalid subnet: {e}{C.RESET}")
        sys.exit(1)

    hosts = list(network.hosts())
    total  = len(hosts)
    live   = []

    print(f"{C.DIM}  Scanning {total} addresses...{C.RESET}")

    def check(ip):
        if ping_host(ip):
            return {"ip": str(ip), "mac": "N/A (ping scan)"}
        return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check, ip): ip for ip in hosts}
        done = 0
        for future in as_completed(futures):
            done += 1
            result = future.result()
            if result:
                live.append(result)
            # simple progress indicator every 10%
            if done % max(1, total // 10) == 0:
                pct = int(done / total * 100)
                print(f"{C.DIM}  Progress: {pct}%{C.RESET}", end="\r")

    print(" " * 30, end="\r")  # clear progress line
    return live


# ── MAIN SCAN ──────────────────────────────────────────────────────────────────
def scan(subnet):
    banner()

    print(f"{C.BOLD}Target:{C.RESET}  {subnet}")
    print(f"{C.BOLD}Time:  {C.RESET}  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # choose scan method
    if SCAPY_AVAILABLE:
        hosts = arp_scan(subnet)
        if hosts is None:
            hosts = ping_scan(subnet)
    else:
        print(f"{C.YELLOW}  Scapy not found — using ping scan (install scapy for faster ARP scanning){C.RESET}")
        hosts = ping_scan(subnet)

    if not hosts:
        print(f"\n{C.YELLOW}  No live hosts found on {subnet}{C.RESET}")
        return

    # resolve hostnames concurrently
    print(f"\n{C.DIM}  Resolving hostnames...{C.RESET}")
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(resolve_hostname, h["ip"]): h for h in hosts}
        for future in as_completed(futures):
            host = futures[future]
            host["hostname"] = future.result()

    # sort by IP
    hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))

    # ── RESULTS TABLE ──────────────────────────────────────────────────────────
    print(f"\n{C.BOLD}{C.GREEN}  {'IP Address':<18} {'Hostname':<35} {'MAC Address'}{C.RESET}")
    print(f"  {'─'*18} {'─'*35} {'─'*20}")

    for h in hosts:
        ip       = h.get("ip", "")
        hostname = h.get("hostname") or f"{C.DIM}(no hostname){C.RESET}"
        mac      = h.get("mac", "")
        print(f"  {C.GREEN}{ip:<18}{C.RESET} {hostname:<35} {C.DIM}{mac}{C.RESET}")

    print(f"\n  {C.BOLD}Found {len(hosts)} live host(s) on {subnet}{C.RESET}\n")

    # ── SAVE RESULTS ───────────────────────────────────────────────────────────
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"scan_{timestamp}.txt"
    try:
        with open(filename, "w") as f:
            f.write(f"Network Scan Results\n")
            f.write(f"Target:  {subnet}\n")
            f.write(f"Time:    {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'─'*70}\n")
            f.write(f"{'IP Address':<18} {'Hostname':<35} {'MAC Address'}\n")
            f.write(f"{'─'*18} {'─'*35} {'─'*20}\n")
            for h in hosts:
                ip       = h.get("ip", "")
                hostname = h.get("hostname") or "(no hostname)"
                mac      = h.get("mac", "")
                f.write(f"{ip:<18} {hostname:<35} {mac}\n")
            f.write(f"\nTotal live hosts: {len(hosts)}\n")
        print(f"  {C.CYAN}Results saved to {filename}{C.RESET}\n")
    except Exception as e:
        print(f"  {C.YELLOW}Could not save results: {e}{C.RESET}\n")


# ── ENTRY POINT ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = get_default_subnet()
        print(f"No target specified — auto-detected subnet: {target}\n")

    # if a single IP is passed, wrap it as a /32
    try:
        ipaddress.ip_address(target)
        target = f"{target}/32"
    except ValueError:
        pass  # it's already a subnet

    scan(target)
