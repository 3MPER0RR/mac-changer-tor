#!/usr/bin/env python3
# mac_changer.py — MAC address spoofer with optional Tor circuit renewal
#
# Supports: Linux (ip link), macOS (ifconfig)
# Optional: Tor circuit renewal via stem or SIGHUP signal
#
# Usage:
#   mac_changer.py -i eth0 -m random
#   mac_changer.py -i en0  -m 00:11:22:33:44:55
#   mac_changer.py -i eth0 -m random --tor
#   mac_changer.py -i eth0 -m random --tor --tor-port 9051 --tor-password secret
#   mac_changer.py -i eth0 --restore
#
# Requirements:
#   pip install stem   (only if --tor is used)
#


import argparse
import os
import platform
import random
import re
import signal
import subprocess
import sys
import time

# ── constants ────────────────────────────────────────────────────────────────

VERSION      = "1.0.0"
TOR_PORT     = 9051
TOR_HOST     = "127.0.0.1"
TOR_PASSWORD = ""          # empty = no auth (cookie auth handled by stem)

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# ── platform helpers ──────────────────────────────────────────────────────────

def os_type():
    s = platform.system()
    if s == "Linux":   return "linux"
    if s == "Darwin":  return "macos"
    die(f"Unsupported OS: {s}")

def run(cmd, capture=True, check=True):
    """Run a shell command and return stdout stripped."""
    try:
        r = subprocess.run(
            cmd, shell=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True
        )
        if check and r.returncode != 0:
            die(f"Command failed [{r.returncode}]: {cmd}\n{r.stderr.strip()}")
        return r.stdout.strip() if capture else ""
    except Exception as e:
        die(f"Execution error: {e}")

def die(msg, code=1):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)

def ok(msg):
    print(f"[+] {msg}")

def info(msg):
    print(f"[*] {msg}")

def warn(msg):
    print(f"[-] {msg}")

# ── MAC utilities ─────────────────────────────────────────────────────────────

def random_mac():
    """Generate a random unicast, locally administered MAC."""
    b = [random.randint(0, 255) for _ in range(6)]
    # bit 0 of first byte = 0 → unicast
    # bit 1 of first byte = 1 → locally administered
    b[0] = (b[0] & 0xFE) | 0x02
    return ":".join(f"{x:02x}" for x in b)

def validate_mac(mac):
    if not MAC_RE.match(mac):
        die(f"Invalid MAC address format: {mac}")
    return mac.lower()

def get_current_mac(iface):
    sys = os_type()
    if sys == "linux":
        out = run(f"ip link show {iface}")
        m = re.search(r"link/ether ([0-9a-f:]{17})", out)
    else:
        out = run(f"ifconfig {iface}")
        m = re.search(r"ether ([0-9a-f:]{17})", out)
    if not m:
        die(f"Could not read MAC for interface {iface}")
    return m.group(1)

def get_original_mac(iface):
    """Try to recover the burned-in MAC via ethtool (Linux) or networksetup (macOS)."""
    sys = os_type()
    if sys == "linux":
        try:
            out = run(f"ethtool -P {iface}", check=False)
            m = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", out)
            if m:
                return m.group(0).lower()
        except Exception:
            pass
    else:
        try:
            out = run(f"networksetup -getmacaddress {iface}", check=False)
            m = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", out)
            if m:
                return m.group(0).lower()
        except Exception:
            pass
    return None

# ── interface control ─────────────────────────────────────────────────────────

def iface_down(iface):
    sys = os_type()
    if sys == "linux":
        run(f"ip link set {iface} down")
    else:
        run(f"ifconfig {iface} down")

def iface_up(iface):
    sys = os_type()
    if sys == "linux":
        run(f"ip link set {iface} up")
    else:
        run(f"ifconfig {iface} up")

def set_mac_linux(iface, mac):
    run(f"ip link set {iface} down")
    run(f"ip link set {iface} address {mac}")
    run(f"ip link set {iface} up")

def set_mac_macos(iface, mac):
    run(f"ifconfig {iface} down")
    run(f"ifconfig {iface} ether {mac}")
    run(f"ifconfig {iface} up")

def set_mac(iface, mac):
    if os_type() == "linux":
        set_mac_linux(iface, mac)
    else:
        set_mac_macos(iface, mac)

# ── Tor integration ───────────────────────────────────────────────────────────

def tor_renew_circuit_stem(host, port, password):
    """Renew Tor circuit via stem controller (NEWNYM signal)."""
    try:
        from stem import Signal
        from stem.control import Controller
    except ImportError:
        die("stem not installed. Run: pip install stem")

    try:
        with Controller.from_port(address=host, port=port) as ctrl:
            if password:
                ctrl.authenticate(password=password)
            else:
                ctrl.authenticate()           # cookie auth
            ctrl.signal(Signal.NEWNYM)
            ok("Tor circuit renewed (NEWNYM signal sent)")
            time.sleep(ctrl.get_newnym_wait())
    except Exception as e:
        die(f"Tor controller error: {e}")

def tor_renew_circuit_sighup():
    """Fallback: send SIGHUP to the tor process to reload config."""
    try:
        out = run("pgrep -x tor", check=False)
        if not out:
            die("Tor process not found (pgrep -x tor returned nothing)")
        for pid in out.splitlines():
            os.kill(int(pid.strip()), signal.SIGHUP)
        ok(f"SIGHUP sent to Tor PID(s): {out.strip()}")
    except Exception as e:
        die(f"SIGHUP error: {e}")

def tor_get_exit_ip():
    """Return the current Tor exit IP by querying check.torproject.org."""
    try:
        out = run(
            "curl -sf --socks5-hostname 127.0.0.1:9050 "
            "https://check.torproject.org/api/ip",
            check=False
        )
        if out:
            import json
            d = json.loads(out)
            return d.get("IP", "unknown")
    except Exception:
        pass
    return None

def tor_renew(args):
    info("Renewing Tor circuit …")
    tor_renew_circuit_stem(
        host=args.tor_host,
        port=args.tor_port,
        password=args.tor_password
    )
    ip = tor_get_exit_ip()
    if ip:
        ok(f"New Tor exit IP: {ip}")
    else:
        warn("Could not verify new exit IP (is Tor SOCKS proxy on :9050?)")

# ── main logic ────────────────────────────────────────────────────────────────

def check_root():
    if os.geteuid() != 0:
        die("This tool requires root privileges. Run with sudo.")

def change_mac(args):
    iface = args.interface

    if args.restore:
        orig = get_original_mac(iface)
        if not orig:
            die("Could not determine original (burned-in) MAC — restore unavailable.")
        target_mac = orig
        info(f"Restoring original MAC: {target_mac}")
    elif args.mac == "random":
        target_mac = random_mac()
        info(f"Generated random MAC: {target_mac}")
    else:
        target_mac = validate_mac(args.mac)
        info(f"Setting MAC: {target_mac}")

    before = get_current_mac(iface)
    info(f"Current MAC on {iface}: {before}")

    set_mac(iface, target_mac)

    after = get_current_mac(iface)
    if after == target_mac:
        ok(f"MAC changed successfully: {before} → {after}")
    else:
        die(f"MAC change failed. Got: {after} (expected {target_mac})")

    return after

def parse_args():
    p = argparse.ArgumentParser(
        prog="mac_changer",
        description="MAC spoofer with optional Tor circuit renewal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  sudo mac_changer.py -i eth0 -m random
  sudo mac_changer.py -i en0  -m aa:bb:cc:dd:ee:ff
  sudo mac_changer.py -i eth0 -m random --tor
  sudo mac_changer.py -i eth0 --restore
        """
    )
    p.add_argument("-i", "--interface", required=True, metavar="IFACE",
                   help="Network interface (e.g. eth0, en0)")
    p.add_argument("-m", "--mac", default="random", metavar="MAC|random",
                   help="Target MAC address or 'random' (default: random)")
    p.add_argument("--restore", action="store_true",
                   help="Restore burned-in hardware MAC (Linux: ethtool, macOS: networksetup)")

    tor = p.add_argument_group("Tor options")
    tor.add_argument("--tor", action="store_true",
                     help="Renew Tor circuit after MAC change")
    tor.add_argument("--tor-host", default=TOR_HOST, metavar="HOST",
                     help=f"Tor controller host (default: {TOR_HOST})")
    tor.add_argument("--tor-port", type=int, default=TOR_PORT, metavar="PORT",
                     help=f"Tor controller port (default: {TOR_PORT})")
    tor.add_argument("--tor-password", default=TOR_PASSWORD, metavar="PASS",
                     help="Tor controller password (default: empty = cookie auth)")

    p.add_argument("-v", "--version", action="version",
                   version=f"%(prog)s {VERSION}")
    return p.parse_args()

def main():
    args = parse_args()
    check_root()
    change_mac(args)
    if args.tor:
        tor_renew(args)

if __name__ == "__main__":
    main()
