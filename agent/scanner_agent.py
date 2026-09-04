#!/usr/bin/env python3
"""Network Asset Discovery - scanner agent.

A small, self-contained L2 scanner you run ON a machine that is directly
connected to the target LAN. It performs the actual discovery/port/fingerprint
work locally (where ARP -> MAC/vendor and nmap -O -> exact OS actually work)
and reports results back to the server over HTTPS. No SSH bridge, no remote
shells - only an API key issued on the server's Agents page.

Quick start (Linux, root for ARP + SYN):
    export SCANNER_AGENT_KEY=<key from the web UI>
    python scanner_agent.py --server http://SERVER:8000 --name "home-lan" --subnets 192.168.1.0/24

Windows/macOS work the same way (nmap needs Npcap on Windows for SYN scans;
fall back to --connect to use plain TCP connects with no extra permissions).

Flags:
    --server   base URL of the server, e.g. http://10.0.0.5:8000
    --api-key  agent API key (or SCANNER_AGENT_KEY env var)
    --name     how this agent appears in the UI
    --subnets  comma list; if omitted, agent detects its locally-attached
               IPv4 subnets and reports them (these advertise L2 coverage)
    --interval seconds between task polls (default 10)
    --once     run a single poll+heartbeat cycle then exit (for cron/SM)
    --connect  use TCP connect scans instead of SYN (no root / no Npcap)
"""
import argparse
import json
import os
import shlex
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Optional

VERSION = "0.1.0"

# Kept small by design: the server re-runs authoritative device classification
# after receiving results, so the agent only needs to parse what nmap emits.
PROBE_TIMING = {"quick": "-T4 --min-rate 500", "full": "-T4", "stealth": "-T2"}


# --------------------------------------------------------------------------- #
# HTTP helpers (stdlib only)
# --------------------------------------------------------------------------- #
class ApiClient:
    def __init__(self, server: str, api_key: str, name: str, timeout: int = 60):
        self.server = server.rstrip("/")
        self.api_key = api_key
        self.name = name
        self.timeout = timeout
        self.agent_id = "?"

    def _request(self, method: str, path: str, payload=None):
        url = f"{self.server}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Api-Key", self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:200]
            raise RuntimeError(f"HTTP {e.code}: {detail}") from e

    def heartbeat(self, subnets: List[str], capabilities: List[str], hostname: str, os: str):
        res = self._request("POST", "/api/agents/heartbeat", {
            "version": VERSION, "hostname": hostname, "os": os,
            "subnets": subnets, "capabilities": capabilities,
        })
        if res and res.get("agent_id"):
            self.agent_id = res["agent_id"]

    def claim(self) -> Optional[dict]:
        return self._request("GET", "/api/agents/tasks/next")

    def state(self, task_id: str) -> dict:
        return self._request("GET", f"/api/agents/tasks/{task_id}/state") or {}

    def log(self, task_id: str, line: str, level: str = "info"):
        try:
            self._request("POST", f"/api/agents/tasks/{task_id}/log", {"line": line[:500], "level": level})
        except Exception:
            pass

    def result(self, task_id: str, hosts, status="completed", error=None, notes=""):
        return self._request("POST", f"/api/agents/tasks/{task_id}/result", {
            "status": status, "error": error, "hosts": hosts, "notes": notes,
        })


# --------------------------------------------------------------------------- #
# Local subnet detection (advertises L2 coverage to the server)
# --------------------------------------------------------------------------- #
def local_subnets() -> List[str]:
    subs = []
    if sys.platform.startswith("linux"):
        try:
            out = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show"],
                                 capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "inet" and i + 1 < len(parts):
                        ip, _, prefix = parts[i + 1].partition("/")
                        if ip.startswith("127.") or ip.startswith("172.") or ip.startswith("169.254."):
                            continue
                        subs.append(f"{ip}/{prefix}")
        except Exception:
            pass
    if subs:
        return subs
    # Generic fallback: derive a /24 from the default-route interface IP.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        subs.append(f"{ip.rsplit('.', 1)[0]}.0/24")
    except Exception:
        pass
    return subs


def host_identity() -> (str, str):
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"
    return hostname, sys.platform


# --------------------------------------------------------------------------- #
# mDNS probing (stdlib only)
#
# Privacy features (iOS "Private Wi-Fi Address", Android MAC randomisation,
# Windows random hardware addresses) erase the burned-in OUI that drive
# `vendor` + device classification. mDNS is the last reliable, active signal:
# devices advertise service types (e.g. `_nearbypresence`=Android,
# `_companion-link`=Apple) and instance hostnames (e.g. `Android_XXXX.local`)
# on UDP 224.0.0.251:5353, which any host on the LAN can query without admin.
# --------------------------------------------------------------------------- #
MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353

# service type -> device-type hint. `_services` is the enumeration question.
MDNS_SERVICES = [
    "_services._dns-sd._udp.local",        # enumerate everything a host offers
    "_nearbypresence._tcp.local",          # Google Nearby (Android)
    "_companion-link._tcp.local",          # Apple Continuity/Handoff
    "_rdlink._tcp.local",                  # Apple Remote Desktop link
    "_airplay._tcp.local",                 # Apple AirPlay
    "_raop._tcp.local",                    # Apple audio
    "_sleep-proxy._udp.local",             # Apple sleep proxy
    "_hap._tcp.local",                     # Apple HomeKit
    "_googlecast._tcp.local",              # Google Cast / Android TV
    "_amzn-wplay._tcp.local",              # Amazon Fire/echo
    "_spotify-connect._tcp.local",         # Spotify cast
    "_sonos._tcp.local",                   # Sonos speaker
    "_meshcop._udp.local",                 # Thread border router
    "_ipp._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local",  # printers
    "_scanner._tcp.local",                 # scanner
    "_smb._tcp.local", "_adisk._tcp.local",  # file share / NAS
    "_sftp-ssh._tcp.local", "_ssh._tcp.local",  # server / workstation
    "_workstation._tcp.local", "_http._tcp.local",  # generic host / server
]

# Service -> device_type, most specific first (checked in order).
_MDNS_TYPE_HINTS = [
    ("_nearbypresence", "mobile"),                       # Android (Nearby Share)
    ("_companion-link", "mobile"),                       # Apple
    ("_rdlink", "mobile"),
    ("_airplay", "mobile"),
    ("_raop", "mobile"),
    ("_sleep-proxy", "mobile"),
    ("_ipp", "printer"),                                 # IPP printing
    ("_printer", "printer"),
    ("_pdl-datastream", "printer"),
    ("_scanner", "printer"),
    ("_adisk", "nas"),                                   # Apple time-machine / NAS
    ("_smb", "nas"),
    ("_meshcop", "network_gear"),                        # Thread border router
    ("_googlecast", "media"),                            # cast-capable display/TV
    ("_amzn-wplay", "media"),
    ("_spotify-connect", "media"),
    ("_sonos", "media"),
    ("_sftp-ssh", "server"),
    ("_ssh", "server"),
    ("_workstation", "workstation"),
    ("_hap", "iot"),                                     # HomeKit accessory
]


def _mdns_enc_name(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        if part:
            out += bytes([len(part.encode())]) + part.encode()
    return out + b"\x00"


def _mdns_build_query(names: List[str]) -> bytes:
    q = b"\x00\x00\x00\x00\x00" + bytes([len(names)]) + b"\x00\x00\x00\x00\x00\x00"
    for n in names:
        q += _mdns_enc_name(n) + b"\x00\x0c\x00\x01"
    return q


def _mdns_decode_name(msg: bytes, off: int):
    """Decode a (possibly compressed) DNS name. Returns (name, new_offset)."""
    labels = []
    cursor = off
    jumped = False
    seen = set()
    lim = len(msg)
    while True:
        if cursor >= lim:
            break
        b = msg[cursor]
        if b == 0:
            cursor += 1
            break
        if b & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", msg[cursor:cursor + 2])[0] & 0x3FFF
            cursor += 2
            if not jumped:
                off = cursor
                jumped = True
            if ptr in seen:
                break
            seen.add(ptr)
            sub, _ = _mdns_decode_name(msg, ptr)
            labels.extend(sub.split("."))
            break
        n = b
        cursor += 1
        if cursor + n > lim:
            break
        labels.append(msg[cursor:cursor + n].decode("utf-8", "replace"))
        cursor += n
    return ".".join(labels), (off if jumped else cursor)


def _mdns_parse_txt(rd: bytes) -> List[str]:
    out = []
    o = 0
    while o < len(rd):
        ln = rd[o]
        o += 1
        if o + ln <= len(rd):
            out.append(rd[o:o + ln].decode("utf-8", "replace"))
            o += ln
        else:
            break
    return out


def mdns_probe(duration: float = 20.0, interval: float = 0.6) -> dict:
    """Actively query mDNS on the local subnet and collect per-IP hints.

    mDNS responses are sparse/non-deterministic (devices answer on their own
    schedule), so the query is re-sent every `interval` seconds for the whole
    `duration` window to give every device a chance to respond. Packets that
    carry no answer records (usually the host OS echoing our own query) are
    skipped.

    Returns {ip: {"services": set(str), "hostnames": set(str), "txt": set(str)}}.
    Best-effort: any platform/socket error returns {} so a failure can never
    abort a scan."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", MDNS_PORT))
        mreq = struct.pack("4s4s", socket.inet_aton(MDNS_GROUP), socket.inet_aton("0.0.0.0"))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.settimeout(0.3)
    except Exception:
        return {}

    query = _mdns_build_query(MDNS_SERVICES)
    per_ip = {}
    end = time.time() + duration
    next_send = 0.0
    try:
        while time.time() < end:
            if time.time() >= next_send:
                try:
                    s.sendto(query, (MDNS_GROUP, MDNS_PORT))
                except Exception:
                    pass
                next_send = time.time() + interval
            try:
                data, addr = s.recvfrom(8192)
            except socket.timeout:
                continue
            except Exception:
                break
            if len(data) < 12:
                continue
            try:
                qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
            except Exception:
                continue
            if an + ar == 0:
                continue  # pure query echo from the local host OS, not a device
            info = per_ip.setdefault(addr[0], {"services": set(), "hostnames": set(), "txt": set()})
            try:
                off = 12
                for _ in range(qd):
                    _, off = _mdns_decode_name(data, off)
                    off += 4

                def _rr(msg, off):
                    name, off = _mdns_decode_name(msg, off)
                    if off + 10 > len(msg):
                        return None, off
                    rtype, _, _, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
                    off += 10
                    rd = msg[off:off + rdlen]
                    return (name, rtype, rd), off + rdlen

                for _ in range(an + ns + ar):
                    rr, off = _rr(data, off)
                    if not rr:
                        continue
                    name, rtype, rd = rr
                    nl = name.lower()
                    if rtype == 1 or rtype == 28:  # A / AAAA
                        info["hostnames"].add(name)
                    elif rtype == 12:  # PTR owner is a service name
                        info["services"].add(nl)
                    elif rtype in (33, 16):  # SRV / TXT owner = <inst>.<service>
                        # store full name; type-hint matching uses substring later
                        info["services"].add(nl)
                        if rtype == 16:
                            info["txt"].update(_mdns_parse_txt(rd))
            except Exception:
                continue
    finally:
        try:
            s.close()
        except Exception:
            pass
    return per_ip


def mdns_device_hint(info: dict) -> (Optional[str], Optional[str]):
    """Turn per-IP mDNS data into (hostname_hint, device_type_hint).

    hostname hint comes from an A/AAAA record (e.g. `Android_XXXX.local`),
    which reveals the device's mDNS hostname even when the MAC is randomised.
    Empty strings mean 'no signal' and are left unset by the caller."""
    hostname = ""
    for h in info.get("hostnames") or ():
        if h.lower().endswith(".local"):
            hostname = h[: -len(".local")]
            break
    services = info.get("services") or ()
    dev = None
    for key, kind in _MDNS_TYPE_HINTS:
        if any(key in s for s in services):
            dev = kind
            break
    return (hostname or None), dev


# --------------------------------------------------------------------------- #
# Persistent mDNS state + background sweeper
#
# mDNS responses from mobile devices are sparse and non-deterministic (a phone
# answers only when it happens to be in a responsive window), so a single 20s
# probe at scan start misses most devices. Instead the agent runs a background
# thread that re-probes mDNS continuously for its whole lifetime, accumulating
# every device it ever hears into a shared map. Scans then snapshot this map at
# start, which is far richer than one burst (and keeps filling in between scans).
# --------------------------------------------------------------------------- #
mdns_lock = threading.Lock()
_mdns_shared = {}  # ip -> {"hostname": str|None, "device_type": str|None, "services": set, "last_seen": float}


def mdns_observe(probe_duration: float = 10.0, interval: float = 0.6):
    """Run one mDNS probe cycle and fold results into the shared map.

    Prefers information that is stable across observation windows: it keeps the
    first hostname/device_type it ever learns for an IP (devices sometimes
    rotate the random suffix on their mDNS hostname between reconnects, so the
    first is no worse than any later one) while continuously adding service
    types. Reprobe every call."""
    probe = mdns_probe(duration=probe_duration, interval=interval)
    now = time.time()
    with mdns_lock:
        for ip, info in probe.items():
            hn, dev = mdns_device_hint(info)
            cur = _mdns_shared.get(ip)
            if cur is None:
                cur = _mdns_shared[ip] = {
                    "hostname": None, "device_type": None,
                    "services": set(), "last_seen": now,
                }
            cur["services"].update(info.get("services") or ())
            if hn and not cur["hostname"]:
                cur["hostname"] = hn
            if dev and not cur["device_type"]:
                cur["device_type"] = dev
            cur["last_seen"] = now


def mdns_snapshot():
    """Return a copy of the shared map in the shape execute_task consumes:
    {ip: {"hostname": str|None, "device_type": str|None}}."""
    with mdns_lock:
        return {ip: {"hostname": c["hostname"], "device_type": c["device_type"]}
                for ip, c in _mdns_shared.items()}


def _run_mdns_sweeper(probe_duration: float = 10.0, gap: float = 5.0, stop_evt=None):
    """Background thread: continuously re-probe mDNS and accumulate into the
    shared map. Runs until stop_evt is set (or forever if None)."""
    while True:
        if stop_evt and stop_evt.is_set():
            return
        try:
            mdns_observe(probe_duration, 0.6)
        except Exception:
            pass  # never let the sweeper crash the agent
        if gap > 0:
            try:
                time.sleep(gap)
            except Exception:
                return

def run_nmap(args: List[str], log_stdout=False) -> str:
    """Run nmap, returning raw output. stderr (liveness/port progress) is
    echoed; the caller decides whether stdout XML is worth keeping."""
    proc = subprocess.run(args, capture_output=True, text=True, errors="replace")
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.stdout or ""


def _fatal(msg: str):
    print(f"[agent] FATAL: {msg}", file=sys.stderr)
    sys.exit(2)


def require_nmap(cmd="nmap"):
    import shutil
    if shutil.which(cmd) is None:
        _fatal(f"'{cmd}' not found on PATH")


# --------------------------------------------------------------------------- #
# Parsers (mirror the server-side nmap XML parser)
# --------------------------------------------------------------------------- #
def _clean(v):
    return " ".join((v or "").split())


def parse_discovery(xml: str) -> List[dict]:
    """Parse an `nmap -sn -oX -` response -> [{ip, mac, vendor, state}]."""
    try:
        root = ET.fromstring(xml)
    except Exception:
        return []
    found = []
    for host_el in root.iter("host"):
        state = None
        st = host_el.find("status")
        if st is not None:
            state = st.get("state")
        ip = mac = vendor = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        if ip:
            found.append({"ip": ip, "mac": mac, "vendor": vendor, "state": state})
    return found


def parse_host_xml(xml: str) -> Optional[dict]:
    """Parse a single-host `nmap -sS/-sT -sV -O -oX -` response into the host
    shape expected by POST /api/agents/tasks/{id}/result."""
    try:
        root = ET.fromstring(xml)
    except Exception:
        return None
    host_el = next(iter(root.iter("host")), None)
    if host_el is None:
        return None

    state = "up"
    st = host_el.find("status")
    if st is not None:
        state = st.get("state", "up")

    ip = mac = vendor = None
    for addr in host_el.iter("address"):
        if addr.get("addrtype") == "ipv4":
            ip = addr.get("addr")
        elif addr.get("addrtype") == "mac":
            mac = addr.get("addr")
            vendor = addr.get("vendor")
    if not ip:
        return None

    ports = []
    for port_el in host_el.iter("port"):
        port_id = port_el.get("portid")
        proto = port_el.get("protocol", "tcp")
        state_el = port_el.find("state")
        port_state = state_el.get("state") if state_el is not None else "closed"
        if port_state != "open":
            continue
        service = version = None
        banner = ""
        scripts = []
        for elem in port_el.iter():
            if elem.tag == "service":
                service = elem.get("name")
                version = elem.get("version") or elem.get("product")
            elif elem.tag == "banner" and elem.text:
                banner = elem.text.strip()[:500]
            elif elem.tag == "script" and elem.get("output"):
                scripts.append(elem.get("output"))
        if scripts:
            combined = " || ".join(scripts)[:500]
            banner = combined if not banner else f"{banner} | {combined}"
        ports.append({
            "port": int(port_id), "protocol": proto, "state": port_state,
            "service": service, "version": version, "banner": banner or None,
        })

    host = {"ip": ip, "mac": mac, "vendor": vendor, "status": "up", "ports": ports}

    if mac:
        host["mac"] = mac
        host["vendor"] = vendor

    os_guess, os_conf = None, None
    os_el = host_el.find("os")
    if os_el is not None:
        best = None
        for osmatch in os_el.iter("osmatch"):
            acc = int(osmatch.get("accuracy", 0) or 0)
            name = _clean(osmatch.get("name"))
            if name and (best is None or acc > best[1]):
                best = (name, acc)
        if best:
            os_guess, os_conf = best
        elif os_guess is None:
            oscls = os_el.find("osclass")
            if oscls is not None:
                vendor = _clean(oscls.get("vendor"))
                family = _clean(oscls.get("osfamily"))
                gen = _clean(oscls.get("osgen"))
                os_guess = " ".join(x for x in (vendor, family, gen) if x) or None
                os_conf = int(oscls.get("accuracy", "") or 0) or None
    if os_guess:
        host["os_guess"] = os_guess
        host["os_confidence"] = os_conf
    return host


# --------------------------------------------------------------------------- #
# Scan execution
# --------------------------------------------------------------------------- #
def _root() -> bool:
    try:
        return os.geteuid() == 0
    except Exception:
        return False


class AgentStopped(Exception):
    pass


def _await_go(client: ApiClient, task_id: str) -> bool:
    """Block until the scan is neither paused nor stopped. Returns False when
    the user stopped it (agent should bail without posting a result)."""
    try:
        st = client.state(task_id) or {}
    except Exception:
        return True
    if st.get("stopped"):
        return False
    while st.get("paused"):
        try:
            st = client.state(task_id) or {}
        except Exception:
            st = {}
        if st.get("stopped"):
            return False
        time.sleep(2)
    return True


def execute_task(client: ApiClient, task: dict, use_connect: bool = False):
    task_id = task["id"]
    scan_id = task["scan_id"]
    targets = task["targets"] or []
    profile = task.get("profile") or "quick"
    port_range = task.get("port_range") or "1-10000"

    client.log(task_id, f"=== Agent scan started (scan={scan_id}, targets={', '.join(targets)}) ===")
    client.log(task_id, f"Phase 1/3: L2/ARP discovery -> live hosts + MAC/vendor", level="cmd")
    client.log(task_id, f"$ nmap -sn {' '.join(targets)} (ARP)", level="cmd")

    posted = set()
    scan_type = "-sT" if use_connect else "-sS"
    timing = PROBE_TIMING.get(profile, "-T4")

    # ---- Phase 0/3: mDNS probing (names randomized-MAC devices) ---------------
    # Privacy-randomised MACs erase the OUI that drives vendor + classification,
    # but devices still answer mDNS with service types + a hostname (e.g. an
    # Android phone advertises `_nearbypresence` and `Android_XXXX.local`).
    # The background sweeper keeps the shared map fresh continuously, so here we
    # just snapshot it (no blocking probe) — this names every device ever heard,
    # far more than a single burst, and costs little per scan.
    mdns_hints = mdns_snapshot()
    named = sum(1 for h in mdns_hints.values() if h["hostname"] or h["device_type"])
    client.log(task_id, f"Phase 0/3: {len(mdns_hints)} known mDNS device(s), {named} usable hint(s)", level="out")

    def _decorate(h: dict):
        h = dict(h)
        hint = mdns_hints.get(h.get("ip"))
        if not hint:
            return h
        if hint["hostname"] and not h.get("hostname"):
            h["hostname"] = hint["hostname"]
        if hint["device_type"] and not h.get("device_type"):
            h["device_type"] = hint["device_type"]
        return h

    # ---- Phase 1/3: ARP (L2) discovery -> live hosts + MAC/vendor -------------
    live = {}
    for t in targets:
        if not _await_go(client, task_id):
            client.log(task_id, "Scan stopped by user", level="warn")
            return
        args = [
            "nmap", "-sn", "-oX", "-", "--host-timeout", "60s",
            "--min-hostgroup", "256", t,
        ]
        xml = run_nmap(args)
        for h in parse_discovery(xml):
            if h.get("state") == "up":
                live[h["ip"]] = h

    if not live:
        client.log(task_id, "Discovery found no live hosts - reporting 0 hosts", level="warn")

    # Merge mDNS responders into the live set. A device that answered mDNS is
    # definitively up even if ARP -sn missed it (power-save radios often ignore
    # ARP pings but do answer multicast), and carrying its hint lets us name a
    # random-MAC device that would otherwise be dropped entirely.
    merged = set(mdns_hints.keys()) - set(live.keys())
    if merged:
        client.log(task_id, f"mDNS-only host(s) added: {', '.join(sorted(merged))}", level="out")
    for ip in merged:
        live[ip] = {"ip": ip, "mac": None, "vendor": None, "state": "up"}

    # Stream ARP results (IP + MAC + vendor) right away as a partial update.
    try:
        client.result(task_id, [
            _decorate({"ip": ip, "mac": m.get("mac"), "vendor": m.get("vendor"),
                       "status": "up", "ports": []})
            for ip, m in live.items()
        ], status="partial", notes="discovery")
        posted.update(live.keys())
        client.log(task_id, f"Phase 1/3 done: {len(live)} live host(s), MAC/vendor streamed", level="out")
    except Exception as e:
        client.log(task_id, f"Partial discovery post failed: {e}", level="err")

    # ---- Phase 2/3: simple port scan (no -sV/-O) -> open ports only ----------
    client.log(task_id, f"Phase 2/3: fast port scan ({scan_type}) on {len(live)} host(s)", level="cmd")
    open_ports = {}  # ip -> [portid]
    for ip in live:
        if not _await_go(client, task_id):
            client.log(task_id, "Scan stopped by user", level="warn")
            return
        args = [
            "nmap", scan_type, "-p", port_range, "--open",
            timing, "--host-timeout", "45s", "-oX", "-", str(ip),
        ]
        client.log(task_id, " ".join(args), level="cmd")
        xml = run_nmap(args)
        found = []
        try:
            root = ET.fromstring(xml)
            for port in root.findall(".//port"):
                if (port.find("state") is not None
                        and port.find("state").get("state") == "open"):
                    found.append(port.get("portid"))
        except Exception:
            pass
        open_ports[ip] = found
        client.log(task_id, f"  {ip}: {len(found)} open port(s)")

    # ---- Phase 3/3: service/OS fingerprint -----------------------------------
    client.log(task_id, f"Phase 3/3: -sV -O fingerprint (ports) / -O (OS-only for no-port hosts)", level="cmd")
    for ip, meta in live.items():
        if not _await_go(client, task_id):
            client.log(task_id, "Scan stopped by user", level="warn")
            return
        ports = open_ports.get(ip, [])
        if not ports:
            # No open ports, so -sV has nothing to probe, but -O can still
            # fingerprint the OS from the host's TCP/IP stack behaviour (works
            # on closed/filtered hosts). Attach any OS guess for richer typing.
            client.log(task_id, f"  {ip}: no open ports - running OS-only fingerprint (-O)", level="cmd")
            args = ["nmap", "-O", "--osscan-guess",
                    timing, "--host-timeout", "120s", str(ip), "-oX", "-"]
            client.log(task_id, " ".join(args), level="cmd")
            xml = run_nmap(args)
            host = parse_host_xml(xml)
            if host:
                host.setdefault("mac", meta.get("mac"))
                host.setdefault("vendor", meta.get("vendor"))
                if not host.get("ports"):
                    host["ports"] = []
                try:
                    client.result(task_id, [_decorate(host)], status="partial", notes="host")
                    posted.add(host["ip"])
                except Exception as e:
                    client.log(task_id, f"Partial host post failed: {e}", level="err")
                os_note = host.get("os_guess") or "n/a"
                client.log(task_id, f"  {ip}: OS-only fingerprint -> {os_note}")
            else:
                client.log(task_id, f"  {ip}: OS-only fingerprint returned no data")
            continue
        scripts = "--script default,http-title,http-headers,http-methods,http-server-header,http-enum,http-generator,rtsp-methods"
        args = (
            ["nmap", scan_type, "-sV", "-O", "-p", ",".join(ports), "--open",
             timing, *shlex.split(scripts), "--host-timeout", "90s", str(ip), "-oX", "-"]
        )
        client.log(task_id, " ".join(args), level="cmd")
        xml = run_nmap(args)
        host = parse_host_xml(xml)
        if host:
            host.setdefault("mac", meta.get("mac"))
            host.setdefault("vendor", meta.get("vendor"))
            try:
                client.result(task_id, [_decorate(host)], status="partial", notes="host")
                posted.add(host["ip"])
            except Exception as e:
                client.log(task_id, f"Partial host post failed: {e}", level="err")
            client.log(task_id, f"  {ip}: {len(host['ports'])} open port(s) fingerprinted")

    # ---- Finalise -------------------------------------------------------------
    remaining = [_decorate(h) for ip, h in [
        (ip, {"ip": ip, "mac": meta.get("mac"), "vendor": meta.get("vendor"),
              "status": "up", "ports": []}) for ip, meta in live.items()
    ] if ip not in posted]
    try:
        client.result(task_id, remaining, status="completed",
                      notes=f"agent={uuid.uuid4()}")
    except Exception as e:
        client.log(task_id, f"Final result post failed: {e}", level="err")
    client.log(task_id, f"=== Agent scan done: {len(live)} hosts reported ===")


def _range_to_ports_set(port_range: str) -> set:
    """Expand an nmap range ('1-10000' / '22,80,443-445') into a set of ints."""
    ports = set()
    if not port_range:
        return ports
    try:
        for part in str(port_range).replace(" ", "").split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo_s, _, hi_s = part.partition("-")
                lo, hi = int(lo_s), int(hi_s)
                ports.update(range(max(1, lo), min(65535, hi) + 1))
            else:
                p = int(part)
                if 0 < p <= 65535:
                    ports.add(p)
    except Exception:
        pass
    return ports


def _leftover_ports_spec(already: set) -> str:
    """Complement of already-scanned ports (1-65535) as an nmap range string."""
    leftover = sorted(set(range(1, 65536)) - already)
    if not leftover:
        return ""
    parts = []
    start = prev = leftover[0]
    for p in leftover[1:]:
        if p == prev + 1:
            prev = p
            continue
        parts.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = p
    parts.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(parts)


def _deep_scan_host(client: ApiClient, task_id: str, ip: str, meta: dict,
                    ports_spec: str, use_connect: bool = False,
                    profile: str = "quick"):
    """Run -sV -O + scripts on the given open ports of a host and post the
    result as a partial update so the server merges it live."""
    scan_type = "-sT" if use_connect else "-sS"
    timing = PROBE_TIMING.get(profile, "-T4")
    scripts = "--script default,http-title,http-headers,http-methods,http-server-header,http-enum,http-generator,rtsp-methods"
    args = (
        ["nmap", scan_type, "-sV", "-O", "-p", ports_spec, "--open",
         timing, *shlex.split(scripts), "--host-timeout", "90s", ip, "-oX", "-"]
    )
    client.log(task_id, " ".join(args), level="cmd")
    xml = run_nmap(args)
    host = parse_host_xml(xml)
    if not host:
        return None
    host.setdefault("mac", meta.get("mac"))
    host.setdefault("vendor", meta.get("vendor"))
    try:
        client.result(task_id, [host], status="partial", notes="host")
    except Exception as e:
        client.log(task_id, f"Partial host post failed: {e}", level="err")
    return host


def execute_reverify(client: ApiClient, task: dict, use_connect: bool = False):
    """Re-verify an already-completed scan: only re-check the previously-down
    hosts (L2 ARP) and sweep the previously-unscanned ports on the up hosts.
    Results are posted as partial updates that the server merges into the SAME
    scan row (upsert by ip / host+port, no duplicates)."""
    task_id = task["id"]
    scan_id = task["scan_id"]
    profile = task.get("profile") or "quick"
    rv = task.get("reverify") or {}
    down_ips = rv.get("down_ips") or []
    up_ips = rv.get("up_ips") or []
    already_ports = rv.get("already_ports") or "1-65535"
    # The component range(s) to sweep: complement of what was already checked.
    sweep_spec = _leftover_ports_spec(_range_to_ports_set(already_ports))

    client.log(task_id, f"=== Agent re-verify started (scan={scan_id}) ===")
    client.log(task_id, f"  down hosts to re-check: {len(down_ips)}, up hosts to sweep: {len(up_ips)}, leftover ports: {sweep_spec or 'none'}")

    # ---- Phase A: re-check previously-down hosts via L2/ARP ----
    newly_up = []
    if down_ips:
        if not _await_go(client, task_id):
            return
        client.log(task_id, f"$ nmap -sn {' '.join(down_ips)} (ARP re-check of down hosts)", level="cmd")
        args = ["nmap", "-sn", "-oX", "-", "--host-timeout", "60s", *down_ips]
        xml = run_nmap(args)
        alive = []
        for h in parse_discovery(xml):
            if h.get("state") == "up":
                alive.append(h)
        client.log(task_id, f"  {len(alive)} previously-down host(s) now responding", level="out")
        for meta in alive:
            if not _await_go(client, task_id):
                return
            client.log(task_id, f"  re-verifying now-up host {meta['ip']} (full pipeline)")
            # TCP port scan
            p_args = ["nmap", "-sT" if use_connect else "-sS", "-p", "1-10000",
                      "--open", PROBE_TIMING.get(profile, "-T4"),
                      "--host-timeout", "45s", "-oX", "-", meta["ip"]]
            pxml = run_nmap(p_args)
            found = []
            try:
                import xml.etree.ElementTree as _ET
                root = _ET.fromstring(pxml)
                for port in root.findall(".//port"):
                    if (port.find("state") is not None
                            and port.find("state").get("state") == "open"):
                        found.append(port.get("portid"))
            except Exception:
                pass
            meta.setdefault("ports", [])
            if found:
                host = _deep_scan_host(client, task_id, meta["ip"], meta,
                                       ",".join(found), use_connect, profile)
                if host:
                    newly_up.append(meta["ip"])
                    client.log(task_id, f"  {meta['ip']}: {len(host['ports'])} open port(s)")
            else:
                # no open ports on a now-up host -> just stream MAC/vendor
                try:
                    client.result(task_id, [{"ip": meta["ip"], "mac": meta.get("mac"),
                                             "vendor": meta.get("vendor"),
                                             "status": "up", "ports": []}],
                                  status="partial", notes="host")
                    newly_up.append(meta["ip"])
                except Exception as e:
                    client.log(task_id, f"Partial post failed: {e}", level="err")

    # ---- Phase B: sweep unscanned ports on the up hosts ----
    if sweep_spec and up_ips:
        if not _await_go(client, task_id):
            return
        client.log(task_id, f"Phase B: sweeping unscanned ports {sweep_spec} on {len(up_ips)} up host(s)")
        for ip in up_ips:
            if not _await_go(client, task_id):
                return
            p_args = ["nmap", "-sT" if use_connect else "-sS", "-p", sweep_spec,
                      "--open", PROBE_TIMING.get(profile, "-T4"),
                      "--host-timeout", "45s", "-oX", "-", ip]
            client.log(task_id, " ".join(p_args), level="cmd")
            pxml = run_nmap(p_args)
            found = []
            try:
                import xml.etree.ElementTree as _ET
                root = _ET.fromstring(pxml)
                for port in root.findall(".//port"):
                    if (port.find("state") is not None
                            and port.find("state").get("state") == "open"):
                        found.append(port.get("portid"))
            except Exception:
                pass
            if not found:
                client.log(task_id, f"  {ip}: no hidden open ports in leftover range")
                continue
            client.log(task_id, f"  {ip}: hidden open port(s) in leftover range: {','.join(found)}")
            _deep_scan_host(client, task_id, ip, {"mac": None, "vendor": None},
                            ",".join(found), use_connect, profile)

    # ---- Finalise ----
    try:
        client.result(task_id, [], status="completed",
                      notes=f"reverify={uuid.uuid4()}")
    except Exception as e:
        client.log(task_id, f"Final result post failed: {e}", level="err")
    client.log(task_id, f"=== Agent re-verify done: {len(newly_up)} host(s) recovered, report merged ===")


def _root() -> bool:
    try:
        return hasattr(os:=__import__("os"), "geteuid") and __import__("os").geteuid() == 0
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(description="LAN scanner agent for Network Asset Discovery")
    parser.add_argument("--server", required=True, help="server base URL, e.g. http://1.2.3.4:8000")
    parser.add_argument("--api-key", default=None, help="agent API key (or SCANNER_AGENT_KEY env)")
    parser.add_argument("--name", required=True, help="agent display name")
    parser.add_argument("--subnets", default=None, help="comma-separated locally-attached subnets")
    parser.add_argument("--interval", type=int, default=10, help="poll interval (seconds)")
    parser.add_argument("--once", action="store_true", help="single poll cycle then exit")
    parser.add_argument("--connect", action="store_true",
                        help="use TCP connect scans instead of SYN (no root/Npcap)")
    args = parser.parse_args()

    api_key = args.api_key or __import__("os").environ.get("SCANNER_AGENT_KEY")
    if not api_key:
        parser.error("--api-key (or SCANNER_AGENT_KEY) is required")

    require_nmap()
    use_connect = args.connect
    client = ApiClient(args.server, api_key, args.name)

    subnets = [s.strip() for s in (args.subnets or "").split(",") if s.strip()] or local_subnets()
    hostname, os_name = host_identity()
    caps = []
    if not use_connect:
        caps.append("syn")
    caps += ["arp", "nse", "nmap", "o-version"]  # authoritative L2 features

    print(f"[agent] {args.name} v{VERSION} starting; subnets={subnets}")

    # Background mDNS sweeper: keep re-probing on a separate thread so the
    # shared state keeps accumulating device names between/around scans. A
    # daemon thread dies with the agent, which is what we want.
    try:
        import threading as _th
        sweeper = _th.Thread(target=_run_mdns_sweeper, kwargs={
            "probe_duration": 15.0, "gap": 2.0,
        }, daemon=True)
        sweeper.start()
    except Exception as e:
        print(f"[agent] mDNS sweeper failed to start (continuing): {e}")

    while True:
        try:
            client.heartbeat(subnets, caps, hostname, os_name)
        except Exception as e:
            print(f"[agent] heartbeat failed: {e}")
            time.sleep(max(args.interval, 5))
            continue
        try:
            task = client.claim()
            if task:
                print(f"[agent] claimed scan {task['scan_id']}, target(s) {task['targets']}")
                try:
                    if task.get("kind") == "reverify":
                        execute_reverify(client, task, use_connect=use_connect)
                    else:
                        execute_task(client, task, use_connect=use_connect)
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    try:
                        client.log(task["id"], f"Agent scan FAILED: {e}", level="err")
                        client.result(task["id"], [], status="failed", error=str(e))
                    except Exception:
                        pass
            else:
                print(f"[agent] idle (polled {datetime.now().strftime('%H:%M:%S')})")
        except Exception as e:
            print(f"[agent] poll error: {e}")

        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()