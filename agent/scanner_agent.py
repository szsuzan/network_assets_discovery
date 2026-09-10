#!/usr/bin/env python3
"""SubNex - scanner agent.

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
import ipaddress
import json
import re
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional

VERSION = "0.1.0"

# Per-host nmap runs in parallel across a bounded worker pool. The agent used to
# launch one nmap per host strictly serially (worst case: N hosts x {45 s port
# scan + up to 120 s OS-only fingerprint}) - a 16-host /24 could burn 44 min.
# nmap is already parallel internally, so bounding concurrency to a few workers
# keeps a LAN-sized scan fast without flooding the wire or the router.
PHASE2_WORKERS = 5
PHASE3_WORKERS = 5

# Runtime override for the Phase 2/3 worker pool, set from the task payload the
# server sends (Settings page > Agent delegation > Agent parallel workers).
_RUNTIME_WORKERS = None


def _p2_workers():
    return _RUNTIME_WORKERS or PHASE2_WORKERS


def _set_runtime_workers(task: dict):
    global _RUNTIME_WORKERS
    try:
        _RUNTIME_WORKERS = int(task.get("workers")) if task.get("workers") else None
    except (TypeError, ValueError):
        _RUNTIME_WORKERS = None

# nmap-style port range grammar, mirror of the server-side schema validator.
_PORT_RANGE_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


def _valid_target(t: str) -> bool:
    """True only if the string is a well-formed IP or CIDR network.

    Anything unparseable (a stray nmap option like ``--script=...``, a hostname,
    whitespace) is rejected so a malicious/compromised server can never smuggle
    extra arguments into the nmap argv we execute locally.
    """
    if not isinstance(t, str) or not t.strip():
        return False
    try:
        ipaddress.ip_network(t.strip(), strict=False)
        return True
    except ValueError:
        return False


def _sane_port_range(port_range: str) -> str:
    """Parse-and-normalise a port range, raising ValueError on anything nan-map
    could interpret as an option rather than a plain -p value."""
    v = "".join(str(port_range).split()) if port_range else ""
    if not v:
        return "1-10000"
    if not _PORT_RANGE_RE.match(v):
        raise ValueError(f"invalid port_range {port_range!r}")
    for part in v.split(","):
        lo, _, hi = part.partition("-")
        lo_v = int(lo)
        if not (0 < lo_v <= 65535):
            raise ValueError("port numbers must be 1-65535")
        if hi and (int(hi) > 65535 or (0 < int(hi) < lo_v)):
            raise ValueError("invalid port range bounds")
    return v

# A lone `nmap -O --osscan-guess` guess on a host with no open ports is only
# kept when nmap reports at least this accuracy. (Real-world no-port responders
# typically score 90+, so this only trims inconclusive 'n/a' blips.)
OS_ONLY_CONF_FLOOR = 50

# Kept small by design: the server re-runs authoritative device classification
# after receiving results, so the agent only needs to parse what nmap emits.
PROBE_TIMING = {"quick": "-T4 --min-rate 1000", "full": "-T4", "stealth": "-T2"}

# OS fingerprinting (-O) measures TCP/IP timing (init seq, window sizing) so it
# must NOT be run under --min-rate: rate-pumping starves/distorts those probes
# and drops the OS guess entirely. Natural -T4 pacing only.
FINGERPRINT_TIMING = {"quick": "-T4", "full": "-T4", "stealth": "-T2"}


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

    def result(self, task_id: str, hosts, status="completed", error=None, notes="", progress=None):
        return self._request("POST", f"/api/agents/tasks/{task_id}/result", {
            "status": status, "error": error, "hosts": hosts, "notes": notes,
            "progress": progress,
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
    "_device-info._tcp.local",             # human-readable device name (iOS/Android)
    "_device-info._udp.local",             # same, UDP incarnation (most Android builds)
    "_apple-mobdev2._tcp.local",           # iPhone proximity pairing
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
    ("_device-info", "mobile"),                          # phone/tablet display name + model
    ("_apple-mobdev2", "mobile"),                        # iPhone proximity
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


def _mdns_packet_info(data: bytes):
    """Parse one raw mDNS UDP payload -> {services, hostnames, txt} or None.

    Answer/Additional records carry the device's facts: A/AAAA owners are the
    device's own hostname, PTR owners are the service types it offers, and TXT
    records its attributes. Pure query echoes (no answer records) are skipped."""
    if len(data) < 12:
        return None
    try:
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    except Exception:
        return None
    if an + ar == 0:
        return None  # pure query echo from the local host OS, not a device
    info = {"services": set(), "hostnames": set(), "txt": set(), "instances": set(),
            "inst2svc": {}, "model": None}
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
                # the instance part ("<name>._service._tcp.local") is the
                # human-readable device name most mDNS devices advertise -
                # a second name source when A/AAAA never appears.
                if "." in name:
                    inst = name.split(".", 1)[0]
                    if inst:
                        info["instances"].add(inst)
                        info["inst2svc"][inst] = nl
                if rtype == 16:
                    info["txt"].update(_mdns_parse_txt(rd))
    except Exception:
        return None
    # TV/phone model attributes: TXT `model=Xiaomi Redmi Note 8`, `mdl=...`
    # (especially from `_device-info`) gives the same label the router shows.
    for raw in sorted(info["txt"]):
        key, _, val = raw.partition("=")
        if key.lower() in ("model", "mdl", "device", "mf") and val and not info["model"]:
            info["model"] = " ".join(val.split())
    return info


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
            info = _mdns_packet_info(data)
            if info is None:
                continue
            entry = per_ip.setdefault(addr[0], {"services": set(), "hostnames": set(), "txt": set(), "instances": set()})
            entry["services"].update(info["services"])
            entry["hostnames"].update(info["hostnames"])
            entry["txt"].update(info["txt"])
            entry["instances"].update(info.get("instances") or ())
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
    Falls back to the SRV/TXT owner instance name (`DESKTOP-ABC._workstation.
    _tcp.local` -> DESKTOP-ABC). Empty strings mean 'no signal' and are left
    unset by the caller."""
    hostname = ""
    # Prefer the human-readable service instance (e.g. `_device-info` gives
    # "OnePlus Nord CE 3 5G") - the closest we get to the router's labels.
    best = None
    for inst, svc in (info.get("inst2svc") or {}).items():
        if "_device-info" in svc and not best:
            best = inst
    if best:
        import re as _re
        if not _re.fullmatch(r"[0-9a-f\\-]{6,}", best) and not best.startswith(("_", ".")):
            hostname = best
    for h in info.get("hostnames") or ():
        if not hostname and h.lower().endswith(".local"):
            hostname = h[: -len(".local")]
    if not hostname:
        import re as _re
        for inst in (info.get("instances") or ()):
            if inst and not _re.fullmatch(r"[0-9a-f\\-]{6,}", inst) \
               and not inst.startswith(("_", ".")):
                hostname = inst
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
                    "hostname": None, "device_type": None, "model": None,
                    "services": set(), "last_seen": now,
                }
            cur["services"].update(info.get("services") or ())
            if hn and not cur["hostname"]:
                cur["hostname"] = hn
            if dev and not cur["device_type"]:
                cur["device_type"] = dev
            if info.get("model") and not cur["model"]:
                cur["model"] = info["model"]
            cur["last_seen"] = now


def mdns_snapshot():
    """Return a copy of the shared map in the shape execute_task consumes:
    {ip: {"hostname": str|None, "device_type": str|None, "model": str|None}}."""
    with mdns_lock:
        return {ip: {"hostname": c["hostname"], "device_type": c["device_type"],
                     "model": c.get("model")}
                for ip, c in _mdns_shared.items()}


def _mdns_observe_scapy(duration: float = 12.0):
    """Capture mDNS over a raw snaplen sniff (bypasses the host firewall that
    silently drops inbound UDP 5353 multicast on Windows) and fold every device
    packet into the shared map. Also grabs announcements from OTHER hosts'
    queries/responses, not just answers to our own probes.

    While sniffing we ALSO actively re-send the service enumeration query over
    a plain UDP socket (sending is not firewall-blocked on Windows, only the
    socket receive is) so devices respond - and the sniff catches those
    answers that the socket layer would have dropped."""
    try:
        from scapy.all import sniff
    except Exception:
        return False
    import threading as _th

    sock = None
    try:
        q = _mdns_build_query(MDNS_SERVICES)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MDNS_PORT))
        mreq = struct.pack("4s4s", socket.inet_aton(MDNS_GROUP), socket.inet_aton("0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(0.05)
    except Exception:
        try:
            sock and sock.close()
        except Exception:
            pass
        sock = None
        q = None

    stop = _th.Event()

    def _sniff():
        try:
            sniff(filter="udp port 5353", store=0,
                  timeout=max(2, int(duration) + 4),
                  prn=lambda p: _mdns_fold_packet(p))
        except Exception:
            pass
        stop.set()

    t = _th.Thread(target=_sniff, daemon=True)
    t.start()
    end = time.time() + max(2, int(duration))
    try:
        while time.time() < end and not stop.is_set():
            if sock is not None and q is not None:
                try:
                    sock.sendto(q, (MDNS_GROUP, MDNS_PORT))
                except Exception:
                    pass
            time.sleep(0.5)
    finally:
        try:
            sock and sock.close()
        except Exception:
            pass
    t.join(timeout=2)
    return t.is_alive() or stop.is_set()


def _mdns_fold_packet(pkt):
    try:
        if not pkt.haslayer("UDP"):
            return
        udp = pkt["UDP"]
        if udp.sport != MDNS_PORT and udp.dport != MDNS_PORT:
            return
        ip = pkt.getlayer("IP")
        if ip is None:
            return
        src = ip.src
        if not src or src == "0.0.0.0":
            return
        info = _mdns_packet_info(bytes(udp.payload))
        if info is None:
            return
        _mdns_fold_raw(src, info)
    except Exception:
        pass


def _mdns_fold_raw(ip: str, info: dict):
    """Accumulate a parsed mDNS packet (from any source, socket or sniff) into
    the shared per-IP map, exactly like mdns_observe does for probe results."""
    hn, dev = mdns_device_hint(info)
    now = time.time()
    with mdns_lock:
        cur = _mdns_shared.get(ip)
        if cur is None:
            cur = _mdns_shared[ip] = {
                "hostname": None, "device_type": None, "model": None,
                "services": set(), "last_seen": now,
            }
        cur["services"].update(info.get("services") or ())
        if hn and not cur["hostname"]:
            cur["hostname"] = hn
        if dev and not cur["device_type"]:
            cur["device_type"] = dev
        if info.get("model") and not cur["model"]:
            cur["model"] = info["model"]
        cur["last_seen"] = now


def _run_mdns_sweeper(probe_duration: float = 10.0, gap: float = 5.0, stop_evt=None):
    """Background thread: continuously capture mDNS and accumulate into the
    shared map. Prefers the raw scapy sniff (reliable on Windows where the
    UDP-socket receive is firewall-blocked); falls back to socket probing when
    scapy is unavailable. Runs until stop_evt is set (or forever if None)."""
    sniff_ok = False
    while True:
        if stop_evt and stop_evt.is_set():
            return
        try:
            if not sniff_ok:
                if _mdns_observe_scapy(probe_duration):
                    sniff_ok = True
                else:
                    mdns_observe(probe_duration, 0.6)
            else:
                _mdns_observe_scapy(probe_duration)
        except Exception:
            pass  # never let the sweeper crash the agent
        if gap > 0:
            try:
                time.sleep(gap)
            except Exception:
                return

def run_nmap(args: List[str]) -> str:
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
        ip = mac = vendor = hostname = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        hnm = host_el.find("hostnames")
        if hnm is not None:
            for hn_el in hnm.findall("hostname"):
                n = (hn_el.get("name") or "").strip().rstrip(".")
                if n:
                    hostname = n[:255]
                    break
        if ip:
            found.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname, "state": state})
    return found


def _hostname_from_banner(ports: list) -> Optional[str]:
    """Pull a device hostname out of script banners when DNS/mDNS gave none.
    Windows hosts advertise their computer name via the default smb-os-discovery
    ('NetBIOS computer name: DESKTOP-ABC123') and nbstat ('NAME<00> UNIQUE'
    Workstation row) scripts; earlier those ended up folded into the banner text
    but never promoted to the hostname field."""
    import re
    pats = (
        re.compile(r"NetBIOS computer name\s*:\s*([^\r\n]+)"),
        re.compile(r"Computer name\s*:\s*([^\r\n]+)"),
        re.compile(r"Workstation\s*:\s*([^\r\n]+)"),
        re.compile(r"([A-Za-z0-9\-_.]{1,63})\s+<00>\s+UNIQUE"),
    )
    for p in ports:
        b = p.get("banner") or ""
        for rx in pats:
            m = rx.search(b)
            if m:
                name = m.group(1).strip().split()[0]
                if name and name.lower() not in ("unknown", "<unknown>", "anonymous"):
                    return name[:255]
    return None


# Ports treated as HTTP-capable for script selection (a web listener -> HTTP
# enumeration; stream ports -> RTSP; SMB -> Windows name/OS discovery).
HTTP_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 7000,
                        7001, 8081, 8082, 9000, 9001, 9080, 9443, 10000, 8083})


def _scripts_for_ports(ports: list) -> str:
    """Pick nmap scripts from the ports actually open, so HTTP enumeration only
    runs where a web service listens, RTSP only on stream ports, and SMB
    discovery on Windows file shares (also the main source of Windows
    hostnames). 'default' always runs and targets each service itself."""
    s = ["default"]
    if any(int(p) in HTTP_PORTS for p in ports):
        s += ["http-title", "http-headers", "http-methods",
              "http-server-header", "http-enum", "http-generator"]
    if 554 in [int(p) for p in ports]:
        s.append("rtsp-methods")
    if 445 in [int(p) for p in ports]:
        s += ["smb-os-discovery", "nbstat"]
    return ",".join(s)


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

    hostname = None
    hnm = host_el.find("hostnames")
    if hnm is not None:
        for hn_el in hnm.findall("hostname"):
            n = (hn_el.get("name") or "").strip().rstrip(".")
            if n:
                hostname = n[:255]
                break

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

    host = {"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname,
            "status": "up", "ports": ports}

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
    if not host.get("hostname") and ports:
        host["hostname"] = _hostname_from_banner(ports)
    return host


def _parse_open_ports(xml: str) -> list:
    """Extract open port ids from `nmap -sS/-sT -p ... --open -oX -` output."""
    found = []
    try:
        root = ET.fromstring(xml)
        for port in root.findall(".//port"):
            st = port.find("state")
            if st is not None and st.get("state") == "open":
                found.append(port.get("portid"))
    except Exception:
        pass
    return found


def _merge_phase2_ports(host: dict, phase2_opens: list) -> None:
    """Overlay Phase-3 -sV/-O enrichment onto the Phase-2 -sS discoveries.

    A port Phase 2 saw open is scan-truth: if the Phase-3 re-probe races a
    sleeping device and re-opens nothing, keep the bare discovery instead of
    erasing it from the report. Phase-3-only opens still count too.
    """
    phase2 = [int(p) for p in (phase2_opens or [])]
    by_port = {p["port"]: p for p in host.get("ports", [])}
    merged = []
    seen = set()
    for pid in phase2:
        if pid in by_port:
            merged.append(by_port[pid])
        else:
            merged.append({"port": pid, "protocol": "tcp", "state": "open",
                           "service": None, "version": None, "banner": None})
        seen.add(pid)
    for p in host.get("ports", []):
        if p["port"] not in seen:
            merged.append(p)
    host["ports"] = merged


def _map_hosts(worker, items: List[tuple], workers: int,
               client: "ApiClient", task_id: str, phase: str):
    """Run a per-host nmap worker across a bounded thread pool.

    Yields (item, result) pairs as each host FINISHES (completion order), so
    findings stream to the server in realtime instead of waiting for slower
    earlier hosts to finish first. A worker that hit a stop/interruption yields
    None for that item. Concurrency is bounded so a subnet scan doesn't
    saturate the uplink or the target router."""
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(worker, it): it for it in items}
        for f in as_completed(futs):
            it = futs[f]
            try:
                yield (it, f.result())
            except Exception as e:  # noqa: BLE001 - worker must never kill a scan
                client.log(task_id, f"  {phase}: worker failed for {it[0]}: {e}", level="err")
                yield (it, None)


# --------------------------------------------------------------------------- #
# Scan execution
# --------------------------------------------------------------------------- #
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
    targets = [t for t in (task["targets"] or []) if _valid_target(t)]
    profile = task.get("profile") or "quick"
    port_range = _sane_port_range(task.get("port_range") or "1-10000")
    _set_runtime_workers(task)

    if not targets:
        client.log(task_id, "Task rejected: no valid targets provided", level="err")
        try:
            client.result(task_id, [], status="failed", notes="invalid targets")
        except Exception:
            pass
        return

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

    # Nudge IPv6-capable clients into DHCPv6 (SOLICIT on UDP 547) so the
    # passive sweeper can hear their Client-FQDN — the router-grade name.
    # Rate-limited internally to ~once/90s; replies fold during the scan and
    # are picked up by the refreshed snapshot at Finalise.
    if _dhcp6_nudge(_pick_passive_iface(targets)):
        client.log(task_id, "DHCPv6 RA nudge sent (M flag) - asking clients to reveal names", level="cmd")

    # Passive evidence harvested between scans (DHCP / ARP / CDP / LLDP). MAC-keyed
    # fingerprints (network gear announcing itself via CDP/LLDP, DHCP on privacy
    # MACs) are cross-referenced onto the IPs ARP discovery just resolved (the fold
    # below runs once live hosts are known, after Phase 1).
    passive = passive_snapshot()
    passive_by_ip = dict(passive["by_ip"])

    def _decorate(h: dict):
        h = dict(h)
        hint = mdns_hints.get(h.get("ip"))
        phint = passive_by_ip.get(h.get("ip"))
        if hint:
            if hint["hostname"] and not h.get("hostname"):
                h["hostname"] = hint["hostname"]
            if hint["device_type"] and not h.get("device_type"):
                h["device_type"] = hint["device_type"]
            if hint.get("model") and not h.get("hostname"):
                h["hostname"] = hint["model"]
        if phint:
            if phint.get("hostname") and not h.get("hostname"):
                h["hostname"] = phint["hostname"]
            if phint.get("device_type") and not h.get("device_type"):
                h["device_type"] = phint["device_type"]
            if phint.get("os_guess") and not h.get("os_guess"):
                h["os_guess"] = phint["os_guess"]
            if phint.get("vendor") and not h.get("vendor"):
                h["vendor"] = phint["vendor"]
            if phint.get("mac") and not h.get("mac"):
                h["mac"] = phint["mac"]
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

    for _ip, _meta in list(live.items()):
        _m = (_meta.get("mac") or "").lower()
        if _m and _m in passive["by_mac"]:
            _entry = dict(passive["by_mac"][_m])
            _entry.update(passive_by_ip.get(_ip, {}))
            passive_by_ip[_ip] = _entry
    if passive_by_ip:
        client.log(task_id, f"Phase 1/3: {len(passive_by_ip)} passive fingerprint(s) folded from DHCP/ARP/CDP/LLDP", level="out")

    if not live:
        client.log(task_id, "Discovery found no live hosts - reporting 0 hosts", level="warn")

    # Merge mDNS responders AND passively-observed hosts into the live set. A
    # device that answered mDNS - or that we saw lease an address / answer ARP
    # while it was awake - is definitively up even if ARP -sn missed it
    # (power-save radios often ignore ARP pings but do answer multicast/DHCP),
    # and carrying its hints lets us name a random-MAC device that would
    # otherwise be dropped entirely. Kept inside the target networks so an
    # mDNS/passive hint from another VLAN cannot leak an out-of-scope host in.
    scope_nets = []
    for t in targets:
        try:
            scope_nets.append(ipaddress.ip_network(t, strict=False))
        except Exception:
            pass  # plain host target -> no fold beyond it, conservatively
    in_scope = (lambda ip: True) if not scope_nets else (
        lambda ip: any(ipaddress.ip_address(ip) in n for n in scope_nets))
    extra = {ip for ip in (set(mdns_hints.keys()) | set(passive_by_ip.keys())) - set(live.keys())
             if in_scope(ip)}
    if extra:
        client.log(task_id, f"Observed-but-invisible host(s) added: {', '.join(sorted(extra))}", level="out")
    for ip in extra:
        live[ip] = {"ip": ip, "mac": None, "vendor": None, "state": "up"}

    # Stream ARP results (IP + MAC + vendor) right away as a partial update.
    try:
        client.result(task_id, [
            _decorate({"ip": ip, "mac": m.get("mac"), "vendor": m.get("vendor"),
                       "hostname": m.get("hostname"),
                       "status": "up", "ports": []})
            for ip, m in live.items()
        ], status="partial", notes="discovery", progress=20)
        posted.update(live.keys())
        client.log(task_id, f"Phase 1/3 done: {len(live)} live host(s), MAC/vendor streamed", level="out")
    except Exception as e:
        client.log(task_id, f"Partial discovery post failed: {e}", level="err")

    # ---- Phase 2/3: simple port scan (no -sV/-O) -> open ports only ----------
    client.log(task_id, f"Phase 2/3: fast port scan ({scan_type}) on {len(live)} host(s), {_p2_workers()} parallel worker(s)", level="cmd")

    def _p2_worker(ip_meta):
        ip, _meta = ip_meta
        if not _await_go(client, task_id):
            return None
        args = [
            "nmap", scan_type, "-p", port_range, "--open",
            timing, "--host-timeout", "30s", "-oX", "-", str(ip),
        ]
        xml = run_nmap(args)
        return _parse_open_ports(xml), " ".join(args)

    open_ports = {}  # ip -> [portid]
    p2_done = 0
    p2_total = max(len(live), 1)
    for (ip, _meta), res in _map_hosts(_p2_worker, list(live.items()),
                                       _p2_workers(), client, task_id, "port-scan"):
        if res is None:
            client.log(task_id, "Scan stopped by user", level="warn")
            break
        found, args_str = res
        open_ports[ip] = found
        p2_done += 1
        client.log(task_id, f"$ {args_str}", level="cmd")
        client.log(task_id, f"  {ip}: {len(found)} open port(s)")
        # Stream each host's open ports as it completes (server MERGES ports,
        # never deletes, so these stay even if the later -sV re-probe races the
        # device to sleep and re-opens nothing).
        p2_prog = min(69, int(20 + 48 * p2_done / p2_total))
        try:
            client.result(task_id, [
                _decorate({"ip": ip, "mac": _meta.get("mac"), "vendor": _meta.get("vendor"),
                           "status": "up",
                           "ports": [{"port": int(p), "protocol": "tcp", "state": "open",
                                      "service": None, "version": None, "banner": None}
                                     for p in found]})
            ], status="partial", notes="ports", progress=p2_prog)
        except Exception as e:
            client.log(task_id, f"Partial Phase-2 port post failed: {e}", level="err")
    # any host still missing an entry (e.g. stopped early) is a no-port host
    for ip in live:
        if ip not in open_ports:
            open_ports[ip] = []

    # ---- Phase 3/3: service/OS fingerprint -----------------------------------
    client.log(task_id, f"Phase 3/3: -sV -O fingerprint (ports) / -O (OS-only for no-port hosts), {PHASE3_WORKERS} parallel worker(s)", level="cmd")

    def _p3_worker(ip_meta):
        ip, _meta = ip_meta
        if not _await_go(client, task_id):
            return None
        fp_timing = FINGERPRINT_TIMING.get(profile, "-T4")
        ports = open_ports.get(ip, [])
        if not ports:
            # No open ports, so -sV has nothing to probe, but -O can still
            # fingerprint the OS from the host's TCP/IP stack behaviour (works
            # on closed/filtered hosts). Attach any OS guess for richer typing.
            args = ["nmap", "-O", "--osscan-guess",
                    fp_timing, "--host-timeout", "60s", str(ip), "-oX", "-"]
            xml = run_nmap(args)
            host = parse_host_xml(xml)
            if host and (host.get("os_confidence") or 0) < OS_ONLY_CONF_FLOOR:
                host.pop("os_guess", None)
                host.pop("os_confidence", None)
            return host, " ".join(args)
        args = (
            ["nmap", scan_type, "-sV", "-O", "-p", ",".join(ports), "--open",
             fp_timing, *shlex.split(f"--script {_scripts_for_ports(ports)}"),
             "--host-timeout", "90s", str(ip), "-oX", "-"]
        )
        xml = run_nmap(args)
        return parse_host_xml(xml), " ".join(args)

    p3_done = 0
    p3_total = max(len(live), 1)
    for (ip, meta), res in _map_hosts(_p3_worker, list(live.items()),
                                      PHASE3_WORKERS, client, task_id, "fingerprint"):
        if res is None:
            client.log(task_id, "Scan stopped by user", level="warn")
            break
        host, args_str = res
        client.log(task_id, f"$ {args_str}", level="cmd")
        ports = open_ports.get(ip, [])
        p3_done += 1
        p3_prog = min(89, int(70 + 19 * p3_done / p3_total))
        if not ports:
            if host:
                host.setdefault("mac", meta.get("mac"))
                host.setdefault("vendor", meta.get("vendor"))
                if not host.get("ports"):
                    host["ports"] = []
                try:
                    client.result(task_id, [_decorate(host)], status="partial", notes="host", progress=p3_prog)
                    posted.add(host["ip"])
                except Exception as e:
                    client.log(task_id, f"Partial host post failed: {e}", level="err")
                client.log(task_id, f"  {ip}: OS-only fingerprint -> {host.get('os_guess') or 'n/a'}")
            else:
                client.log(task_id, f"  {ip}: OS-only fingerprint returned no data")
                try:
                    client.result(task_id, [], status="partial", notes="progress", progress=p3_prog)
                except Exception:
                    pass
        elif host:
            host.setdefault("mac", meta.get("mac"))
            host.setdefault("vendor", meta.get("vendor"))
            _merge_phase2_ports(host, ports)
            try:
                client.result(task_id, [_decorate(host)], status="partial", notes="host", progress=p3_prog)
                posted.add(host["ip"])
            except Exception as e:
                client.log(task_id, f"Partial host post failed: {e}", level="err")
            client.log(task_id, f"  {ip}: {len(host['ports'])} open port(s) fingerprinted")
        elif ports:
            # Verification probe returned nothing parseable (the device went to
            # sleep / RST raced us). Never lose the discovery: post the ports we
            # already confirmed open, unenriched, so the report keeps them.
            host = {"ip": ip,
                    "ports": [{"port": int(p), "protocol": "tcp", "state": "open",
                               "service": None, "version": None, "banner": None}
                              for p in ports]}
            host.setdefault("mac", meta.get("mac"))
            host.setdefault("vendor", meta.get("vendor"))
            try:
                client.result(task_id, [_decorate(host)], status="partial", notes="host", progress=p3_prog)
                posted.add(host["ip"])
            except Exception as e:
                client.log(task_id, f"Partial host post failed: {e}", level="err")

    # ---- Finalise -------------------------------------------------------------
    # Re-read passive evidence: the RA nudge + background sweeps may have
    # surfaced DHCPv6/DHCP hostnames during the scan window.
    passive_by_ip = dict(passive_snapshot()["by_ip"])
    remaining = [_decorate(h) for ip, h in [
        (ip, {"ip": ip, "mac": meta.get("mac"), "vendor": meta.get("vendor"),
              "status": "up",
              "ports": [{"port": int(p), "protocol": "tcp", "state": "open",
                         "service": None, "version": None, "banner": None}
                        for p in open_ports.get(ip, [])]})
        for ip, meta in live.items()
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
    ports = ([int(x) for x in ports_spec.split(",")] if ports_spec else [])
    args = (
        ["nmap", scan_type, "-sV", "-O", "-p", ports_spec, "--open",
         timing, *shlex.split(f"--script {_scripts_for_ports(ports)}"),
         "--host-timeout", "90s", ip, "-oX", "-"]
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
    down_ips = [ip for ip in (rv.get("down_ips") or []) if _valid_target(ip)]
    up_ips = [ip for ip in (rv.get("up_ips") or []) if _valid_target(ip)]
    already_ports = _sane_port_range(rv.get("already_ports") or "1-65535")
    _set_runtime_workers(task)
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
        client.log(task_id, f"  {len(alive)} previously-down host(s) now responding")
        scan_type_a = "-sT" if use_connect else "-sS"
        timing_a = PROBE_TIMING.get(profile, "-T4")
        client.log(task_id, f"  re-checking now-up host(s) (full pipeline), {_p2_workers()} parallel worker(s)")

        def _rv_down_worker(meta_ip):
            ip, meta = meta_ip
            if not _await_go(client, task_id):
                return None
            p_args = ["nmap", scan_type_a, "-p", "1-10000",
                      "--open", timing_a,
                      "--host-timeout", "45s", "-oX", "-", ip]
            pxml = run_nmap(p_args)
            found = _parse_open_ports(pxml)
            if not found:
                # no open ports on a now-up host -> just stream MAC/vendor
                if meta and meta.get("mac"):
                    try:
                        client.result(task_id, [{"ip": ip, "mac": meta.get("mac"),
                                                 "vendor": meta.get("vendor"),
                                                 "status": "up", "ports": []}],
                                      status="partial", notes="host")
                    except Exception as e:
                        client.log(task_id, f"Partial post failed: {e}", level="err")
                return {"ip": ip, "ports": []}
            return _deep_scan_host(client, task_id, ip, meta or {},
                                   ",".join(found), use_connect, profile) or {"ip": ip, "ports": []}

        for (ip, _meta), host in _map_hosts(_rv_down_worker, [(a["ip"], a) for a in alive],
                                            _p2_workers(), client, task_id, "re-verify-up"):
            if host is None:
                client.log(task_id, "Scan stopped by user", level="warn")
                break
            newly_up.append(ip)
            client.log(task_id, f"  {ip}: {len(host.get('ports', []))} open port(s)")

    # ---- Phase B: sweep unscanned ports on the up hosts (parallel) ----
    if sweep_spec and up_ips:
        if not _await_go(client, task_id):
            return
        scan_type_b = "-sT" if use_connect else "-sS"
        timing_b = PROBE_TIMING.get(profile, "-T4")
        client.log(task_id, f"Phase B: sweeping unscanned ports {sweep_spec} on {len(up_ips)} up host(s), {_p2_workers()} parallel worker(s)")

        def _rv_sweep_worker(ip_meta):
            ip, _meta = ip_meta
            if not _await_go(client, task_id):
                return None
            args = ["nmap", scan_type_b, "-p", sweep_spec, "--open", timing_b,
                    "--host-timeout", "45s", "-oX", "-", ip]
            client.log(task_id, " ".join(args), level="cmd")
            pxml = run_nmap(args)
            found = _parse_open_ports(pxml)
            if found:
                _deep_scan_host(client, task_id, ip, {"mac": None, "vendor": None},
                                ",".join(found), use_connect, profile)
            return found

        leftover_done = 0
        leftover_total = max(len(up_ips), 1)
        for (ip, _meta), found in _map_hosts(_rv_sweep_worker, [(ip, {}) for ip in up_ips],
                                             _p2_workers(), client, task_id, "leftover-sweep"):
            if found is None:
                client.log(task_id, "Scan stopped by user", level="warn")
                break
            leftover_done += 1
            if not found:
                client.log(task_id, f"  {ip}: no hidden open ports in leftover range")
            else:
                client.log(task_id, f"  {ip}: hidden open port(s) in leftover range: {','.join(map(str, found))}")
            try:
                client.result(task_id, [], status="partial", notes="progress",
                              progress=min(99, int(40 + 60 * leftover_done / leftover_total)))
            except Exception:
                pass

    # ---- Finalise ----
    try:
        client.result(task_id, [], status="completed",
                      notes=f"reverify={uuid.uuid4()}")
    except Exception as e:
        client.log(task_id, f"Final result post failed: {e}", level="err")
    client.log(task_id, f"=== Agent re-verify done: {len(newly_up)} host(s) recovered, report merged ===")


# --------------------------------------------------------------------------- #
# Passive fingerprinting (optional Scapy: DHCP / ARP / CDP / LLDP)
#
# Active fingerprinting needs the target to answer. Passive capture sees what
# the LAN already says:
#   * DHCP (UDP 67/68) - the hostname and vendor-class-id a device advertises
#     while leasing an address. This names privacy-MAC phones/tablets (their
#     OUI is randomised away) and reveals brand/OS for printers, routers, NAS.
#   * ARP - real IP<->MAC bindings, including devices whose radios ignore the
#     broadcast ARP ping nmap sends.
#   * CDP / LLDP - network gear announces itself (Cisco Discovery Protocol and
#     Link Layer Discovery Protocol): switch/AP/router identity, platform,
#     software version, and *authoritative* system capabilities. A switch that
#     never answers an L3 probe is still named here.
# Scapy is optional: if it is not installed (or lacks Npcap/privileges), the
# agent just logs once and keeps running with active scanning only. Like the
# mDNS sweeper this runs on a daemon thread for the agent's whole lifetime, so
# fingerprints accumulate between scans and every scan harvests the full map.
# --------------------------------------------------------------------------- #
_PASSIVE_LOCK = threading.Lock()
_passive_shared = {
    "by_ip": {},  # ip        -> {"hostname","os_guess","device_type","vendor","mac","last_seen"}
    "by_mac": {},  # mac.lower -> {"hostname","os_guess","device_type","vendor","port_id","last_seen"}
}
_passive_sniffer_ok = False
_passive_sniffer_noted = False


# VCI (DHCP option 60) -> (os_guess_hint, vendor_hint, coarse device_type fallback).
# Specific brands first; generic OSes last. Only used when the classifier lacks
# a stronger signal (nmap -O / SNMP win as usual - merge is fill-if-blank).
_DHCP_VCI_RULES = [
    ("mikrotik",            "MikroTik RouterOS (DHCP VCI)", "MikroTik", "network_gear"),
    ("openwrt",             "OpenWrt (DHCP VCI)",           None,       "network_gear"),
    ("dd-wrt",              "DD-WRT (DHCP VCI)",            None,       "network_gear"),
    ("hikvision",           "Hikvision (DHCP VCI)",         "Hikvision","camera"),
    ("dahua",               "Dahua (DHCP VCI)",             "Dahua",    "camera"),
    ("brother",             "Brother printer (DHCP VCI)",   "Brother",  "printer"),
    ("mfl-",                "Brother printer (DHCP VCI)",   "Brother",  "printer"),
    ("epson",               "Epson printer (DHCP VCI)",     "Epson",    "printer"),
    ("lexmark",             "Lexmark printer (DHCP VCI)",   "Lexmark",  "printer"),
    ("canon",               "Canon printer (DHCP VCI)",     "Canon",    "printer"),
    ("hewlett-packard",     "HP printer (DHCP VCI)",        "HP",       "printer"),
    ("hp ",                 "HP printer (DHCP VCI)",        "HP",       "printer"),
    ("synology",            "Synology NAS (DHCP VCI)",      "Synology", "nas"),
    ("qnap",                "QNAP NAS (DHCP VCI)",          "QNAP",     "nas"),
    ("msft",                "Windows (DHCP VCI: MSFT)",     None,       None),
    ("android",             "Android (DHCP VCI)",           None,       "smartphone"),
    ("ios",                 "Apple iOS (DHCP VCI)",         "Apple",    "smartphone"),
    ("macos",               "Apple macOS (DHCP VCI)",       "Apple",    None),
    ("darwin",              "Apple macOS (DHCP VCI)",       "Apple",    None),
    ("udhcpc",              "Linux (udhcpc DHCP)",          None,       None),
    ("udhcp",               "Linux (udhcpc DHCP)",          None,       None),
    ("dhcpcd",              "Linux/BSD (dhcpcd DHCP)",      None,       None),
    ("linux",               "Linux (DHCP VCI)",             None,       None),
]


# Brand -> canonical vendor string, sniffed from LLDP/CDP platform/descriptions.
_VENDOR_KEYWORDS = [
    ("aruba", "Aruba"), ("cisco", "Cisco"), ("juniper", "Juniper"),
    ("arista", "Arista"), ("mikrotik", "MikroTik"), ("ubiquiti", "Ubiquiti"),
    ("huawei", "Huawei"), ("fortinet", "Fortinet"), ("palo alto", "Palo Alto"),
    ("paloalto", "Palo Alto"), ("extreme", "Extreme"), ("brocade", "Brocade"),
    ("fritzbox", "AVM"), ("dell", "Dell"), ("hpe", "HPE"), ("hewlett", "HP"),
    ("synology", "Synology"), ("qnap", "QNAP"), ("hikvision", "Hikvision"),
    ("tp-link", "TP-Link"), ("tplink", "TP-Link"), ("netgear", "Netgear"),
    ("zyxel", "Zyxel"), ("sophos", "Sophos"), ("avm", "AVM"),
]


def _ip_in_subnet(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


def _pick_passive_iface(subnets: List[str]) -> Optional[str]:
    """Pick the local interface whose IPv4 address sits inside the advertised
    subnets (that is the LAN we must sniff). Returns None when Scapy is missing
    or no interface is useable at all."""
    try:
        from scapy.all import get_if_addr, get_if_list
    except Exception:
        return None
    candidates = []
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
        except Exception:
            continue
        if addr and addr != "0.0.0.0":
            candidates.append((iface, addr))
    for iface, addr in candidates:
        if any(_ip_in_subnet(addr, s) for s in subnets):
            return iface
    # No adapter matched the subnet (e.g. VPN/VM adapters came first) - fall
    # back to the first usable LAN/private adapter rather than disabling
    # passive evidence entirely. Sniffing the wrong L2 is harmless: the packet
    # handler scopes every result back through the target subnets anyway.
    import ipaddress as _ipa
    for iface, addr in candidates:
        try:
            if _ipa.ip_address(addr).is_private:
                return iface
        except Exception:
            continue
    return candidates[0][0] if candidates else None


def _vci_hint(vci: str):
    """Map a DHCP vendor-class-id to (os_guess, vendor, coarse device_type)."""
    v = vci.lower().strip()
    if not v:
        return None, None, None
    for token, os_hint, vendor, dev in _DHCP_VCI_RULES:
        if token in v:
            return os_hint, vendor, dev
    return None, None, None


def _sniff_vendor(text: str) -> Optional[str]:
    t = (text or "").lower()
    for kw, name in _VENDOR_KEYWORDS:
        if kw in t:
            return name
    return None


def _mac_from_bytes(b: bytes) -> str:
    try:
        return ":".join("%02x" % x for x in b[:6])
    except Exception:
        return ""


def _clean_str(v: bytes, limit: int = 120) -> Optional[str]:
    try:
        s = v.decode("utf-8", "replace").strip()
    except Exception:
        return None
    s = " ".join(s.split())
    if not s:
        return None
    return s[:limit]


def _parse_dhcp_options(options):
    """Extract (hostname, vendor_class_id) from Scapy BOOTP.options."""
    hostname = vci = None
    for opt in options or ():
        if not (isinstance(opt, tuple) and len(opt) >= 2):
            continue
        key = opt[0]
        val = opt[1]
        if key == "hostname" and not hostname:
            hostname = _clean_str(val if isinstance(val, bytes) else str(val).encode())
        elif key == "vendor_class_id" and not vci:
            vci = _clean_str(val if isinstance(val, bytes) else str(val).encode(), limit=64)
        elif key in (81, "client_fqdn", "fqdn", "option_81") and not hostname:
            # RFC 4702 client FQDN: flags(1) + keytag(1) + name (DNS wire).
            h = _parse_fqdn_option(val if isinstance(val, bytes) else b"")
            if h:
                hostname = h
    return hostname, vci


def _dns_wire_name(buf: bytes):
    """Decode one DNS wire-format name -> dot-joined string (or None)."""
    parts = []
    i = 0
    while i < len(buf):
        n = buf[i]
        i += 1
        if n == 0:
            return ".".join(parts) or None
        if n > 63 or i + n > len(buf):
            return None
        lab = buf[i:i + n].decode("utf-8", "replace")
        if "\x00" in lab:
            return None
        parts.append(lab)
        i += n
    return None


def _parse_fqdn_option(val: bytes) -> Optional[str]:
    """Client-FQDN option payload (flags + optional keytag + DNS-wire name).

    The name always starts AFTER the flags byte (RFC 4702: flags, optional
    keytag/len field, then the wire-form name). Try the two plausible offsets
    (flags only, or flags + keytag) and return the first clean decode."""
    if not val:
        return None
    for start in (2 if len(val) >= 3 else 1, 1):
        if start >= len(val):
            continue
        n = _dns_wire_name(val[start:])
        if n:
            return n
    return None


def _parse_dhcp6_fqdn(payload: bytes) -> Optional[str]:
    """Hostname from a DHCPv6 SOLICIT/REQUEST (client-to-server, port 547):
    option 39 (Client FQDN) carries the client's name the router knows."""
    try:
        if len(payload) < 4 or payload[0] not in (1, 3, 5, 7, 11, 13):
            return None
        o = 4  # msg-type(1) + transaction-id(3)
        while o + 4 <= len(payload):
            code = int.from_bytes(payload[o:o + 2], "big")
            ln = int.from_bytes(payload[o + 2:o + 4], "big")
            o += 4
            if o + ln > len(payload):
                break
            val = payload[o:o + ln]
            o += ln
            if code == 39:
                n = _parse_fqdn_option(val)
                if n:
                    return n
    except Exception:
        pass
    return None


def _parse_cdp(payload: bytes) -> dict:
    """Parse a CDP message body -> {device_id, port_id, platform, software}."""
    out = {}
    if len(payload) < 4:
        return out
    body = payload[4:]  # version(1) ttl(1) checksum(2)
    i = 0
    while i + 4 <= len(body):
        t = int.from_bytes(body[i:i + 2], "big")
        ln = int.from_bytes(body[i + 2:i + 4], "big")
        if ln < 4 or i + ln > len(body):
            break
        val = _clean_str(body[i + 4:i + ln], limit=255)
        if val:
            if t == 1 and not out.get("device_id"):
                out["device_id"] = val
            elif t == 3 and not out.get("port_id"):
                out["port_id"] = val
            elif t == 5 and not out.get("software"):
                out["software"] = val
            elif t == 6 and not out.get("platform"):
                out["platform"] = val
        i += ln
    return out


def _parse_lldp(payload: bytes) -> dict:
    """Parse an LLDPDU -> {system_name, system_description, capabilities}."""
    out = {}
    i = 0
    while i + 2 <= len(payload):
        b0 = payload[i]
        b1 = payload[i + 1]
        t = (b0 & 0xFE) >> 1
        ln = ((b0 & 0x01) << 8) | b1
        i += 2
        if t == 0:  # End-of-LLDPDU
            break
        if i + ln > len(payload):
            break
        val = payload[i:i + ln]
        i += ln
        if t == 1 and not out.get("chassis"):
            out["chassis"] = _clean_str(val, limit=255)
        elif t == 2 and not out.get("port_id"):
            out["port_id"] = _clean_str(val, limit=255)
        elif t == 5 and not out.get("system_name"):
            out["system_name"] = _clean_str(val, limit=255)
        elif t == 6 and not out.get("system_description"):
            out["system_description"] = _clean_str(val, limit=255)
        elif t == 7 and ln >= 2 and not out.get("capabilities"):
            out["capabilities"] = int.from_bytes(val[:2], "big")
    return out


def _lldp_caps_device(caps: int) -> Optional[str]:
    """LLDP System-Capabilities bits -> coarse device_type fallback.
    bit7 station, bit4 router, bit3 wlan-ap, bit2 bridge(switch)."""
    if caps & (1 << 4):
        return "router"
    if caps & (1 << 3):
        return "wireless_access_point"
    if caps & (1 << 2):
        return "switch"
    if caps & (1 << 7):
        return "workstation"
    return None


def _passive_record(entry: dict, hints: dict):
    """Merge hints into a shared entry (fill-if-blank, keep last_seen fresh)."""
    for k in ("hostname", "os_guess", "device_type", "vendor", "mac"):
        if hints.get(k) and not entry.get(k):
            entry[k] = hints[k]
    if hints.get("port_id") and not entry.get("port_id"):
        entry["port_id"] = hints["port_id"]
    entry["last_seen"] = time.time()


def _passive_packet(pkt, subnets: List[str]):
    try:
        from scapy.all import ARP, BOOTP, Ether, SNAP

        _guard = False
        if pkt.haslayer(ARP):
            a = pkt[ARP]
            ip = getattr(a, "psrc", None)
            mac = getattr(a, "hwsrc", None)
            if (ip and mac and ip not in ("0.0.0.0", "255.255.255.255")
                    and any(_ip_in_subnet(ip, s) for s in subnets)):
                with _PASSIVE_LOCK:
                    _mac_to_ip(mac, ip)
                    _passive_record(
                        _passive_shared["by_ip"].setdefault(
                            ip, {"hostname": None, "os_guess": None,
                                 "device_type": None, "vendor": None,
                                 "mac": None, "last_seen": 0.0}),
                        {"mac": mac},
                    )
                    _guard = True

        if pkt.haslayer(BOOTP):
            b = pkt[BOOTP]
            chaddr = _mac_from_bytes(bytes(b.chaddr) if isinstance(b.chaddr, bytes) else b.chaddr)
            hostname, vci = _parse_dhcp_options(b.options)
            os_hint, vendor, dev = _vci_hint(vci or "")
            yiaddr = None
            try:
                raw = bytes(b.yiaddr)
                if raw and raw != b"\x00\x00\x00\x00":
                    yiaddr = socket.inet_ntoa(raw)
            except Exception:
                yiaddr = None
            if yiaddr and any(_ip_in_subnet(yiaddr, s) for s in subnets):
                with _PASSIVE_LOCK:
                    rec = _passive_shared["by_ip"].setdefault(
                        yiaddr, {"hostname": None, "os_guess": None,
                                 "device_type": None, "vendor": None,
                                 "mac": None, "last_seen": 0.0})
                    _passive_record(rec, {
                        "hostname": hostname or None,
                        "os_guess": os_hint,
                        "device_type": dev,
                        "vendor": vendor,
                        "mac": chaddr or None,
                    })
                    if chaddr:
                        _mac_to_ip(chaddr, yiaddr)
            if chaddr and (hostname or os_hint or vendor or dev):
                with _PASSIVE_LOCK:
                    rec = _passive_shared["by_mac"].setdefault(
                        chaddr, {"hostname": None, "os_guess": None,
                                 "device_type": None, "vendor": None,
                                 "port_id": None, "last_seen": 0.0})
                    _passive_record(rec, {
                        "hostname": hostname or None, "os_guess": os_hint,
                        "device_type": dev, "vendor": vendor,
                    })
                    _guard = True

        # DHCPv6: Android/iOS negotiate IPv6 DNS by multicasting SOLICIT/REQUEST
        # (ff02::1:2, src ff02::1:2/port 547) to the router - visible to any
        # listener on the L2, unlike unicast DHCPv4 renewals. The Client-FQDN
        # option (39) is the very hostname the router's DHCP table shows.
        if pkt.haslayer("UDP"):
            udp6 = pkt["UDP"]
            if udp6.dport == 547:
                try:
                    fqdn = _parse_dhcp6_fqdn(bytes(udp6.payload))
                except Exception:
                    fqdn = None
                if fqdn:
                    eth6 = pkt.getlayer(Ether)
                    mac6 = (eth6.src or "").lower() if eth6 else ""
                    if mac6 and "ff" * 3 != mac6:
                        with _PASSIVE_LOCK:
                            rec = _passive_shared["by_mac"].setdefault(
                                mac6, {"hostname": None, "os_guess": None,
                                       "device_type": None, "vendor": None,
                                       "port_id": None, "last_seen": 0.0})
                            _passive_record(rec, {"hostname": fqdn})
                            _guard = True

        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            src_mac = (eth.src or "").lower()
            if eth.type == 0x88CC and src_mac and "ff" * 3 != src_mac:
                info = _parse_lldp(bytes(eth.payload))
                if info:
                    dev = _lldp_caps_device(info.get("capabilities") or 0) if info.get("capabilities") else None
                    vendor = _sniff_vendor(info.get("system_description") or info.get("system_name") or "")
                    with _PASSIVE_LOCK:
                        rec = _passive_shared["by_mac"].setdefault(
                            src_mac, {"hostname": None, "os_guess": None,
                                      "device_type": None, "vendor": None,
                                      "port_id": None, "last_seen": 0.0})
                        _passive_record(rec, {
                            "hostname": info.get("system_name"),
                            "os_guess": info.get("system_description"),
                            "device_type": dev,
                            "vendor": vendor,
                            "port_id": info.get("port_id"),
                        })
                        _guard = True
            elif eth.dst.lower() == "01:00:0c:cc:cc:cc" and pkt.haslayer(SNAP):
                snap = pkt[SNAP]
                if getattr(snap, "code", None) == 0x2000:
                    pl = snap.payload
                    orig = getattr(pl, "original", None) or bytes(pl)
                    info = _parse_cdp(bytes(orig))
                    if info:
                        vendor = _sniff_vendor(info.get("platform") or info.get("software") or "")
                        os_hint = info.get("software") or None
                        with _PASSIVE_LOCK:
                            rec = _passive_shared["by_mac"].setdefault(
                                src_mac, {"hostname": None, "os_guess": None,
                                          "device_type": None, "vendor": None,
                                          "port_id": None, "last_seen": 0.0})
                            _passive_record(rec, {
                                "hostname": info.get("device_id"),
                                "os_guess": os_hint,
                                "device_type": "switch" if vendor else None,
                                "vendor": vendor,
                                "port_id": info.get("port_id"),
                            })
                            _guard = True
        # Promote MAC-keyed fingerprints (CDP/LLDP/DHCP) to the IP we now know
        # they map to, so scans can name the gear even without nmap answering.
        if _guard:
            with _PASSIVE_LOCK:
                for ip, mac in list(_passive_shared.get("_mac2ip", {}).items()):
                    e = _passive_shared["by_mac"].get(mac)
                    if e:
                        _passive_record(_passive_shared["by_ip"].setdefault(
                            ip, {"hostname": None, "os_guess": None,
                                 "device_type": None, "vendor": None,
                                 "mac": None, "last_seen": 0.0}),
                            e)
    except Exception:
        pass


def _mac_to_ip(mac: str, ip: str):
    m = (mac or "").lower()
    if m and ("ff" * 3) != m and not _passive_shared.get("_mac2ip", {}).get(m):
        _passive_shared.setdefault("_mac2ip", {})[m] = ip


def _passive_observe(duration: float, subnets: List[str], iface: Optional[str]):
    """Sniff one window of DHCP/ARP/CDP/LLDP traffic and fold results into the
    shared map. Best-effort: any platform/permission error just disables it."""
    global _passive_sniffer_ok, _passive_sniffer_noted
    try:
        from scapy.all import sniff
    except Exception:
        _passive_sniffer_ok = False
        if not _passive_sniffer_noted:
            _passive_sniffer_noted = True
            print("[agent] passive fingerprinter OFF - 'pip install scapy' to enable", file=sys.stderr)
        return

    filters = [
        "arp or (udp and (port 67 or port 68 or port 547)) or (ether proto 0x88cc) or (ether dst 01:00:0c:cc:cc:cc)",
        "arp or udp or ether proto 0x88cc",
        None,
    ]
    last_err = None
    for filt in filters:
        try:
            sniff(iface=iface, filter=filt, prn=lambda p: _passive_packet(p, subnets),
                  store=0, timeout=max(1, int(duration)))
            _passive_sniffer_ok = True
            return
        except Exception as e:
            last_err = e
    _passive_sniffer_ok = False
    if not _passive_sniffer_noted:
        _passive_sniffer_noted = True
        print(f"[agent] passive fingerprinter unavailable (permissions/interface): {last_err}", file=sys.stderr)


def _run_passive_sweeper(subnets: List[str], duration: float = 12.0, gap: float = 3.0,
                         stop_evt=None, iface: Optional[str] = None):
    """Background thread: continuously sniff passive fingerprints and accumulate
    them into the shared map. Runs until stop_evt is set (or forever if None)."""
    while True:
        if stop_evt and stop_evt.is_set():
            return
        try:
            _passive_observe(duration, subnets, iface)
        except Exception:
            pass
        if gap > 0:
            try:
                time.sleep(gap)
            except Exception:
                return


def passive_snapshot() -> dict:
    """Copy of the shared map, keyed for scan-time merging:
    {"by_ip": {ip: {...hints...}}, "by_mac": {mac: {...hints...}}}"""
    with _PASSIVE_LOCK:
        return {
            "by_ip": {ip: {k: v for k, v in e.items()} for ip, e in _passive_shared["by_ip"].items()},
            "by_mac": {m: {k: v for k, v in e.items()} for m, e in _passive_shared["by_mac"].items()},
        }


_RA_NUDGE_LOCK = threading.Lock()
_RA_NUDGE_LAST = 0.0


def _dhcp6_nudge(iface: Optional[str], min_gap_s: float = 90.0) -> bool:
    """Multicast a Router Advertisement with the M (Managed-config) flag to
    ff02::1 so IPv6-aware hosts run DHCPv6. Their SOLICIT/REQUEST (multicast,
    UDP 547) is captured by the passive sniffer, which extracts the
    Client-FQDN option - the same hostname the router's DHCP table shows but
    which unicast DHCPv4 renewals hide. routerlifetime=0 + no prefix info means
    hosts never adopt us as a gateway (our routing tables stay untouched).
    Rate-limited to one burst per min_gap_s across the whole agent."""
    global _RA_NUDGE_LAST
    try:
        with _RA_NUDGE_LOCK:
            now = time.time()
            if now - _RA_NUDGE_LAST < min_gap_s:
                return False
            _RA_NUDGE_LAST = now
    except Exception:
        return False
    try:
        from scapy.all import Ether, IPv6, ICMPv6ND_RA, sendp, get_if_hwaddr
    except Exception:
        return False
    try:
        if not iface:
            return False
        mac = get_if_hwaddr(iface)
        pkt = (Ether(src=mac, dst="33:33:00:00:00:01") /
               IPv6(src="fe80::1", dst="ff02::1", nh=58, hlim=255) /
               ICMPv6ND_RA(routerlifetime=0, chlim=64, M=1))
        for _ in range(3):
            sendp(pkt, iface=iface, verbose=0)
            time.sleep(1.0)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
def main():
    parser = argparse.ArgumentParser(description="LAN scanner agent for SubNex")
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

    # Passive Scapy fingerprinter (optional): DHCP/ARP/CDP/LLDP evidence on a
    # daemon thread, exactly like the mDNS sweeper. Requires `pip install scapy`
    # plus Npcap (Windows) / raw-socket privileges (Linux); degrades to
    # active-only silently when unavailable.
    try:
        passive_iface = _pick_passive_iface(subnets)
        if passive_iface:
            psweeper = _th.Thread(target=_run_passive_sweeper, kwargs={
                "subnets": subnets, "duration": 12.0, "gap": 3.0,
                "iface": passive_iface,
            }, daemon=True)
            psweeper.start()
            caps.append("passive")
            print(f"[agent] passive fingerprinter running on '{passive_iface}'")
        else:
            print("[agent] Scapy available but no interface on target subnets; passive off")
    except Exception as e:
        print(f"[agent] passive fingerprinter disabled: {e} (pip install scapy to enable)")

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