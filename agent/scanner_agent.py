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
import os
import re
import shlex
import shutil
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

VERSION = "0.2.0"


class RemoteAuthError(RuntimeError):
    """The server rejected the agent credentials (401/403).

    After the user rotates the key in the web UI, the next heartbeat is
    rejected; the agent redeems the new key via /key/sync with the old one."""


def _key_file() -> str:
    return os.path.join(os.path.expanduser("~"), ".subnex", "agent_key")


def _write_disk_key(key: str) -> None:
    try:
        dirpath = os.path.dirname(_key_file())
        os.makedirs(dirpath, exist_ok=True)
        with open(_key_file(), "w", encoding="utf-8") as fh:
            fh.write(key.strip())
    except Exception as e:
        print(f"[agent] could not persist API key to {_key_file()}: {e}")
    else:
        print(f"[agent] API key persisted to {_key_file()}")

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
            code = e.code
            detail = e.read().decode("utf-8", "replace")[:200]
            if code in (401, 403):
                raise RemoteAuthError(f"HTTP {code}: {detail}") from e
            raise RuntimeError(f"HTTP {code}: {detail}") from e

    def sync_key(self, agent_id: str) -> str:
        """Redeem the new API key using the (already-revoked) old one.

        Called when the server rotated the key in the UI: the old key is dead
        against the DB instantly, but the pending rotation record lets exactly
        this key fetch the replacement during the 5-minute grace window."""
        url = f"{self.server}/api/agents/key/sync?agent_id={agent_id}"
        req = urllib.request.Request(url, data=b"", method="POST")
        req.add_header("X-Api-Key", self.api_key)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            res = json.loads(resp.read())
        new_key = res.get("api_key") if isinstance(res, dict) else None
        if not new_key:
            raise RuntimeError("key sync returned no api_key")
        return new_key

    def persist_key(self, key: str) -> None:
        self.api_key = key
        _write_disk_key(key)

    def fetch_script(self) -> str:
        """Download the current server-side scanner_agent.py for self-update."""
        url = f"{self.server}/api/agents/script"
        req = urllib.request.Request(url)
        req.add_header("X-Api-Key", self.api_key)
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read().decode("utf-8")

    def heartbeat(self, subnets: List[str], capabilities: List[str], hostname: str, os: str):
        res = self._request("POST", "/api/agents/heartbeat", {
            "version": VERSION, "hostname": hostname, "os": os,
            "subnets": subnets, "capabilities": capabilities,
        })
        if res and res.get("agent_id"):
            self.agent_id = res["agent_id"]
        return res

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
    ("_meshcop", "router"),                              # Thread border router
    ("_device-info", "mobile"),                          # phone/tablet display name + model
    ("_apple-mobdev2", "mobile"),                        # iPhone proximity
    ("_googlecast", "iot"),                              # cast-capable display/TV
    ("_amzn-wplay", "iot"),
    ("_spotify-connect", "iot"),
    ("_sonos", "iot"),
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
    records its attributes. Pure query packets are skipped - a `_googlecast`
    QUERY means the sender is a casting *client* (phone/laptop app hunting for
    a receiver), which is not a type signal we can safely act on."""
    if len(data) < 12:
        return None
    try:
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    except Exception:
        return None
    if an + ar == 0:
        return None  # pure query, no device facts
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
    if not dev:
        dev = _type_from_hostname(hostname)
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


def _scripts_for_ports(ports: list, discovery: bool = False) -> str:
    """Pick nmap scripts from the ports actually open, so HTTP enumeration only
    runs where a web service listens, RTSP only on stream ports, and SMB
    discovery on Windows file shares (also the main source of Windows
    hostnames). 'default' always runs and targets each service itself.

    In discovery-only mode the heavyweight findings scripts (http-enum's
    directory walk, http-methods, http-headers, http-generator) are dropped -
    they exist purely to enrich findings/risk rules which are OFF there - while
    the identity-bearing ones (http-title, http-server-header, smb-os-discovery,
    nbstat, rtsp-methods) are kept because they feed os_guess/device_type/
    hostname. This is the main speedup for a discovery-only sweep."""
    s = ["default"]
    if any(int(p) in HTTP_PORTS for p in ports):
        s += ["http-title", "http-server-header"]
        if not discovery:
            s += ["http-methods", "http-headers", "http-generator", "http-enum"]
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
                yield (it, {})


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
    mode = task.get("mode") or "standard"
    _set_runtime_workers(task)

    if not targets:
        client.log(task_id, "Task rejected: no valid targets provided", level="err")
        try:
            client.result(task_id, [], status="failed", notes="invalid targets")
        except Exception:
            pass
        return

    client.log(task_id, f"=== Agent scan started (scan={scan_id}, targets={', '.join(targets)}) ===")
    client.log(task_id, f"Phase 1/3: L2/ARP discovery -> live hosts + MAC/vendor", level="out")
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
        client.log(task_id, "DHCPv6 RA nudge sent (M flag) - asking clients to reveal names", level="out")

    # Passive evidence harvested between scans (DHCP / ARP / CDP / LLDP / SSDP /
    # NetBIOS). MAC-keyed fingerprints (network gear announcing itself via
    # CDP/LLDP, DHCP on privacy MACs) are cross-referenced onto the IPs ARP
    # discovery just resolved (the fold below runs once live hosts are known,
    # after Phase 1).
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
        if not h.get("device_type") and h.get("hostname"):
            _t = _type_from_hostname(h.get("hostname"))
            if _t:
                h["device_type"] = _t
        return h

    # ---- Phase 1/3: ARP (L2) discovery -> live hosts + MAC/vendor -------------
    live = {}
    for t in targets:
        if not _await_go(client, task_id):
            client.log(task_id, "Scan stopped by user", level="warn")
            return
        args = [
            "nmap", "-sn", "-n", "-oX", "-",
            "--max-retries", "1", "--host-timeout", "40s",
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
        client.log(task_id, f"Phase 1/3: {len(passive_by_ip)} passive fingerprint(s) folded from DHCP/ARP/CDP/LLDP/SSDP/NetBIOS", level="out")

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

    # Backfill: the continuous ARP sweeper's cache is cross-checked to the
    # scope's candidate IPs only - it cannot leak an out-of-scope host in.
    arp_cache = _arp_snapshot()
    if arp_cache:
        cached = {ip for ip in arp_cache if in_scope(ip) and ip not in live}
        cached -= set(mdns_hints.keys()) | set(passive_by_ip.keys())
    else:
        cached = set()
    if cached:
        client.log(task_id, f"Phase 1/3: {len(cached)} host(s) resurrected from ARP liveness cache: {', '.join(sorted(cached))}", level="out")
        for ip in cached:
            live[ip] = {"ip": ip, "mac": arp_cache[ip].get("mac"),
                        "vendor": arp_cache[ip].get("vendor"),
                        "hostname": None, "state": "up"}

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
    open_ports = {}  # ip -> [portid]
    if mode == "discovery":
        client.log(task_id, "Discovery-only mode: full ARP + L3/TCP probing + banner grabbing + OS fingerprint (no findings)", level="out")
    client.log(task_id, f"Phase 2/3: fast port scan ({scan_type}) on {len(live)} host(s), {_p2_workers()} parallel worker(s)", level="out")

    def _p2_worker(ip_meta):
        ip, _meta = ip_meta
        if not _await_go(client, task_id):
            return None
        args = [
            "nmap", scan_type, "-n", "-p", port_range, "--open",
            timing, "--max-retries", "1", "--host-timeout", "30s", "-oX", "-", str(ip),
        ]
        client.log(task_id, f"$ {' '.join(args)}", level="cmd")
        xml = run_nmap(args)
        return _parse_open_ports(xml)

    p2_done = 0
    p2_total = max(len(live), 1)
    for (ip, _meta), res in _map_hosts(_p2_worker, list(live.items()),
                                       _p2_workers(), client, task_id, "port-scan"):
        if res is None:
            client.log(task_id, "Scan stopped by user", level="warn")
            break
        found = res
        open_ports[ip] = found
        p2_done += 1
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
    client.log(task_id, f"Phase 3/3: -sV -O fingerprint (ports) / -O (OS-only for no-port hosts), {PHASE3_WORKERS} parallel worker(s)", level="out")

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
            args = ["nmap", "-O", "--osscan-guess", "-n",
                    fp_timing, "--max-retries", "1", "--host-timeout", "60s", str(ip), "-oX", "-"]
            client.log(task_id, f"$ {' '.join(args)}", level="cmd")
            xml = run_nmap(args)
            host = parse_host_xml(xml)
            if host and (host.get("os_confidence") or 0) < OS_ONLY_CONF_FLOOR:
                host.pop("os_guess", None)
                host.pop("os_confidence", None)
            # An unparseable/empty result means "no data for THIS host", NOT a
            # user stop. Return {} so the phase loop keeps going and only a real
            # `_await_go` failure surfaces as None (which the loop treats as stop).
            return host or {}
        args = (
            ["nmap", scan_type, "-n", *([] if mode == "discovery" else ["-sV"]), "-O", "-p", ",".join(ports), "--open",
             fp_timing, *shlex.split(f"--script {_scripts_for_ports(ports, discovery=(mode == 'discovery'))}"),
             "--max-retries", "1", "--host-timeout", "90s", str(ip), "-oX", "-"]
        )
        client.log(task_id, f"$ {' '.join(args)}", level="cmd")
        xml = run_nmap(args)
        return parse_host_xml(xml) or {}

    p3_done = 0
    p3_total = max(len(live), 1)
    for (ip, meta), res in _map_hosts(_p3_worker, list(live.items()),
                                      PHASE3_WORKERS, client, task_id, "fingerprint"):
        if res is None:
            client.log(task_id, "Scan stopped by user", level="warn")
            break
        host = res
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
    # Refresh mDNS evidence too: the never-ending sweeper keeps folding
    # query-side service hints (e.g. `_googlecast` from cast devices) all scan
    # long, so Phase-0's snapshot is stale by the time we report.
    mdns_hints = mdns_snapshot()
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
                    profile: str = "quick", discovery: bool = False):
    """Run -sV -O + scripts on the given open ports of a host and post the
    result as a partial update so the server merges it live."""
    scan_type = "-sT" if use_connect else "-sS"
    timing = PROBE_TIMING.get(profile, "-T4")
    ports = ([int(x) for x in ports_spec.split(",")] if ports_spec else [])
    args = (
        ["nmap", scan_type, "-n", *([] if discovery else ["-sV"]),
         "-O", "-p", ports_spec, "--open",
         timing, *shlex.split(f"--script {_scripts_for_ports(ports, discovery=discovery)}"),
         "--max-retries", "1", "--host-timeout", "90s", ip, "-oX", "-"]
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
    mode = task.get("mode") or "standard"
    rv = task.get("reverify") or {}
    down_ips = [ip for ip in (rv.get("down_ips") or []) if _valid_target(ip)]
    up_ips = [ip for ip in (rv.get("up_ips") or []) if _valid_target(ip)]
    already_ports = _sane_port_range(rv.get("already_ports") or "1-65535")
    _set_runtime_workers(task)
    # The component range(s) to sweep: complement of what was already checked.
    sweep_spec = _leftover_ports_spec(_range_to_ports_set(already_ports))

    # Live progress ladder: each ACTIVE re-verify phase owns an equal slice of
    # the 2..98 band, so the server's max-guarded progress tracks the real
    # re-verify flow (new-host check -> down re-check -> leftover sweep) instead
    # of sitting still and jumping to 100 at the end.
    _plan = []
    if rv.get("check_new_hosts"):
        _plan.append("new_hosts")
    if down_ips:
        _plan.append("down")
    if sweep_spec and up_ips:
        _plan.append("sweep")
    _slice = 96.0 / max(1, len(_plan))
    _pbands = {p: (2 + i * _slice, 2 + (i + 1) * _slice) for i, p in enumerate(_plan)}

    def _rv_pct(phase: str, frac: float, lo_off: float = 0.0, hi_off: float = 1.0) -> int:
        lo, hi = _pbands.get(phase, (2, 98))
        a = lo_off + (hi_off - lo_off) * frac
        return min(99, int(lo + (hi - lo) * min(1.0, max(0.0, a))))

    def _rv_phase_end(phase: str) -> int:
        lo, hi = _pbands.get(phase, (2, 98))
        return int(hi)

    def _post_rv_progress(pct: int):
        try:
            client.result(task_id, [], status="partial", notes="progress", progress=min(99, max(2, int(pct))))
        except Exception:
            pass

    client.log(task_id, f"=== Agent re-verify started (scan={scan_id}) ===")
    client.log(task_id, f"  down hosts to re-check: {len(down_ips)}, up hosts to sweep: {len(up_ips)}, leftover ports: {sweep_spec or 'none'}")
    if _plan:
        _post_rv_progress(2)

    # ---- Phase 0: check for NEW hosts (optional, ARP discovery) ----
    # Re-discovers the targets at L2 and registers hosts that were not part of
    # the previous scan. New hosts have no prior port data, so they get the FULL
    # pipeline (discovery -> port scan -> deep fingerprint), unlike the delta
    # re-checks below which reuse the scanned state.
    known_ips = set(down_ips) | set(up_ips)
    new_hosts_up = []
    if rv.get("check_new_hosts"):
        if not _await_go(client, task_id):
            return
        scan_type_0 = "-sT" if use_connect else "-sS"
        timing_0 = PROBE_TIMING.get(profile, "-T4")
        client.log(task_id, "Phase 0: host discovery -> NEW hosts not in the previous scan")
        _post_rv_progress(_rv_pct("new_hosts", 0.04))
        new_live = {}
        for t in (task.get("targets") or []):
            if not _valid_target(t):
                continue
            args = ["nmap", "-sn", "-n", "-oX", "-", "--max-retries", "1",
                    "--host-timeout", "40s", "--min-hostgroup", "256", t]
            client.log(task_id, f"$ {' '.join(args)}", level="cmd")
            xml = run_nmap(args)
            for h in parse_discovery(xml):
                if h.get("state") == "up" and h.get("ip") not in known_ips:
                    new_live.setdefault(h["ip"], h)
        # Fold the ARP liveness cache for in-scope addresses ARP -sn missed
        scope_nets = []
        for t in (task.get("targets") or []):
            try:
                scope_nets.append(ipaddress.ip_network(t, strict=False))
            except Exception:
                pass
        arp_cache = _arp_snapshot()
        for ip, entry in arp_cache.items():
            if ip in known_ips or ip in new_live:
                continue
            if scope_nets and not any(ipaddress.ip_address(ip) in n for n in scope_nets):
                continue
            new_live[ip] = {"ip": ip, "mac": entry.get("mac"),
                            "vendor": entry.get("vendor"), "state": "up"}
        if not new_live:
            client.log(task_id, "Phase 0: no new hosts found - inventory unchanged")
            _post_rv_progress(_rv_phase_end("new_hosts"))
        else:
            client.log(task_id, f"Phase 0: {len(new_live)} new host(s) found: {', '.join(sorted(new_live))}", level="out")
            if not _await_go(client, task_id):
                return
            full_range = _sane_port_range(task.get("port_range") or "1-10000")
            client.log(task_id, f"Phase 0: full port scan ({scan_type_0} -p {full_range}) + fingerprint on new host(s), {_p2_workers()} parallel worker(s)")

            def _new_host_worker(ip_meta):
                ip, meta = ip_meta
                if not _await_go(client, task_id):
                    return None
                p_args = ["nmap", scan_type_0, "-n", "-p", full_range, "--open", timing_0,
                          "--max-retries", "1", "--host-timeout", "45s", "-oX", "-", ip]
                client.log(task_id, f"$ {' '.join(p_args)}", level="cmd")
                pxml = run_nmap(p_args)
                found = _parse_open_ports(pxml)
                if not found:
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
                                       ",".join(found), use_connect, profile,
                                       discovery=(mode == "discovery")) or {"ip": ip, "ports": []}

            _new_done = 0
            _new_total = max(len(new_live), 1)
            for (ip, _meta), host in _map_hosts(_new_host_worker, [(a["ip"], a) for a in new_live.values()],
                                                _p2_workers(), client, task_id, "new-host-scan"):
                if host is None:
                    client.log(task_id, "Scan stopped by user", level="warn")
                    break
                new_hosts_up.append(ip)
                _new_done += 1
                _post_rv_progress(_rv_pct("new_hosts", 0.05 + 0.95 * (_new_done / _new_total)))
                client.log(task_id, f"  {ip}: {len(host.get('ports', []))} open port(s)")
            _post_rv_progress(_rv_phase_end("new_hosts"))

    # ---- Phase A: re-check previously-down hosts via L2/ARP ----
    newly_up = []
    if down_ips:
        if not _await_go(client, task_id):
            return
        client.log(task_id, f"$ nmap -sn {' '.join(down_ips)} (ARP re-check of down hosts)", level="cmd")
        _post_rv_progress(_rv_pct("down", 0.04))
        args = ["nmap", "-sn", "-oX", "-", "--host-timeout", "60s", *down_ips]
        xml = run_nmap(args)
        alive = []
        for h in parse_discovery(xml):
            if h.get("state") == "up":
                alive.append(h)
        client.log(task_id, f"  {len(alive)} previously-down host(s) now responding")
        _post_rv_progress(_rv_pct("down", 0.35))
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
                                   ",".join(found), use_connect, profile,
                                   discovery=(mode == "discovery")) or {"ip": ip, "ports": []}

        _down_done = 0
        _down_total = max(len(alive), 1)
        for (ip, _meta), host in _map_hosts(_rv_down_worker, [(a["ip"], a) for a in alive],
                                            _p2_workers(), client, task_id, "re-verify-up"):
            if host is None:
                client.log(task_id, "Scan stopped by user", level="warn")
                break
            newly_up.append(ip)
            _down_done += 1
            _post_rv_progress(_rv_pct("down", 0.35 + 0.65 * (_down_done / _down_total)))
            client.log(task_id, f"  {ip}: {len(host.get('ports', []))} open port(s)")
        _post_rv_progress(_rv_phase_end("down"))

    # ---- Phase B: sweep unscanned ports on the up hosts (parallel) ----
    if sweep_spec and up_ips:
        if not _await_go(client, task_id):
            return
        scan_type_b = "-sT" if use_connect else "-sS"
        timing_b = PROBE_TIMING.get(profile, "-T4")
        client.log(task_id, f"Phase B: sweeping unscanned ports {sweep_spec} on {len(up_ips)} up host(s), {_p2_workers()} parallel worker(s)")
        _post_rv_progress(_rv_pct("sweep", 0.05))

        def _rv_sweep_worker(ip_meta):
            ip, _meta = ip_meta
            if not _await_go(client, task_id):
                return None
            args = ["nmap", scan_type_b, "-n", "-p", sweep_spec, "--open", timing_b,
                    "--max-retries", "1", "--host-timeout", "45s", "-oX", "-", ip]
            client.log(task_id, " ".join(args), level="cmd")
            pxml = run_nmap(args)
            found = _parse_open_ports(pxml)
            if found:
                _deep_scan_host(client, task_id, ip, {"mac": None, "vendor": None},
                                ",".join(found), use_connect, profile,
                                discovery=(mode == "discovery"))
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
            _post_rv_progress(_rv_pct("sweep", 0.05 + 0.95 * (leftover_done / leftover_total)))
        _post_rv_progress(_rv_phase_end("sweep"))

    # ---- Finalise ----
    try:
        client.result(task_id, [], status="completed",
                      notes=f"reverify={uuid.uuid4()}")
    except Exception as e:
        client.log(task_id, f"Final result post failed: {e}", level="err")
    client.log(task_id, f"=== Agent re-verify done: {len(newly_up)} host(s) recovered, report merged ===")


# --------------------------------------------------------------------------- #
# Passive fingerprinting (optional Scapy: DHCP / ARP / CDP / LLDP / SSDP / NetBIOS)
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
#   * SSDP / UPnP (UDP 1900) - smart TVs/media/IoT announce themselves with a
#     SERVER header and a LOCATION URL; the friendly name behind it is fetched
#     best-effort. Devices in AP-isolation that block every active probe still
#     answer multicast here.
#   * NetBIOS (UDP 137) - Windows hosts register <00>/<03>/<20> names from
#     their own IP, naming them with zero ports open.
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
    ("android",             "Android (DHCP VCI)",         None,       "mobile"),
    ("ios",                 "Apple iOS (DHCP VCI)",         "Apple",    "mobile"),
    ("macos",               "Apple macOS (DHCP VCI)",       "Apple",    None),
    ("darwin",              "Apple macOS (DHCP VCI)",       "Apple",    None),
    ("udhcpc",              "Linux (udhcpc DHCP)",          None,       None),
    ("udhcp",               "Linux (udhcpc DHCP)",          None,       None),
    ("dhcpcd",              "Linux/BSD (dhcpcd DHCP)",      None,       None),
    ("linux",               "Linux (DHCP VCI)",             None,       None),
]


# Hostname prefixes -> coarse device_type. With randomised MACs erasing the OUI
# and filtered TCP killing port classification, the device's own name is often
# the ONLY surviving type signal (Windows `DESKTOP-XX`, Android `Android_XXX`,
# Samsung `SM-XXX`, Apple `iPhone-XX`...). Applied as a fill-if-blank fallback
# everywhere a hostname is folded in (mDNS/DHCP/NBNS), so it never overrides a
# service/VCI-derived type. Checked in order, most specific first.
_HOSTNAME_TYPE_RULES = [
    (("DESKTOP-", "LAPTOP-", "PC-", "WIN-", "WIN10", "WIN11", "WINDOWS"), "workstation"),
    (("IPHONE-", "IPAD-", "IPOD-", "IOS-"),                              "mobile"),
    (("ANDROID", "SM-", "GALAXY", "PIXEL", "REDMI", "MI-", "MI_",
      "HUAWEI-", "ONEPLUS", "OPPO-", "VIVO-", "XIAOMI-", "NOKIA-"),   "mobile"),
    (("MACBOOK", "IMAC-", "MAC-"),                                      "workstation"),
    (("UBUNTU-", "FEDORA-", "DEBIAN-", "KALI-", "LINUX-"),              "workstation"),
    (("ESP32", "ESP-", "ESP_", "TASMOTA", "SHELLY", "SONOFF", "HOMEBRIDGE"), "iot"),
    (("PRINTER", "EPSON", "CANON-", "BROTHER", "PIXMA", "MP-", "TS-",
      "HL-", "MFC-", "SCX-"),                                           "printer"),
    (("SYNOLOGY", "QNAP-", "NAS-", "ZYXEL"),                            "nas"),
    (("ROUTER", "ROUTEUR", "GATEWAY", "OPENWRT", "MIKROTIK"),
                                                                         "network_gear"),
    (("CHROMECAST", "APPLE-TV", "ANDROIDTV", "ANDROID-TV", "SMART-TV",
      "SAMSUNGTV"),                                                     "iot"),
    (("SERVER", "SRV-", "NS1", "DC-"),                                  "server"),
]

# DHCP option 55 (Parameter Request List) fingerprints -> (os_guess, device_type).
# The set+order of options a client demands reliably reveals its OS/family even
# with a randomised MAC (the same table Fing/Fingerbank use). Stored as the
# option codes; matched as an ordered subsequence of the observed PRL so extra
# options the OS adds don't defeat the match. Longest matching signature wins.
_DHCP_PRL_RULES = [
    ((1, 15, 3, 6, 44, 46, 47, 31, 33, 43),                "Windows 7", "workstation"),
    ((1, 3, 6, 15, 44, 46, 47, 31, 33, 121, 249, 43),      "Windows 8/10", "workstation"),
    ((1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43),      "Windows 8/10", "workstation"),
    ((1, 3, 6, 15, 119, 252, 26, 28, 43),                  "iOS/macOS", "mobile"),
    ((1, 3, 6, 15, 119, 26, 28, 43),                       "macOS", "workstation"),
    ((1, 3, 28, 2, 6, 15, 119, 26, 121, 42, 51, 54, 43),   "Android", "mobile"),
    ((1, 3, 6, 15, 26, 28, 51, 58, 59, 12),                "Linux (dhclient)", "workstation"),
    ((1, 3, 6, 12, 15, 119, 51, 0, 45, 43),                "Linux", "workstation"),
]


def _type_from_hostname(name: Optional[str]) -> Optional[str]:
    """Coarse device_type from a hostname prefix family (fallback only)."""
    if not name:
        return None
    up = name.strip().upper()
    if not up or len(up) < 2:
        return None
    for prefixes, kind in _HOSTNAME_TYPE_RULES:
        for p in prefixes:
            if up.startswith(p):
                return kind
    return None


def _prl_hint(prl: list) -> (Optional[str], Optional[str]):
    """Longest ordered-subsequence PRL fingerprint -> (os_guess, device_type)."""
    if not prl:
        return None, None
    observed = tuple(int(x) for x in prl if isinstance(x, int) or str(x).isdigit())
    if not observed:
        return None, None

    def _is_subsequence(sig, seq):
        it = iter(seq)
        return all(e in it for e in sig)

    best_os, best_dev, best_len = None, None, 0
    for sig, os_g, dev in _DHCP_PRL_RULES:
        if len(sig) > best_len and _is_subsequence(sig, observed):
            best_os, best_dev, best_len = os_g, dev, len(sig)
    return best_os, best_dev


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
    """Extract (hostname, vendor_class_id, param_req_list) from Scapy BOOTP.options."""
    hostname = vci = None
    prl = []
    for opt in options or ():
        if not (isinstance(opt, tuple) and len(opt) >= 2):
            continue
        key = opt[0]
        val = opt[1]
        if key == "hostname" and not hostname:
            hostname = _clean_str(val if isinstance(val, bytes) else str(val).encode())
        elif key == "vendor_class_id" and not vci:
            vci = _clean_str(val if isinstance(val, bytes) else str(val).encode(), limit=64)
        elif key in (55, "param_req_list", "parameter_request_list") and not prl:
            # DHCP option 55: the option codes this client is asking for, in
            # order - the classic OS/device fingerprinting channel that works
            # even when the MAC is randomised and TCP is filtered.
            if isinstance(val, (bytes, bytearray)):
                prl = list(val)
            elif isinstance(val, (list, tuple)):
                prl = list(val)
        elif key in (81, "client_fqdn", "fqdn", "option_81") and not hostname:
            # RFC 4702 client FQDN: flags(1) + keytag(1) + name (DNS wire).
            h = _parse_fqdn_option(val if isinstance(val, bytes) else b"")
            if h:
                hostname = h
    return hostname, vci, prl


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
        return "router"
    if caps & (1 << 2):
        return "switch"
    if caps & (1 << 7):
        return "workstation"
    return None


# --------------------------------------------------------------------------- #
# SSDP / UPnP (UDP 1900) + NetBIOS (UDP 137) passive discovery
#
# Two more "wake-up-only" channels Fing-style discovery feeds on:
#   * SSDP - smart TVs, media renderers, routers and IoT send NOTIFY/multicast
#     M-SEARCH announcements with a unique service name, a SERVER header (OS
#     fingerprint) and a LOCATION URL -> the friendly name in the device
#     description XML. Devices that block ICMP/ARP-ping still announce here.
#   * NetBIOS - Windows hosts send name REGISTRATION/QUERY frames (workstation
#     <00>, file-server <20>, messenger <03>) whose source reveals the machine
#     name and its own IP without any port needing to be open.
# --------------------------------------------------------------------------- #
_SSDP_TYPE_HINTS = [
    ("mediarenderer", "iot"),
    ("mediaserver", "iot"),
    ("mediaplayer", "iot"),
    ("tvdevice", "iot"),
    ("scheduledrecording", "media"),
    ("internetgatewaydevice", "router"),
    ("windevice", "router"),
    ("printerdevice", "printer"),
    ("scannerdevice", "printer"),
    ("scanner", "printer"),
]

# NetBIOS name-suffix byte -> coarse device_type.
_NB_SUFFIX_TYPE = {0x00: "workstation", 0x03: "workstation",
                   0x20: "server", 0x1b: "server", 0x1c: "server"}

_SSDP_LOCK = threading.Lock()
_ssdp_pending = {}   # src_ip -> {"location": str, "last_fetch": float}
_ssdp_known = {}     # location url -> friendly name (persist across windows)


def _parse_ssdp(data: bytes) -> dict:
    """Parse an SSDP notify/response body -> {os_guess, device_type, location}."""
    txt = data.decode("utf-8", "replace")
    out = {"os_guess": None, "device_type": None, "location": None}
    for line in txt.splitlines():
        head, _, rest = line.partition(":")
        k = head.strip().lower()
        v = rest.strip()
        if not v:
            continue
        if k == "location":
            out["location"] = v
        elif k == "server" and not out["os_guess"]:
            out["os_guess"] = " ".join(v.split())[:120]
        elif k in ("st", "nt"):
            vl = v.lower()
            for key, dev in _SSDP_TYPE_HINTS:
                if key in vl:
                    out["device_type"] = dev
                    break
    return out


def _decode_nb_name(raw: bytes):
    """16-byte NetBIOS node-name field -> (name, suffix_byte) or (None, None)."""
    if len(raw) < 16:
        return None, None
    ln = raw[0]
    if not (0 < ln <= 15):
        return None, None
    name = raw[1:1 + ln].decode("utf-8", "replace")
    return name, raw[15]


def _nbns_packet_info(data: bytes) -> dict:
    """Parse an NBNS (UDP/137) payload.

    Returns {"self_names": [(name, suffix)], "ip_names": {owner_ip: [(name, suffix)]}}.
    Registration/query packets (QR=0) name the SENDER; response answers carry a
    4-6 byte owner IP in RDATA that names that owner."""
    res = {"self_names": [], "ip_names": {}}
    try:
        if len(data) < 12:
            return res
        _tid, flags, qd, an, ns_cnt, ar_cnt = struct.unpack(">HHHHHH", data[:12])
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        off = 12

        def _read_name():
            nonlocal off
            if off + 16 > len(data):
                return None
            r = _decode_nb_name(data[off:off + 16])
            off += 16
            return r

        def _read_question():
            nonlocal off
            if off + 20 > len(data):
                return None
            r = _read_name()
            if r is None:
                return None
            ntype, _nclass = struct.unpack(">HH", data[off:off + 4])
            off += 4
            return r[0], r[1], ntype

        def _read_answer():
            nonlocal off
            if off + 26 > len(data):
                return None
            r = _read_name()
            if r is None:
                return None
            ntype, _nclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rd = data[off:off + rdlen]
            off += rdlen
            return r[0], r[1], ntype, rd

        qrecs = []
        for _ in range(qd):
            q = _read_question()
            if q:
                qrecs.append(q)
        arecs = []
        for _ in range(an + ns_cnt + ar_cnt):
            a = _read_answer()
            if a:
                arecs.append(a)

        for name, suffix, ntype in qrecs:
            if ntype == 0x0020 and name:
                res["self_names"].append((name, suffix))
        if qr:
            for name, suffix, ntype, rd in arecs:
                if ntype != 0x0020:
                    continue
                ip = None
                if len(rd) == 4:
                    ip = socket.inet_ntoa(rd)
                elif len(rd) == 6:
                    ip = socket.inet_ntoa(rd[2:6])
                name = name.strip()
                if ip and name and not ip.startswith("255."):
                    res["ip_names"].setdefault(ip, []).append((name, suffix))
    except Exception:
        pass
    return res


def _parse_friendly_name(body: bytes) -> Optional[str]:
    """Pull <friendlyName> out of a UPnP device-description XML body."""
    try:
        m = re.search(rb"<friendlyName[^>]*>([^<]{1,200})</friendlyName>", body, re.I)
        if m:
            val = " ".join(m.group(1).decode("utf-8", "replace").split()).strip()
            return val or None
    except Exception:
        pass
    return None


def _ssdp_fetch_pending(subnets: List[str], max_fetch: int = 8):
    """Best-effort, rate-limited FETCH of pending SSDP LOCATION URLs to recover
    the friendly device name (or the model in its absence). Runs on the daemon
    sweeper thread after each sniff window, never inside the scanner hot path."""
    with _SSDP_LOCK:
        pending = [(ip, e.get("location")) for ip, e in list(_ssdp_pending.items())
                   if e.get("location") and (time.time() - e.get("last_fetch", 0)) > 300]
    if not pending:
        return
    fetched = []
    for ip, loc in pending[:max_fetch]:
        if loc in _ssdp_known:
            name = _ssdp_known[loc]
        else:
            name = None
            try:
                req = urllib.request.Request(loc, headers={"User-Agent": "SubNex-agent/0.1"})
                with urllib.request.urlopen(req, timeout=1.5) as r:
                    name = _parse_friendly_name(r.read(65536))
            except Exception:
                pass
            with _SSDP_LOCK:
                _ssdp_pending.setdefault(ip, {})["last_fetch"] = time.time()
                if name:
                    _ssdp_known[loc] = name
        if name:
            fetched.append((ip, name))
    if fetched:
        with _PASSIVE_LOCK:
            for ip, name in fetched:
                if not any(_ip_in_subnet(ip, s) for s in subnets):
                    continue
                rec = _passive_shared["by_ip"].setdefault(
                    ip, {"hostname": None, "os_guess": None,
                         "device_type": None, "vendor": None,
                         "mac": None, "last_seen": 0.0})
                _passive_record(rec, {"hostname": name})


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
        from scapy.all import ARP, BOOTP, Ether, IP, IPv6, SNAP, UDP

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
            hostname, vci, prl = _parse_dhcp_options(b.options)
            os_hint, vendor, dev = _vci_hint(vci or "")
            prl_os, prl_dev = _prl_hint(prl)
            if not os_hint and prl_os:
                os_hint = prl_os
            if not dev and prl_dev:
                dev = prl_dev
            hname_type = None if dev else _type_from_hostname(hostname)
            if hname_type:
                dev = hname_type
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

        # SSDP/UPnP (UDP 1900): smart TVs, media gear, printers and IoT announce
        # themselves with SERVER (OS) and LOCATION (-> friendly name) even when
        # they block ICMP/ARP-ping and TCP probing. NetBIOS (UDP 137): Windows
        # hosts register <00>/<03>/<20> names from their own IP.
        if pkt.haslayer(UDP):
            udp = pkt["UDP"]
            sport, dport = udp.sport, udp.dport
            if sport == 1900 or dport == 1900:
                info = _parse_ssdp(bytes(udp.payload))
                src = None
                l3 = pkt.getlayer(IP)
                if l3 is not None:
                    src = getattr(l3, "src", None)
                else:
                    l6 = pkt.getlayer(IPv6)
                    src = getattr(l6, "src", None) if l6 is not None else None
                if src and (info["os_guess"] or info["device_type"] or info["location"]):
                    eth = pkt.getlayer(Ether)
                    mac = (eth.src or "").lower() if eth else ""
                    if mac and mac != "ff" * 6:
                        _mac_to_ip(mac, src)
                    with _PASSIVE_LOCK:
                        rec = _passive_shared["by_ip"].setdefault(
                            src, {"hostname": None, "os_guess": None,
                                  "device_type": None, "vendor": None,
                                  "mac": None, "last_seen": 0.0})
                        _passive_record(rec, {
                            "os_guess": info["os_guess"],
                            "device_type": info["device_type"],
                            "mac": mac or None,
                        })
                    if info["location"]:
                        with _SSDP_LOCK:
                            _ssdp_pending.setdefault(src, {})["location"] = info["location"]
                    _guard = True
            if sport == 137 or dport == 137:
                nb = _nbns_packet_info(bytes(udp.payload))
                eth = pkt.getlayer(Ether)
                mac = (eth.src or "").lower() if eth else ""
                if nb["self_names"] or nb["ip_names"]:
                    l3 = pkt.getlayer(IP)
                    src = getattr(l3, "src", None) if l3 is not None else None
                    if not src:
                        l6 = pkt.getlayer(IPv6)
                        src = getattr(l6, "src", None) if l6 is not None else None
                    if src and mac and mac != "ff" * 6:
                        _mac_to_ip(mac, src)
                    with _PASSIVE_LOCK:
                        for name, suffix in nb["self_names"][:3]:
                            name = name.strip()
                            if not name:
                                continue
                            rec = _passive_shared["by_ip"].setdefault(
                                src, {"hostname": None, "os_guess": None,
                                      "device_type": None, "vendor": None,
                                      "mac": None, "last_seen": 0.0})
                            _passive_record(rec, {
                                "hostname": name or None,
                                "device_type": _NB_SUFFIX_TYPE.get(suffix),
                                "mac": mac or None,
                            })
                        for ip, names in nb["ip_names"].items():
                            if not any(_ip_in_subnet(ip, s) for s in subnets):
                                continue
                            name, suffix = names[0]
                            rec = _passive_shared["by_ip"].setdefault(
                                ip, {"hostname": None, "os_guess": None,
                                     "device_type": None, "vendor": None,
                                     "mac": None, "last_seen": 0.0})
                            _passive_record(rec, {
                                "hostname": name.strip() or None,
                                "device_type": _NB_SUFFIX_TYPE.get(suffix),
                            })
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


# --------------------------------------------------------------------------- #
# Active NBNS / LLMNR name-query probing (no router access needed)
#
# A sniffer only hears broadcast DISCOVER / multicast traffic on its own VLAN
# and only when targets happen to send it. Active broadcast queries close that
# gap: a NetBIOS name query (NBNS, UDP 137) broadcast reaches every host on the
# L2 segment - Windows machines answer with their computer name and MAC, and
# privacy-MAC hosts still reveal their real name this way. LLMNR (UDP 5355) is
# likewise multicast-resolved by Windows when normal DNS fails. Both are pure
# L2 broadcasts: they need no router access, no credentials, and no admin.
#
# Rather than hand-assemble DB-encoded NBNS packets (fragile, easy to send a
# malformed query), the probe reuses nmap's battle-tested `nbstat` NSE script
# over UDP 137/139 - the same mechanism nbtstat/nmblookup use online. LLMNR
# replies are captured passively: 5355 is added to the sniff filter below so
# windows which resolve by multicast announce themselves to any listener.
# Results fold through _passive_record (fill-if-blank), exactly like all other
# evidence, so scans finalize with the recovered names and MACs automatically.
# --------------------------------------------------------------------------- #
_NBNS_LOCK = threading.Lock()
_NBNS_LAST = 0.0
_NBNS_MIN_GAP = 120.0


def _nbns_probe(subnets: List[str]) -> dict:
    """One active NBNS sweep: nmap `-sU -p137 --script nbstat -Pn` asks every
    host over UDP 137 for its NetBIOS status and returns (ip, mac, name) for
    each that answers. Windows/SMB hosts reply to the status query even when
    the port looks filtered. Returns
    {ip: {"hostname": str, "mac": str}}. Best-effort: nmap missing/failing gives
    {} so this can never break a scan."""
    out = {}
    if not subnets or not shutil.which("nmap"):
        return out
    try:
        import xml.etree.ElementTree as _ET
        root = _ET.fromstring(subprocess.run(
            ["nmap", "-Pn", "-sU", "-p137", "--script", "nbstat",
             "--host-timeout", "6s", "--min-hostgroup", "256", "-oX", "-"] + subnets,
            capture_output=True, text=True, timeout=150).stdout or "")
    except Exception:
        return out
    for host_el in root.iter("host"):
        st = host_el.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip = None
        mac = None
        hostname = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
        for hostscript in host_el.iter("hostscript"):
            for scr in hostscript.findall("script"):
                if scr.get("id") != "nbstat":
                    continue
                out_txt = scr.get("output") or ""
                m = re.search(r"NetBIOS name:\s*([^\s]+)", out_txt)
                if m:
                    hostname = m.group(1)
        if ip and (hostname or mac):
            entry = out.setdefault(ip, {"hostname": None, "mac": None})
            entry["hostname"] = (hostname or "").strip() or None
            entry["mac"] = (mac or "").lower() or None
    return out


def _nbns_observe(subnets: List[str]):
    """Run one NBNS sweep and fold the results into the passive shared map,
    fill-if-blank so it augments (never overwrites) probe/SNMP evidence."""
    global _NBNS_LAST
    with _NBNS_LOCK:
        now = time.time()
        if now - _NBNS_LAST < _NBNS_MIN_GAP:
            return
        _NBNS_LAST = now
    results = _nbns_probe(subnets)
    if not results:
        return
    with _PASSIVE_LOCK:
        for ip, info in results.items():
            if not any(_ip_in_subnet(ip, s) for s in subnets):
                continue
            mac = info.get("mac")
            hostname = info.get("hostname")
            if mac:
                _mac_to_ip(mac, ip)
            _passive_record(
                _passive_shared["by_ip"].setdefault(
                    ip, {"hostname": None, "os_guess": None,
                         "device_type": None, "vendor": None,
                         "mac": None, "last_seen": 0.0}),
                {"hostname": hostname, "mac": mac})
            if mac:
                _passive_record(
                    _passive_shared["by_mac"].setdefault(
                        mac, {"hostname": None, "os_guess": None,
                              "device_type": None, "vendor": None,
                              "port_id": None, "last_seen": 0.0}),
                    {"hostname": hostname})


def _run_nbns_sweeper(subnets: List[str], gap: float = 30.0, stop_evt=None):
    """Background thread: periodically run an active NBNS (NetBIOS) sweep so that
    Windows / SMB hosts reveal their computer names + MACs even when they never
    send unsolicited multicast. Runs until stop_evt is set (or forever)."""
    while True:
        if stop_evt and stop_evt.is_set():
            return
        try:
            _nbns_observe(subnets)
        except Exception:
            pass
        if gap > 0:
            try:
                time.sleep(gap)
            except Exception:
                return


# --------------------------------------------------------------------------- #
# Active SSDP (UPnP) query + SNMP sweep
#
# Passive SSDP only hears announcements targets happen to send. Most UPnP gear
# (TVs, printers, media, cameras, smart-hub routers) will answer a query even
# when it blocks every TCP port: an HTTP M-SEARCH to the 239.255.255.250:1900
# group returns SERVER (OS) + LOCATION (→ friendly name) per sale. Same trick
# for SNMP: nmap snmp-info on UDP 161 reveals sysName/sysDescr/sysObjectID for
# cameras/NAS/routers whose TCP is filtered but whose SNMP agent answers.
# Both are plain UDP (no router/admin) and fold through _passive_record, and
# SSDP LOCATIONs are queued for the existing friendly-name fetcher.
# --------------------------------------------------------------------------- #
SSDP_GROUP = "239.255.255.250"
SSDP_PORT = 1900

SSDP_SEARCH_TARGETS = [
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:MediaRenderer:1",
    "urn:schemas-upnp-org:device:MediaServer:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:Printer:1",
]

# Likely nmap snmp-info variants -> parsed recursively below; a few key OID
# prefixes map to product vendors when sysObjectID says nothing else useful.
_SNMP_SYSOBJECT_HINTS = {
    "1.3.6.1.4.1.9": "Cisco",
    "1.3.6.1.4.1.2636": "Juniper",
    "1.3.6.1.4.1.14988": "MikroTik",
    "1.3.6.1.4.1.8072": "Linux (net-snmp)",
    "1.3.6.1.4.1.2021": "Linux (net-snmp)",
    "1.3.6.1.4.1.671": "Ubiquiti",
    "1.3.6.1.4.1.4242": "Proxmox/QEMU",
    "1.3.6.1.4.1.318": "APC",
    "1.3.6.1.4.1.11": "HP/HPE",
}


def _ssdp_build_msearch(st: str, mx: int = 1) -> bytes:
    return ("M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: %d\r\n"
            "ST: %s\r\n\r\n" % (mx, st)).encode("ascii", "replace")


def _ssdp_probe(subnets: List[str], duration: float = 6.0, interval: float = 0.4) -> dict:
    """Actively query SSDP on the local subnet, reusing _parse_ssdp.

    Sends one M-SEARCH per SSDP_SEARCH_TARGETS on each interval and folds every
    response into the passive shared map (os_guess/device_type/mac) and queues
    LOCATIONs for the existing friendly-name fetcher. Returns the number of
    distinct responder IPs seen. Pure multicast UDP - works on AP-isolated or
    TCP-filtered segments. Best-effort: any error returns 0."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", SSDP_PORT))
        mreq = struct.pack("4s4s", socket.inet_aton(SSDP_GROUP), socket.inet_aton("0.0.0.0"))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.settimeout(0.2)
    except Exception:
        return {}

    queries = [_ssdp_build_msearch(st) for st in SSDP_SEARCH_TARGETS]
    seen = {}
    end = time.time() + duration
    next_send = 0.0
    q_i = 0
    try:
        while time.time() < end:
            if time.time() >= next_send:
                q = queries[q_i % len(queries)]
                q_i += 1
                try:
                    s.sendto(q, (SSDP_GROUP, SSDP_PORT))
                except Exception:
                    pass
                next_send = time.time() + interval
            try:
                data, addr = s.recvfrom(8192)
            except socket.timeout:
                continue
            except Exception:
                break
            info = _parse_ssdp(data)
            src = addr[0]
            if not any(_ip_in_subnet(src, s2) for s2 in subnets):
                continue
            existing = seen.get(src)
            if existing is None:
                existing = seen[src] = {"os_guess": None, "device_type": None,
                                        "location": None}
            existing["os_guess"] = existing["os_guess"] or info["os_guess"]
            existing["device_type"] = existing["device_type"] or info["device_type"]
            existing["location"] = existing["location"] or info["location"]
    finally:
        try:
            s.close()
        except Exception:
            pass

    with _PASSIVE_LOCK:
        for src, info in seen.items():
            _passive_record(
                _passive_shared["by_ip"].setdefault(
                    src, {"hostname": None, "os_guess": None,
                          "device_type": None, "vendor": None,
                          "mac": None, "last_seen": 0.0}),
                {"os_guess": info["os_guess"], "device_type": info["device_type"]})
            if info["location"]:
                with _SSDP_LOCK:
                    _ssdp_pending.setdefault(src, {})["location"] = info["location"]
    return seen


def _run_ssdp_sweeper(subnets: List[str], duration: float = 6.0, gap: float = 120.0,
                      stop_evt=None):
    """Background thread: periodically M-SEARCH the SSDP group so UPnP devices
    that only respond to queries get named. Runs until stop_evt is set."""
    while True:
        if stop_evt and stop_evt.is_set():
            return
        try:
            _ssdp_probe(subnets, duration=duration)
            _ssdp_fetch_pending(subnets)
        except Exception:
            pass
        if gap > 0:
            try:
                time.sleep(gap)
            except Exception:
                return


def _snmp_sweep(subnets: List[str]) -> dict:
    """Ask every host in scope over UDP 161 for its SNMP identity via nmap's
    snmp-info script; returns {ip: {"hostname","os_guess","vendor"}}. Many
    cameras/NAS/routers answer SNMP with default 'public' even when their TCP
    ports are filtered. Best-effort: nmap missing/failing gives {}."""
    out = {}
    if not subnets or not shutil.which("nmap"):
        return out
    try:
        import xml.etree.ElementTree as _ET
        root = _ET.fromstring(subprocess.run(
            ["nmap", "-Pn", "-sU", "-p161", "--script", "snmp-info",
             "--host-timeout", "6s", "--min-hostgroup", "256", "-oX", "-"] + subnets,
            capture_output=True, text=True, timeout=180).stdout or "")
    except Exception:
        return out
    for host_el in root.iter("host"):
        st = host_el.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        if not ip:
            continue
        fields = {}
        for hostscript in host_el.iter("hostscript"):
            for scr in hostscript.findall("script"):
                if scr.get("id") != "snmp-info":
                    continue
                text = scr.get("output") or ""
                for m in re.finditer(r"(?m)^\s*\|?\s*(sysName|sysDescr|sysObjectID|sysLocation|sysContact):\s*(.*)$", text):
                    fields[m.group(1)] = m.group(2).strip()
        if not fields:
            continue
        entry = {"hostname": None, "os_guess": None, "vendor": None}
        sys_name = fields.get("sysName") or fields.get("sysName.")
        if sys_name:
            entry["hostname"] = " ".join(sys_name.split())[:255]
        descr = fields.get("sysDescr") or ""
        if descr:
            entry["os_guess"] = " ".join(descr.split())[:200]
        sys_obj = fields.get("sysObjectID") or ""
        vendor = None
        for oid_prefix, name in _SNMP_SYSOBJECT_HINTS.items():
            if sys_obj.replace(".0", "", 1).startswith(oid_prefix):
                vendor = name
                break
        if not vendor:
            vendor = _sniff_vendor(descr)
        entry["vendor"] = vendor
        out[ip] = {k: v for k, v in entry.items() if v}
    return out


def _run_snmp_sweeper(subnets: List[str], gap: float = 300.0, stop_evt=None):
    """Background thread: periodically sweep UDP 161 so SNMP-capable devices
    reveal their identity even when their TCP stack is fully filtered."""
    while True:
        if stop_evt and stop_evt.is_set():
            return
        try:
            results = _snmp_sweep(subnets)
            with _PASSIVE_LOCK:
                for ip, info in results.items():
                    _passive_record(
                        _passive_shared["by_ip"].setdefault(
                            ip, {"hostname": None, "os_guess": None,
                                  "device_type": None, "vendor": None,
                                  "mac": None, "last_seen": 0.0}),
                        {"hostname": info.get("hostname"),
                         "os_guess": info.get("os_guess"),
                         "vendor": info.get("vendor")})
        except Exception:
            pass
        if gap > 0:
            try:
                time.sleep(gap)
            except Exception:
                return


# --------------------------------------------------------------------------- #
# Continuous ARP liveness sweeper ("the switch's ARP table", kept fresh)
#
# Enterprise discovery reads the switch/router ARP + FDB tables because a host
# that answered ARP *is* attached to the LAN - more authoritative than a scan
# that happens to run while the radio is asleep. We can't walk the real switch
# tables (no SNMP access), but active ARP pings over L2 carry the same signal
# and need no router/creds. This background thread re-runs `nmap -sn -PR` over
# the subnets every few minutes and caches "IP answered ARP at time T" with its
# MAC/vendor. Scan discovery then treats any cache entry < ARP_CACHE_TTL old as
# definitively up - rescuing power-save radios that the scan-time -sn missed.
# --------------------------------------------------------------------------- #
_ARP_LOCK = threading.Lock()
_arp_alive = {}  # ip -> {"mac": str|None, "vendor": str|None, "last_seen": float}
ARP_CACHE_TTL = 900.0        # a host that answered ARP this recently is up
_ARP_SWEEP_GAP = 120.0


def _arp_sweep(subnets: List[str]) -> dict:
    """Run one ARP self-scan of the subnets; returns
    {ip: {"mac": str|None, "vendor": str|None}} for every host that answered."""
    out = {}
    if not subnets or not shutil.which("nmap"):
        return out
    for t in subnets:
        try:
            xml = run_nmap(["nmap", "-sn", "-PR", "-oX", "-",
                            "--host-timeout", "10s", "--min-hostgroup", "256", t])
        except Exception:
            continue
        for h in parse_discovery(xml):
            if h.get("state") == "up" and h.get("ip"):
                out[h["ip"]] = {"mac": h.get("mac"), "vendor": h.get("vendor")}
    return out


def _arp_observe(subnets: List[str]):
    """Run one ARP sweep and fold it into the shared cache, pruning entries that
    have gone silent far beyond the TTL so the cache can't pin a dead address
    forever. Runs under the sweeper thread - never blocks the scan hot path."""
    results = _arp_sweep(subnets)
    now = time.time()
    with _ARP_LOCK:
        for ip, meta in results.items():
            old = _arp_alive.get(ip)
            _arp_alive[ip] = {
                "mac": meta.get("mac") or (old or {}).get("mac"),
                "vendor": meta.get("vendor") or (old or {}).get("vendor"),
                "last_seen": now,
            }
        for ip in [ip for ip, e in _arp_alive.items()
                   if now - e["last_seen"] > ARP_CACHE_TTL * 3]:
            _arp_alive.pop(ip, None)


def _arp_snapshot(ttl: float = ARP_CACHE_TTL) -> dict:
    """Copy the fresh ARP cache: {ip: {"mac","vendor"}} for entries seen within
    `ttl` seconds - the caller's authoritative 'up right now' signal."""
    now = time.time()
    with _ARP_LOCK:
        return {ip: {"mac": e.get("mac"), "vendor": e.get("vendor")}
                for ip, e in _arp_alive.items()
                if now - e["last_seen"] <= ttl}


def _run_arp_sweeper(subnets: List[str], gap: float = _ARP_SWEEP_GAP,
                     stop_evt=None):
    """Background thread: keep the ARP liveness cache fresh continuously, so a
    host that answered ARP at any point stays discoverable even if a scan runs
    while it sleeps. Cheap (`nmap -sn -PR` on a /24 is seconds)."""
    while True:
        if stop_evt and stop_evt.is_set():
            return
        try:
            _arp_observe(subnets)
        except Exception:
            pass
        if gap > 0:
            try:
                time.sleep(gap)
            except Exception:
                return


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
        "arp or (udp and (port 67 or port 68 or port 547 or port 137 or port 138 or port 1900 or port 5353 or port 5355)) or (ether proto 0x88cc) or (ether dst 01:00:0c:cc:cc:cc)",
        "arp or udp or ether proto 0x88cc",
        None,
    ]
    last_err = None
    for filt in filters:
        try:
            sniff(iface=iface, filter=filt, prn=lambda p: _passive_packet(p, subnets),
                  store=0, timeout=max(1, int(duration)))
            _passive_sniffer_ok = True
            # Best-effort SSDP LOCATION -> friendly-name fetches queued during
            # the window. Runs after sniff() returns so it never stalls it.
            _ssdp_fetch_pending(subnets)
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
def self_update(client: "ApiClient") -> None:
    """Pull the latest scanner_agent.py from the server, swap it in atomically,
    then re-exec a fresh process under the same supervisor/args."""
    script = os.path.realpath(sys.argv[0]) if os.path.exists(sys.argv[0]) else os.path.abspath(__file__)
    try:
        cur = open(script, encoding="utf-8").read()
    except Exception:
        cur = ""
    new_src = client.fetch_script()
    if not new_src or "def execute_task" not in new_src or "class ApiClient" not in new_src:
        raise RuntimeError("refusing: fetched script does not look like the agent")
    if new_src == cur:
        print("[agent] agent code is already current")
        return
    tmp = script + ".new"
    backup = script + ".bak"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(new_src)
    try:
        shutil.copy(script, backup)
    except Exception as e:
        print(f"[agent] could not write backup {backup}: {e}")
    os.replace(tmp, script)
    print(f"[agent] updated agent code at {script}; re-executing")
    argv = [sys.executable, "-u", script] + sys.argv[1:]
    try:
        os.execv(sys.executable, argv)
    except OSError:
        pass  # Windows may emulate execv via spawn; supervisor relaunch handles it
    sys.exit(0)


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

    # Active NBNS/NetBIOS name sweeper (optional): periodically broadcasts a
    # NetBIOS name query so Windows hosts reveal their computer name + MAC even
    # when they never send unsolicited multicast. No router/creds required -
    # pure L2 broadcast like the mDNS sweeper; degrades silently if nmap is
    # missing or NBNS is filtered.
    try:
        nsweeper = _th.Thread(target=_run_nbns_sweeper, kwargs={
            "subnets": subnets, "gap": 30.0,
        }, daemon=True)
        nsweeper.start()
    except Exception as e:
        print(f"[agent] NBNS name sweeper failed to start (continuing): {e}")

    # Active SSDP M-SEARCH sweeper (optional): periodically queries the UPnP
    # multicast group so TVs/printers/cameras/IoT reveal SERVER + LOCATION even
    # when they block TCP and never send announcements. Pure multicast UDP, no
    # router/creds; degrades silently if the socket can't be opened.
    try:
        ssner = _th.Thread(target=_run_ssdp_sweeper, kwargs={
            "subnets": subnets, "duration": 6.0, "gap": 120.0,
        }, daemon=True)
        ssner.start()
    except Exception as e:
        print(f"[agent] SSDP M-SEARCH sweeper failed to start (continuing): {e}")

    # Active SNMP sweeper (optional): sweeps UDP 161 every few minutes so
    # cameras/NAS/routers with filtered TCP still volunteer sysName/sysDescr.
    try:
        snsweeper = _th.Thread(target=_run_snmp_sweeper, kwargs={
            "subnets": subnets, "gap": 300.0,
        }, daemon=True)
        snsweeper.start()
    except Exception as e:
        print(f"[agent] SNMP sweeper failed to start (continuing): {e}")

    # Continuous ARP liveness sweeper: re-queries the subnet via ARP every
    # two minutes and caches which IPs answered. The cache feeds scan-time
    # discovery so power-save devices that missed the scan's one-shot -sn
    # still count as live — the closest analogue to reading a managed switch
    # ARP table without SNMP access.
    try:
        arper = _th.Thread(target=_run_arp_sweeper, kwargs={
            "subnets": subnets, "gap": _ARP_SWEEP_GAP,
        }, daemon=True)
        arper.start()
    except Exception as e:
        print(f"[agent] ARP liveness sweeper failed to start (continuing): {e}")

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
            try:
                hb = client.heartbeat(subnets, caps, hostname, os_name)
            except RemoteAuthError as e:
                print(f"[agent] heartbeat rejected ({e}); trying key sync with previous key...")
                try:
                    if client.agent_id and client.agent_id != "?":
                        new_key = client.sync_key(client.agent_id)
                        client.persist_key(new_key)
                        print("[agent] new API key synced and persisted")
                        hb = client.heartbeat(subnets, caps, hostname, os_name)
                    else:
                        raise RuntimeError("agent id unknown — cannot sync key")
                except RemoteAuthError as ke:
                    print(f"[agent] key sync rejected ({ke}); grace window expired or key already rotated again — "
                          "re-rotate in the UI or set the key manually")
                    time.sleep(max(args.interval, 5))
                    continue
                except Exception as ke:
                    print(f"[agent] key sync failed: {ke}")
                    time.sleep(max(args.interval, 5))
                    continue
            if hb and hb.get("restart_requested"):
                print("[agent] restart requested by server — exiting so supervisor relaunches")
                sys.exit(0)
            if hb and hb.get("update_requested"):
                try:
                    self_update(client)
                except Exception as ue:
                    print(f"[agent] self-update failed: {ue}")
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