# Scan Pipeline — commands run step‑by‑step

How each scan executes, phase by phase, with the **exact commands** the worker
runs and what is happening on the network while they run. The same commands are
streamed live to the **Core Command Console** on the Live Scan screen.

---

## Lifecycle

A scan moves through these statuses:

```
queued → discovering → scanning → fingerprinting → analyzing → completed
                                        │
                                        └ (or) failed / stopped
```

When a [scanner agent](WALKTHROUGH.md#13-scanner-agents-full-layer-2-discovery)
is online and covers the targets, the same scan is **delegated** instead:

```
queued → agent_running → (agent executes) → analyzing → completed / failed
```

| Status | Meaning |
|---|---|
| `queued` | Scan row created, Celery task submitted |
| `agent_running` | Scan handed to a scanner agent; its logs/results drive completion |
| `discovering` | Phase 0 — host discovery (CIDR expansion + probes) |
| `scanning` | Phases 1–2 — re-verification + port scan |
| `fingerprinting` | Phase 3 — deep service/OS fingerprint on open ports |
| `paused` | User paused; progress frozen between phases (worker or agent) |
| `analyzing` | Risk rules + topology + final DB persistence |
| `completed` | Done, `progress_pct = 100` |

---

## Scan profiles and their nmap timing

The `profile` only changes the nmap timing template (`-T*`). Everything else in
the pipeline is identical across profiles.

| Profile | `-T` flag | When to use |
|---|---|---|
| `quick` | `-T4` | Fast top‑1000 sweep, standard engagements |
| `full` | `-T3` | Comprehensive top‑10000 scan, deep fingerprinting |
| `stealth` | `-T1` | Heavily throttled; safe for fragile OT/IoT devices |
| `passive_only` | *(none)* | No active port scanning — discovery + SNMP only, zero footprint |

---

## Phase 0/3 — Host discovery

```
--- Phase 0/3: Host discovery (CIDR expansion + probes) ---
```

1. **Expand targets** into concrete IPv4 addresses.
   - `192.168.1.0/24` → 254 usable IPs (`192.168.1.1..254`). Network `.0` and
     broadcast `.255` are excluded; `/31` and `/32` are kept whole.
   - A single IP stays as‑is.
2. **L2-first, L3-fallback** — the worker first tries to hand the whole scan to an
   online [scanner agent](WALKTHROUGH.md#13-scanner-agents-full-layer-2-discovery)
   whose local subnets cover the targets (`agent_running`, real ARP → MAC/vendor,
   SYN + `-O` → OS). If no online L2-capable agent covers the targets, it emits a
   console warning
   (`No online L2-capable agent covers the targets — falling back to L3 container
   scan…`) and proceeds with **L3-only discovery** here — the container has no
   Layer-2 access to the target LAN (Docker virtual network), so ARP/LLDP passive
   discovery is not attempted. MAC/vendor/OS stay blank without an agent.
3. **Liveness probe (no shell command)** — a concurrent TCP connect attempt to
   each candidate on up to 64 threads, 1 s timeout, on the probe ports:

   ```
   PROBE_PORTS = 80, 443, 22, 445, 3389, 23, 53, 8080, 8443, 515, 631, 135, 139
   ```

   Hosts answering any port are marked `up` (`tcp_probe`). Hosts that don't
   answer are **still registered** as inventory entries (`scope`) so the
   inventory mirrors the order.
4. **Register hosts**: each candidate is registered. TCP‑confirmed hosts get
   `tcp_probe` as their discovery method; unconfirmed ones get `scope`. Each
   emits a `host_discovered` WS event.

---

## Phase 1/3 — Re-verify down hosts (skipped)

```
--- Phase 1/3: skipped (no L2/ARP data - nmap -sn unreliable; keeping probe-confirmed hosts) ---
```

This phase re-runs `nmap -sn` on hosts that did not confirm alive during
discovery. It was historically used when ARP discovery (bridge mode) found hosts
but TCP probes missed them (firewalled hosts). Since the container now runs
L3-only and TCP probes are the ground truth for liveness, this phase is always
skipped — nmap `-sn` on routed subnets is unreliable (routers/tunnels proxy-ARP,
causing false positives).

Real L2 discovery and firewalled-host re-checks are performed by a
[scanner agent](WALKTHROUGH.md#13-scanner-agents-full-layer-2-discovery) on the
target LAN when one is registered and online.

---

## Phase 2/3 — Port scan (connect, no fingerprint)

```
--- Phase 2/3: Port scan (connect, no fingerprint) ---
```

Runs **per confirmed‑up host**, sequentially. This is the fast pass that only
produces the *open port list* — no service/version work yet.

Equivalent command:

```bash
nmap -sT <timing> -p <port_range> --open -oX - <ip>     # TCP protocol
nmap -sU <timing> -p <port_range> --open -oX - <ip>     # UDP protocol
```

Examples:

```bash
nmap -sT -T4 -p 1-1000 --open -oX - 192.168.1.254
nmap -sU -T4 -p 1-500 --open -oX - 192.168.1.206
```

- `-sT` — TCP connect scan (no root needed). `--open` keeps only open results,
  so the output is compact XML.
- Every open port is stored (`state=open`, service/version still blank) and a
  `host_updated` WS event carrying the `ports[]` array fires — this is what the
  Live Scan **Open Ports** counter counts.
- One command per host, 60 s timeout each. Progress advances `20% → 70%`.

---

## Phase 3/3 — Service fingerprinting (open ports only)

```
--- Phase 3/3: Service fingerprinting (open ports only) ---
```

The expensive part: version detection, default scripts, and OS detection are
run **only on ports already proven open**, never a full sweep.

Equivalent command (open ports joined with commas):

```bash
# TCP
nmap -sT -sV -O <timing> -p <ports> --open -oX - <ip>
# UDP
nmap -sU -sV <timing> -p <ports> --open -oX - <ip>
```

Examples:

```bash
nmap -sT -sV -O -T4 -p 22,80,443 --open -oX - 192.168.1.254
nmap -sU -sV -T4 -p 53,161 --open -oX - 192.168.1.206
```

- `-sT` TCP connect scan (works without root; SYN scans with `-sS` are
  available when run by a [scanner agent](WALKTHROUGH.md#13-scanner-agents-full-layer-2-discovery) with the necessary privileges),
  `-sV` version probe, `-O` OS fingerprint.
- Results (service name, version, banner) update the previously stored port
  rows and are pushed as `host_updated` events. Banner text is truncated to 500
  chars. Timeout 120 s per host.

---

## Analyzing — risk rules, SNMP, topology

```
--- Analyzing: risk rules + topology ---
```

These have no per‑host shell sweep; they operate on the collected data.

1. **SNMP walk** (`fingerprint_hosts`) — for each host, net‑snmp `snmpget`
   against the standard OIDs using community `public`:

   ```bash
   snmpget -v1 -c public -t 3 -r 0 -On <ip> .1.3.6.1.2.1.1.1.0     # sysDescr
   snmpget -v1 -c public -t 3 -r 0 -On <ip> .1.3.6.1.2.1.1.5.0     # sysName
   snmpget -v1 -c public -t 3 -r 0 -On <ip> .1.3.6.1.2.1.1.6.0     # sysLocation
   snmpget -v1 -c public -t 3 -r 0 -On <ip> .1.3.6.1.2.1.1.2.0     # sysObjectID
   snmpget -v1 -c public -t 3 -r 0 -On <ip> .1.3.6.1.2.1.1.3.0     # sysUpTime
   ```

   Success → stores sysDescr/name/location/uptime, vendor inferred from the
   `sysObjectID` OID prefix, and marks `default_community_found=True` (a
   finding). Also classifies device type (router/switch/etc.) from OUI +
   open ports.
2. **Risk rules** (`run_risk_rules`) — creates findings:
   - Default SNMP community (`public`) responds → `critical`-adjacent finding.
   - Banner/version match against a curated outdated‑software table
     (`KNOWN_OUTDATED`, e.g. vsftpd 2.3.4, OpenSSH <7.4, Samba <4.6, …).
   - Exposed admin panels (SSH/Telnet/admin-web on gateways).
   - Unencrypted protocols (Telnet 23, FTP 21, HTTP 80, SMB 445 on internet‑facing).
3. **Topology** (`capture_topology`) — placeholder for now: hosts are chained
   into `l2_adjacency` edges (**no self‑loops / no CIDR‑string nodes**). In
   production this is CDP/LLDP passive capture + traceroute.

Finally `scan_completed` fires, status = `completed`, `progress_pct = 100`.

---

## Live console — what you'll see during a run

Commands and output stream **live**, not after the fact:

| Console line | Meaning | Color |
|---|---|---|
| `=== Scan started (id=…, targets=…, profile=…, protocol=…) ===` | Start banner | green (info) |
| `$ nmap -sT -T4 -p 1-1000 --open -oX - 192.168.1.254` | Command about to run | cyan (cmd) |
| `Starting Nmap 7.90 …`, `Nmap scan report for …`, `PORT    STATE SERVICE` | Live nmap progress from stderr | gray (out) |
| `  192.168.1.254: 22/tcp open  ssh` | Concise summary per open port (parsed from XML) | gray (out) |
| `[timeout after 60s]` | A command took too long and was killed | amber (warn) |
| `=== Scan FAILED: … ===` | Phase raised an exception | red (err) |

Implementation notes:

- nmap runs via `Popen`; its **stderr** is forwarded line‑by‑line to Redis →
  WS the instant each line is produced, so you watch a scan, not a replay.
- **stdout** (the `-oX -` XML) is captured in full and parsed for the port
  table + summary; the human‑friendly stderr copy is what you see live.
- Timeouts are enforced with `proc.wait(timeout)`; on expiry the process is
  `kill()`ed.
- The console panel is 55&thinsp;vh (viewport height) with auto‑scroll and
  preserve‑wrap for long lines. `Clear` resets it.