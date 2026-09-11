"""NSE (Nmap Scripting Engine) finding extraction.

The scan pipeline already runs nmap -sV -sC -O with a per-port set of safe NSE
scripts and stashes the raw XML under backend/scan_output/<scan_id>/ (phases
"fingerprint"/"ports"/"nse"). Up to now that NSE output was only folded into the
port `banner` string and OS detection -- the risk rules ignored it. This module
parses the saved XML and turns structured NSE evidence into findings (weak TLS,
SMB signing, anonymous FTP, dangerous HTTP verbs, exposed admin UIs, ...).

Every rule is evidence-driven: a finding is created only when the NSE script
actually reported the condition, never from a bare port/service guess.
"""

import re
from datetime import datetime
from xml.etree import ElementTree as ET

# type -> (CWE, CVSS base score, CVSS:3.1 vector). Used for both NSE-driven and
# heuristic findings so every finding carries a defensible scoring reference.
FINDING_META = {
    "weak_crypto":            ("CWE-327", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "expired_certificate":    ("CWE-295", 7.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "smb_signing_disabled":   ("CWE-693", 5.9, "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "anonymous_ftp":          ("CWE-287", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "unrestricted_share":     ("CWE-732", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "dangerous_http_methods": ("CWE-650", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "missing_auth":           ("CWE-306", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "empty_password":         ("CWE-521", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "exposed_admin_panel":    ("CWE-284", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
    "web_service_exposed":    ("CWE-284", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "information_disclosure": ("CWE-538", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "unencrypted_protocol":   ("CWE-319", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "unencrypted_video":      ("CWE-319", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "default_credentials":    ("CWE-798", 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "eol_software":           ("CWE-1104", 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
    "known_vulnerability":    ("", None, None),
}


def _data_for_meta(finding_type: str, severity: str) -> dict:
    """Resolve the CWE/CVSS stamp for a finding type bundled with NSE evidence."""
    cwe, score, vector = FINDING_META.get(finding_type, ("", None, None))
    return {"cwe": cwe or None, "cvss_score": score, "cvss_vector": vector}


def _make(host_ip: str, label: str, ftype: str, severity: str, title: str,
          description: str, recommendation: str, port, evidence,
          cve_refs: list = None) -> dict:
    base = _data_for_meta(ftype, severity)
    return {
        "type": ftype,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "cve_refs": cve_refs or [],
        "port": port,
        "evidence": evidence,
        **base,
    }


def iter_nse_entries(xml_text: str):
    """Yield {port, script, output, elems} for every NSE script result.

    elems is a flat {path.key: text} map built from the XML <table>/<elem>
    structure (e.g. "subject/commonName"), with list indexes flattened to
    "name@N" keys -- enough for the rule matchers below.
    """
    if not xml_text or not xml_text.strip():
        return
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return

    def _flatten(table_or_elem, prefix="", out=None):
        out = {} if out is None else out
        for child in list(table_or_elem):
            key = child.get("key")
            if child.tag == "table":
                _flatten(child, f"{prefix}{key}/" if key else prefix, out)
            elif child.tag == "elem":
                k = f"{prefix}{key or ''}" if prefix else (key or "")
                # multiple elems share keys after first (list) -> index them
                if k and k in out:
                    k = f"{k}@{len([x for x in out if x.startswith(k)])}"
                if k and child.text:
                    out[k] = child.text.strip()
        return out

    for host_el in root.findall("host"):
        # Host-level scripts (no port).
        for script_el in host_el.findall("./hostscript/script"):
            yield {
                "port": None,
                "script": script_el.get("id"),
                "output": (script_el.get("output") or "").strip(),
                "elems": _flatten(script_el),
            }
        # Per-port scripts.
        for port_el in host_el.findall(".//port"):
            try:
                port = int(port_el.get("portid"))
            except (TypeError, ValueError):
                port = None
            for script_el in port_el.findall("script"):
                yield {
                    "port": port,
                    "script": script_el.get("id"),
                    "output": (script_el.get("output") or "").strip(),
                    "elems": _flatten(script_el),
                }


# --------------------------------------------------------------------------- #
# Individual script rules. Returned list of finding dicts (no host context).
# --------------------------------------------------------------------------- #

_SSH_WEAK_KEX = (
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
)
_SSH_WEAK_HOSTKEY = ("ssh-dss", "ssh-rsa", "rsa-sha1")


def _rule_ssh(entry, port) -> list:
    out = []
    text = entry["output"]
    elems = entry["elems"]
    if entry["script"] == "ssh2-enum-algos":
        weak_kex = [k for k in _SSH_WEAK_KEX if k.lower() in text.lower() or k.lower() in " ".join(elems.values()).lower()]
        weak_hostkey = [k for k in _SSH_WEAK_HOSTKEY if k.lower() in " ".join(elems.values()).lower()]
        if weak_kex or weak_hostkey:
            out.append(_make("", "", "weak_crypto", "notable",
                f"Weak SSH algorithm negotiation on port {port}",
                "The SSH server accepts deprecated algorithms: "
                f"kex={', '.join(weak_kex) or 'none'} hostkey={', '.join(weak_hostkey) or 'none'}.",
                "Disable SSHv1-era key exchange (group1/group14-sha1) and DSA host keys; "
                "prefer curve25519-sha256 / ed25519.",
                port, {"script": "ssh2-enum-algos", "output": text[:500]}))
    elif entry["script"] == "ssh-hostkey":
        short = re.findall(r"(\d{3,4})-bit RSA", text)
        if short and any(int(s) < 2048 for s in short):
            out.append(_make("", "", "weak_crypto", "concerning",
                f"Weak SSH host key strength on port {port}",
                f"The SSH host key is {short[0]}-bit RSA; keys shorter than 2048 bits are easily factored.",
                "Regenerate the host key at 3072 or 4096 bits.",
                port, {"script": "ssh-hostkey", "output": text[:300]}))
    return out


def _rule_ssl_cert(entry, port) -> list:
    out = []
    text = entry["output"]
    el = entry["elems"]
    not_after = (el.get("notAfter") or None)
    if not not_after:
        m = re.search(r"Not valid after:\s*(.+)$", text, re.M)
        if m:
            not_after = m.group(1).strip()
        m = re.search(r"Not valid after:\s*([^\n]+)", text)
        if m:
            not_after = m.group(1).strip()
    bits = el.get("pubkey/bits") or None
    if not bits:
        m = re.search(r"Public Key bits:\s*(\d+)", text)
        if m:
            bits = m.group(1)
    sig = (el.get("sig_algo") or "").lower()
    if not sig:
        m = re.search(r"Signature Algorithm:\s*([^\n]+)", text, re.I)
        if m:
            sig = m.group(1).strip().lower()
    if not not_after and not bits and "self-signed" not in text.lower():
        return out

    try:
        parsed = datetime.fromisoformat(not_after.replace("Z", "+00:00").replace(" ", "T"))
        now = datetime.now().astimezone()
        if not_after and not_after and parsed < now:
            out.append(_make("", "", "expired_certificate", "concerning",
                f"Expired TLS certificate on port {port}",
                f"The server presents a certificate that expired {parsed.isoformat()}: {text[:200]}",
                "Renew the certificate; expired certs are trusted by browsers but fail validation "
                "and often indicate abandoned or misconfigured services.",
                port, {"script": "ssl-cert", "output": text[:500]}))
    except Exception:
        pass

    if bits:
        try:
            n = int(bits)
            if n < 2048:
                out.append(_make("", "", "weak_crypto", "concerning",
                    f"Weak TLS key strength on port {port}",
                    f"The TLS certificate uses only a {n}-bit RSA key.",
                    "Use a certificate with a 2048-bit (or stronger) RSA key, or ECDSA P-256+.",
                    port, {"script": "ssl-cert", "output": text[:300]}))
        except (TypeError, ValueError):
            pass

    subject_cn = el.get("subject/commonName") or ""
    issuer_cn = el.get("issuer/commonName") or ""
    self_signed = False
    # Structured XML path: subject CN == issuer CN is the precise signal.
    # Text fallback: self-signed is only claimed when the output literally says
    # so -- never from a bare "Issuer:" line, which every cert carries.
    if subject_cn and issuer_cn:
        self_signed = subject_cn.lower() == issuer_cn.lower()
    elif "self-signed" in text.lower():
        self_signed = True

    if self_signed:
        out.append(_make("", "", "weak_crypto", "notable",
            f"Self-signed TLS certificate on port {port}",
            "The service presents a self-signed certificate, preventing clients from "
            "verifying the identity of the server.",
            "Replace with a certificate from a trusted CA or an internal CA enrolled on managed clients.",
            port, {"script": "ssl-cert", "output": text[:300]}))
    if sig and ("md5" in sig or ("sha1" in sig and "sha256" not in sig)):
        out.append(_make("", "", "weak_crypto", "notable",
            f"Weak TLS certificate signature on port {port}",
            "The certificate is signed with a deprecated hash algorithm (MD5/SHA-1).",
            "Re-issue with SHA-256 or better.",
            port, {"script": "ssl-cert", "output": text[:300]}))
    return out


_WEAK_CIPHERS = ("rc4", "des_cbc3", "3des", "_des_", "_null_", "anon", "export", "psk")
_DEPRECATED_PROTOCOLS = ("SSLv3", "TLSv1.0", "TLSv1.1")


def _ssl_protocols(elems: dict, text: str) -> set:
    """Protocol versions the SSL/TLS endpoint actually negotiated.

    Prefer the structured XML table keys (``TLSv1.2/ciphers/name`` → protocol
    at the first path segment); fall back to scanning the text for version
    header tokens ``SSLv3:`` / ``TLSv1.0:`` / ``TLSv1.1:`` / ``TLSv1.2:`` ...

    Crucially we never test the bare substring ``TLSv1`` against the output --
    that matches ``TLSv1.2``/``TLSv1.3`` too and turns a clean TLSv1.2-only
    endpoint into a false-positive "TLSv1" alert.
    """
    protocols = set()
    for key in elems:
        head = key.split("/", 1)[0]
        if head.lower().startswith(("ssl", "tls")) and len(head) > 3:
            protocols.add(head)
    if not protocols:
        protocols = set(re.findall(r"(SSLv[23]|TLSv1\.\d+)", text, re.IGNORECASE))
    return protocols


def _rule_ssl_ciphers(entry, port) -> list:
    out = []
    text = entry["output"].lower()
    elems = entry["elems"]
    # Structured XML: each cipher suite is `TLSvX.Y/ciphers/name[@N]`.
    suite_keys = sorted(k for k in elems if "/ciphers/name" in k)
    if suite_keys:
        names = [elems[k] for k in suite_keys]
    else:
        # text fallback: "TLSv1.0:  ... TLS_RSA_WITH_RC4_128_SHA  "
        names = re.findall(r"(TLS|SSL)[A-Z0-9_]+", entry["output"])
    weak = sorted({n for n in names if any(w in n.lower() for w in _WEAK_CIPHERS)})
    deprecated = sorted(_ssl_protocols(elems, entry["output"]) & set(_DEPRECATED_PROTOCOLS))
    if weak or deprecated:
        desc = "The TLS service accepts deprecated/weak cipher suites or protocol versions."
        if weak:
            desc += f" Weak suites observed: {', '.join(weak[:12])}."
        if deprecated:
            desc += f" Deprecated protocol version enabled: {', '.join(deprecated)}."
        out.append(_make("", "", "weak_crypto", "concerning",
            f"Weak TLS configuration on port {port}",
            desc,
            "Disable SSLv3/1.0/1.1 and RC4/3DES/NULL/anon suites; prefer TLS 1.2+ with AEAD ciphers.",
            port, {"script": "ssl-enum-ciphers", "output": entry["output"][:600]}))
    return out


def _rule_smb_signing(entry, port) -> list:
    text = entry["output"]
    if "signing enabled and required" in text.lower():
        return []
    if "signing enabled but not required" in text.lower():
        return [_make("", "", "smb_signing_disabled", "notable",
            f"SMB message signing not required on port {port}",
            "SMB signing is supported but not required, allowing man-in-the-middle "
            "attacks such as SMB relay (NTLM relaying, credential theft).",
            "Enable SMB signing for all SMB clients/servers (RequireSecuritySignature / "
            "SMB signing required).",
            port, {"script": entry["script"], "output": text[:300]})]
    if "signing disabled" in text.lower():
        return [_make("", "", "smb_signing_disabled", "concerning",
            f"SMB signing disabled on port {port}",
            "SMB message signing is disabled, permitting relay and tampering attacks.",
            "Enable and require SMB message signing.",
            port, {"script": entry["script"], "output": text[:300]})]
    return []


def _rule_smb_shares(entry, port) -> list:
    out = []
    text = entry["output"]
    el = entry["elems"]
    # Share keys are first-level tables: "Everyone", "public", "C$", ...
    share_keys = sorted({k.split("/")[0] for k in el if "/" in k})
    for share in share_keys:
        acc = el.get(f"{share}/anonymous access", "").lower()
        if acc and "write" in acc:
            name = share.lower()
            if name in ("c$", "admin$", "ipc$", "print$"):
                continue
            out.append(_make("", "", "unrestricted_share", "concerning",
                f"World-readable SMB share '{share}' on port {port}",
                f"SMB share '{share}' allows anonymous access with write permission "
                f"('{acc}'), exposing data to any network client.",
                "Remove the share or restrict to authenticated users with least privilege.",
                port, {"script": "smb-enum-shares", "output": text[:400]}))
    # text fallback: share list w/ anonymous read/write column
    for line in text.splitlines():
        m = re.match(r"\s*([\w\-\.$]+)\s+(\w+)\s+(.+)", line)
        if m and "READ" in m.group(2).upper() and "WRITE" in m.group(2).upper():
            share = m.group(1)
            if share.lower() in ("c$", "admin$", "ipc$", "print$"):
                continue
            if not any(s["title"].startswith(f"World-readable SMB share '{share}'") for s in out):
                out.append(_make("", "", "unrestricted_share", "concerning",
                    f"World-readable SMB share '{share}' on port {port}",
                    f"SMB share '{share}' permits anonymous access.",
                    "Restrict SMB shares to authenticated users.",
                    port, {"script": "smb-enum-shares", "output": text[:400]}))
    return out


def _rule_ftp_anon(entry, port) -> list:
    if "anonymous ftp login allowed" in entry["output"].lower():
        return [_make("", "", "anonymous_ftp", "notable",
            f"Anonymous FTP login allowed on port {port}",
            "The FTP server accepts anonymous logins, exposing files to any network client.",
            "Disable anonymous access; require authenticated accounts with least privilege.",
            port, {"script": "ftp-anon", "output": entry["output"][:300]})]
    return []


def _rule_http_methods(entry, port) -> list:
    m = re.search(r"Supported Methods:\s*(.+)$", entry["output"], re.I)
    if not m:
        m = re.search(r"Potentially risky methods:\s*(.+)$", entry["output"], re.I)
    if not m:
        return []
    methods = {s.strip() for s in m.group(1).split()}
    dangerous = methods & {"PUT", "DELETE", "TRACE", "PATCH"}
    if dangerous:
        return [_make("", "", "dangerous_http_methods", "notable",
            f"Dangerous HTTP methods allowed on port {port}",
            f"The web service accepts {', '.join(sorted(dangerous))}, which can be used "
            "to modify content or trigger XST.",
            "Disable non-essential HTTP methods at the server/application layer.",
            port, {"script": "http-methods", "output": entry["output"][:300]})]
    return []


def _rule_telnet(entry, port) -> list:
    if "no encryption" in entry["output"].lower():
        return [_make("", "", "unencrypted_protocol", "concerning",
            f"Telnet negotiates no encryption on port {port}",
            "Telnet-encryption reports NO ENCRYPTION: credentials and session data "
            "transit the network in clear text.",
            "Replace Telnet with SSH; if unavoidable, tunnel it or restrict to a management VLAN.",
            port, {"script": "telnet-encryption", "output": entry["output"][:300]})]
    return []


def _rule_mysql_empty(entry, port) -> list:
    if "mysql empty password" in entry["output"].lower():
        return [_make("", "", "empty_password", "concerning",
            f"MySQL allows empty-password login on port {port}",
            "The MySQL server accepts connections with an empty password.",
            "Assign credentials to all MySQL accounts.",
            port, {"script": "mysql-empty-password", "output": entry["output"][:300]})]
    return []


def _rule_mongo_auth(entry, port) -> list:
    text = entry["output"].lower()
    if "authentication is not enabled" in text or "authentication not enabled" in text \
       or "no auth" in text and "authorized" not in text:
        return [_make("", "", "missing_auth", "notable",
            f"MongoDB requires no authentication on port {port}",
            "The MongoDB server exposes data without requiring authentication.",
            "Enable MongoDB authentication with strong credentials and restrict network access.",
            port, {"script": "mongodb-info", "output": entry["output"][:300]})]
    return []


def _rule_login_less_services(entry, port) -> list:
    """redis/vnc/mysql-style services that expose data with no authentication."""
    sid, text = entry["script"], entry["output"]
    low = text.lower()
    if sid == "redis-info":
        # redis-info prints the auth_required value when configured to do so;
        # many builds only print it once auth is actually needed.
        m = re.search(r"auth_required:\s*(\d+)", text, re.I)
        if m and m.group(1) == "0":
            return [_make("", "", "missing_auth", "notable",
                f"Redis requires no authentication on port {port}",
                "The Redis server accepts unauthenticated connections, exposing all keys to any network client.",
                "Set requirepass and bind to trusted interfaces only (protected-mode on).",
                port, {"script": "redis-info", "output": text[:300]})]
        # Fallback for the classic output shape.
        if "auth not required" in low or "authentication not required" in low:
            return [_make("", "", "missing_auth", "notable",
                f"Redis requires no authentication on port {port}",
                "The Redis server accepts unauthenticated connections, exposing all keys to any network client.",
                "Set requirepass and bind to trusted interfaces only (protected-mode on).",
                port, {"script": "redis-info", "output": text[:300]})]
    if sid == "vnc-info":
        if "authentication required: no" in low:
            return [_make("", "", "missing_auth", "notable",
                f"VNC exposes the desktop without authentication on port {port}",
                "The VNC server allows connections without a password, exposing the live desktop to anyone on the network.",
                "Require a strong VNC password and restrict clients to a management VLAN.",
                port, {"script": "vnc-info", "output": text[:300]})]
    if sid == "mysql-info" and "authentication required" not in text and "anonymous" in low:
        return [_make("", "", "missing_auth", "notable",
            f"MySQL allows anonymous connections on port {port}",
            "The MySQL server accepts connections without valid credentials.",
            "Enforce authentication for all MySQL accounts and remove anonymous users.",
            port, {"script": "mysql-info", "output": text[:300]})]
    return []


# Explicit well-known exploitability: keep the CVEs a script reports so the
# finding carries concrete references even before NVD matching runs.
_VULN_STATE_LINES = ("VULNERABLE", "VULNERABILITY", "exploit available", "CVE-")


def _extract_cves(text: str) -> list:
    seen = []
    for m in re.finditer(r"(CVE-\d{4}-\d{4,7})", text, re.IGNORECASE):
        cve = m.group(1).upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def _rule_smb_vuln(entry, port) -> list:
    """smb-vuln-* scripts report patched vs vulnerable state directly."""
    text = entry["output"]
    low = text.lower()
    if "not vulnerable" in low or "not_vulnerable" in low:
        return []
    if any(state in low for state in ("vulnerable", "exploit available")) \
       and any(sig in low for sig in ("ids:", "cve-", "risk factor", "state:", "impact", "summary")):
        cves = _extract_cves(text)
        title = f"Known SMB vulnerability on port {port}"
        if cves:
            title = f"{', '.join(cves[:3])} on SMB port {port}"
        return [_make("", "", "known_vulnerability", "critical",
            title,
            text.strip()[:400],
            "Patch the SMB service immediately; mitigations include blocking SMB "
            "1.0 and restricting 445 to trusted clients.",
            port, {"script": entry["script"], "output": text[:600]}, cves)]
    return []


def _rule_ssl_dos(entry, port) -> list:
    """ssl-ccs-injection / ssl-dh-params / ssl-poodle / ssl-heartbleed style
    scripts that mark the endpoint vulnerable with an explicit state line."""
    text = entry["output"]
    low = text.lower()
    if "not vulnerable" in low or "not_vulnerable" in low:
        return []
    if any(state in low for state in ("vulnerable", "exploit available")) \
       and any(sig in low for sig in ("ids:", "cve-", "risk factor", "state:", "impact", "summary")):
        cves = _extract_cves(text)
        return [_make("", "", "known_vulnerability", "critical",
            f"Exploitable TLS issue on port {port}"
            + (f" ({', '.join(cves[:3])})" if cves else ""),
            text.strip()[:400],
            "Patch the TLS stack and re-test; if not promptly patchable, limit "
            "exposure of the affected service.",
            port, {"script": entry["script"], "output": text[:600]}, cves)]
    return []


def _rule_dns_zone_transfer(entry, port) -> list:
    """A successful DNS zone transfer is full disclosure of the zone records."""
    text = entry["output"]
    if "attempting zone transfer" not in text.lower():
        return []
    if any(s in text.upper() for s in ("MISC", "SUCCESS", "SUCCEEDED")) and "FAILED" not in text.upper():
        return [_make("", "", "information_disclosure", "notable",
            f"DNS zone transfer allowed on port {port}",
            "The DNS server answered an AXFR request, leaking the full zone "
            "(hostnames, IPs, MX/SRV records) to any client.",
            "Restrict zone transfers to designated secondary nameservers and use TSIG.",
            port, {"script": "dns-zone-transfer", "output": text[:400]})]
    return []


_ADMIN_MARKERS = (
    "login", "admin", "management", "configuration", "config", "router", "gateway",
    "camera", "nvr", "dvr", "hikvision", "dahua", "tp-link", "d-link", "tenda",
    "netcore", "console", "setup", "control panel", "websoap", "firmware", "fritz!",
    "mikrotik", "fortigate", "web admin", "supervisor", "dashboard",
)
_SENSITIVE_PATHS = (".git", ".svn", ".env", "backup", "www.zip", "config.php")


def _harvest_http_evidence(entries, port_from_script: dict):
    """Group http-title/http-enum/http-server-header/http-headers/http-generator
    results per port to decide whether the web service is a management interface."""
    out = {"title": None, "server": None, "paths": [], "admin": False, "sensitive": []}
    for entry in entries:
        if entry["port"] != port_from_script:
            continue
        sid = entry["script"]
        text = entry["output"]
        if sid == "http-title":
            m = re.search(r"Title:\s*(.+)$", text, re.I)
            if m:
                out["title"] = m.group(1).strip()[:120]
        elif sid == "http-server-header":
            m = re.search(r"([\w\-\/\.]+)$", text.strip().splitlines()[0]) if text.strip() else None
            out["server"] = text.strip().splitlines()[0][:120] if text.strip() else None
        elif sid == "http-generator":
            out["server"] = text.strip().splitlines()[0][:120] or out["server"]
        elif sid == "http-enum":
            for line in text.splitlines():
                line = line.strip()
                path = re.sub(r"\s*\[\d+\]\s*$", "", line.rstrip())
                if path:
                    out["paths"].append(path[:120])
        elif sid == "http-headers":
            pass
    low = (out["title"] or "").lower()
    low_paths = " ".join(out["paths"]).lower()
    for mk in _ADMIN_MARKERS:
        if mk in low or mk in low_paths:
            out["admin"] = True
            break
    for sp in _SENSITIVE_PATHS:
        if sp in low_paths:
            out["sensitive"].append(sp)
    return out


def nse_findings_for_host(scan_id, host, label, xml_text) -> dict:
    """Run every evidence rule over one host's NSE XML.

    Returns {"findings": [...], "web": {port: {"title":.., "server":.., "admin":bool}}}
    `web` is used by run_risk_rules for the http-port fallback decision.
    """
    out = []
    entries = list(iter_nse_entries(xml_text))

    # Group entries by port for the web/panel logic.
    by_port = {}
    for e in entries:
        by_port.setdefault(e["port"], []).append(e)

    for entry in entries:
        port = entry["port"]
        sid = entry["script"]
        if sid == "ssh2-enum-algos" or sid == "ssh-hostkey":
            out += _rule_ssh(entry, port)
        elif sid == "ssl-cert":
            out += _rule_ssl_cert(entry, port)
        elif sid == "ssl-enum-ciphers":
            out += _rule_ssl_ciphers(entry, port)
        elif sid in ("smb-security-mode", "smb2-security-mode"):
            out += _rule_smb_signing(entry, port)
        elif sid == "smb-enum-shares":
            out += _rule_smb_shares(entry, port)
        elif sid == "ftp-anon":
            out += _rule_ftp_anon(entry, port)
        elif sid == "http-methods":
            out += _rule_http_methods(entry, port)
        elif sid == "telnet-encryption":
            out += _rule_telnet(entry, port)
        elif sid == "mysql-empty-password":
            out += _rule_mysql_empty(entry, port)
        elif sid == "mongodb-info":
            out += _rule_mongo_auth(entry, port)
        elif sid in ("redis-info", "vnc-info", "mysql-info"):
            out += _rule_login_less_services(entry, port)
        elif sid.startswith("smb-vuln-"):
            out += _rule_smb_vuln(entry, port)
        elif sid in ("ssl-ccs-injection", "ssl-poodle", "ssl-heartbleed",
                     "ssl-dh-params", "ssl-dos", "http-shellshock"):
            out += _rule_ssl_dos(entry, port)
        elif sid == "dns-zone-transfer":
            out += _rule_dns_zone_transfer(entry, port)

    web = {}
    for port, ents in by_port.items():
        http_scripts = [e for e in ents if e["script"].startswith("http-")]
        if not http_scripts:
            continue
        ev = _harvest_http_evidence(ents, port)
        if ev["sensitive"]:
            out.append(_make("", "", "information_disclosure", "notable",
                f"Sensitive files exposed on port {port}",
                f"The web server exposes: {', '.join(ev['sensitive'])} "
                f"({' '.join(ev['paths'])[:160]}).",
                "Remove version-control metadata, backups and environment files from the web root.",
                port, {"script": "http-enum", "output": "paths: " + ", ".join(ev["paths"])}))
        if ev["admin"]:
            title_ctx = f" (title '{ev['title']}')" if ev["title"] else ""
            out.append(_make("", "", "exposed_admin_panel", "concerning",
                f"Exposed administrative web interface on port {port}{title_ctx}",
                "The web service exposes a management/login interface: "
                f"title='{ev['title']}' server='{ev['server']}'. Check for default credentials.",
                "Validate authentication and authorization; change default credentials.",
                port, {"script": "http-enum/http-title", "output": f"title={ev['title']} server={ev['server']} paths={ev['paths'][:8]}"}))
        elif ev["title"] or ev["server"]:
            out.append(_make("", "", "web_service_exposed", "info",
                f"Web service exposed on port {port}"
                + (f" ('{ev['title']}')" if ev["title"] else ""),
                f"The host runs a web service{(' titled ' + ev['title']) if ev['title'] else ''}"
                f"{(' ' + ev['server']) if ev['server'] else ''} that is reachable from the network.",
                "Ensure the service is patched and access-controlled; consider TLS.",
                port, {"script": "http-title", "output": f"title={ev['title']} server={ev['server']}"}))
        web[port] = ev

    # Global dedup across ports (crypto/TLS findings are per-port already via key).
    seen = set()
    deduped = []
    for f in out:
        port = f["port"]
        key = (f["type"], f["evidence"].get("script"), port)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)

    # Stitch host context into titles so reports are self-contained.
    for f in deduped:
        f["title"] = f["title"].replace(" on port ", f" on {label} port ")
    return {"findings": deduped, "web": web}