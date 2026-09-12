"""Configurable risk-rule catalog.

Every finding type the engine can produce is registered here. Per scan the
operator can disable a rule and/or override the severity (stored in
`scan.risk_rules` as `{"<key>": {"enabled": bool, "severity": "concerning"}}`).
Severity overrides are applied at analysis time so the PDF/API only ever see the
effective severity.
"""

RISK_RULES: list[dict] = [
    {"key": "weak_crypto", "label": "Weak TLS / SSH crypto", "default_severity": "concerning",
     "kind": "nse", "description": "Ciphers/parameters rated weak by ssl-enum-ciphers or ssh2-enum-algos (short keys, 3DES/RC4, deprecated protocols)."},
    {"key": "expired_certificate", "label": "Expired TLS certificate", "default_severity": "notable",
     "kind": "nse", "description": "Certificate is past its validity window (ssl-cert)."},
    {"key": "smb_signing_disabled", "label": "SMB signing not required", "default_severity": "notable",
     "kind": "nse", "description": "SMB signing disabled or not required, enabling man-in-the-middle attacks (smb-security-mode)."},
    {"key": "anonymous_ftp", "label": "Anonymous FTP", "default_severity": "notable",
     "kind": "nse", "description": "FTP server allows anonymous login (ftp-anon)."},
    {"key": "unrestricted_share", "label": "World-writable SMB share", "default_severity": "concerning",
     "kind": "nse", "description": "SMB share allows anonymous writes (smb-enum-shares)."},
    {"key": "dangerous_http_methods", "label": "Dangerous HTTP methods", "default_severity": "notable",
     "kind": "nse", "description": "Web server permits PUT/DELETE/TRACE/PATCH (http-methods)."},
    {"key": "missing_auth", "label": "Missing authentication", "default_severity": "concerning",
     "kind": "nse", "description": "Service exposed without authentication (e.g. MongoDB)."},
    {"key": "empty_password", "label": "Empty password", "default_severity": "critical",
     "kind": "nse", "description": "Account/service accepts an empty password (mysql-empty-password and peers)."},
    {"key": "information_disclosure", "label": "Information disclosure", "default_severity": "notable",
     "kind": "nse", "description": "Sensitive files/source readable via the web server (.git, .env, backups)."},
    {"key": "exposed_admin_panel", "label": "Exposed admin panel", "default_severity": "concerning",
     "kind": "nse", "description": "Administrative login page reachable from the network (identifiable page title/banner)."},
    {"key": "web_service_exposed", "label": "Web service exposed", "default_severity": "info",
     "kind": "web", "description": "Any listening HTTP service — coverage finding so the full web surface is documented."},
    {"key": "default_credentials", "label": "Default credentials", "default_severity": "notable",
     "kind": "heuristic", "description": "Service answers with default credentials (e.g. SNMP community 'public')."},
    {"key": "unencrypted_protocol", "label": "Unencrypted protocol", "default_severity": "info",
     "kind": "heuristic", "description": "Clear-text protocol in use where encryption is expected (Telnet/FTP/SMB/SIP)."},
    {"key": "unencrypted_video", "label": "Unencrypted video stream", "default_severity": "concerning",
     "kind": "heuristic", "description": "Raw RTSP camera/media stream on the LAN."},
    {"key": "eol_software", "label": "End-of-life software", "default_severity": "concerning",
     "kind": "heuristic", "description": "Service version is out of support (banner parsing)."},
    {"key": "known_vulnerability", "label": "Known CVE vulnerability", "default_severity": "critical",
     "kind": "nse", "description": "Exploit-reporting NSE scripts (smb-vuln-*, ssl-ccs-injection, ssl-poodle, ...) and CPE-CVE matches against the offline NVD catalog."},
    {"key": "open_dns_recursion", "label": "Open DNS recursion", "default_severity": "notable",
     "kind": "nse", "description": "DNS server answers recursive lookups for any client, enabling reflection/amplification abuse (dns-recursion)."},
    {"key": "smtp_open_relay", "label": "Open mail relay", "default_severity": "notable",
     "kind": "nse", "description": "SMTP server relays mail for arbitrary senders, enabling spam/phishing abuse (smtp-open-relay)."},
    {"key": "x11_exposed", "label": "Exposed X11 server", "default_severity": "concerning",
     "kind": "nse", "description": "X11 display reachable without access control, allowing screen capture/keylogging (x11-access)."},
    {"key": "rdp_nla_disabled", "label": "RDP without NLA", "default_severity": "concerning",
     "kind": "nse", "description": "RDP accepts sessions without Network Level Authentication, enabling MITM/relay attacks (rdp-enum-encryption)."},
    {"key": "smbv1_enabled", "label": "SMBv1 enabled", "default_severity": "concerning",
     "kind": "nse", "description": "Server negotiates SMBv1 (dialect 1.0.0), enabling wormable exploits like EternalBlue (smb-protocols)."},
]

DEFAULT_RULES: dict = {r["key"]: {"enabled": True, "severity": None} for r in RISK_RULES}


def merged_rules(scan_risk_rules: dict | None) -> dict:
    """Per-scan view of the catalog: defaults merged with stored overrides."""
    cfg = {k: dict(v) for k, v in DEFAULT_RULES.items()}
    for key, over in (scan_risk_rules or {}).items():
        if key not in cfg:
            continue
        if isinstance(over, dict):
            if "enabled" in over:
                cfg[key]["enabled"] = bool(over["enabled"])
            if over.get("severity"):
                cfg[key]["severity"] = over["severity"]
    return cfg


def rule_enabled(cfg: dict, key: str) -> bool:
    return bool(cfg.get(key, {}).get("enabled", True))


def effective_severity(cfg: dict, key: str, current: str) -> str:
    sev = cfg.get(key, {}).get("severity")
    return sev if sev else current


def to_json(cfg: dict) -> list[dict]:
    out = []
    for r in RISK_RULES:
        row = dict(r)
        row["enabled"] = rule_enabled(cfg, r["key"])
        row["severity"] = cfg.get(r["key"], {}).get("severity")
        out.append(row)
    return out


def store_overrides(scan_risk_rules: dict | None, received: list[dict]) -> dict:
    """Merge a client patch (list of {key, enabled, severity}) into stored JSON."""
    current = {k: dict(v) for k, v in (scan_risk_rules or {}).items()}
    for item in received:
        key = item.get("key")
        if not key or key not in DEFAULT_RULES:
            continue
        over = current.setdefault(key, {})
        if "enabled" in item and item["enabled"] is not None:
            over["enabled"] = bool(item["enabled"])
        sev = item.get("severity")
        if sev in (None, ""):
            over.pop("severity", None)
        else:
            over["severity"] = sev
        if not over:
            current.pop(key, None)
    return current