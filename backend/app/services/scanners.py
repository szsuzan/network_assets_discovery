"""Active network scanning helpers used by the Celery scan worker.

Every function degrades gracefully to an empty return value if its underlying
tool/library is not installed or lacks permissions, so scans never hard-fail
because of a missing dependency.
"""
import logging
import subprocess

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# MAC vendor lookup (OUI database)
# --------------------------------------------------------------------------- #
def mac_vendor(mac: str) -> str | None:
    """Look up a MAC address prefix in the Wireshark OUI database.

    Returns a vendor string or None if unknown/unavailable.
    """
    norm = "".join(c for c in (mac or "") if c.isalnum()).upper()
    if len(norm) < 6:
        return None
    prefix = ":".join(norm[i:i + 2] for i in range(0, 6, 2))
    try:
        from manuf import manuf
        parser = manuf.MacParser()
        return parser.get_manuf(prefix)
    except Exception:
        pass

    # Fallback: /sys/class/net vendor-independent local file is unlikely to help
    # in a container, so return None rather than fabricate data.
    return None


# --------------------------------------------------------------------------- #
# SNMP walk (device OS / system identification) via snmpwalk or pysnmp
# --------------------------------------------------------------------------- #
SNMP_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
SNMP_SYSDESCR = "1.3.6.1.2.1.1.1.0"
SNMP_SYSNAME = "1.3.6.1.2.1.1.5.0"
SNMP_SYSLOCATION = "1.3.6.1.2.1.1.6.0"
SNMP_SYSUPTIME = "1.3.6.1.2.1.1.3.0"

# Map sysObjectID prefixes to device/OS interpretations.
SYSOBJECT_HINTS = {
    "1.3.6.1.4.1.9": "Cisco",
    "1.3.6.1.4.1.2636": "Juniper",
    "1.3.6.1.4.1.14988": "MikroTik",
    "1.3.6.1.4.1.11": "HP/HPE",
    "1.3.6.1.4.1.318": "APC",
    "1.3.6.1.4.1.8072": "Linux (net-snmp)",
    "1.3.6.1.4.1.2021": "Linux (net-snmp)",
    "1.3.6.1.4.1.311": "Windows Server",
    "1.3.6.1.4.1.4413": "Windows (QADelegate)",
    "1.3.6.1.4.1.671": "Ubiquiti",
    "1.3.6.1.4.1.4242": "Proxmox/QEMU",
    "1.3.6.1.4.1.3375": "Citrix NetScaler",
}


def snmp_walk(ip: str, community: str = "public", timeout: float = 3.0) -> dict:
    """Gather basic SNMP system info from a host via the net-snmp CLI.

    Returns a dict with keys sys_descr, sys_name, sys_location, sys_objectid,
    uptime, vendor and default_community_found. Returns {} if the host does not
    respond to SNMP or the snmpget CLI is unavailable.
    """
    oids = [SNMP_SYSDESCR, SNMP_SYSNAME, SNMP_SYSLOCATION, SNMP_SYSOBJECTID, SNMP_SYSUPTIME]
    labels = ["sys_descr", "sys_name", "sys_location", "sys_objectid", "uptime"]
    values = {}

    for oid, label in zip(oids, labels):
        try:
            proc = subprocess.run(
                ["snmpget", "-v1", "-c", community, "-t", str(int(timeout)),
                 "-r", "0", "-On", str(ip), oid],
                capture_output=True, text=True, timeout=timeout + 1,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            log.debug("snmpget failed for %s: %s", ip, exc)
            return {}

        out = proc.stdout.strip()
        if "Time out" in out or "No Response" in out or "snmpget: " in out or "=" not in out:
            return {}
        value = out.split("=", 1)[1].strip()
        # Strip leading OID/type noise like "STRING: " — keep the raw value.
        if ": " in value and not value.startswith("OID:"):
            value = value.split(": ", 1)[1].strip('"')
        values[label] = value

    if not values.get("sys_objectid"):
        return {}

    vendor = None
    if values.get("sys_objectid"):
        for prefix, name in SYSOBJECT_HINTS.items():
            if values["sys_objectid"].startswith(prefix):
                vendor = name
                break
    values["vendor"] = vendor
    values["default_community_found"] = True
    return values

