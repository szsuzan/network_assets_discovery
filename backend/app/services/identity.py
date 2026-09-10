"""Device identity for host deduplication.

A single physical device (a laptop on Wi-Fi + Ethernet, a phone with privacy-MAC
rotation) publishes the same mDNS/NetBIOS hostname on several IPs. Two Host rows
in one scan that share a *non-generic* published hostname are treated as the same
logical device and folded into one canonical row (extra IPs kept in
Host.secondary_ips, MAC history in Host.macs).

Hostnames that do NOT uniquely identify a device (generic words like "android",
"pc", or "android-2") return None so identical generic names are never merged.
"""
import re
from typing import Optional

_GENERIC_HOSTNAMES = {
    "android", "android-2", "android-3", "android-4", "android-5", "android-6",
    "android-7", "android-8", "android-9", "host", "host-1", "host-2", "pc",
    "desktop", "laptop", "server", "workstation", "nas", "printer", "camera",
    "router", "gateway", "modem", "switch", "ap", "wap", "access point", "tv",
    "iphone", "ipad", "macbook", "imac", "unknown", "none", "device",
    "localhost", "dhcp", "default", "ubnt", "raspberry", "raspberrypi",
    "esp32", "esp8266",
}
_ANDROID_GENERIC_RE = re.compile(r"^android[-_\d]+$")


def identity_hostname(name) -> Optional[str]:
    """Normalise a published hostname into an identity key, or None if the name
    is generic (two hosts sharing it are different devices, not duplicates)."""
    if not name:
        return None
    s = " ".join(str(name).strip().lower().split())
    if not s or s in _GENERIC_HOSTNAMES or s.isdigit():
        return None
    if _ANDROID_GENERIC_RE.match(s):
        return None  # android-2, android_3... never identifiable
    return s