import ipaddress
import re
from typing import List, Optional, Tuple, Union

Target = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

_IPV4_MAX_PREFIX = 32
_IPV6_MAX_PREFIX = 128


def _parse(entry: str) -> Optional[Union[Target, Network]]:
    """Parse an entry as an IP address or CIDR network. Returns None if it is
    neither (which also covers typos and hostnames)."""
    entry = (entry or "").strip()
    if not entry:
        return None
    try:
        return ipaddress.ip_address(entry)
    except ValueError:
        pass
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _prefix_message(entry: str) -> Optional[str]:
    """Return a specific message when a CIDR prefix is out of range."""
    m = re.match(r"^\s*([0-9.]+)/([0-9]+)\s*$", entry or "")
    if m:
        addr = m.group(1)
        try:
            version = ipaddress.ip_address(addr).version
        except ValueError:
            return None
        limit = _IPV4_MAX_PREFIX if version == 4 else _IPV6_MAX_PREFIX
        prefix = int(m.group(2))
        if prefix > limit:
            kind = "IPv4" if version == 4 else "IPv6"
            return (
                f"{kind} CIDR prefix /{prefix} is out of range (max /{limit}). "
                f"Use a prefix such as /{limit - 8} or drop the /xxx suffix for a single host."
            )
    return None


def _suggest_fix(entry: str) -> Optional[str]:
    """Try obvious typo corrections and return a parseable version if possible."""
    cand = entry.strip()
    # 192.168.1.0./24 -> 192.168.1.0/24
    fixed = cand.replace("./", "/")
    if fixed != cand and _parse(fixed) is not None:
        return fixed
    # 192.168.1.0/ -> 192.168.1.0
    if cand.endswith("/"):
        fixed = cand[:-1]
        if _parse(fixed) is not None:
            return fixed
    # 192.168.1.0//24 -> 192.168.1.0/24
    fixed = re.sub(r"/{2,}", "/", cand)
    if fixed != cand and _parse(fixed) is not None:
        return fixed
    return None


def _format_entry_issues(entry: str) -> str:
    """Human explanation + actionable suggestion for a single unparseable entry."""
    entry = entry.strip()
    if any(ch.isalpha() for ch in entry):
        return (
            f"'{entry}' is a hostname, but scan targets must be IPs or subnets. "
            f"Resolve it to an IP (e.g. `192.168.1.5`) or use the containing subnet (e.g. `192.168.1.0/24`)."
        )
    suggestion = _suggest_fix(entry)
    if suggestion:
        return (
            f"'{entry}' is not a valid IP or subnet. Expected `X.X.X.X` (host) or "
            f"`X.X.X.X/prefix` (subnet). Did you mean `{suggestion}`?"
        )
    if "-" in entry and "/" not in entry:
        return (
            f"'{entry}' looks like an IP range, which isn't supported. Use a subnet "
            f"instead, e.g. `192.168.1.10/28`."
        )
    return (
        f"'{entry}' is not a valid IP or subnet. Expected `X.X.X.X` (host, e.g. "
        f"192.168.1.5) or `X.X.X.X/prefix` (subnet, e.g. 192.168.1.0/24)."
    )


def _issue_for_entry(raw: str) -> Tuple[str, str]:
    """Return (entry, issue-message) for one bad target/scope entry."""
    entry = (raw or "").strip()
    prefix_err = _prefix_message(entry)
    if prefix_err:
        return entry, prefix_err
    return entry, _format_entry_issues(entry)


def validate_scan_targets(targets: List[str], authorized_scope: List[str]) -> None:
    """Validate scan target format AND scope containment in one pass.

    Raises ValueError with per-target, actionable messages:

    * targets that aren't IPs/subnets (typos, hostnames, ranges) are reported
      with an explicit expected format and a ''Did you mean...'' suggestion;
    * well-formed targets that fall outside the engagement's authorized scope
      are listed with the authorized scope so the user can fix either side.
    """
    bad_format = []
    outside = []
    for raw in targets or []:
        entry = (raw or "").strip()
        if not entry:
            bad_format.append(_issue_for_entry(raw))
            continue
        parsed = _parse(entry)
        if parsed is None:
            bad_format.append(_issue_for_entry(raw))
        elif not is_target_in_scope(entry, authorized_scope):
            outside.append(entry)

    problems = []
    if bad_format:
        problems.append("Badly formatted target(s):")
        problems.extend(f"  - {e}: {msg}" for e, msg in bad_format)
    if outside:
        problems.append(
            "Target(s) outside the engagement's authorized scope "
            f"({', '.join(authorized_scope) or 'empty'}):"
        )
        problems.extend(f"  - {t}" for t in outside)
        problems.append(
            "Only addresses inside the engagement's authorized IPs/subnets can be "
            "scanned. Widen the engagement's scope (Edit engagement) if needed."
        )
    if problems:
        raise ValueError("\n".join(problems))


def is_target_in_scope(target: str, authorized_scope: List[str]) -> bool:
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        try:
            target_net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
        return any(target_net.subnet_of(ipaddress.ip_network(scope, strict=False)) for scope in authorized_scope)
    
    for scope in authorized_scope:
        try:
            scope_net = ipaddress.ip_network(scope, strict=False)
            if target_ip in scope_net:
                return True
        except ValueError:
            continue
    return False

def validate_targets_in_scope(targets: List[str], authorized_scope: List[str]) -> List[str]:
    invalid = [t for t in targets if not is_target_in_scope(t, authorized_scope)]
    if invalid:
        raise ValueError(f"Targets outside authorized scope: {', '.join(invalid)}")
    return targets

def count_hosts_in_scope(targets: List[str]) -> int:
    total = 0
    for t in targets:
        addr_or_net = _parse(t)
        if addr_or_net is None:
            continue
        if isinstance(addr_or_net, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            total += 1
            continue
        net = addr_or_net
        # Mirror net.hosts(): IPv4 networks have network/broadcast addresses
        # excluded, except point-to-point /31 and single-host /32.
        if net.version == 4 and net.prefixlen < 31:
            total += net.num_addresses - 2
        else:
            total += net.num_addresses
    return total


def validate_scope(scope: List[str]) -> None:
    """Validate an engagement's authorized scope list, raising ValueError with
    the offending entries.

    Entries that clearly describe numeric IP targets must parse as an IP
    address or CIDR network (an easy typo like ``192.168.1.0./24`` is rejected
    here instead of silently never matching at scan time). Non-numeric entries
    (hostnames such as ``fileserver.lan``) are treated as plain labels and
    allowed through as-is.
    """
    if not scope:
        return
    bad = []
    for entry in scope:
        entry = (entry or "").strip()
        if not entry:
            continue
        # Contains alphabetic chars -> assume hostname label, accept.
        if any(ch.isalpha() for ch in entry):
            continue
        if _parse(entry) is None:
            bad.append(_issue_for_entry(entry))
    if bad:
        lines = ["Invalid scope entry(ies):"]
        lines.extend(f"  - {e}: {msg}" for e, msg in bad)
        lines.append("Expected formats: 192.168.1.0/24 (subnet) or 192.168.1.5 (single host).")
        raise ValueError("\n".join(lines))