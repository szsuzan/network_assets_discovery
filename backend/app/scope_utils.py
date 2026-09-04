import ipaddress
from typing import List

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
        try:
            addr = ipaddress.ip_address(t)
            total += 1
            continue
        except ValueError:
            pass
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            total += 1
            continue
        # Mirror net.hosts(): IPv4 networks have network/broadcast addresses
        # excluded, except point-to-point /31 and single-host /32.
        if net.version == 4 and net.prefixlen < 31:
            total += net.num_addresses - 2
        else:
            total += net.num_addresses
    return total
