"""Shared helpers for analyzers."""
from __future__ import annotations

import ipaddress

# RFC1918 blocks per RFC1918 sec 3.
_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

# OPNsense WAN interface keys reported by /interfaces/overview/interfacesInfo.
# Use "type" not name where possible. Names are user-renamable.
_WAN_TYPE_KEYS = {"wan"}


def truthy(val) -> bool:
    """Return True for OPNsense-style truthy values.

    OPNsense returns enabled flags as "1"/"0" strings, sometimes booleans, sometimes
    a dict like {"value": "1", "selected": 1} from form-rendered settings.
    """
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val != 0
    if isinstance(val, dict):
        if "selected" in val:
            return truthy(val["selected"])
        if "value" in val:
            return truthy(val["value"])
        # form-key style: dict of options where the active key has selected=1
        for v in val.values():
            if isinstance(v, dict) and truthy(v.get("selected", "0")):
                return True
        return False
    s = str(val).strip().lower()
    return s in ("1", "true", "yes", "on", "enabled")


def first_truthy(*vals) -> bool:
    return any(truthy(v) for v in vals)


def is_rfc1918(addr: str) -> bool:
    """True for any IP literal or CIDR fully contained in RFC1918."""
    s = str(addr or "").strip()
    if not s:
        return False
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            if net.version != 4:
                return False
            return any(net.subnet_of(p) for p in _RFC1918_NETS)
        ip = ipaddress.ip_address(s)
        if ip.version != 4:
            return False
        return any(ip in p for p in _RFC1918_NETS)
    except (ValueError, TypeError):
        return False


def is_any(val) -> bool:
    """OPNsense source/dest 'any' equivalents."""
    s = str(val or "").strip().lower()
    return s in ("", "any", "0.0.0.0/0", "::/0")


def is_wan_iface(iface_id: str, ifaces_info: list[dict] | None = None) -> bool:
    """Check whether iface_id is the WAN interface using interfacesInfo when available."""
    s = (iface_id or "").lower()
    if not s:
        return False
    if ifaces_info:
        for row in ifaces_info:
            if (row.get("identifier") or "").lower() != s:
                continue
            t = (row.get("type") or row.get("ifname_type") or "").lower()
            if t in _WAN_TYPE_KEYS:
                return True
            descr = (row.get("descr") or "").lower()
            if descr == "wan" or descr.startswith("wan "):
                return True
            return False
    return s == "wan" or s.startswith("wan_") or s.startswith("opt_wan")


def iface_subnet(iface_id: str, ifaces_info: list[dict] | None) -> ipaddress.IPv4Network | None:
    """Return the v4 subnet configured on iface_id, when available."""
    if not iface_id or not ifaces_info:
        return None
    s = iface_id.lower()
    for row in ifaces_info:
        if (row.get("identifier") or "").lower() != s:
            continue
        addr = row.get("addr4") or row.get("ipaddr") or ""
        prefix = row.get("subnet4") or row.get("subnet") or ""
        if not addr:
            continue
        try:
            if isinstance(prefix, str) and "/" in addr:
                return ipaddress.ip_network(addr, strict=False)
            if prefix:
                return ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        except (ValueError, TypeError):
            continue
    return None
