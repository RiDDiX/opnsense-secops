"""
Router Advertisement checks.

Reads /api/radvd/settings/searchEntry. Findings cover dangerous modes
(managed without RA, assist without DHCPv6) and missing entries on
LAN-style interfaces that have a global v6 prefix.
"""
from dataclasses import dataclass, field


@dataclass
class RadvdFinding:
    severity: str
    rule_id: str
    rule_description: str
    issue: str
    reason: str
    solution: str
    rule_details: dict
    interface: str = ""
    opnsense_path: str = "Services > Router Advertisements"
    implementation_steps: list[str] = field(default_factory=list)


_VALID_MODES = {"router", "unmanaged", "managed", "assist", "stateless"}


class RadvdAnalyzer:
    def __init__(self, exceptions: list[dict] | None = None) -> None:
        self.exceptions = exceptions or []

    def analyze(self, radvd_entries: list[dict], interfaces_info: list[dict] | None = None) -> list[RadvdFinding]:
        findings: list[RadvdFinding] = []
        seen_ifaces = set()

        for entry in radvd_entries or []:
            iface = entry.get("interface") or entry.get("%interface") or ""
            seen_ifaces.add(iface)
            if str(entry.get("enabled", "0")) != "1":
                continue
            mode = (entry.get("ramode") or entry.get("mode") or "").lower()
            if mode and mode not in _VALID_MODES:
                findings.append(RadvdFinding(
                    severity="MEDIUM",
                    rule_id=entry.get("uuid", iface),
                    rule_description=f"radvd entry on {iface}",
                    issue=f"Unbekannter RA Modus '{mode}'",
                    reason="OPNsense unterstuetzt: router, unmanaged, managed, assist, stateless.",
                    solution="Auf einen der gueltigen Modi setzen.",
                    rule_details=entry,
                    interface=iface,
                ))

        # Skip uplinks, loopback, and tunnel-style devices, only LAN/VLAN/DMZ
        # need RA on a normal OPNsense setup.
        skip_link_types = {"dhcp", "pppoe", "ppp", "none"}
        skip_device_prefixes = ("lo", "tailscale", "wg", "ovpn", "openvpn", "ipsec", "tun", "tap", "gif", "gre", "enc", "pflog")
        for row in interfaces_info or []:
            iface_descr = row.get("description") or row.get("identifier") or ""
            if not iface_descr:
                continue
            if not row.get("addr6"):
                continue
            ident = (row.get("identifier") or "").lower()
            device = (row.get("device") or "").lower()
            link_type = (row.get("link_type") or "").lower()
            if ident in {"wan", "lo0"}:
                continue
            if link_type in skip_link_types:
                continue
            if any(device.startswith(p) for p in skip_device_prefixes):
                continue
            if iface_descr in seen_ifaces or row.get("identifier") in seen_ifaces:
                continue
            findings.append(RadvdFinding(
                severity="LOW",
                rule_id=f"radvd_missing_{ident or iface_descr}",
                rule_description=f"radvd missing on {iface_descr}",
                issue=f"Interface {iface_descr} hat globales IPv6, aber keinen RA Eintrag",
                reason=(
                    "Mit globalem v6 Praefix aber ohne RA bekommen Hosts hinter dem "
                    "Interface keine Default Route per RA. Falls dnsmasq RA macht, "
                    "ist das in Ordnung. Sonst stille Konnektivitaetsluecke."
                ),
                solution="Entweder RA Entry anlegen oder pruefen ob dnsmasq RA Mode aktiv ist.",
                rule_details={"interface": iface_descr, "identifier": row.get("identifier")},
                interface=row.get("identifier", iface_descr),
            ))

        return findings
