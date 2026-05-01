"""VLAN segmentation analyzer."""
import logging
from collections import defaultdict
from dataclasses import dataclass

from src.analyzers._utils import is_rfc1918, truthy

logger = logging.getLogger(__name__)


def _vlan_tag(v: dict) -> str:
    return str(v.get("tag", "") or "").strip()


@dataclass
class VLANFinding:
    """Represents a VLAN security finding"""
    severity: str
    vlan_id: int
    vlan_name: str
    issue: str
    reason: str
    solution: str
    details: dict


class VLANAnalyzer:
    """Analyzes VLAN configuration for security issues"""

    def __init__(self, rules_config: dict, exceptions: list[dict]):
        self.rules_config = rules_config
        self.exceptions = exceptions
        self.vlan_security = rules_config.get("vlan_security", {})
        self.recommended_vlans = rules_config.get("network_segmentation", {}).get("recommended_vlans", [])

    def analyze(self, vlans: list[dict], interfaces: dict, firewall_rules: list[dict]) -> list[VLANFinding]:
        """Analyze VLAN configuration and segmentation"""
        findings = []

        if not vlans:
            findings.append(VLANFinding(
                severity="MEDIUM",
                vlan_id=0,
                vlan_name="N/A",
                issue="Keine VLANs konfiguriert",
                reason="Netzwerk-Segmentierung fehlt, alle Geräte im selben Broadcast-Domain",
                solution="Implementiere VLANs für Netzwerk-Segmentierung (Management, Server, Workstations, IoT, Guest)",
                details={"current_vlans": 0, "recommended_vlans": len(self.recommended_vlans)}
            ))
            return findings

        # Analyze VLAN isolation
        findings.extend(self._analyze_vlan_isolation(vlans, firewall_rules))

        # Check for management VLAN
        findings.extend(self._check_management_vlan(vlans))

        # Check for guest network isolation
        findings.extend(self._check_guest_isolation(vlans, firewall_rules))

        # Analyze VLAN tagging security
        findings.extend(self._check_vlan_security(vlans))

        # Check recommended segmentation
        findings.extend(self._check_segmentation_best_practices(vlans))

        return findings

    def _analyze_vlan_isolation(self, vlans: list[dict], firewall_rules: list[dict]) -> list[VLANFinding]:
        """Check if VLANs are properly isolated"""
        findings = []

        # Build VLAN connectivity map from firewall rules
        vlan_connections = defaultdict(set)

        for rule in firewall_rules:
            if not truthy(rule.get("enabled")) or rule.get("action") != "pass":
                continue

            src_interfaces = {i for i in (rule.get("interface", "") or "").split(",") if i}
            dst_net = rule.get("destination_net", "")

            for vlan in vlans:
                vlan_interface = vlan.get("if", "")
                if vlan_interface and vlan_interface in src_interfaces:
                    vlan_connections[_vlan_tag(vlan)].add(dst_net)

        # Check for overly permissive inter-VLAN routing.
        max_dest = self.vlan_security.get("max_destinations_per_vlan", 8)
        for vlan in vlans:
            vlan_tag = _vlan_tag(vlan)
            vlan_desc = vlan.get("descr", f"VLAN {vlan_tag}")

            connections = vlan_connections.get(vlan_tag, set())

            if "any" in connections or len(connections) > max_dest:
                if not self._is_vlan_exception_allowed("vlan_isolation", vlan_tag):
                    findings.append(VLANFinding(
                        severity="HIGH",
                        vlan_id=int(vlan_tag) if vlan_tag.isdigit() else 0,
                        vlan_name=vlan_desc,
                        issue="VLAN hat zu weitreichende Routing-Berechtigungen",
                        reason="VLANs sollten nur mit notwendigen Netzwerken kommunizieren.",
                        solution=f"Inter-VLAN Routing fuer VLAN {vlan_tag} auf benoetigte Netze beschraenken.",
                        details={"allowed_destinations": list(connections)[:10]},
                    ))

        return findings

    def _check_management_vlan(self, vlans: list[dict]) -> list[VLANFinding]:
        """Check if management VLAN exists and is properly configured"""
        findings = []

        # Management VLAN: tag 10 or 'manage' in description.
        management_vlans = [
            v for v in vlans
            if _vlan_tag(v) == "10" or "manage" in (v.get("descr", "") or "").lower()
        ]

        if not management_vlans:
            findings.append(VLANFinding(
                severity="CRITICAL",
                vlan_id=0,
                vlan_name="Management VLAN",
                issue="Kein dediziertes Management VLAN konfiguriert",
                reason="Management-Traffic sollte in separatem VLAN isoliert sein",
                solution="Erstelle VLAN 10 für Management (OPNsense, Switches, APs, etc.)",
                details={"recommended_vlan_id": 10}
            ))

        return findings

    def _check_guest_isolation(self, vlans: list[dict], firewall_rules: list[dict]) -> list[VLANFinding]:
        """Check if guest network is properly isolated"""
        findings = []

        # Look for guest VLAN
        guest_vlans = [
            v for v in vlans
            if "guest" in v.get("descr", "").lower()
        ]

        if not guest_vlans:
            findings.append(VLANFinding(
                severity="MEDIUM",
                vlan_id=0,
                vlan_name="Guest VLAN",
                issue="Kein dediziertes Guest VLAN",
                reason="Gast-Geräte sollten vom internen Netzwerk isoliert sein",
                solution="Erstelle separates Guest VLAN (z.B. VLAN 50) mit Internet-Only Zugriff",
                details={"recommended_vlan_id": 50}
            ))
        else:
            for guest_vlan in guest_vlans:
                vlan_tag = _vlan_tag(guest_vlan)
                vlan_interface = guest_vlan.get("if", "")

                has_internal_access = False
                for rule in firewall_rules:
                    if not truthy(rule.get("enabled")) or rule.get("action") != "pass":
                        continue
                    src_interfaces = {i for i in (rule.get("interface", "") or "").split(",") if i}
                    dst_net = rule.get("destination_net", "")
                    if vlan_interface and vlan_interface in src_interfaces and is_rfc1918(dst_net):
                        has_internal_access = True
                        break

                if has_internal_access:
                    findings.append(VLANFinding(
                        severity="HIGH",
                        vlan_id=int(vlan_tag) if vlan_tag.isdigit() else 0,
                        vlan_name=guest_vlan.get("descr", "Guest"),
                        issue="Guest VLAN hat Zugriff auf interne Netzwerke",
                        reason="Guest-Geraete sollten nur Internet-Zugriff haben.",
                        solution=f"Zugriff von VLAN {vlan_tag} auf RFC1918-Netze blockieren.",
                        details={"vlan": vlan_tag},
                    ))

        return findings

    def _check_vlan_security(self, vlans: list[dict]) -> list[VLANFinding]:
        """Check for VLAN-specific security issues"""
        findings = []

        # Check for VLAN 1 usage (default VLAN).
        vlan_1_in_use = any(_vlan_tag(v) == "1" for v in vlans)
        if vlan_1_in_use:
            findings.append(VLANFinding(
                severity="MEDIUM",
                vlan_id=1,
                vlan_name="Default VLAN",
                issue="VLAN 1 wird verwendet",
                reason="VLAN 1 ist das Default VLAN und sollte nicht verwendet werden",
                solution="Verwende VLAN 1 nicht für produktiven Traffic, nutze höhere VLAN IDs",
                details={"vlan": 1}
            ))

        # Check for unusual or invalid VLAN tags. Valid 802.1Q range is 1-4094.
        for vlan in vlans:
            vlan_tag = _vlan_tag(vlan)
            try:
                vlan_tag_int = int(vlan_tag) if vlan_tag else -1
            except (ValueError, TypeError):
                vlan_tag_int = -1
            if vlan_tag_int < 1 or vlan_tag_int > 4094:
                findings.append(VLANFinding(
                    severity="LOW",
                    vlan_id=vlan_tag_int if vlan_tag_int > 0 else 0,
                    vlan_name=vlan.get("descr", "Unknown"),
                    issue=f"VLAN ID '{vlan_tag}' ausserhalb 1..4094",
                    reason="802.1Q erlaubt VLAN IDs 1..4094, alles andere wird vom Switch verworfen.",
                    solution="VLAN ID im Bereich 2..4094 verwenden.",
                    details={"vlan": vlan_tag},
                ))

        return findings

    def _check_segmentation_best_practices(self, vlans: list[dict]) -> list[VLANFinding]:
        """Check against recommended VLAN segmentation"""
        findings = []

        existing_purposes = set()
        for vlan in vlans:
            desc = vlan.get("descr", "").lower()
            existing_purposes.add(desc)

        # Check for recommended VLANs
        recommended_purposes = {
            "management": "Dediziertes VLAN für Infrastruktur-Management",
            "server": "Separates VLAN für Server und Services",
            "iot": "Isoliertes VLAN für IoT-Geräte",
            "guest": "Isoliertes VLAN für Gäste"
        }

        missing_vlans = []
        for purpose, description in recommended_purposes.items():
            if not any(purpose in existing.lower() for existing in existing_purposes):
                missing_vlans.append(f"{purpose} ({description})")

        if missing_vlans and len(vlans) < 4:
            findings.append(VLANFinding(
                severity="MEDIUM",
                vlan_id=0,
                vlan_name="Segmentation",
                issue="Unvollständige Netzwerk-Segmentierung",
                reason="Best Practice empfiehlt dedizierte VLANs für verschiedene Zwecke",
                solution=f"Erwäge Erstellung von VLANs für: {', '.join(missing_vlans)}",
                details={
                    "current_vlans": len(vlans),
                    "missing_purposes": missing_vlans,
                    "recommended": self.recommended_vlans
                }
            ))

        return findings

    def _is_vlan_exception_allowed(self, check: str, vlan_id: int) -> bool:
        """Check if VLAN is in exceptions"""
        for exc in self.exceptions:
            if exc.get("check") == check:
                allowed_vlans = exc.get("vlans", [])
                if vlan_id in allowed_vlans:
                    return True
        return False

    def get_vlan_recommendations(self) -> list[dict]:
        """Get recommended VLAN structure"""
        return self.recommended_vlans
