"""
VLAN Analyzer
Analyzes VLAN configuration and segmentation for security issues
"""
import logging
from typing import Dict, List, Set
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class VLANFinding:
    """Represents a VLAN security finding"""
    severity: str
    vlan_id: int
    vlan_name: str
    issue: str
    reason: str
    solution: str
    details: Dict


class VLANAnalyzer:
    """Analyzes VLAN configuration for security issues"""

    def __init__(self, rules_config: Dict, exceptions: List[Dict]):
        self.rules_config = rules_config
        self.exceptions = exceptions
        self.vlan_security = rules_config.get("vlan_security", {})
        self.recommended_vlans = rules_config.get("network_segmentation", {}).get("recommended_vlans", [])

    def analyze(self, vlans: List[Dict], interfaces: Dict, firewall_rules: List[Dict]) -> List[VLANFinding]:
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

    def _analyze_vlan_isolation(self, vlans: List[Dict], firewall_rules: List[Dict]) -> List[VLANFinding]:
        """Check if VLANs are properly isolated"""
        findings = []

        # Build VLAN connectivity map from firewall rules
        vlan_connections = defaultdict(set)

        for rule in firewall_rules:
            if rule.get("enabled") != "1" or rule.get("action") != "pass":
                continue

            src_interface = rule.get("interface", "")
            dst_net = rule.get("destination_net", "")

            # Track which VLANs can reach which destinations
            for vlan in vlans:
                vlan_interface = vlan.get("if", "")
                if src_interface and vlan_interface in src_interface:
                    vlan_connections[vlan.get("tag")].add(dst_net)

        # Check for overly permissive inter-VLAN routing
        for vlan in vlans:
            vlan_tag = vlan.get("tag")
            vlan_desc = vlan.get("descr", f"VLAN {vlan_tag}")

            connections = vlan_connections.get(vlan_tag, set())

            # Check if VLAN can reach "any" or too many destinations
            if "any" in connections or len(connections) > 5:
                if not self._is_vlan_exception_allowed("vlan_isolation", vlan_tag):
                    findings.append(VLANFinding(
                        severity="HIGH",
                        vlan_id=vlan_tag,
                        vlan_name=vlan_desc,
                        issue="VLAN hat zu weitreichende Routing-Berechtigungen",
                        reason="VLANs sollten nur mit notwendigen Netzwerken kommunizieren können",
                        solution=f"Beschränke Inter-VLAN Routing für VLAN {vlan_tag} auf spezifische benötigte Netzwerke",
                        details={"allowed_destinations": list(connections)[:10]}
                    ))

        return findings

    def _check_management_vlan(self, vlans: List[Dict]) -> List[VLANFinding]:
        """Check if management VLAN exists and is properly configured"""
        findings = []

        # Look for management VLAN (typically VLAN 10 or contains 'management' in name)
        management_vlans = [
            v for v in vlans
            if v.get("tag") == 10 or "manage" in v.get("descr", "").lower()
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

    def _check_guest_isolation(self, vlans: List[Dict], firewall_rules: List[Dict]) -> List[VLANFinding]:
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
            # Check if guest VLAN has access to internal networks
            for guest_vlan in guest_vlans:
                vlan_tag = guest_vlan.get("tag")
                vlan_interface = guest_vlan.get("if", "")

                # Check firewall rules for guest VLAN access
                has_internal_access = False
                for rule in firewall_rules:
                    if rule.get("enabled") != "1" or rule.get("action") != "pass":
                        continue

                    src_interface = rule.get("interface", "")
                    dst_net = rule.get("destination_net", "")

                    if vlan_interface in src_interface:
                        # Check if destination is internal network
                        internal_nets = ["192.168.", "10.", "172.16.", "172.17.", "172.18."]
                        if any(net in str(dst_net) for net in internal_nets):
                            has_internal_access = True
                            break

                if has_internal_access:
                    findings.append(VLANFinding(
                        severity="HIGH",
                        vlan_id=vlan_tag,
                        vlan_name=guest_vlan.get("descr", "Guest"),
                        issue="Guest VLAN hat Zugriff auf interne Netzwerke",
                        reason="Guest-Geräte sollten nur Internet-Zugriff haben",
                        solution=f"Blockiere Zugriff von VLAN {vlan_tag} auf interne RFC1918 Netzwerke",
                        details={"vlan": vlan_tag}
                    ))

        return findings

    def _check_vlan_security(self, vlans: List[Dict]) -> List[VLANFinding]:
        """Check for VLAN-specific security issues"""
        findings = []

        # Check for VLAN 1 usage (default VLAN)
        vlan_1_in_use = any(v.get("tag") == 1 for v in vlans)
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

        # Check for unusual VLAN ranges
        for vlan in vlans:
            vlan_tag = vlan.get("tag")
            if vlan_tag > 4094:
                findings.append(VLANFinding(
                    severity="LOW",
                    vlan_id=vlan_tag,
                    vlan_name=vlan.get("descr", "Unknown"),
                    issue=f"VLAN ID {vlan_tag} außerhalb normalem Bereich",
                    reason="VLAN IDs sollten zwischen 2 und 4094 liegen",
                    solution=f"Verwende VLAN IDs im Standard-Bereich (2-4094)",
                    details={"vlan": vlan_tag}
                ))

        return findings

    def _check_segmentation_best_practices(self, vlans: List[Dict]) -> List[VLANFinding]:
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

    def get_vlan_recommendations(self) -> List[Dict]:
        """Get recommended VLAN structure"""
        return self.recommended_vlans
