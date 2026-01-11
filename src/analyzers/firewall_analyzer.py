"""
Firewall Rule Analyzer
Analyzes firewall rules for security issues
"""
import logging
from typing import Dict, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FirewallFinding:
    """Represents a security finding in firewall rules"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    rule_id: str
    rule_description: str
    issue: str
    reason: str
    solution: str
    rule_details: Dict


class FirewallAnalyzer:
    """Analyzes firewall rules for security issues"""

    def __init__(self, rules_config: Dict, exceptions: List[Dict]):
        self.rules_config = rules_config
        self.exceptions = exceptions

    def analyze(self, firewall_rules: List[Dict], nat_rules: List[Dict]) -> List[FirewallFinding]:
        """Analyze firewall and NAT rules"""
        findings = []

        findings.extend(self._analyze_firewall_rules(firewall_rules))
        findings.extend(self._analyze_nat_rules(nat_rules))

        return findings

    def _analyze_firewall_rules(self, rules: List[Dict]) -> List[FirewallFinding]:
        """Analyze firewall filter rules"""
        findings = []

        for rule in rules:
            if not rule.get("enabled", "0") == "1":
                continue

            # Check for any-to-any rules
            if self._is_any_to_any(rule):
                findings.append(FirewallFinding(
                    severity="CRITICAL",
                    rule_id=rule.get("uuid", "unknown"),
                    rule_description=rule.get("description", "No description"),
                    issue="Any-to-Any Rule",
                    reason="Diese Regel erlaubt Traffic von überall nach überall ohne Einschränkungen",
                    solution="Definiere spezifische Source und Destination Adressen/Netzwerke",
                    rule_details=rule
                ))

            # Check for WAN incoming rules
            if self._is_insecure_wan_rule(rule):
                findings.append(FirewallFinding(
                    severity="HIGH",
                    rule_id=rule.get("uuid", "unknown"),
                    rule_description=rule.get("description", "No description"),
                    issue="Eingehender WAN Traffic ohne Einschränkung",
                    reason="Erlaubt eingehenden Traffic vom Internet ohne Port-Beschränkung",
                    solution="Beschränke eingehenden WAN Traffic auf spezifische, notwendige Ports",
                    rule_details=rule
                ))

            # Check for missing logging on important rules
            if self._should_have_logging(rule) and not self._has_logging(rule):
                findings.append(FirewallFinding(
                    severity="MEDIUM",
                    rule_id=rule.get("uuid", "unknown"),
                    rule_description=rule.get("description", "No description"),
                    issue="Fehlende Logging-Aktivierung",
                    reason="Wichtige Firewall-Regeln sollten geloggt werden für Forensik",
                    solution="Aktiviere Logging für diese Regel in den Regel-Einstellungen",
                    rule_details=rule
                ))

            # Check for overly permissive protocol rules
            if self._is_overly_permissive(rule):
                findings.append(FirewallFinding(
                    severity="MEDIUM",
                    rule_id=rule.get("uuid", "unknown"),
                    rule_description=rule.get("description", "No description"),
                    issue="Zu permissive Protokoll-Regel",
                    reason="Regel erlaubt 'any' Protokoll statt spezifischer Protokolle",
                    solution="Definiere spezifische Protokolle (TCP, UDP, ICMP) statt 'any'",
                    rule_details=rule
                ))

        return findings

    def _analyze_nat_rules(self, rules: List[Dict]) -> List[FirewallFinding]:
        """Analyze NAT port forwarding rules"""
        findings = []

        for rule in rules:
            if not rule.get("enabled", "0") == "1":
                continue

            # Check for port forwards to critical services
            dst_port = rule.get("destination_port", "")
            if self._is_critical_port_forward(dst_port):
                findings.append(FirewallFinding(
                    severity="CRITICAL",
                    rule_id=rule.get("uuid", "unknown"),
                    rule_description=rule.get("description", "No description"),
                    issue=f"Port Forward zu kritischem Service (Port {dst_port})",
                    reason="Dieser Port sollte nicht vom Internet aus erreichbar sein",
                    solution=f"Entferne Port Forward für Port {dst_port} oder beschränke Source IPs",
                    rule_details=rule
                ))

            # Check for unrestricted source in port forwards
            if self._has_unrestricted_source(rule):
                findings.append(FirewallFinding(
                    severity="HIGH",
                    rule_id=rule.get("uuid", "unknown"),
                    rule_description=rule.get("description", "No description"),
                    issue="Port Forward ohne Source-Einschränkung",
                    reason="Port Forward erlaubt Zugriff von überall im Internet",
                    solution="Beschränke Source auf bekannte/vertrauenswürdige IP-Adressen wenn möglich",
                    rule_details=rule
                ))

        return findings

    def _is_any_to_any(self, rule: Dict) -> bool:
        """Check if rule is any-to-any"""
        src = rule.get("source_net", "").lower()
        dst = rule.get("destination_net", "").lower()

        any_values = ["any", "", "0.0.0.0/0", "::/0"]

        return src in any_values and dst in any_values

    def _is_insecure_wan_rule(self, rule: Dict) -> bool:
        """Check if rule allows insecure WAN access"""
        interface = rule.get("interface", "").lower()
        direction = rule.get("direction", "").lower()
        action = rule.get("action", "").lower()
        dst = rule.get("destination_net", "").lower()

        # Check if it's an incoming WAN rule that allows traffic
        is_wan = "wan" in interface
        is_incoming = direction == "in"
        is_allow = action == "pass"
        is_broad_destination = dst in ["any", "", "0.0.0.0/0"]

        return is_wan and is_incoming and is_allow and is_broad_destination

    def _should_have_logging(self, rule: Dict) -> bool:
        """Determine if rule should have logging enabled"""
        interface = rule.get("interface", "").lower()
        action = rule.get("action", "").lower()

        # WAN rules and block rules should be logged
        return "wan" in interface or action == "block"

    def _has_logging(self, rule: Dict) -> bool:
        """Check if rule has logging enabled"""
        return rule.get("log", "0") == "1"

    def _is_overly_permissive(self, rule: Dict) -> bool:
        """Check if rule is overly permissive with protocols"""
        protocol = rule.get("protocol", "").lower()
        action = rule.get("action", "").lower()

        return protocol in ["any", ""] and action == "pass"

    def _is_critical_port_forward(self, port: str) -> bool:
        """Check if port forward is to a critical service"""
        critical_ports = self.rules_config.get("firewall_rules", {}).get("critical_ports", [])

        try:
            port_num = int(port)
            for critical in critical_ports:
                if critical.get("port") == port_num:
                    return True
        except (ValueError, TypeError):
            pass

        return False

    def _has_unrestricted_source(self, rule: Dict) -> bool:
        """Check if NAT rule has unrestricted source"""
        src = rule.get("source_net", "").lower()
        return src in ["any", "", "0.0.0.0/0", "::/0"]
