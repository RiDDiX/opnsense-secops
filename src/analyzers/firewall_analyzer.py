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
        findings.extend(self._analyze_security_policies(firewall_rules))
        findings.extend(self._analyze_ipv6_rules(firewall_rules))
        findings.extend(self._analyze_rule_ordering(firewall_rules))

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

    def _analyze_security_policies(self, rules: List[Dict]) -> List[FirewallFinding]:
        """Analyze overall security policies"""
        findings = []

        # Check for default deny policy
        has_default_deny = False
        has_bogon_block = False
        has_rfc1918_block_wan = False
        has_anti_spoofing = False

        for rule in rules:
            if not rule.get("enabled", "0") == "1":
                continue

            interface = rule.get("interface", "").lower()
            action = rule.get("action", "").lower()
            src = rule.get("source_net", "").lower()
            dst = rule.get("destination_net", "").lower()
            description = rule.get("description", "").lower()

            # Check for default deny (last rule blocking all)
            if action == "block" and src in ["any", ""] and dst in ["any", ""]:
                has_default_deny = True

            # Check for bogon blocking on WAN
            if "wan" in interface and action == "block":
                if "bogon" in description or "bogon" in src:
                    has_bogon_block = True

            # Check for RFC1918 blocking on WAN incoming
            if "wan" in interface and action == "block":
                if any(net in src for net in ["10.0.0.0", "172.16.0.0", "192.168.0.0", "rfc1918", "private"]):
                    has_rfc1918_block_wan = True

            # Check for anti-spoofing rules
            if "spoof" in description or "anti-spoof" in description:
                has_anti_spoofing = True

        if not has_default_deny:
            findings.append(FirewallFinding(
                severity="HIGH",
                rule_id="policy_default_deny",
                rule_description="Default Deny Policy",
                issue="No default deny policy detected",
                reason="Without a default deny policy, unmatched traffic may be allowed",
                solution="Add a final rule on each interface that blocks all unmatched traffic",
                rule_details={"recommendation": "Block any to any as last rule"}
            ))

        if not has_bogon_block:
            findings.append(FirewallFinding(
                severity="MEDIUM",
                rule_id="policy_bogon_block",
                rule_description="Bogon Blocking",
                issue="No bogon blocking on WAN interface",
                reason="Bogon addresses (unallocated IP ranges) should be blocked on WAN",
                solution="Enable bogon blocking in Firewall > Settings or add explicit bogon block rules",
                rule_details={"recommendation": "Block bogon networks on WAN"}
            ))

        if not has_rfc1918_block_wan:
            findings.append(FirewallFinding(
                severity="HIGH",
                rule_id="policy_rfc1918_wan",
                rule_description="RFC1918 on WAN",
                issue="No RFC1918 (private) address blocking on WAN incoming",
                reason="Private IP addresses should never arrive from WAN - indicates spoofing",
                solution="Block incoming traffic from 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 on WAN",
                rule_details={"recommendation": "Block private networks on WAN inbound"}
            ))

        if not has_anti_spoofing:
            findings.append(FirewallFinding(
                severity="MEDIUM",
                rule_id="policy_anti_spoofing",
                rule_description="Anti-Spoofing",
                issue="No explicit anti-spoofing rules detected",
                reason="Anti-spoofing prevents attackers from forging source IP addresses",
                solution="Enable anti-spoofing in Firewall > Settings > Advanced or use pf anti-spoof",
                rule_details={"recommendation": "Enable anti-spoofing protection"}
            ))

        return findings

    def _analyze_ipv6_rules(self, rules: List[Dict]) -> List[FirewallFinding]:
        """Analyze IPv6 specific rules"""
        findings = []

        has_ipv6_rules = False
        ipv6_any_allow = False

        for rule in rules:
            if not rule.get("enabled", "0") == "1":
                continue

            # Check if rule applies to IPv6
            ipprotocol = rule.get("ipprotocol", "").lower()
            src = rule.get("source_net", "")
            dst = rule.get("destination_net", "")

            if ipprotocol == "inet6" or "::" in src or "::" in dst:
                has_ipv6_rules = True

                # Check for overly permissive IPv6 rules
                action = rule.get("action", "").lower()
                if action == "pass":
                    if src in ["any", "::/0", ""] and dst in ["any", "::/0", ""]:
                        ipv6_any_allow = True

        # If IPv6 is enabled but no specific rules, warn
        if has_ipv6_rules and ipv6_any_allow:
            findings.append(FirewallFinding(
                severity="HIGH",
                rule_id="ipv6_any_allow",
                rule_description="IPv6 Any-to-Any",
                issue="IPv6 any-to-any rule detected",
                reason="IPv6 should have the same restrictions as IPv4",
                solution="Apply the same firewall policies to IPv6 as IPv4",
                rule_details={"recommendation": "Review and restrict IPv6 rules"}
            ))

        return findings

    def _analyze_rule_ordering(self, rules: List[Dict]) -> List[FirewallFinding]:
        """Analyze rule ordering for potential issues"""
        findings = []

        # Group rules by interface
        interface_rules = {}
        for rule in rules:
            if not rule.get("enabled", "0") == "1":
                continue
            interface = rule.get("interface", "unknown")
            if interface not in interface_rules:
                interface_rules[interface] = []
            interface_rules[interface].append(rule)

        for interface, iface_rules in interface_rules.items():
            # Check if allow-all appears before more specific rules
            allow_all_index = -1
            specific_rule_after = False

            for idx, rule in enumerate(iface_rules):
                action = rule.get("action", "").lower()
                src = rule.get("source_net", "").lower()
                dst = rule.get("destination_net", "").lower()

                if action == "pass" and src in ["any", ""] and dst in ["any", ""]:
                    allow_all_index = idx
                elif allow_all_index >= 0 and action in ["pass", "block"]:
                    # There's a specific rule after an allow-all
                    specific_rule_after = True
                    break

            if allow_all_index >= 0 and specific_rule_after:
                findings.append(FirewallFinding(
                    severity="MEDIUM",
                    rule_id=f"rule_order_{interface}",
                    rule_description=f"Rule ordering on {interface}",
                    issue=f"Specific rules appear after allow-all on {interface}",
                    reason="Rules after an allow-all will never be evaluated",
                    solution=f"Reorder rules on {interface} - specific rules should come before general rules",
                    rule_details={"interface": interface, "allow_all_position": allow_all_index}
                ))

        return findings

    def get_optimal_firewall_config(self) -> Dict:
        """Return optimal firewall configuration recommendations"""
        return {
            "recommended_policies": [
                {
                    "name": "Default Deny",
                    "description": "Block all traffic not explicitly allowed",
                    "implementation": "Add 'Block any to any' as last rule on each interface"
                },
                {
                    "name": "Bogon Blocking",
                    "description": "Block unallocated IP address ranges",
                    "implementation": "Enable in Firewall > Settings > Advanced > Block bogon networks"
                },
                {
                    "name": "RFC1918 Blocking on WAN",
                    "description": "Block private addresses from WAN",
                    "implementation": "Enable in Firewall > Settings > Advanced > Block private networks"
                },
                {
                    "name": "Anti-Spoofing",
                    "description": "Prevent IP address spoofing",
                    "implementation": "Enable antispoof for each interface in Firewall > Settings"
                },
                {
                    "name": "Stateful Filtering",
                    "description": "Track connection states",
                    "implementation": "Enabled by default - ensure 'State Type' is set appropriately"
                },
                {
                    "name": "Logging",
                    "description": "Log blocked traffic for analysis",
                    "implementation": "Enable logging on block rules, especially WAN"
                }
            ],
            "recommended_rule_order": [
                "1. Anti-lockout rule (if needed)",
                "2. Block bogon/RFC1918 on WAN",
                "3. Allow established/related connections",
                "4. Specific allow rules (most specific first)",
                "5. Specific block rules",
                "6. Default deny (block all)"
            ]
        }
