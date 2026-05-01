"""Firewall rule analyzer."""
import logging
from dataclasses import dataclass, field

from src.analyzers._utils import is_any, is_rfc1918, truthy

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
    rule_details: dict
    interface: str = ""
    implementation_steps: list[str] = field(default_factory=list)
    opnsense_path: str = ""
    suggested_rule: dict | None = None


class FirewallAnalyzer:
    """Analyzes firewall rules for security issues"""

    def __init__(self, rules_config: dict, exceptions: list[dict]):
        self.rules_config = rules_config
        self.exceptions = exceptions

    def analyze(self, firewall_rules: list[dict], nat_rules: list[dict]) -> list[FirewallFinding]:
        """Analyze firewall and NAT rules"""
        findings = []

        findings.extend(self._analyze_firewall_rules(firewall_rules))
        findings.extend(self._analyze_nat_rules(nat_rules))
        findings.extend(self._analyze_security_policies(firewall_rules))
        findings.extend(self._analyze_ipv6_rules(firewall_rules))
        findings.extend(self._analyze_icmpv6_rules(firewall_rules))
        findings.extend(self._analyze_rule_ordering(firewall_rules))

        return findings

    # ICMPv6 default-pass list per src/etc/inc/filter.lib.inc#L230-L271:
    # global types 1, 2, 3, 4, 135, 136 plus link-local 128, 129, 133, 134.
    _ICMP6_DEFAULT_GLOBAL = {"1", "2", "3", "4", "135", "136"}
    _ICMP6_DEFAULT_LOCAL = {"128", "129", "133", "134", "135", "136"}

    def _analyze_icmpv6_rules(self, rules: list[dict]) -> list[FirewallFinding]:
        """Flag pass rules for ICMPv6 that pass everything instead of typed entries."""
        findings = []
        allowed_total = self._ICMP6_DEFAULT_GLOBAL | self._ICMP6_DEFAULT_LOCAL
        for rule in rules:
            if str(rule.get("enabled", "0")) != "1":
                continue
            if rule.get("action") != "pass":
                continue
            proto = (rule.get("protocol") or "").lower()
            if proto not in ("icmp", "icmpv6", "ipv6-icmp"):
                continue
            ipproto = rule.get("ipprotocol")
            if ipproto not in ("inet6", "inet46"):
                continue
            icmp6 = (rule.get("icmp6type") or "").strip()
            iface = rule.get("interface", "unknown") or "unknown"
            if not icmp6:
                findings.append(FirewallFinding(
                    severity="HIGH",
                    rule_id=rule.get("uuid", ""),
                    rule_description=rule.get("description", "ICMPv6 pass without type list"),
                    issue="ICMPv6 Pass Regel ohne icmp6type Beschraenkung",
                    reason=(
                        "OPNsense laesst ohne icmp6type alle ICMPv6 Typen zu. "
                        "Mindestnotwendig sind die Typen aus filter.lib.inc: "
                        "1, 2, 3, 4, 135, 136 global und 128, 129, 133, 134 link-local."
                    ),
                    solution="icmp6type auf die noetigen Typen einschraenken.",
                    rule_details=rule,
                    interface=iface,
                    opnsense_path=f"Firewall > Rules > {iface.upper()}",
                    implementation_steps=[
                        "1. Regel in Firewall > Rules oeffnen.",
                        "2. Feld 'ICMPv6 type' auf 1, 2, 3, 4, 135, 136 setzen.",
                        "3. Speichern und Apply Changes.",
                    ],
                ))
                continue
            entries = {e.strip() for e in icmp6.split(",") if e.strip()}
            unexpected = entries - allowed_total
            if unexpected:
                ordered = sorted(unexpected, key=lambda x: int(x) if str(x).isdigit() else 0)
                findings.append(FirewallFinding(
                    severity="MEDIUM",
                    rule_id=rule.get("uuid", ""),
                    rule_description=rule.get("description", "ICMPv6 with non-default types"),
                    issue=f"ICMPv6 Pass Regel mit unueblichen Typen: {ordered}",
                    reason=(
                        "Diese Typen liegen ausserhalb der Default Whitelist von OPNsense. "
                        "Bewusste Konfiguration moeglich, sonst Risiko."
                    ),
                    solution="Liste auf die notwendigen Typen pruefen, sonst entfernen.",
                    rule_details=rule,
                    interface=iface,
                    opnsense_path=f"Firewall > Rules > {iface.upper()}",
                    implementation_steps=[
                        "1. Regel oeffnen.",
                        "2. ICMPv6 type Feld pruefen.",
                        "3. Nicht benoetigte Typen entfernen.",
                    ],
                ))
        return findings

    def _analyze_firewall_rules(self, rules: list[dict]) -> list[FirewallFinding]:
        """Analyze firewall filter rules"""
        findings = []

        for rule in rules:
            if not truthy(rule.get("enabled")):
                continue

            iface = rule.get("interface", "unknown")
            rule_uuid = rule.get("uuid", "unknown")

            # Check for any-to-any rules
            if self._is_any_to_any(rule):
                findings.append(FirewallFinding(
                    severity="CRITICAL",
                    rule_id=rule_uuid,
                    rule_description=rule.get("description", "No description"),
                    issue="Any-to-Any Rule",
                    reason="Diese Regel erlaubt Traffic von überall nach überall ohne Einschränkungen",
                    solution="Definiere spezifische Source und Destination Adressen/Netzwerke",
                    rule_details=rule,
                    interface=iface,
                    opnsense_path=f"Firewall > Rules > {iface.upper()}",
                    implementation_steps=[
                        f"1. Gehe zu Firewall > Rules > {iface.upper()}",
                        f"2. Finde Regel: {rule.get('description', rule_uuid)}",
                        "3. Klicke auf 'Edit' (Stift-Symbol)",
                        "4. Ändere 'Source' von 'any' auf spezifisches Netzwerk (z.B. LAN net)",
                        "5. Ändere 'Destination' von 'any' auf spezifisches Ziel",
                        "6. Speichern und 'Apply Changes' klicken"
                    ]
                ))

            # Check for WAN incoming rules
            if self._is_insecure_wan_rule(rule):
                findings.append(FirewallFinding(
                    severity="HIGH",
                    rule_id=rule_uuid,
                    rule_description=rule.get("description", "No description"),
                    issue="Eingehender WAN Traffic ohne Einschränkung",
                    reason="Erlaubt eingehenden Traffic vom Internet ohne Port-Beschränkung",
                    solution="Beschränke eingehenden WAN Traffic auf spezifische, notwendige Ports",
                    rule_details=rule,
                    interface=iface,
                    opnsense_path="Firewall > Rules > WAN",
                    implementation_steps=[
                        "1. Gehe zu Firewall > Rules > WAN",
                        f"2. Finde Regel: {rule.get('description', rule_uuid)}",
                        "3. Klicke auf 'Edit' (Stift-Symbol)",
                        "4. Unter 'Destination port range' spezifische Ports angeben",
                        "5. Unter 'Source' ggf. auf bestimmte IPs einschränken",
                        "6. Speichern und 'Apply Changes' klicken",
                        "ODER: Regel deaktivieren/löschen falls nicht benötigt"
                    ]
                ))

            # Check for missing logging on important rules
            if self._should_have_logging(rule) and not self._has_logging(rule):
                findings.append(FirewallFinding(
                    severity="MEDIUM",
                    rule_id=rule_uuid,
                    rule_description=rule.get("description", "No description"),
                    issue="Fehlende Logging-Aktivierung",
                    reason="Wichtige Firewall-Regeln sollten geloggt werden für Forensik",
                    solution="Aktiviere Logging für diese Regel in den Regel-Einstellungen",
                    rule_details=rule,
                    interface=iface,
                    opnsense_path=f"Firewall > Rules > {iface.upper()}",
                    implementation_steps=[
                        f"1. Gehe zu Firewall > Rules > {iface.upper()}",
                        f"2. Finde Regel: {rule.get('description', rule_uuid)}",
                        "3. Klicke auf 'Edit' (Stift-Symbol)",
                        "4. Scrolle zu 'Log' und aktiviere die Checkbox",
                        "5. Speichern und 'Apply Changes' klicken"
                    ]
                ))

            # Check for overly permissive protocol rules
            if self._is_overly_permissive(rule):
                findings.append(FirewallFinding(
                    severity="MEDIUM",
                    rule_id=rule_uuid,
                    rule_description=rule.get("description", "No description"),
                    issue="Zu permissive Protokoll-Regel",
                    reason="Regel erlaubt 'any' Protokoll statt spezifischer Protokolle",
                    solution="Definiere spezifische Protokolle (TCP, UDP, ICMP) statt 'any'",
                    rule_details=rule,
                    interface=iface,
                    opnsense_path=f"Firewall > Rules > {iface.upper()}",
                    implementation_steps=[
                        f"1. Gehe zu Firewall > Rules > {iface.upper()}",
                        f"2. Finde Regel: {rule.get('description', rule_uuid)}",
                        "3. Klicke auf 'Edit' (Stift-Symbol)",
                        "4. Ändere 'Protocol' von 'any' auf 'TCP', 'UDP' oder 'TCP/UDP'",
                        "5. Falls mehrere Protokolle nötig: separate Regeln erstellen",
                        "6. Speichern und 'Apply Changes' klicken"
                    ]
                ))

        return findings

    def _analyze_nat_rules(self, rules: list[dict]) -> list[FirewallFinding]:
        """Analyze NAT port forwarding rules"""
        findings = []

        for rule in rules:
            if not truthy(rule.get("enabled")):
                continue

            rule_uuid = rule.get("uuid", "unknown")
            # Support both normalized and raw field names from OPNsense 25.x API
            target_ip = rule.get("target", rule.get("redirect_target", rule.get("target_ip", "")))
            dst_port = rule.get("destination_port", rule.get("target_port", rule.get("local-port", "")))

            # Check for port forwards to critical services
            if self._is_critical_port_forward(dst_port):
                findings.append(FirewallFinding(
                    severity="CRITICAL",
                    rule_id=rule_uuid,
                    rule_description=rule.get("description", "No description"),
                    issue=f"Port Forward zu kritischem Service (Port {dst_port})",
                    reason="Dieser Port sollte nicht vom Internet aus erreichbar sein",
                    solution=f"Entferne Port Forward für Port {dst_port} oder beschränke Source IPs",
                    rule_details=rule,
                    interface="WAN",
                    opnsense_path="Firewall > NAT > Port Forward",
                    implementation_steps=[
                        "1. Gehe zu Firewall > NAT > Port Forward",
                        f"2. Finde Regel für Port {dst_port} -> {target_ip}",
                        "3. Option A: Regel löschen (Mülleimer-Symbol)",
                        "4. Option B: Regel bearbeiten und Source einschränken:",
                        "   - Klicke 'Edit' (Stift-Symbol)",
                        "   - Unter 'Source' wähle 'Single host or Network'",
                        "   - Trage vertrauenswürdige IP/Netzwerk ein",
                        "5. Speichern und 'Apply Changes' klicken",
                        f"ALTERNATIVE: VPN statt Port Forward für {dst_port} nutzen"
                    ]
                ))

            # Check for unrestricted source in port forwards
            if self._has_unrestricted_source(rule):
                findings.append(FirewallFinding(
                    severity="HIGH",
                    rule_id=rule_uuid,
                    rule_description=rule.get("description", "No description"),
                    issue="Port Forward ohne Source-Einschränkung",
                    reason="Port Forward erlaubt Zugriff von überall im Internet",
                    solution="Beschränke Source auf bekannte/vertrauenswürdige IP-Adressen wenn möglich",
                    rule_details=rule,
                    interface="WAN",
                    opnsense_path="Firewall > NAT > Port Forward",
                    implementation_steps=[
                        "1. Gehe zu Firewall > NAT > Port Forward",
                        f"2. Finde Regel: {rule.get('description', rule_uuid)}",
                        "3. Klicke auf 'Edit' (Stift-Symbol)",
                        "4. Unter 'Source' ändere von 'any' auf:",
                        "   - 'Single host or Network' für spezifische IP",
                        "   - Oder erstelle Alias unter Firewall > Aliases",
                        "5. Speichern und 'Apply Changes' klicken"
                    ]
                ))

        return findings

    def _is_any_to_any(self, rule: dict) -> bool:
        """Pass any to any only counts as dangerous on WAN or floating."""
        src = (rule.get("source_net") or "").lower()
        dst = (rule.get("destination_net") or "").lower()
        interface = (rule.get("interface") or "").lower()
        action = (rule.get("action") or "").lower()
        dst_port = (rule.get("destination_port") or "").strip()
        protocol = (rule.get("protocol") or "").lower()

        if not is_any(src) or not is_any(dst):
            return False
        if action != "pass":
            return False
        if dst_port and not is_any(dst_port):
            return False
        if protocol and protocol != "any":
            return False

        internal_patterns = (
            "lan", "vlan", "opt", "openvpn", "ovpn", "wireguard", "wg",
            "ipsec", "vpn", "tailscale", "zerotier", "tun", "tap",
        )
        for pattern in internal_patterns:
            if pattern in interface:
                return False
        return True

    def _is_insecure_wan_rule(self, rule: dict) -> bool:
        """Inbound WAN pass without port restriction is dangerous."""
        interface = (rule.get("interface") or "").lower()
        direction = (rule.get("direction") or "").lower()
        action = (rule.get("action") or "").lower()
        dst = (rule.get("destination_net") or "").lower()
        dst_port = (rule.get("destination_port") or "").strip()

        if "wan" not in interface:
            return False
        if direction != "in":
            return False
        if action != "pass":
            return False
        if not is_any(dst):
            return False
        if dst_port and not is_any(dst_port):
            return False
        return True

    def _should_have_logging(self, rule: dict) -> bool:
        """Determine if rule should have logging enabled"""
        interface = rule.get("interface", "").lower()
        action = rule.get("action", "").lower()

        # WAN rules and block rules should be logged
        return "wan" in interface or action == "block"

    def _has_logging(self, rule: dict) -> bool:
        return truthy(rule.get("log"))

    def _is_overly_permissive(self, rule: dict) -> bool:
        """Check if rule is overly permissive with protocols.

        Only flag on WAN or floating rules. Internal/VPN interfaces
        commonly use protocol 'any' for standard outbound access.
        """
        protocol = rule.get("protocol", "").lower()
        action = rule.get("action", "").lower()
        interface = rule.get("interface", "").lower()

        if protocol not in ["any", ""] or action != "pass":
            return False

        # Internal/VPN interfaces: protocol 'any' is standard practice
        internal_patterns = [
            "lan", "vlan", "opt", "openvpn", "ovpn", "wireguard", "wg",
            "ipsec", "vpn", "tailscale", "zerotier", "tun", "tap"
        ]
        for pattern in internal_patterns:
            if pattern in interface:
                return False

        return True

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

    def _has_unrestricted_source(self, rule: dict) -> bool:
        src = rule.get("source") or rule.get("source_net") or ""
        return is_any(src)

    def _analyze_security_policies(self, rules: list[dict]) -> list[FirewallFinding]:
        """Default deny, bogon, RFC1918 on WAN, anti-spoof."""
        findings = []

        # Group enabled rules per interface for ordering checks.
        per_iface: dict[str, list[dict]] = {}
        for rule in rules:
            if not truthy(rule.get("enabled")):
                continue
            iface = (rule.get("interface") or "").lower() or "floating"
            per_iface.setdefault(iface, []).append(rule)

        has_default_deny_last = False
        for _iface, iface_rules in per_iface.items():
            if not iface_rules:
                continue
            last = iface_rules[-1]
            if (last.get("action") or "").lower() == "block" and is_any(last.get("source_net")) and is_any(last.get("destination_net")):
                has_default_deny_last = True
                break

        has_bogon_block = False
        has_rfc1918_block_wan = False
        has_anti_spoofing = False

        for rule in rules:
            if not truthy(rule.get("enabled")):
                continue
            interface = (rule.get("interface") or "").lower()
            action = (rule.get("action") or "").lower()
            src = (rule.get("source_net") or "")
            description = (rule.get("description") or "").lower()

            if "wan" in interface and action == "block":
                src_lc = src.lower()
                if "bogon" in description or "bogon" in src_lc:
                    has_bogon_block = True
                if "rfc1918" in src_lc or "private" in src_lc or is_rfc1918(src):
                    has_rfc1918_block_wan = True

            if "spoof" in description:
                has_anti_spoofing = True

        has_default_deny = has_default_deny_last

        if not has_default_deny:
            findings.append(FirewallFinding(
                severity="HIGH",
                rule_id="policy_default_deny",
                rule_description="Default Deny Policy",
                issue="Keine explizite Default-Deny Regel als letzte Regel auf einem Interface",
                reason="OPNsense hat zwar einen impliziten Default-Deny, ohne explizite Block-Regel werden Hits nicht geloggt.",
                solution="Letzte Regel pro Interface auf Block + Log setzen.",
                rule_details={"recommendation": "Block any to any as last rule"},
                interface="ALL",
                opnsense_path="Firewall > Rules > [Interface]",
                implementation_steps=[
                    "1. Firewall > Rules > [Interface] oeffnen.",
                    "2. Neue Regel als letzte Regel anlegen.",
                    "3. Action Block, Source any, Destination any.",
                    "4. Log packets aktivieren.",
                    "5. Apply Changes.",
                ],
                suggested_rule={"rule": {
                    "enabled": "1",
                    "action": "block",
                    "direction": "in",
                    "ipprotocol": "inet46",
                    "protocol": "any",
                    "interface": "lan",
                    "source_net": "any",
                    "destination_net": "any",
                    "log": "1",
                    "quick": "1",
                    "description": "secops: explicit default deny",
                }},
            ))

        if not has_bogon_block:
            findings.append(FirewallFinding(
                severity="MEDIUM",
                rule_id="policy_bogon_block",
                rule_description="Bogon Blocking",
                issue="Keine Bogon-Block-Regel auf WAN",
                reason="Bogon-Bereiche (unallokierte IP-Praefixe) sollten am WAN blockiert werden.",
                solution="Firewall > Settings > Advanced: 'Block bogon networks' aktivieren.",
                rule_details={"recommendation": "Block bogon networks on WAN"},
                interface="WAN",
                opnsense_path="Firewall > Settings > Advanced",
                implementation_steps=[
                    "1. Firewall > Settings > Advanced oeffnen.",
                    "2. 'Block bogon networks' aktivieren.",
                    "3. Speichern.",
                ],
            ))

        if not has_rfc1918_block_wan:
            findings.append(FirewallFinding(
                severity="HIGH",
                rule_id="policy_rfc1918_wan",
                rule_description="RFC1918 on WAN",
                issue="Keine RFC1918-Block-Regel auf WAN inbound",
                reason="Private IP-Adressen am WAN inbound deuten auf Spoofing oder Misconfig auf der Provider-Seite hin.",
                solution="Firewall > Settings > Advanced: 'Block private networks' aktivieren.",
                rule_details={"recommendation": "Block private networks on WAN inbound"},
                interface="WAN",
                opnsense_path="Firewall > Settings > Advanced",
                implementation_steps=[
                    "1. Firewall > Settings > Advanced oeffnen.",
                    "2. 'Block private networks' aktivieren.",
                    "3. Speichern.",
                ],
                suggested_rule={"rule": {
                    "enabled": "1",
                    "action": "block",
                    "direction": "in",
                    "ipprotocol": "inet",
                    "protocol": "any",
                    "interface": "wan",
                    "source_net": "10.0.0.0/8",
                    "destination_net": "any",
                    "log": "1",
                    "quick": "1",
                    "description": "secops: block RFC1918 source on WAN inbound (10/8)",
                }},
            ))

        if not has_anti_spoofing:
            findings.append(FirewallFinding(
                severity="MEDIUM",
                rule_id="policy_anti_spoofing",
                rule_description="Anti-Spoofing",
                issue="No explicit anti-spoofing rules detected",
                reason="Anti-spoofing prevents attackers from forging source IP addresses",
                solution="Enable anti-spoofing in Firewall > Settings > Advanced or use pf anti-spoof",
                rule_details={"recommendation": "Enable anti-spoofing protection"},
                interface="ALL",
                opnsense_path="Firewall > Settings > Advanced",
                implementation_steps=[
                    "1. Gehe zu Firewall > Settings > Advanced",
                    "2. Finde 'Anti-spoof' Optionen",
                    "3. Aktiviere für alle Interfaces",
                    "4. Speichern",
                    "Dies verhindert IP-Spoofing-Angriffe"
                ]
            ))

        return findings

    def _analyze_ipv6_rules(self, rules: list[dict]) -> list[FirewallFinding]:
        """Analyze IPv6 specific rules"""
        findings = []

        has_ipv6_rules = False
        ipv6_any_allow = False

        for rule in rules:
            if not truthy(rule.get("enabled")):
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
                rule_details={"recommendation": "Review and restrict IPv6 rules"},
                interface="ALL (IPv6)",
                opnsense_path="Firewall > Rules > [Interface]",
                implementation_steps=[
                    "1. Gehe zu Firewall > Rules > [Interface]",
                    "2. Prüfe alle Regeln mit 'IPv6' oder 'inet6'",
                    "3. Wende gleiche Einschränkungen wie bei IPv4 an",
                    "4. Erstelle spezifische IPv6-Regeln statt any-to-any",
                    "5. Speichern und 'Apply Changes'"
                ]
            ))

        return findings

    def _analyze_rule_ordering(self, rules: list[dict]) -> list[FirewallFinding]:
        """Analyze rule ordering for potential issues"""
        findings = []

        # Group rules by interface
        interface_rules = {}
        for rule in rules:
            if not truthy(rule.get("enabled")):
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
                    rule_details={"interface": interface, "allow_all_position": allow_all_index},
                    interface=interface,
                    opnsense_path=f"Firewall > Rules > {interface.upper()}",
                    implementation_steps=[
                        f"1. Gehe zu Firewall > Rules > {interface.upper()}",
                        "2. Identifiziere die 'Allow All' Regel (any -> any)",
                        "3. Verschiebe spezifischere Regeln VOR die Allow-All Regel",
                        "4. Nutze Drag & Drop oder die Pfeile zum Verschieben",
                        "5. Reihenfolge: Spezifisch -> Allgemein -> Default Deny",
                        "6. 'Apply Changes' klicken"
                    ]
                ))

        return findings

    def get_optimal_firewall_config(self) -> dict:
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
