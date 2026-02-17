"""
Optimal Configuration Generator
Security hardening recommendations for OPNsense
"""
import logging
from typing import Dict, List
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ConfigRecommendation:
    """Represents a configuration recommendation"""
    category: str
    priority: str  # CRITICAL, HIGH, MEDIUM, LOW
    setting: str
    current_value: str
    recommended_value: str
    reason: str
    implementation_steps: List[str]
    impact: str


class OptimalConfigGenerator:
    """Generates optimal security configuration recommendations"""

    def __init__(self):
        self.recommendations = []

    def generate_recommendations(self, audit_results: Dict) -> Dict:
        """Build config recommendations from audit data"""
        
        recommendations = {
            "security_score": 0,
            "max_score": 100,
            "grade": "F",
            "categories": {},
            "priority_actions": [],
            "optimal_config": self._get_optimal_config(),
            "implementation_guide": self._get_implementation_guide()
        }

        # Calculate score based on all findings with diminishing returns
        severity_weights = {'CRITICAL': 15, 'HIGH': 8, 'MEDIUM': 3, 'LOW': 1}
        all_findings = []
        for key in ['firewall_findings', 'port_findings', 'dns_findings',
                     'vlan_findings', 'vulnerability_findings', 'system_findings']:
            all_findings.extend(audit_results.get(key, []))
        
        # Sort by severity (most severe first) for fair diminishing
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        all_findings.sort(key=lambda f: sev_order.get(
            (f.get('severity', '') or '').upper(), 4))
        
        total_penalty = 0
        for i, f in enumerate(all_findings):
            sev = (f.get('severity', '') or '').upper()
            weight = severity_weights.get(sev, 0)
            diminish = 1.0 / (1 + i * 0.15)
            total_penalty += weight * diminish
        score = max(0, round(100 - total_penalty))

        recommendations["security_score"] = score
        recommendations["grade"] = self._score_to_grade(score)

        # Generate category-specific recommendations
        recommendations["categories"] = {
            "firewall": self._analyze_firewall_recommendations(audit_results),
            "dns": self._analyze_dns_recommendations(audit_results),
            "network": self._analyze_network_recommendations(audit_results),
            "system": self._analyze_system_recommendations(audit_results),
            "monitoring": self._analyze_monitoring_recommendations(audit_results)
        }

        # Generate prioritized action list
        recommendations["priority_actions"] = self._generate_priority_actions(audit_results)

        return recommendations

    def _score_to_grade(self, score: int) -> str:
        """Convert numeric score to letter grade"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def _analyze_firewall_recommendations(self, audit_results: Dict) -> Dict:
        """Generate firewall-specific recommendations"""
        firewall_findings = audit_results.get("firewall_findings", [])
        
        recommendations = {
            "status": "secure" if len(firewall_findings) == 0 else "needs_attention",
            "findings_count": len(firewall_findings),
            "recommendations": []
        }

        # Standard firewall recommendations
        standard_recs = [
            {
                "setting": "Default Deny Policy",
                "description": "Block all traffic not explicitly allowed",
                "steps": [
                    "Go to Firewall > Rules > [Interface]",
                    "Add rule at bottom: Action=Block, Source=any, Destination=any",
                    "Enable logging for this rule"
                ]
            },
            {
                "setting": "Bogon Blocking",
                "description": "Block unroutable IP addresses on WAN",
                "steps": [
                    "Go to Firewall > Settings > Advanced",
                    "Check 'Block bogon networks'",
                    "Apply changes"
                ]
            },
            {
                "setting": "Private Network Blocking",
                "description": "Block RFC1918 addresses on WAN",
                "steps": [
                    "Go to Firewall > Settings > Advanced",
                    "Check 'Block private networks'",
                    "Apply changes"
                ]
            },
            {
                "setting": "Logging",
                "description": "Enable logging on critical rules",
                "steps": [
                    "Edit each WAN rule",
                    "Check 'Log packets that are handled by this rule'",
                    "Save and apply"
                ]
            }
        ]

        recommendations["recommendations"] = standard_recs
        return recommendations

    def _analyze_dns_recommendations(self, audit_results: Dict) -> Dict:
        """Generate DNS-specific recommendations"""
        dns_findings = audit_results.get("dns_findings", [])

        return {
            "status": "secure" if len(dns_findings) == 0 else "needs_attention",
            "findings_count": len(dns_findings),
            "recommendations": [
                {
                    "setting": "DNSSEC",
                    "description": "Enable DNS Security Extensions",
                    "steps": [
                        "Go to Services > Unbound DNS > General",
                        "Check 'Enable DNSSEC Support'",
                        "Save and apply"
                    ]
                },
                {
                    "setting": "DNS over TLS",
                    "description": "Encrypt DNS queries",
                    "steps": [
                        "Go to Services > Unbound DNS > Query Forwarding",
                        "Add DNS-over-TLS server (e.g., 1.1.1.1@853#cloudflare-dns.com)",
                        "Check 'Use System Nameservers'",
                        "Enable 'Forward SSL/TLS queries'"
                    ]
                },
                {
                    "setting": "DNS Rebinding Protection",
                    "description": "Prevent DNS rebinding attacks",
                    "steps": [
                        "Go to Services > Unbound DNS > Advanced",
                        "Check 'Private Address support'",
                        "Save and apply"
                    ]
                },
                {
                    "setting": "Access Control",
                    "description": "Restrict DNS to local networks only",
                    "steps": [
                        "Go to Services > Unbound DNS > Access Lists",
                        "Add allow rules for internal networks only",
                        "Deny all others"
                    ]
                }
            ]
        }

    def _analyze_network_recommendations(self, audit_results: Dict) -> Dict:
        """Generate network/VLAN recommendations"""
        vlan_findings = audit_results.get("vlan_findings", [])
        
        return {
            "status": "secure" if len(vlan_findings) == 0 else "needs_attention",
            "findings_count": len(vlan_findings),
            "recommended_vlan_structure": [
                {"vlan_id": 10, "name": "Management", "purpose": "Network infrastructure management"},
                {"vlan_id": 20, "name": "Servers", "purpose": "Server and services"},
                {"vlan_id": 30, "name": "Workstations", "purpose": "User workstations"},
                {"vlan_id": 40, "name": "IoT", "purpose": "IoT devices (isolated)"},
                {"vlan_id": 50, "name": "Guest", "purpose": "Guest network (internet only)"},
                {"vlan_id": 99, "name": "DMZ", "purpose": "Public-facing services"}
            ],
            "inter_vlan_rules": [
                "Management VLAN can access all VLANs",
                "Servers can respond to Workstations (not initiate)",
                "IoT VLAN blocked from all internal VLANs",
                "Guest VLAN internet-only, no internal access",
                "DMZ limited to specific services from internal"
            ]
        }

    def _analyze_system_recommendations(self, audit_results: Dict) -> Dict:
        """Generate system security recommendations"""
        system_findings = audit_results.get("system_findings", [])

        return {
            "status": "secure" if len(system_findings) == 0 else "needs_attention",
            "findings_count": len(system_findings),
            "recommendations": [
                {
                    "setting": "Admin Interface Security",
                    "steps": [
                        "Use HTTPS only (disable HTTP)",
                        "Change default port from 443",
                        "Enable HSTS",
                        "Restrict to LAN interface only",
                        "Set session timeout to 15-30 minutes"
                    ]
                },
                {
                    "setting": "SSH Hardening",
                    "steps": [
                        "Disable root login",
                        "Use key-based authentication only",
                        "Change default port",
                        "Restrict to management VLAN"
                    ]
                },
                {
                    "setting": "Authentication",
                    "steps": [
                        "Enable Two-Factor Authentication (TOTP)",
                        "Set account lockout after 3-5 failed attempts",
                        "Use strong password policy"
                    ]
                },
                {
                    "setting": "Updates",
                    "steps": [
                        "Enable automatic update checking",
                        "Apply security updates promptly",
                        "Backup configuration before updates"
                    ]
                }
            ]
        }

    def _analyze_monitoring_recommendations(self, audit_results: Dict) -> Dict:
        """Generate monitoring and logging recommendations"""
        return {
            "status": "review_recommended",
            "recommendations": [
                {
                    "setting": "Intrusion Detection (IDS/IPS)",
                    "steps": [
                        "Enable Suricata in Services > Intrusion Detection",
                        "Enable ET Open and Abuse.ch rulesets",
                        "Consider IPS mode for active blocking",
                        "Enable automatic rule updates"
                    ]
                },
                {
                    "setting": "Logging",
                    "steps": [
                        "Enable firewall logging for block rules",
                        "Configure remote syslog for log retention",
                        "Set up log rotation",
                        "Monitor critical events"
                    ]
                },
                {
                    "setting": "Alerting",
                    "steps": [
                        "Configure email notifications",
                        "Set up alerts for failed logins",
                        "Alert on firewall rule changes",
                        "Monitor certificate expiration"
                    ]
                }
            ]
        }

    def _generate_priority_actions(self, audit_results: Dict) -> List[Dict]:
        """Generate prioritized action list based on findings"""
        actions = []

        # Process all findings and create priority actions
        all_findings = []
        
        for finding in audit_results.get("firewall_findings", []):
            all_findings.append({"type": "firewall", **finding})
        for finding in audit_results.get("dns_findings", []):
            all_findings.append({"type": "dns", **finding})
        for finding in audit_results.get("vlan_findings", []):
            all_findings.append({"type": "vlan", **finding})
        for finding in audit_results.get("port_findings", []):
            all_findings.append({"type": "port", **finding})
        for finding in audit_results.get("system_findings", []):
            all_findings.append({"type": "system", **finding})

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 4))

        # Create action items
        for idx, finding in enumerate(all_findings[:20]):  # Top 20 priority items
            actions.append({
                "priority": idx + 1,
                "severity": finding.get("severity", "UNKNOWN"),
                "category": finding.get("type", "unknown"),
                "issue": finding.get("issue", "Unknown issue"),
                "action": finding.get("solution", "Review and remediate"),
                "impact": self._get_impact_description(finding.get("severity", "LOW"))
            })

        return actions

    def _get_impact_description(self, severity: str) -> str:
        """Get impact description based on severity"""
        impacts = {
            "CRITICAL": "Immediate risk of compromise - requires urgent attention",
            "HIGH": "Significant security risk - should be addressed within 24 hours",
            "MEDIUM": "Moderate risk - should be addressed within 1 week",
            "LOW": "Minor risk - address during regular maintenance"
        }
        return impacts.get(severity, "Unknown impact")

    def _get_optimal_config(self) -> Dict:
        """Return the optimal security configuration"""
        return {
            "firewall": {
                "default_policy": "Deny",
                "bogon_blocking": "Enabled on WAN",
                "private_network_blocking": "Enabled on WAN",
                "anti_spoofing": "Enabled",
                "logging": "Enabled for block rules",
                "state_policy": "Strict",
                "ipv6": "Same policies as IPv4"
            },
            "dns": {
                "dnssec": "Enabled",
                "dns_over_tls": "Enabled",
                "rebinding_protection": "Enabled",
                "access_lists": "Internal networks only",
                "forwarding": "Trusted DNS providers (e.g., Cloudflare, Quad9)"
            },
            "network_segmentation": {
                "vlans": "Minimum 4 (Management, Internal, IoT, Guest)",
                "inter_vlan_routing": "Strictly controlled",
                "management_vlan": "Separate from user traffic",
                "guest_isolation": "Internet-only access"
            },
            "admin_access": {
                "protocol": "HTTPS only",
                "port": "Non-standard",
                "interfaces": "Management VLAN only",
                "2fa": "Enabled (TOTP)",
                "session_timeout": "15-30 minutes",
                "hsts": "Enabled"
            },
            "ssh": {
                "enabled": "Only if needed",
                "root_login": "Disabled",
                "authentication": "Key-based only",
                "port": "Non-standard",
                "interfaces": "Management VLAN only"
            },
            "ids_ips": {
                "enabled": "Yes",
                "mode": "IPS (inline blocking)",
                "rulesets": "ET Open, Abuse.ch, Feodo Tracker",
                "auto_update": "Enabled"
            },
            "monitoring": {
                "logging": "Centralized syslog",
                "retention": "30+ days",
                "alerting": "Email for critical events",
                "netflow": "Consider for traffic analysis"
            }
        }

    def _get_implementation_guide(self) -> List[Dict]:
        """Return step-by-step implementation guide"""
        return [
            {
                "phase": 1,
                "title": "Immediate Security Hardening",
                "duration": "1-2 hours",
                "steps": [
                    "Enable HTTPS-only for admin interface",
                    "Enable bogon and private network blocking on WAN",
                    "Review and remove any 'any-to-any' rules",
                    "Enable logging on all block rules",
                    "Verify default deny policy exists"
                ]
            },
            {
                "phase": 2,
                "title": "DNS Security",
                "duration": "30 minutes",
                "steps": [
                    "Enable DNSSEC",
                    "Configure DNS over TLS forwarding",
                    "Enable DNS rebinding protection",
                    "Configure DNS access lists"
                ]
            },
            {
                "phase": 3,
                "title": "Network Segmentation",
                "duration": "2-4 hours",
                "steps": [
                    "Plan VLAN structure",
                    "Create VLANs in Interfaces > Other Types > VLAN",
                    "Assign VLANs to interfaces",
                    "Configure DHCP for each VLAN",
                    "Create inter-VLAN firewall rules"
                ]
            },
            {
                "phase": 4,
                "title": "Access Control Hardening",
                "duration": "1 hour",
                "steps": [
                    "Enable Two-Factor Authentication",
                    "Configure account lockout policy",
                    "Harden SSH if enabled",
                    "Review user permissions"
                ]
            },
            {
                "phase": 5,
                "title": "Monitoring Setup",
                "duration": "1-2 hours",
                "steps": [
                    "Enable Suricata IDS/IPS",
                    "Configure rule updates",
                    "Set up syslog forwarding",
                    "Configure email notifications"
                ]
            }
        ]
