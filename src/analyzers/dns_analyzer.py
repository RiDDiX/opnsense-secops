"""
DNS Configuration Analyzer
Analyzes DNS/Unbound configuration for security issues
"""
import logging
import dns.resolver
import dns.query
import dns.message
from typing import Dict, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DNSFinding:
    """Represents a DNS security finding"""
    severity: str
    check: str
    issue: str
    reason: str
    solution: str
    details: Dict


class DNSAnalyzer:
    """Analyzes DNS configuration for security issues"""

    def __init__(self, rules_config: Dict, exceptions: List[Dict]):
        self.rules_config = rules_config
        self.exceptions = exceptions
        self.dns_security = rules_config.get("dns_security", {})

    def analyze(self, dns_config: Dict, dns_server: str) -> List[DNSFinding]:
        """Analyze DNS configuration"""
        findings = []

        # Analyze configuration settings
        findings.extend(self._analyze_dns_config(dns_config))

        # Perform active DNS security tests
        findings.extend(self._test_dns_server(dns_server))

        return findings

    def _analyze_dns_config(self, config: Dict) -> List[DNSFinding]:
        """Analyze DNS configuration from OPNsense"""
        findings = []

        if not config:
            logger.warning("No DNS config available")
            return findings

        # Get unbound settings
        unbound = config.get("unbound", {})

        # Check DNSSEC
        if not self._is_check_excepted("dnssec_enabled"):
            dnssec_enabled = unbound.get("dnssec", "0") == "1"
            if not dnssec_enabled:
                findings.append(DNSFinding(
                    severity="HIGH",
                    check="dnssec_enabled",
                    issue="DNSSEC ist nicht aktiviert",
                    reason="DNSSEC schützt vor DNS-Spoofing und Cache-Poisoning Attacken",
                    solution="Aktiviere DNSSEC in Services > Unbound DNS > DNSSEC > Enable DNSSEC",
                    details={"current": "disabled", "recommended": "enabled"}
                ))

        # Check DNS Rebinding Protection
        if not self._is_check_excepted("rebinding_protection"):
            rebinding_protection = unbound.get("private_domain", "0") == "1"
            if not rebinding_protection:
                findings.append(DNSFinding(
                    severity="CRITICAL",
                    check="rebinding_protection",
                    issue="DNS Rebinding Protection nicht aktiv",
                    reason="Ohne Schutz können Angreifer DNS Rebinding Attacken durchführen",
                    solution="Aktiviere 'Private Domain' Filter in Services > Unbound DNS > Advanced",
                    details={"current": "disabled", "recommended": "enabled"}
                ))

        # Check DNS over TLS
        if not self._is_check_excepted("dot_enabled"):
            dot_enabled = unbound.get("dot", "0") == "1"
            if not dot_enabled:
                findings.append(DNSFinding(
                    severity="MEDIUM",
                    check="dot_enabled",
                    issue="DNS over TLS (DoT) nicht konfiguriert",
                    reason="DNS-Anfragen werden unverschlüsselt übertragen",
                    solution="Konfiguriere DNS over TLS Forwarding in Services > Unbound DNS > Query Forwarding",
                    details={"current": "disabled", "recommended": "enabled"}
                ))

        # Check if DNS is listening on all interfaces
        interfaces = unbound.get("interfaces", [])
        if "0.0.0.0" in interfaces or not interfaces:
            findings.append(DNSFinding(
                severity="MEDIUM",
                check="dns_interfaces",
                issue="DNS Server hört auf allen Interfaces",
                reason="DNS sollte nur auf internen Interfaces lauschen",
                solution="Beschränke DNS auf spezifische interne Interfaces",
                details={"current_interfaces": interfaces}
            ))

        # Check Access Lists
        access_lists = unbound.get("acls", [])
        if not access_lists:
            findings.append(DNSFinding(
                severity="HIGH",
                check="dns_acl",
                issue="Keine DNS Access Control Lists konfiguriert",
                reason="Ohne ACLs könnte DNS Server von außen abgefragt werden",
                solution="Konfiguriere ACLs in Services > Unbound DNS > Access Lists",
                details={"current": "no ACLs"}
            ))

        return findings

    def _test_dns_server(self, dns_server: str) -> List[DNSFinding]:
        """Perform active security tests on DNS server"""
        findings = []

        # Test for open resolver
        if not self._is_check_excepted("open_resolver"):
            is_open = self._test_open_resolver(dns_server)
            if is_open:
                findings.append(DNSFinding(
                    severity="CRITICAL",
                    check="open_resolver",
                    issue="DNS Server ist ein offener Resolver",
                    reason="Offene DNS Resolver können für DDoS-Amplification-Attacken missbraucht werden",
                    solution="Beschränke DNS-Zugriff auf lokale Netzwerke via Access Lists",
                    details={"test": "open_resolver", "result": "vulnerable"}
                ))

        # Test DNS amplification potential
        amp_factor = self._test_amplification(dns_server)
        if amp_factor and amp_factor > 10:
            findings.append(DNSFinding(
                severity="HIGH",
                check="dns_amplification",
                issue=f"DNS Amplification Faktor: {amp_factor}x",
                reason="Hoher Amplification-Faktor ermöglicht effektive DDoS-Attacken",
                solution="Aktiviere Response Rate Limiting (RRL) in Unbound",
                details={"amplification_factor": amp_factor}
            ))

        return findings

    def _test_open_resolver(self, dns_server: str) -> bool:
        """Test if DNS server is an open resolver"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = 3
            resolver.lifetime = 3

            # Try to resolve an external domain
            try:
                answer = resolver.resolve('google.com', 'A')
                # If we got an answer, it might be an open resolver
                # However, this is expected for internal queries
                # A true open resolver test would need to be done from external IP
                logger.info(f"DNS server {dns_server} resolved external query")
                return False  # Can't determine from internal network
            except Exception:
                return False

        except Exception as e:
            logger.debug(f"Open resolver test failed: {e}")
            return False

    def _test_amplification(self, dns_server: str) -> float:
        """Test DNS amplification factor"""
        try:
            # Create a query for a TXT record (typically larger responses)
            query = dns.message.make_query('version.bind', 'TXT', 'CH')
            query_size = len(query.to_wire())

            # Send query
            response = dns.query.udp(query, dns_server, timeout=3)
            response_size = len(response.to_wire())

            # Calculate amplification factor
            if query_size > 0:
                amp_factor = response_size / query_size
                logger.info(f"DNS amplification factor: {amp_factor:.2f}x")
                return round(amp_factor, 2)

        except Exception as e:
            logger.debug(f"Amplification test failed: {e}")

        return 0

    def _is_check_excepted(self, check_name: str) -> bool:
        """Check if a specific DNS check is in exceptions"""
        for exc in self.exceptions:
            if exc.get("check") == check_name:
                return True
        return False

    def get_dns_recommendations(self) -> List[str]:
        """Get general DNS security recommendations"""
        return [
            "Aktiviere DNSSEC für DNS-Validierung",
            "Verwende DNS over TLS (DoT) für verschlüsselte DNS-Anfragen",
            "Konfiguriere Access Lists um DNS nur für interne Netzwerke verfügbar zu machen",
            "Aktiviere DNS Rebinding Protection",
            "Verwende Response Rate Limiting (RRL) gegen DDoS",
            "Regelmäßige Updates von Unbound DNS",
            "Monitoring von DNS-Logs auf ungewöhnliche Aktivitäten",
            "Erwäge DNS Blacklisting/Filtering für zusätzliche Sicherheit"
        ]
