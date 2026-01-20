"""
DNS Configuration Analyzer
Analyzes DNS/Unbound configuration for security issues
"""
import logging
import socket
import subprocess
import dns.resolver
import dns.query
import dns.message
from typing import Dict, List, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DNSFinding:
    severity: str
    check: str
    issue: str
    reason: str
    solution: str
    details: Dict
    opnsense_path: str = ""


class DNSAnalyzer:
    """Analyzes DNS configuration for security issues"""

    def __init__(self, rules_config: Dict, exceptions: List[Dict]):
        self.rules_config = rules_config
        self.exceptions = exceptions
        self.dns_security = rules_config.get("dns_security", {})

    def analyze(self, dns_config: Dict, dns_server: str) -> List[DNSFinding]:
        """Analyze DNS configuration"""
        findings = []

        # Analyze Unbound/OPNsense settings
        findings.extend(self._analyze_dns_config(dns_config))

        # Detect and test actual DNS servers in use
        active_servers = self._detect_active_dns_servers(dns_config, dns_server)
        findings.extend(self._analyze_active_dns_servers(active_servers))

        # Test OPNsense DNS server
        findings.extend(self._test_dns_server(dns_server))

        return findings

    def _detect_active_dns_servers(self, dns_config: Dict, opnsense_ip: str) -> List[Dict]:
        """Detect which DNS servers are actually in use"""
        servers = []
        
        # OPNsense Unbound
        unbound = dns_config.get("unbound", {})
        if unbound.get("enabled", "0") == "1":
            servers.append({
                "ip": opnsense_ip,
                "type": "unbound",
                "name": "OPNsense Unbound",
                "forwarding": unbound.get("forwarding", "0") == "1"
            })
        
        # Check forwarding servers
        fwd_servers = unbound.get("forward_servers", [])
        for fwd in fwd_servers:
            if isinstance(fwd, str):
                servers.append({"ip": fwd, "type": "forwarder", "name": f"Forwarder {fwd}"})
            elif isinstance(fwd, dict):
                servers.append({
                    "ip": fwd.get("ip", ""),
                    "type": "forwarder",
                    "name": fwd.get("name", "Forwarder"),
                    "dot": fwd.get("dot", False)
                })
        
        # Check dnsmasq
        dnsmasq = dns_config.get("dnsmasq", {})
        if dnsmasq.get("enabled", "0") == "1":
            servers.append({
                "ip": opnsense_ip,
                "type": "dnsmasq",
                "name": "OPNsense Dnsmasq"
            })
        
        # Check system DNS (resolv.conf)
        system_dns = dns_config.get("system_dns", [])
        for dns_ip in system_dns:
            if dns_ip and dns_ip not in [s["ip"] for s in servers]:
                servers.append({
                    "ip": dns_ip,
                    "type": "system",
                    "name": f"System DNS {dns_ip}"
                })
        
        # Check DHCP-assigned DNS for clients
        dhcp_dns = dns_config.get("dhcp_dns_servers", [])
        for dns_ip in dhcp_dns:
            if dns_ip and dns_ip not in [s["ip"] for s in servers]:
                servers.append({
                    "ip": dns_ip,
                    "type": "dhcp_assigned",
                    "name": f"DHCP DNS {dns_ip}"
                })
        
        return servers

    def _analyze_active_dns_servers(self, servers: List[Dict]) -> List[DNSFinding]:
        """Analyze active DNS servers for security issues"""
        findings = []
        
        public_dns = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"]
        isp_patterns = ["isp", "provider", "telekom", "vodafone", "comcast"]
        
        for srv in servers:
            ip = srv.get("ip", "")
            srv_type = srv.get("type", "")
            
            # Check public DNS without DoT
            if ip in public_dns and not srv.get("dot", False):
                findings.append(DNSFinding(
                    severity="MEDIUM",
                    check="public_dns_unencrypted",
                    issue=f"Public DNS {ip} ohne Verschlüsselung",
                    reason="DNS-Anfragen an öffentliche Server sind ohne DoT/DoH sichtbar",
                    solution="Aktiviere DNS-over-TLS für externe DNS-Server",
                    details={"server": ip, "encrypted": False},
                    opnsense_path="Services > Unbound DNS > Query Forwarding"
                ))
            
            # Test server response
            if ip and srv_type != "unbound":
                test_result = self._test_external_dns(ip)
                if test_result.get("issues"):
                    for issue in test_result["issues"]:
                        findings.append(issue)
        
        # Check if no local DNS
        local_dns = [s for s in servers if s.get("type") in ["unbound", "dnsmasq"]]
        if not local_dns:
            findings.append(DNSFinding(
                severity="HIGH",
                check="no_local_dns",
                issue="Kein lokaler DNS-Resolver aktiv",
                reason="Ohne lokalen Resolver gehen alle Anfragen direkt ins Internet",
                solution="Aktiviere Unbound DNS als lokalen Resolver",
                details={"active_servers": [s["ip"] for s in servers]},
                opnsense_path="Services > Unbound DNS > General"
            ))
        
        # Check forwarding mode without caching
        for srv in servers:
            if srv.get("type") == "unbound" and srv.get("forwarding"):
                findings.append(DNSFinding(
                    severity="LOW",
                    check="dns_forwarding_mode",
                    issue="Unbound im Forwarding-Modus",
                    reason="Forwarding-Modus kann Caching und DNSSEC-Validierung beeinträchtigen",
                    solution="Prüfe ob direkter Resolving-Modus möglich ist",
                    details={"mode": "forwarding"},
                    opnsense_path="Services > Unbound DNS > Query Forwarding"
                ))
        
        return findings

    def _test_external_dns(self, dns_ip: str) -> Dict:
        """Test external DNS server for issues"""
        result = {"issues": [], "latency": None}
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_ip]
            resolver.timeout = 5
            resolver.lifetime = 5
            
            import time
            start = time.time()
            resolver.resolve("google.com", "A")
            latency = (time.time() - start) * 1000
            result["latency"] = latency
            
            # High latency warning
            if latency > 200:
                result["issues"].append(DNSFinding(
                    severity="LOW",
                    check="dns_latency",
                    issue=f"Hohe DNS-Latenz zu {dns_ip}: {latency:.0f}ms",
                    reason="Hohe Latenz verlangsamt alle Netzwerkverbindungen",
                    solution="Verwende geografisch nähere DNS-Server",
                    details={"server": dns_ip, "latency_ms": latency},
                    opnsense_path="Services > Unbound DNS > Query Forwarding"
                ))
                
        except Exception as e:
            result["issues"].append(DNSFinding(
                severity="HIGH",
                check="dns_unreachable",
                issue=f"DNS-Server {dns_ip} nicht erreichbar",
                reason=f"Server antwortet nicht: {str(e)[:50]}",
                solution="Prüfe Netzwerkverbindung und DNS-Server-Status",
                details={"server": dns_ip, "error": str(e)},
                opnsense_path="Services > Unbound DNS > Query Forwarding"
            ))
        
        return result

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
                    solution="Aktiviere DNSSEC in Services > Unbound DNS > DNSSEC",
                    details={"current": "disabled", "recommended": "enabled"},
                    opnsense_path="Services > Unbound DNS > General > DNSSEC"
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
                    solution="Aktiviere 'Private Domain' Filter",
                    details={"current": "disabled", "recommended": "enabled"},
                    opnsense_path="Services > Unbound DNS > Advanced > Private Domains"
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
                    solution="Konfiguriere DNS over TLS Forwarding",
                    details={"current": "disabled", "recommended": "enabled"},
                    opnsense_path="Services > Unbound DNS > Query Forwarding"
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
                details={"current_interfaces": interfaces},
                opnsense_path="Services > Unbound DNS > General > Network Interfaces"
            ))

        # Check Access Lists
        access_lists = unbound.get("acls", [])
        if not access_lists:
            findings.append(DNSFinding(
                severity="HIGH",
                check="dns_acl",
                issue="Keine DNS Access Control Lists konfiguriert",
                reason="Ohne ACLs könnte DNS Server von außen abgefragt werden",
                solution="Konfiguriere ACLs für interne Netzwerke",
                details={"current": "no ACLs"},
                opnsense_path="Services > Unbound DNS > Access Lists"
            ))
        
        # Check cache size
        cache_size = unbound.get("cache_size", "")
        if not cache_size or int(cache_size or 0) < 50:
            findings.append(DNSFinding(
                severity="LOW",
                check="dns_cache_size",
                issue="DNS Cache zu klein oder nicht konfiguriert",
                reason="Größerer Cache verbessert Performance und reduziert externe Anfragen",
                solution="Erhöhe Cache-Größe auf mindestens 50MB",
                details={"current": cache_size or "default"},
                opnsense_path="Services > Unbound DNS > Advanced > Cache Size"
            ))
        
        # Check prefetch
        prefetch = unbound.get("prefetch", "0") == "1"
        if not prefetch:
            findings.append(DNSFinding(
                severity="LOW",
                check="dns_prefetch",
                issue="DNS Prefetching nicht aktiviert",
                reason="Prefetching hält populäre Einträge im Cache aktuell",
                solution="Aktiviere Prefetch für bessere Performance",
                details={"current": "disabled"},
                opnsense_path="Services > Unbound DNS > Advanced > Prefetch Support"
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
