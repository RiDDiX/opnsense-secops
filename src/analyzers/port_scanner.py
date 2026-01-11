"""
Port Scanner
Scans networks for open ports and identifies security issues
"""
import nmap
import logging
from typing import Dict, List, Set
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


@dataclass
class PortFinding:
    """Represents a port security finding"""
    severity: str
    host: str
    port: int
    service: str
    state: str
    issue: str
    reason: str
    solution: str


class PortScanner:
    """Scans network for open ports and security issues"""

    def __init__(self, rules_config: Dict, exceptions: List[Dict], scan_options: Dict):
        self.rules_config = rules_config
        self.exceptions = exceptions
        self.scan_options = scan_options
        self.nm = nmap.PortScanner()

        # Build critical ports map
        self.critical_ports = {}
        for port_rule in rules_config.get("critical_ports", []):
            self.critical_ports[port_rule["port"]] = port_rule

        # Build allowed ports set
        self.allowed_ports = set()
        for port_rule in rules_config.get("allowed_ports", []):
            self.allowed_ports.add(port_rule["port"])

        # Build exception ports map
        self.exception_ports = {}
        for exc in (exceptions or []):
            port = exc.get("port")
            host = exc.get("host", "*")
            if port:
                if host not in self.exception_ports:
                    self.exception_ports[host] = set()
                self.exception_ports[host].add(port)

    def scan_network(self, network: str, hosts: List[str] = None) -> List[PortFinding]:
        """Scan network or specific hosts for open ports"""
        findings = []

        if hosts:
            # Scan specific hosts
            for host in hosts:
                findings.extend(self._scan_host(host))
        else:
            # Scan entire network
            findings.extend(self._scan_network_range(network))

        return findings

    def _scan_network_range(self, network: str) -> List[PortFinding]:
        """Scan entire network range"""
        findings = []

        logger.info(f"Starting network scan for {network}")

        try:
            # First, do a quick ping scan to find live hosts
            self.nm.scan(hosts=network, arguments='-sn')
            live_hosts = self.nm.all_hosts()

            logger.info(f"Found {len(live_hosts)} live hosts")

            # Now scan each live host for ports
            max_workers = self.scan_options.get("max_parallel_scans", 10)

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_host = {
                    executor.submit(self._scan_host, host): host
                    for host in live_hosts
                }

                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        host_findings = future.result()
                        findings.extend(host_findings)
                    except Exception as e:
                        logger.error(f"Error scanning host {host}: {e}")

        except Exception as e:
            logger.error(f"Network scan failed: {e}")

        return findings

    def _scan_host(self, host: str) -> List[PortFinding]:
        """Scan a single host for open ports"""
        findings = []

        logger.info(f"Scanning host {host}")

        try:
            # Build port list: all critical ports + common ports
            critical_port_list = list(self.critical_ports.keys())
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                           1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

            all_ports = set(critical_port_list + common_ports)
            port_range = ','.join(map(str, sorted(all_ports)))

            # Perform SYN scan
            arguments = f'-sS -sV --version-intensity 5 -T4'
            if self.scan_options.get("aggressive_scan", False):
                arguments += ' -A'

            self.nm.scan(hosts=host, ports=port_range, arguments=arguments)

            if host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()

                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        state = port_info.get('state', 'unknown')

                        if state == 'open':
                            finding = self._analyze_open_port(host, port, port_info)
                            if finding:
                                findings.append(finding)

        except Exception as e:
            logger.error(f"Error scanning host {host}: {e}")

        return findings

    def _analyze_open_port(self, host: str, port: int, port_info: Dict) -> PortFinding:
        """Analyze if an open port is a security issue"""

        # Check if port is in exceptions
        if self._is_excepted(host, port):
            logger.debug(f"Port {port} on {host} is excepted")
            return None

        # Check if port is in allowed list
        if port in self.allowed_ports:
            logger.debug(f"Port {port} is in allowed list")
            return None

        # Check if port is critical
        if port in self.critical_ports:
            critical_info = self.critical_ports[port]
            service = port_info.get('name', critical_info['name'])

            return PortFinding(
                severity=critical_info['severity'],
                host=host,
                port=port,
                service=service,
                state=port_info.get('state', 'open'),
                issue=f"Kritischer Port {port} ({service}) ist offen",
                reason=critical_info['reason'],
                solution=self._generate_port_solution(port, service)
            )

        # Unknown open port - flag as informational
        service = port_info.get('name', 'unknown')
        return PortFinding(
            severity="LOW",
            host=host,
            port=port,
            service=service,
            state=port_info.get('state', 'open'),
            issue=f"Unbekannter offener Port {port}",
            reason="Port ist offen, aber nicht in der kritischen Liste",
            solution=f"Prüfe ob Port {port} ({service}) benötigt wird und schließe ihn wenn nicht"
        )

    def _is_excepted(self, host: str, port: int) -> bool:
        """Check if port/host combination is in exceptions"""
        # Check host-specific exceptions
        if host in self.exception_ports and port in self.exception_ports[host]:
            return True

        # Check wildcard exceptions
        if "*" in self.exception_ports and port in self.exception_ports["*"]:
            return True

        return False

    def _generate_port_solution(self, port: int, service: str) -> str:
        """Generate solution for closing/securing a port"""
        solutions = {
            22: "SSH sollte nur über VPN oder mit Key-basierter Authentifizierung + Fail2Ban erreichbar sein",
            23: "Deaktiviere Telnet sofort und verwende SSH stattdessen",
            3389: "RDP sollte nur über VPN erreichbar sein oder mit Network Level Authentication (NLA)",
            3306: "MySQL sollte nur von lokalen/vertrauenswürdigen Hosts erreichbar sein. Bind auf 127.0.0.1",
            5432: "PostgreSQL sollte nur von lokalen/vertrauenswürdigen Hosts erreichbar sein",
            6379: "Redis sollte nur lokal erreichbar sein und requirepass verwenden",
            27017: "MongoDB sollte Authentifizierung aktiviert haben und nur lokal/intern erreichbar sein",
            445: "SMB sollte niemals öffentlich erreichbar sein. Blockiere Port 445 auf WAN",
            2375: "Docker API sollte niemals unverschlüsselt erreichbar sein",
            9200: "Elasticsearch sollte hinter einem Reverse Proxy mit Authentifizierung sein"
        }

        return solutions.get(port, f"Schließe Port {port} in der Firewall oder beschränke Zugriff auf vertrauenswürdige IPs")

    def get_scan_summary(self, findings: List[PortFinding]) -> Dict:
        """Generate summary statistics"""
        return {
            "total_findings": len(findings),
            "critical": len([f for f in findings if f.severity == "CRITICAL"]),
            "high": len([f for f in findings if f.severity == "HIGH"]),
            "medium": len([f for f in findings if f.severity == "MEDIUM"]),
            "low": len([f for f in findings if f.severity == "LOW"]),
            "unique_hosts": len(set(f.host for f in findings)),
            "unique_ports": len(set(f.port for f in findings))
        }
