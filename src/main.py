"""
OPNsense Security Auditor - Main Application
Comprehensive security audit tool for OPNsense firewalls
"""
import os
import sys
import logging
from typing import Dict, List
from dataclasses import asdict

from src.opnsense_client import OPNsenseClient
from src.config_loader import ConfigLoader
from src.report_generator import ReportGenerator
from src.analyzers.firewall_analyzer import FirewallAnalyzer
from src.analyzers.port_scanner import PortScanner
from src.analyzers.dns_analyzer import DNSAnalyzer
from src.analyzers.vlan_analyzer import VLANAnalyzer
from src.analyzers.network_discovery import NetworkDiscovery
from src.analyzers.vulnerability_scanner import VulnerabilityScanner
from src.analyzers.system_security_analyzer import SystemSecurityAnalyzer
from src.analyzers.optimal_config_generator import OptimalConfigGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/app/reports/audit.log')
    ]
)
logger = logging.getLogger(__name__)


class SecurityAuditor:
    """Main security auditor application"""

    def __init__(self):
        self.config_loader = ConfigLoader()
        self.rules, self.exceptions = self.config_loader.load_all()

        # Get OPNsense connection details from environment
        self.opnsense_host = os.getenv("OPNSENSE_HOST")
        self.opnsense_api_key = os.getenv("OPNSENSE_API_KEY")
        self.opnsense_api_secret = os.getenv("OPNSENSE_API_SECRET")
        self.scan_network = os.getenv("SCAN_NETWORK", "192.168.1.0/24")

        # Initialize client
        self.client = None

        # Initialize analyzers
        self.firewall_analyzer = None
        self.port_scanner = None
        self.dns_analyzer = None
        self.vlan_analyzer = None
        self.network_discovery = None
        self.vulnerability_scanner = None
        self.system_security_analyzer = None
        self.optimal_config_generator = None

        # Report generator
        self.report_generator = ReportGenerator(self.config_loader.get_report_options())

    def validate_configuration(self) -> bool:
        """Validate configuration before running"""
        if not self.opnsense_host:
            logger.error("OPNSENSE_HOST environment variable not set")
            return False

        if not self.opnsense_api_key or not self.opnsense_api_secret:
            logger.error("OPNSENSE_API_KEY and OPNSENSE_API_SECRET must be set")
            return False

        # Validate config files
        warnings = self.config_loader.validate_config()
        for warning in warnings:
            logger.warning(f"Configuration warning: {warning}")

        return True

    def initialize_client(self) -> bool:
        """Initialize OPNsense API client"""
        try:
            self.client = OPNsenseClient(
                host=self.opnsense_host,
                api_key=self.opnsense_api_key,
                api_secret=self.opnsense_api_secret,
                verify_ssl=False
            )

            if not self.client.test_connection():
                logger.error("Failed to connect to OPNsense")
                return False

            logger.info(f"Successfully connected to OPNsense at {self.opnsense_host}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize OPNsense client: {e}")
            return False

    def _get_scan_networks(self) -> List[str]:
        """Get list of networks to scan from config or environment"""
        import json
        networks = []
        
        # First, check for saved network selection in config
        config_file = "/app/config/scan_networks.json"
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                selected = config.get('selected_networks', [])
                if selected:
                    networks = [n.get('network') for n in selected if n.get('network') and n.get('enabled', True)]
                    if networks:
                        logger.info(f"Using {len(networks)} networks from config: {networks}")
                        return networks
        except Exception as e:
            logger.debug(f"Could not load network config: {e}")
        
        # Fallback to environment variables
        if self.scan_network:
            networks.append(self.scan_network)
        
        additional_networks = os.getenv("ADDITIONAL_NETWORKS", "")
        if additional_networks:
            networks.extend([n.strip() for n in additional_networks.split(",")])
        
        # Filter to only private networks
        import ipaddress
        private_networks = []
        for net in networks:
            try:
                network = ipaddress.ip_network(net, strict=False)
                if network.is_private:
                    private_networks.append(net)
                else:
                    logger.warning(f"Skipping non-private network: {net}")
            except ValueError:
                logger.warning(f"Invalid network format: {net}")
        
        logger.info(f"Scanning networks: {private_networks}")
        return private_networks

    def initialize_analyzers(self):
        """Initialize all analyzers"""
        scan_options = self.config_loader.get_scan_options()

        self.firewall_analyzer = FirewallAnalyzer(
            self.rules,
            self.config_loader.get_firewall_exceptions()
        )

        self.port_scanner = PortScanner(
            self.rules,
            self.config_loader.get_port_exceptions(),
            scan_options
        )

        self.dns_analyzer = DNSAnalyzer(
            self.rules,
            self.config_loader.get_dns_exceptions()
        )

        self.vlan_analyzer = VLANAnalyzer(
            self.rules,
            self.config_loader.get_vlan_exceptions()
        )

        self.network_discovery = NetworkDiscovery(scan_options)

        self.vulnerability_scanner = VulnerabilityScanner(scan_options)

        self.system_security_analyzer = SystemSecurityAnalyzer(
            self.rules,
            self.config_loader.get_system_exceptions()
        )

        self.optimal_config_generator = OptimalConfigGenerator()

        logger.info("All analyzers initialized")

    def _update_progress(self, step_name: str, step_number: int) -> bool:
        """Update scan progress if scan_manager is available. Returns False if cancelled."""
        if hasattr(self, 'scan_manager') and self.scan_manager:
            return self.scan_manager.update(step_name, step_number)
        return True

    def _is_cancelled(self) -> bool:
        """Check if scan was cancelled"""
        if hasattr(self, 'scan_manager') and self.scan_manager:
            return self.scan_manager.is_cancelled()
        return False

    def _get_wan_exposed_ports(self, nat_rules: List[Dict]) -> List[Dict]:
        """Extract WAN-exposed port forwards from NAT rules"""
        exposed_ports = []
        
        for rule in nat_rules:
            # Check if this is a port forward rule
            if not rule.get('enabled', True):
                continue
            
            # Get target/destination info
            target_ip = rule.get('target', rule.get('destination', {}).get('address', ''))
            target_port = rule.get('local-port', rule.get('destination', {}).get('port', ''))
            external_port = rule.get('source', {}).get('port', target_port)
            protocol = rule.get('protocol', 'tcp')
            description = rule.get('descr', rule.get('description', ''))
            
            # Handle port ranges
            if target_port and '-' in str(target_port):
                ports = str(target_port).split('-')
                try:
                    for p in range(int(ports[0]), int(ports[1]) + 1):
                        exposed_ports.append({
                            'external_port': p,
                            'internal_port': p,
                            'internal_ip': target_ip,
                            'protocol': protocol,
                            'description': description
                        })
                except:
                    pass
            elif target_port:
                try:
                    exposed_ports.append({
                        'external_port': int(external_port) if external_port else int(target_port),
                        'internal_port': int(target_port),
                        'internal_ip': target_ip,
                        'protocol': protocol,
                        'description': description
                    })
                except:
                    pass
        
        return exposed_ports

    def run_audit(self) -> Dict:
        """Run complete security audit"""
        logger.info("Starting security audit...")

        results = {
            "opnsense_host": self.opnsense_host,
            "scan_timestamp": self.report_generator.timestamp,
            "firewall_findings": [],
            "port_findings": [],
            "dns_findings": [],
            "vlan_findings": [],
            "vulnerability_findings": [],
            "system_findings": [],
            "devices": [],
            "network_map": {},
            "statistics": {},
            "vulnerability_summary": {},
            "summary": {},
            "optimal_config": {},
            "security_score": 0,
            "security_grade": "F"
        }

        # Step 4: Collect data from OPNsense
        if not self._update_progress('Collecting data from OPNsense...', 4):
            return results
        
        logger.info("Collecting data from OPNsense...")
        firewall_rules = self.client.get_firewall_rules()
        nat_rules = self.client.get_nat_rules()
        vlans = self.client.get_vlans()
        interfaces = self.client.get_interfaces()
        dns_config = self.client.get_dns_config()
        dhcp_leases = self.client.get_dhcp_leases()
        arp_table = self.client.get_arp_table()

        logger.info(f"Retrieved {len(firewall_rules)} firewall rules")
        logger.info(f"Retrieved {len(nat_rules)} NAT rules")
        logger.info(f"Retrieved {len(vlans)} VLANs")

        if self._is_cancelled():
            return results

        # Analyze Firewall Rules
        logger.info("Analyzing firewall rules...")
        firewall_findings = self.firewall_analyzer.analyze(firewall_rules, nat_rules)
        results["firewall_findings"] = [asdict(f) for f in firewall_findings]
        logger.info(f"Found {len(firewall_findings)} firewall issues")

        # Analyze DNS Configuration
        logger.info("Analyzing DNS configuration...")
        dns_findings = self.dns_analyzer.analyze(dns_config, self.opnsense_host)
        results["dns_findings"] = [asdict(f) for f in dns_findings]
        logger.info(f"Found {len(dns_findings)} DNS issues")

        # Analyze VLANs
        logger.info("Analyzing VLAN configuration...")
        vlan_findings = self.vlan_analyzer.analyze(vlans, interfaces, firewall_rules)
        results["vlan_findings"] = [asdict(f) for f in vlan_findings]
        logger.info(f"Found {len(vlan_findings)} VLAN issues")

        if self._is_cancelled():
            return results

        # Step 5: Network Discovery
        if not self._update_progress('Discovering network devices...', 5):
            return results
        
        logger.info("Starting network discovery...")
        networks = self._get_scan_networks()

        devices = self.network_discovery.discover_network(networks, dhcp_leases, arp_table, vlans)
        results["devices"] = [asdict(d) for d in devices]
        logger.info(f"Discovered {len(devices)} devices")

        # Generate network map
        results["network_map"] = self.network_discovery.generate_network_map(devices)
        results["statistics"] = self.network_discovery.get_device_statistics(devices)

        if self._is_cancelled():
            return results

        # Step 6: Port Scanning (WAN-exposed ports only)
        if not self._update_progress('Checking WAN-exposed ports...', 6):
            return results
        
        logger.info("Checking for WAN-exposed ports via NAT rules...")
        
        # Get WAN-exposed ports from NAT rules - these are the security concerns
        wan_exposed_ports = self._get_wan_exposed_ports(nat_rules)
        logger.info(f"Found {len(wan_exposed_ports)} WAN-exposed port forwards")
        
        # Only scan and report ports that are exposed to WAN
        port_findings = self.port_scanner.scan_wan_exposed(wan_exposed_ports)
        results["port_findings"] = [asdict(f) for f in port_findings]
        results["wan_exposed_ports"] = wan_exposed_ports
        logger.info(f"Found {len(port_findings)} WAN-exposed port security issues")

        # System Security Analysis
        logger.info("Analyzing system security configuration...")
        system_config = self.client.get_system_config()
        system_findings = self.system_security_analyzer.analyze(system_config)
        results["system_findings"] = [asdict(f) for f in system_findings]
        logger.info(f"Found {len(system_findings)} system security issues")

        # Vulnerability Scanning
        logger.info("Scanning for known vulnerabilities...")

        # Build service map from discovered devices
        service_map = {}
        for device in devices:
            for port, service in device.services.items():
                endpoint = f"{device.ip}:{port}"
                service_map[endpoint] = {
                    "name": service,
                    "version": "Unknown"  # nmap version detection would provide this
                }

        vuln_findings = self.vulnerability_scanner.scan_services(service_map)

        # Also check OPNsense version
        system_info = self.client.get_system_info()
        opnsense_version = system_info.get("product_version", "")
        if opnsense_version:
            logger.info(f"Checking OPNsense version {opnsense_version} for vulnerabilities")
            opnsense_vulns = self.vulnerability_scanner.check_opnsense_version(opnsense_version)
            vuln_findings.extend(opnsense_vulns)

        # Check for critical service vulnerabilities
        critical_services = [{"name": s} for s in set(service_map.values()) if s]
        critical_vulns = self.vulnerability_scanner.check_critical_services(critical_services)
        vuln_findings.extend(critical_vulns)

        results["vulnerability_findings"] = [asdict(f) for f in vuln_findings]
        results["vulnerability_summary"] = self.vulnerability_scanner.get_vulnerability_summary(vuln_findings)
        logger.info(f"Found {len(vuln_findings)} known vulnerabilities")

        # Generate Summary
        all_findings = firewall_findings + port_findings + dns_findings + vlan_findings + vuln_findings + system_findings
        results["summary"] = self._generate_summary(all_findings)

        # Generate Optimal Configuration Recommendations
        logger.info("Generating optimal configuration recommendations...")
        config_recommendations = self.optimal_config_generator.generate_recommendations(results)
        results["optimal_config"] = config_recommendations.get("optimal_config", {})
        results["security_score"] = config_recommendations.get("security_score", 0)
        results["security_grade"] = config_recommendations.get("grade", "F")
        results["priority_actions"] = config_recommendations.get("priority_actions", [])
        results["implementation_guide"] = config_recommendations.get("implementation_guide", [])
        results["category_recommendations"] = config_recommendations.get("categories", {})

        logger.info(f"Security Score: {results['security_score']}/100 (Grade: {results['security_grade']})")
        logger.info("Security audit completed")
        return results

    def _generate_summary(self, findings: List) -> Dict:
        """Generate summary statistics"""
        summary = {
            "total_findings": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

        for finding in findings:
            severity = finding.severity if hasattr(finding, 'severity') else finding.get('severity', 'UNKNOWN')
            if severity == "CRITICAL":
                summary["critical"] += 1
            elif severity == "HIGH":
                summary["high"] += 1
            elif severity == "MEDIUM":
                summary["medium"] += 1
            elif severity == "LOW":
                summary["low"] += 1

        return summary

    def run(self):
        """Main execution flow"""
        logger.info("=" * 80)
        logger.info("OPNsense Security Auditor Starting")
        logger.info("=" * 80)

        # Validate configuration
        if not self.validate_configuration():
            logger.error("Configuration validation failed")
            sys.exit(1)

        # Initialize client
        if not self.initialize_client():
            logger.error("Failed to initialize OPNsense client")
            sys.exit(1)

        # Initialize analyzers
        self.initialize_analyzers()

        # Run audit
        try:
            results = self.run_audit()

            # Print summary to console
            self.report_generator.print_summary(results)

            # Generate reports
            logger.info("Generating reports...")
            report_files = self.report_generator.generate_reports(results)

            logger.info("Reports generated:")
            for report_file in report_files:
                logger.info(f"  - {report_file}")

            logger.info("=" * 80)
            logger.info("Security Audit Completed Successfully")
            logger.info("=" * 80)

        except Exception as e:
            logger.error(f"Audit failed with error: {e}", exc_info=True)
            sys.exit(1)


def main():
    """Entry point"""
    auditor = SecurityAuditor()
    auditor.run()


if __name__ == "__main__":
    main()
