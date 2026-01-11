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

        # Collect data from OPNsense
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

        # Network Discovery
        logger.info("Starting network discovery...")
        networks = [self.scan_network]
        additional_networks = os.getenv("ADDITIONAL_NETWORKS", "")
        if additional_networks:
            networks.extend([n.strip() for n in additional_networks.split(",")])

        devices = self.network_discovery.discover_network(networks, dhcp_leases, arp_table, vlans)
        results["devices"] = [asdict(d) for d in devices]
        logger.info(f"Discovered {len(devices)} devices")

        # Generate network map
        results["network_map"] = self.network_discovery.generate_network_map(devices)
        results["statistics"] = self.network_discovery.get_device_statistics(devices)

        # Port Scanning
        logger.info("Scanning for open ports on discovered devices...")
        active_hosts = [d.ip for d in devices if d.status == "active"]
        excluded_hosts = self.config_loader.get_host_exceptions()
        scan_hosts = [h for h in active_hosts if h not in excluded_hosts]

        logger.info(f"Scanning {len(scan_hosts)} hosts (excluded {len(excluded_hosts)})")

        port_findings = self.port_scanner.scan_network(None, scan_hosts)
        results["port_findings"] = [asdict(f) for f in port_findings]
        logger.info(f"Found {len(port_findings)} port security issues")

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
