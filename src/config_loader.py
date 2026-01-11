"""
Configuration Loader
Loads and validates configuration from YAML files
"""
import yaml
import os
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Loads configuration files"""

    def __init__(self, config_dir: str = "/app/config"):
        self.config_dir = config_dir
        self.rules = {}
        self.exceptions = {}

    def load_all(self) -> tuple[Dict, Dict]:
        """Load all configuration files"""
        self.rules = self.load_rules()
        self.exceptions = self.load_exceptions()
        return self.rules, self.exceptions

    def load_rules(self) -> Dict:
        """Load security rules configuration"""
        rules_file = os.path.join(self.config_dir, "rules.yaml")

        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                rules = yaml.safe_load(f)
                logger.info(f"Loaded rules from {rules_file}")
                return rules
        except FileNotFoundError:
            logger.error(f"Rules file not found: {rules_file}")
            return self._get_default_rules()
        except yaml.YAMLError as e:
            logger.error(f"Error parsing rules YAML: {e}")
            return self._get_default_rules()

    def load_exceptions(self) -> Dict:
        """Load exceptions configuration"""
        exceptions_file = os.path.join(self.config_dir, "exceptions.yaml")

        try:
            with open(exceptions_file, 'r', encoding='utf-8') as f:
                exceptions = yaml.safe_load(f)
                logger.info(f"Loaded exceptions from {exceptions_file}")
                return exceptions
        except FileNotFoundError:
            logger.warning(f"Exceptions file not found: {exceptions_file}, using defaults")
            return self._get_default_exceptions()
        except yaml.YAMLError as e:
            logger.error(f"Error parsing exceptions YAML: {e}")
            return self._get_default_exceptions()

    def _get_default_rules(self) -> Dict:
        """Get default rules if file not found"""
        return {
            "critical_ports": [],
            "allowed_ports": [],
            "dns_security": {},
            "firewall_rules": {},
            "vlan_security": {},
            "network_segmentation": {}
        }

    def _get_default_exceptions(self) -> Dict:
        """Get default exceptions if file not found"""
        return {
            "port_exceptions": [],
            "firewall_exceptions": [],
            "dns_exceptions": [],
            "vlan_exceptions": [],
            "host_exceptions": [],
            "scan_options": {
                "aggressive_scan": False,
                "port_scan_timeout": 300,
                "max_parallel_scans": 10,
                "skip_ping": False
            },
            "report_options": {
                "output_format": "all",
                "detail_level": "normal",
                "critical_only": False,
                "include_solutions": True
            }
        }

    def get_scan_options(self) -> Dict:
        """Get scan options from exceptions config"""
        return self.exceptions.get("scan_options", self._get_default_exceptions()["scan_options"])

    def get_report_options(self) -> Dict:
        """Get report options from exceptions config"""
        return self.exceptions.get("report_options", self._get_default_exceptions()["report_options"])

    def get_port_exceptions(self) -> List[Dict]:
        """Get port exceptions"""
        return self.exceptions.get("port_exceptions", [])

    def get_firewall_exceptions(self) -> List[Dict]:
        """Get firewall exceptions"""
        return self.exceptions.get("firewall_exceptions", [])

    def get_dns_exceptions(self) -> List[Dict]:
        """Get DNS exceptions"""
        return self.exceptions.get("dns_exceptions", [])

    def get_vlan_exceptions(self) -> List[Dict]:
        """Get VLAN exceptions"""
        return self.exceptions.get("vlan_exceptions", [])

    def get_host_exceptions(self) -> List[str]:
        """Get list of hosts to exclude from scanning"""
        exceptions = self.exceptions.get("host_exceptions", [])
        return [exc.get("ip") for exc in exceptions if exc.get("ip")]

    def validate_config(self) -> List[str]:
        """Validate configuration and return list of warnings"""
        warnings = []

        # Validate rules
        if not self.rules.get("critical_ports"):
            warnings.append("No critical ports defined in rules")

        # Validate scan options
        scan_opts = self.get_scan_options()
        if scan_opts.get("max_parallel_scans", 0) > 50:
            warnings.append("max_parallel_scans is very high, may cause network issues")

        if scan_opts.get("port_scan_timeout", 0) > 600:
            warnings.append("port_scan_timeout is very high")

        return warnings
