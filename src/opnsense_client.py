"""
OPNsense API Client
Handles all communication with OPNsense API
"""
import requests
import urllib3
from typing import Dict, List, Optional, Any
import logging

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class OPNsenseClient:
    """Client for OPNsense API communication"""

    def __init__(self, host: str, api_key: str, api_secret: str, verify_ssl: bool = False):
        self.host = host.rstrip('/')
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{self.host}/api"
        self.session = requests.Session()
        self.session.auth = (api_key, api_secret)
        self.session.verify = verify_ssl

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """Make HTTP request to OPNsense API"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        try:
            if method.upper() == "GET":
                response = self.session.get(url, timeout=30)
            elif method.upper() == "POST":
                response = self.session.post(url, json=data, timeout=30)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise

    def get_firewall_rules(self) -> List[Dict]:
        """Get all firewall rules"""
        try:
            result = self._make_request("GET", "/firewall/filter/searchRule")
            return result.get("rows", [])
        except Exception as e:
            logger.error(f"Failed to get firewall rules: {e}")
            return []

    def get_nat_rules(self) -> List[Dict]:
        """Get NAT port forwarding rules"""
        try:
            result = self._make_request("GET", "/firewall/nat/searchRule")
            return result.get("rows", [])
        except Exception as e:
            logger.error(f"Failed to get NAT rules: {e}")
            return []

    def get_interfaces(self) -> Dict:
        """Get all network interfaces"""
        try:
            result = self._make_request("GET", "/interfaces/overview/export")
            return result
        except Exception as e:
            logger.error(f"Failed to get interfaces: {e}")
            return {}

    def get_vlans(self) -> List[Dict]:
        """Get VLAN configuration"""
        try:
            result = self._make_request("GET", "/interfaces/vlan_settings/search")
            return result.get("rows", [])
        except Exception as e:
            logger.error(f"Failed to get VLANs: {e}")
            return []

    def get_dhcp_leases(self) -> List[Dict]:
        """Get DHCP leases"""
        try:
            result = self._make_request("GET", "/dhcpv4/leases/searchLease")
            return result.get("rows", [])
        except Exception as e:
            logger.error(f"Failed to get DHCP leases: {e}")
            return []

    def get_arp_table(self) -> List[Dict]:
        """Get ARP table"""
        try:
            result = self._make_request("GET", "/diagnostics/interface/search_arp")
            return result.get("rows", [])
        except Exception as e:
            logger.error(f"Failed to get ARP table: {e}")
            return []

    def get_dns_config(self) -> Dict:
        """Get DNS/Unbound configuration"""
        try:
            result = self._make_request("GET", "/unbound/settings/get")
            return result
        except Exception as e:
            logger.error(f"Failed to get DNS config: {e}")
            return {}

    def get_alias_list(self) -> List[Dict]:
        """Get firewall aliases"""
        try:
            result = self._make_request("GET", "/firewall/alias/searchItem")
            return result.get("rows", [])
        except Exception as e:
            logger.error(f"Failed to get aliases: {e}")
            return []

    def get_system_info(self) -> Dict:
        """Get system information"""
        try:
            result = self._make_request("GET", "/core/system/status")
            return result
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {}

    def get_routes(self) -> List[Dict]:
        """Get routing table"""
        try:
            result = self._make_request("GET", "/routes/routes/search")
            return result.get("rows", [])
        except Exception as e:
            logger.error(f"Failed to get routes: {e}")
            return []

    def test_connection(self) -> bool:
        """Test if connection to OPNsense is working"""
        try:
            self.get_system_info()
            logger.info(f"Successfully connected to OPNsense at {self.host}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to OPNsense: {e}")
            return False
