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

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, silent: bool = False) -> Dict:
        """Make HTTP request to OPNsense API
        
        Args:
            method: HTTP method (GET/POST)
            endpoint: API endpoint
            data: Optional JSON data for POST requests
            silent: If True, don't log errors (for expected fallbacks)
        """
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
            if not silent:
                logger.error(f"API request failed: {e}")
            raise

    def get_firewall_rules(self) -> List[Dict]:
        """Get all firewall rules from automation API"""
        try:
            # Use POST for search endpoints per OPNsense API docs
            result = self._make_request("POST", "/firewall/filter/search_rule")
            return result.get("rows", [])
        except Exception as e:
            logger.error(f"Failed to get firewall rules: {e}")
            return []

    def get_nat_rules(self) -> List[Dict]:
        """Get NAT rules (Source NAT / Outbound)"""
        nat_rules = []
        
        # Get Source NAT rules
        try:
            result = self._make_request("POST", "/firewall/source_nat/search_rule")
            for rule in result.get("rows", []):
                rule["nat_type"] = "source_nat"
                nat_rules.append(rule)
        except Exception as e:
            logger.debug(f"Failed to get Source NAT rules: {e}")
        
        # Get 1:1 NAT rules
        try:
            result = self._make_request("POST", "/firewall/one_to_one/search_rule")
            for rule in result.get("rows", []):
                rule["nat_type"] = "one_to_one"
                nat_rules.append(rule)
        except Exception as e:
            logger.debug(f"Failed to get 1:1 NAT rules: {e}")
        
        # Get NPT (IPv6 Network Prefix Translation) rules
        try:
            result = self._make_request("POST", "/firewall/npt/search_rule")
            for rule in result.get("rows", []):
                rule["nat_type"] = "npt"
                nat_rules.append(rule)
        except Exception as e:
            logger.debug(f"Failed to get NPT rules: {e}")
        
        return nat_rules

    def get_interfaces(self) -> Dict:
        """Get all network interfaces from multiple sources"""
        interfaces = {}
        
        # Method 1: Try overview/export (newer API)
        try:
            result = self._make_request("GET", "/interfaces/overview/export", silent=True)
            if result and isinstance(result, dict):
                interfaces.update(result)
                logger.debug(f"Got {len(result)} interfaces from overview/export")
        except Exception:
            pass
        
        # Method 2: Try diagnostics/interface/getInterfaceConfig
        try:
            result = self._make_request("GET", "/diagnostics/interface/getInterfaceConfig", silent=True)
            if result and isinstance(result, dict):
                for iface_name, iface_data in result.items():
                    if iface_name not in interfaces:
                        interfaces[iface_name] = iface_data
                logger.debug(f"Got {len(result)} interfaces from getInterfaceConfig")
        except Exception:
            pass
        
        # Method 3: Try legacy config endpoint
        try:
            result = self._make_request("GET", "/diagnostics/interface/getInterfaceNames", silent=True)
            if result and isinstance(result, dict):
                for iface_key, iface_name in result.items():
                    if iface_key not in interfaces:
                        interfaces[iface_key] = {'descr': iface_name, 'if': iface_key}
                logger.debug(f"Got {len(result)} interface names")
        except Exception:
            pass
        
        logger.info(f"Total interfaces found: {len(interfaces)} - {list(interfaces.keys())}")
        return interfaces

    def get_vlans(self) -> List[Dict]:
        """Get VLAN configuration"""
        try:
            # Use POST for search_item per OPNsense API docs
            result = self._make_request("POST", "/interfaces/vlan_settings/search_item")
            return result.get("rows", [])
        except Exception as e:
            logger.debug(f"Failed to get VLANs: {e}")
            return []

    def get_dhcp_leases(self) -> List[Dict]:
        """Get DHCP leases from various possible endpoints"""
        leases = []
        
        # Method 1: ISC DHCP leases plugin (older)
        try:
            result = self._make_request("GET", "/dhcpleases/service/get", silent=True)
            if result and isinstance(result, dict):
                lease_data = result.get("leases", {})
                if isinstance(lease_data, dict):
                    leases = lease_data.get("lease", [])
                    if leases:
                        logger.debug(f"Got {len(leases)} leases from dhcpleases plugin")
                        return leases if isinstance(leases, list) else [leases]
        except Exception:
            pass  # Silently try next method
        
        # Method 2: Kea DHCP4 leases (newer)
        try:
            result = self._make_request("POST", "/kea/leases4/search", silent=True)
            if result and isinstance(result, dict):
                leases = result.get("rows", [])
                if leases:
                    logger.debug(f"Got {len(leases)} leases from Kea leases4")
                    return leases
        except Exception:
            pass
        
        # Method 3: Kea DHCP4 search
        try:
            result = self._make_request("POST", "/kea/dhcpv4/searchLease", silent=True)
            if result and isinstance(result, dict):
                leases = result.get("rows", [])
                if leases:
                    logger.debug(f"Got {len(leases)} leases from Kea dhcpv4")
                    return leases
        except Exception:
            pass
        
        # Method 4: ISC DHCP service status
        try:
            result = self._make_request("GET", "/dhcpv4/leases/searchLease", silent=True)
            if result and isinstance(result, dict):
                leases = result.get("rows", [])
                if leases:
                    logger.debug(f"Got {len(leases)} leases from dhcpv4")
                    return leases
        except Exception:
            pass
        
        logger.debug("No DHCP leases found from any endpoint")
        return []

    def get_arp_table(self) -> List[Dict]:
        """Get ARP table"""
        try:
            result = self._make_request("GET", "/diagnostics/interface/getArp")
            return result.get("rows", []) if isinstance(result, dict) else result
        except Exception as e:
            logger.debug(f"Failed to get ARP table: {e}")
            return []

    def get_dns_config(self) -> Dict:
        """Get DNS configuration including active servers"""
        config = {
            "unbound": {},
            "dnsmasq": {},
            "system_dns": [],
            "dhcp_dns_servers": [],
            "forward_servers": []
        }
        
        # Unbound settings
        try:
            result = self._make_request("GET", "/unbound/settings/get")
            if result:
                unbound = result.get("unbound", result)
                config["unbound"] = unbound
                
                # Extract forwarding servers
                fwd = unbound.get("dots", {})
                if fwd:
                    for key, server in fwd.items():
                        if isinstance(server, dict) and server.get("enabled", "0") == "1":
                            config["forward_servers"].append({
                                "ip": server.get("server", ""),
                                "port": server.get("port", "853"),
                                "dot": True,
                                "name": server.get("domain", "")
                            })
        except Exception as e:
            logger.debug(f"Failed to get Unbound config: {e}")
        
        # Dnsmasq settings
        try:
            result = self._make_request("GET", "/dnsmasq/settings/get")
            if result:
                config["dnsmasq"] = result.get("dnsmasq", result)
        except Exception as e:
            logger.debug(f"Dnsmasq not available: {e}")
        
        # System nameservers
        try:
            result = self._make_request("GET", "/core/system/generalSettings/get")
            if result:
                general = result.get("general", {})
                dns1 = general.get("dns_server1", "")
                dns2 = general.get("dns_server2", "")
                dns3 = general.get("dns_server3", "")
                config["system_dns"] = [d for d in [dns1, dns2, dns3] if d]
        except Exception as e:
            logger.debug(f"Failed to get system DNS: {e}")
        
        # DHCP server DNS settings (what clients get)
        try:
            result = self._make_request("GET", "/dhcpv4/settings/get")
            if result:
                for iface, settings in result.items():
                    if isinstance(settings, dict):
                        dns = settings.get("dns_servers", "")
                        if dns:
                            config["dhcp_dns_servers"].extend(dns.split(","))
        except Exception as e:
            logger.debug(f"Failed to get DHCP DNS: {e}")
        
        return config

    def get_alias_list(self) -> List[Dict]:
        """Get firewall aliases"""
        try:
            result = self._make_request("POST", "/firewall/alias/search_item")
            return result.get("rows", [])
        except Exception as e:
            logger.debug(f"Failed to get aliases: {e}")
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
            result = self._make_request("GET", "/routes/gateway/status")
            return result.get("items", []) if isinstance(result, dict) else []
        except Exception as e:
            logger.debug(f"Failed to get routes: {e}")
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

    def get_system_config(self) -> Dict:
        """Fetch system security settings"""
        config = {
            "ssh": {},
            "webgui": {},
            "ids": {},
            "firmware": {},
            "general": {},
            "auth": {},
            "vpn": {},
            "logging": {},
            "cron": {},
            "captiveportal": {}
        }

        # SSH
        try:
            result = self._make_request("GET", "/core/system/sshSettings/get")
            config["ssh"] = result.get("settings", {})
        except Exception as e:
            logger.debug(f"SSH config: {e}")

        # Web GUI
        try:
            result = self._make_request("GET", "/core/system/webguiSettings/get")
            config["webgui"] = result.get("webgui", {})
        except Exception as e:
            logger.debug(f"WebGUI config: {e}")

        # IDS/IPS
        try:
            result = self._make_request("GET", "/ids/settings/get")
            config["ids"] = result.get("ids", {})
        except Exception as e:
            logger.debug(f"IDS config: {e}")

        # Firmware
        try:
            result = self._make_request("GET", "/core/firmware/status")
            config["firmware"] = result
        except Exception as e:
            logger.debug(f"Firmware status: {e}")

        # General
        try:
            result = self._make_request("GET", "/core/system/generalSettings/get")
            config["general"] = result.get("general", {})
        except Exception as e:
            logger.debug(f"General settings: {e}")

        # VPN configs
        config["vpn"] = self._get_vpn_security_config()

        # Logging
        try:
            result = self._make_request("GET", "/syslog/settings/get")
            config["logging"] = result.get("syslog", {})
        except Exception as e:
            logger.debug(f"Syslog config: {e}")

        # Backup/Cron
        try:
            result = self._make_request("GET", "/cron/settings/get")
            config["cron"] = result.get("cron", {})
        except Exception as e:
            logger.debug(f"Cron config: {e}")

        # Captive Portal
        try:
            result = self._make_request("GET", "/captiveportal/settings/get")
            config["captiveportal"] = result.get("captiveportal", {})
        except Exception as e:
            logger.debug(f"Captive Portal: {e}")

        return config

    def _get_vpn_security_config(self) -> Dict:
        """Get VPN security-relevant settings"""
        vpn = {"openvpn": {"servers": []}, "ipsec": {}, "wireguard": {}}
        
        # OpenVPN servers
        try:
            result = self._make_request("GET", "/openvpn/export/providers")
            if result:
                for key, srv in result.items():
                    if isinstance(srv, dict):
                        vpn["openvpn"]["servers"].append({
                            "name": srv.get("description", key),
                            "cipher": srv.get("cipher", ""),
                            "auth": srv.get("auth", ""),
                            "tls_auth": srv.get("tls", "0"),
                            "protocol": srv.get("protocol", "")
                        })
        except Exception as e:
            logger.debug(f"OpenVPN export: {e}")
        
        # OpenVPN instances
        try:
            result = self._make_request("POST", "/openvpn/instances/search")
            rows = result.get("rows", [])
            for row in rows:
                vpn["openvpn"]["servers"].append({
                    "name": row.get("description", ""),
                    "cipher": row.get("crypto", ""),
                    "auth": row.get("auth", ""),
                    "role": row.get("role", "")
                })
        except Exception as e:
            logger.debug(f"OpenVPN instances: {e}")
        
        # IPsec
        try:
            result = self._make_request("GET", "/ipsec/tunnel/searchPhase1")
            if result:
                vpn["ipsec"]["enabled"] = "1"
                vpn["ipsec"]["phase1"] = result.get("rows", [])
        except Exception as e:
            logger.debug(f"IPsec: {e}")
        
        # WireGuard
        try:
            result = self._make_request("GET", "/wireguard/general/get")
            if result:
                wg = result.get("general", {})
                vpn["wireguard"]["enabled"] = wg.get("enabled", "0")
        except Exception as e:
            logger.debug(f"WireGuard: {e}")
        
        try:
            result = self._make_request("POST", "/wireguard/client/searchClient")
            vpn["wireguard"]["peers"] = result.get("rows", [])
        except Exception as e:
            logger.debug(f"WireGuard peers: {e}")
        
        return vpn

    def get_certificates(self) -> List[Dict]:
        """Get SSL/TLS certificates"""
        try:
            result = self._make_request("POST", "/trust/cert/search")
            return result.get("rows", [])
        except Exception as e:
            logger.debug(f"Failed to get certificates: {e}")
            return []

    def get_vpn_config(self) -> Dict:
        """Get VPN configurations"""
        vpn_config = {"openvpn": [], "wireguard": [], "ipsec": {}}

        try:
            result = self._make_request("POST", "/openvpn/instances/search")
            vpn_config["openvpn"] = result.get("rows", [])
        except Exception as e:
            logger.debug(f"Failed to get OpenVPN config: {e}")

        try:
            result = self._make_request("POST", "/wireguard/server/search_server")
            vpn_config["wireguard"] = result.get("rows", [])
        except Exception as e:
            logger.debug(f"Failed to get WireGuard config: {e}")

        try:
            result = self._make_request("POST", "/ipsec/tunnel/search_phase1")
            vpn_config["ipsec"] = result.get("rows", [])
        except Exception as e:
            logger.debug(f"Failed to get IPsec config: {e}")

        return vpn_config

    def get_firewall_settings(self) -> Dict:
        """Get firewall advanced settings"""
        try:
            result = self._make_request("GET", "/firewall/filter_base/get")
            return result
        except Exception as e:
            logger.debug(f"Failed to get firewall settings: {e}")
            return {}

    def get_legacy_config(self, section: str) -> Dict:
        """Get legacy configuration via diagnostics API"""
        try:
            result = self._make_request("GET", f"/diagnostics/firewall/pf_states")
            return result
        except Exception as e:
            logger.debug(f"Failed to get legacy config: {e}")
            return {}
