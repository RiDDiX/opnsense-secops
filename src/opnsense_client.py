"""
OPNsense API Client
Handles communication with OPNsense 25.x API
"""
import requests
import urllib3
from typing import Dict, List, Optional, Any, Union
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
        """Get firewall filter rules via /api/firewall/filter/searchRule"""
        try:
            result = self._make_request("POST", "/firewall/filter/searchRule")
            rows = result.get("rows", [])
            logger.info(f"Retrieved {len(rows)} firewall rules")
            return self._normalize_firewall_rules(rows)
        except Exception as e:
            logger.error(f"Failed to get firewall rules: {e}")
            return []

    def _normalize_firewall_rules(self, rules: List[Dict]) -> List[Dict]:
        """Normalize firewall rule fields for consistent analysis"""
        normalized = []
        for rule in rules:
            norm = {
                "uuid": rule.get("uuid", ""),
                "enabled": rule.get("enabled", "0"),
                "sequence": rule.get("sequence", 0),
                "description": rule.get("description", ""),
                "interface": rule.get("interface", ""),
                "direction": rule.get("direction", "in"),
                "ipprotocol": rule.get("ipprotocol", "inet"),
                "protocol": rule.get("protocol", "any"),
                "source_net": rule.get("source_net", "any"),
                "source_port": rule.get("source_port", ""),
                "destination_net": rule.get("destination_net", "any"),
                "destination_port": rule.get("destination_port", ""),
                "action": rule.get("action", "pass"),
                "log": rule.get("log", "0"),
                "quick": rule.get("quick", "1"),
                "_raw": rule
            }
            normalized.append(norm)
        return normalized

    def get_nat_rules(self) -> List[Dict]:
        """Get all NAT rules (Port Forward, Source NAT, 1:1, NPT)"""
        nat_rules = []
        
        # Port Forward rules (most common)
        try:
            result = self._make_request("POST", "/firewall/nat/search_rule", silent=True)
            for rule in result.get("rows", []):
                rule["nat_type"] = "port_forward"
                nat_rules.append(self._normalize_nat_rule(rule))
        except Exception:
            pass
        
        # Source NAT / Outbound
        try:
            result = self._make_request("POST", "/firewall/source_nat/searchRule")
            for rule in result.get("rows", []):
                rule["nat_type"] = "source_nat"
                nat_rules.append(self._normalize_nat_rule(rule))
        except Exception as e:
            logger.debug(f"Source NAT: {e}")
        
        # 1:1 NAT
        try:
            result = self._make_request("POST", "/firewall/one_to_one/searchRule")
            for rule in result.get("rows", []):
                rule["nat_type"] = "one_to_one"
                nat_rules.append(self._normalize_nat_rule(rule))
        except Exception as e:
            logger.debug(f"1:1 NAT: {e}")
        
        # NPT (IPv6)
        try:
            result = self._make_request("POST", "/firewall/npt/searchRule")
            for rule in result.get("rows", []):
                rule["nat_type"] = "npt"
                nat_rules.append(self._normalize_nat_rule(rule))
        except Exception as e:
            logger.debug(f"NPT: {e}")
        
        logger.info(f"Retrieved {len(nat_rules)} NAT rules")
        return nat_rules

    def _normalize_nat_rule(self, rule: Dict) -> Dict:
        """Normalize NAT rule fields"""
        return {
            "uuid": rule.get("uuid", ""),
            "enabled": rule.get("enabled", "0"),
            "description": rule.get("description", ""),
            "interface": rule.get("interface", ""),
            "source": rule.get("source_net", rule.get("source", "any")),
            "destination": rule.get("destination_net", rule.get("destination", "")),
            "destination_port": rule.get("destination_port", rule.get("local-port", "")),
            "target": rule.get("target", rule.get("redirect_target", "")),
            "target_port": rule.get("target_port", rule.get("local-port", "")),
            "protocol": rule.get("protocol", "any"),
            "nat_type": rule.get("nat_type", "unknown"),
            "_raw": rule
        }

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
        """Get DNS configuration via OPNsense 25.x API"""
        config = {
            "unbound": {},
            "dnsmasq": {},
            "system_dns": [],
            "dhcp_dns_servers": [],
            "forward_servers": []
        }
        
        # Unbound general settings via /api/unbound/settings/get
        try:
            result = self._make_request("GET", "/unbound/settings/get")
            if result:
                unbound = result.get("unbound", {})
                if not unbound and isinstance(result, dict):
                    unbound = result
                config["unbound"] = self._normalize_unbound_config(unbound)
                logger.info(f"Unbound config retrieved, enabled={config['unbound'].get('enabled', 'unknown')}")
        except Exception as e:
            logger.debug(f"Unbound settings: {e}")
        
        # Unbound forwarding servers via /api/unbound/settings/searchForward
        try:
            result = self._make_request("POST", "/unbound/settings/searchForward")
            if result and result.get("rows"):
                for fwd in result["rows"]:
                    if fwd.get("enabled", "0") == "1":
                        config["forward_servers"].append({
                            "ip": fwd.get("server", fwd.get("ip", "")),
                            "port": fwd.get("port", "53"),
                            "dot": fwd.get("forward_type", "") == "dot",
                            "domain": fwd.get("domain", ""),
                            "enabled": True
                        })
                logger.info(f"Found {len(config['forward_servers'])} DNS forwarders")
        except Exception as e:
            logger.debug(f"Unbound forwards: {e}")
        
        # Dnsmasq via /api/dnsmasq/settings/get
        try:
            result = self._make_request("GET", "/dnsmasq/settings/get")
            if result:
                dnsmasq = result.get("dnsmasq", result)
                config["dnsmasq"] = {
                    "enabled": dnsmasq.get("enabled", "0"),
                    "port": dnsmasq.get("port", "53")
                }
        except Exception as e:
            logger.debug(f"Dnsmasq: {e}")
        
        # System DNS servers via /api/core/system/generalSettings/get
        try:
            result = self._make_request("GET", "/core/system/generalSettings/get")
            if result:
                general = result.get("general", {})
                for i in range(1, 5):
                    dns = general.get(f"dns_server{i}", general.get(f"dnsserver{i}", ""))
                    if dns and dns.strip():
                        config["system_dns"].append(dns.strip())
        except Exception as e:
            logger.debug(f"System DNS: {e}")
        
        # DHCPv4 DNS settings via /api/dhcpv4/settings/get
        try:
            result = self._make_request("GET", "/dhcpv4/settings/get")
            if result:
                dhcp = result.get("dhcpv4", result)
                if isinstance(dhcp, dict):
                    for key, iface in dhcp.items():
                        if isinstance(iface, dict):
                            dns = iface.get("dns_servers", iface.get("dnsserver", ""))
                            if dns:
                                for d in str(dns).split(","):
                                    if d.strip() and d.strip() not in config["dhcp_dns_servers"]:
                                        config["dhcp_dns_servers"].append(d.strip())
        except Exception as e:
            logger.debug(f"DHCP DNS: {e}")
        
        # Kea DHCPv4 DNS (newer OPNsense)
        try:
            result = self._make_request("GET", "/kea/dhcpv4/get")
            if result:
                kea = result.get("dhcpv4", result)
                if isinstance(kea, dict):
                    for key, subnet in kea.get("subnets", {}).items():
                        if isinstance(subnet, dict):
                            dns = subnet.get("option_data_dns_servers", "")
                            if dns:
                                for d in str(dns).split(","):
                                    if d.strip() and d.strip() not in config["dhcp_dns_servers"]:
                                        config["dhcp_dns_servers"].append(d.strip())
        except Exception as e:
            logger.debug(f"Kea DHCP: {e}")
        
        return config

    def _normalize_unbound_config(self, unbound: Dict) -> Dict:
        """Normalize Unbound config fields"""
        return {
            "enabled": unbound.get("enabled", unbound.get("enable", "0")),
            "dnssec": unbound.get("dnssec", "0"),
            "forwarding": unbound.get("forwarding", unbound.get("forward_mode", "0")),
            "port": unbound.get("port", "53"),
            "interfaces": unbound.get("active_interface", unbound.get("interfaces", [])),
            "private_domain": unbound.get("private_domain", unbound.get("rebind_protection", "0")),
            "cache_size": unbound.get("msgcachesize", unbound.get("cache_size", "")),
            "prefetch": unbound.get("prefetch", "0"),
            "dot": unbound.get("dot", unbound.get("dns_over_tls", "0")),
            "acls": unbound.get("acls", {}),
            "_raw": unbound
        }

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
        """Fetch system security settings via OPNsense 25.x API"""
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

        # SSH via /api/core/system/sshSettings/get
        try:
            result = self._make_request("GET", "/core/system/sshSettings/get")
            ssh = result.get("settings", result.get("ssh", {}))
            config["ssh"] = {
                "enabled": ssh.get("enabled", ssh.get("enable", "0")),
                "permitrootlogin": ssh.get("permitrootlogin", ssh.get("root_login", "0")),
                "passwordauth": ssh.get("passwordauth", ssh.get("password_auth", "0")),
                "port": ssh.get("port", "22"),
                "interfaces": ssh.get("interfaces", ssh.get("listen_interfaces", [])),
                "_raw": ssh
            }
            logger.info(f"SSH config: enabled={config['ssh']['enabled']}")
        except Exception as e:
            logger.debug(f"SSH config: {e}")

        # Web GUI via /api/core/system/webguiSettings/get
        try:
            result = self._make_request("GET", "/core/system/webguiSettings/get")
            webgui = result.get("webgui", result.get("settings", {}))
            config["webgui"] = {
                "protocol": webgui.get("protocol", "https"),
                "port": webgui.get("port", webgui.get("webguiport", "443")),
                "httpsredirect": webgui.get("httpsredirect", webgui.get("ssl_redirect", "0")),
                "hsts": webgui.get("hsts", webgui.get("stricttransportsecurity", "0")),
                "session_timeout": webgui.get("session_timeout", webgui.get("authserver_timeout", "240")),
                "interfaces": webgui.get("interfaces", webgui.get("listen_interfaces", [])),
                "_raw": webgui
            }
        except Exception as e:
            logger.debug(f"WebGUI config: {e}")

        # IDS/IPS via /api/ids/settings/get
        try:
            result = self._make_request("GET", "/ids/settings/get")
            ids = result.get("ids", result.get("settings", {}))
            config["ids"] = {
                "enabled": ids.get("enabled", ids.get("enable", "0")),
                "ips_mode": ids.get("ips", ids.get("ips_mode", "0")),
                "auto_update": ids.get("UpdateCron", ids.get("auto_update", "0")),
                "rulesets": ids.get("rulesets", {}),
                "_raw": ids
            }
        except Exception as e:
            logger.debug(f"IDS config: {e}")

        # Firmware via /api/core/firmware/status
        try:
            result = self._make_request("GET", "/core/firmware/status")
            config["firmware"] = {
                "updates_available": result.get("status", "") == "update",
                "current_version": result.get("product_version", ""),
                "last_update": result.get("last_check", ""),
                "_raw": result
            }
        except Exception as e:
            logger.debug(f"Firmware status: {e}")

        # General via /api/core/system/generalSettings/get
        try:
            result = self._make_request("GET", "/core/system/generalSettings/get")
            general = result.get("general", result.get("settings", {}))
            config["general"] = {
                "hostname": general.get("hostname", ""),
                "domain": general.get("domain", ""),
                "ntp_servers": [
                    general.get("timeservers", general.get("ntpserver", ""))
                ],
                "console_menu": general.get("disableconsolemenu", "0") != "1",
                "_raw": general
            }
        except Exception as e:
            logger.debug(f"General settings: {e}")

        # Auth settings
        try:
            result = self._make_request("GET", "/auth/settings/get")
            auth = result.get("settings", result.get("auth", {}))
            config["auth"] = {
                "totp_enabled": auth.get("totp", auth.get("totp_enabled", "0")),
                "lockout_threshold": int(auth.get("lockout_attempts", auth.get("lockout_threshold", 0)) or 0),
                "_raw": auth
            }
        except Exception as e:
            logger.debug(f"Auth settings: {e}")

        # VPN
        config["vpn"] = self._get_vpn_security_config()

        # Syslog via /api/syslog/settings/get
        try:
            result = self._make_request("GET", "/syslog/settings/get")
            syslog = result.get("syslog", result.get("settings", {}))
            destinations = syslog.get("destinations", {})
            has_remote = any(
                isinstance(d, dict) and d.get("enabled", "0") == "1" 
                for d in destinations.values()
            ) if isinstance(destinations, dict) else False
            config["logging"] = {
                "remote_syslog": {"enabled": has_remote},
                "preserve_logs": int(syslog.get("preservelogs", 31) or 31),
                "firewall": {"log_default_block": syslog.get("logdefaultblock", "1") == "1"},
                "_raw": syslog
            }
        except Exception as e:
            logger.debug(f"Syslog config: {e}")

        # Cron/Backup via /api/cron/settings/get
        try:
            result = self._make_request("GET", "/cron/settings/get")
            cron = result.get("cron", result.get("settings", {}))
            jobs = cron.get("jobs", {})
            has_backup = any(
                isinstance(j, dict) and "backup" in str(j.get("command", "")).lower()
                for j in jobs.values()
            ) if isinstance(jobs, dict) else False
            config["cron"] = {
                "backup": {"enabled": has_backup, "encrypted": False},
                "_raw": cron
            }
        except Exception as e:
            logger.debug(f"Cron config: {e}")

        # Captive Portal via /api/captiveportal/settings/get
        try:
            result = self._make_request("GET", "/captiveportal/settings/get")
            cp = result.get("captiveportal", result.get("settings", {}))
            zones = cp.get("zones", {})
            active_zones = [z for z in zones.values() if isinstance(z, dict) and z.get("enabled", "0") == "1"]
            if active_zones:
                zone = active_zones[0]
                config["captiveportal"] = {
                    "enabled": True,
                    "https": zone.get("certificate", "") != "",
                    "timeout": int(zone.get("idletimeout", 0) or 0),
                    "_raw": cp
                }
            else:
                config["captiveportal"] = {"enabled": False}
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
