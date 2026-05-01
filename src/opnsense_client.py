"""OPNsense REST client. Targets 25.x and 26.x."""
import logging
import os

import requests
import urllib3

logger = logging.getLogger(__name__)


def _env_truthy(name: str) -> bool:
    return str(os.getenv(name, "")).lower() in ("1", "true", "yes", "on")


class OPNsenseClient:

    def __init__(
        self,
        host: str,
        api_key: str,
        api_secret: str,
        verify_ssl: bool | None = None,
        timeout: int | None = None,
    ):
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret

        if verify_ssl is None:
            verify_ssl = not _env_truthy("OPNSENSE_INSECURE_TLS")
        self.verify_ssl = bool(verify_ssl)

        if timeout is None:
            try:
                timeout = int(os.getenv("OPNSENSE_API_TIMEOUT", "30"))
            except ValueError:
                timeout = 30
        self.timeout = max(1, int(timeout))

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.base_url = f"https://{self.host}/api"
        self.session = requests.Session()
        self.session.auth = (api_key, api_secret)
        self.session.verify = self.verify_ssl

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: dict | None = None,
        silent: bool = False,
    ) -> dict:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        method_u = method.upper()
        try:
            if method_u == "GET":
                response = self.session.get(url, timeout=self.timeout)
            elif method_u == "POST":
                response = self.session.post(url, json=data or {}, timeout=self.timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()

            ctype = (response.headers.get("Content-Type") or "").lower()
            if "json" not in ctype:
                snippet = (response.text or "")[:200]
                raise ValueError(
                    f"Non-JSON response from {endpoint} (status={response.status_code}, ctype={ctype}): {snippet}"
                )
            return response.json()
        except requests.exceptions.RequestException as e:
            if not silent:
                logger.error(f"API request failed: {e}")
            raise

    def _search_all(
        self,
        endpoint: str,
        page_size: int = 500,
        max_pages: int = 50,
        silent: bool = False,
    ) -> list[dict]:
        rows: list[dict] = []
        page = 1
        while page <= max_pages:
            body = {
                "current": page,
                "rowCount": page_size,
                "sort": {},
                "searchPhrase": "",
            }
            result = self._make_request("POST", endpoint, data=body, silent=silent)
            chunk = result.get("rows", []) if isinstance(result, dict) else []
            rows.extend(chunk)
            total = 0
            try:
                total = int(result.get("total", 0) or 0)
            except (TypeError, ValueError):
                total = 0
            if not chunk or len(chunk) < page_size or len(rows) >= total:
                break
            page += 1
        return rows

    def get_firewall_rules(self) -> list[dict]:
        try:
            rows = self._search_all("/firewall/filter/search_rule")
            logger.info(f"Retrieved {len(rows)} firewall rules")
            return self._normalize_firewall_rules(rows)
        except Exception as e:
            logger.error(f"Failed to get firewall rules: {e}")
            return []

    def _normalize_firewall_rules(self, rules: list[dict]) -> list[dict]:
        normalized = []
        for rule in rules:
            prio_group = str(rule.get("prio_group", "") or "")
            interfacenot = str(rule.get("interfacenot", "0") or "0")
            is_floating = prio_group.startswith("200000") or interfacenot == "1"
            interfaces = [i for i in str(rule.get("interface", "") or "").split(",") if i]
            norm = {
                "uuid": rule.get("uuid", ""),
                "enabled": str(rule.get("enabled", "0") or "0"),
                "sequence": rule.get("sequence", 0),
                "sort_order": rule.get("sort_order", ""),
                "prio_group": prio_group,
                "is_floating": is_floating,
                "is_group_rule": prio_group.startswith("300000"),
                "interfaces": interfaces,
                "description": rule.get("description", ""),
                "interface": rule.get("interface", ""),
                "interfacenot": interfacenot,
                "direction": rule.get("direction", "in"),
                "ipprotocol": rule.get("ipprotocol", "inet"),
                "protocol": rule.get("protocol", "any"),
                "icmptype": rule.get("icmptype", ""),
                "icmp6type": rule.get("icmp6type", ""),
                "source_net": rule.get("source_net", "any"),
                "source_port": rule.get("source_port", ""),
                "source_not": str(rule.get("source_not", "0") or "0"),
                "destination_net": rule.get("destination_net", "any"),
                "destination_port": rule.get("destination_port", ""),
                "destination_not": str(rule.get("destination_not", "0") or "0"),
                "action": rule.get("action", "pass"),
                "log": str(rule.get("log", "0") or "0"),
                "quick": str(rule.get("quick", "1") or "1"),
                "gateway": rule.get("gateway", ""),
                "replyto": rule.get("replyto", ""),
                "disablereplyto": str(rule.get("disablereplyto", "0") or "0"),
                "categories": rule.get("categories", ""),
                "categories_named": rule.get("%categories", ""),
                "tag": rule.get("tag", ""),
                "tagged": rule.get("tagged", ""),
                "set-prio": rule.get("set-prio", ""),
                "sched": rule.get("sched", ""),
                "statetimeout": rule.get("statetimeout", ""),
                "udp-first": rule.get("udp-first", ""),
                "udp-multiple": rule.get("udp-multiple", ""),
                "udp-single": rule.get("udp-single", ""),
                "max-src-conn": rule.get("max-src-conn", ""),
                "max-src-states": rule.get("max-src-states", ""),
                "max-src-conn-rate": rule.get("max-src-conn-rate", ""),
                "max-src-conn-rates": rule.get("max-src-conn-rates", ""),
                "tcpflags1": rule.get("tcpflags1", ""),
                "tcpflags2": rule.get("tcpflags2", ""),
                "tcpflags_any": str(rule.get("tcpflags_any", "0") or "0"),
                "divert-to": rule.get("divert-to", ""),
                "statetype": rule.get("statetype", ""),
                "state-policy": rule.get("state-policy", ""),
                "_raw": rule,
            }
            normalized.append(norm)
        return normalized

    def get_nat_rules(self) -> list[dict]:
        nat_rules = []

        # Port Forward (DNAT). 26.x renames the module to d_nat, 25.x kept "nat" as fallback.
        port_forward_rows = []
        try:
            port_forward_rows = self._search_all("/firewall/d_nat/search_rule", silent=True)
        except Exception:
            try:
                port_forward_rows = self._search_all("/firewall/nat/search_rule", silent=True)
            except Exception as e:
                logger.debug(f"Port Forward: {e}")
        for rule in port_forward_rows:
            rule["nat_type"] = "port_forward"
            nat_rules.append(self._normalize_nat_rule(rule))

        for path, nat_type in (
            ("/firewall/source_nat/search_rule", "source_nat"),
            ("/firewall/one_to_one/search_rule", "one_to_one"),
            ("/firewall/npt/search_rule", "npt"),
        ):
            try:
                for rule in self._search_all(path, silent=True):
                    rule["nat_type"] = nat_type
                    nat_rules.append(self._normalize_nat_rule(rule))
            except Exception as e:
                logger.debug(f"{nat_type}: {e}")

        logger.info(f"Retrieved {len(nat_rules)} NAT rules")
        return nat_rules

    def _normalize_nat_rule(self, rule: dict) -> dict:
        nat_type = rule.get("nat_type", "unknown")
        # OPNsense uses different field names per NAT type. Keep them distinct.
        if nat_type == "port_forward":
            destination = rule.get("destination_net", rule.get("destination", ""))
            destination_port = rule.get("destination_port", rule.get("dstport", ""))
            target = rule.get("target", rule.get("redirect_target", ""))
            target_port = rule.get("local-port", rule.get("target_port", ""))
        elif nat_type == "source_nat":
            destination = rule.get("destination_net", rule.get("destination", ""))
            destination_port = rule.get("destination_port", "")
            target = rule.get("target", "")
            target_port = ""
        elif nat_type == "one_to_one":
            destination = rule.get("destination_net", rule.get("destination", ""))
            destination_port = ""
            target = rule.get("target", rule.get("external", ""))
            target_port = ""
        elif nat_type == "npt":
            destination = rule.get("destination_net", rule.get("destination", ""))
            destination_port = ""
            target = rule.get("destination", "")
            target_port = ""
        else:
            destination = rule.get("destination_net", rule.get("destination", ""))
            destination_port = rule.get("destination_port", "")
            target = rule.get("target", "")
            target_port = rule.get("target_port", "")

        return {
            "uuid": rule.get("uuid", ""),
            "enabled": rule.get("enabled", "0"),
            "description": rule.get("description", ""),
            "interface": rule.get("interface", ""),
            "source": rule.get("source_net", rule.get("source", "any")),
            "destination": destination,
            "destination_port": destination_port,
            "target": target,
            "target_port": target_port,
            "protocol": rule.get("protocol", "any"),
            "nat_type": nat_type,
            "_raw": rule,
        }

    def get_interfaces(self) -> dict:
        interfaces: dict = {}
        sources = []

        try:
            result = self._make_request("GET", "/interfaces/overview/export", silent=True)
            if isinstance(result, dict) and result:
                interfaces.update(result)
                sources.append(f"overview/export={len(result)}")
        except Exception:
            pass

        try:
            result = self._make_request("GET", "/diagnostics/interface/getInterfaceConfig", silent=True)
            if isinstance(result, dict) and result:
                added = 0
                for k, v in result.items():
                    if k not in interfaces:
                        interfaces[k] = v
                        added += 1
                sources.append(f"getInterfaceConfig+={added}")
        except Exception:
            pass

        try:
            result = self._make_request("GET", "/diagnostics/interface/getInterfaceNames", silent=True)
            if isinstance(result, dict) and result:
                added = 0
                for k, name in result.items():
                    if k not in interfaces:
                        interfaces[k] = {"descr": name, "if": k}
                        added += 1
                sources.append(f"getInterfaceNames+={added}")
        except Exception:
            pass

        if not interfaces:
            logger.warning("Could not load interfaces from any endpoint")
        else:
            logger.info(f"Total interfaces: {len(interfaces)} ({', '.join(sources)})")
        return interfaces

    def get_vlans(self) -> list[dict]:
        try:
            return self._search_all("/interfaces/vlan_settings/search_item")
        except Exception as e:
            logger.debug(f"Failed to get VLANs: {e}")
            return []

    def get_dhcp_leases(self) -> list[dict]:
        # Kea is the default in current releases. Try Kea first, then fall back to ISC.
        try:
            rows = self._search_all("/kea/leases4/search", silent=True)
            if rows:
                logger.info(f"DHCP leases source=kea/leases4 count={len(rows)}")
                return rows
        except Exception:
            pass

        try:
            rows = self._search_all("/kea/dhcpv4/searchLease", silent=True)
            if rows:
                logger.info(f"DHCP leases source=kea/dhcpv4 count={len(rows)}")
                return rows
        except Exception:
            pass

        try:
            result = self._make_request("GET", "/dhcpv4/leases/search_lease", silent=True)
            if isinstance(result, dict):
                rows = result.get("rows", []) or []
                if rows:
                    logger.info(f"DHCP leases source=isc/dhcpv4 count={len(rows)}")
                    return rows
        except Exception:
            pass

        try:
            result = self._make_request("GET", "/dhcpleases/service/get", silent=True)
            if isinstance(result, dict):
                lease_data = result.get("leases", {})
                if isinstance(lease_data, dict):
                    leases = lease_data.get("lease", [])
                    if isinstance(leases, list) and leases:
                        logger.info(f"DHCP leases source=dhcpleases plugin count={len(leases)}")
                        return leases
                    if isinstance(leases, dict):
                        return [leases]
        except Exception:
            pass

        logger.info("No DHCP leases found")
        return []

    def get_arp_table(self) -> list[dict]:
        try:
            result = self._make_request("GET", "/diagnostics/interface/getArp")
            if isinstance(result, dict):
                return result.get("rows", []) or []
            if isinstance(result, list):
                return result
            return []
        except Exception as e:
            logger.debug(f"Failed to get ARP table: {e}")
            return []

    def get_dns_config(self) -> dict:
        config = {
            "unbound": {},
            "dnsmasq": {},
            "system_dns": [],
            "dhcp_dns_servers": [],
            "dhcpv6_dns_servers": [],
            "forward_servers": [],
        }

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

        try:
            for fwd in self._search_all("/unbound/settings/searchForward"):
                if str(fwd.get("enabled", "0")) == "1":
                    config["forward_servers"].append({
                        "ip": fwd.get("server", fwd.get("ip", "")),
                        "port": fwd.get("port", "53"),
                        "dot": fwd.get("forward_type", "") == "dot",
                        "domain": fwd.get("domain", ""),
                        "enabled": True,
                    })
            logger.info(f"Found {len(config['forward_servers'])} DNS forwarders")
        except Exception as e:
            logger.debug(f"Unbound forwards: {e}")

        try:
            result = self._make_request("GET", "/dnsmasq/settings/get", silent=True)
            if result:
                dnsmasq = result.get("dnsmasq", result)
                config["dnsmasq"] = {
                    "enabled": dnsmasq.get("enabled", "0"),
                    "port": dnsmasq.get("port", "53"),
                }
        except Exception as e:
            logger.debug(f"Dnsmasq: {e}")

        try:
            result = self._make_request("GET", "/core/system/generalSettings/get", silent=True)
            if result:
                general = result.get("general", {})
                for i in range(1, 5):
                    dns = general.get(f"dns_server{i}", general.get(f"dnsserver{i}", ""))
                    if dns and str(dns).strip():
                        config["system_dns"].append(str(dns).strip())
        except Exception as e:
            logger.debug(f"System DNS: {e}")

        # Legacy ISC DHCPv4 was removed from core in 26.1, kept silent for older releases.
        try:
            result = self._make_request("GET", "/dhcpv4/settings/get", silent=True)
            if result:
                dhcp = result.get("dhcpv4", result)
                if isinstance(dhcp, dict):
                    for _key, iface in dhcp.items():
                        if isinstance(iface, dict):
                            dns = iface.get("dns_servers", iface.get("dnsserver", ""))
                            if dns:
                                for d in str(dns).split(","):
                                    if d.strip() and d.strip() not in config["dhcp_dns_servers"]:
                                        config["dhcp_dns_servers"].append(d.strip())
        except Exception as e:
            logger.debug(f"DHCP DNS: {e}")

        try:
            for row in self.get_kea_dhcpv4_subnets():
                dns = row.get("option_data.domain_name_servers", "")
                if dns:
                    for d in str(dns).split(","):
                        d = d.strip()
                        if d and d not in config["dhcp_dns_servers"]:
                            config["dhcp_dns_servers"].append(d)
        except Exception as e:
            logger.debug(f"Kea v4 subnets: {e}")

        try:
            for row in self.get_kea_dhcpv6_subnets():
                dns = row.get("option_data.dns_servers", "")
                if dns:
                    for d in str(dns).split(","):
                        d = d.strip()
                        if d and d not in config["dhcpv6_dns_servers"]:
                            config["dhcpv6_dns_servers"].append(d)
        except Exception as e:
            logger.debug(f"Kea v6 subnets: {e}")

        return config

    def _normalize_unbound_config(self, unbound: dict) -> dict:
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
            "_raw": unbound,
        }

    def get_alias_list(self) -> list[dict]:
        try:
            return self._search_all("/firewall/alias/search_item")
        except Exception as e:
            logger.debug(f"Failed to get aliases: {e}")
            return []

    def get_system_info(self) -> dict:
        try:
            return self._make_request("GET", "/core/system/status")
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {}

    def get_routes(self) -> list[dict]:
        try:
            result = self._make_request("GET", "/routes/gateway/status")
            if isinstance(result, dict):
                return result.get("items", []) or []
            return []
        except Exception as e:
            logger.debug(f"Failed to get routes: {e}")
            return []

    def test_connection(self) -> bool:
        try:
            self.get_system_info()
            logger.info(f"Connected to OPNsense at {self.host}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to OPNsense: {e}")
            return False

    def get_system_config(self) -> dict:
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
            "captiveportal": {},
        }

        try:
            result = self._make_request("GET", "/core/system/sshSettings/get")
            ssh = result.get("settings", result.get("ssh", {}))
            config["ssh"] = {
                "enabled": ssh.get("enabled", ssh.get("enable", "0")),
                "permitrootlogin": ssh.get("permitrootlogin", ssh.get("root_login", "0")),
                "passwordauth": ssh.get("passwordauth", ssh.get("password_auth", "0")),
                "port": ssh.get("port", "22"),
                "interfaces": ssh.get("interfaces", ssh.get("listen_interfaces", [])),
                "_raw": ssh,
            }
            logger.info(f"SSH config: enabled={config['ssh']['enabled']}")
        except Exception as e:
            logger.debug(f"SSH config: {e}")

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
                "_raw": webgui,
            }
        except Exception as e:
            logger.debug(f"WebGUI config: {e}")

        try:
            result = self._make_request("GET", "/ids/settings/get")
            ids = result.get("ids", result.get("settings", {}))
            config["ids"] = {
                "enabled": ids.get("enabled", ids.get("enable", "0")),
                "ips_mode": ids.get("ips", ids.get("ips_mode", "0")),
                "auto_update": ids.get("UpdateCron", ids.get("auto_update", "0")),
                "rulesets": ids.get("rulesets", {}),
                "_raw": ids,
            }
        except Exception as e:
            logger.debug(f"IDS config: {e}")

        try:
            result = self._make_request("GET", "/core/firmware/status")
            config["firmware"] = {
                "updates_available": result.get("status", "") == "update",
                "current_version": result.get("product_version", ""),
                "last_update": result.get("last_check", ""),
                "_raw": result,
            }
        except Exception as e:
            logger.debug(f"Firmware status: {e}")

        try:
            result = self._make_request("GET", "/core/system/generalSettings/get", silent=True)
            general = result.get("general", result.get("settings", {}))
            config["general"] = {
                "hostname": general.get("hostname", ""),
                "domain": general.get("domain", ""),
                "ntp_servers": [general.get("timeservers", general.get("ntpserver", ""))],
                "console_menu": general.get("disableconsolemenu", "0") != "1",
                "_raw": general,
            }
        except Exception as e:
            logger.debug(f"General settings: {e}")

        try:
            result = self._make_request("GET", "/auth/settings/get")
            auth = result.get("settings", result.get("auth", {}))
            config["auth"] = {
                "totp_enabled": auth.get("totp", auth.get("totp_enabled", "0")),
                "lockout_threshold": int(
                    auth.get("lockout_attempts", auth.get("lockout_threshold", 0)) or 0
                ),
                "_raw": auth,
            }
        except Exception as e:
            logger.debug(f"Auth settings: {e}")

        config["vpn"] = self._get_vpn_security_config()

        try:
            result = self._make_request("GET", "/syslog/settings/get")
            syslog = result.get("syslog", result.get("settings", {}))
            destinations = syslog.get("destinations", {})
            has_remote = (
                any(
                    isinstance(d, dict) and str(d.get("enabled", "0")) == "1"
                    for d in destinations.values()
                )
                if isinstance(destinations, dict)
                else False
            )
            config["logging"] = {
                "remote_syslog": {"enabled": has_remote},
                "preserve_logs": int(syslog.get("preservelogs", 31) or 31),
                "firewall": {"log_default_block": str(syslog.get("logdefaultblock", "1")) == "1"},
                "_raw": syslog,
            }
        except Exception as e:
            logger.debug(f"Syslog config: {e}")

        try:
            result = self._make_request("GET", "/cron/settings/get")
            cron = result.get("cron", result.get("settings", {}))
            jobs = cron.get("jobs", {})
            has_backup = (
                any(
                    isinstance(j, dict) and "backup" in str(j.get("command", "")).lower()
                    for j in jobs.values()
                )
                if isinstance(jobs, dict)
                else False
            )
            config["cron"] = {"backup": {"enabled": has_backup, "encrypted": False}, "_raw": cron}
        except Exception as e:
            logger.debug(f"Cron config: {e}")

        try:
            result = self._make_request("GET", "/captiveportal/settings/get")
            cp = result.get("captiveportal", result.get("settings", {}))
            zones = cp.get("zones", {})
            active_zones = [
                z for z in zones.values() if isinstance(z, dict) and str(z.get("enabled", "0")) == "1"
            ]
            if active_zones:
                zone = active_zones[0]
                config["captiveportal"] = {
                    "enabled": True,
                    "https": zone.get("certificate", "") != "",
                    "timeout": int(zone.get("idletimeout", 0) or 0),
                    "_raw": cp,
                }
            else:
                config["captiveportal"] = {"enabled": False}
        except Exception as e:
            logger.debug(f"Captive Portal: {e}")

        return config

    def _get_vpn_security_config(self) -> dict:
        vpn = {"openvpn": {"servers": []}, "ipsec": {}, "wireguard": {}}

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
                            "protocol": srv.get("protocol", ""),
                        })
        except Exception as e:
            logger.debug(f"OpenVPN export: {e}")

        try:
            for row in self._search_all("/openvpn/instances/search"):
                vpn["openvpn"]["servers"].append({
                    "name": row.get("description", ""),
                    "cipher": row.get("crypto", ""),
                    "auth": row.get("auth", ""),
                    "role": row.get("role", ""),
                })
        except Exception as e:
            logger.debug(f"OpenVPN instances: {e}")

        try:
            phase1 = self._search_all("/ipsec/tunnel/search_phase1")
            vpn["ipsec"]["enabled"] = "1" if phase1 else "0"
            vpn["ipsec"]["phase1"] = phase1
        except Exception as e:
            logger.debug(f"IPsec phase1: {e}")

        try:
            result = self._make_request("GET", "/wireguard/general/get")
            if result:
                wg = result.get("general", {})
                vpn["wireguard"]["enabled"] = wg.get("enabled", "0")
        except Exception as e:
            logger.debug(f"WireGuard general: {e}")

        try:
            vpn["wireguard"]["peers"] = self._search_all("/wireguard/client/search_client")
        except Exception as e:
            logger.debug(f"WireGuard peers: {e}")

        try:
            vpn["wireguard"]["servers"] = self._search_all("/wireguard/server/search_server")
        except Exception as e:
            logger.debug(f"WireGuard servers: {e}")

        return vpn

    def get_certificates(self) -> list[dict]:
        try:
            return self._search_all("/trust/cert/search")
        except Exception as e:
            logger.debug(f"Failed to get certificates: {e}")
            return []

    def get_firewall_settings(self) -> dict:
        try:
            result = self._make_request("GET", "/firewall/filter/get")
            return result.get("filter", result) if isinstance(result, dict) else {}
        except Exception as e:
            logger.debug(f"Failed to get firewall settings: {e}")
            return {}

    def add_firewall_rule(self, rule_payload: dict) -> dict:
        try:
            return self._make_request("POST", "/firewall/filter/add_rule", data=rule_payload)
        except Exception as e:
            logger.error(f"add_rule failed: {e}")
            raise

    def delete_firewall_rule(self, uuid: str) -> dict:
        try:
            return self._make_request("POST", f"/firewall/filter/del_rule/{uuid}")
        except Exception as e:
            logger.error(f"del_rule failed: {e}")
            raise

    def apply_firewall_changes(self) -> dict:
        try:
            return self._make_request("POST", "/firewall/filter/apply")
        except Exception as e:
            logger.error(f"apply failed: {e}")
            raise

    def get_kea_dhcpv4_settings(self) -> dict:
        try:
            result = self._make_request("GET", "/kea/dhcpv4/get")
            return result.get("dhcpv4", result) if isinstance(result, dict) else {}
        except Exception as e:
            logger.debug(f"Kea v4 settings: {e}")
            return {}

    def get_kea_dhcpv6_settings(self) -> dict:
        try:
            result = self._make_request("GET", "/kea/dhcpv6/get")
            return result.get("dhcpv6", result) if isinstance(result, dict) else {}
        except Exception as e:
            logger.debug(f"Kea v6 settings: {e}")
            return {}

    def get_kea_dhcpv6_subnets(self) -> list[dict]:
        try:
            return self._search_all("/kea/dhcpv6/searchSubnet")
        except Exception as e:
            logger.debug(f"Kea v6 subnets: {e}")
            return []

    def get_kea_dhcpv4_subnets(self) -> list[dict]:
        try:
            return self._search_all("/kea/dhcpv4/searchSubnet")
        except Exception as e:
            logger.debug(f"Kea v4 subnets: {e}")
            return []

    def get_kea_dhcpv6_leases(self) -> list[dict]:
        try:
            return self._search_all("/kea/leases6/search")
        except Exception as e:
            logger.debug(f"Kea v6 leases: {e}")
            return []

    def get_radvd_entries(self) -> list[dict]:
        try:
            return self._search_all("/radvd/settings/searchEntry")
        except Exception as e:
            logger.debug(f"Radvd search: {e}")
            return []

    def get_radvd_settings(self) -> dict:
        try:
            result = self._make_request("GET", "/radvd/settings/get")
            return result.get("radvd", result) if isinstance(result, dict) else {}
        except Exception as e:
            logger.debug(f"Radvd settings: {e}")
            return {}

    def get_gateway_settings(self) -> list[dict]:
        try:
            return self._search_all("/routing/settings/searchGateway")
        except Exception as e:
            logger.debug(f"Routing gateways: {e}")
            return []

    def get_interfaces_info(self) -> list[dict]:
        try:
            result = self._make_request("GET", "/interfaces/overview/interfacesInfo")
            if isinstance(result, dict):
                return result.get("rows", []) or []
            return []
        except Exception as e:
            logger.debug(f"Interfaces info: {e}")
            return []
