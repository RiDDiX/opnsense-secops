"""
Network Discovery
Discovers and maps all devices in the network
"""
import ipaddress
import logging
import socket
from collections import defaultdict
from dataclasses import dataclass

import nmap

logger = logging.getLogger(__name__)


@dataclass
class NetworkDevice:
    """Represents a discovered network device"""
    ip: str
    mac: str
    hostname: str
    vendor: str
    network: str
    vlan: str
    status: str
    open_ports: list[int]
    services: dict[int, str]
    os_guess: str
    last_seen: str


class NetworkDiscovery:
    """Discovers and analyzes network devices"""

    def __init__(self, scan_options: dict):
        self.scan_options = scan_options
        self.nm = nmap.PortScanner()

    @staticmethod
    def _extract_field(entry: dict, keys: tuple) -> str:
        """Extract a value from a dict trying multiple possible field names"""
        for key in keys:
            val = entry.get(key, '')
            if val and str(val) not in ('', '--', '(incomplete)', 'incomplete', 'Unknown', '?', '*'):
                return str(val)
        return ''

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if an IP address is private (RFC1918/RFC4193)"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private and not ip.is_loopback and not ip.is_link_local
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _resolve_hostname(ip_str: str, timeout: float = 1.0) -> str:
        """Resolve hostname via reverse DNS lookup"""
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_str)
                return hostname
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (TimeoutError, socket.herror, socket.gaierror, OSError):
            return ""

    def discover_network(self, networks: list[str], dhcp_leases: list[dict],
                        arp_table: list[dict], vlans: list[dict]) -> list[NetworkDevice]:
        """Discover all devices in specified networks (private IPs only)"""
        devices = []

        # Combine data from different sources
        device_map = defaultdict(dict)

        # Add data from DHCP leases (only private IPs)
        for lease in dhcp_leases:
            ip = self._extract_field(lease, ("address", "ip", "ip-address", "ip_address", "ipaddr"))
            if ip and self._is_private_ip(ip):
                mac = self._extract_field(lease, ("mac", "hwaddr", "hw_address", "hw-address", "hwaddress", "mac_address"))
                hostname = self._extract_field(lease, ("hostname", "name", "client-hostname", "client_hostname", "client_name"))
                device_map[ip].update({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "status": "active" if lease.get("state", lease.get("binding_state", "")) in ("active", "Active") else "inactive"
                })

        # Add data from ARP table (only private IPs)
        for arp_entry in arp_table:
            ip = self._extract_field(arp_entry, ("ip", "ip-address", "address", "ip_address"))
            if ip and self._is_private_ip(ip):
                mac = self._extract_field(arp_entry, ("mac", "hwaddr", "hw_address", "hw-address", "mac_address"))
                if ip not in device_map:
                    device_map[ip] = {"ip": ip}
                if mac:
                    device_map[ip]["mac"] = mac
                elif not device_map[ip].get("mac"):
                    device_map[ip]["mac"] = ""
                if not device_map[ip].get("vendor"):
                    device_map[ip]["vendor"] = ""
                device_map[ip]["status"] = "active"
                # ARP hostname (some OPNsense versions include it)
                arp_hostname = self._extract_field(arp_entry, ("hostname", "name", "host"))
                if arp_hostname and not device_map[ip].get("hostname"):
                    device_map[ip]["hostname"] = arp_hostname

        # Perform active network discovery
        for network in networks:
            logger.info(f"Discovering devices in {network}")
            discovered = self._scan_network(network)

            for device_info in discovered:
                ip = device_info["ip"]
                if ip not in device_map:
                    device_map[ip] = device_info
                else:
                    device_map[ip].update(device_info)

        # Assign VLANs and resolve hostnames for devices
        for ip, device_info in device_map.items():
            vlan = self._determine_vlan(ip, vlans)
            device_info["vlan"] = vlan
            device_info["network"] = self._determine_network(ip, networks)

            # Resolve hostname if not already known
            current_hostname = device_info.get("hostname", "")
            if not current_hostname or current_hostname in ("Unknown", "", "--"):
                resolved = self._resolve_hostname(ip)
                if resolved:
                    device_info["hostname"] = resolved

        # Convert to NetworkDevice objects
        for ip, info in device_map.items():
            device = NetworkDevice(
                ip=info.get("ip", ip),
                mac=info.get("mac", "Unknown"),
                hostname=info.get("hostname", "") or "Unknown",
                vendor=info.get("vendor", "Unknown"),
                network=info.get("network", "Unknown"),
                vlan=info.get("vlan", "Unknown"),
                status=info.get("status", "unknown"),
                open_ports=info.get("open_ports", []),
                services=info.get("services", {}),
                os_guess=info.get("os_guess", "Unknown"),
                last_seen=info.get("last_seen", "Now")
            )
            devices.append(device)

        return devices

    def _scan_network(self, network: str) -> list[dict]:
        """Scan network for devices (only private IPs)"""
        devices = []

        try:
            logger.info(f"Scanning {network} for live hosts")

            # Default ping scan with multiple probes so non-ICMP hosts are still found.
            scan_args = '-sn -PE -PA80,443'
            if self.scan_options.get("skip_ping", False):
                scan_args = '-Pn -sS -p 22,80,443'

            self.nm.scan(hosts=network, arguments=scan_args)

            for host in self.nm.all_hosts():
                # Skip non-private IPs (public/ISP addresses)
                if not self._is_private_ip(host):
                    logger.debug(f"Skipping public IP {host}")
                    continue

                nmap_hostname = self._get_hostname(host)
                # Try reverse DNS if nmap didn't resolve
                if not nmap_hostname or nmap_hostname == "Unknown":
                    nmap_hostname = self._resolve_hostname(host) or "Unknown"

                device_info = {
                    "ip": host,
                    "status": self.nm[host].state(),
                    "hostname": nmap_hostname,
                    "mac": self._get_mac(host),
                    "vendor": self._get_vendor(host),
                    "os_guess": self._get_os_guess(host),
                    "open_ports": [],
                    "services": {}
                }

                # If we did a port scan, add port info
                if 'tcp' in self.nm[host]:
                    for port in self.nm[host]['tcp'].keys():
                        if self.nm[host]['tcp'][port]['state'] == 'open':
                            device_info["open_ports"].append(port)
                            device_info["services"][port] = self.nm[host]['tcp'][port].get('name', 'unknown')

                devices.append(device_info)

        except Exception as e:
            logger.error(f"Error scanning network {network}: {e}")

        return devices

    def _get_hostname(self, host: str) -> str:
        """Get hostname from scan results"""
        try:
            if 'hostnames' in self.nm[host] and self.nm[host]['hostnames']:
                for hostname_entry in self.nm[host]['hostnames']:
                    if hostname_entry.get('name'):
                        return hostname_entry['name']
        except Exception:
            pass
        return "Unknown"

    def _get_mac(self, host: str) -> str:
        """Get MAC address from scan results"""
        try:
            if 'addresses' in self.nm[host] and 'mac' in self.nm[host]['addresses']:
                return self.nm[host]['addresses']['mac']
        except Exception:
            pass
        return "Unknown"

    def _get_vendor(self, host: str) -> str:
        """Get vendor from scan results"""
        try:
            if 'vendor' in self.nm[host] and self.nm[host]['vendor']:
                mac = self._get_mac(host)
                if mac in self.nm[host]['vendor']:
                    return self.nm[host]['vendor'][mac]
        except Exception:
            pass
        return "Unknown"

    def _get_os_guess(self, host: str) -> str:
        """Get OS guess from scan results"""
        try:
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                return self.nm[host]['osmatch'][0].get('name', 'Unknown')
        except Exception:
            pass
        return "Unknown"

    def _lookup_vendor(self, mac: str) -> str:
        """Vendor lookup happens via nmap MAC database during scan."""
        return ""

    def _determine_vlan(self, ip: str, vlans: list[dict]) -> str:
        """Match an IP to a VLAN by subnet, when the VLAN entry carries one."""
        if not ip or not vlans:
            return "Unknown"
        try:
            ip_obj = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return "Unknown"

        for vlan in vlans:
            subnet = vlan.get("subnet") or vlan.get("network") or ""
            if not subnet:
                continue
            try:
                if ip_obj in ipaddress.ip_network(subnet, strict=False):
                    tag = vlan.get("tag", "")
                    return f"{vlan.get('descr', f'VLAN {tag}')} (VLAN {tag})"
            except (ValueError, TypeError):
                continue
        return "Unknown"

    def _determine_network(self, ip: str, networks: list[str]) -> str:
        """Determine which network an IP belongs to"""
        try:
            ip_obj = ipaddress.ip_address(ip)

            for network_str in networks:
                network = ipaddress.ip_network(network_str, strict=False)
                if ip_obj in network:
                    return network_str

        except Exception:
            pass

        return "Unknown"

    def generate_network_map(self, devices: list[NetworkDevice]) -> dict:
        """Generate network topology map"""
        network_map = defaultdict(lambda: defaultdict(list))

        for device in devices:
            network = device.network
            vlan = device.vlan

            network_map[network][vlan].append({
                "ip": device.ip,
                "hostname": device.hostname,
                "mac": device.mac,
                "vendor": device.vendor,
                "status": device.status,
                "open_ports": device.open_ports
            })

        return dict(network_map)

    def get_device_statistics(self, devices: list[NetworkDevice]) -> dict:
        """Get statistics about discovered devices"""
        stats = {
            "total_devices": len(devices),
            "active_devices": len([d for d in devices if d.status == "active"]),
            "devices_by_network": defaultdict(int),
            "devices_by_vlan": defaultdict(int),
            "devices_by_vendor": defaultdict(int),
            "total_open_ports": sum(len(d.open_ports) for d in devices),
            "unique_services": set()
        }

        for device in devices:
            stats["devices_by_network"][device.network] += 1
            stats["devices_by_vlan"][device.vlan] += 1
            if device.vendor != "Unknown":
                stats["devices_by_vendor"][device.vendor] += 1

            for service in device.services.values():
                stats["unique_services"].add(service)

        # Convert non-serializable types for JSON
        stats["unique_services"] = list(stats["unique_services"])
        stats["devices_by_network"] = dict(stats["devices_by_network"])
        stats["devices_by_vlan"] = dict(stats["devices_by_vlan"])
        stats["devices_by_vendor"] = dict(stats["devices_by_vendor"])

        return stats
