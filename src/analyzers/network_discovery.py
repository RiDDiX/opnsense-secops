"""
Network Discovery
Discovers and maps all devices in the network
"""
import logging
import nmap
import socket
from typing import Dict, List, Set
from dataclasses import dataclass
from collections import defaultdict
import ipaddress

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
    open_ports: List[int]
    services: Dict[int, str]
    os_guess: str
    last_seen: str


class NetworkDiscovery:
    """Discovers and analyzes network devices"""

    def __init__(self, scan_options: Dict):
        self.scan_options = scan_options
        self.nm = nmap.PortScanner()

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
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return ""

    def discover_network(self, networks: List[str], dhcp_leases: List[Dict],
                        arp_table: List[Dict], vlans: List[Dict]) -> List[NetworkDevice]:
        """Discover all devices in specified networks (private IPs only)"""
        devices = []

        # Combine data from different sources
        device_map = defaultdict(dict)

        # Add data from DHCP leases (only private IPs)
        for lease in dhcp_leases:
            ip = lease.get("address", lease.get("ip", ""))
            if ip and self._is_private_ip(ip):
                device_map[ip].update({
                    "ip": ip,
                    "mac": lease.get("mac", ""),
                    "hostname": lease.get("hostname", ""),
                    "status": "active" if lease.get("state") == "active" else "inactive"
                })

        # Add data from ARP table (only private IPs)
        for arp_entry in arp_table:
            ip = arp_entry.get("ip", "")
            if ip and self._is_private_ip(ip):
                if ip not in device_map:
                    device_map[ip] = {"ip": ip}
                device_map[ip].update({
                    "mac": arp_entry.get("mac", device_map[ip].get("mac", "")),
                    "vendor": self._lookup_vendor(arp_entry.get("mac", "")),
                    "status": "active"
                })

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

    def _scan_network(self, network: str) -> List[Dict]:
        """Scan network for devices (only private IPs)"""
        devices = []

        try:
            # Quick host discovery
            logger.info(f"Scanning {network} for live hosts")

            scan_args = '-sn'  # Ping scan only
            if self.scan_options.get("skip_ping", False):
                scan_args = '-Pn -sS -p 22,80,443'  # Assume host is up, scan common ports

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
        """Lookup vendor from MAC address"""
        # This would need a MAC vendor database
        # For now, return Unknown
        return "Unknown"

    def _determine_vlan(self, ip: str, vlans: List[Dict]) -> str:
        """Determine which VLAN an IP belongs to"""
        try:
            ip_obj = ipaddress.ip_address(ip)

            # Match IP to VLAN based on subnet
            # This is simplified - in reality you'd need subnet info from VLANs
            for vlan in vlans:
                vlan_tag = vlan.get("tag", "")
                vlan_desc = vlan.get("descr", f"VLAN {vlan_tag}")
                # You would match against VLAN subnet here
                # For now, return description
                return f"{vlan_desc} (VLAN {vlan_tag})"

        except Exception:
            pass

        return "Unknown"

    def _determine_network(self, ip: str, networks: List[str]) -> str:
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

    def generate_network_map(self, devices: List[NetworkDevice]) -> Dict:
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

    def get_device_statistics(self, devices: List[NetworkDevice]) -> Dict:
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
