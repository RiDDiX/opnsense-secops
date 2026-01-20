"""
System Security Analyzer
Analyzes OPNsense system security settings
"""
import logging
from typing import Dict, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SystemSecurityFinding:
    severity: str
    category: str
    check: str
    issue: str
    reason: str
    solution: str
    details: Dict
    opnsense_path: str = ""


class SystemSecurityAnalyzer:
    """Analyzes OPNsense system security configuration"""

    def __init__(self, rules_config: Dict, exceptions: List[Dict]):
        self.rules_config = rules_config
        self.exceptions = exceptions

    def analyze(self, system_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze system security configuration"""
        findings = []

        findings.extend(self._analyze_ssh_config(system_config.get("ssh", {})))
        findings.extend(self._analyze_admin_interface(system_config.get("webgui", {})))
        findings.extend(self._analyze_ids_config(system_config.get("ids", {})))
        findings.extend(self._analyze_update_config(system_config.get("firmware", {})))
        findings.extend(self._analyze_general_settings(system_config.get("general", {})))
        findings.extend(self._analyze_authentication(system_config.get("auth", {})))
        findings.extend(self._analyze_vpn_config(system_config.get("vpn", {})))
        findings.extend(self._analyze_logging_config(system_config.get("logging", {})))
        findings.extend(self._analyze_cron_backup(system_config.get("cron", {})))
        findings.extend(self._analyze_captive_portal(system_config.get("captiveportal", {})))

        return findings

    def _analyze_ssh_config(self, ssh_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze SSH configuration"""
        findings = []

        if not ssh_config:
            return findings

        ssh_enabled = ssh_config.get("enabled", "0") == "1"

        if ssh_enabled:
            root_login = ssh_config.get("permitrootlogin", "0") == "1"
            if root_login:
                findings.append(SystemSecurityFinding(
                    severity="HIGH",
                    category="SSH",
                    check="ssh_root_login",
                    issue="SSH Root-Login aktiviert",
                    reason="Direkter Root-Zugang ist ein Sicherheitsrisiko",
                    solution="Deaktiviere Root-Login, nutze sudo",
                    details={"current": "enabled"},
                    opnsense_path="System > Settings > Administration > Secure Shell"
                ))

            password_auth = ssh_config.get("passwordauth", "0") == "1"
            if password_auth:
                findings.append(SystemSecurityFinding(
                    severity="MEDIUM",
                    category="SSH",
                    check="ssh_password_auth",
                    issue="SSH Passwort-Authentifizierung aktiviert",
                    reason="Key-basierte Auth ist sicherer als Passwörter",
                    solution="Nutze SSH-Keys und deaktiviere Passwort-Auth",
                    details={"current": "password"},
                    opnsense_path="System > Settings > Administration > Secure Shell"
                ))

            ssh_port = ssh_config.get("port", "22")
            if ssh_port == "22":
                findings.append(SystemSecurityFinding(
                    severity="LOW",
                    category="SSH",
                    check="ssh_default_port",
                    issue="SSH auf Standard-Port 22",
                    reason="Nicht-Standard-Port reduziert automatisierte Angriffe",
                    solution="Port auf z.B. 2222 ändern",
                    details={"current_port": 22},
                    opnsense_path="System > Settings > Administration > Secure Shell"
                ))

            ssh_interfaces = ssh_config.get("interfaces", [])
            if not ssh_interfaces or "wan" in str(ssh_interfaces).lower():
                findings.append(SystemSecurityFinding(
                    severity="CRITICAL",
                    category="SSH",
                    check="ssh_wan_access",
                    issue="SSH möglicherweise von WAN erreichbar",
                    reason="SSH darf nie direkt aus dem Internet erreichbar sein",
                    solution="SSH nur auf LAN/Management beschränken",
                    details={"interfaces": ssh_interfaces},
                    opnsense_path="System > Settings > Administration > Secure Shell"
                ))

        return findings

    def _analyze_admin_interface(self, webgui_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze web admin interface configuration"""
        findings = []

        if not webgui_config:
            return findings

        # Check HTTPS enforcement
        protocol = webgui_config.get("protocol", "https")
        if protocol != "https":
            findings.append(SystemSecurityFinding(
                severity="CRITICAL",
                category="Admin Interface",
                check="webgui_https",
                issue="Web interface not using HTTPS",
                reason="Admin credentials can be intercepted without encryption",
                solution="Enable HTTPS in System > Settings > Administration",
                details={"current": protocol, "recommended": "https"}
            ))

        # Check HTTPS redirect
        https_redirect = webgui_config.get("httpsredirect", "0") == "1"
        if not https_redirect and protocol == "https":
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Admin Interface",
                check="webgui_redirect",
                issue="HTTP to HTTPS redirect not enabled",
                reason="Users might accidentally access admin via HTTP",
                solution="Enable 'Redirect HTTP to HTTPS' in admin settings",
                details={"current": "disabled", "recommended": "enabled"}
            ))

        # Check default port
        port = webgui_config.get("port", "443")
        if port in ["80", "443"]:
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="Admin Interface",
                check="webgui_default_port",
                issue=f"Admin interface on standard port {port}",
                reason="Non-standard ports reduce automated attack surface",
                solution="Consider using a non-standard port for admin interface",
                details={"current_port": port}
            ))

        # Check session timeout
        session_timeout = int(webgui_config.get("session_timeout", "240"))
        if session_timeout > 30:
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="Admin Interface",
                check="webgui_session_timeout",
                issue=f"Long session timeout ({session_timeout} minutes)",
                reason="Long sessions increase risk of session hijacking",
                solution="Reduce session timeout to 15-30 minutes",
                details={"current": session_timeout, "recommended": "15-30 minutes"}
            ))

        # Check if accessible from WAN
        interfaces = webgui_config.get("interfaces", [])
        if "wan" in str(interfaces).lower():
            findings.append(SystemSecurityFinding(
                severity="CRITICAL",
                category="Admin Interface",
                check="webgui_wan_access",
                issue="Admin interface accessible from WAN",
                reason="Admin interface should never be exposed to internet",
                solution="Remove WAN from allowed interfaces, use VPN for remote access",
                details={"interfaces": interfaces}
            ))

        # Check HSTS
        hsts_enabled = webgui_config.get("hsts", "0") == "1"
        if not hsts_enabled:
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Admin Interface",
                check="webgui_hsts",
                issue="HTTP Strict Transport Security (HSTS) not enabled",
                reason="HSTS prevents protocol downgrade attacks",
                solution="Enable HSTS in System > Settings > Administration",
                details={"current": "disabled", "recommended": "enabled"}
            ))

        return findings

    def _analyze_ids_config(self, ids_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze Intrusion Detection System configuration"""
        findings = []

        # Check if IDS is enabled
        ids_enabled = ids_config.get("enabled", "0") == "1"

        if not ids_enabled:
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="IDS/IPS",
                check="ids_enabled",
                issue="Intrusion Detection System is not enabled",
                reason="IDS provides additional layer of security by detecting attacks",
                solution="Enable Suricata IDS in Services > Intrusion Detection",
                details={"current": "disabled", "recommended": "enabled"}
            ))
        else:
            # Check IDS mode (IDS vs IPS)
            ips_mode = ids_config.get("ips_mode", "0") == "1"
            if not ips_mode:
                findings.append(SystemSecurityFinding(
                    severity="LOW",
                    category="IDS/IPS",
                    check="ids_ips_mode",
                    issue="IDS running in detection mode only",
                    reason="IPS mode can actively block detected threats",
                    solution="Consider enabling IPS mode for active blocking",
                    details={"current": "IDS", "recommended": "IPS"}
                ))

            # Check if rules are updated
            rule_update = ids_config.get("auto_update", "0") == "1"
            if not rule_update:
                findings.append(SystemSecurityFinding(
                    severity="MEDIUM",
                    category="IDS/IPS",
                    check="ids_rule_updates",
                    issue="Automatic rule updates not enabled",
                    reason="Outdated rules may miss new threats",
                    solution="Enable automatic rule updates in IDS settings",
                    details={"current": "manual", "recommended": "automatic"}
                ))

        return findings

    def _analyze_update_config(self, firmware_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze firmware/update configuration"""
        findings = []

        # Check for pending updates
        updates_available = firmware_config.get("updates_available", False)
        if updates_available:
            findings.append(SystemSecurityFinding(
                severity="HIGH",
                category="Updates",
                check="firmware_updates_pending",
                issue="Firmware updates are available",
                reason="Security patches may be pending installation",
                solution="Apply updates via System > Firmware > Updates",
                details={"updates_available": True}
            ))

        # Check last update
        last_update = firmware_config.get("last_update", "")
        if not last_update:
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Updates",
                check="firmware_last_update",
                issue="Unable to determine last update date",
                reason="Regular updates are critical for security",
                solution="Check and apply updates regularly",
                details={"last_update": "unknown"}
            ))

        return findings

    def _analyze_general_settings(self, general_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze general system settings"""
        findings = []

        # Check NTP configuration
        ntp_servers = general_config.get("ntp_servers", [])
        if not ntp_servers:
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="System",
                check="ntp_configured",
                issue="No NTP servers configured",
                reason="Accurate time is important for logging and certificates",
                solution="Configure NTP servers in System > Settings > General",
                details={"ntp_servers": ntp_servers}
            ))

        # Check console access
        console_menu = general_config.get("console_menu", "1") == "1"
        if console_menu:
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="System",
                check="console_menu",
                issue="Console menu is enabled",
                reason="Physical console access could be restricted for security",
                solution="Consider disabling console menu if physical security is a concern",
                details={"current": "enabled"}
            ))

        return findings

    def _analyze_authentication(self, auth_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze authentication settings"""
        findings = []

        if not auth_config:
            return findings

        # Check for 2FA
        totp_enabled = auth_config.get("totp_enabled", "0") == "1"
        if not totp_enabled:
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Authentication",
                check="auth_2fa",
                issue="Two-factor authentication not enabled",
                reason="2FA provides additional protection for admin access",
                solution="Enable TOTP in System > Access > Users",
                details={"current": "disabled", "recommended": "enabled"}
            ))

        # Check lockout policy
        lockout_threshold = auth_config.get("lockout_threshold", 0)
        if lockout_threshold == 0 or lockout_threshold > 5:
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Authentication",
                check="auth_lockout",
                issue="Weak or no account lockout policy",
                reason="Lockout prevents brute force attacks",
                solution="Configure account lockout after 3-5 failed attempts",
                details={"current_threshold": lockout_threshold, "recommended": "3-5"}
            ))

        return findings

    def _analyze_vpn_config(self, vpn_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze VPN configuration"""
        findings = []
        
        if not vpn_config:
            return findings
        
        # OpenVPN checks
        openvpn = vpn_config.get("openvpn", {})
        for server in openvpn.get("servers", []):
            # Check cipher strength
            cipher = server.get("cipher", "")
            weak_ciphers = ["DES", "RC4", "BF-CBC", "CAST5"]
            if any(weak in cipher.upper() for weak in weak_ciphers):
                findings.append(SystemSecurityFinding(
                    severity="HIGH",
                    category="VPN",
                    check="vpn_weak_cipher",
                    issue=f"OpenVPN Server nutzt schwache Verschlüsselung: {cipher}",
                    reason="Schwache Cipher sind anfällig für Angriffe",
                    solution="Nutze AES-256-GCM oder CHACHA20-POLY1305",
                    details={"cipher": cipher},
                    opnsense_path="VPN > OpenVPN > Servers"
                ))
            
            # Check auth digest
            auth = server.get("auth", "")
            if auth.upper() in ["MD5", "SHA1"]:
                findings.append(SystemSecurityFinding(
                    severity="MEDIUM",
                    category="VPN",
                    check="vpn_weak_auth",
                    issue=f"OpenVPN nutzt schwachen Hash-Algorithmus: {auth}",
                    reason="MD5/SHA1 sind veraltet und unsicher",
                    solution="Nutze SHA256 oder SHA512",
                    details={"auth": auth},
                    opnsense_path="VPN > OpenVPN > Servers"
                ))
            
            # Check TLS auth
            tls_auth = server.get("tls_auth", "0") == "1"
            if not tls_auth:
                findings.append(SystemSecurityFinding(
                    severity="MEDIUM",
                    category="VPN",
                    check="vpn_no_tls_auth",
                    issue="OpenVPN TLS-Auth nicht aktiviert",
                    reason="TLS-Auth schützt vor DoS und unauthorized scanning",
                    solution="Aktiviere TLS Authentication",
                    details={"tls_auth": "disabled"},
                    opnsense_path="VPN > OpenVPN > Servers > Cryptographic Settings"
                ))
        
        # IPsec checks
        ipsec = vpn_config.get("ipsec", {})
        if ipsec.get("enabled", "0") == "1":
            # Check Phase 1 proposals
            for p1 in ipsec.get("phase1", []):
                enc = p1.get("encryption", "")
                if "3des" in enc.lower() or "des" in enc.lower():
                    findings.append(SystemSecurityFinding(
                        severity="HIGH",
                        category="VPN",
                        check="ipsec_weak_enc",
                        issue="IPsec Phase 1 nutzt schwache Verschlüsselung",
                        reason="DES/3DES sind veraltet",
                        solution="Nutze AES-256",
                        details={"encryption": enc},
                        opnsense_path="VPN > IPsec > Tunnel Settings"
                    ))
        
        # WireGuard checks
        wireguard = vpn_config.get("wireguard", {})
        if wireguard.get("enabled", "0") == "1":
            for peer in wireguard.get("peers", []):
                # Check if keepalive is set for NAT traversal
                keepalive = peer.get("keepalive", 0)
                if not keepalive:
                    findings.append(SystemSecurityFinding(
                        severity="LOW",
                        category="VPN",
                        check="wg_no_keepalive",
                        issue="WireGuard Peer ohne Keepalive",
                        reason="Keepalive hilft bei NAT-Traversal",
                        solution="Setze Persistent Keepalive auf 25 Sekunden",
                        details={"peer": peer.get("name", "unknown")},
                        opnsense_path="VPN > WireGuard > Peers"
                    ))
        
        return findings

    def _analyze_logging_config(self, logging_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze logging configuration"""
        findings = []
        
        if not logging_config:
            # No logging config means defaults
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Logging",
                check="logging_not_configured",
                issue="Logging nicht explizit konfiguriert",
                reason="Logs sind essentiell für Security Monitoring",
                solution="Konfiguriere Logging-Einstellungen",
                details={},
                opnsense_path="System > Settings > Logging"
            ))
            return findings
        
        # Check remote syslog
        remote_syslog = logging_config.get("remote_syslog", {})
        if not remote_syslog.get("enabled", False):
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="Logging",
                check="no_remote_syslog",
                issue="Kein Remote-Syslog konfiguriert",
                reason="Remote-Logging schützt Logs vor lokaler Manipulation",
                solution="Konfiguriere Remote-Syslog-Server",
                details={},
                opnsense_path="System > Settings > Logging > Remote"
            ))
        
        # Check log retention
        preserve_logs = logging_config.get("preserve_logs", 7)
        if preserve_logs < 30:
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="Logging",
                check="short_log_retention",
                issue=f"Log-Aufbewahrung nur {preserve_logs} Tage",
                reason="Längere Aufbewahrung ermöglicht forensische Analyse",
                solution="Erhöhe Log-Retention auf mindestens 30 Tage",
                details={"current_days": preserve_logs},
                opnsense_path="System > Settings > Logging"
            ))
        
        # Check firewall logging
        fw_log = logging_config.get("firewall", {})
        if not fw_log.get("log_default_block", True):
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Logging",
                check="no_default_block_logging",
                issue="Default-Block-Regel ohne Logging",
                reason="Blockierte Verbindungen sollten geloggt werden",
                solution="Aktiviere Logging für Default-Block",
                details={},
                opnsense_path="Firewall > Settings > Advanced"
            ))
        
        return findings

    def _analyze_cron_backup(self, cron_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze backup and cron configuration"""
        findings = []
        
        # Check for config backup
        backup = cron_config.get("backup", {})
        if not backup.get("enabled", False):
            findings.append(SystemSecurityFinding(
                severity="HIGH",
                category="Backup",
                check="no_auto_backup",
                issue="Kein automatisches Config-Backup konfiguriert",
                reason="Ohne Backup kann Config-Verlust zum Problem werden",
                solution="Konfiguriere automatisches Backup",
                details={},
                opnsense_path="System > Configuration > Backups"
            ))
        
        # Check backup encryption
        if backup.get("enabled", False) and not backup.get("encrypted", False):
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Backup",
                check="backup_not_encrypted",
                issue="Config-Backup nicht verschlüsselt",
                reason="Backup enthält sensible Daten wie Passwörter",
                solution="Aktiviere Backup-Verschlüsselung",
                details={},
                opnsense_path="System > Configuration > Backups"
            ))
        
        return findings

    def _analyze_captive_portal(self, cp_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze Captive Portal configuration"""
        findings = []
        
        if not cp_config or not cp_config.get("enabled", False):
            return findings
        
        # Check HTTPS
        if not cp_config.get("https", False):
            findings.append(SystemSecurityFinding(
                severity="HIGH",
                category="Captive Portal",
                check="cp_no_https",
                issue="Captive Portal ohne HTTPS",
                reason="Login-Daten werden unverschlüsselt übertragen",
                solution="Aktiviere HTTPS für Captive Portal",
                details={},
                opnsense_path="Services > Captive Portal"
            ))
        
        # Check session timeout
        timeout = cp_config.get("timeout", 0)
        if timeout == 0 or timeout > 480:
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="Captive Portal",
                check="cp_long_timeout",
                issue="Captive Portal Session-Timeout zu lang oder unbegrenzt",
                reason="Lange Sessions erhöhen Missbrauchsrisiko",
                solution="Setze angemessenes Timeout (z.B. 4 Stunden)",
                details={"timeout": timeout},
                opnsense_path="Services > Captive Portal"
            ))
        
        return findings

    def get_optimal_system_config(self) -> Dict:
        """Return optimal system security configuration"""
        return {
            "ssh_settings": {
                "enabled": "Only if necessary",
                "root_login": "Disabled",
                "password_auth": "Disabled (use keys)",
                "port": "Non-standard (e.g., 2222)",
                "interfaces": "LAN/Management only",
                "key_type": "Ed25519 or RSA-4096"
            },
            "admin_interface": {
                "protocol": "HTTPS only",
                "port": "Non-standard (e.g., 8443)",
                "interfaces": "LAN/Management only",
                "hsts": "Enabled",
                "session_timeout": "15-30 minutes",
                "https_redirect": "Enabled"
            },
            "ids_ips": {
                "enabled": "Yes",
                "mode": "IPS (active blocking)",
                "rule_updates": "Automatic",
                "rulesets": "ET Open, Abuse.ch, Feodo Tracker"
            },
            "authentication": {
                "2fa": "Enabled (TOTP)",
                "lockout_threshold": "3-5 attempts",
                "lockout_duration": "15-30 minutes",
                "password_policy": "Strong passwords required"
            },
            "updates": {
                "frequency": "Check weekly",
                "auto_check": "Enabled",
                "backup_before_update": "Always"
            },
            "logging": {
                "syslog": "Enabled",
                "remote_logging": "Recommended",
                "log_firewall": "Block rules",
                "retention": "30+ days"
            }
        }
