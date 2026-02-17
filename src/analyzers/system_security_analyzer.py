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
    current_value: str = ""
    recommended_value: str = ""
    implementation_steps: list = None


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
                    reason="Direkter Root-Zugang über SSH ermöglicht Angreifern bei kompromittierten Credentials vollen Systemzugriff ohne Audit-Trail",
                    solution="Root-Login deaktivieren und dedizierten Admin-User mit sudo-Rechten verwenden",
                    details={"permitrootlogin": "1"},
                    opnsense_path="System > Settings > Administration > Secure Shell",
                    current_value="Root-Login: Erlaubt",
                    recommended_value="Root-Login: Deaktiviert",
                    implementation_steps=[
                        "System > Settings > Administration öffnen",
                        "Im Bereich 'Secure Shell' die Option 'Permit root user login' deaktivieren",
                        "Sicherstellen, dass ein Admin-User mit sudo existiert",
                        "Speichern und SSH-Verbindung mit neuem User testen"
                    ]
                ))

            password_auth = ssh_config.get("passwordauth", "0") == "1"
            if password_auth:
                findings.append(SystemSecurityFinding(
                    severity="MEDIUM",
                    category="SSH",
                    check="ssh_password_auth",
                    issue="SSH Passwort-Authentifizierung aktiviert",
                    reason="Passwörter sind anfällig für Brute-Force-Angriffe. Key-basierte Authentifizierung ist deutlich sicherer",
                    solution="SSH-Keys einrichten und Passwort-Authentifizierung deaktivieren",
                    details={"passwordauth": "1"},
                    opnsense_path="System > Settings > Administration > Secure Shell",
                    current_value="Passwort-Auth: Aktiviert",
                    recommended_value="Passwort-Auth: Deaktiviert (nur SSH-Keys)",
                    implementation_steps=[
                        "SSH-Key-Paar generieren: ssh-keygen -t ed25519",
                        "Public Key unter System > Access > Users > [User] > Authorized keys einfügen",
                        "SSH-Verbindung mit Key testen",
                        "Erst dann: System > Settings > Administration > 'Permit password login' deaktivieren"
                    ]
                ))

            ssh_port = ssh_config.get("port", "22")
            if str(ssh_port) == "22":
                findings.append(SystemSecurityFinding(
                    severity="LOW",
                    category="SSH",
                    check="ssh_default_port",
                    issue="SSH auf Standard-Port 22",
                    reason="Port 22 wird von automatisierten Scannern und Bots gezielt angegriffen. Ein geänderter Port reduziert Rauschen in den Logs erheblich",
                    solution="SSH-Port auf nicht-standardisierten Port ändern (z.B. 2222, 8022)",
                    details={"port": ssh_port},
                    opnsense_path="System > Settings > Administration > Secure Shell",
                    current_value=f"SSH-Port: {ssh_port}",
                    recommended_value="SSH-Port: 2222 oder anderer nicht-standard Port",
                    implementation_steps=[
                        "System > Settings > Administration öffnen",
                        "Im Bereich 'Secure Shell' den Port auf z.B. 2222 ändern",
                        "Firewall-Regel für neuen Port anpassen",
                        "Speichern und mit ssh -p 2222 user@firewall testen"
                    ]
                ))

            ssh_interfaces = ssh_config.get("interfaces", [])
            iface_str = str(ssh_interfaces) if ssh_interfaces else "Alle (nicht eingeschränkt)"
            if not ssh_interfaces or "wan" in str(ssh_interfaces).lower():
                findings.append(SystemSecurityFinding(
                    severity="CRITICAL",
                    category="SSH",
                    check="ssh_wan_access",
                    issue="SSH von WAN erreichbar oder nicht auf Interface beschränkt",
                    reason="SSH aus dem Internet erreichbar macht die Firewall zum direkten Angriffsziel für Brute-Force und Exploit-Versuche",
                    solution="SSH ausschließlich auf LAN/Management-Interface beschränken. Für Remote-Zugriff VPN nutzen",
                    details={"interfaces": ssh_interfaces},
                    opnsense_path="System > Settings > Administration > Secure Shell",
                    current_value=f"Listen-Interfaces: {iface_str}",
                    recommended_value="Listen-Interfaces: Nur LAN / Management-VLAN",
                    implementation_steps=[
                        "System > Settings > Administration öffnen",
                        "Im Bereich 'Secure Shell' unter 'Listen Interfaces' nur LAN auswählen",
                        "WAN-Interface entfernen",
                        "Für Remote-Zugriff: VPN-Tunnel einrichten (WireGuard/OpenVPN)"
                    ]
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
                issue="WebGUI verwendet kein HTTPS",
                reason="Ohne HTTPS werden Admin-Zugangsdaten im Klartext übertragen und können im Netzwerk abgefangen werden",
                solution="HTTPS in System > Settings > Administration aktivieren",
                details={"protocol": protocol},
                opnsense_path="System > Settings > Administration > Web GUI",
                current_value=f"Protokoll: {protocol.upper()}",
                recommended_value="Protokoll: HTTPS",
                implementation_steps=[
                    "System > Settings > Administration öffnen",
                    "Protocol auf 'HTTPS' setzen",
                    "SSL-Zertifikat prüfen (idealerweise eigenes CA-Zertifikat)",
                    "Speichern — Achtung: URL ändert sich zu https://"
                ]
            ))

        # Check HTTPS redirect
        https_redirect = webgui_config.get("httpsredirect", "0") == "1"
        if not https_redirect and protocol == "https":
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Admin Interface",
                check="webgui_redirect",
                issue="HTTP-zu-HTTPS-Umleitung nicht aktiviert",
                reason="Ohne Redirect können Benutzer versehentlich unverschlüsselt auf das Admin-Interface zugreifen",
                solution="HTTP-zu-HTTPS-Redirect aktivieren",
                details={"httpsredirect": "0"},
                opnsense_path="System > Settings > Administration > Web GUI",
                current_value="HTTP→HTTPS Redirect: Deaktiviert",
                recommended_value="HTTP→HTTPS Redirect: Aktiviert",
                implementation_steps=[
                    "System > Settings > Administration öffnen",
                    "'HTTP Redirect' aktivieren",
                    "Speichern"
                ]
            ))

        # Check default port
        port = webgui_config.get("port", "443")
        if str(port) in ["80", "443", ""]:
            display_port = port if port else "443 (Standard)"
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="Admin Interface",
                check="webgui_default_port",
                issue=f"WebGUI auf Standard-Port {display_port}",
                reason="Standard-Ports werden von Scannern gezielt geprüft. Ein alternativer Port reduziert die Angriffsfläche",
                solution="WebGUI-Port auf nicht-standard Port ändern (z.B. 8443, 10443)",
                details={"port": port},
                opnsense_path="System > Settings > Administration > Web GUI",
                current_value=f"WebGUI-Port: {display_port}",
                recommended_value="WebGUI-Port: 8443 oder anderer nicht-standard Port",
                implementation_steps=[
                    "System > Settings > Administration öffnen",
                    "'TCP Port' auf z.B. 8443 ändern",
                    "Speichern — Achtung: URL ändert sich zu https://firewall:8443",
                    "Firewall-Regel prüfen/anpassen"
                ]
            ))

        # Check session timeout
        try:
            session_timeout = int(webgui_config.get("session_timeout", "240") or 240)
        except (ValueError, TypeError):
            session_timeout = 240
        if session_timeout > 30:
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="Admin Interface",
                check="webgui_session_timeout",
                issue=f"Langes Session-Timeout ({session_timeout} Minuten)",
                reason="Lange Sessions erhöhen das Risiko von Session-Hijacking bei unbeaufsichtigten Workstations",
                solution="Session-Timeout auf 15-30 Minuten reduzieren",
                details={"session_timeout": session_timeout},
                opnsense_path="System > Settings > Administration > Web GUI",
                current_value=f"Session-Timeout: {session_timeout} Minuten",
                recommended_value="Session-Timeout: 15-30 Minuten",
                implementation_steps=[
                    "System > Settings > Administration öffnen",
                    "'Session Timeout' auf 30 setzen (oder 15 für höhere Sicherheit)",
                    "Speichern"
                ]
            ))

        # Check if accessible from WAN
        interfaces = webgui_config.get("interfaces", [])
        iface_str = str(interfaces) if interfaces else "Alle (nicht eingeschränkt)"
        if "wan" in str(interfaces).lower():
            findings.append(SystemSecurityFinding(
                severity="CRITICAL",
                category="Admin Interface",
                check="webgui_wan_access",
                issue="WebGUI vom WAN erreichbar",
                reason="Das Admin-Interface aus dem Internet erreichbar zu machen ist eines der größten Sicherheitsrisiken. Angreifer können Brute-Force-Angriffe und bekannte Exploits nutzen",
                solution="WAN aus Listen-Interfaces entfernen und VPN für Remote-Zugriff nutzen",
                details={"interfaces": interfaces},
                opnsense_path="System > Settings > Administration > Web GUI",
                current_value=f"Listen-Interfaces: {iface_str}",
                recommended_value="Listen-Interfaces: Nur LAN / Management-VLAN",
                implementation_steps=[
                    "System > Settings > Administration öffnen",
                    "Unter 'Listen Interfaces' nur LAN/Management auswählen",
                    "WAN entfernen",
                    "VPN-Zugang für Remote-Administration einrichten"
                ]
            ))

        # Check HSTS
        hsts_enabled = webgui_config.get("hsts", "0") == "1"
        if not hsts_enabled:
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Admin Interface",
                check="webgui_hsts",
                issue="HTTP Strict Transport Security (HSTS) nicht aktiviert",
                reason="Ohne HSTS können Protocol-Downgrade-Angriffe (SSL-Stripping) die HTTPS-Verschlüsselung umgehen",
                solution="HSTS in den WebGUI-Einstellungen aktivieren",
                details={"hsts": "0"},
                opnsense_path="System > Settings > Administration > Web GUI",
                current_value="HSTS: Deaktiviert",
                recommended_value="HSTS: Aktiviert",
                implementation_steps=[
                    "System > Settings > Administration öffnen",
                    "'HTTP Strict Transport Security' aktivieren",
                    "Speichern"
                ]
            ))

        return findings

    def _analyze_ids_config(self, ids_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze Intrusion Detection System configuration"""
        findings = []

        ids_enabled = ids_config.get("enabled", "0") == "1"

        if not ids_enabled:
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="IDS/IPS",
                check="ids_enabled",
                issue="Intrusion Detection System (Suricata) nicht aktiviert",
                reason="Ohne IDS/IPS werden Angriffe wie Port-Scans, Exploit-Versuche und bekannte Malware-Kommunikation nicht erkannt",
                solution="Suricata IDS unter Services > Intrusion Detection aktivieren",
                details={"enabled": "0"},
                opnsense_path="Services > Intrusion Detection > Administration",
                current_value="IDS/IPS: Deaktiviert",
                recommended_value="IDS/IPS: Aktiviert (IPS-Modus)",
                implementation_steps=[
                    "Services > Intrusion Detection > Administration öffnen",
                    "'Enabled' aktivieren",
                    "'IPS mode' aktivieren für aktive Blockierung",
                    "Unter 'Download' Rulesets aktivieren (ET Open, Abuse.ch, Feodo)",
                    "'Schedule' für automatische Updates konfigurieren",
                    "Interfaces auswählen (mindestens WAN)",
                    "Speichern und Apply"
                ]
            ))
        else:
            ips_mode = ids_config.get("ips_mode", "0") == "1"
            if not ips_mode:
                findings.append(SystemSecurityFinding(
                    severity="LOW",
                    category="IDS/IPS",
                    check="ids_ips_mode",
                    issue="Suricata läuft nur im Erkennungsmodus (IDS)",
                    reason="Im IDS-Modus werden Bedrohungen nur protokolliert, aber nicht aktiv blockiert",
                    solution="IPS-Modus aktivieren für aktive Blockierung erkannter Angriffe",
                    details={"ips_mode": "0"},
                    opnsense_path="Services > Intrusion Detection > Administration",
                    current_value="Modus: IDS (nur Erkennung)",
                    recommended_value="Modus: IPS (Erkennung + Blockierung)",
                    implementation_steps=[
                        "Services > Intrusion Detection > Administration öffnen",
                        "'IPS mode' aktivieren",
                        "Speichern und Apply"
                    ]
                ))

            auto_update = ids_config.get("auto_update", "0")
            has_auto_update = auto_update not in ("0", "", None)
            if not has_auto_update:
                findings.append(SystemSecurityFinding(
                    severity="MEDIUM",
                    category="IDS/IPS",
                    check="ids_rule_updates",
                    issue="Automatische Regel-Updates nicht konfiguriert",
                    reason="Veraltete IDS-Regeln erkennen neue Bedrohungen und aktuelle Malware-Signaturen nicht",
                    solution="Automatischen Update-Schedule für IDS-Regeln einrichten",
                    details={"auto_update": str(auto_update)},
                    opnsense_path="Services > Intrusion Detection > Administration",
                    current_value="Regel-Updates: Manuell",
                    recommended_value="Regel-Updates: Automatisch (täglich)",
                    implementation_steps=[
                        "Services > Intrusion Detection > Administration öffnen",
                        "Unter 'Schedule' einen Cron-Job für tägliche Updates einrichten",
                        "Speichern und Apply"
                    ]
                ))

        return findings

    def _analyze_update_config(self, firmware_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze firmware/update configuration"""
        findings = []

        current_version = firmware_config.get("current_version", "Unbekannt")
        updates_available = firmware_config.get("updates_available", False)
        last_update = firmware_config.get("last_update", "")

        if updates_available:
            findings.append(SystemSecurityFinding(
                severity="HIGH",
                category="Updates",
                check="firmware_updates_pending",
                issue="Firmware-Updates verfügbar",
                reason="Ausstehende Updates können kritische Sicherheitspatches enthalten. Ungepatchte Systeme sind anfällig für bekannte Exploits",
                solution="Updates zeitnah über System > Firmware > Updates einspielen",
                details={"updates_available": True, "version": current_version},
                opnsense_path="System > Firmware > Updates",
                current_value=f"Version: {current_version} — Updates verfügbar!",
                recommended_value="Immer auf dem neuesten Stand",
                implementation_steps=[
                    "System > Firmware > Updates öffnen",
                    "'Check for updates' klicken",
                    "Changelog prüfen",
                    "Backup vor Update erstellen (System > Configuration > Backups)",
                    "'Update' klicken und Reboot abwarten"
                ]
            ))

        if not last_update:
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Updates",
                check="firmware_last_update",
                issue="Letztes Update-Datum nicht ermittelbar",
                reason="Ohne regelmäßige Update-Prüfung können kritische Sicherheitslücken übersehen werden",
                solution="Regelmäßige Update-Prüfung einrichten",
                details={"last_update": "unknown", "version": current_version},
                opnsense_path="System > Firmware > Updates",
                current_value=f"Letzter Check: Unbekannt (Version: {current_version})",
                recommended_value="Update-Check: Mindestens wöchentlich",
                implementation_steps=[
                    "System > Firmware > Updates öffnen",
                    "'Check for updates' klicken",
                    "Wöchentlichen Cron-Job einrichten unter System > Settings > Cron"
                ]
            ))

        return findings

    def _analyze_general_settings(self, general_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze general system settings"""
        findings = []

        hostname = general_config.get("hostname", "")
        domain = general_config.get("domain", "")

        # Check NTP configuration
        ntp_servers = general_config.get("ntp_servers", [])
        # Filter out empty strings
        ntp_servers = [s for s in ntp_servers if s and s.strip()]
        if not ntp_servers:
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="System",
                check="ntp_configured",
                issue="Keine NTP-Server konfiguriert",
                reason="Ohne korrekte Zeitsynchronisation sind Logs unbrauchbar, TLS-Zertifikate können fehlschlagen und Cron-Jobs laufen falsch",
                solution="NTP-Server konfigurieren (z.B. de.pool.ntp.org)",
                details={"ntp_servers": ntp_servers},
                opnsense_path="System > Settings > General",
                current_value="NTP-Server: Nicht konfiguriert",
                recommended_value="NTP-Server: 0.de.pool.ntp.org, 1.de.pool.ntp.org",
                implementation_steps=[
                    "System > Settings > General öffnen",
                    "'Time server hostname' auf z.B. '0.de.pool.ntp.org 1.de.pool.ntp.org' setzen",
                    "Speichern"
                ]
            ))

        # Check hostname/domain
        if not hostname or hostname in ("OPNsense", "opnsense", "firewall"):
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="System",
                check="hostname_default",
                issue=f"Standard-Hostname in Verwendung: '{hostname or 'leer'}'",
                reason="Ein individueller Hostname erleichtert die Identifikation im Netzwerk und in Logs",
                solution="Eindeutigen Hostnamen vergeben",
                details={"hostname": hostname, "domain": domain},
                opnsense_path="System > Settings > General",
                current_value=f"Hostname: {hostname or '(leer)'}.{domain or '(leer)'}",
                recommended_value="Hostname: Individueller Name (z.B. fw-standort)"
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
                issue="Zwei-Faktor-Authentifizierung (2FA) nicht aktiviert",
                reason="Ohne 2FA genügt ein kompromittiertes Passwort für vollen Admin-Zugriff. TOTP bietet zusätzlichen Schutz",
                solution="TOTP-basierte 2FA für alle Admin-Benutzer aktivieren",
                details={"totp_enabled": "0"},
                opnsense_path="System > Access > Users",
                current_value="2FA: Deaktiviert",
                recommended_value="2FA: TOTP aktiviert für alle Admin-User",
                implementation_steps=[
                    "System > Access > Tester öffnen und TOTP-Server anlegen",
                    "System > Access > Users > [Admin-User] bearbeiten",
                    "'OTP seed' generieren und QR-Code mit Authenticator-App scannen",
                    "Unter System > Settings > Administration den TOTP-Server als Auth-Backend wählen",
                    "Testen: Ausloggen und mit Passwort + TOTP-Code einloggen"
                ]
            ))

        # Check lockout policy
        try:
            lockout_threshold = int(auth_config.get("lockout_threshold", 0) or 0)
        except (ValueError, TypeError):
            lockout_threshold = 0
        if lockout_threshold == 0 or lockout_threshold > 5:
            threshold_display = lockout_threshold if lockout_threshold > 0 else "Kein Limit"
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Authentication",
                check="auth_lockout",
                issue=f"Schwache Login-Sperre (aktuell: {threshold_display})",
                reason="Ohne Lockout-Policy können Angreifer unbegrenzt Passwörter durchprobieren (Brute-Force)",
                solution="Account-Sperre nach 3-5 fehlgeschlagenen Versuchen konfigurieren",
                details={"lockout_threshold": lockout_threshold},
                opnsense_path="System > Settings > Administration",
                current_value=f"Lockout-Threshold: {threshold_display}",
                recommended_value="Lockout-Threshold: 3-5 Versuche",
                implementation_steps=[
                    "System > Settings > Administration öffnen",
                    "'Max login attempts' auf 5 setzen",
                    "Speichern"
                ]
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
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Logging",
                check="logging_not_configured",
                issue="Logging nicht explizit konfiguriert",
                reason="Ohne konfiguriertes Logging fehlen forensische Daten bei Sicherheitsvorfällen",
                solution="Logging-Einstellungen konfigurieren und Remote-Syslog aktivieren",
                details={},
                opnsense_path="System > Settings > Logging",
                current_value="Logging: Standard-Einstellungen (nicht konfiguriert)",
                recommended_value="Logging: Explizit konfiguriert mit Remote-Syslog"
            ))
            return findings
        
        # Check remote syslog
        remote_syslog = logging_config.get("remote_syslog", {})
        has_remote = remote_syslog.get("enabled", False)
        if not has_remote:
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="Logging",
                check="no_remote_syslog",
                issue="Kein Remote-Syslog konfiguriert",
                reason="Lokale Logs können bei einem Angriff manipuliert oder gelöscht werden. Remote-Logging sichert Logs auf einem separaten System",
                solution="Remote-Syslog-Server konfigurieren (z.B. Graylog, ELK, rsyslog)",
                details={"remote_syslog": "disabled"},
                opnsense_path="System > Settings > Logging > Remote",
                current_value="Remote-Syslog: Deaktiviert",
                recommended_value="Remote-Syslog: Aktiviert (separater Log-Server)",
                implementation_steps=[
                    "System > Settings > Logging > Remote öffnen",
                    "Neues Ziel anlegen (IP/Port des Syslog-Servers)",
                    "Aktivieren und relevante Facilities wählen",
                    "Speichern"
                ]
            ))
        
        # Check log retention
        try:
            preserve_logs = int(logging_config.get("preserve_logs", 7) or 7)
        except (ValueError, TypeError):
            preserve_logs = 7
        if preserve_logs < 30:
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="Logging",
                check="short_log_retention",
                issue=f"Kurze Log-Aufbewahrung: {preserve_logs} Tage",
                reason="Bei Security-Incidents werden oft Logs der letzten 30+ Tage benötigt. {preserve_logs} Tage reichen für forensische Analyse nicht aus",
                solution="Log-Retention auf mindestens 30 Tage erhöhen",
                details={"preserve_logs": preserve_logs},
                opnsense_path="System > Settings > Logging",
                current_value=f"Log-Aufbewahrung: {preserve_logs} Tage",
                recommended_value="Log-Aufbewahrung: ≥ 30 Tage",
                implementation_steps=[
                    "System > Settings > Logging öffnen",
                    "'Preserve logs' auf mindestens 31 setzen",
                    "Speichern"
                ]
            ))
        
        # Check firewall logging
        fw_log = logging_config.get("firewall", {})
        if not fw_log.get("log_default_block", True):
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Logging",
                check="no_default_block_logging",
                issue="Default-Block-Regel ohne Logging",
                reason="Ohne Logging der Default-Block-Regel bleiben geblockte Angriffsversuche und Port-Scans unsichtbar",
                solution="Logging für die Default-Block-Regel aktivieren",
                details={"log_default_block": False},
                opnsense_path="Firewall > Settings > Advanced",
                current_value="Log Default-Block: Deaktiviert",
                recommended_value="Log Default-Block: Aktiviert",
                implementation_steps=[
                    "Firewall > Settings > Advanced öffnen",
                    "'Log packets matched from the default block rule' aktivieren",
                    "Speichern und Apply"
                ]
            ))
        
        return findings

    def _analyze_cron_backup(self, cron_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze backup and cron configuration"""
        findings = []
        
        backup = cron_config.get("backup", {})
        has_backup = backup.get("enabled", False)
        if not has_backup:
            findings.append(SystemSecurityFinding(
                severity="HIGH",
                category="Backup",
                check="no_auto_backup",
                issue="Kein automatisches Config-Backup konfiguriert",
                reason="Ohne automatisches Backup geht bei Hardware-Ausfall, fehlgeschlagenen Updates oder Fehlkonfiguration die gesamte Konfiguration verloren",
                solution="Automatisches Config-Backup einrichten (lokal + Google Drive/Nextcloud)",
                details={"backup_enabled": False},
                opnsense_path="System > Configuration > Backups",
                current_value="Automatisches Backup: Nicht konfiguriert",
                recommended_value="Automatisches Backup: Aktiviert (täglich)",
                implementation_steps=[
                    "System > Configuration > Backups öffnen",
                    "Google Drive oder Nextcloud-Backup einrichten",
                    "Alternativ: Cron-Job unter System > Settings > Cron anlegen",
                    "Backup-Verschlüsselung aktivieren"
                ]
            ))
        
        if has_backup and not backup.get("encrypted", False):
            findings.append(SystemSecurityFinding(
                severity="MEDIUM",
                category="Backup",
                check="backup_not_encrypted",
                issue="Config-Backup nicht verschlüsselt",
                reason="Unverschlüsselte Backups enthalten Passwörter, API-Keys und VPN-Zertifikate im Klartext",
                solution="Backup-Verschlüsselung aktivieren",
                details={"encrypted": False},
                opnsense_path="System > Configuration > Backups",
                current_value="Backup-Verschlüsselung: Deaktiviert",
                recommended_value="Backup-Verschlüsselung: Aktiviert",
                implementation_steps=[
                    "System > Configuration > Backups öffnen",
                    "'Encrypt configuration backups' aktivieren",
                    "Sicheres Passwort vergeben und separat aufbewahren",
                    "Speichern"
                ]
            ))
        
        return findings

    def _analyze_captive_portal(self, cp_config: Dict) -> List[SystemSecurityFinding]:
        """Analyze Captive Portal configuration"""
        findings = []
        
        if not cp_config or not cp_config.get("enabled", False):
            return findings
        
        has_https = cp_config.get("https", False)
        if not has_https:
            findings.append(SystemSecurityFinding(
                severity="HIGH",
                category="Captive Portal",
                check="cp_no_https",
                issue="Captive Portal ohne HTTPS",
                reason="Login-Daten werden unverschlüsselt über WLAN/LAN übertragen und können leicht abgefangen werden",
                solution="HTTPS für das Captive Portal aktivieren",
                details={"https": False},
                opnsense_path="Services > Captive Portal",
                current_value="Captive Portal HTTPS: Deaktiviert",
                recommended_value="Captive Portal HTTPS: Aktiviert",
                implementation_steps=[
                    "Services > Captive Portal öffnen",
                    "Zone bearbeiten",
                    "SSL-Zertifikat zuweisen",
                    "Speichern"
                ]
            ))
        
        try:
            timeout = int(cp_config.get("timeout", 0) or 0)
        except (ValueError, TypeError):
            timeout = 0
        if timeout == 0 or timeout > 480:
            timeout_display = f"{timeout} Minuten" if timeout > 0 else "Unbegrenzt"
            findings.append(SystemSecurityFinding(
                severity="LOW",
                category="Captive Portal",
                check="cp_long_timeout",
                issue=f"Captive Portal Session-Timeout: {timeout_display}",
                reason="Zu lange oder unbegrenzte Sessions ermöglichen Missbrauch durch nicht-autorisierte Geräte",
                solution="Session-Timeout auf 4-8 Stunden setzen",
                details={"timeout": timeout},
                opnsense_path="Services > Captive Portal",
                current_value=f"Session-Timeout: {timeout_display}",
                recommended_value="Session-Timeout: 240-480 Minuten"
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
