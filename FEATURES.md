# OPNsense Security Auditor - Feature-Übersicht

## 🎯 Hauptfeatures

### 1. Umfassende Security-Analyse

#### 🔥 Firewall-Regel-Analyse
- **Any-to-Any Regel-Erkennung** - Identifiziert übermäßig permissive Regeln
- **WAN-Regel-Sicherheit** - Prüft eingehende WAN-Regeln auf Sicherheitsprobleme
- **Logging-Prüfung** - Stellt sicher, dass kritische Regeln geloggt werden
- **Protokoll-Validierung** - Warnt vor "any" Protokoll-Regeln
- **NAT Port-Forward-Analyse** - Identifiziert gefährliche Port-Forwards
- **Source-Beschränkung** - Prüft ob Port-Forwards Source-IPs einschränken

**Beispiel-Findings:**
- ❌ Any-to-Any Regel erlaubt unbeschränkten Traffic
- ❌ WAN-Regel erlaubt eingehenden Traffic ohne Port-Beschränkung
- ⚠️ Port-Forward für Port 3389 (RDP) ohne Source-Beschränkung

#### 🔓 Port-Security-Scanner
- **Nmap-Integration** - Professioneller Port-Scanner
- **Service-Detection** - Identifiziert laufende Services
- **Kritische Port-Datenbank** - 30+ vordefinierte kritische Ports
- **Paralleles Scanning** - Scannt mehrere Hosts gleichzeitig
- **Konfigurierbare Timeouts** - Anpassbare Scan-Geschwindigkeit
- **Host-Ausnahmen** - Schließe bestimmte Hosts vom Scan aus

**Erkannte kritische Services:**
- SSH (22), Telnet (23), RDP (3389)
- MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379)
- SMB (445), NetBIOS (139), NFS (111)
- Docker (2375/2376), Elasticsearch (9200), Kibana (5601)
- Webmin (10000), Alternative HTTP/HTTPS Ports

**Beispiel-Findings:**
- 🔴 CRITICAL: MySQL Port 3306 offen auf 192.168.1.100
- 🟠 HIGH: SSH Port 22 öffentlich erreichbar
- 🟡 MEDIUM: Alternative HTTPS Port 8443 ohne Authentifizierung

#### 🌐 DNS-Sicherheits-Analyse
- **DNSSEC-Prüfung** - Validiert DNS-Signatur-Konfiguration
- **DNS Rebinding Protection** - Prüft Schutz vor Rebinding-Attacken
- **DNS over TLS (DoT)** - Validiert verschlüsselte DNS-Konfiguration
- **Open Resolver Test** - Prüft auf offene DNS-Resolver
- **ACL-Validierung** - Stellt sicher dass DNS nur intern verfügbar ist
- **Amplification-Test** - Misst DNS-Amplification-Potential
- **Interface-Binding** - Prüft auf welchen Interfaces DNS hört

**Beispiel-Findings:**
- 🔴 CRITICAL: DNS ist ein offener Resolver (DDoS-Gefahr)
- 🟠 HIGH: DNSSEC nicht aktiviert
- 🟡 MEDIUM: DNS over TLS nicht konfiguriert

#### 🔀 VLAN-Segmentierungs-Analyse
- **VLAN-Isolation** - Prüft Inter-VLAN Routing-Regeln
- **Management VLAN** - Validiert dediziertes Management-Netzwerk
- **Guest Network** - Prüft Guest-Netzwerk-Isolation
- **IoT Segmentierung** - Empfiehlt IoT-Geräte-Isolation
- **VLAN 1 Prüfung** - Warnt vor Nutzung des Default-VLANs
- **Best-Practice Empfehlungen** - Schlägt ideale VLAN-Struktur vor

**Empfohlene VLAN-Struktur:**
- VLAN 10: Management (OPNsense, Switches, APs)
- VLAN 20: Server & Services
- VLAN 30: Workstations
- VLAN 40: IoT Devices (isoliert)
- VLAN 50: Guest (Internet-only)
- VLAN 99: DMZ (Public Services)

**Beispiel-Findings:**
- 🔴 CRITICAL: Kein dediziertes Management VLAN
- 🟠 HIGH: Guest VLAN hat Zugriff auf interne Netzwerke
- 🟡 MEDIUM: VLAN 1 wird für produktiven Traffic verwendet

#### 📊 Netzwerk-Discovery & Mapping
- **Automatische Device-Erkennung** - Findet alle Geräte im Netzwerk
- **VLAN-Zuordnung** - Ordnet Geräte ihren VLANs zu
- **MAC-Vendor-Lookup** - Identifiziert Gerätehersteller
- **Hostname-Resolution** - Resolved Hostnamen
- **DHCP-Integration** - Nutzt DHCP-Lease-Informationen
- **ARP-Tabellen-Analyse** - Integriert ARP-Daten
- **Netzwerk-Topologie-Map** - Erstellt visuelle Netzwerkkarte
- **Service-Mapping** - Zeigt offene Ports pro Gerät

**Statistiken:**
- Gesamtanzahl Geräte
- Aktive vs. Inactive Geräte
- Geräte pro Netzwerk/VLAN
- Geräte pro Hersteller
- Offene Ports gesamt
- Unique Services

### 2. Intelligente Konfiguration

#### ⚙️ Flexibles Ausnahmen-System
- **Port-Ausnahmen** - Erlaube spezifische Ports auf bestimmten Hosts
- **Firewall-Regel-Ausnahmen** - Überspringe bekannte/gewollte Regeln
- **DNS-Check-Ausnahmen** - Deaktiviere spezifische DNS-Prüfungen
- **VLAN-Ausnahmen** - Erlaube bewusste Inter-VLAN-Kommunikation
- **Host-Ausnahmen** - Schließe Hosts vom Scanning aus

**Beispiel-Konfiguration:**
```yaml
port_exceptions:
  - port: 8080
    host: "192.168.1.100"
    reason: "Home Assistant Web-Interface"
  - port: 32400
    host: "192.168.1.105"
    reason: "Plex Media Server"
```

#### 🎛️ Anpassbare Scan-Optionen
- **Aggressive Scan** - Detaillierte Service-Erkennung
- **Timeout-Konfiguration** - Balance zwischen Geschwindigkeit und Genauigkeit
- **Parallele Scans** - 1-50 parallele Host-Scans
- **Ping-Skip** - Scanne auch Hosts die nicht auf Ping antworten

#### 📄 Report-Anpassung
- **Multi-Format** - HTML, JSON, Text oder alle drei
- **Detailgrad** - Minimal, Normal, Verbose
- **Filtering** - Nur kritische Findings anzeigen
- **Lösungen** - Ein/Ausschalten von Lösungsvorschlägen

### 3. Professionelle Reports

#### 📊 HTML-Report
- **Interaktives Dashboard** - Executive Summary mit Statistiken
- **Farbcodierung** - Severity-basierte Farben (Rot, Orange, Gelb, Blau)
- **Kategorisierung** - Findings nach Typ gruppiert
- **Detailansicht** - Vollständige Informationen zu jedem Finding
- **Lösungsvorschläge** - Konkrete Handlungsempfehlungen
- **Responsive Design** - Funktioniert auf Desktop und Mobile
- **Druckoptimiert** - Sauberes Layout für PDF-Export

**HTML-Report Sections:**
- Executive Summary Dashboard
- Firewall Rule Findings
- Port Security Findings
- DNS Security Findings
- VLAN Security Findings
- Network Statistics

#### 📋 JSON-Report
- **Maschinenlesbar** - Perfekt für Integration
- **Vollständige Daten** - Alle Details verfügbar
- **API-Integration** - Nutzbar für Monitoring-Systeme
- **Parsing-freundlich** - Strukturiertes Format

**Use Cases:**
- Integration in SIEM-Systeme
- Automatisierte Alerting-Pipelines
- Langzeit-Trend-Analyse
- Custom-Dashboards

#### 📝 Text-Report
- **Terminal-Friendly** - Lesbar in der Konsole
- **Email-geeignet** - Perfekt für automatische Reports
- **Log-Integration** - Einfaches Parsing
- **Schnelle Übersicht** - Ohne GUI nutzbar

### 4. Automation & Integration

#### ⏰ Scheduled Scanning
- **Cronjob-Ready** - Vorgefertigtes Script
- **Automatisches Logging** - Detaillierte Scan-Logs
- **Alte Reports** - Automatische Bereinigung (>30 Tage)
- **Benachrichtigungen** - Alert bei kritischen Findings
- **Flexible Zeitpläne** - Täglich, wöchentlich, monatlich

**Notification-Optionen:**
- Email (sendmail/SMTP)
- Slack Webhook
- Telegram Bot
- Custom Webhooks

#### 📈 Trend-Analyse
- **Scan-Vergleich** - Compare-Script zeigt Änderungen
- **CSV-Export** - Historische Daten exportieren
- **Langzeit-Tracking** - Verfolge Sicherheits-Trends
- **Delta-Reports** - Zeigt was sich geändert hat

#### 🔗 API-Integration
- **OPNsense API** - Nutzt offizielle REST API
- **Read-Only** - Keine Änderungen an Konfiguration
- **SSL-Support** - Unterstützt self-signed Certificates
- **Timeout-Handling** - Robuste Fehlerbehandlung

### 5. Docker-Integration

#### 🐳 Docker Features
- **Single Command Deploy** - `docker-compose up`
- **Network Host Mode** - Voller Netzwerk-Zugriff für Scanning
- **Volume Persistence** - Config und Reports bleiben erhalten
- **Environment-basiert** - Einfache Konfiguration via .env
- **Multi-Netzwerk** - Scanne mehrere Netzwerke gleichzeitig

#### 📦 Container-Vorteile
- ✅ Keine lokale Python-Installation nötig
- ✅ Alle Dependencies vorinstalliert
- ✅ Konsistente Umgebung
- ✅ Einfache Updates (rebuild)
- ✅ Portabel zwischen Systemen

### 6. Sicherheits-Features

#### 🔒 Best Practices
- ✅ API-Keys in .env (nicht in Git)
- ✅ Read-Only API-Zugriff ausreichend
- ✅ Keine Konfigurationsänderungen
- ✅ Audit-Logs für alle Aktionen
- ✅ Sichere Credential-Verwaltung

#### 🛡️ Scope-Beschränkung
- Nur autorisierte Netzwerke scannen
- Konfigurierbare Host-Ausnahmen
- Respektiert Firewall-Regeln
- Keine invasiven Tests
- Transparent logging

## 📚 Dokumentation

### Enthaltene Dokumentation
- **README.md** - Vollständige Anleitung (8.6 KB)
- **QUICKSTART.md** - 5-Minuten-Schnellstart
- **PROJEKTSTRUKTUR.md** - Technische Architektur
- **FEATURES.md** - Diese Datei
- **scripts/README.md** - Hilfs-Skript-Dokumentation

### Code-Qualität
- ✅ Type Hints
- ✅ Docstrings
- ✅ Logging
- ✅ Error Handling
- ✅ Modular aufgebaut
- ✅ Erweiterbar

## 🎯 Use Cases

### Homelab
- Regelmäßige Security-Audits
- Neue Service-Erkennung
- Port-Monitoring
- VLAN-Validierung

### Enterprise
- Compliance-Reports
- Change-Detection
- Security-Baselines
- Audit-Trails

### MSPs
- Multi-Tenant Scanning
- Scheduled Audits
- SLA-Monitoring
- Customer-Reports

## 🚀 Performance

- **Scan-Zeit**: ~5-10 Minuten für 50 Hosts
- **Parallele Scans**: Bis zu 50 gleichzeitig
- **Memory**: <500 MB RAM
- **Storage**: <100 MB (ohne Reports)

## 🔄 Update-Frequenz

**Empfohlene Scan-Intervalle:**
- Homelab: Wöchentlich
- Small Business: Täglich
- Enterprise: Täglich + nach Änderungen
- MSP: Pro Kunde individuell

## 📊 Reporting-Kapazitäten

- **Max. Geräte**: 1000+ (limitiert durch Nmap)
- **Max. Findings**: Unbegrenzt
- **Report-Größe**: Typisch 100-500 KB
- **History**: Unbegrenzt (manuelle Bereinigung)

## 🎨 Customization

### Erweiterbar durch:
- Eigene Analyzer-Module
- Custom Rules
- Additional Checks
- Report-Templates
- Notification-Kanäle

### API für Integration:
- JSON-Output für Automation
- Exit-Codes für CI/CD
- Webhook-Support
- Custom Scripts
