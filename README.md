# OPNsense Security Auditor

Ein umfassendes Security-Audit-Tool für OPNsense Firewalls. Analysiert automatisch Firewall-Regeln, offene Ports, DNS-Konfiguration, VLAN-Segmentierung und erstellt detaillierte Sicherheitsberichte mit konkreten Lösungsvorschlägen.

## Features

### 🔥 Firewall-Regel-Analyse
- Erkennt "Any-to-Any" Regeln
- Identifiziert unsichere WAN-Regeln
- Prüft fehlende Logging-Konfiguration
- Analysiert NAT Port-Forwarding Regeln
- Warnt vor zu permissiven Protokoll-Regeln

### 🔓 Port-Security-Scanner
- Scannt alle Geräte im Netzwerk nach offenen Ports
- Identifiziert kritische Services (SSH, RDP, Datenbanken, etc.)
- Prüft gegen konfigurierbare Port-Whitelist
- Service-Detection und Version-Scanning
- Paralleles Scanning für bessere Performance

### 🌐 DNS-Sicherheits-Analyse
- DNSSEC Status-Prüfung
- DNS Rebinding Protection
- DNS over TLS (DoT) Konfiguration
- Open Resolver Detection
- DNS Amplification Tests
- Access Control List Prüfung

### 🔀 VLAN-Segmentierungs-Analyse
- Prüft VLAN-Isolation
- Erkennt fehlende Management-VLANs
- Analysiert Guest-Network-Isolation
- Empfiehlt Best-Practice VLAN-Struktur
- Inter-VLAN Routing Security

### 📊 Netzwerk-Discovery
- Automatische Geräte-Erkennung
- VLAN-Zuordnung für alle Geräte
- MAC-Vendor-Lookup
- Netzwerk-Topologie-Mapping
- Integration mit DHCP-Leases und ARP-Tabelle

### 📄 Reporting
- **HTML-Reports**: Interaktive, farbcodierte Reports
- **JSON-Reports**: Maschinenlesbare Daten für Integration
- **Text-Reports**: Einfache Lesbarkeit für Terminal/Email
- Severity-basierte Priorisierung
- Konkrete Lösungsvorschläge für jedes Finding
- Executive Summary Dashboard

## Installation

### Voraussetzungen

1. **OPNsense API Keys generieren**:
   - In OPNsense: System > Access > Users
   - User auswählen/erstellen
   - API Keys generieren und notieren

2. **Docker & Docker Compose installiert**

### Setup

1. Repository klonen oder Dateien kopieren:
```bash
cd /path/to/opnsensedashboardtester
```

2. Umgebungsvariablen konfigurieren:
```bash
cp .env.example .env
nano .env
```

Trage deine OPNsense-Daten ein:
```env
OPNSENSE_HOST=192.168.1.1
OPNSENSE_API_KEY=dein_api_key
OPNSENSE_API_SECRET=dein_api_secret
SCAN_NETWORK=192.168.1.0/24
```

3. Konfiguration anpassen (optional):
```bash
# Ports/Services für dein Homelab freigeben
nano config/exceptions.yaml
```

Beispiel für Homelab-Services:
```yaml
port_exceptions:
  - port: 8080
    host: "192.168.1.100"
    reason: "Home Assistant"
  - port: 32400
    host: "192.168.1.105"
    reason: "Plex Media Server"
  - port: 9000
    host: "192.168.1.110"
    reason: "Portainer"
```

4. Docker Image bauen:
```bash
docker-compose build
```

## Verwendung

### Einfacher Scan
```bash
docker-compose up
```

### Als Script ausführen
```bash
docker-compose run --rm opnsense-auditor
```

### Scan mit zusätzlichen Netzwerken
```bash
ADDITIONAL_NETWORKS="192.168.2.0/24,192.168.10.0/24" docker-compose up
```

### Reports ansehen
Die Reports werden im `reports/` Verzeichnis gespeichert:
- `security_audit_YYYYMMDD_HHMMSS.html` - HTML Report (im Browser öffnen)
- `security_audit_YYYYMMDD_HHMMSS.json` - JSON Daten
- `security_audit_YYYYMMDD_HHMMSS.txt` - Text Report
- `audit.log` - Detaillierte Logs

## Konfiguration

### Security Rules (`config/rules.yaml`)

Definiert welche Ports und Konfigurationen als kritisch gelten:

```yaml
critical_ports:
  - port: 22
    name: "SSH"
    severity: "HIGH"
    reason: "SSH sollte nicht öffentlich erreichbar sein"
```

### Ausnahmen (`config/exceptions.yaml`)

#### Port-Ausnahmen für Homelab
Wenn du Services öffentlich verfügbar machst:
```yaml
port_exceptions:
  - port: 443
    host: "192.168.1.100"
    reason: "Reverse Proxy für Webservices"
  - port: 8123
    host: "192.168.1.101"
    reason: "Home Assistant"
```

#### Firewall-Regel-Ausnahmen
Wenn du bewusst eine Regel hast die normalerweise gewarnt würde:
```yaml
firewall_exceptions:
  - rule_id: "uuid-der-regel"
    reason: "Benötigt für VPN Zugriff"
```

#### DNS-Ausnahmen
```yaml
dns_exceptions:
  - check: "dnssec_enabled"
    reason: "ISP unterstützt kein DNSSEC"
```

#### VLAN-Ausnahmen
Wenn VLANs bewusst kommunizieren sollen:
```yaml
vlan_exceptions:
  - check: "vlan_isolation"
    vlans: [10, 20]
    reason: "Management muss auf Server zugreifen"
```

#### Scan-Optionen
```yaml
scan_options:
  aggressive_scan: false        # Mehr Details, dauert länger
  port_scan_timeout: 300        # Timeout in Sekunden
  max_parallel_scans: 10        # Anzahl paralleler Scans
  skip_ping: false              # Hosts scannen auch wenn Ping fehlschlägt
```

#### Report-Optionen
```yaml
report_options:
  output_format: "all"          # json, html, text, all
  detail_level: "normal"        # minimal, normal, verbose
  critical_only: false          # Nur kritische Findings
  include_solutions: true       # Lösungsvorschläge einbeziehen
```

## Beispiel: Homelab-Konfiguration

Typische Homelab-Ausnahmen:

```yaml
port_exceptions:
  # Web-Services
  - port: 80
    reason: "HTTP Services (automatisch HTTPS Redirect)"
  - port: 443
    reason: "HTTPS Services (Reverse Proxy)"

  # Media
  - port: 32400
    host: "192.168.1.105"
    reason: "Plex Media Server"

  # Home Automation
  - port: 8123
    host: "192.168.1.101"
    reason: "Home Assistant"

  # Monitoring
  - port: 3000
    host: "192.168.1.120"
    reason: "Grafana Dashboard"

  # Container Management
  - port: 9000
    host: "192.168.1.110"
    reason: "Portainer"

host_exceptions:
  - ip: "192.168.1.1"
    reason: "OPNsense selbst"
```

## Empfohlene VLAN-Struktur

Das Tool empfiehlt folgende VLAN-Segmentierung:

| VLAN ID | Name | Zweck |
|---------|------|-------|
| 10 | Management | OPNsense, Switches, APs |
| 20 | Server | Server & Services |
| 30 | Workstations | User Workstations |
| 40 | IoT | IoT Devices (isoliert) |
| 50 | Guest | Guest Network (isoliert) |
| 99 | DMZ | Public facing services |

## Sicherheits-Checks im Detail

### Firewall
- ✅ Keine Any-to-Any Regeln
- ✅ Eingehender WAN Traffic beschränkt
- ✅ Logging für wichtige Regeln aktiviert
- ✅ Spezifische Protokolle statt "any"
- ✅ NAT Port Forwards nur für notwendige Services
- ✅ Source-Beschränkung für Port Forwards

### Ports
- ✅ SSH (22) nicht öffentlich
- ✅ RDP (3389) nicht öffentlich
- ✅ Datenbanken nicht öffentlich erreichbar
- ✅ Docker API nicht exponiert
- ✅ Admin-Interfaces geschützt
- ✅ SMB/NetBIOS blockiert

### DNS
- ✅ DNSSEC aktiviert
- ✅ DNS Rebinding Protection
- ✅ DNS over TLS konfiguriert
- ✅ Kein offener Resolver
- ✅ Access Lists konfiguriert
- ✅ Response Rate Limiting

### VLANs
- ✅ Dediziertes Management VLAN
- ✅ Guest Network isoliert
- ✅ IoT Devices segmentiert
- ✅ Inter-VLAN Routing beschränkt
- ✅ VLAN 1 nicht verwendet

## Troubleshooting

### Container hat keine Berechtigung für Port-Scan
```bash
# Docker mit erweiterten Berechtigungen starten
docker-compose run --cap-add=NET_ADMIN --cap-add=NET_RAW opnsense-auditor
```

### API-Verbindung schlägt fehl
- API Keys in OPNsense überprüfen
- Firewall-Regel für API-Zugriff prüfen
- Netzwerk-Erreichbarkeit testen: `ping <opnsense-ip>`

### Scan dauert zu lange
Passe `scan_options` an:
```yaml
scan_options:
  max_parallel_scans: 20  # Mehr parallel (Vorsicht: Netzwerklast)
  port_scan_timeout: 120  # Kürzeres Timeout
```

### Zu viele False Positives
Nutze `exceptions.yaml` um bekannte/gewollte Konfigurationen auszunehmen.

## Automatisierung

### Cronjob für regelmäßige Scans
```bash
# Täglich um 3 Uhr morgens
0 3 * * * cd /path/to/opnsensedashboardtester && docker-compose run --rm opnsense-auditor
```

### Integration mit Monitoring
Die JSON-Reports können in Monitoring-Systeme integriert werden:
```python
import json

with open('reports/security_audit_latest.json') as f:
    audit = json.load(f)

if audit['summary']['critical'] > 0:
    send_alert("Kritische Sicherheitsprobleme gefunden!")
```

## Sicherheitshinweise

- 🔒 API Keys niemals in Git committen
- 🔒 Docker Container läuft mit `network_mode: host` für Netzwerk-Scanning
- 🔒 Tool nur in vertrauenswürdigen Netzwerken ausführen
- 🔒 Reports können sensible Netzwerk-Informationen enthalten
- 🔒 Regelmäßige Scans empfohlen (wöchentlich/monatlich)

## Beitragen

Feedback und Verbesserungsvorschläge willkommen! Öffne ein Issue oder Pull Request.

## Lizenz

MIT License - Frei verwendbar für private und kommerzielle Projekte.

## Wichtiger Hinweis

Dieses Tool ist für **autorisierte Sicherheitstests** gedacht. Verwende es nur in Netzwerken, für die du die Berechtigung hast. Port-Scanning ohne Erlaubnis kann illegal sein.

---

**Erstellt für sichere Homelab- und Enterprise-Netzwerke mit OPNsense** 🔒
