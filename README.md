# NetSec Auditor for OPNsense

Security audit toolkit for OPNsense firewalls. Scans firewall configs, open ports, DNS settings and VLAN setups. Outputs reports with fix recommendations.

---

**[English](#english) | [Deutsch](#deutsch)**

---

<a name="english"></a>
## English

### What it does

- **Firewall Analysis** - Finds risky rules like any-to-any, missing logs, open NAT forwards
- **Port Scanner** - Checks your network for exposed services (SSH, RDP, DBs, etc.)
- **DNS Audit** - DNSSEC, DoT, rebinding protection, open resolver checks
- **VLAN Check** - Segmentation analysis, isolation verification
- **Asset Discovery** - Device enumeration with MAC lookup
- **Reports** - HTML/JSON/TXT output with severity ratings

### Quick Start

```bash
# clone repo
git clone https://github.com/RiDDiX/opnsense-secops.git
cd opnsense-secops

# set credentials
cp .env.example .env
# edit .env with your OPNsense API key/secret

# run
docker-compose up -d

# open browser
# http://localhost:5000
```

### Config

#### API Keys (required)
Generate in OPNsense: `System > Access > Users > [User] > API Keys`

```env
OPNSENSE_HOST=192.168.1.1
OPNSENSE_API_KEY=xxx
OPNSENSE_API_SECRET=xxx
```

#### Exceptions
File: `config/exceptions.yaml`

```yaml
port_exceptions:
  - port: 32400
    host: "192.168.1.50"
    reason: "Plex"
  - port: 8123
    host: "192.168.1.51"
    reason: "Home Assistant"

firewall_exceptions:
  - rule_id: "abc123"
    reason: "VPN passthrough"

scan_options:
  aggressive_scan: false
  port_scan_timeout: 300
  max_parallel_scans: 10
```

### VLAN Layout (recommended)

| ID | Name | Use |
|----|------|-----|
| 10 | MGMT | Firewall, Switches, APs |
| 20 | SRV | Server |
| 30 | CLIENT | Workstations |
| 40 | IOT | Smart devices (isolated) |
| 50 | GUEST | Guests (isolated) |
| 99 | DMZ | Public services |

### Checks

**Firewall**
- No any-to-any
- WAN inbound locked
- Logging on critical rules
- NAT source restrictions

**Ports**
- SSH/RDP not WAN-exposed
- DBs internal only
- Docker API secured
- SMB blocked

**DNS**
- DNSSEC active
- DoT configured
- No open resolver
- Rebinding protection

### Troubleshooting

**Nmap permission denied**
```bash
docker-compose run --cap-add=NET_ADMIN --cap-add=NET_RAW opnsense-auditor
```

**API timeout**
Check firewall allows API access from Docker network.

**Slow scans**
Reduce `port_scan_timeout` or increase `max_parallel_scans`.

### Cron

```bash
0 3 * * 0 cd /opt/opnsense-secops && docker-compose run --rm opnsense-auditor
```

---

<a name="deutsch"></a>
## Deutsch

### Funktionen

- **Firewall-Analyse** - Findet riskante Regeln (Any-to-Any, fehlende Logs, offene NAT-Forwards)
- **Port-Scanner** - Prüft Netzwerk auf exponierte Dienste (SSH, RDP, DBs, etc.)
- **DNS-Audit** - DNSSEC, DoT, Rebinding-Schutz, Open-Resolver-Check
- **VLAN-Prüfung** - Segmentierung, Isolations-Verifizierung
- **Asset Discovery** - Geräteerkennung mit MAC-Lookup
- **Reports** - HTML/JSON/TXT mit Severity-Bewertung

### Schnellstart

```bash
# Repo klonen
git clone https://github.com/RiDDiX/opnsense-secops.git
cd opnsense-secops

# Zugangsdaten setzen
cp .env.example .env
# .env bearbeiten mit OPNsense API Key/Secret

# Starten
docker-compose up -d

# Browser öffnen
# http://localhost:5000
```

### Konfiguration

#### API Keys (erforderlich)
Erstellen in OPNsense: `System > Zugriff > Benutzer > [User] > API Schlüssel`

```env
OPNSENSE_HOST=192.168.1.1
OPNSENSE_API_KEY=xxx
OPNSENSE_API_SECRET=xxx
```

#### Ausnahmen
Datei: `config/exceptions.yaml`

```yaml
port_exceptions:
  - port: 32400
    host: "192.168.1.50"
    reason: "Plex"
  - port: 8123
    host: "192.168.1.51"
    reason: "Home Assistant"

firewall_exceptions:
  - rule_id: "abc123"
    reason: "VPN Durchleitung"

scan_options:
  aggressive_scan: false
  port_scan_timeout: 300
  max_parallel_scans: 10
```

### VLAN-Struktur (empfohlen)

| ID | Name | Verwendung |
|----|------|------------|
| 10 | MGMT | Firewall, Switches, APs |
| 20 | SRV | Server |
| 30 | CLIENT | Arbeitsplätze |
| 40 | IOT | Smarte Geräte (isoliert) |
| 50 | GUEST | Gäste (isoliert) |
| 99 | DMZ | Öffentliche Dienste |

### Prüfungen

**Firewall**
- Kein any-to-any
- WAN Inbound gesperrt
- Logging bei kritischen Regeln
- NAT-Quellbeschränkungen

**Ports**
- SSH/RDP nicht WAN-exponiert
- DBs nur intern
- Docker API gesichert
- SMB blockiert

**DNS**
- DNSSEC aktiv
- DoT konfiguriert
- Kein offener Resolver
- Rebinding-Schutz

### Problemlösung

**Nmap permission denied**
```bash
docker-compose run --cap-add=NET_ADMIN --cap-add=NET_RAW opnsense-auditor
```

**API Timeout**
Firewall-Regel für API-Zugriff vom Docker-Netzwerk prüfen.

**Langsame Scans**
`port_scan_timeout` reduzieren oder `max_parallel_scans` erhöhen.

### Automatisierung

```bash
0 3 * * 0 cd /opt/opnsense-secops && docker-compose run --rm opnsense-auditor
```

---

## Lizenz

MIT

## Hinweis

Nur für autorisierte Sicherheitstests. Port-Scanning ohne Genehmigung kann illegal sein.
