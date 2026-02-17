# OPNsense Security Auditor

Security analysis tool for OPNsense firewalls. Analyzes firewall rules, NAT configs, DNS settings, system hardening and network segmentation. Provides actionable recommendations.

[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](https://github.com/RiDDiX/opnsense-secops/pkgs/container/opnsense-secops)
[![OPNsense](https://img.shields.io/badge/OPNsense-25.x-orange)](https://opnsense.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

**[English](#english) | [Deutsch](#deutsch)**

---

<a name="english"></a>
## English

### Features

| Module | Description |
|--------|-------------|
| **Firewall** | Detects any-to-any rules, missing logging, insecure WAN access, NAT misconfigs |
| **DNS** | Checks DNSSEC, DNS-over-TLS, rebinding protection, open resolver status |
| **System** | Analyzes SSH config, web admin security, IDS/IPS, VPN, logging |
| **Network** | VLAN segmentation, device discovery, WAN-exposed port detection |
| **Reports** | HTML/JSON/TXT with severity ratings and OPNsense menu paths |

### Dashboard

- Real-time scan progress with detailed check status
- Security score per category (Firewall, DNS, System, VPN)
- Findings with severity, description and fix instructions
- Direct links to OPNsense config pages
- Dark theme optimized for SOC environments

### Quick Start

```bash
git clone https://github.com/RiDDiX/opnsense-secops.git
cd opnsense-secops

# Configure
cp .env.example .env
nano .env  # Set OPNSENSE_HOST, API_KEY, API_SECRET

# Run
docker-compose up -d

# Open http://localhost:5000
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

| Modul | Beschreibung |
|-------|--------------|
| **Firewall** | Erkennt Any-to-Any Regeln, fehlendes Logging, unsichere WAN-Zugriffe, NAT-Fehlkonfigurationen |
| **DNS** | Prüft DNSSEC, DNS-over-TLS, Rebinding-Schutz, Open-Resolver-Status |
| **System** | Analysiert SSH-Konfig, Web-Admin-Sicherheit, IDS/IPS, VPN, Logging |
| **Netzwerk** | VLAN-Segmentierung, Geräte-Discovery, WAN-exponierte Ports |
| **Reports** | HTML/JSON/TXT mit Severity-Bewertung und OPNsense-Menüpfaden |

### Dashboard

- Echtzeit-Scan-Fortschritt mit detailliertem Check-Status
- Security-Score pro Kategorie (Firewall, DNS, System, VPN)
- Findings mit Severity, Beschreibung und Behebungsanleitung
- Direktlinks zu OPNsense-Konfigurationsseiten
- Dark Theme für SOC-Umgebungen

### Schnellstart

```bash
git clone https://github.com/RiDDiX/opnsense-secops.git
cd opnsense-secops

# Konfigurieren
cp .env.example .env
nano .env  # OPNSENSE_HOST, API_KEY, API_SECRET setzen

# Starten
docker-compose up -d

# Öffnen: http://localhost:5000
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
