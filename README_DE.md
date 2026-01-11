# 🔒 OPNsense Security Auditor

[English](README.md) | **Deutsch**

Ein umfassendes Security-Audit-Tool für OPNsense Firewalls mit Web-Dashboard, CVE-Datenbank-Integration und automatischer Schwachstellenerkennung.

## ✨ Features

- 🎯 **Web-Dashboard** - Moderne Benutzeroberfläche (Deutsch/Englisch)
- 🔥 **Firewall-Analyse** - Erkennt unsichere Regeln und Konfigurationen
- 🔓 **Port-Scanning** - Identifiziert kritische offene Ports mit nmap
- 🌐 **DNS-Security** - DNSSEC, DNS Rebinding, Open Resolver Tests
- 🔀 **VLAN-Analyse** - Netzwerk-Segmentierung und Best Practices
- 🔴 **CVE-Scanning** - Integration mit NVD, CVE circl.lu, Vulners
- 📊 **Netzwerk-Discovery** - Automatische Geräteerkennung
- 📄 **Multi-Format-Reports** - HTML, JSON, Text
- ⚙️ **Konfigurierbare Ausnahmen** - Ignorier-Liste für bekannte Services

## 🚀 Quick Start

### 1. OPNsense API Keys erstellen

```
System > Access > Users > [User wählen] > API Keys > [+]
```

Kopiere API Key und Secret (wird nur einmal angezeigt!)

### 2. Docker starten

```bash
git clone <repository-url>
cd opnsensedashboardtester

# Environment konfigurieren (optional - kann auch im Dashboard gemacht werden)
cp .env.example .env
nano .env

# Container starten
docker-compose up -d
```

### 3. Dashboard öffnen

```
http://localhost:5000
```

### 4. Im Dashboard konfigurieren

1. **Configuration** → OPNsense Host, API Keys eingeben
2. **Scan-Optionen** anpassen
3. **Start Scan** klicken
4. **Dashboard** → Findings nach Schweregrad ansehen

## 📊 Dashboard-Features

### Kategorien

Findings werden in 5 Kategorien angezeigt:

- 🔴 **Kritisch** - Sofortiges Handeln erforderlich
- 🟠 **Wichtig** - Zeitnahes Patching notwendig
- 🟡 **Mittel** - Sollte behoben werden
- 🔵 **Unwichtig** - Geringe Priorität
- ✅ **Gut** - Keine Probleme

### Konfiguration

Im Dashboard können Sie einstellen:

- **OPNsense** - Host, API Keys, Netzwerk
- **Scan-Optionen** - Aggressive Scan, Timeouts, CVE-Scanning
- **Sprache** - Deutsch/Englisch

### Ignorier-Liste

Findings können direkt zur Ignorier-Liste hinzugefügt werden:
- Klicke "Zur Ignorier-Liste hinzufügen" bei jedem Finding
- Verwalte Ausnahmen unter "Ignorier-Liste"

## 🔍 Was wird geprüft?

### Firewall (12 Checks)
- Any-to-Any Regeln
- Unsichere WAN-Regeln
- Fehlende Logging-Aktivierung
- NAT Port-Forwards
- Protokoll-Spezifikation

### Ports (30+ kritische Services)
- SSH, RDP, Telnet
- Datenbanken (MySQL, PostgreSQL, MongoDB, Redis)
- Docker, Elasticsearch
- SMB, NFS
- Admin-Interfaces

### DNS (8 Checks)
- DNSSEC
- DNS Rebinding Protection
- DNS over TLS
- Open Resolver
- ACLs

### VLANs (6 Checks)
- VLAN-Isolation
- Management VLAN
- Guest Isolation
- Best-Practice Struktur

### CVEs (3 Datenbanken)
- National Vulnerability Database (NVD)
- CVE circl.lu
- Vulners.com
- OPNsense-spezifisch
- Aktuelle CVEs (90 Tage)

## ⚙️ Konfiguration

### Beispiel: Homelab Port-Ausnahmen

Im Dashboard oder in `config/exceptions.yaml`:

```yaml
port_exceptions:
  - port: 443
    reason: "HTTPS Reverse Proxy"
  - port: 8123
    host: "192.168.1.101"
    reason: "Home Assistant"
  - port: 32400
    host: "192.168.1.105"
    reason: "Plex Media Server"
```

### Scan-Optionen

```yaml
scan_options:
  aggressive_scan: false
  port_scan_timeout: 300
  max_parallel_scans: 10
  enable_vulnerability_scan: true
```

## 📄 Reports

Reports werden in 3 Formaten generiert:

- **HTML** - Interaktives Dashboard
- **JSON** - Für Automation/SIEM
- **TEXT** - Terminal-friendly

Download über Dashboard oder im `reports/` Verzeichnis.

## 🐳 Docker

### Standard-Start

```bash
docker-compose up -d
```

### Logs ansehen

```bash
docker-compose logs -f
```

### Neu bauen

```bash
docker-compose build --no-cache
docker-compose up -d
```

## 🔐 Sicherheit

- ⚠️ Nur in autorisierten Netzwerken verwenden
- 🔒 API-Keys sicher aufbewahren
- 🛡️ Tool macht keine Änderungen an OPNsense
- 📊 Reports enthalten sensible Daten

## 📚 Dokumentation

- [QUICKSTART_DE.md](QUICKSTART_DE.md) - Schnellstart-Anleitung
- [CVE_INTEGRATION.md](CVE_INTEGRATION.md) - CVE-Datenbank-Details
- [FEATURES.md](FEATURES.md) - Vollständige Feature-Liste

## 🌍 Sprachen

- 🇩🇪 Deutsch (vollständig)
- 🇬🇧 English (vollständig)

Umschalten im Dashboard oder per Language-Selector.

## 🤝 Beitragen

Pull Requests willkommen! Für größere Änderungen bitte zuerst ein Issue öffnen.

## 📝 Lizenz

MIT License - Frei verwendbar für private und kommerzielle Projekte.

---

**Erstellt für sichere Homelab- und Enterprise-Netzwerke** 🔒
