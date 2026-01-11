# CVE & Vulnerability Database Integration

## Übersicht

Das OPNsense Security Auditor Tool ist jetzt mit mehreren CVE- und Vulnerability-Datenbanken integriert, um aktuelle Sicherheitslücken automatisch zu erkennen und Lösungen anzubieten.

## Integrierte Datenbanken

### 1. National Vulnerability Database (NVD)
**URL:** https://nvd.nist.gov/
**API:** NVD API 2.0

**Was wird geprüft:**
- Alle entdeckten Services und deren Versionen
- OPNsense-Version selbst
- Kürzlich veröffentlichte CVEs (letzte 90 Tage)

**Features:**
- CVSS v3.1 Scores
- Offizielle CVE-Beschreibungen
- Referenz-Links zu Patches
- Severity-Klassifizierung

**Beispiel-Output:**
```json
{
  "cve_id": "CVE-2024-1234",
  "severity": "CRITICAL",
  "cvss_score": 9.8,
  "affected_service": "192.168.1.100:22 (ssh)",
  "affected_version": "OpenSSH 7.4",
  "description": "Remote code execution in OpenSSH...",
  "solution": "Update SSH server to version 8.9+",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]
}
```

### 2. CVE circl.lu API
**URL:** https://cve.circl.lu/
**API:** REST API

**Was wird geprüft:**
- Service/Version-spezifische CVEs
- Schnelle Lookup-Funktion
- Ergänzende CVE-Informationen

**Vorteile:**
- Schnelle Response-Zeiten
- Einfache API ohne Authentifizierung
- Gut strukturierte Daten

### 3. Vulners.com API
**URL:** https://vulners.com/
**API:** Lucene Search API

**Was wird geprüft:**
- Umfassende Vulnerability-Suche
- Multiple Datenquellen
- Exploit-Datenbank-Integration

**Vorteile:**
- Große Vulnerability-Datenbank
- Exploit-Verfügbarkeits-Information
- Erweiterte Search-Capabilities

## Automatische Prüfungen

### 1. Service-basierte Scans

Für jeden entdeckten Service wird automatisch geprüft:

```
Service Discovery (nmap)
    ↓
Service: SSH, Version: OpenSSH 7.4
    ↓
CVE Lookup (NVD, circl.lu, Vulners)
    ↓
Bekannte Vulnerabilities:
- CVE-2024-1234 (CRITICAL)
- CVE-2023-5678 (HIGH)
    ↓
Solutions bereitgestellt
```

### 2. OPNsense-Version Check

```
OPNsense API → System Info → Version: 24.1.1
    ↓
NVD CVE Search: "opnsense 24.1.1"
    ↓
Bekannte OPNsense CVEs
    ↓
Update-Empfehlungen
```

### 3. Kritische Services Monitoring

Automatische Überwachung für:
- **OpenSSH** - Remote-Access
- **Apache/Nginx** - Webserver
- **MySQL/PostgreSQL** - Datenbanken
- **Redis** - Cache/DB
- **Docker** - Container-Platform
- **Elasticsearch** - Search Engine

Für diese Services werden **immer** die neuesten CVEs geprüft (letzte 90 Tage).

## CVSS Severity Mapping

```
CVSS Score    Severity     Beschreibung
----------    --------     ------------
9.0 - 10.0    CRITICAL     Sofortiges Handeln erforderlich
7.0 - 8.9     HIGH         Zeitnahes Patching notwendig
4.0 - 6.9     MEDIUM       Sollte gepatched werden
0.1 - 3.9     LOW          Geringe Priorität
```

## Report-Integration

### HTML Report

Neue Sektion: **🔴 Known Vulnerabilities (CVE)**

Zeigt für jedes Finding:
- CVE-ID mit Link zur Referenz
- CVSS Score und Severity
- Betroffener Service und Version
- Detaillierte Beschreibung
- Konkrete Lösungsvorschläge
- Patch-/Update-Links

**Beispiel:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 CRITICAL - CVE-2024-1234

Service: 192.168.1.100:22 (OpenSSH 7.4)
CVSS Score: 9.8
Published: 2024-01-15

Description:
Remote code execution vulnerability in OpenSSH versions
7.0-7.4 allows unauthenticated attackers to execute
arbitrary code with root privileges.

💡 Solution:
Update SSH server to OpenSSH 8.9+ immediately.
Check https://nvd.nist.gov/vuln/detail/CVE-2024-1234
for specific patch level.

References:
- https://nvd.nist.gov/vuln/detail/CVE-2024-1234
- https://www.openssh.com/security.html
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### JSON Report

Zusätzliche Felder:
```json
{
  "vulnerability_findings": [
    {
      "severity": "CRITICAL",
      "cve_id": "CVE-2024-1234",
      "cvss_score": 9.8,
      "affected_service": "192.168.1.100:22 (ssh)",
      "affected_version": "OpenSSH 7.4",
      "description": "...",
      "solution": "...",
      "references": ["..."],
      "published_date": "2024-01-15T10:00:00"
    }
  ],
  "vulnerability_summary": {
    "total_vulnerabilities": 15,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2,
    "unique_cves": 12,
    "average_cvss": 6.8
  }
}
```

## API Rate Limits

### NVD API
- **Limit:** 5 requests per 30 seconds (ohne API Key)
- **Mit API Key:** 50 requests per 30 seconds
- **Empfehlung:** Für Production-Nutzung API Key beantragen

**API Key beantragen:**
https://nvd.nist.gov/developers/request-an-api-key

Dann in `.env` hinzufügen:
```env
NVD_API_KEY=dein-api-key
```

### CVE circl.lu
- **Limit:** Keine harten Limits
- **Fair Use:** Nicht mehr als 10 requests/second

### Vulners
- **Limit:** 20 requests/day (kostenlos)
- **Mit API Key:** Höhere Limits

## Konfiguration

### Vulnerability Scanning aktivieren/deaktivieren

In `config/exceptions.yaml`:

```yaml
scan_options:
  # CVE-Scanning
  enable_vulnerability_scan: true
  vulnerability_max_age_days: 90  # Nur CVEs der letzten X Tage

  # API-Konfiguration
  nvd_api_enabled: true
  cve_search_enabled: true
  vulners_enabled: true
```

### API Keys (optional)

Erstelle `.env.secrets`:
```env
NVD_API_KEY=your-nvd-api-key
VULNERS_API_KEY=your-vulners-api-key
```

## Praktische Beispiele

### Beispiel 1: Veraltetes OpenSSH erkannt

**Finding:**
```
🔴 CRITICAL - CVE-2023-38408
Service: 192.168.1.50:22 (OpenSSH 8.9p1)
CVSS: 9.8

Remote Code Execution in OpenSSH
Attacker kann Root-Zugriff erlangen

Solution:
apt update && apt upgrade openssh-server
oder
pkg upgrade openssh-server (FreeBSD/OPNsense)
```

**Aktion:**
1. SSH zum Server
2. Update durchführen
3. Service neustarten
4. Erneuten Scan durchführen zur Verifizierung

### Beispiel 2: Ungeschütztes Elasticsearch

**Finding:**
```
🔴 CRITICAL - CVE-2023-31419
Service: 192.168.1.100:9200 (Elasticsearch)
CVSS: 10.0

Unauthenticated RCE in Elasticsearch < 7.17.9
Vollständige System-Kompromittierung möglich

Solution:
1. Update auf Elasticsearch 7.17.9+
2. Aktiviere X-Pack Security
3. Beschränke Netzwerk-Zugriff
4. Verwende Reverse Proxy mit Auth
```

**Aktion:**
1. Sofortiges Update
2. Security-Features aktivieren
3. Firewall-Regel hinzufügen
4. Monitoring aktivieren

### Beispiel 3: OPNsense selbst betroffen

**Finding:**
```
🟠 HIGH - CVE-2024-2345
Service: OPNsense 24.1.1
CVSS: 7.5

Privilege Escalation in OPNsense Web Interface
Lokaler Angreifer kann Admin-Rechte erlangen

Solution:
Update OPNsense via:
System > Firmware > Updates
Auf Version 24.1.3+ aktualisieren
```

**Aktion:**
1. In OPNsense einloggen
2. System > Firmware > Updates
3. Update durchführen
4. System rebooten

## Automatische Benachrichtigungen

### Bei kritischen CVEs

Erweitere `scripts/scheduled-scan.sh`:

```bash
# Check for critical CVEs
CRITICAL_CVES=$(grep -o '"severity": "CRITICAL"' "$LATEST_JSON" | wc -l | tr -d ' ')

if [ "$CRITICAL_CVES" -gt 0 ]; then
    # Email mit CVE-Details
    python3 <<EOF
import json

with open("$LATEST_JSON") as f:
    data = json.load(f)

critical_vulns = [
    v for v in data["vulnerability_findings"]
    if v["severity"] == "CRITICAL"
]

email_body = "CRITICAL CVEs gefunden:\\n\\n"
for vuln in critical_vulns:
    email_body += f"- {vuln['cve_id']}: {vuln['title']}\\n"
    email_body += f"  Service: {vuln['affected_service']}\\n"
    email_body += f"  CVSS: {vuln['cvss_score']}\\n"
    email_body += f"  Solution: {vuln['solution']}\\n\\n"

print(email_body)
EOF
fi
```

## Integration mit SIEM/Monitoring

### Splunk Integration

```python
import requests
import json

# Load audit results
with open('reports/security_audit_latest.json') as f:
    audit = json.load(f)

# Send to Splunk HEC
splunk_url = "https://splunk:8088/services/collector/event"
splunk_token = "your-hec-token"

for vuln in audit['vulnerability_findings']:
    if vuln['severity'] in ['CRITICAL', 'HIGH']:
        event = {
            "sourcetype": "opnsense:vulnerability",
            "event": vuln
        }

        requests.post(
            splunk_url,
            headers={"Authorization": f"Splunk {splunk_token}"},
            json=event
        )
```

### Prometheus/Grafana

Erstelle Metrics-Exporter:

```python
from prometheus_client import Gauge, start_http_server
import json
import time

# Metrics
vuln_critical = Gauge('opnsense_vulnerabilities_critical', 'Critical CVEs')
vuln_high = Gauge('opnsense_vulnerabilities_high', 'High CVEs')
vuln_total = Gauge('opnsense_vulnerabilities_total', 'Total CVEs')

def update_metrics():
    with open('reports/security_audit_latest.json') as f:
        data = json.load(f)

    summary = data['vulnerability_summary']
    vuln_critical.set(summary['critical'])
    vuln_high.set(summary['high'])
    vuln_total.set(summary['total_vulnerabilities'])

if __name__ == '__main__':
    start_http_server(8000)
    while True:
        update_metrics()
        time.sleep(3600)  # Update jede Stunde
```

## Troubleshooting

### API-Anfragen schlagen fehl

```bash
# Test NVD API
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=openssh"

# Test CVE circl.lu
curl "https://cve.circl.lu/api/search/openssh/8.9"
```

### Zu viele False Positives

Vulnerability-Scanning kann generisch sein. Filtern in `exceptions.yaml`:

```yaml
vulnerability_exceptions:
  - cve_id: "CVE-2023-12345"
    reason: "Betrifft nur Windows, wir nutzen Linux"
  - service: "Apache"
    version: "2.4.41"
    reason: "Custom-Patch bereits angewendet"
```

### Performance-Optimierung

Für große Netzwerke:

```yaml
scan_options:
  # Nur kritische Services prüfen
  vulnerability_critical_services_only: true

  # Cache CVE-Lookups
  vulnerability_cache_enabled: true
  vulnerability_cache_ttl: 86400  # 24 Stunden
```

## Best Practices

1. **Wöchentliche CVE-Scans** - Neue CVEs werden ständig veröffentlicht
2. **Kritische sofort patchen** - CVSS ≥ 9.0 haben Priorität
3. **Update-Windows** - Plane regelmäßige Wartungsfenster
4. **Test vor Production** - Teste Updates in Staging-Umgebung
5. **Monitoring** - Automatische Alerts bei neuen kritischen CVEs
6. **Dokumentation** - Dokumentiere bekannte False Positives

## Weiterführende Ressourcen

- **NVD:** https://nvd.nist.gov/
- **CVE:** https://cve.mitre.org/
- **CVSS Calculator:** https://www.first.org/cvss/calculator/3.1
- **OPNsense Security:** https://docs.opnsense.org/security.html
- **Vulners:** https://vulners.com/
