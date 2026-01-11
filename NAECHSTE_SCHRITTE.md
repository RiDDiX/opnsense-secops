# Nächste Schritte - OPNsense Security Auditor

## ✅ Was ist fertig

Das komplette OPNsense Security Audit Tool ist einsatzbereit mit:

- ✅ Firewall-Regel-Analyse
- ✅ Port-Scanner mit kritischen Port-Datenbank
- ✅ DNS-Sicherheits-Analyse
- ✅ VLAN-Segmentierungs-Prüfung
- ✅ Netzwerk-Device-Discovery
- ✅ Konfigurierbares Ausnahmen-System
- ✅ Multi-Format-Reports (HTML/JSON/Text)
- ✅ Docker-Integration
- ✅ Automation-Scripts
- ✅ Vollständige Dokumentation

## 🚀 Setup-Anleitung (10 Minuten)

### Schritt 1: OPNsense API-Keys erstellen (2 Min)

1. In OPNsense einloggen
2. Navigiere zu: **System > Access > Users**
3. Wähle Admin-User
4. Scrolle zu **API keys**
5. Klicke **"+"** für neuen Key
6. **Notiere API Key und Secret**

### Schritt 2: Projekt konfigurieren (3 Min)

```bash
cd /Users/maximilianhammerschmid/Documents/projekte/opnsensedashboardtester

# .env erstellen
cp .env.example .env

# .env editieren
nano .env
```

Trage ein:
```env
OPNSENSE_HOST=192.168.1.1           # Deine OPNsense IP
OPNSENSE_API_KEY=<dein-key>
OPNSENSE_API_SECRET=<dein-secret>
SCAN_NETWORK=192.168.1.0/24         # Dein Netzwerk
```

### Schritt 3: Ausnahmen konfigurieren (optional, 2 Min)

```bash
nano config/exceptions.yaml
```

Füge deine Homelab-Services hinzu:
```yaml
port_exceptions:
  - port: 8080
    host: "192.168.1.100"
    reason: "Home Assistant"
  - port: 32400
    host: "192.168.1.105"
    reason: "Plex Media Server"
  # Weitere Services...
```

### Schritt 4: Ersten Scan durchführen (3 Min)

```bash
# Einfachste Methode
./run.sh

# Oder mit Docker Compose
docker-compose build
docker-compose up
```

### Schritt 5: Reports ansehen (2 Min)

```bash
# HTML Report im Browser öffnen
open reports/security_audit_*.html

# Oder Text-Report in Terminal
cat reports/security_audit_*.txt
```

## 📋 Empfohlene Konfiguration für Homelab

### Typische Port-Ausnahmen

```yaml
port_exceptions:
  # Web-Services
  - port: 80
    reason: "HTTP Services (Auto-Redirect zu HTTPS)"
  - port: 443
    reason: "HTTPS Services (Reverse Proxy)"

  # Home Automation
  - port: 8123
    host: "192.168.1.101"
    reason: "Home Assistant"
  - port: 1883
    host: "192.168.1.101"
    reason: "MQTT Broker"

  # Media Server
  - port: 32400
    host: "192.168.1.105"
    reason: "Plex Media Server"
  - port: 8096
    host: "192.168.1.106"
    reason: "Jellyfin"

  # Monitoring & Management
  - port: 3000
    host: "192.168.1.120"
    reason: "Grafana Dashboard"
  - port: 9090
    host: "192.168.1.120"
    reason: "Prometheus"
  - port: 9000
    host: "192.168.1.110"
    reason: "Portainer"

  # Storage
  - port: 5000
    host: "192.168.1.130"
    reason: "Synology NAS"

  # Smart Home
  - port: 8081
    host: "192.168.1.140"
    reason: "UniFi Controller"
```

### Host-Ausnahmen

```yaml
host_exceptions:
  - ip: "192.168.1.1"
    reason: "OPNsense selbst"
  - ip: "192.168.1.254"
    reason: "Backup Gateway"
```

### Scan-Optionen für Homelab

```yaml
scan_options:
  aggressive_scan: false          # false für schnellere Scans
  port_scan_timeout: 300          # 5 Minuten
  max_parallel_scans: 10          # Balance zwischen Speed und Load
  skip_ping: false                # true wenn Hosts Ping blockieren
```

## 🔄 Automatisierung einrichten

### Option 1: Wöchentlicher Scan (Sonntags 2 Uhr)

```bash
# Cronjob editieren
crontab -e

# Hinzufügen:
0 2 * * 0 /Users/maximilianhammerschmid/Documents/projekte/opnsensedashboardtester/scripts/scheduled-scan.sh
```

### Option 2: Täglicher Scan (3 Uhr nachts)

```bash
0 3 * * * /Users/maximilianhammerschmid/Documents/projekte/opnsensedashboardtester/scripts/scheduled-scan.sh
```

### Option 3: Monatlicher Scan (Erster des Monats)

```bash
0 1 1 * * /Users/maximilianhammerschmid/Documents/projekte/opnsensedashboardtester/scripts/scheduled-scan.sh
```

## 📧 Benachrichtigungen einrichten

### Email bei kritischen Findings

Editiere `scripts/scheduled-scan.sh` und füge nach Zeile 45 hinzu:

```bash
if [ "$CRITICAL_COUNT" -gt 0 ]; then
    log "⚠️  WARNING: $CRITICAL_COUNT critical security issues found!"

    # Email senden
    echo "OPNsense Security Alert: $CRITICAL_COUNT kritische Findings gefunden!" | \
        mail -s "⚠️ OPNsense Security Alert" deine@email.de
fi
```

### Slack-Benachrichtigung

```bash
SLACK_WEBHOOK="https://hooks.slack.com/services/DEIN/WEBHOOK/URL"

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"⚠️ OPNsense: $CRITICAL_COUNT kritische Security-Issues!\"}" \
        "$SLACK_WEBHOOK"
fi
```

## 🎯 Erste Schritte nach dem ersten Scan

### 1. Report analysieren

Öffne den HTML-Report und schaue dir an:
- ❗ Kritische Findings zuerst
- 🔍 Welche Services sind exponiert
- 🛡️ Welche Firewall-Regeln problematisch sind
- 🌐 DNS-Konfiguration-Status

### 2. Bekannte Services freigeben

Für jeden gewollten offenen Port:
```yaml
port_exceptions:
  - port: <port-nummer>
    host: "<ip-adresse>"
    reason: "<service-name>"
```

### 3. Kritische Issues beheben

Arbeite die kritischen Findings ab:
1. Unsichere Firewall-Regeln anpassen
2. Unnötige offene Ports schließen
3. DNS-Security aktivieren (DNSSEC, Rebinding Protection)
4. VLAN-Segmentierung verbessern

### 4. Zweiten Scan durchführen

Nach Änderungen:
```bash
./run.sh
```

Dann vergleichen:
```bash
./scripts/compare-scans.sh reports/security_audit_[alt].json reports/security_audit_[neu].json
```

## 📊 Langzeit-Monitoring einrichten

### 1. Wöchentliche Scans automatisieren

```bash
crontab -e
# Jeden Sonntag um 2 Uhr
0 2 * * 0 /path/to/scripts/scheduled-scan.sh
```

### 2. Monatlichen Vergleichsbericht

Erstelle Script `monthly-report.sh`:
```bash
#!/bin/bash
LATEST=$(ls -t reports/security_audit_*.json | head -n1)
MONTH_AGO=$(ls -t reports/security_audit_*.json | sed -n '31p')

if [ -f "$LATEST" ] && [ -f "$MONTH_AGO" ]; then
    ./scripts/compare-scans.sh "$MONTH_AGO" "$LATEST" | \
        mail -s "Monatlicher OPNsense Security Report" admin@example.com
fi
```

### 3. CSV-Export für Trend-Analyse

```bash
# History exportieren
echo "Date,Total,Critical,High,Medium,Low" > reports/history.csv

for file in reports/security_audit_*.json; do
    DATE=$(basename "$file" | sed 's/security_audit_\(.*\)\.json/\1/')
    TOTAL=$(grep -o '"total_findings": [0-9]*' "$file" | grep -o '[0-9]*')
    CRITICAL=$(grep -o '"critical": [0-9]*' "$file" | head -n1 | grep -o '[0-9]*')
    HIGH=$(grep -o '"high": [0-9]*' "$file" | head -n1 | grep -o '[0-9]*')
    MEDIUM=$(grep -o '"medium": [0-9]*' "$file" | head -n1 | grep -o '[0-9]*')
    LOW=$(grep -o '"low": [0-9]*' "$file" | head -n1 | grep -o '[0-9]*')

    echo "$DATE,$TOTAL,$CRITICAL,$HIGH,$MEDIUM,$LOW" >> reports/history.csv
done
```

Dann in Excel/Google Sheets importieren für Grafiken.

## 🔧 Troubleshooting

### Problem: Container startet nicht

```bash
# Logs prüfen
docker-compose logs

# Neu bauen ohne Cache
docker-compose build --no-cache
```

### Problem: API-Verbindung schlägt fehl

```bash
# OPNsense erreichbar?
ping 192.168.1.1

# API-Keys korrekt in .env?
cat .env | grep API

# Firewall-Regel für API-Zugriff?
# In OPNsense: Firewall > Rules > LAN
# Erlaube Zugriff auf Port 443 von Scan-Host zu OPNsense
```

### Problem: Port-Scan liefert keine Ergebnisse

```bash
# Container mit erweiterten Rechten
docker-compose run --cap-add=NET_ADMIN --cap-add=NET_RAW opnsense-auditor

# Oder skip_ping aktivieren in exceptions.yaml
scan_options:
  skip_ping: true
```

### Problem: Zu viele False Positives

Nutze `exceptions.yaml` um bekannte Services freizugeben.

## 📚 Weiterführende Schritte

### 1. VLAN-Segmentierung verbessern

Basierend auf den Empfehlungen:
- VLAN 10: Management
- VLAN 20: Server
- VLAN 30: Workstations
- VLAN 40: IoT
- VLAN 50: Guest

In OPNsense: Interfaces > Other Types > VLAN

### 2. DNS-Security härten

- DNSSEC aktivieren (Services > Unbound DNS > DNSSEC)
- DNS over TLS konfigurieren (Services > Unbound DNS > Query Forwarding)
- Rebinding Protection (Services > Unbound DNS > Advanced)
- ACLs setzen (Services > Unbound DNS > Access Lists)

### 3. Firewall-Regeln optimieren

- Default Deny Policy
- Logging für WAN-Regeln
- Spezifische Source/Destination
- Regelmäßige Review

### 4. Monitoring integrieren

Integriere in dein bestehendes Monitoring:
```python
import json

with open('reports/security_audit_latest.json') as f:
    audit = json.load(f)

if audit['summary']['critical'] > 0:
    # Alert an Monitoring-System
    send_alert(f"Critical: {audit['summary']['critical']}")
```

## 🎓 Best Practices

1. **Wöchentliche Scans** - Regelmäßigkeit ist wichtig
2. **Trend-Analyse** - Verfolge Änderungen über Zeit
3. **Schnelle Reaktion** - Kritische Findings sofort beheben
4. **Dokumentation** - Ausnahmen begründen
5. **Review** - Monatlich Regeln und Ausnahmen prüfen

## 🚨 Wichtige Sicherheitshinweise

1. ⚠️ **Nur in eigenen Netzwerken** - Port-Scanning ohne Erlaubnis ist illegal
2. 🔒 **API-Keys sicher** - Niemals in Git committen
3. 📊 **Reports schützen** - Enthalten sensible Netzwerk-Informationen
4. 🛡️ **Read-Only** - Tool macht keine Änderungen an OPNsense
5. ⏰ **Off-Hours scannen** - Reduziert Netzwerklast

## 💡 Tipps für maximale Effizienz

1. **Erste Scans detailliert** - Lerne dein Netzwerk kennen
2. **Ausnahmen dokumentieren** - Mit aussagekräftigen Reasons
3. **Automatisierung** - Spare Zeit mit Cronjobs
4. **Reports archivieren** - Für Compliance und Audits
5. **Regelmäßige Updates** - Docker Image neu bauen für Updates

## 📞 Hilfe & Support

- 📖 Vollständige Doku: `README.md`
- 🚀 Schnellstart: `QUICKSTART.md`
- 🏗️ Architektur: `PROJEKTSTRUKTUR.md`
- ✨ Features: `FEATURES.md`
- 🔧 Scripts: `scripts/README.md`

## ✅ Checkliste für Produktiv-Betrieb

- [ ] OPNsense API-Keys erstellt
- [ ] .env konfiguriert
- [ ] Erster Test-Scan durchgeführt
- [ ] Ausnahmen für bekannte Services konfiguriert
- [ ] HTML-Report analysiert
- [ ] Kritische Findings behoben
- [ ] Zweiter Scan zur Verifizierung
- [ ] Automatisierung eingerichtet (Cronjob)
- [ ] Benachrichtigungen konfiguriert
- [ ] Dokumentiert welche Ausnahmen warum existieren
- [ ] Langzeit-Monitoring aktiv

## 🎉 Viel Erfolg!

Du hast jetzt ein professionelles OPNsense Security Audit Tool!

Bei Fragen oder Problemen:
1. Prüfe die Logs: `docker-compose logs`
2. Lies die Dokumentation
3. Überprüfe die Konfiguration

**Happy Auditing! 🔒**
