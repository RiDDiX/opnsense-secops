# Hilfs-Skripte

## scheduled-scan.sh

Führt einen automatisierten Security Scan durch. Geeignet für Cronjobs.

### Features
- ✅ Automatisches Logging
- ✅ Zusammenfassung der Findings
- ✅ Warnung bei kritischen Findings
- ✅ Automatische Bereinigung alter Reports (>30 Tage)

### Verwendung

**Manuell:**
```bash
./scripts/scheduled-scan.sh
```

**Als Cronjob (täglich um 3 Uhr):**
```bash
# Cronjob editieren
crontab -e

# Folgende Zeile hinzufügen:
0 3 * * * /path/to/opnsensedashboardtester/scripts/scheduled-scan.sh
```

**Wöchentlich (Sonntags um 2 Uhr):**
```bash
0 2 * * 0 /path/to/opnsensedashboardtester/scripts/scheduled-scan.sh
```

**Monatlich (am 1. um 1 Uhr):**
```bash
0 1 1 * * /path/to/opnsensedashboardtester/scripts/scheduled-scan.sh
```

### Logs ansehen
```bash
cat reports/scheduled_scan_*.log
```

### Benachrichtigung bei kritischen Findings

Erweitere das Skript um Benachrichtigungen:

**Email via sendmail:**
```bash
# In scheduled-scan.sh, nach Zeile mit "Critical security issues found":
echo "Critical findings: $CRITICAL_COUNT" | mail -s "OPNsense Security Alert" admin@example.com
```

**Slack Webhook:**
```bash
# In scheduled-scan.sh:
SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

send_slack_notification() {
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"⚠️ OPNsense Security Alert: $1\"}" \
        "$SLACK_WEBHOOK"
}

# Dann verwenden:
send_slack_notification "Critical security issues found: $CRITICAL_COUNT"
```

**Telegram:**
```bash
TELEGRAM_BOT_TOKEN="your_bot_token"
TELEGRAM_CHAT_ID="your_chat_id"

send_telegram() {
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" \
        -d text="$1"
}

send_telegram "⚠️ Critical security issues: $CRITICAL_COUNT"
```

---

## compare-scans.sh

Vergleicht zwei Security Scans um Änderungen zu erkennen.

### Verwendung

```bash
./scripts/compare-scans.sh reports/security_audit_20240101_030000.json reports/security_audit_20240108_030000.json
```

### Ausgabe-Beispiel
```
==========================================
Security Scan Comparison
==========================================
Old: reports/security_audit_20240101_030000.json
New: reports/security_audit_20240108_030000.json

Findings Comparison:
-------------------
Severity             Old        New     Change
--------             ---        ---     ------
Critical              12          8         -4
High                  23         25         +2
Total                 67         64         -3

✅ GOOD: Critical findings decreased by 4
⚠️  Total findings increased by 3
==========================================
```

### Automatischer wöchentlicher Vergleich

Erstelle einen Cronjob der wöchentlich vergleicht:

```bash
#!/bin/bash
# Vergleiche mit Scan von vor einer Woche

REPORTS_DIR="/path/to/reports"
LATEST=$(ls -t "$REPORTS_DIR"/security_audit_*.json | head -n1)
WEEK_AGO=$(ls -t "$REPORTS_DIR"/security_audit_*.json | sed -n '8p')  # Annahme: 1 Scan pro Tag

if [ -f "$LATEST" ] && [ -f "$WEEK_AGO" ]; then
    /path/to/scripts/compare-scans.sh "$WEEK_AGO" "$LATEST"
fi
```

---

## Weitere nützliche Kommandos

### Letzten Report ansehen
```bash
# HTML
open reports/security_audit_*.html | tail -n1

# JSON (formatiert)
cat reports/security_audit_*.json | tail -n1 | jq '.'

# Text
cat reports/security_audit_*.txt | tail -n1
```

### Nur kritische Findings anzeigen
```bash
cat reports/security_audit_*.json | tail -n1 | jq '[.firewall_findings[], .port_findings[], .dns_findings[], .vlan_findings[]] | map(select(.severity == "CRITICAL"))'
```

### Statistiken aller Scans
```bash
for file in reports/security_audit_*.json; do
    echo "$(basename $file):"
    grep -o '"total_findings": [0-9]*' "$file" | grep -o '[0-9]*'
done
```

### Reports als CSV exportieren
```bash
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

echo "✅ Exported to reports/history.csv"
```

### Docker Container aufräumen
```bash
# Alte Container entfernen
docker-compose down

# Images neu bauen
docker-compose build --no-cache

# Volumes aufräumen
docker volume prune
```

### Logs in Echtzeit verfolgen
```bash
docker-compose logs -f
```
