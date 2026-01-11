# Quick Start Guide

## 1. OPNsense API Keys erstellen

1. In OPNsense einloggen
2. Navigiere zu: **System > Access > Users**
3. Wähle deinen Admin-User oder erstelle einen neuen
4. Scrolle runter zu **API keys**
5. Klicke auf **"+"** um einen neuen Key zu erstellen
6. **Kopiere API Key und Secret** (wird nur einmal angezeigt!)

## 2. Projekt Setup

```bash
# In das Projekt-Verzeichnis wechseln
cd opnsensedashboardtester

# .env Datei erstellen
cp .env.example .env

# .env editieren und deine Daten eintragen
nano .env
```

Trage ein:
```env
OPNSENSE_HOST=192.168.1.1
OPNSENSE_API_KEY=<dein-api-key>
OPNSENSE_API_SECRET=<dein-api-secret>
SCAN_NETWORK=192.168.1.0/24
```

## 3. Docker Image bauen

```bash
docker-compose build
```

## 4. Ersten Scan durchführen

```bash
docker-compose up
```

## 5. Reports ansehen

```bash
# HTML Report im Browser öffnen
open reports/security_audit_*.html

# Oder Text Report anzeigen
cat reports/security_audit_*.txt
```

## Optionale Konfiguration

### Homelab Services freigeben

Editiere `config/exceptions.yaml`:

```yaml
port_exceptions:
  - port: 8080
    host: "192.168.1.100"
    reason: "Home Assistant"
  - port: 32400
    host: "192.168.1.105"
    reason: "Plex"
```

### Mehrere Netzwerke scannen

```bash
ADDITIONAL_NETWORKS="192.168.2.0/24,10.0.0.0/24" docker-compose up
```

## Troubleshooting

**Problem:** API-Verbindung fehlgeschlagen
```bash
# OPNsense Erreichbarkeit testen
ping 192.168.1.1

# API Keys überprüfen
# Stelle sicher dass in .env keine Leerzeichen vor/nach dem = sind
```

**Problem:** Port-Scan schlägt fehl
```bash
# Mit erweiterten Berechtigungen ausführen
docker-compose run --cap-add=NET_ADMIN --cap-add=NET_RAW opnsense-auditor
```

**Problem:** Container startet nicht
```bash
# Logs anzeigen
docker-compose logs

# Container neu bauen
docker-compose build --no-cache
```

## Nächste Schritte

1. ✅ Ersten Scan durchgeführt
2. 📊 HTML-Report ansehen
3. 🔍 Findings analysieren
4. ⚙️ Exceptions für bekannte Services konfigurieren
5. 🔄 Regelmäßige Scans einrichten
6. 📖 Vollständige README.md lesen für Details

## Hilfe

Bei Fragen oder Problemen:
1. Prüfe die Logs: `docker-compose logs`
2. Lies die vollständige Dokumentation in `README.md`
3. Überprüfe deine Konfiguration in `config/`
