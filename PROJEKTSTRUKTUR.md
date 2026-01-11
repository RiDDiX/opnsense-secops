# Projektstruktur

```
opnsensedashboardtester/
│
├── config/                          # Konfigurationsdateien
│   ├── rules.yaml                   # Sicherheits-Regeln und Definitionen
│   └── exceptions.yaml              # Ausnahmen und Scan-Optionen
│
├── src/                             # Haupt-Quellcode
│   ├── __init__.py
│   ├── main.py                      # Hauptanwendung
│   ├── opnsense_client.py          # OPNsense API Client
│   ├── config_loader.py            # Konfigurations-Loader
│   ├── report_generator.py         # Report-Generator (HTML/JSON/Text)
│   │
│   └── analyzers/                   # Analyse-Module
│       ├── __init__.py
│       ├── firewall_analyzer.py    # Firewall-Regel-Analyse
│       ├── port_scanner.py         # Port-Scanner
│       ├── dns_analyzer.py         # DNS-Konfiguration-Analyse
│       ├── vlan_analyzer.py        # VLAN-Segmentierung-Analyse
│       └── network_discovery.py    # Netzwerk-Device-Discovery
│
├── reports/                         # Generierte Reports (git-ignored)
│   ├── security_audit_*.html
│   ├── security_audit_*.json
│   ├── security_audit_*.txt
│   └── audit.log
│
├── Dockerfile                       # Docker Image Definition
├── docker-compose.yml              # Docker Compose Konfiguration
├── requirements.txt                # Python Dependencies
├── .env.example                    # Beispiel Environment-Variablen
├── .env                            # Deine Environment-Variablen (git-ignored)
├── .gitignore                      # Git Ignore Regeln
│
├── README.md                        # Vollständige Dokumentation
├── QUICKSTART.md                   # Schnellstart-Anleitung
├── PROJEKTSTRUKTUR.md              # Diese Datei
└── run.sh                          # Convenience-Script zum Starten
```

## Modulbeschreibungen

### Core Module

#### `main.py`
- Haupteinstiegspunkt der Anwendung
- Orchestriert alle Analyzer
- Sammelt Daten von OPNsense
- Generiert finale Reports

#### `opnsense_client.py`
- REST API Client für OPNsense
- Endpoints für:
  - Firewall-Regeln
  - NAT-Regeln
  - VLANs
  - Interfaces
  - DNS-Konfiguration
  - DHCP-Leases
  - ARP-Tabelle

#### `config_loader.py`
- Lädt YAML-Konfigurationsdateien
- Validiert Konfiguration
- Stellt Zugriff auf Rules und Exceptions bereit

#### `report_generator.py`
- Generiert Reports in 3 Formaten:
  - HTML (interaktiv, farbcodiert)
  - JSON (maschinenlesbar)
  - Text (Terminal-friendly)
- Verwendet Jinja2 Templates für HTML

### Analyzer Module

#### `firewall_analyzer.py`
**Prüft:**
- Any-to-Any Regeln
- Unsichere WAN-Regeln
- Fehlende Logging-Aktivierung
- Zu permissive Protokoll-Regeln
- Kritische NAT Port-Forwards

**Output:** `List[FirewallFinding]`

#### `port_scanner.py`
**Funktionen:**
- Netzwerk-Scanning mit nmap
- Paralleles Scanning mehrerer Hosts
- Service-Detection
- Kritische Port-Identifikation

**Output:** `List[PortFinding]`

#### `dns_analyzer.py`
**Prüft:**
- DNSSEC Status
- DNS Rebinding Protection
- DNS over TLS
- Open Resolver
- ACL Konfiguration
- Amplification-Potential

**Output:** `List[DNSFinding]`

#### `vlan_analyzer.py`
**Prüft:**
- VLAN-Isolation
- Management VLAN
- Guest Network Isolation
- Best-Practice Segmentierung
- Inter-VLAN Routing

**Output:** `List[VLANFinding]`

#### `network_discovery.py`
**Funktionen:**
- Automatische Device-Discovery
- VLAN-Zuordnung
- MAC-Vendor-Lookup
- Netzwerk-Mapping
- Integration mit DHCP/ARP

**Output:** `List[NetworkDevice]`

## Konfigurationsdateien

### `rules.yaml`
Definiert Sicherheits-Standards:
- Kritische Ports (mit Severity-Level)
- Erlaubte Ports
- DNS-Sicherheits-Checks
- Firewall-Regel-Patterns
- VLAN-Sicherheits-Anforderungen
- Empfohlene Netzwerk-Segmentierung

### `exceptions.yaml`
Definiert Ausnahmen für:
- Spezifische Ports/Hosts
- Firewall-Regeln
- DNS-Checks
- VLAN-Konfigurationen
- Scan-Optionen
- Report-Optionen

## Docker Setup

### Dockerfile
- Base: Python 3.11 Slim
- Tools: nmap, dnsutils, net-tools
- Python-Pakete: siehe requirements.txt

### docker-compose.yml
- `network_mode: host` für Netzwerk-Scanning
- Volume-Mounts für Config und Reports
- Environment-Variablen aus .env

## Datenfluss

```
1. Start (main.py)
   ↓
2. Load Config (config_loader.py)
   ↓
3. Connect to OPNsense (opnsense_client.py)
   ↓
4. Collect Data
   - Firewall Rules
   - NAT Rules
   - VLANs
   - DNS Config
   - DHCP Leases
   - ARP Table
   ↓
5. Run Analyzers (parallel wo möglich)
   - firewall_analyzer
   - dns_analyzer
   - vlan_analyzer
   - network_discovery
   - port_scanner
   ↓
6. Aggregate Results
   ↓
7. Generate Reports (report_generator.py)
   - HTML
   - JSON
   - Text
   ↓
8. Output to reports/
```

## Erweiterbarkeit

### Neuen Analyzer hinzufügen

1. Erstelle `src/analyzers/new_analyzer.py`:
```python
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class NewFinding:
    severity: str
    issue: str
    reason: str
    solution: str

class NewAnalyzer:
    def __init__(self, rules_config: Dict, exceptions: List[Dict]):
        self.rules = rules_config
        self.exceptions = exceptions

    def analyze(self, data) -> List[NewFinding]:
        findings = []
        # Analyse-Logik hier
        return findings
```

2. Integriere in `main.py`:
```python
from analyzers.new_analyzer import NewAnalyzer

# In __init__:
self.new_analyzer = NewAnalyzer(self.rules, exceptions)

# In run_audit():
new_findings = self.new_analyzer.analyze(data)
results["new_findings"] = [asdict(f) for f in new_findings]
```

3. Erweitere `report_generator.py` für neue Findings

### Neue Rules/Checks hinzufügen

Editiere `config/rules.yaml`:
```yaml
your_new_check:
  setting: "value"
  severity: "HIGH"
  reason: "Warum wichtig"
  solution: "Wie beheben"
```

## Testing

### Manueller Test
```bash
# Lokales Testing ohne Docker
cd src
python -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt

export OPNSENSE_HOST=192.168.1.1
export OPNSENSE_API_KEY=...
export OPNSENSE_API_SECRET=...

python main.py
```

### Docker Test
```bash
docker-compose build
docker-compose run --rm opnsense-auditor
```

## Performance-Optimierung

### Paralleles Scanning
- `max_parallel_scans` in exceptions.yaml anpassen
- ThreadPoolExecutor in port_scanner.py

### Scan-Zeit reduzieren
- `port_scan_timeout` verringern
- `aggressive_scan: false`
- Host-Liste beschränken via `host_exceptions`

### Memory-Optimierung
- Große Netzwerke in Chunks scannen
- Stream-Processing für Reports

## Sicherheit

### Best Practices
- ✅ API Keys in .env (nicht in Git)
- ✅ SSL-Verifikation optional (self-signed certs)
- ✅ Read-only API-Zugriff ausreichend
- ✅ Reports enthalten sensible Daten (sicher speichern)
- ✅ Container läuft als non-root wo möglich

### API-Berechtigungen
Minimale OPNsense API-Berechtigungen:
- Firewall: Read
- Interfaces: Read
- Services: Read
- Diagnostics: Read
