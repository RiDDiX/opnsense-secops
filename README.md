# OPNsense Security Auditor

A comprehensive security audit tool for OPNsense firewalls. Automatically analyzes firewall rules, open ports, DNS configuration, VLAN segmentation and creates detailed security reports with concrete remediation suggestions.

## Features

### 🔥 Firewall Rule Analysis
- Detects "Any-to-Any" rules
- Identifies insecure WAN rules
- Checks for missing logging configuration
- Analyzes NAT port forwarding rules
- Warns about overly permissive protocol rules

### 🔓 Port Security Scanner
- Scans all devices on the network for open ports
- Identifies critical services (SSH, RDP, databases, etc.)
- Checks against configurable port whitelist
- Service detection and version scanning
- Parallel scanning for better performance

### 🌐 DNS Security Analysis
- DNSSEC status check
- DNS rebinding protection
- DNS over TLS (DoT) configuration
- Open resolver detection
- DNS amplification tests
- Access control list verification

### 🔀 VLAN Segmentation Analysis
- Checks VLAN isolation
- Detects missing management VLANs
- Analyzes guest network isolation
- Recommends best-practice VLAN structure
- Inter-VLAN routing security

### 📊 Network Discovery
- Automatic device detection
- VLAN assignment for all devices
- MAC vendor lookup
- Network topology mapping
- Integration with DHCP leases and ARP table

### 📄 Reporting
- **HTML Reports**: Interactive, color-coded reports
- **JSON Reports**: Machine-readable data for integration
- **Text Reports**: Simple readability for terminal/email
- Severity-based prioritization
- Concrete remediation suggestions for each finding
- Executive summary dashboard

## Installation

### Prerequisites

1. **Generate OPNsense API Keys**:
   - In OPNsense: System > Access > Users
   - Select/create user
   - Generate API keys and note them down

2. **Docker & Docker Compose installed**

### Setup

1. Clone repository or copy files:
```bash
cd /path/to/opnsense-secops
```

2. Configure environment variables:
```bash
cp .env.example .env
nano .env
```

Enter your OPNsense credentials:
```env
OPNSENSE_HOST=192.168.1.1
OPNSENSE_API_KEY=your_api_key
OPNSENSE_API_SECRET=your_api_secret
SCAN_NETWORK=192.168.1.0/24
```

3. Customize configuration (optional):
```bash
# Allow ports/services for your homelab
nano config/exceptions.yaml
```

Example for homelab services:
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

4. Build Docker image:
```bash
docker-compose build
```

## Usage

### Simple Scan
```bash
docker-compose up
```

### Run as Script
```bash
docker-compose run --rm opnsense-auditor
```

### Scan with Additional Networks
```bash
ADDITIONAL_NETWORKS="192.168.2.0/24,192.168.10.0/24" docker-compose up
```

### View Reports
Reports are saved in the `reports/` directory:
- `security_audit_YYYYMMDD_HHMMSS.html` - HTML report (open in browser)
- `security_audit_YYYYMMDD_HHMMSS.json` - JSON data
- `security_audit_YYYYMMDD_HHMMSS.txt` - Text report
- `audit.log` - Detailed logs

## Configuration

### Security Rules (`config/rules.yaml`)

Defines which ports and configurations are considered critical:

```yaml
critical_ports:
  - port: 22
    name: "SSH"
    severity: "HIGH"
    reason: "SSH should not be publicly accessible"
```

### Exceptions (`config/exceptions.yaml`)

#### Port Exceptions for Homelab
If you expose services publicly:
```yaml
port_exceptions:
  - port: 443
    host: "192.168.1.100"
    reason: "Reverse proxy for web services"
  - port: 8123
    host: "192.168.1.101"
    reason: "Home Assistant"
```

#### Firewall Rule Exceptions
If you intentionally have a rule that would normally trigger a warning:
```yaml
firewall_exceptions:
  - rule_id: "uuid-of-rule"
    reason: "Required for VPN access"
```

#### DNS Exceptions
```yaml
dns_exceptions:
  - check: "dnssec_enabled"
    reason: "ISP does not support DNSSEC"
```

#### VLAN Exceptions
If VLANs should intentionally communicate:
```yaml
vlan_exceptions:
  - check: "vlan_isolation"
    vlans: [10, 20]
    reason: "Management needs to access servers"
```

#### Scan Options
```yaml
scan_options:
  aggressive_scan: false        # More details, takes longer
  port_scan_timeout: 300        # Timeout in seconds
  max_parallel_scans: 10        # Number of parallel scans
  skip_ping: false              # Scan hosts even if ping fails
```

#### Report Options
```yaml
report_options:
  output_format: "all"          # json, html, text, all
  detail_level: "normal"        # minimal, normal, verbose
  critical_only: false          # Only critical findings
  include_solutions: true       # Include remediation suggestions
```

## Example: Homelab Configuration

Typical homelab exceptions:

```yaml
port_exceptions:
  # Web Services
  - port: 80
    reason: "HTTP Services (automatic HTTPS redirect)"
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
    reason: "OPNsense itself"
```

## Recommended VLAN Structure

The tool recommends the following VLAN segmentation:

| VLAN ID | Name | Purpose |
|---------|------|---------|
| 10 | Management | OPNsense, Switches, APs |
| 20 | Server | Servers & Services |
| 30 | Workstations | User Workstations |
| 40 | IoT | IoT Devices (isolated) |
| 50 | Guest | Guest Network (isolated) |
| 99 | DMZ | Public facing services |

## Security Checks in Detail

### Firewall
- ✅ No Any-to-Any rules
- ✅ Inbound WAN traffic restricted
- ✅ Logging enabled for important rules
- ✅ Specific protocols instead of "any"
- ✅ NAT port forwards only for necessary services
- ✅ Source restriction for port forwards

### Ports
- ✅ SSH (22) not publicly accessible
- ✅ RDP (3389) not publicly accessible
- ✅ Databases not publicly reachable
- ✅ Docker API not exposed
- ✅ Admin interfaces protected
- ✅ SMB/NetBIOS blocked

### DNS
- ✅ DNSSEC enabled
- ✅ DNS rebinding protection
- ✅ DNS over TLS configured
- ✅ No open resolver
- ✅ Access lists configured
- ✅ Response rate limiting

### VLANs
- ✅ Dedicated management VLAN
- ✅ Guest network isolated
- ✅ IoT devices segmented
- ✅ Inter-VLAN routing restricted
- ✅ VLAN 1 not used

## Troubleshooting

### Container Lacks Permission for Port Scan
```bash
# Start Docker with extended permissions
docker-compose run --cap-add=NET_ADMIN --cap-add=NET_RAW opnsense-auditor
```

### API Connection Fails
- Check API keys in OPNsense
- Verify firewall rule for API access
- Test network connectivity: `ping <opnsense-ip>`

### Scan Takes Too Long
Adjust `scan_options`:
```yaml
scan_options:
  max_parallel_scans: 20  # More parallel (caution: network load)
  port_scan_timeout: 120  # Shorter timeout
```

### Too Many False Positives
Use `exceptions.yaml` to exclude known/intended configurations.

## Automation

### Cronjob for Regular Scans
```bash
# Daily at 3 AM
0 3 * * * cd /path/to/opnsense-secops && docker-compose run --rm opnsense-auditor
```

### Integration with Monitoring
JSON reports can be integrated into monitoring systems:
```python
import json

with open('reports/security_audit_latest.json') as f:
    audit = json.load(f)

if audit['summary']['critical'] > 0:
    send_alert("Critical security issues found!")
```

## Security Notes

- 🔒 Never commit API keys to Git
- 🔒 Docker container runs with `network_mode: host` for network scanning
- 🔒 Only run tool in trusted networks
- 🔒 Reports may contain sensitive network information
- 🔒 Regular scans recommended (weekly/monthly)

## Contributing

Feedback and improvement suggestions welcome! Open an issue or pull request.

## License

MIT License - Free to use for private and commercial projects.

## Important Notice

This tool is intended for **authorized security testing**. Only use it on networks you have permission to test. Port scanning without authorization may be illegal.

---

**Built for secure homelab and enterprise networks with OPNsense** 🔒
