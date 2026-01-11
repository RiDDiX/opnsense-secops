"""
Report Generator
Generates comprehensive security audit reports in multiple formats
"""
import json
import logging
from typing import Dict, List, Any
from datetime import datetime
from jinja2 import Template
from tabulate import tabulate

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security audit reports"""

    def __init__(self, report_options: Dict):
        self.options = report_options
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_reports(self, audit_results: Dict, output_dir: str = "/app/reports") -> List[str]:
        """Generate reports in configured formats"""
        generated_files = []
        output_format = self.options.get("output_format", "all")

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")

        if output_format in ["json", "all"]:
            json_file = f"{output_dir}/security_audit_{timestamp_str}.json"
            self._generate_json_report(audit_results, json_file)
            generated_files.append(json_file)

        if output_format in ["html", "all"]:
            html_file = f"{output_dir}/security_audit_{timestamp_str}.html"
            self._generate_html_report(audit_results, html_file)
            generated_files.append(html_file)

        if output_format in ["text", "all"]:
            text_file = f"{output_dir}/security_audit_{timestamp_str}.txt"
            self._generate_text_report(audit_results, text_file)
            generated_files.append(text_file)

        return generated_files

    def _generate_json_report(self, results: Dict, output_file: str):
        """Generate JSON report"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str, ensure_ascii=False)
            logger.info(f"JSON report generated: {output_file}")
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")

    def _generate_text_report(self, results: Dict, output_file: str):
        """Generate text report"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(self._format_text_report(results))
            logger.info(f"Text report generated: {output_file}")
        except Exception as e:
            logger.error(f"Failed to generate text report: {e}")

    def _format_text_report(self, results: Dict) -> str:
        """Format results as text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("OPNsense Security Audit Report")
        lines.append("=" * 80)
        lines.append(f"Generated: {self.timestamp}")
        lines.append(f"OPNsense Host: {results.get('opnsense_host', 'Unknown')}")
        lines.append("")

        # Executive Summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 80)
        summary = results.get("summary", {})
        lines.append(f"Total Findings: {summary.get('total_findings', 0)}")
        lines.append(f"  Critical: {summary.get('critical', 0)}")
        lines.append(f"  High:     {summary.get('high', 0)}")
        lines.append(f"  Medium:   {summary.get('medium', 0)}")
        lines.append(f"  Low:      {summary.get('low', 0)}")
        lines.append("")

        # Firewall Findings
        firewall_findings = results.get("firewall_findings", [])
        if firewall_findings:
            lines.append("FIREWALL RULE FINDINGS")
            lines.append("-" * 80)
            for finding in firewall_findings:
                lines.append(f"\n[{finding.get('severity', 'UNKNOWN')}] {finding.get('issue', 'Unknown Issue')}")
                lines.append(f"Rule: {finding.get('rule_description', 'Unknown')}")
                lines.append(f"Reason: {finding.get('reason', '')}")
                if self.options.get("include_solutions", True):
                    lines.append(f"Solution: {finding.get('solution', '')}")
                lines.append("")

        # Port Scan Findings
        port_findings = results.get("port_findings", [])
        if port_findings:
            lines.append("\nPORT SECURITY FINDINGS")
            lines.append("-" * 80)
            for finding in port_findings:
                lines.append(f"\n[{finding.get('severity', 'UNKNOWN')}] {finding.get('issue', 'Unknown Issue')}")
                lines.append(f"Host: {finding.get('host', 'Unknown')} | Port: {finding.get('port', 'Unknown')} ({finding.get('service', 'unknown')})")
                lines.append(f"Reason: {finding.get('reason', '')}")
                if self.options.get("include_solutions", True):
                    lines.append(f"Solution: {finding.get('solution', '')}")
                lines.append("")

        # DNS Findings
        dns_findings = results.get("dns_findings", [])
        if dns_findings:
            lines.append("\nDNS SECURITY FINDINGS")
            lines.append("-" * 80)
            for finding in dns_findings:
                lines.append(f"\n[{finding.get('severity', 'UNKNOWN')}] {finding.get('issue', 'Unknown Issue')}")
                lines.append(f"Check: {finding.get('check', 'Unknown')}")
                lines.append(f"Reason: {finding.get('reason', '')}")
                if self.options.get("include_solutions", True):
                    lines.append(f"Solution: {finding.get('solution', '')}")
                lines.append("")

        # VLAN Findings
        vlan_findings = results.get("vlan_findings", [])
        if vlan_findings:
            lines.append("\nVLAN SECURITY FINDINGS")
            lines.append("-" * 80)
            for finding in vlan_findings:
                lines.append(f"\n[{finding.get('severity', 'UNKNOWN')}] {finding.get('issue', 'Unknown Issue')}")
                lines.append(f"VLAN: {finding.get('vlan_name', 'Unknown')} (ID: {finding.get('vlan_id', 'Unknown')})")
                lines.append(f"Reason: {finding.get('reason', '')}")
                if self.options.get("include_solutions", True):
                    lines.append(f"Solution: {finding.get('solution', '')}")
                lines.append("")

        # Network Map
        network_map = results.get("network_map", {})
        if network_map:
            lines.append("\nNETWORK DEVICE MAP")
            lines.append("-" * 80)
            for network, vlans in network_map.items():
                lines.append(f"\nNetwork: {network}")
                for vlan, devices in vlans.items():
                    lines.append(f"  VLAN: {vlan}")
                    for device in devices:
                        lines.append(f"    - {device.get('ip', 'Unknown')} ({device.get('hostname', 'Unknown')}) "
                                   f"- {device.get('vendor', 'Unknown')} - MAC: {device.get('mac', 'Unknown')}")
                        if device.get('open_ports'):
                            lines.append(f"      Open Ports: {', '.join(map(str, device['open_ports']))}")

        # Statistics
        stats = results.get("statistics", {})
        if stats:
            lines.append("\n\nSTATISTICS")
            lines.append("-" * 80)
            lines.append(f"Total Devices: {stats.get('total_devices', 0)}")
            lines.append(f"Active Devices: {stats.get('active_devices', 0)}")
            lines.append(f"Total Open Ports: {stats.get('total_open_ports', 0)}")

        lines.append("\n" + "=" * 80)
        lines.append("End of Report")
        lines.append("=" * 80)

        return "\n".join(lines)

    def _generate_html_report(self, results: Dict, output_file: str):
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OPNsense Security Audit Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-bottom: 30px; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 15px; border-left: 4px solid #3498db; padding-left: 10px; }
        h3 { color: #555; margin-top: 20px; margin-bottom: 10px; }
        .header-info { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .summary-card h3 { color: white; font-size: 2em; margin: 0; }
        .summary-card p { margin: 5px 0 0 0; opacity: 0.9; }
        .finding {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            background: #fafafa;
        }
        .finding-header {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }
        .severity {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-right: 15px;
            font-size: 0.9em;
        }
        .severity.CRITICAL { background: #e74c3c; color: white; }
        .severity.HIGH { background: #e67e22; color: white; }
        .severity.MEDIUM { background: #f39c12; color: white; }
        .severity.LOW { background: #95a5a6; color: white; }
        .finding-title { font-weight: bold; font-size: 1.1em; }
        .finding-detail { margin: 8px 0; }
        .finding-detail strong { color: #555; }
        .solution {
            background: #d5f4e6;
            border-left: 4px solid #27ae60;
            padding: 10px;
            margin-top: 10px;
            border-radius: 3px;
        }
        .device-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 0.9em;
        }
        .device-table th {
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
        }
        .device-table td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        .device-table tr:hover { background: #f8f9fa; }
        .network-section { margin-top: 20px; background: #f8f9fa; padding: 15px; border-radius: 5px; }
        .vlan-section { margin-left: 20px; margin-top: 10px; }
        footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #777;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 OPNsense Security Audit Report</h1>

        <div class="header-info">
            <strong>Generated:</strong> {{ timestamp }}<br>
            <strong>OPNsense Host:</strong> {{ opnsense_host }}
        </div>

        <h2>📊 Executive Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <h3>{{ summary.total_findings }}</h3>
                <p>Total Findings</p>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <h3>{{ summary.critical }}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);">
                <h3>{{ summary.high }}</h3>
                <p>High</p>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #fccb90 0%, #d57eeb 100%);">
                <h3>{{ summary.medium }}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);">
                <h3>{{ summary.low }}</h3>
                <p>Low</p>
            </div>
        </div>

        {% if firewall_findings %}
        <h2>🔥 Firewall Rule Findings</h2>
        {% for finding in firewall_findings %}
        <div class="finding">
            <div class="finding-header">
                <span class="severity {{ finding.severity }}">{{ finding.severity }}</span>
                <span class="finding-title">{{ finding.issue }}</span>
            </div>
            <div class="finding-detail"><strong>Rule:</strong> {{ finding.rule_description }}</div>
            <div class="finding-detail"><strong>Reason:</strong> {{ finding.reason }}</div>
            {% if include_solutions %}
            <div class="solution">
                <strong>💡 Solution:</strong> {{ finding.solution }}
            </div>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}

        {% if port_findings %}
        <h2>🔓 Port Security Findings</h2>
        {% for finding in port_findings %}
        <div class="finding">
            <div class="finding-header">
                <span class="severity {{ finding.severity }}">{{ finding.severity }}</span>
                <span class="finding-title">{{ finding.issue }}</span>
            </div>
            <div class="finding-detail"><strong>Host:</strong> {{ finding.host }}</div>
            <div class="finding-detail"><strong>Port:</strong> {{ finding.port }} ({{ finding.service }})</div>
            <div class="finding-detail"><strong>Reason:</strong> {{ finding.reason }}</div>
            {% if include_solutions %}
            <div class="solution">
                <strong>💡 Solution:</strong> {{ finding.solution }}
            </div>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}

        {% if dns_findings %}
        <h2>🌐 DNS Security Findings</h2>
        {% for finding in dns_findings %}
        <div class="finding">
            <div class="finding-header">
                <span class="severity {{ finding.severity }}">{{ finding.severity }}</span>
                <span class="finding-title">{{ finding.issue }}</span>
            </div>
            <div class="finding-detail"><strong>Check:</strong> {{ finding.check }}</div>
            <div class="finding-detail"><strong>Reason:</strong> {{ finding.reason }}</div>
            {% if include_solutions %}
            <div class="solution">
                <strong>💡 Solution:</strong> {{ finding.solution }}
            </div>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}

        {% if vlan_findings %}
        <h2>🔀 VLAN Security Findings</h2>
        {% for finding in vlan_findings %}
        <div class="finding">
            <div class="finding-header">
                <span class="severity {{ finding.severity }}">{{ finding.severity }}</span>
                <span class="finding-title">{{ finding.issue }}</span>
            </div>
            <div class="finding-detail"><strong>VLAN:</strong> {{ finding.vlan_name }} (ID: {{ finding.vlan_id }})</div>
            <div class="finding-detail"><strong>Reason:</strong> {{ finding.reason }}</div>
            {% if include_solutions %}
            <div class="solution">
                <strong>💡 Solution:</strong> {{ finding.solution }}
            </div>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}

        {% if statistics %}
        <h2>📈 Network Statistics</h2>
        <div class="finding">
            <div class="finding-detail"><strong>Total Devices:</strong> {{ statistics.total_devices }}</div>
            <div class="finding-detail"><strong>Active Devices:</strong> {{ statistics.active_devices }}</div>
            <div class="finding-detail"><strong>Total Open Ports:</strong> {{ statistics.total_open_ports }}</div>
        </div>
        {% endif %}

        <footer>
            <p>Generated by OPNsense Security Auditor | {{ timestamp }}</p>
        </footer>
    </div>
</body>
</html>
        """

        try:
            template = Template(html_template)
            html_content = template.render(
                timestamp=self.timestamp,
                opnsense_host=results.get("opnsense_host", "Unknown"),
                summary=results.get("summary", {}),
                firewall_findings=results.get("firewall_findings", []),
                port_findings=results.get("port_findings", []),
                dns_findings=results.get("dns_findings", []),
                vlan_findings=results.get("vlan_findings", []),
                statistics=results.get("statistics", {}),
                include_solutions=self.options.get("include_solutions", True)
            )

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {output_file}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

    def print_summary(self, results: Dict):
        """Print summary to console"""
        summary = results.get("summary", {})

        print("\n" + "=" * 80)
        print("OPNsense Security Audit - Summary")
        print("=" * 80)
        print(f"Total Findings: {summary.get('total_findings', 0)}")
        print(f"  🔴 Critical: {summary.get('critical', 0)}")
        print(f"  🟠 High:     {summary.get('high', 0)}")
        print(f"  🟡 Medium:   {summary.get('medium', 0)}")
        print(f"  🔵 Low:      {summary.get('low', 0)}")
        print("=" * 80 + "\n")
