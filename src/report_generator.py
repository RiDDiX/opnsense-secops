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
        """Generate HTML report with dark technical theme"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report // {{ opnsense_host }}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap');
        *{margin:0;padding:0;box-sizing:border-box}
        :root{
            --bg:#0a0e17;--surface:#111827;--card:#1a2235;--elevated:#232d42;
            --border:#2a3f5f;--text:#e8ecf4;--muted:#94a3b8;--dim:#64748b;
            --cyan:#06b6d4;--green:#10b981;--red:#ef4444;--orange:#f97316;--yellow:#eab308;
        }
        html{font-size:13px}
        body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}
        .container{max-width:1100px;margin:0 auto}
        .header{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:2rem;margin-bottom:1.5rem;display:flex;justify-content:space-between;align-items:center}
        .header h1{font-size:1.5rem;font-weight:600;display:flex;align-items:center;gap:.75rem}
        .header h1::before{content:'';width:8px;height:8px;background:var(--cyan);border-radius:50%;box-shadow:0 0 12px var(--cyan)}
        .meta{text-align:right;font-size:.85rem;color:var(--muted)}
        .meta strong{color:var(--text)}
        .metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:1.5rem}
        .metric{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.25rem;text-align:center;position:relative;overflow:hidden}
        .metric::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
        .metric.total::before{background:var(--cyan)}.metric.crit::before{background:var(--red)}
        .metric.high::before{background:var(--orange)}.metric.med::before{background:var(--yellow)}
        .metric.low::before{background:var(--dim)}
        .metric-val{font-size:2rem;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1}
        .metric.crit .metric-val{color:var(--red)}.metric.high .metric-val{color:var(--orange)}
        .metric.med .metric-val{color:var(--yellow)}.metric.low .metric-val{color:var(--dim)}
        .metric-label{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:.35rem}
        .score-box{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:1.5rem}
        .score-circle{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.75rem;font-weight:700;font-family:'JetBrains Mono',monospace;border:4px solid var(--cyan);color:var(--cyan)}
        .score-info h3{font-size:1rem;margin-bottom:.25rem}.score-info .grade{font-size:1.25rem;font-weight:700}
        .grade-a{color:var(--green)}.grade-b{color:var(--cyan)}.grade-c{color:var(--yellow)}.grade-d{color:var(--orange)}.grade-f{color:var(--red)}
        .section{background:var(--card);border:1px solid var(--border);border-radius:8px;margin-bottom:1.25rem;overflow:hidden}
        .section-header{padding:1rem 1.25rem;border-bottom:1px solid var(--border);font-weight:600;font-size:.95rem;display:flex;align-items:center;gap:.6rem}
        .section-header.crit{background:rgba(239,68,68,.1);color:var(--red)}
        .section-header.high{background:rgba(249,115,22,.1);color:var(--orange)}
        .section-header.med{background:rgba(234,179,8,.1);color:var(--yellow)}
        .section-header.low{background:rgba(100,116,139,.1);color:var(--dim)}
        .section-header .count{margin-left:auto;background:var(--elevated);padding:.2rem .6rem;border-radius:10px;font-size:.8rem;font-family:'JetBrains Mono',monospace}
        .findings{padding:1rem}
        .finding{background:var(--elevated);border:1px solid var(--border);border-radius:6px;padding:1rem 1.25rem;margin-bottom:.75rem}
        .finding:last-child{margin-bottom:0}
        .finding-title{font-weight:600;margin-bottom:.6rem;display:flex;align-items:center;gap:.5rem}
        .tag{font-size:.65rem;font-weight:600;text-transform:uppercase;padding:3px 8px;border-radius:4px;background:rgba(6,182,212,.15);color:var(--cyan);font-family:'JetBrains Mono',monospace}
        .finding-row{display:flex;gap:.5rem;font-size:.85rem;margin-bottom:.3rem}
        .finding-row .lbl{color:var(--muted);min-width:90px}
        .solution{background:rgba(16,185,129,.1);border-left:3px solid var(--green);padding:.75rem 1rem;border-radius:0 6px 6px 0;margin-top:.75rem;font-size:.85rem}
        .solution strong{color:var(--green);display:block;margin-bottom:.25rem}
        .steps{margin-top:.6rem;padding-left:1.25rem;color:var(--muted)}
        .steps li{margin-bottom:.25rem}
        .stats-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;padding:1rem}
        .stat-item{text-align:center}
        .stat-item .val{font-size:1.5rem;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--cyan)}
        .stat-item .lbl{font-size:.75rem;color:var(--muted);text-transform:uppercase}
        footer{text-align:center;padding:2rem 0 1rem;color:var(--dim);font-size:.8rem;border-top:1px solid var(--border);margin-top:2rem}
        @media print{body{background:#fff;color:#000}.container{max-width:100%}.metric,.section,.finding{break-inside:avoid}}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Security Audit Report</h1>
        <div class="meta">
            <div><strong>Target:</strong> {{ opnsense_host }}</div>
            <div><strong>Generated:</strong> {{ timestamp }}</div>
        </div>
    </div>

    <div class="metrics">
        <div class="metric total"><div class="metric-val">{{ summary.total_findings }}</div><div class="metric-label">Total</div></div>
        <div class="metric crit"><div class="metric-val">{{ summary.critical }}</div><div class="metric-label">Critical</div></div>
        <div class="metric high"><div class="metric-val">{{ summary.high }}</div><div class="metric-label">High</div></div>
        <div class="metric med"><div class="metric-val">{{ summary.medium }}</div><div class="metric-label">Medium</div></div>
        <div class="metric low"><div class="metric-val">{{ summary.low }}</div><div class="metric-label">Low</div></div>
    </div>

    {% if security_score %}
    <div class="score-box">
        <div class="score-circle">{{ security_score }}</div>
        <div class="score-info">
            <h3>Security Score</h3>
            <div class="grade grade-{{ security_grade|lower }}">Grade: {{ security_grade }}</div>
        </div>
    </div>
    {% endif %}

    {% if firewall_findings %}
    <div class="section">
        <div class="section-header crit">Firewall Findings<span class="count">{{ firewall_findings|length }}</span></div>
        <div class="findings">
        {% for f in firewall_findings %}
        <div class="finding">
            <div class="finding-title">{% if f.interface %}<span class="tag">{{ f.interface }}</span>{% endif %}{{ f.issue }}</div>
            <div class="finding-row"><span class="lbl">Rule:</span><span>{{ f.rule_description }}</span></div>
            <div class="finding-row"><span class="lbl">Details:</span><span>{{ f.reason }}</span></div>
            {% if f.opnsense_path %}<div class="finding-row"><span class="lbl">Path:</span><span style="font-family:'JetBrains Mono',monospace;font-size:.8rem">{{ f.opnsense_path }}</span></div>{% endif %}
            {% if include_solutions and f.solution %}<div class="solution"><strong>Recommendation</strong>{{ f.solution }}</div>{% endif %}
            {% if f.implementation_steps %}<ol class="steps">{% for s in f.implementation_steps %}<li>{{ s }}</li>{% endfor %}</ol>{% endif %}
        </div>
        {% endfor %}
        </div>
    </div>
    {% endif %}

    {% if port_findings %}
    <div class="section">
        <div class="section-header high">Port Security<span class="count">{{ port_findings|length }}</span></div>
        <div class="findings">
        {% for f in port_findings %}
        <div class="finding">
            <div class="finding-title">{{ f.issue }}</div>
            <div class="finding-row"><span class="lbl">Host:</span><span>{{ f.host }}</span></div>
            <div class="finding-row"><span class="lbl">Port:</span><span>{{ f.port }} ({{ f.service }})</span></div>
            <div class="finding-row"><span class="lbl">Details:</span><span>{{ f.reason }}</span></div>
            {% if include_solutions and f.solution %}<div class="solution"><strong>Recommendation</strong>{{ f.solution }}</div>{% endif %}
        </div>
        {% endfor %}
        </div>
    </div>
    {% endif %}

    {% if dns_findings %}
    <div class="section">
        <div class="section-header med">DNS Configuration<span class="count">{{ dns_findings|length }}</span></div>
        <div class="findings">
        {% for f in dns_findings %}
        <div class="finding">
            <div class="finding-title">{{ f.issue }}</div>
            <div class="finding-row"><span class="lbl">Check:</span><span>{{ f.check }}</span></div>
            <div class="finding-row"><span class="lbl">Details:</span><span>{{ f.reason }}</span></div>
            {% if include_solutions and f.solution %}<div class="solution"><strong>Recommendation</strong>{{ f.solution }}</div>{% endif %}
        </div>
        {% endfor %}
        </div>
    </div>
    {% endif %}

    {% if vlan_findings %}
    <div class="section">
        <div class="section-header med">VLAN Security<span class="count">{{ vlan_findings|length }}</span></div>
        <div class="findings">
        {% for f in vlan_findings %}
        <div class="finding">
            <div class="finding-title">{{ f.issue }}</div>
            <div class="finding-row"><span class="lbl">VLAN:</span><span>{{ f.vlan_name }} (ID: {{ f.vlan_id }})</span></div>
            <div class="finding-row"><span class="lbl">Details:</span><span>{{ f.reason }}</span></div>
            {% if include_solutions and f.solution %}<div class="solution"><strong>Recommendation</strong>{{ f.solution }}</div>{% endif %}
        </div>
        {% endfor %}
        </div>
    </div>
    {% endif %}

    {% if statistics %}
    <div class="section">
        <div class="section-header low">Network Statistics</div>
        <div class="stats-grid">
            <div class="stat-item"><div class="val">{{ statistics.total_devices }}</div><div class="lbl">Devices</div></div>
            <div class="stat-item"><div class="val">{{ statistics.active_devices }}</div><div class="lbl">Active</div></div>
            <div class="stat-item"><div class="val">{{ statistics.total_open_ports }}</div><div class="lbl">Open Ports</div></div>
        </div>
    </div>
    {% endif %}

    <footer>NetSec Auditor // Report generated {{ timestamp }}</footer>
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
                security_score=results.get("security_score"),
                security_grade=results.get("security_grade", "N/A"),
                firewall_findings=results.get("firewall_findings", []),
                port_findings=results.get("port_findings", []),
                dns_findings=results.get("dns_findings", []),
                vlan_findings=results.get("vlan_findings", []),
                vulnerability_findings=results.get("vulnerability_findings", []),
                system_findings=results.get("system_findings", []),
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
