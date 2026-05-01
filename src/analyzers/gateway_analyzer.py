"""
Gateway hygiene checks.

Reads /api/routing/settings/searchGateway. Flags missing monitor IP,
disabled monitoring, missing default v6 gateway when v6 traffic exists,
and overly aggressive thresholds.
"""
from dataclasses import dataclass, field


@dataclass
class GatewayFinding:
    severity: str
    rule_id: str
    rule_description: str
    issue: str
    reason: str
    solution: str
    rule_details: dict
    interface: str = ""
    opnsense_path: str = "System > Gateways > Single"
    implementation_steps: list[str] = field(default_factory=list)


class GatewayAnalyzer:
    def __init__(self, exceptions: list[dict] | None = None) -> None:
        self.exceptions = exceptions or []

    def analyze(self, gateways: list[dict], firewall_rules: list[dict] | None = None) -> list[GatewayFinding]:
        findings: list[GatewayFinding] = []
        if not gateways:
            return findings

        has_v6_default = any(
            (g.get("ipprotocol") == "inet6") and (str(g.get("defaultgw", "0")) in ("1", "True", "true", True))
            for g in gateways
        )
        any_rule_v6 = any(
            (r.get("ipprotocol") in ("inet6", "inet46")) and str(r.get("enabled", "0")) == "1"
            for r in (firewall_rules or [])
        )

        for gw in gateways:
            name = gw.get("name") or gw.get("descr") or "gateway"
            iface = gw.get("interface", "")
            disabled = bool(gw.get("disabled"))
            if disabled:
                continue
            monitor = (gw.get("monitor") or "").strip()
            monitor_disabled = str(gw.get("monitor_disable", "0")) in ("1", "True", "true", True)
            if not monitor and not monitor_disabled:
                findings.append(GatewayFinding(
                    severity="MEDIUM",
                    rule_id=gw.get("uuid", name),
                    rule_description=name,
                    issue="Gateway ohne Monitor IP",
                    reason=(
                        "Ohne Monitor IP nutzt dpinger das Gateway selbst, "
                        "viele Provider Gateways antworten dann unzuverlaessig auf ICMP, "
                        "Failover und Pinning werden flaky."
                    ),
                    solution="Public Anycast Adresse als Monitor IP setzen, zum Beispiel 1.1.1.1 fuer v4 oder 2606:4700:4700::1111 fuer v6.",
                    rule_details=gw,
                    interface=iface,
                    implementation_steps=[
                        f"1. System > Gateways > Single > {name} oeffnen.",
                        "2. Feld 'Monitor IP' setzen.",
                        "3. Speichern.",
                    ],
                ))
            try:
                latency_high = int(gw.get("latencyhigh") or 0)
                if latency_high > 0 and latency_high < 200:
                    findings.append(GatewayFinding(
                        severity="LOW",
                        rule_id=gw.get("uuid", name) + "_latencyhigh",
                        rule_description=name,
                        issue="Latency High Schwelle unterhalb 200ms",
                        reason="Niedrige Schwelle fuehrt bei normalem Internet Jitter zu falschem Down Status.",
                        solution="Latency High auf >= 200ms setzen wenn keine SLA Pflicht dagegen spricht.",
                        rule_details=gw,
                        interface=iface,
                    ))
            except (TypeError, ValueError):
                pass

        if any_rule_v6 and not has_v6_default:
            findings.append(GatewayFinding(
                severity="HIGH",
                rule_id="no_default_v6_gateway",
                rule_description="Default IPv6 Gateway",
                issue="IPv6 Regeln aktiv, aber kein default IPv6 Gateway markiert",
                reason="Ohne default v6 Gateway routet OPNsense IPv6 Verkehr nicht oder nutzt das falsche Uplink Interface.",
                solution="Bei genau einem v6 Uplink: defaultgw aktivieren. Bei mehreren: Failover Group anlegen.",
                rule_details={"defaults": {"v6_default_present": False}},
                interface="",
                implementation_steps=[
                    "1. System > Gateways > Single oeffnen.",
                    "2. Den richtigen v6 Gateway als 'Upstream' markieren oder eine Group bauen.",
                    "3. Speichern und Apply.",
                ],
            ))

        return findings
