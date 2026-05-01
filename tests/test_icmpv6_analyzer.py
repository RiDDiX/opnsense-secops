"""ICMPv6 audit branch in FirewallAnalyzer."""
from src.analyzers.firewall_analyzer import FirewallAnalyzer


def _analyzer():
    return FirewallAnalyzer({"firewall_rules": {"critical_ports": []}}, [])


def _r(**over):
    base = {
        "uuid": "x",
        "enabled": "1",
        "action": "pass",
        "direction": "in",
        "ipprotocol": "inet6",
        "protocol": "icmpv6",
        "interface": "wan",
        "icmp6type": "",
        "source_net": "any",
        "destination_net": "any",
        "destination_port": "",
        "description": "icmpv6 test",
        "log": "0",
    }
    base.update(over)
    return base


def test_icmpv6_pass_without_type_high():
    findings = _analyzer()._analyze_icmpv6_rules([_r()])
    assert findings and findings[0].severity == "HIGH"


def test_icmpv6_default_types_no_finding():
    rule = _r(icmp6type="1,2,3,4,135,136")
    findings = _analyzer()._analyze_icmpv6_rules([rule])
    assert findings == []


def test_icmpv6_unexpected_type_medium():
    rule = _r(icmp6type="139")
    findings = _analyzer()._analyze_icmpv6_rules([rule])
    assert findings and findings[0].severity == "MEDIUM"
