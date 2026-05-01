"""IPv6 parity analyzer tests."""
from src.analyzers.ipv6_parity_analyzer import IPv6ParityAnalyzer


def _r(**over):
    base = {
        "uuid": "x",
        "enabled": "1",
        "action": "pass",
        "direction": "in",
        "ipprotocol": "inet",
        "protocol": "any",
        "interface": "lan",
        "interfaces": ["lan"],
        "source_net": "any",
        "source_port": "",
        "destination_net": "any",
        "destination_port": "",
        "description": "test",
    }
    base.update(over)
    return base


def test_default_allow_lan_v6_detected():
    rule = _r(
        ipprotocol="inet6",
        source_net="lan",
        destination_net="any",
        description="Default allow LAN IPv6 to any rule",
    )
    findings = IPv6ParityAnalyzer().analyze([rule])
    assert any(f.issue.startswith("Auto-Regel") for f in findings)
    assert findings[0].severity == "CRITICAL"
    assert findings[0].suggested_rule["rule"]["ipprotocol"] == "inet6"


def test_v4_pass_without_v6_sibling_low_when_iface_has_no_v6():
    v4 = _r(uuid="a", description="allow lan https",
            destination_port="443", protocol="tcp")
    findings = IPv6ParityAnalyzer().analyze([v4], interfaces_info=[])
    parity = [f for f in findings if "ohne IPv6 Pendant" in f.issue]
    assert len(parity) == 1
    assert parity[0].severity == "LOW"


def test_v4_pass_without_v6_sibling_critical_when_iface_has_global_v6():
    v4 = _r(uuid="a", description="allow lan https",
            destination_port="443", protocol="tcp")
    info = [{"identifier": "lan", "addr6": "2a02:810d::1/64"}]
    findings = IPv6ParityAnalyzer().analyze([v4], interfaces_info=info)
    parity = [f for f in findings if "ohne IPv6 Pendant" in f.issue]
    assert len(parity) == 1
    assert parity[0].severity == "CRITICAL"


def test_link_local_only_does_not_promote_severity():
    v4 = _r(uuid="a", destination_port="443", protocol="tcp")
    info = [{"identifier": "lan", "addr6": "fe80::1/64"}]
    findings = IPv6ParityAnalyzer().analyze([v4], interfaces_info=info)
    parity = [f for f in findings if "ohne IPv6 Pendant" in f.issue]
    assert parity and parity[0].severity == "LOW"


def test_v4_pass_with_matching_v6_sibling_not_flagged():
    v4 = _r(uuid="a", destination_port="443", protocol="tcp")
    v6 = _r(uuid="b", ipprotocol="inet6", destination_port="443", protocol="tcp")
    findings = IPv6ParityAnalyzer().analyze([v4, v6])
    assert all("ohne IPv6 Pendant" not in f.issue for f in findings)


def test_strict_false_downgrades_to_high_when_iface_has_v6():
    v4 = _r(uuid="a", destination_port="443", protocol="tcp")
    info = [{"identifier": "lan", "addr6": "2a02:810d::1/64"}]
    findings = IPv6ParityAnalyzer(strict=False).analyze([v4], interfaces_info=info)
    parity = [f for f in findings if "ohne IPv6 Pendant" in f.issue]
    assert parity and parity[0].severity == "HIGH"
