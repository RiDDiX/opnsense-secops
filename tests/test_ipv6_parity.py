"""IPv6 parity analyzer tests, severities follow expert consensus.

References:
- opnsense/core filter.lib.inc#L222-L228 (default deny is inet46)
- opnsense/core config.xml.sample#L121-L132 (LAN IPv6 allow rule)
- Netgate forum threads, default WAN ruleset is empty so unsolicited inbound
  is dropped, NAT was never the boundary.
- RFC 4890, ICMPv6 must not be pauschal blocked.
"""
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


def test_default_allow_lan_v6_is_low_informational():
    rule = _r(
        ipprotocol="inet6",
        source_net="lan",
        destination_net="any",
        description="Default allow LAN IPv6 to any rule",
    )
    findings = IPv6ParityAnalyzer().analyze([rule])
    auto = [f for f in findings if "Default allow LAN IPv6" in f.issue]
    assert auto, "auto rule should produce a finding"
    assert auto[0].severity == "LOW"
    assert auto[0].suggested_rule is not None
    assert auto[0].suggested_rule["rule"]["interface"] == "wan"
    assert auto[0].suggested_rule["rule"]["action"] == "block"
    assert auto[0].suggested_rule["rule"]["destination_net"] == "lan"


def test_default_allow_lan_v6_no_suggestion_when_wan_block_already_present():
    auto_rule = _r(
        ipprotocol="inet6",
        source_net="lan",
        destination_net="any",
        description="Default allow LAN IPv6 to any rule",
    )
    wan_block = _r(
        uuid="wb",
        action="block",
        direction="in",
        ipprotocol="inet6",
        interface="wan",
        interfaces=["wan"],
        source_net="any",
        destination_net="lan",
        description="block inbound v6 to lan net",
    )
    findings = IPv6ParityAnalyzer().analyze([auto_rule, wan_block])
    auto = [f for f in findings if "Default allow LAN IPv6" in f.issue]
    assert auto and auto[0].suggested_rule is None


def test_wan_inbound_v6_pass_flagged_high():
    wan_pass = _r(
        uuid="w1",
        action="pass",
        ipprotocol="inet6",
        direction="in",
        interface="wan",
        interfaces=["wan"],
        source_net="any",
        destination_net="any",
        destination_port="443",
        protocol="tcp",
        description="allow https from internet",
    )
    findings = IPv6ParityAnalyzer().analyze([wan_pass])
    wan = [f for f in findings if "WAN Inbound IPv6 Pass" in f.issue]
    assert wan and wan[0].severity == "HIGH"


def test_v4_pass_without_v6_sibling_is_low():
    v4 = _r(uuid="a", description="allow lan https",
            destination_port="443", protocol="tcp")
    info = [{"identifier": "lan", "addr6": "2a02:810d::1/64"}]
    findings = IPv6ParityAnalyzer().analyze([v4], interfaces_info=info)
    parity = [f for f in findings if "ohne IPv6 Pendant" in f.issue]
    assert parity and parity[0].severity == "LOW"


def test_v4_pass_with_matching_v6_sibling_not_flagged():
    v4 = _r(uuid="a", destination_port="443", protocol="tcp")
    v6 = _r(uuid="b", ipprotocol="inet6", destination_port="443", protocol="tcp")
    findings = IPv6ParityAnalyzer().analyze([v4, v6])
    assert all("ohne IPv6 Pendant" not in f.issue for f in findings)


def test_strict_flag_does_not_force_critical_for_parity():
    """Severity comes from threat model, not the strict flag."""
    v4 = _r(uuid="a", destination_port="443", protocol="tcp")
    info = [{"identifier": "lan", "addr6": "2a02:810d::1/64"}]
    findings = IPv6ParityAnalyzer(strict=False).analyze([v4], interfaces_info=info)
    parity = [f for f in findings if "ohne IPv6 Pendant" in f.issue]
    assert parity and parity[0].severity == "LOW"
