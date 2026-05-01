"""Gateway and Radvd analyzer."""
from src.analyzers.gateway_analyzer import GatewayAnalyzer
from src.analyzers.radvd_analyzer import RadvdAnalyzer


def test_gateway_no_monitor_ip_finding():
    gw = [{"uuid": "1", "name": "WAN_DHCP", "ipprotocol": "inet", "interface": "wan",
           "monitor": "", "monitor_disable": "0", "disabled": False}]
    out = GatewayAnalyzer().analyze(gw)
    assert any(f.issue.startswith("Gateway ohne Monitor IP") for f in out)


def test_gateway_v6_default_missing_when_v6_rules_present():
    gw = [{"uuid": "1", "name": "WAN", "ipprotocol": "inet", "interface": "wan",
           "monitor": "1.1.1.1", "monitor_disable": "0", "disabled": False, "defaultgw": "1"}]
    rules = [{"ipprotocol": "inet6", "enabled": "1"}]
    out = GatewayAnalyzer().analyze(gw, rules)
    assert any(f.rule_id == "no_default_v6_gateway" for f in out)


def test_radvd_unknown_mode():
    entries = [{"uuid": "x", "interface": "lan", "enabled": "1", "ramode": "wishful"}]
    out = RadvdAnalyzer().analyze(entries)
    assert any("Unbekannter RA Modus" in f.issue for f in out)


def test_radvd_lan_global_v6_no_entry_low():
    entries = []
    info = [{"identifier": "lan", "description": "LAN", "device": "igc2",
             "link_type": "static", "addr6": "2a02:810d:708a:9e00::1/64"}]
    out = RadvdAnalyzer().analyze(entries, info)
    assert any(f.severity == "LOW" for f in out)


def test_radvd_skips_loopback_pppoe_and_tunnels():
    entries = []
    info = [
        {"identifier": "lo0", "description": "Loopback", "device": "lo0",
         "link_type": "static", "addr6": "::1/128"},
        {"identifier": "opt5", "description": "Telekom", "device": "pppoe0",
         "link_type": "pppoe", "addr6": "2003:ee::1/64"},
        {"identifier": "opt8", "description": "TailScale", "device": "tailscale0",
         "link_type": "none", "addr6": "fd7a::1/48"},
        {"identifier": "wan", "description": "Vodafone", "device": "igc0",
         "link_type": "dhcp", "addr6": "2a02:810d::1/128"},
    ]
    out = RadvdAnalyzer().analyze(entries, info)
    assert out == []
