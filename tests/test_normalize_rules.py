"""Field mapping tests for the firewall rule normalizer."""
from src.opnsense_client import OPNsenseClient


def _client():
    return OPNsenseClient(host="x", api_key="x", api_secret="x")


def test_normalize_carries_new_2026_fields():
    raw = {
        "uuid": "u1",
        "enabled": "1",
        "sequence": "21",
        "sort_order": "200000.0000021",
        "prio_group": "200000",
        "interfacenot": "0",
        "interface": "lan,opt5",
        "direction": "any",
        "ipprotocol": "inet",
        "protocol": "any",
        "icmptype": "",
        "icmp6type": "",
        "source_net": "any",
        "source_port": "",
        "source_not": "0",
        "destination_net": "any",
        "destination_port": "",
        "destination_not": "0",
        "action": "block",
        "log": "1",
        "quick": "1",
        "gateway": "",
        "replyto": "",
        "categories": "uuid1,uuid2",
        "%categories": "malware, blocked",
        "tag": "",
        "tagged": "",
        "set-prio": "",
        "sched": "",
        "statetimeout": "",
        "udp-first": "",
        "udp-multiple": "",
        "udp-single": "",
        "max-src-conn": "",
        "max-src-states": "",
        "tcpflags_any": "0",
        "divert-to": "",
    }
    norm = _client()._normalize_firewall_rules([raw])[0]
    assert norm["uuid"] == "u1"
    assert norm["interfaces"] == ["lan", "opt5"]
    assert norm["is_floating"] is True  # prio_group 200000 -> floating
    assert norm["is_group_rule"] is False
    assert norm["categories_named"] == "malware, blocked"
    assert norm["icmp6type"] == ""
    assert norm["max-src-conn"] == ""
    assert norm["divert-to"] == ""
    assert "_raw" in norm


def test_group_rule_flag_set():
    raw = {"prio_group": "300000", "interface": "lan"}
    norm = _client()._normalize_firewall_rules([raw])[0]
    assert norm["is_group_rule"] is True
    assert norm["is_floating"] is False


def test_interface_negation_marks_floating():
    raw = {"prio_group": "400000", "interfacenot": "1", "interface": "lan"}
    norm = _client()._normalize_firewall_rules([raw])[0]
    assert norm["is_floating"] is True
