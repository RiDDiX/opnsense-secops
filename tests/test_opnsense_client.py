"""Endpoint and method correctness tests for OPNsenseClient."""
from unittest.mock import patch

import pytest

from src.opnsense_client import OPNsenseClient


class _FakeResp:
    def __init__(self, json_data=None, status=200, ctype="application/json"):
        self._json = json_data if json_data is not None else {}
        self.status_code = status
        self.headers = {"Content-Type": ctype}
        self.text = ""

    def raise_for_status(self):
        if self.status_code >= 400:
            from requests import HTTPError
            raise HTTPError(f"{self.status_code}")

    def json(self):
        return self._json


@pytest.fixture
def client():
    # Disable real TLS verification for the test client (test only).
    return OPNsenseClient(
        host="fw.test", api_key="k", api_secret="s", verify_ssl=False, timeout=5
    )


def _record_calls():
    calls = []

    def fake_get(url, **kwargs):
        calls.append(("GET", url, kwargs.get("json")))
        return _FakeResp({"rows": [], "total": 0})

    def fake_post(url, **kwargs):
        calls.append(("POST", url, kwargs.get("json")))
        return _FakeResp({"rows": [], "total": 0})

    return calls, fake_get, fake_post


def test_search_endpoints_use_snake_case(client):
    calls, fake_get, fake_post = _record_calls()
    with patch.object(client.session, "get", side_effect=fake_get), \
         patch.object(client.session, "post", side_effect=fake_post):
        client.get_firewall_rules()
        client.get_nat_rules()
        client.get_vlans()
        client.get_alias_list()

    paths = [c[1] for c in calls]
    assert any("/firewall/filter/search_rule" in p for p in paths)
    assert any("/firewall/d_nat/search_rule" in p for p in paths), \
        "Port forward endpoint must be d_nat, not nat"
    assert any("/firewall/source_nat/search_rule" in p for p in paths)
    assert any("/firewall/one_to_one/search_rule" in p for p in paths)
    assert any("/firewall/npt/search_rule" in p for p in paths)
    assert any("/interfaces/vlan_settings/search_item" in p for p in paths)
    assert any("/firewall/alias/search_item" in p for p in paths)


def test_search_endpoints_send_pagination_body(client):
    calls, fake_get, fake_post = _record_calls()
    with patch.object(client.session, "get", side_effect=fake_get), \
         patch.object(client.session, "post", side_effect=fake_post):
        client.get_firewall_rules()

    post_calls = [c for c in calls if c[0] == "POST"]
    assert post_calls, "search must POST"
    body = post_calls[0][2]
    assert isinstance(body, dict)
    assert "current" in body and "rowCount" in body and "searchPhrase" in body


def test_ipsec_uses_post_search_phase1(client):
    calls, fake_get, fake_post = _record_calls()
    with patch.object(client.session, "get", side_effect=fake_get), \
         patch.object(client.session, "post", side_effect=fake_post):
        client._get_vpn_security_config()

    methods_paths = [(m, p) for (m, p, _) in calls]
    ipsec_calls = [(m, p) for (m, p) in methods_paths if "/ipsec/" in p]
    # Must use POST and snake_case action.
    assert any(m == "POST" and "/ipsec/tunnel/search_phase1" in p for (m, p) in ipsec_calls)
    assert not any("searchPhase1" in p for (_, p) in ipsec_calls)


def test_kea_first_for_dhcp_leases(client):
    """Kea is the default in current OPNsense, the client must try Kea first."""
    seen_paths = []

    def fake_get(url, **kwargs):
        seen_paths.append(("GET", url))
        return _FakeResp({"rows": []})

    def fake_post(url, **kwargs):
        seen_paths.append(("POST", url))
        # First Kea endpoint returns one row so we stop early.
        if "/kea/leases4/search" in url:
            return _FakeResp({"rows": [{"address": "192.0.2.1"}], "total": 1})
        return _FakeResp({"rows": []})

    with patch.object(client.session, "get", side_effect=fake_get), \
         patch.object(client.session, "post", side_effect=fake_post):
        leases = client.get_dhcp_leases()

    assert leases, "should return leases from Kea"
    # First call must hit Kea, not ISC.
    first = seen_paths[0][1]
    assert "/kea/" in first


def test_make_request_rejects_non_json(client):
    def fake_get(url, **kwargs):
        return _FakeResp(json_data={}, status=200, ctype="text/html")

    with patch.object(client.session, "get", side_effect=fake_get):
        with pytest.raises(ValueError):
            client._make_request("GET", "/anything")
