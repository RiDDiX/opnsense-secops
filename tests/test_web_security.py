"""Security regression tests for the Flask app."""
import json
import os
import re

import pytest

# Some web app behaviours look up CONFIG_DIR / REPORTS_DIR. Patch them before importing.
os.environ.setdefault("OPNSENSE_HOST", "")
os.environ.setdefault("OPNSENSE_API_KEY", "")
os.environ.setdefault("OPNSENSE_API_SECRET", "")


@pytest.fixture
def app(tmp_path, monkeypatch):
    cfg = tmp_path / "config"
    rpt = tmp_path / "reports"
    cfg.mkdir()
    rpt.mkdir()
    monkeypatch.setenv("CONFIG_DIR_OVERRIDE", str(cfg))
    # Import inside fixture so module-level CONFIG_DIR uses defaults; we patch attributes after import.
    from src.web import app as web

    web.CONFIG_DIR = str(cfg)
    web.REPORTS_DIR = str(rpt)
    web.app.config.update(TESTING=True)
    return web


@pytest.fixture
def client(app):
    return app.app.test_client()


def _csrf_pair(client):
    """Make a GET request to obtain a CSRF cookie, return (cookie, header value)."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    cookie = client.get_cookie("secops_csrf")
    assert cookie is not None
    return cookie.value


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_csrf_required_on_state_changes(client):
    # No cookie at all: must be rejected.
    resp = client.post("/api/scan/start", json={})
    assert resp.status_code in (400, 403)


def test_csrf_accepted_with_matching_token(client):
    tok = _csrf_pair(client)
    resp = client.post(
        "/api/config",
        data=json.dumps({"opnsense": {}}),
        content_type="application/json",
        headers={"X-CSRF-Token": tok},
    )
    # 200 or 500 both prove CSRF passed; we only care that it is not 403.
    assert resp.status_code != 403


def test_get_config_does_not_leak_secret(app, client, tmp_path):
    cfg_path = os.path.join(app.CONFIG_DIR, "opnsense.json")
    with open(cfg_path, "w") as f:
        json.dump({"host": "fw", "api_key": "REAL_KEY", "api_secret": "REAL_SECRET"}, f)
    resp = client.get("/api/config")
    body = resp.get_json()
    opn = body["opnsense"]
    assert "REAL_SECRET" not in json.dumps(body)
    assert "REAL_KEY" not in json.dumps(body)
    assert opn["api_key_set"] is True
    assert opn["api_secret_set"] is True


def test_path_traversal_rejected(client):
    # Even encoded forms must be rejected by the whitelist.
    for name in ("../etc/passwd", "..%2Fetc%2Fpasswd", "evil.json"):
        resp = client.get(f"/api/reports/{name}")
        assert resp.status_code in (400, 404)


def test_max_content_length_enforced(app, client):
    tok = _csrf_pair(client)
    # 2 MiB body, server cap is 1 MiB
    big = b"a" * (2 * 1024 * 1024)
    resp = client.post(
        "/api/config",
        data=big,
        content_type="application/json",
        headers={"X-CSRF-Token": tok},
    )
    assert resp.status_code == 413


def test_report_filename_whitelist():
    rx = re.compile(r"^security_audit_[A-Za-z0-9_\-]+\.json$")
    assert rx.fullmatch("security_audit_2025-01-01_10-00-00.json")
    assert not rx.fullmatch("security_audit_../etc.json")
    assert not rx.fullmatch("evil.json")
