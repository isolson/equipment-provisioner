"""Snapshot web API tests (R3, issue #116).

The HTTP-surface half of the redaction guarantee: no secret-classified
field value (per the R0 §3.3 map, including the default-secret rule for
unclassified identity fields) and no part of the raw vendor blob may
appear in ANY response body. All fixture secrets are obviously fake.
"""

import json

from fastapi.testclient import TestClient

from provisioner.config import Config
from provisioner.snapshot_store import SnapshotStore
from provisioner.web.app import create_app

from test_snapshot_store import (
    ALL_SECRET_SENTINELS,
    FAKE_PSK,
    make_snapshot,
)


class DummyProvisioner:
    """Minimal provisioner stub (config only) for snapshot API tests."""

    def __init__(self, config):
        self.config = config


def make_client(tmp_path, **snapshot_cfg):
    cfg = {"path": str(tmp_path / "snapshots")}
    cfg.update(snapshot_cfg)
    config = Config(snapshots=cfg)
    app = create_app(provisioner=DummyProvisioner(config))
    client = TestClient(app)
    return client, app


def seed(app, **overrides):
    """Write a snapshot through the internal write path (as R4 will).

    Pre-sets ``app.state.snapshot_store`` the way the capture path may;
    the router must reuse it rather than build a second store.
    """
    store = getattr(app.state, "snapshot_store", None)
    if store is None:
        store = SnapshotStore.from_config(app.state.provisioner.config)
        app.state.snapshot_store = store
    return store.save(make_snapshot(**overrides))


def assert_response_has_no_secrets(response):
    body = response.text
    for sentinel in ALL_SECRET_SENTINELS:
        assert sentinel not in body, "secret value leaked over HTTP: %s" % sentinel


def test_list_is_paginated_and_redacted(tmp_path):
    client, app = make_client(tmp_path)
    for hour in (10, 11, 12):
        seed(app, serial_number="SN-%d" % hour,
             captured_at="2026-08-21T%02d:00:00Z" % hour)

    response = client.get("/api/snapshots", params={"limit": 2, "offset": 0})
    assert response.status_code == 200
    assert_response_has_no_secrets(response)
    payload = response.json()
    assert payload["total"] == 3
    assert len(payload["snapshots"]) == 2
    assert payload["snapshots"][0]["captured_at"] == "2026-08-21T12:00:00Z"

    page2 = client.get("/api/snapshots", params={"limit": 2, "offset": 2}).json()
    assert len(page2["snapshots"]) == 1


def test_list_and_get_never_leak_secret_classified_values(tmp_path):
    """Assert against the R0 map: psk, raw.content, and default-secret
    identity fields are absent from every HTTP response body."""
    client, app = make_client(tmp_path)
    saved = seed(app)

    list_response = client.get("/api/snapshots")
    get_response = client.get("/api/snapshots/%s" % saved["id"])
    assert list_response.status_code == 200
    assert get_response.status_code == 200

    for response in (list_response, get_response):
        assert_response_has_no_secrets(response)
        blob = response.text
        # Field-level map assertions (names, not just sentinel values):
        assert '"psk":' not in blob
        assert '"content":' not in blob
        assert '"security_mode"' not in blob   # default-secret rule
        assert '"radius_secret"' not in blob   # default-secret rule

    doc = get_response.json()
    assert doc["identity"]["wireless"]["psk_present"] is True
    assert doc["identity"]["wireless"]["psk_length"] == len(FAKE_PSK)
    assert doc["raw"] == {
        "content_present": True,
        "format": "tachyon-export-json",
        "encoding": "json",
    }
    assert "identity.wireless.psk" in doc["redacted_fields"]
    assert "raw.content" in doc["redacted_fields"]


def test_get_masks_but_keeps_public_identity(tmp_path):
    client, app = make_client(tmp_path)
    saved = seed(app)
    doc = client.get("/api/snapshots/%s" % saved["id"]).json()
    assert doc["identity"]["wireless"]["ssid"] == "NORTH"
    assert doc["identity"]["mgmt_ip"]["address"] == "10.20.30.40"
    assert doc["identity"]["routing"]["mode"] == "ospf"
    assert doc["identity"]["ptp_role"] == "a"
    assert doc["serial_number"] == "SN0000000"
    assert doc["hostname"] == "tw05-north"


def test_list_filters_by_vendor(tmp_path):
    client, app = make_client(tmp_path)
    seed(app)
    seed(app, vendor="cambium", serial_number="SN-CAM")
    payload = client.get("/api/snapshots", params={"vendor": "cambium"}).json()
    assert payload["total"] == 1
    assert payload["snapshots"][0]["vendor"] == "cambium"


def test_get_unknown_snapshot_404(tmp_path):
    client, _app = make_client(tmp_path)
    assert client.get("/api/snapshots/does-not-exist").status_code == 404


def test_hostile_snapshot_id_404_not_traversal(tmp_path):
    client, app = make_client(tmp_path)
    seed(app)
    response = client.get("/api/snapshots/..%2F..%2Fetc%2Fpasswd")
    assert response.status_code == 404
    assert client.delete("/api/snapshots/..%2Fescape").status_code == 404


def test_delete_snapshot(tmp_path):
    client, app = make_client(tmp_path)
    saved = seed(app)
    assert client.delete("/api/snapshots/%s" % saved["id"]).status_code == 200
    assert client.get("/api/snapshots/%s" % saved["id"]).status_code == 404
    assert client.delete("/api/snapshots/%s" % saved["id"]).status_code == 404


def test_corrupt_snapshot_listed_as_skipped_and_deletable(tmp_path):
    client, app = make_client(tmp_path)
    saved = seed(app)
    store = app.state.snapshot_store
    (store.base_path / "corrupt-entry-1.json").write_text("{broken json")

    payload = client.get("/api/snapshots").json()
    assert payload["total"] == 1
    assert payload["skipped_unreadable"] == 1
    assert payload["snapshots"][0]["id"] == saved["id"]

    assert client.get("/api/snapshots/corrupt-entry-1").status_code == 422
    assert client.delete("/api/snapshots/corrupt-entry-1").status_code == 200


def test_newer_schema_version_readable_conflict(tmp_path):
    client, app = make_client(tmp_path)
    saved = seed(app)
    store = app.state.snapshot_store
    path = store.base_path / (saved["id"] + ".json")
    doc = json.loads(path.read_text())
    doc["schema_version"] = 99
    path.write_text(json.dumps(doc))

    response = client.get("/api/snapshots/%s" % saved["id"])
    assert response.status_code == 409
    assert "newer than supported" in response.json()["detail"]
    assert_response_has_no_secrets(response)
    # Manual delete still possible.
    assert client.delete("/api/snapshots/%s" % saved["id"]).status_code == 200


def test_snapshots_api_unavailable_without_provisioner_config():
    app = create_app(provisioner=None)
    client = TestClient(app)
    assert client.get("/api/snapshots").status_code == 503


def test_limit_validation(tmp_path):
    client, _app = make_client(tmp_path)
    assert client.get("/api/snapshots", params={"limit": 0}).status_code == 422
    assert client.get("/api/snapshots", params={"limit": 1000}).status_code == 422
    assert client.get("/api/snapshots", params={"offset": -1}).status_code == 422
