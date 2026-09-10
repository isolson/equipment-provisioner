"""Endpoints behind the vendor assets page."""

import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

from provisioner.config import Config
from provisioner.web.app import create_app


def _client(tmp_path, monkeypatch):
    config = Config()
    config.data.local_path = str(tmp_path)
    monkeypatch.setattr("provisioner.config._config", config)
    provisioner = SimpleNamespace(config=config)
    return TestClient(create_app(provisioner=provisioner)), config


def test_config_baselines_report_install_state_and_witnesses(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    body = client.get("/api/config-baselines?device_type=cambium").json()
    families = {f["family"]: f for f in body["families"]}
    assert set(families) == {"ePMP-3K", "ePMP-4K"}
    four = families["ePMP-4K"]["sm_baseline"]
    assert four["status"] == "not_installed"
    assert four["repo_path"].endswith("ePMP-4K/5.11.1/SM/default.json")
    assert "ePMP 4518 5.11.1" in four["witnesses"] and "ePMP 4616 5.11.1" in four["witnesses"]
    assert four["fresh_sm_proven"] is False

    installed = client.post("/api/config-baselines/sync", json={"device_type": "cambium"}).json()
    assert installed["success"] and installed["copied"] >= 2
    body = client.get("/api/config-baselines?device_type=cambium").json()
    four = next(f for f in body["families"] if f["family"] == "ePMP-4K")["sm_baseline"]
    assert four["status"] == "installed" and four["in_sync"] is True and four["lint"] == []

    # A hand edit that breaks the contract shows as a lint problem.
    path = tmp_path / four["runtime_path"]
    doc = json.loads(path.read_text())
    doc["device_props"]["wirelessInterfaceSSID"] = "site"
    path.write_text(json.dumps(doc))
    four = next(f for f in client.get("/api/config-baselines?device_type=cambium").json()["families"] if f["family"] == "ePMP-4K")["sm_baseline"]
    assert four["status"] == "lint_problem"
    assert four["lint"] == ["wirelessInterfaceSSID (mode_action)"]


def test_baseline_sync_is_scoped_to_the_vendor(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    result = client.post("/api/config-baselines/sync", json={"device_type": "tachyon", "family": "TNA-303L-65"}).json()
    assert result["copied"] >= 1
    assert all(f.startswith("tachyon/TNA-303L-65/") for f in result["copied_files"])
    assert not (tmp_path / "configs/templates/cambium").exists()
    assert client.post("/api/config-baselines/sync", json={"device_type": "cambium", "family": "nope"}).status_code == 400


def test_host_credentials_report_keys_and_required_secrets(tmp_path, monkeypatch):
    client, config = _client(tmp_path, monkeypatch)
    config.credentials["cambium"].wpa_key = ""
    rows = {r["device_type"]: r for r in client.get("/api/host-credentials").json()["credentials"]}
    assert rows["cambium"]["required_secrets"] == ["wpa_key"]
    assert rows["cambium"]["missing_secrets"] == ["wpa_key"]
    assert rows["cambium"]["keys"]["password"] is True
    assert "wpa_key" not in json.dumps(rows["cambium"]["keys"]).replace('"wpa_key": false', "")
    assert rows["tarana"]["required_secrets"] == []


def test_host_credentials_put_edits_the_system_config(tmp_path, monkeypatch):
    client, _ = _client(tmp_path, monkeypatch)
    system_config = tmp_path / "etc" / "config.yaml"
    system_config.parent.mkdir(parents=True)
    system_config.write_text("credentials:\n  cambium:\n    username: admin\n    password: x\n")
    monkeypatch.setattr("provisioner.web.api._get_system_config_path", lambda: system_config)
    response = client.put("/api/host-credentials/cambium", json={"wpa_key": "SECRET-1", "snmp_community": "c"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert sorted(body["changed"]) == ["snmp_community", "wpa_key"]
    assert body["restart_required"] is True
    assert "SECRET-1" not in response.text
    text = system_config.read_text()
    assert 'wpa_key: "SECRET-1"' in text and "username: admin" in text
    assert client.get("/api/host-credentials").json()["restart_required"] is True
    assert client.put("/api/host-credentials/cambium", json={}).status_code == 400
    assert client.put("/api/host-credentials/nope", json={"wpa_key": "x"}).status_code == 400


def test_upload_infers_side_mode_and_export_firmware(tmp_path, monkeypatch):
    from provisioner.handlers.cambium import CambiumHandler

    client, _ = _client(tmp_path, monkeypatch)
    props = dict(CambiumHandler.SM_FLEET_POLICY)
    props.update({
        "wirelessInterfaceMode": "2",
        "wirelessInterfacePTPMode": "1",
        "wirelessInterfaceProtocolMode": "3",
        "wirelessInterfaceScanFrequencyBandwidth": "51",
        "wirelessInterfaceSSID": "tw32-tw18",
        "prefferedAPTable": [{"prefferedListTableEntrySSID": "tw32-tw18"}],
    })
    export = {"device_props": props, "template_props": {"version": "5.11.1"}}
    response = client.post(
        "/api/config-assets/upload",
        data={"device_type": "cambium", "family": "ePMP-4K", "role": "PTP", "ptp_side": "b", "link_profile": "tw32-tw18"},
        files={"file": ("export.json", json.dumps(export), "application/json")},
    )
    assert response.status_code == 200, response.text
    asset = response.json()["asset"]
    assert asset["asset_kind"] == "field_export"
    assert asset["firmware"] == "5.11.1"
    assert asset["mode"] == "ptp-b"
    assert (tmp_path / "configs/templates/cambium/ePMP-4K/5.11.1/PTP/tw32-tw18/SM/default.json").is_file()
    bad = client.post(
        "/api/config-assets/upload",
        data={"device_type": "cambium", "family": "ePMP-4K", "role": "PTP", "ptp_side": "c"},
        files={"file": ("export.json", json.dumps(export), "application/json")},
    )
    assert bad.status_code == 400
