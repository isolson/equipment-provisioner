"""Safety and capability checks for operator-triggered actions."""

from types import SimpleNamespace

from fastapi.testclient import TestClient

from provisioner.config import Config
from provisioner.handlers.tachyon import TachyonHandler
from provisioner.web.app import create_app


class _PortManager:
    def __init__(self, status, peer=None):
        self._status = status
        self._peer = peer

    def get_port_status(self):
        return {4: dict(self._status)}

    def get_available_ptp_side(self, _my_tower, _remote_tower, port_num=None):
        return "b" if self._peer else "a"

    def get_ptp_peer(self, _link_id, _port_num):
        return self._peer


def _client(monkeypatch, status, mode_config=False, peer=None):
    config = Config()
    config.features.mode_config = mode_config
    monkeypatch.setattr("provisioner.config._config", config)
    provisioner = SimpleNamespace(
        config=config,
        port_manager=_PortManager(status, peer=peer),
    )
    return TestClient(create_app(provisioner=provisioner))


def _qualify(tmp_path, monkeypatch, vendor, model, firmware, modes=("ptp",)):
    """Record both directions of each mode in a temporary evidence root."""
    import textwrap
    from provisioner import qualification

    rows = []
    for mode in modes:
        rows.append("  - {from: sm, to: %s, result: success}\n" % mode)
        rows.append("  - {from: %s, to: sm, result: success}\n" % mode)
    directory = tmp_path / vendor / model.replace(" ", "_") / firmware
    directory.mkdir(parents=True, exist_ok=True)
    directory.joinpath("manifest.yaml").write_text(textwrap.dedent("""\
        vendor: %s
        model: %s
        firmware: %s
        config_role: SM
        artifact_purpose: hardware-validation
        reusable_template: false
        canonical_template_status: tracked-family-baseline
        transitions:
        """) % (vendor, model, firmware) + "".join(rows))
    monkeypatch.setenv("PROVISIONER_QUALIFICATION_ROOT", str(tmp_path))
    qualification.clear_cache()


def _status(device_type, mac):
    return {
        "vlan_id": 1994,
        "link_up": True,
        "device_detected": True,
        "device_type": device_type,
        "device_ip": "192.0.2.1",
        "device_mac": mac,
        "firmware_version": "5.11.1",
        "provisioning": False,
        "last_result": "success",
        "checklist": {"config_upload": True, "config_verify": True},
        "device_mode": None,
    }


def test_netinstall_rejects_non_capable_device(monkeypatch):
    client = _client(
        monkeypatch,
        _status("tachyon", "78:5E:E8:D0:4C:38"),
    )

    response = client.post("/api/netinstall", json={"port_number": 4})

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Netinstall is not supported for the detected device"
    )


def test_netinstall_rejects_stale_device_type_with_wrong_oui(monkeypatch):
    client = _client(
        monkeypatch,
        _status("mikrotik", "9C:05:D6:B4:AD:CF"),
    )

    response = client.post("/api/netinstall", json={"port_number": 4})

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Netinstall requires a detected MikroTik MAC address"
    )


def test_netinstall_accepts_capable_device_with_mikrotik_oui(monkeypatch):
    calls = []

    async def fake_run(provisioner, port_number):
        calls.append(port_number)

    monkeypatch.setattr("provisioner.web.api._run_netinstall", fake_run)
    client = _client(
        monkeypatch,
        _status("mikrotik", "74:4D:28:00:00:01"),
    )

    response = client.post("/api/netinstall", json={"port_number": 4})

    assert response.status_code == 200
    assert calls == [4]


def test_mode_endpoint_rejects_unqualified_vendor_with_templates(monkeypatch):
    client = _client(
        monkeypatch,
        _status("tachyon", "78:5E:E8:D0:4C:38"),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ap", "tower": 5, "direction": "north"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Mode configuration not supported for tachyon"
    )


def test_mode_endpoint_uses_handler_capability(tmp_path, monkeypatch):
    _qualify(tmp_path, monkeypatch, "tachyon", "TNA-303X", "5.11.1", ('ap', 'ptp'))
    calls = []

    async def fake_run(provisioner, port_number, device_type, device_ip, req, *_rest):
        calls.append((port_number, device_type, req.mode))

    monkeypatch.setattr(
        TachyonHandler,
        "qualified_post_provision_modes",
        ("ap", "ptp"),
    )
    monkeypatch.setattr("provisioner.web.api._run_apply_mode", fake_run)
    client = _client(
        monkeypatch,
        dict(_status("tachyon", "78:5E:E8:D0:4C:38"), device_model="TNA-303X"),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ap", "tower": 5, "direction": "north"},
    )

    assert response.status_code == 200
    assert calls == [(4, "tachyon", "ap")]


def test_mode_endpoint_accepts_sm_restore_for_configured_cambium(monkeypatch):
    calls = []

    async def fake_run(*args):
        calls.append((args[1], args[4].mode, args[5]))

    monkeypatch.setattr("provisioner.web.api._run_apply_mode", fake_run)
    monkeypatch.setattr(
        "provisioner.web.api._resolve_sm_template",
        lambda *args: ("/tmp/sm.json", None),
    )
    client = _client(
        monkeypatch,
        dict(
            _status("cambium", "00:00:00:00:00:01"),
            device_model="ePMP 4616",
            device_mode="ptp-a",
        ),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "sm"},
    )

    assert response.status_code == 200
    assert calls == [(4, "sm", "/tmp/sm.json")]


def test_mode_endpoint_rejects_sm_restore_for_unsupported_handler(monkeypatch):
    client = _client(
        monkeypatch,
        dict(
            _status("tarana", "00:00:00:00:00:01"),
            device_mode="ptp-a",
        ),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "sm"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "SM configuration restore not supported for tarana"
    )


def test_mode_endpoint_rejects_sm_restore_without_template(monkeypatch):
    monkeypatch.setattr(
        "provisioner.web.api._resolve_sm_template",
        lambda *args: (None, None),
    )
    client = _client(
        monkeypatch,
        dict(
            _status("cambium", "00:00:00:00:00:01"),
            device_model="ePMP 4616",
            device_mode="ptp-a",
        ),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "sm"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "A standard SM configuration template is required for restore"
    )


def test_mode_endpoint_rejects_sm_restore_without_verified_baseline(monkeypatch):
    monkeypatch.setattr(
        "provisioner.web.api._resolve_sm_template",
        lambda *args: ("/tmp/sm.json", None),
    )
    status = dict(
        _status("cambium", "00:00:00:00:00:01"),
        device_model="ePMP 4616",
        device_mode="ptp-a",
        checklist={"config_upload": True, "config_verify": "unverified"},
    )
    client = _client(monkeypatch, status, mode_config=True)

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "sm"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "Verified SM configuration is required before SM restore"
    )


def test_mode_endpoint_uses_model_qualified_cambium_ptp(tmp_path, monkeypatch):
    _qualify(tmp_path, monkeypatch, "cambium", "ePMP 4616", "5.11.1")
    calls = []

    async def fake_run(provisioner, port_number, device_type, device_ip, req, *_rest):
        calls.append((port_number, device_type, req.mode, req.my_tower, req.remote_tower))

    monkeypatch.setattr("provisioner.web.api._run_apply_mode", fake_run)
    monkeypatch.setattr(
        "provisioner.mode_config.ModeConfigManager.load_template",
        lambda *args, **kwargs: {
            "device_props": {
                "wirelessInterfaceMode": "1",
                "wirelessInterfacePTPMode": "1",
                "wirelessInterfaceProtocolMode": "3",
                "wirelessInterfaceTDDFrameSize": "5000",
                "wirelessInterfaceTDDRatio": "4",
                "centerFrequency": "6835",
            }
        },
    )
    client = _client(
        monkeypatch,
        dict(_status("cambium", "00:00:00:00:00:01"), device_model="ePMP 4616"),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ptp", "my_tower": 33, "remote_tower": 35},
    )

    assert response.status_code == 200
    assert calls == [(4, "cambium", "ptp", 33, 35)]


def test_mode_endpoint_accepts_cambium_family_ptp(tmp_path, monkeypatch):
    _qualify(tmp_path, monkeypatch, "cambium", "ePMP 3000", "5.11.1")
    calls = []

    async def fake_run(provisioner, port_number, device_type, device_ip, req, *_rest):
        calls.append((port_number, device_type, req.mode, req.my_tower, req.remote_tower))

    monkeypatch.setattr("provisioner.web.api._run_apply_mode", fake_run)
    monkeypatch.setattr(
        "provisioner.mode_config.ModeConfigManager.load_template",
        lambda *args, **kwargs: {
            "device_props": {
                "wirelessInterfaceMode": "1",
                "wirelessInterfacePTPMode": "1",
                "wirelessInterfaceProtocolMode": "3",
                "wirelessInterfaceTDDFrameSize": "5000",
                "wirelessInterfaceTDDRatio": "4",
                "centerFrequency": "6835",
            }
        },
    )
    client = _client(
        monkeypatch,
        dict(_status("cambium", "00:00:00:00:00:01"), device_model="ePMP 3000"),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ptp", "my_tower": 32, "remote_tower": 18},
    )

    assert response.status_code == 200
    assert calls == [(4, "cambium", "ptp", 32, 18)]


def test_mode_endpoint_requires_cambium_ptp_profile(tmp_path, monkeypatch):
    _qualify(tmp_path, monkeypatch, "cambium", "ePMP 4518", "5.11.1")
    client = _client(
        monkeypatch,
        dict(_status("cambium", "00:00:00:00:00:01"), device_model="ePMP 4518"),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ptp", "my_tower": 33, "remote_tower": 35},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "A certified PTP settings profile is required for this family and link"
    )


def test_mode_endpoint_accepts_certified_cross_family_pair(tmp_path, monkeypatch):
    _qualify(tmp_path, monkeypatch, "cambium", "ePMP 3000", "5.11.1")
    monkeypatch.setattr(
        "provisioner.web.api._run_apply_mode",
        lambda *args: None,
    )
    monkeypatch.setattr(
        "provisioner.mode_config.ModeConfigManager.load_template",
        lambda *args, **kwargs: {
            "device_props": {
                "wirelessInterfaceMode": "2",
                "wirelessInterfacePTPMode": "1",
                "wirelessInterfaceProtocolMode": "3",
                "wirelessInterfaceTDDFrameSize": "5000",
                "wirelessInterfaceTDDRatio": "2",
                "centerFrequency": "6565",
                "wirelessInterfaceSSID": "captured-ssid",
                "prefferedAPTable": [
                    {"prefferedListTableEntrySSID": "captured-ssid"}
                ],
            }
        },
    )
    client = _client(
        monkeypatch,
        dict(_status("cambium", "00:00:00:00:00:01"), device_model="ePMP 3000"),
        mode_config=True,
        peer={
            "device_type": "cambium",
            "device_model": "ePMP 4616",
            "port": 5,
        },
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ptp", "my_tower": 32, "remote_tower": 18},
    )

    assert response.status_code == 200


def test_mode_endpoint_rejects_uncertified_ptp_pair(tmp_path, monkeypatch):
    _qualify(tmp_path, monkeypatch, "cambium", "ePMP 4616", "5.11.1")
    client = _client(
        monkeypatch,
        dict(_status("cambium", "00:00:00:00:00:01"), device_model="ePMP 4616"),
        mode_config=True,
        peer={
            "device_type": "tachyon",
            "device_model": "TNA-303X",
            "port": 5,
        },
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ptp", "my_tower": 32, "remote_tower": 18},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "The two device families are not certified for PTP"
    )


def test_mode_endpoint_requires_tachyon_ptp_profile(tmp_path, monkeypatch):
    _qualify(tmp_path, monkeypatch, "tachyon", "TNA-301", "5.11.1", ('ptp',))
    client = _client(
        monkeypatch,
        dict(_status("tachyon", "78:5E:E8:D0:4C:38"), device_model="TNA-301"),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ptp", "my_tower": 32, "remote_tower": 18},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "A certified PTP settings profile is required for this family and link"
    )


def test_mode_endpoint_requires_verified_handler_baseline(tmp_path, monkeypatch):
    _qualify(tmp_path, monkeypatch, "tachyon", "TNA-303X", "5.11.1", ('ap', 'ptp'))
    monkeypatch.setattr(
        TachyonHandler,
        "qualified_post_provision_modes",
        ("ap", "ptp"),
    )
    status = dict(_status("tachyon", "78:5E:E8:D0:4C:38"), device_model="TNA-303X")
    status["checklist"] = {"config_upload": "skipped", "config_verify": None}
    client = _client(monkeypatch, status, mode_config=True)

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ap", "tower": 5, "direction": "north"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "Verified SM configuration is required before AP/PTP conversion"
    )


def test_ap_qualification_does_not_authorize_ptp(monkeypatch):
    monkeypatch.setattr(
        TachyonHandler,
        "qualified_post_provision_modes",
        ("ap",),
    )
    client = _client(
        monkeypatch,
        _status("tachyon", "78:5E:E8:D0:4C:38"),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ptp", "my_tower": 5, "remote_tower": 12},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Mode configuration not supported for tachyon"
    )


def test_mode_preview_describes_changes_without_reserving(tmp_path, monkeypatch):
    _qualify(tmp_path, monkeypatch, "cambium", "ePMP 4616", "5.11.1")
    reserved = []
    monkeypatch.setattr(
        "provisioner.mode_config.ModeConfigManager.load_template",
        lambda *args, **kwargs: {
            "device_props": {
                "wirelessInterfaceMode": "1",
                "wirelessInterfacePTPMode": "1",
                "wirelessInterfaceProtocolMode": "3",
                "wirelessInterfaceTDDFrameSize": "5000",
                "wirelessInterfaceTDDRatio": "4",
                "centerFrequency": "6835",
            }
        },
    )
    client = _client(
        monkeypatch,
        dict(_status("cambium", "00:00:00:00:00:01"), device_model="ePMP 4616"),
        mode_config=True,
    )
    port_manager = client.app.state.provisioner.port_manager
    port_manager.reserve_ptp_side = lambda *args, **kwargs: reserved.append(args) or "a"

    response = client.post(
        "/api/ports/4/mode-preview",
        json={"mode": "ptp", "my_tower": 33, "remote_tower": 35},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert body["current_mode"] == "sm"
    assert body["target_mode"] == "ptp"
    assert body["ptp_side"] == "a"
    assert body["ptp_link_id"] == "tw33-tw35"
    assert body["template_found"] is True
    fields = {change["field"]: change["to"] for change in body["changes"]}
    assert fields["radio role"] == "ptp-a"
    assert fields["hostname"] == body["naming"]["hostname"]
    assert "sm_config_path" not in body
    assert reserved == []


def test_mode_preview_reports_the_unqualified_reason(monkeypatch):
    client = _client(
        monkeypatch,
        dict(_status("cambium", "00:00:00:00:00:01"), device_model="ePMP 4616"),
        mode_config=True,
    )
    response = client.post(
        "/api/ports/4/mode-preview",
        json={"mode": "ptp", "my_tower": 33, "remote_tower": 35},
    )
    assert response.status_code == 400
    assert response.json()["detail"].startswith("PTP not qualified for ePMP 4616 on 5.11.1")


def test_mode_preview_for_sm_restore_lists_cleared_link_state(monkeypatch, tmp_path):
    status = dict(
        _status("cambium", "00:00:00:00:00:01"),
        device_model="ePMP 4616",
        device_mode="ptp-a",
        mode_config={"hostname": "tw33a-tw35", "ssid": "tw33-tw35"},
    )
    client = _client(monkeypatch, status, mode_config=True)
    template = tmp_path / "configs" / "templates" / "cambium" / "ePMP-4K" / "SM"
    template.mkdir(parents=True)
    (template / "default.json").write_text('{"device_props": {"networkMode": "2"}}')
    client.app.state.provisioner.config.data.local_path = str(tmp_path)

    response = client.post("/api/ports/4/mode-preview", json={"mode": "sm"})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["target_mode"] == "sm"
    assert body["warnings"] == ["PTP settings and link tracking will be cleared"]
    assert {c["field"] for c in body["changes"]} == {"radio role", "hostname", "ssid"}


def test_mode_change_is_refused_while_a_mode_job_runs(tmp_path, monkeypatch):
    _qualify(tmp_path, monkeypatch, "cambium", "ePMP 4616", "5.11.1", ("ap",))
    status = dict(
        _status("cambium", "00:00:00:00:00:01"),
        device_model="ePMP 4616",
        mode_job={"id": "4-1", "mode": "ap", "steps": [], "status": {}},
    )
    client = _client(monkeypatch, status, mode_config=True)
    response = client.post("/api/ports/4/mode-preview", json={"mode": "ap", "tower": 5, "direction": "north"})
    assert response.status_code == 409
    assert "already running" in response.json()["detail"]


def test_port_events_endpoint(monkeypatch):
    client = _client(monkeypatch, _status("cambium", "00:00:00:00:00:01"))
    port_manager = client.app.state.provisioner.port_manager
    port_manager.get_events = lambda port, since=0, limit=200: {
        "port_number": port, "latest_seq": 2, "events": [{"seq": 2, "kind": "link_up"}] if since < 2 else [],
    }
    assert client.get("/api/ports/4/events").json()["events"] == [{"seq": 2, "kind": "link_up"}]
    assert client.get("/api/ports/4/events?since=2").json()["events"] == []
    assert client.get("/api/ports/9/events").status_code == 404
