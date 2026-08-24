"""Safety and capability checks for operator-triggered actions."""

from types import SimpleNamespace

from fastapi.testclient import TestClient

from provisioner.config import Config
from provisioner.handlers.tachyon import TachyonHandler
from provisioner.web.app import create_app


class _PortManager:
    def __init__(self, status):
        self._status = status

    def get_port_status(self):
        return {4: dict(self._status)}


def _client(monkeypatch, status, mode_config=False):
    config = Config()
    config.features.mode_config = mode_config
    monkeypatch.setattr("provisioner.config._config", config)
    provisioner = SimpleNamespace(
        config=config,
        port_manager=_PortManager(status),
    )
    return TestClient(create_app(provisioner=provisioner))


def _status(device_type, mac):
    return {
        "vlan_id": 1994,
        "link_up": True,
        "device_detected": True,
        "device_type": device_type,
        "device_ip": "192.0.2.1",
        "device_mac": mac,
        "provisioning": False,
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


def test_mode_endpoint_uses_handler_capability(monkeypatch):
    calls = []

    async def fake_run(provisioner, port_number, device_type, device_ip, req):
        calls.append((port_number, device_type, req.mode))

    monkeypatch.setattr(
        TachyonHandler,
        "qualified_post_provision_modes",
        ("ap", "ptp"),
    )
    monkeypatch.setattr("provisioner.web.api._run_apply_mode", fake_run)
    client = _client(
        monkeypatch,
        _status("tachyon", "78:5E:E8:D0:4C:38"),
        mode_config=True,
    )

    response = client.post(
        "/api/ports/4/apply-mode",
        json={"mode": "ap", "tower": 5, "direction": "north"},
    )

    assert response.status_code == 200
    assert calls == [(4, "tachyon", "ap")]
