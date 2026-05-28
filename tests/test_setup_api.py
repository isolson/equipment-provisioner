"""Tests for first-run readiness and setup bundle import APIs."""

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from provisioner.config import Config
from provisioner.web.app import create_app


class DummyProvisioner:
    """Minimal provisioner stub for API tests."""

    def __init__(self, config):
        self.config = config
        self.port_manager = None


class DummyPortManager:
    """Minimal port manager stub for API status tests."""

    def __init__(self):
        self.port_states = {
            5: SimpleNamespace(
                provisioning=False,
                last_result="success",
                last_error=None,
                device_mac=None,
            )
        }

    def get_port_status(self):
        return {
            5: {
                "vlan_id": 1995,
                "link_up": True,
                "device_detected": False,
                "device_type": None,
                "device_ip": None,
                "provisioning": False,
                "link_speed": "1Gbps",
                "last_result": "success",
                "last_error": None,
            }
        }

    def get_interface_for_port(self, port_number):
        return f"eno1.199{port_number}"

    def mark_port_provisioning(self, port_number, provisioning=True, success=False, error=None):
        state = self.port_states[port_number]
        state.provisioning = provisioning
        if not provisioning:
            state.last_result = "success" if success else "failed"
            state.last_error = None if success else error

    def update_checklist(self, port_number, step, value):
        pass

    def _get_single_port_status(self, port_number):
        state = self.port_states[port_number]
        return {
            "provisioning": state.provisioning,
            "last_result": state.last_result,
            "last_error": state.last_error,
            "checklist": {},
        }

    def update_port_device_info(self, port_number, mac=None, serial=None, model=None):
        state = self.port_states[port_number]
        state.device_mac = mac
        state.device_serial = serial
        state.device_model = model


def make_client(tmp_path: Path):
    data_path = tmp_path / "repo"
    data_path.mkdir(parents=True, exist_ok=True)

    config = Config()
    config.data.local_path = str(data_path)
    config.network.interface = "eth0"
    config.network.management.enabled = True
    config.network.management.vlan = 1990
    config.network.management.switch_ip = "192.168.88.1"

    provisioner = DummyProvisioner(config)
    app = create_app(provisioner=provisioner)
    return TestClient(app), config, data_path


def test_ports_api_includes_last_provisioning_result(tmp_path):
    client, _config, _data_path = make_client(tmp_path)
    client.app.state.provisioner.port_manager = DummyPortManager()

    response = client.get("/api/ports")

    assert response.status_code == 200
    port = response.json()[0]
    assert port["port_number"] == 5
    assert port["last_result"] == "success"
    assert port["last_error"] is None


async def test_netinstall_broadcasts_completion_on_success(tmp_path, monkeypatch):
    from provisioner.web.api import _run_netinstall

    class FakeMikrotikHandler:
        BOOTSTRAP_USER = "fleet-bootstrap"
        BASE_FLASH_VERSION = "universal-v1"

        def __init__(self, *args, **kwargs):
            pass

        async def netinstall(self, **kwargs):
            return True

        async def wait_for_reboot(self, timeout):
            return True

        async def connect(self):
            return True

        async def get_info(self):
            return SimpleNamespace(
                serial_number="HKC0TEST123",
                mac_address="04:f4:1c:c2:06:80",
                model="hAP ax S",
                firmware_version="7.22.2",
                hardware_version="arm64",
            )

        @staticmethod
        async def fetch_base_flash(url):
            return "/system note set note=\"base_flash_version=universal-v1\""

        @staticmethod
        def build_import_script(**kwargs):
            return "/system note set note=\"base_flash_version=universal-v1\""

        async def apply_config_file(self, script_path):
            return True

        async def wait_for_base_flash_applied(self):
            return True

        async def verify_ztp_ready(self, serial):
            return True, "ZTP-ready"

        async def disconnect(self):
            pass

    config = Config()
    config.credentials.mikrotik.bootstrap_password = "bootstrap-pass"
    config.device_settings.mikrotik.ztp_api_url = "https://wifi.example.test"
    provisioner = SimpleNamespace(
        config=config,
        port_manager=DummyPortManager(),
        firmware_manager=SimpleNamespace(firmware_path=tmp_path),
    )

    completed = AsyncMock()
    monkeypatch.setattr("provisioner.web.api.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("provisioner.web.api._select_latest_npk_per_arch", lambda _: [tmp_path / "routeros-arm64.npk"])
    monkeypatch.setattr("provisioner.web.api.MikrotikHandler", FakeMikrotikHandler, raising=False)
    monkeypatch.setattr("provisioner.handlers.mikrotik.MikrotikHandler", FakeMikrotikHandler)
    monkeypatch.setattr("provisioner.equipment_registry.register_mikrotik", AsyncMock())
    monkeypatch.setattr("provisioner.web.websocket.notify_port_change", AsyncMock())
    monkeypatch.setattr("provisioner.web.websocket.notify_provisioning_completed", completed)

    await _run_netinstall(provisioner, 5)

    completed.assert_awaited_once()
    args = completed.await_args.args
    assert args[:3] == (5, 0, True)
    assert provisioner.port_manager.port_states[5].last_result == "success"


def test_setup_readiness_reports_switch_and_missing_assets(tmp_path, monkeypatch):
    client, config, data_path = make_client(tmp_path)

    config.credentials.cambium.password = "fleet-pass"
    config.credentials.mikrotik.password = "switch-pass"
    config.credentials.tachyon.password = "fleet-pass"
    config.credentials.tarana.password = "fleet-pass"
    config.credentials.ubiquiti.password = "fleet-pass"
    config.device_settings.tarana.operator_id = 12345

    (data_path / "configs" / "templates" / "cambium").mkdir(parents=True)
    (data_path / "configs" / "templates" / "tachyon").mkdir(parents=True)
    (data_path / "configs" / "templates" / "cambium" / "default.json").write_text("{}")
    (data_path / "configs" / "templates" / "tachyon" / "default.json").write_text("{}")
    (data_path / "firmware" / "mikrotik").mkdir(parents=True)
    (data_path / "firmware" / "mikrotik" / "routeros-arm-7.15.npk").write_text("npk")

    monkeypatch.setattr("provisioner.setup_tools._interface_exists", lambda _: True)
    monkeypatch.setattr(
        "provisioner.setup_tools.probe_mikrotik_switch",
        lambda cfg: {
            "reachable": True,
            "mode": "configured",
            "host": "192.168.88.1",
            "identity": "provisioner-switch",
            "board_name": "CRS310-8G+2S+IN",
            "version": "7.15",
            "status": "ready",
            "summary": "Provisioning switch is configured for the first eight ports.",
            "actions": [],
            "checks": [{"name": "ether8 PVID", "status": "ready"}],
        },
    )

    response = client.get("/api/setup/readiness")
    assert response.status_code == 200

    payload = response.json()
    checks = {item["id"]: item for item in payload["checks"]}

    assert payload["switch_port_map"] == [
        "ether1-ether6: provisioning ports for VLANs 1991-1996",
        "ether7: WAN or internet uplink",
        "ether8: trunk to the host",
    ]
    assert checks["mikrotik_switch"]["status"] == "ready"
    assert checks["management_network"]["status"] == "ready"
    assert checks["firmware_inventory"]["status"] == "warning"
    assert checks["config_templates"]["status"] == "warning"


def test_setup_bundle_import_copies_repo_and_optional_system_files(tmp_path, monkeypatch):
    client, _config, data_path = make_client(tmp_path)

    system_dir = tmp_path / "etc" / "provisioner"
    system_dir.mkdir(parents=True, exist_ok=True)
    config_path = system_dir / "config.yaml"
    env_path = system_dir / "provisioner.env"

    monkeypatch.setattr("provisioner.web.api._get_system_config_path", lambda: config_path)
    monkeypatch.setattr("provisioner.web.api._get_system_env_path", lambda: env_path)

    bundle_path = tmp_path / "setup-bundle.zip"
    with zipfile.ZipFile(bundle_path, "w") as archive:
        archive.writestr("bundle/configs/templates/cambium/default.json", "{}")
        archive.writestr("bundle/firmware/mikrotik/routeros-arm-7.15.npk", "npk")
        archive.writestr(
            "bundle/credentials.json",
            json.dumps({"cambium": [{"username": "admin", "password": "fleet"}]}),
        )
        archive.writestr("bundle/manifest.yaml", "firmware: {}\n")
        archive.writestr("bundle/settings/config.yaml", "network:\n  interface: eth1\n")
        archive.writestr("bundle/settings/provisioner.env", "CAMBIUM_PASSWORD=fleet\n")

    with bundle_path.open("rb") as handle:
        response = client.post(
            "/api/setup/bundle/import",
            files={"file": ("setup-bundle.zip", handle, "application/zip")},
            data={"apply_system_files": "true"},
        )

    assert response.status_code == 200
    payload = response.json()

    assert payload["success"] is True
    assert payload["summary"]["configs"] == 1
    assert payload["summary"]["firmware"] == 1
    assert payload["summary"]["credentials"] == 1
    assert payload["summary"]["manifest"] == 1
    assert payload["summary"]["system_files"] == 2
    assert payload["restart_required"] is True

    assert (data_path / "configs" / "templates" / "cambium" / "default.json").read_text() == "{}"
    assert (data_path / "firmware" / "mikrotik" / "routeros-arm-7.15.npk").read_text() == "npk"
    assert json.loads((data_path / "credentials.json").read_text())["cambium"][0]["password"] == "fleet"
    assert config_path.read_text() == "network:\n  interface: eth1\n"
    assert env_path.read_text() == "CAMBIUM_PASSWORD=fleet\n"


def test_setup_bundle_export_includes_repo_and_optional_system_files(tmp_path, monkeypatch):
    client, _config, data_path = make_client(tmp_path)

    (data_path / "configs" / "templates" / "cambium").mkdir(parents=True)
    (data_path / "configs" / "templates" / "cambium" / "default.json").write_text("{}")
    (data_path / "firmware" / "mikrotik").mkdir(parents=True)
    (data_path / "firmware" / "mikrotik" / "routeros-arm-7.15.npk").write_text("npk")
    (data_path / "credentials.json").write_text(json.dumps({"cambium": [{"username": "admin", "password": "fleet"}]}))
    (data_path / "manifest.yaml").write_text("firmware: {}\n")

    system_dir = tmp_path / "etc" / "provisioner"
    system_dir.mkdir(parents=True, exist_ok=True)
    config_path = system_dir / "config.yaml"
    env_path = system_dir / "provisioner.env"
    config_path.write_text("network:\n  interface: eth1\n")
    env_path.write_text("CAMBIUM_PASSWORD=fleet\n")

    monkeypatch.setattr("provisioner.web.api._get_system_config_path", lambda: config_path)
    monkeypatch.setattr("provisioner.web.api._get_system_env_path", lambda: env_path)

    response = client.get("/api/setup/bundle/export?include_system_files=true")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert "provisioner-setup-" in response.headers.get("content-disposition", "")

    bundle_path = tmp_path / "export.zip"
    bundle_path.write_bytes(response.content)

    with zipfile.ZipFile(bundle_path) as archive:
        names = set(archive.namelist())
        assert "configs/templates/cambium/default.json" in names
        assert "firmware/mikrotik/routeros-arm-7.15.npk" in names
        assert "credentials.json" in names
        assert "manifest.yaml" in names
        assert "settings/config.yaml" in names
        assert "settings/provisioner.env" in names


def test_setup_switch_configure_runs_switch_script(tmp_path, monkeypatch):
    client, _config, _data_path = make_client(tmp_path)

    class DummyProc:
        returncode = 0

        async def communicate(self):
            return (b"Setup complete", b"")

    captured = {}

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return DummyProc()

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_create_subprocess_exec)

    response = client.post(
        "/api/setup/switch/configure",
        json={
            "ip": "192.168.88.1",
            "username": "admin",
            "password": "",
            "skip_password_change": True,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert "first eight ports" in payload["message"].lower()
    assert captured["cmd"][0] == "/bin/bash"
    assert "--skip-password-change" in captured["cmd"]


def test_setup_seed_templates_copies_repo_templates(tmp_path, monkeypatch):
    client, _config, data_path = make_client(tmp_path)

    fake_repo = tmp_path / "repo-root"
    template_dir = fake_repo / "configs" / "templates" / "cambium"
    template_dir.mkdir(parents=True)
    (template_dir / "ap.json").write_text('{"mode":"ap"}')

    monkeypatch.setattr("provisioner.web.api._get_repo_root", lambda: fake_repo)

    response = client.post("/api/setup/templates/seed", json={"overwrite": False})
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["copied"] == 1
    assert (data_path / "configs" / "templates" / "cambium" / "ap.json").read_text() == '{"mode":"ap"}'


def test_device_settings_put_persists_to_disk(tmp_path, monkeypatch):
    """PUT /api/device-settings must write to disk so the value survives restart."""
    import provisioner.config as config_module

    overrides_path = tmp_path / "device-settings.json"
    monkeypatch.setattr(config_module, "DEVICE_SETTINGS_OVERRIDES_PATH", overrides_path)

    client, config, _data_path = make_client(tmp_path)
    # Simulate config.yaml setting an install-time secret in the same subtree.
    config.device_settings.mikrotik.ztp_api_key = "from-yaml"

    response = client.put("/api/device-settings", json={"tarana": {"operator_id": 12345}})
    assert response.status_code == 200
    assert response.json() == {"success": True}

    # File must exist with the new value.
    assert overrides_path.exists()
    loaded = config_module.load_device_settings_overrides(overrides_path)
    assert loaded == {"tarana": {"operator_id": 12345}}
    # Crucially, we did NOT snapshot the in-memory mikrotik secret to disk.
    assert "mikrotik" not in loaded

    # GET should reflect the same value (round-trip through in-memory config).
    get_response = client.get("/api/device-settings")
    assert get_response.status_code == 200
    assert get_response.json()["tarana"]["operator_id"] == 12345


def test_device_settings_put_merges_with_existing_overrides(tmp_path, monkeypatch):
    """A second PUT must merge into the file, not clobber prior overrides."""
    import provisioner.config as config_module

    overrides_path = tmp_path / "device-settings.json"
    # Pre-seed with a future-shape override that no current endpoint writes.
    overrides_path.write_text('{"future_vendor": {"some_field": "preserved"}}')

    monkeypatch.setattr(config_module, "DEVICE_SETTINGS_OVERRIDES_PATH", overrides_path)
    client, _config, _data_path = make_client(tmp_path)

    response = client.put("/api/device-settings", json={"tarana": {"operator_id": 9}})
    assert response.status_code == 200

    loaded = config_module.load_device_settings_overrides(overrides_path)
    assert loaded["tarana"]["operator_id"] == 9
    assert loaded["future_vendor"]["some_field"] == "preserved"


def test_device_settings_load_config_overlays_overrides(tmp_path, monkeypatch):
    """load_config() must overlay the persisted overrides file at startup."""
    import provisioner.config as config_module

    overrides_path = tmp_path / "device-settings.json"
    overrides_path.write_text('{"tarana": {"operator_id": 777}}')
    monkeypatch.setattr(config_module, "DEVICE_SETTINGS_OVERRIDES_PATH", overrides_path)

    config_yaml = tmp_path / "config.yaml"
    config_yaml.write_text("network:\n  interface: eth0\n")

    config = config_module.load_config(str(config_yaml))
    assert config.device_settings.tarana.operator_id == 777


def test_setup_restart_service_schedules_systemctl_restart(tmp_path, monkeypatch):
    client, _config, _data_path = make_client(tmp_path)

    captured = {}

    class DummyPopen:
        def __init__(self, cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs

    monkeypatch.setattr("subprocess.Popen", DummyPopen)

    response = client.post("/api/setup/restart-service")
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert captured["cmd"][0] == "/bin/sh"
    assert "systemctl restart provisioner-web" in captured["cmd"][2]
