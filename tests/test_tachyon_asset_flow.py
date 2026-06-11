from pathlib import Path
import logging
import sys
import types

import pytest

from provisioner.config import Config
from provisioner.config_store import init_store
from provisioner.fingerprint import DeviceFingerprint, DeviceType
from provisioner.handlers.base import DeviceInfo, ProvisioningResult


if "rich.console" not in sys.modules:
    rich_module = types.ModuleType("rich")
    rich_console_module = types.ModuleType("rich.console")
    rich_logging_module = types.ModuleType("rich.logging")

    class _Console:
        def print(self, *args, **kwargs):
            return None

    class _RichHandler(logging.Handler):
        pass

    rich_console_module.Console = _Console
    rich_logging_module.RichHandler = _RichHandler
    sys.modules["rich"] = rich_module
    sys.modules["rich.console"] = rich_console_module
    sys.modules["rich.logging"] = rich_logging_module

if "aiosqlite" not in sys.modules:
    sys.modules["aiosqlite"] = types.ModuleType("aiosqlite")

from provisioner.main import Provisioner


class _StubDB:
    def __init__(self):
        self.updates = []

    async def create_job(self, record):
        return 1

    async def update_job(self, job_id, **kwargs):
        self.updates.append((job_id, kwargs))

    async def update_inventory(self, **kwargs):
        return None


class _StubNotifier:
    async def notify_started(self, **kwargs):
        return None

    async def notify_completed(self, result):
        return None

    async def notify_failed(self, result, ip):
        return None


class _StubPortManager:
    def __init__(self):
        self.device_info_updates = []

    def get_interface_for_port(self, port_num):
        return "eth0.1996"

    def reset_checklist(self, port_num):
        return None

    def update_port_device_info(self, port_num, **kwargs):
        self.device_info_updates.append((port_num, kwargs))

    def update_checklist(self, port_num, step, value):
        return None

    def _get_single_port_status(self, port_num):
        return {"port_number": port_num}

    def set_expecting_reboot(self, port_num, expecting):
        return None


class _StubFirmwareManager:
    def get_firmware_file(self, device_type, model):
        return None


class _StubHandlerManager:
    def __init__(self):
        self.info_calls = []
        self.provision_calls = []

    async def login_and_get_info(self, **kwargs):
        self.info_calls.append(kwargs)
        return ProvisioningResult(
            success=True,
            device_info=DeviceInfo(
                device_type="tachyon",
                model="TNA-303L-65",
                firmware_version="1.15.0.8503",
                mac_address="78:5E:E8:D1:65:30",
                serial_number="TNA303L462500013",
            ),
        )

    async def provision_device(self, **kwargs):
        self.provision_calls.append(kwargs)
        return ProvisioningResult(
            success=True,
            old_firmware="1.15.0.8503",
            new_firmware="1.15.0.8503",
            config_applied=kwargs.get("config_path"),
            device_info=DeviceInfo(
                device_type="tachyon",
                model="TNA-303L-65",
                firmware_version="1.15.0.8503",
                mac_address="78:5E:E8:D1:65:30",
                serial_number="TNA303L462500013",
            ),
        )


@pytest.mark.asyncio
async def test_tachyon_preflight_model_selects_family_config_not_tns100(tmp_path, monkeypatch):
    template_dir = tmp_path / "configs" / "templates" / "tachyon"
    template_dir.mkdir(parents=True)
    tna_template = template_dir / "20260424.143334.TNA-303L-65.tar"
    tna_template.write_text("{}")
    (template_dir / "tns-100.json").write_text("{}")
    init_store(str(tmp_path))

    config = Config()
    config.data.local_path = str(tmp_path)

    provisioner = Provisioner(config)
    provisioner.port_manager = _StubPortManager()
    provisioner.firmware_manager = _StubFirmwareManager()
    provisioner.handler_manager = _StubHandlerManager()

    async def fake_identify_device(ip, mac=None, interface=None):
        return DeviceFingerprint(
            device_type=DeviceType.TACHYON,
            confidence=0.95,
            model=None,
        )

    async def noop(*args, **kwargs):
        return None

    db = _StubDB()

    import provisioner.db as db_module
    import provisioner.main as main_module
    import provisioner.web.websocket as websocket_module

    async def fake_get_db():
        return db

    monkeypatch.setattr(main_module, "identify_device", fake_identify_device)
    monkeypatch.setattr(main_module, "get_notifier", lambda: _StubNotifier())
    monkeypatch.setattr(db_module, "get_db", fake_get_db)
    monkeypatch.setattr(websocket_module, "notify_provisioning_started", noop)
    monkeypatch.setattr(websocket_module, "notify_provisioning_progress", noop)
    monkeypatch.setattr(websocket_module, "notify_provisioning_completed", noop)
    monkeypatch.setattr(websocket_module, "notify_port_change", noop)

    success = await provisioner._provision_port_device(
        port_num=6,
        device_type="tachyon",
        device_ip="169.254.1.1",
    )

    assert success is True
    assert len(provisioner.handler_manager.info_calls) == 1
    assert len(provisioner.handler_manager.provision_calls) == 1

    provision_call = provisioner.handler_manager.provision_calls[0]
    assert provision_call["fingerprint"].model == "TNA-303L-65"
    assert provision_call["config_path"] == str(tna_template)
    assert "tns-100" not in provision_call["config_path"]
