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
                expecting_reboot=False,
            )
        }
        # Ordered log of set_expecting_reboot(bool) calls for bracketing tests.
        self.expecting_reboot_calls = []

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

    def set_expecting_reboot(self, port_number, expecting):
        self.port_states[port_number].expecting_reboot = expecting
        self.expecting_reboot_calls.append(expecting)

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


# Register response with the ship-ready readback (wifi PR #255) in the state
# the contract requires before a unit ships.
SHIP_READY_READBACK = {
    "device_id": 631,
    "name": "fleet-init-HKC0TEST123",
    "status": "planned",
    "message": "ok",
    "role": "unknown",
    "customer_id": None,
    "has_checkin_secret": False,
}


async def test_netinstall_broadcasts_completion_on_success(tmp_path, monkeypatch):
    from provisioner.web.api import _run_netinstall

    class FakeMikrotikHandler:
        BOOTSTRAP_USER = "fleet-bootstrap"
        BASE_FLASH_VERSION = "universal-v1"
        base_flash_version_detected = "universal-v1"
        fetched = False
        last_netinstall_kwargs = None
        last_init_kwargs = None

        def __init__(self, *args, **kwargs):
            type(self).last_init_kwargs = kwargs

        async def netinstall(self, **kwargs):
            assert type(self).fetched is True
            assert kwargs["configure_script_body"] == "# served netinstall bootstrap\n"
            type(self).last_netinstall_kwargs = kwargs
            return True

        @staticmethod
        async def fetch_provisioning_credentials(url, api_key):
            assert url == "https://wifi.example.test"
            assert api_key == "ztp-api-key"
            return {
                "bootstrap_password": "canonical-pass",
                "onboarding_ssid": "th-ext-join",
                "onboarding_passphrase": "join-pass",
            }

        async def wait_for_reboot(self, timeout):
            return True

        async def connect(self):
            return True

        async def get_info(self):
            return SimpleNamespace(
                serial_number="HKC0TEST123",
                mac_address="04:f4:1c:c2:06:80",
                model="hAP ax S",
                firmware_version="7.23.1",
                hardware_version="arm",
            )

        from provisioner.handlers.mikrotik import MikrotikHandler as _Real
        wifi_driver_for_model = _Real.wifi_driver_for_model

        @staticmethod
        async def fetch_netinstall_bootstrap(url, api_key):
            assert url == "https://wifi.example.test"
            assert api_key == "ztp-api-key"
            FakeMikrotikHandler.fetched = True
            return "# served netinstall bootstrap\n"

        @staticmethod
        async def fetch_netinstall_mode(url):
            assert url == "https://wifi.example.test"
            return "# served netinstall mode\n"

        async def wait_for_base_flash_applied(self):
            return True

        async def verify_ztp_ready(self, serial):
            return True, "ZTP-ready"

        async def verify_wifi_radios_bound(self):
            return True

        async def get_phone_home_url(self):
            return "https://wifi.example.test/ztp/mikrotik/checkin"

        async def disconnect(self):
            pass

    config = Config()
    config.credentials.mikrotik.bootstrap_password = "bootstrap-pass"
    config.device_settings.mikrotik.ztp_api_url = "https://wifi.example.test"
    config.device_settings.mikrotik.ztp_api_key = "ztp-api-key"
    provisioner = SimpleNamespace(
        config=config,
        port_manager=DummyPortManager(),
        firmware_manager=SimpleNamespace(firmware_path=tmp_path),
    )

    completed = AsyncMock()
    register = AsyncMock(return_value=SHIP_READY_READBACK)
    monkeypatch.setattr("provisioner.web.api.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("provisioner.web.api._select_latest_npk_per_arch", lambda _: [tmp_path / "routeros-arm64.npk"])
    monkeypatch.setattr("provisioner.web.api.MikrotikHandler", FakeMikrotikHandler, raising=False)
    monkeypatch.setattr("provisioner.handlers.mikrotik.MikrotikHandler", FakeMikrotikHandler)
    monkeypatch.setattr("provisioner.equipment_registry.register_mikrotik", register)
    monkeypatch.setattr("provisioner.web.websocket.notify_port_change", AsyncMock())
    monkeypatch.setattr("provisioner.web.websocket.notify_provisioning_completed", completed)

    await _run_netinstall(provisioner, 5)

    completed.assert_awaited_once()
    args = completed.await_args.args
    assert args[:3] == (5, 0, True)
    assert provisioner.port_manager.port_states[5].last_result == "success"
    assert FakeMikrotikHandler.last_netinstall_kwargs["firmware_paths"] == [tmp_path / "routeros-arm64.npk"]
    # Both first-boot scripts are backend-owned: the served Mode script body
    # must reach netinstall-cli's -sm exactly as fetched.
    assert FakeMikrotikHandler.last_netinstall_kwargs["mode_script_body"] == (
        "# served netinstall mode\n"
    )
    # The post-flash SSH login must use the wifi-api's stored bootstrap
    # password (which the served Configure script embeds), not the local
    # MIKROTIK_BOOTSTRAP_PASS it would otherwise drift against.
    assert FakeMikrotikHandler.last_init_kwargs["credentials"] == {
        "username": "fleet-bootstrap",
        "password": "canonical-pass",
    }
    register.assert_awaited_once_with(
        ztp_api_url="https://wifi.example.test",
        api_key="ztp-api-key",
        serial="HKC0TEST123",
        mac="04:f4:1c:c2:06:80",
        model="hAP ax S",
        firmware_version="7.23.1",
        base_flash_version="universal-v1",
    )

    # The link-loss watchdog must be suppressed for the pipeline's planned
    # reboots: set True once (after netinstall-cli), cleared exactly once at
    # the end, and never left True.
    pm = provisioner.port_manager
    assert pm.expecting_reboot_calls == [True, False]
    assert pm.port_states[5].expecting_reboot is False


async def test_netinstall_clears_expecting_reboot_when_step_after_flash_fails(tmp_path, monkeypatch):
    """A failure AFTER the watchdog-suppression flag is set must still clear it.

    The flag is set once netinstall-cli returns; every later step can fail and
    return early. All those paths go through finish(), which clears the flag —
    so expecting_reboot must never leak True even when the pipeline fails after
    the flash (here: the post-flash boot never comes back).
    """
    from provisioner.web.api import _run_netinstall

    class FakeMikrotikHandler:
        BOOTSTRAP_USER = "fleet-bootstrap"
        BASE_FLASH_VERSION = "universal-v1"

        def __init__(self, *args, **kwargs):
            pass

        @staticmethod
        async def fetch_netinstall_bootstrap(url, api_key):
            return "# served netinstall bootstrap\n"

        @staticmethod
        async def fetch_netinstall_mode(url):
            return "# served netinstall mode\n"

        async def netinstall(self, **kwargs):
            return True

        async def wait_for_reboot(self, timeout):
            return False  # device never comes back after the flash

    config = Config()
    config.credentials.mikrotik.bootstrap_password = "bootstrap-pass"
    config.device_settings.mikrotik.ztp_api_url = "https://wifi.example.test"
    config.device_settings.mikrotik.ztp_api_key = "ztp-api-key"
    provisioner = SimpleNamespace(
        config=config,
        port_manager=DummyPortManager(),
        firmware_manager=SimpleNamespace(firmware_path=tmp_path),
    )

    monkeypatch.setattr("provisioner.web.api.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("provisioner.web.api._select_latest_npk_per_arch", lambda _: [tmp_path / "routeros-arm64.npk"])
    monkeypatch.setattr("provisioner.web.api.MikrotikHandler", FakeMikrotikHandler, raising=False)
    monkeypatch.setattr("provisioner.handlers.mikrotik.MikrotikHandler", FakeMikrotikHandler)
    monkeypatch.setattr("provisioner.web.websocket.notify_port_change", AsyncMock())
    monkeypatch.setattr("provisioner.web.websocket.notify_provisioning_completed", AsyncMock())

    await _run_netinstall(provisioner, 5)

    pm = provisioner.port_manager
    # True was set (after netinstall), then cleared by finish() on the failure.
    assert pm.expecting_reboot_calls == [True, False]
    assert pm.port_states[5].expecting_reboot is False
    assert pm.port_states[5].last_result == "failed"


async def test_netinstall_ships_wifi_driver_packages_in_flash_payload(tmp_path, monkeypatch):
    """Netinstall now ships the selected WiFi packages in the initial flash."""
    from provisioner.web.api import _run_netinstall

    flashed = []

    class FakeMikrotikHandler:
        BOOTSTRAP_USER = "fleet-bootstrap"
        BASE_FLASH_VERSION = "universal-v1"
        base_flash_version_detected = "universal-v1"

        def __init__(self, *args, **kwargs):
            pass

        async def netinstall(self, **kwargs):
            flashed.extend(Path(path).name for path in kwargs["firmware_paths"])
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
                firmware_version="7.23.1",
                hardware_version="arm",
            )

        # The real classmethod the flow consults to pick the driver family.
        from provisioner.handlers.mikrotik import MikrotikHandler as _Real
        wifi_driver_for_model = _Real.wifi_driver_for_model

        @staticmethod
        async def fetch_netinstall_bootstrap(url, api_key):
            return "# served netinstall bootstrap\n"

        @staticmethod
        async def fetch_netinstall_mode(url):
            return "# served netinstall mode\n"

        async def wait_for_base_flash_applied(self):
            return True

        async def verify_ztp_ready(self, serial):
            return True, "ZTP-ready"

        async def verify_wifi_radios_bound(self):
            return True

        async def get_phone_home_url(self):
            return "https://wifi.example.test/ztp/mikrotik/checkin"

        async def disconnect(self):
            pass

    config = Config()
    config.credentials.mikrotik.bootstrap_password = "bootstrap-pass"
    config.device_settings.mikrotik.ztp_api_url = "https://wifi.example.test"
    config.device_settings.mikrotik.ztp_api_key = "ztp-api-key"
    provisioner = SimpleNamespace(
        config=config,
        port_manager=DummyPortManager(),
        firmware_manager=SimpleNamespace(firmware_path=tmp_path),
    )

    # Every selected package ships in the flash set; netinstall-cli matches arch.
    selected = [
        tmp_path / "routeros-arm-7.23.1.npk",
        tmp_path / "wifi-qcom-7.23.1-arm.npk",
        tmp_path / "wifi-mediatek-7.23.1-arm.npk",
    ]
    monkeypatch.setattr("provisioner.web.api.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("provisioner.web.api._select_latest_npk_per_arch", lambda _: selected)
    monkeypatch.setattr("provisioner.web.api.MikrotikHandler", FakeMikrotikHandler, raising=False)
    monkeypatch.setattr("provisioner.handlers.mikrotik.MikrotikHandler", FakeMikrotikHandler)
    monkeypatch.setattr("provisioner.equipment_registry.register_mikrotik", AsyncMock(return_value=SHIP_READY_READBACK))
    monkeypatch.setattr("provisioner.web.websocket.notify_port_change", AsyncMock())
    monkeypatch.setattr("provisioner.web.websocket.notify_provisioning_completed", AsyncMock())

    await _run_netinstall(provisioner, 5)

    assert flashed == [
        "routeros-arm-7.23.1.npk",
        "wifi-qcom-7.23.1-arm.npk",
        "wifi-mediatek-7.23.1-arm.npk",
    ]
    assert provisioner.port_manager.port_states[5].last_result == "success"


async def test_netinstall_fails_before_register_when_wifi_radios_not_bound(tmp_path, monkeypatch):
    """A wifi-capable model with an empty /interface/wifi must not register.

    This is the hAP ax radio-binding failure mode: routeros + wifi driver in
    one flash can leave the driver loaded but the radio unbound. The runbook's
    step-1 pass criterion is a non-empty /interface/wifi.
    """
    from provisioner.web.api import _run_netinstall

    class FakeMikrotikHandler:
        BOOTSTRAP_USER = "fleet-bootstrap"
        BASE_FLASH_VERSION = "universal-v1"
        base_flash_version_detected = "universal-v1"

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
                firmware_version="7.23.1",
                hardware_version="arm",
            )

        from provisioner.handlers.mikrotik import MikrotikHandler as _Real
        wifi_driver_for_model = _Real.wifi_driver_for_model

        @staticmethod
        async def fetch_netinstall_bootstrap(url, api_key):
            return "# served netinstall bootstrap\n"

        @staticmethod
        async def fetch_netinstall_mode(url):
            return "# served netinstall mode\n"

        async def wait_for_base_flash_applied(self):
            return True

        async def verify_ztp_ready(self, serial):
            return True, "ZTP-ready"

        async def verify_wifi_radios_bound(self):
            return False

        async def disconnect(self):
            pass

    config = Config()
    config.credentials.mikrotik.bootstrap_password = "bootstrap-pass"
    config.device_settings.mikrotik.ztp_api_url = "https://wifi.example.test"
    config.device_settings.mikrotik.ztp_api_key = "ztp-api-key"
    provisioner = SimpleNamespace(
        config=config,
        port_manager=DummyPortManager(),
        firmware_manager=SimpleNamespace(firmware_path=tmp_path),
    )

    register = AsyncMock()
    monkeypatch.setattr("provisioner.web.api.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("provisioner.web.api._select_latest_npk_per_arch", lambda _: [tmp_path / "routeros-arm.npk"])
    monkeypatch.setattr("provisioner.web.api.MikrotikHandler", FakeMikrotikHandler, raising=False)
    monkeypatch.setattr("provisioner.handlers.mikrotik.MikrotikHandler", FakeMikrotikHandler)
    monkeypatch.setattr("provisioner.equipment_registry.register_mikrotik", register)
    monkeypatch.setattr("provisioner.web.websocket.notify_port_change", AsyncMock())
    monkeypatch.setattr("provisioner.web.websocket.notify_provisioning_completed", AsyncMock())

    await _run_netinstall(provisioner, 5)

    register.assert_not_awaited()
    assert provisioner.port_manager.port_states[5].last_result == "failed"
    assert provisioner.port_manager.port_states[5].last_error == (
        "WiFi radios not bound after Netinstall (/interface/wifi empty)"
    )


def _ship_ready_fake_handler(phone_home_url="https://wifi.example.test/ztp/mikrotik/checkin"):
    """Minimal happy-path fake for ship-ready / baked-URL pipeline tests."""

    class FakeMikrotikHandler:
        BOOTSTRAP_USER = "fleet-bootstrap"
        BASE_FLASH_VERSION = "universal-v1"
        base_flash_version_detected = "universal-v1"

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
                firmware_version="7.23.1",
                hardware_version="arm",
            )

        from provisioner.handlers.mikrotik import MikrotikHandler as _Real
        wifi_driver_for_model = _Real.wifi_driver_for_model

        @staticmethod
        async def fetch_netinstall_bootstrap(url, api_key):
            return "# served netinstall bootstrap\n"

        @staticmethod
        async def fetch_netinstall_mode(url):
            return "# served netinstall mode\n"

        async def wait_for_base_flash_applied(self):
            return True

        async def verify_ztp_ready(self, serial):
            return True, "ZTP-ready"

        async def verify_wifi_radios_bound(self):
            return True

        async def get_phone_home_url(self):
            return phone_home_url

        async def disconnect(self):
            pass

    return FakeMikrotikHandler


def _netinstall_env(monkeypatch, tmp_path, handler_cls, register):
    config = Config()
    config.credentials.mikrotik.bootstrap_password = "bootstrap-pass"
    config.device_settings.mikrotik.ztp_api_url = "https://wifi.example.test"
    config.device_settings.mikrotik.ztp_api_key = "ztp-api-key"
    provisioner = SimpleNamespace(
        config=config,
        port_manager=DummyPortManager(),
        firmware_manager=SimpleNamespace(firmware_path=tmp_path),
    )
    monkeypatch.setattr("provisioner.web.api.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("provisioner.web.api._select_latest_npk_per_arch", lambda _: [tmp_path / "routeros-arm.npk"])
    monkeypatch.setattr("provisioner.web.api.MikrotikHandler", handler_cls, raising=False)
    monkeypatch.setattr("provisioner.handlers.mikrotik.MikrotikHandler", handler_cls)
    monkeypatch.setattr("provisioner.equipment_registry.register_mikrotik", register)
    monkeypatch.setattr("provisioner.web.websocket.notify_port_change", AsyncMock())
    monkeypatch.setattr("provisioner.web.websocket.notify_provisioning_completed", AsyncMock())
    return provisioner


async def test_netinstall_remediates_stale_ship_ready_state(tmp_path, monkeypatch):
    """A recycled unit (locked role, old customer, stale TOFU secret) must be
    cleared via the contract endpoints, re-registered, and re-asserted."""
    from provisioner.web.api import _run_netinstall

    stale = {
        **SHIP_READY_READBACK,
        "role": "gateway",
        "customer_id": 7,
        "has_checkin_secret": True,
    }
    register = AsyncMock(side_effect=[stale, SHIP_READY_READBACK])
    clear_role = AsyncMock(return_value={})
    clear_secret = AsyncMock(return_value={"cleared": True})
    provisioner = _netinstall_env(
        monkeypatch, tmp_path, _ship_ready_fake_handler(), register
    )
    monkeypatch.setattr("provisioner.equipment_registry.clear_role_lock", clear_role)
    monkeypatch.setattr("provisioner.equipment_registry.clear_checkin_secret", clear_secret)

    await _run_netinstall(provisioner, 5)

    assert provisioner.port_manager.port_states[5].last_result == "success"
    clear_role.assert_awaited_once_with("https://wifi.example.test", "ztp-api-key", "HKC0TEST123")
    clear_secret.assert_awaited_once_with("https://wifi.example.test", "ztp-api-key", "HKC0TEST123")
    assert register.await_count == 2


async def test_netinstall_fails_when_still_stale_after_remediation(tmp_path, monkeypatch):
    """A unit ships only when all three assertions hold — if remediation
    doesn't clear the state, the run must fail, not ship."""
    from provisioner.web.api import _run_netinstall

    stale = {**SHIP_READY_READBACK, "has_checkin_secret": True}
    register = AsyncMock(side_effect=[stale, stale])
    clear_secret = AsyncMock(return_value={"cleared": True})
    provisioner = _netinstall_env(
        monkeypatch, tmp_path, _ship_ready_fake_handler(), register
    )
    monkeypatch.setattr("provisioner.equipment_registry.clear_checkin_secret", clear_secret)

    await _run_netinstall(provisioner, 5)

    assert provisioner.port_manager.port_states[5].last_result == "failed"
    assert "not ship-ready" in provisioner.port_manager.port_states[5].last_error


async def test_netinstall_skips_ship_ready_on_legacy_backend(tmp_path, monkeypatch):
    """A backend without the readback fields (pre wifi PR #255) must not
    block the bench — assertions are skipped with a warning."""
    from provisioner.web.api import _run_netinstall

    register = AsyncMock(return_value={
        "device_id": 631,
        "name": "fleet-init-HKC0TEST123",
        "status": "planned",
        "message": "ok",
    })
    provisioner = _netinstall_env(
        monkeypatch, tmp_path, _ship_ready_fake_handler(), register
    )

    await _run_netinstall(provisioner, 5)

    assert provisioner.port_manager.port_states[5].last_result == "success"
    register.assert_awaited_once()


async def test_netinstall_fails_on_baked_phone_home_host_mismatch(tmp_path, monkeypatch):
    """Contract rule 4: a Configure script that baked a different host (the
    retired-api.infra failure class) must fail before register."""
    from provisioner.web.api import _run_netinstall

    register = AsyncMock(return_value=SHIP_READY_READBACK)
    provisioner = _netinstall_env(
        monkeypatch,
        tmp_path,
        _ship_ready_fake_handler(
            phone_home_url="https://api.infra.treehouse.mn/ztp/mikrotik/checkin"
        ),
        register,
    )

    await _run_netinstall(provisioner, 5)

    register.assert_not_awaited()
    assert provisioner.port_manager.port_states[5].last_result == "failed"
    assert "phone-home URL mismatch" in provisioner.port_manager.port_states[5].last_error


async def test_netinstall_fails_when_phone_home_url_unparseable(tmp_path, monkeypatch):
    from provisioner.web.api import _run_netinstall

    register = AsyncMock(return_value=SHIP_READY_READBACK)
    provisioner = _netinstall_env(
        monkeypatch, tmp_path, _ship_ready_fake_handler(phone_home_url=None), register
    )

    await _run_netinstall(provisioner, 5)

    register.assert_not_awaited()
    assert provisioner.port_manager.port_states[5].last_result == "failed"


async def test_netinstall_requires_ztp_api_key_before_flash(tmp_path, monkeypatch):
    from provisioner.web.api import _run_netinstall

    class FakeMikrotikHandler:
        BOOTSTRAP_USER = "fleet-bootstrap"
        netinstall_called = False

        def __init__(self, *args, **kwargs):
            pass

        async def netinstall(self, **kwargs):
            type(self).netinstall_called = True
            return True

    config = Config()
    config.credentials.mikrotik.bootstrap_password = "bootstrap-pass"
    config.device_settings.mikrotik.ztp_api_url = "https://wifi.example.test"
    provisioner = SimpleNamespace(
        config=config,
        port_manager=DummyPortManager(),
        firmware_manager=SimpleNamespace(firmware_path=tmp_path),
    )

    monkeypatch.setattr("provisioner.web.api._select_latest_npk_per_arch", lambda _: [tmp_path / "routeros-arm64.npk"])
    monkeypatch.setattr("provisioner.web.api.MikrotikHandler", FakeMikrotikHandler, raising=False)
    monkeypatch.setattr("provisioner.handlers.mikrotik.MikrotikHandler", FakeMikrotikHandler)
    monkeypatch.setattr("provisioner.web.websocket.notify_port_change", AsyncMock())
    monkeypatch.setattr("provisioner.web.websocket.notify_provisioning_completed", AsyncMock())

    await _run_netinstall(provisioner, 5)

    assert FakeMikrotikHandler.netinstall_called is False
    assert provisioner.port_manager.port_states[5].last_result == "failed"
    assert provisioner.port_manager.port_states[5].last_error == (
        "device_settings.mikrotik.ztp_api_key not configured"
    )


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
