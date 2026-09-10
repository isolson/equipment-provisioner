"""Tests for restoring a provisioned radio to its standard SM config."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from provisioner.config import Config
from provisioner.fingerprint import DeviceType
from provisioner.web.api import ApplyModeRequest, _resolve_sm_template, _run_apply_mode


class _PortManager:
    def __init__(self, device_mode="ptp-a"):
        self._status = {
            4: {
                "device_model": "ePMP 4616",
                "firmware_version": "5.11.1",
                "device_mode": device_mode,
            }
        }
        self.clear_calls = []

    def get_port_status(self):
        return {4: dict(self._status[4])}

    def get_interface_for_port(self, _port_number):
        return "eth0.1994"

    def clear_device_mode(self, port_number):
        self.clear_calls.append(port_number)
        self._status[port_number]["device_mode"] = None

    def _get_single_port_status(self, _port_number):
        return self._status[4]


class _Handler:
    def __init__(self, apply_result=True, verify_result=True):
        self.apply_result = apply_result
        self.verify_result = verify_result
        self.applied_paths = []
        self.verify_calls = 0
        self.antenna_gain_calls = 0

    async def connect(self):
        return True

    async def disconnect(self):
        return None

    async def apply_config_file(self, path):
        self.applied_paths.append(path)
        return self.apply_result

    async def verify_config(self):
        self.verify_calls += 1
        return self.verify_result

    async def apply_antenna_gain(self, *_args, **_kwargs):
        self.antenna_gain_calls += 1
        return True


def test_sm_restore_resolves_the_standard_family_template(tmp_path):
    template = tmp_path / "configs" / "templates" / "cambium" / "ePMP-4K" / "SM"
    template.mkdir(parents=True)
    expected = template / "default.json"
    expected.write_text('{"device_props": {"networkMode": "2"}}')

    config = Config()
    config.data.local_path = str(tmp_path)
    provisioner = SimpleNamespace(config=config)
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(provisioner=provisioner))
    )

    path, resolved = _resolve_sm_template(request, provisioner, "cambium", "ePMP 4616")

    assert path == str(expected)
    assert resolved is not None
    resolved.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("apply_result", "verify_result"),
    ((True, True), (True, False), (False, True)),
)
async def test_sm_restore_clears_mode_only_after_verified_apply(
    monkeypatch, apply_result, verify_result
):
    port_manager = _PortManager()
    handler = _Handler(apply_result, verify_result)
    handler_manager = SimpleNamespace(get_handler=lambda *args, **kwargs: handler)
    provisioner = SimpleNamespace(
        port_manager=port_manager,
        handler_manager=handler_manager,
    )

    async def identify_device(*_args, **_kwargs):
        return SimpleNamespace(device_type=DeviceType.CAMBIUM, model="ePMP 4616")

    notify = AsyncMock()
    monkeypatch.setattr("provisioner.fingerprint.identify_device", identify_device)
    monkeypatch.setattr("provisioner.web.websocket.notify_port_change", notify)

    await _run_apply_mode(
        provisioner,
        4,
        "cambium",
        "192.0.2.1",
        ApplyModeRequest(mode="sm"),
        "/tmp/approved-sm.json",
    )

    assert handler.applied_paths == ["/tmp/approved-sm.json"]
    assert handler.antenna_gain_calls == 0
    assert port_manager.clear_calls == ([4] if apply_result and verify_result else [])
    assert notify.await_count == 1


def test_sm_restore_preserves_the_other_ptp_side():
    from provisioner.port_manager import PortManager

    manager = PortManager(num_ports=2)
    manager._generate_port_configs()
    manager._ptp_links.clear()
    manager._ptp_reservations.clear()
    try:
        first = manager.port_states[1]
        first.device_type = "cambium"
        first.device_model = "ePMP 3000"
        manager.set_device_mode(
            1,
            "ptp-a",
            {"my_tower": 32, "remote_tower": 18},
            "tw18-tw32",
        )

        second = manager.port_states[2]
        second.device_type = "cambium"
        second.device_model = "ePMP 4616"
        manager.set_device_mode(
            2,
            "ptp-b",
            {"my_tower": 18, "remote_tower": 32},
            "tw18-tw32",
        )

        manager.clear_device_mode(1)

        assert first.device_mode is None
        assert first.ptp_link_id is None
        assert manager.get_ptp_link("tw18-tw32") == {
            "side_a_port": None,
            "side_b_port": 2,
            "device_type": "cambium",
            "device_model": "ePMP 3000",
            "my_tower": 32,
            "remote_tower": 18,
            "side_a_device_type": "cambium",
            "side_a_device_model": "ePMP 3000",
            "side_b_device_type": "cambium",
            "side_b_device_model": "ePMP 4616",
            "side_a_family": "ePMP-3K",
            "side_b_family": "ePMP-4K",
        }
        assert second.device_mode == "ptp-b"
    finally:
        manager._ptp_links.clear()
        manager._ptp_reservations.clear()
