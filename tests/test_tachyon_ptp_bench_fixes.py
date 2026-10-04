"""Tachyon PTP fixes from the 2026-09-28 bench run (#181).

Python 3.9 - no 3.10+ syntax.
"""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from provisioner.fingerprint import DeviceType
from provisioner.handlers.tachyon import TachyonHandler
from provisioner.web import api
from provisioner.web.api import ApplyModeRequest, _run_apply_mode

ROGUE_PATH = ("network", "zones", "wan", "dhcp_snooping", "block_rogue_servers_enabled")


def _ptp_profile(rogue=None):
    config = {"wireless": {"radios": {"wlan0": {"vaps": [{"mode": "ap", "ptp": True}]}}}}
    if rogue is not None:
        config["network"] = {
            "zones": {"wan": {"dhcp_snooping": {"block_rogue_servers_enabled": rogue}}}
        }
    return config


def _rogue(config):
    value = config
    for key in ROGUE_PATH:
        value = value[key]
    return value


# ---------------------------------------------------------------------------
# Side A turns off rogue-DHCP blocking; side B keeps the profile value.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile_value", (None, True, False))
def test_side_a_turns_off_rogue_dhcp_blocking(profile_value):
    config = TachyonHandler.generate_ptp_settings(
        _ptp_profile(profile_value), "a", "TNA-303L-65"
    )
    assert _rogue(config) is False


@pytest.mark.parametrize("profile_value", (True, False))
def test_side_b_keeps_the_profile_rogue_dhcp_value(profile_value):
    config = TachyonHandler.generate_ptp_settings(
        _ptp_profile(profile_value), "b", "TNA-303L-65"
    )
    assert _rogue(config) is profile_value


def test_side_b_does_not_add_rogue_dhcp_field():
    config = TachyonHandler.generate_ptp_settings(_ptp_profile(), "b", "TNA-303L-65")
    assert "network" not in config


def test_side_a_refuses_invalid_wan_section():
    config = _ptp_profile()
    config["network"] = {"zones": {"wan": "invalid"}}
    with pytest.raises(ValueError, match="network.zones.wan"):
        TachyonHandler.generate_ptp_settings(config, "a", "TNA-303L-65")


# ---------------------------------------------------------------------------
# Reboot after a PTP apply.
# ---------------------------------------------------------------------------


def test_reboot_property_defaults():
    from provisioner.handlers.base import BaseHandler

    assert BaseHandler.ptp_apply_requires_reboot.fget(None) is False
    handler = TachyonHandler("192.0.2.1", {"username": "root", "password": "unused"})
    assert handler.ptp_apply_requires_reboot is True


class _PortManager:
    def __init__(self):
        self.mode_calls = []
        self.steps = []
        self.finished = []

    def get_port_status(self):
        return {4: {"device_model": "TNA-303L-65", "firmware_version": "1.15.1"}}

    def get_reserved_ptp_side(self, _link_id, _port_number):
        return "a"

    def get_ptp_peer(self, _link_id, _port_number):
        return None

    def get_interface_for_port(self, _port_number):
        return "eth0.1994"

    def set_device_mode(self, port_number, mode, _naming, _link_id):
        self.mode_calls.append((port_number, mode))

    def update_mode_job(self, _port_number, key, status, _detail=None):
        self.steps.append((key, status))

    def finish_mode_job(self, _port_number, success, error=None):
        self.finished.append((success, error))

    def _get_single_port_status(self, _port_number):
        return {}


class _Handler:
    def __init__(self, requires_reboot, reboot=True, back=True, verify=True):
        self.ptp_apply_requires_reboot = requires_reboot
        self.reboot_result = reboot
        self.back_result = back
        self.verify_result = verify
        self.last_verify_mismatches = []
        self.calls = []

    async def connect(self):
        return True

    async def disconnect(self):
        return None

    async def apply_mode_config(self, _config):
        self.calls.append("apply")
        return True

    async def apply_antenna_gain(self, *_args, **_kwargs):
        return True

    async def reboot(self):
        self.calls.append("reboot")
        return self.reboot_result

    async def wait_for_reboot(self, timeout=180):
        self.calls.append("wait")
        return self.back_result

    async def verify_config(self):
        self.calls.append("verify")
        return self.verify_result


class _ModeConfigManager:
    def generate_ap_naming(self, *_args):
        return {"hostname": "host", "ssid": "ssid"}

    def generate_ptp_naming(self, *_args):
        return {"hostname": "host", "ssid": "ssid"}

    def load_template(self, *_args, **_kwargs):
        return {"profile": True}

    def generate_ptp_settings(self, template, *_args):
        return deepcopy(template)

    def render_template(self, template, *_args):
        return deepcopy(template)


async def _run(monkeypatch, handler, request):
    port_manager = _PortManager()
    provisioner = SimpleNamespace(
        port_manager=port_manager,
        handler_manager=SimpleNamespace(get_handler=lambda *args, **kwargs: handler),
    )

    async def identify_device(*_args, **_kwargs):
        return SimpleNamespace(device_type=DeviceType.TACHYON, model="TNA-303L-65")

    monkeypatch.setattr("provisioner.fingerprint.identify_device", identify_device)
    monkeypatch.setattr("provisioner.web.websocket.notify_port_change", AsyncMock())
    monkeypatch.setattr(
        "provisioner.mode_config.get_mode_config_manager", lambda: _ModeConfigManager()
    )
    monkeypatch.setattr(
        api.HandlerManager, "operator_capabilities_for", lambda *_args: {}
    )
    await _run_apply_mode(provisioner, 4, "tachyon", "192.0.2.1", request)
    return port_manager


PTP = ApplyModeRequest(mode="ptp", my_tower=32, remote_tower=18)
AP = ApplyModeRequest(mode="ap", tower=32, direction="north")


@pytest.mark.asyncio
async def test_ptp_apply_reboots_and_verifies_again(monkeypatch):
    handler = _Handler(requires_reboot=True)
    port_manager = await _run(monkeypatch, handler, PTP)

    assert handler.calls == ["apply", "reboot", "wait", "verify"]
    assert ("reboot", True) in port_manager.steps
    assert port_manager.mode_calls == [(4, "ptp-a")]
    assert port_manager.finished == [(True, None)]


@pytest.mark.asyncio
@pytest.mark.parametrize("request_", (PTP, AP))
async def test_no_reboot_when_property_is_false(monkeypatch, request_):
    handler = _Handler(requires_reboot=False)
    port_manager = await _run(monkeypatch, handler, request_)

    assert handler.calls == ["apply"]
    assert port_manager.finished == [(True, None)]


@pytest.mark.asyncio
async def test_no_reboot_for_ap_mode(monkeypatch):
    handler = _Handler(requires_reboot=True)
    port_manager = await _run(monkeypatch, handler, AP)

    assert handler.calls == ["apply"]
    assert port_manager.finished == [(True, None)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reboot", "back", "verify", "calls", "error"),
    (
        (False, True, True, ["apply", "reboot"], "reboot after PTP apply"),
        (True, False, True, ["apply", "reboot", "wait"], "reboot after PTP apply"),
        (True, True, False, ["apply", "reboot", "wait", "verify"], "verify after reboot"),
    ),
)
async def test_failed_reboot_or_second_verify_fails_the_job(
    monkeypatch, reboot, back, verify, calls, error
):
    handler = _Handler(requires_reboot=True, reboot=reboot, back=back, verify=verify)
    port_manager = await _run(monkeypatch, handler, PTP)

    assert handler.calls == calls
    assert port_manager.mode_calls == []
    assert port_manager.finished == [(False, error)]


# ---------------------------------------------------------------------------
# wlan1 guard.
# ---------------------------------------------------------------------------


def _wlan1_config(vap):
    config = {"system": {"hostname": "unit"}, "wireless": {"radios": {"wlan0": {}}}}
    if vap is not None:
        config["wireless"]["radios"]["wlan1"] = {"enabled": True, "vaps": [vap]}
    return config


def _guard_handler(monkeypatch):
    handler = TachyonHandler("192.0.2.1", {"username": "root", "password": "unused"})
    request = AsyncMock(return_value={})
    monkeypatch.setattr(handler, "_api_request", request)

    async def readback():
        return deepcopy(handler._last_applied_config)

    monkeypatch.setattr(handler, "_read_config_after_apply", readback)
    return handler, request


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "vap",
    (None, {"enabled": True, "network": {"zone": "lan"}}),
    ids=("no-wlan1", "zone-lan"),
)
async def test_wlan1_guard_passes(monkeypatch, vap):
    handler, request = _guard_handler(monkeypatch)

    assert await handler.apply_config(_wlan1_config(vap)) is True
    assert request.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "vap",
    (
        {"enabled": True, "network": {"zone": "wan"}},
        {"enabled": True, "network": {}},
        {"enabled": True},
    ),
    ids=("zone-wan", "no-zone", "no-network"),
)
async def test_wlan1_guard_refuses_without_a_request(monkeypatch, caplog, vap):
    handler, request = _guard_handler(monkeypatch)

    assert await handler.apply_config(_wlan1_config(vap)) is False
    assert request.await_count == 0
    assert "wireless.radios.wlan1.vaps[0].network.zone" in caplog.text
