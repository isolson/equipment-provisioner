"""A refused login shows a reset instruction and retries after a reset.

The fixture is the redacted bench log of a Cambium ePMP 4625 that refused
every login (port 6, 2026-09-29). The device stays connected and powered
during the reset, so the retry comes from its reboot signature: a link down
and up, or a ping loss and return.
"""

import dataclasses
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from provisioner import vendor_registry
from provisioner.handlers.base import ConnectionFailureKind
from provisioner.port_manager import (
    RESULT_LOGIN_FAILED,
    DeviceLinkLocalIP,
    PortManager,
)
from provisioner.web.api import PortStatus
from provisioner.workflow_actions import presentation_for_port, result_reason_for


FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "login_failed_cambium_epmp4625.json").read_text()
)
MAC = "00:04:56:AA:BB:CC"
HEADLINE = "Login failed: reset may resolve"
DEFAULT_ACTION = "Hold the reset button 10 s while the device stays powered."


def test_fixture_has_no_credential_value():
    text = json.dumps(FIXTURE).lower()
    for secret_marker in ("admin/admin", "password=", "passwd", "psk"):
        assert secret_marker not in text


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authentication_failure_classifies_as_login_failed(spy_handler_factory):
    spy = spy_handler_factory()

    async def connect():
        spy.login_error = FIXTURE["login_error"]
        spy.set_connection_failure(
            ConnectionFailureKind(FIXTURE["connection_failure_kind"])
        )
        return False

    spy.connect = connect
    result = await spy.provision()

    assert result.success is False
    assert result.needs_credentials is True
    assert result_reason_for(result) == RESULT_LOGIN_FAILED == "login_failed"


@pytest.mark.asyncio
async def test_transport_failure_has_no_result_reason(spy_handler_factory, fast_sleep):
    spy = spy_handler_factory()

    async def connect():
        # The text mentions a password, but the typed kind decides.
        spy.login_error = "Connection timed out after password prompt"
        spy.set_connection_failure(ConnectionFailureKind.TRANSPORT)
        return False

    spy.connect = connect
    result = await spy.provision()

    assert result.needs_credentials is False
    assert result_reason_for(result) is None


# ---------------------------------------------------------------------------
# Reset instruction resolution
# ---------------------------------------------------------------------------


def test_default_reset_action_for_the_bench_case():
    assert vendor_registry.DEFAULT_RESET_ACTION == DEFAULT_ACTION
    assert vendor_registry.reset_action(
        FIXTURE["device_type"], FIXTURE["device_model"]
    ) == DEFAULT_ACTION
    assert vendor_registry.reset_action("cambium", None) == DEFAULT_ACTION
    assert vendor_registry.reset_action(None, None) == DEFAULT_ACTION
    assert vendor_registry.reset_action("unknown-vendor", "x") == DEFAULT_ACTION


def test_vendor_documented_variants():
    mikrotik = vendor_registry.reset_action("mikrotik", "hEX S")
    assert "apply power" in mikrotik
    assert mikrotik != DEFAULT_ACTION
    assert vendor_registry.reset_action("tachyon", "TNA-303X") == (
        "Hold the reset button 20 s while the device stays powered."
    )
    # No vendor document was found for these vendors: default.
    assert vendor_registry.reset_action("tarana", "RN") == DEFAULT_ACTION
    assert vendor_registry.reset_action("ubiquiti", "Wave-Pro") == DEFAULT_ACTION


def test_family_variant_overrides_vendor_value(monkeypatch):
    spec = vendor_registry._SPECS["cambium"]
    families = tuple(
        dataclasses.replace(family, reset_action="Family action.")
        if family.directory == "ePMP-4K" else family
        for family in spec.config_families
    )
    patched = dataclasses.replace(
        spec, reset_action="Vendor action.", config_families=families
    )
    monkeypatch.setitem(vendor_registry._SPECS, "cambium", patched)

    assert vendor_registry.reset_action("cambium", "ePMP 4625") == "Family action."
    assert vendor_registry.reset_action("cambium", "ePMP 3000") == "Vendor action."


# ---------------------------------------------------------------------------
# Port state, API field, and card presentation
# ---------------------------------------------------------------------------


def _failed_port(manager, port_num=1):
    """Put a port in the state the bench log left port 6 in."""
    state = manager.port_states[port_num]
    state.link_up = True
    state.device_detected = True
    state.device_type = FIXTURE["device_type"]
    state.device_model = FIXTURE["device_model"]
    state.device_ip = FIXTURE["device_ip"]
    state.device_mac = MAC
    state.provision_attempted = True
    manager.mark_port_provisioning(port_num, True)
    manager.set_needs_credentials(port_num, True)
    manager.set_result_reason(port_num, RESULT_LOGIN_FAILED)
    manager.mark_port_provisioning(
        port_num, False, success=False, error=FIXTURE["login_error"]
    )
    return state


def test_api_port_status_reports_reason_and_instruction():
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()
    _failed_port(manager)

    status = manager._get_single_port_status(1)
    model = PortStatus(port_number=1, **status)

    assert model.result_reason == "login_failed"
    assert model.reset_instruction == DEFAULT_ACTION
    assert model.presentation["phase"] == "login_failed"
    assert model.presentation["headline"] == HEADLINE
    assert model.presentation["detail"] == DEFAULT_ACTION
    assert model.presentation["tone"] == "warning"
    assert "reconnect" not in json.dumps(status).lower()


def test_instruction_survives_the_reset_reboot():
    """Link loss clears the model, so the instruction is resolved at failure."""
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()
    state = _failed_port(manager)

    manager._clear_port_state_on_disconnect(1)

    assert state.device_type is None
    p = presentation_for_port(state, True)
    assert p["phase"] == "login_failed"
    assert p["detail"] == DEFAULT_ACTION


def test_new_attempt_clears_the_reset_message():
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()
    state = _failed_port(manager)

    manager.mark_port_provisioning(1, True)

    assert state.result_reason is None
    assert state.reset_instruction is None
    assert presentation_for_port(state, True)["phase"] == "running"


# ---------------------------------------------------------------------------
# Auto-retry after a factory reset
# ---------------------------------------------------------------------------


def _detect_mocks(manager, monkeypatch, reachable):
    """Mock detection. ``reachable`` is a one-item list the test flips."""
    monkeypatch.setattr(
        DeviceLinkLocalIP, "ALL", [(FIXTURE["device_ip"], [FIXTURE["device_type"]])]
    )
    monkeypatch.setattr(DeviceLinkLocalIP, "MIKROTIK_FALLBACKS", [])

    async def ping(_iface, _ip, arp_fallback=True):
        return reachable[0]

    manager._ping_device = ping  # type: ignore[method-assign]
    manager._try_passive_detection = AsyncMock(return_value=None)  # type: ignore[method-assign]
    manager._identify_device_type = AsyncMock(  # type: ignore[method-assign]
        return_value=FIXTURE["device_type"]
    )
    manager._lookup_neighbor_mac = AsyncMock(return_value=MAC)  # type: ignore[method-assign]
    detected = AsyncMock()
    manager.on_device_detected(detected)
    return detected


def _in_cooldown(state):
    """Make the same MAC look recently provisioned (30-minute cooldown)."""
    state.last_provisioned_at = time.time()
    state.last_provisioned_mac = MAC


@pytest.mark.asyncio
async def test_no_retry_while_the_device_stays_reachable(monkeypatch):
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()
    state = _failed_port(manager)
    detected = _detect_mocks(manager, monkeypatch, [True])

    for _ in range(manager.PING_FAILURE_THRESHOLD * 3):
        await manager._check_all_ports_parallel()

    detected.assert_not_awaited()
    assert state.result_reason == RESULT_LOGIN_FAILED
    assert state.provision_attempted is True


@pytest.mark.asyncio
async def test_retry_after_unreachable_then_reachable_with_link_up(monkeypatch):
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()
    state = _failed_port(manager)
    _in_cooldown(state)
    reachable = [False]
    detected = _detect_mocks(manager, monkeypatch, reachable)

    # The reset reboots the device: pings stop, the link stays up.
    for _ in range(manager.PING_FAILURE_THRESHOLD + 2):
        await manager._check_all_ports_parallel()
    detected.assert_not_awaited()
    assert presentation_for_port(state, True)["phase"] == "login_failed"

    reachable[0] = True
    await manager._check_all_ports_parallel()

    detected.assert_awaited_once_with(1, FIXTURE["device_type"], FIXTURE["device_ip"])

    # The device stays up after the retry starts: no second attempt.
    for _ in range(3):
        await manager._check_all_ports_parallel()
    detected.assert_awaited_once()


@pytest.mark.asyncio
async def test_retry_after_link_down_and_up_with_same_mac(monkeypatch):
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()
    state = _failed_port(manager)
    _in_cooldown(state)
    detected = _detect_mocks(manager, monkeypatch, [True])

    await manager.handle_switch_port_event("ether1", False)
    await manager.handle_switch_port_event("ether1", True)
    assert state.waiting_for_boot is True
    state.boot_wait_until = time.time() - 1

    await manager._check_all_ports_parallel()

    detected.assert_awaited_once_with(1, FIXTURE["device_type"], FIXTURE["device_ip"])


@pytest.mark.asyncio
async def test_cooldown_still_blocks_a_successful_device(monkeypatch):
    """Control case: without the login failure the cooldown holds."""
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()
    state = _failed_port(manager)
    state.result_reason = None
    state.reset_instruction = None
    _in_cooldown(state)
    detected = _detect_mocks(manager, monkeypatch, [True])

    await manager.handle_switch_port_event("ether1", False)
    await manager.handle_switch_port_event("ether1", True)
    state.boot_wait_until = time.time() - 1
    await manager._check_all_ports_parallel()

    detected.assert_not_awaited()
