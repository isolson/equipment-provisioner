"""Tests for port manager state transitions."""

import pytest

from provisioner.port_manager import PortManager


@pytest.mark.asyncio
async def test_ping_disconnect_clears_device_metadata():
    """When ping disconnect logic trips, stale model/checklist data should be cleared."""
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    state = manager.port_states[1]
    state.link_up = True
    state.device_detected = True
    state.device_type = "mikrotik"
    state.device_ip = "192.168.88.1"
    state.device_model = "hEX PoE"
    state.device_mac = "00:11:22:33:44:55"
    state.device_serial = "ABC123"
    state.last_result = "failed"
    state.last_error = "Invalid credentials"
    state.checklist.model_confirmed = "hEX PoE"
    state.checklist.login = False

    async def always_down(_iface: str, _ip: str) -> bool:
        return False

    async def no_detect(_port_num: int) -> None:
        return None

    manager._ping_device = always_down  # type: ignore[method-assign]
    manager._detect_device_on_port = no_detect  # type: ignore[method-assign]

    for _ in range(manager.PING_FAILURE_THRESHOLD):
        await manager._check_all_ports_parallel()

    assert state.link_up is False
    assert state.device_detected is False
    assert state.device_type is None
    assert state.device_ip is None
    assert state.device_model is None
    assert state.device_mac is None
    assert state.device_serial is None
    assert state.last_result is None
    assert state.last_error is None
    assert state.checklist.model_confirmed is None
    assert state.checklist.login is None


@pytest.mark.asyncio
async def test_link_down_during_boot_wait_preserves_state():
    """Link-down during boot wait is treated as autonegotiation flap.

    State should be preserved (boot_wait keeps running) so that when
    the link renegotiates back up, the boot cycle isn't reset.
    """
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    state = manager.port_states[1]
    state.link_up = True
    state.waiting_for_boot = True
    state.boot_wait_until = 9999999999
    state.boot_ping_responded = False
    state.link_speed = "100Mbps"

    handled = await manager.handle_switch_port_event("ether1", link_up=False, speed=None)
    assert handled is True

    # link_up should be False, but boot_wait state should remain intact
    assert state.link_up is False
    assert state.waiting_for_boot is True
    assert state.boot_wait_until == 9999999999
    assert state.link_speed == "100Mbps"  # preserved from earlier link-up


@pytest.mark.asyncio
async def test_link_renegotiation_during_boot_wait_updates_speed():
    """Link-down then link-up during boot wait should update speed."""
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    state = manager.port_states[1]
    state.link_up = True
    state.waiting_for_boot = True
    state.boot_wait_until = 9999999999
    state.link_speed = "100Mbps"

    # Link goes down during autonegotiation
    await manager.handle_switch_port_event("ether1", link_up=False, speed=None)
    assert state.link_up is False
    assert state.waiting_for_boot is True

    # Link comes back up at higher speed
    await manager.handle_switch_port_event("ether1", link_up=True, speed="1Gbps")
    assert state.link_up is True
    assert state.link_speed == "1Gbps"
    assert state.waiting_for_boot is True  # boot wait still running


@pytest.mark.asyncio
async def test_boot_wait_expiry_clears_state_when_link_down():
    """If link is still down when boot_wait expires, state should be fully cleared."""
    import time

    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    state = manager.port_states[1]
    state.link_up = False  # link went down during boot wait
    state.waiting_for_boot = True
    state.boot_wait_until = time.time() - 1  # already expired
    state.boot_ping_responded = False
    state.link_speed = "100Mbps"

    async def no_ping(_iface, _ip, **kw):
        return False

    async def no_detect(_port_num):
        return None

    manager._ping_device = no_ping  # type: ignore[method-assign]
    manager._detect_device_on_port = no_detect  # type: ignore[method-assign]

    await manager._check_all_ports_parallel()

    assert state.link_up is False
    assert state.waiting_for_boot is False
    assert state.device_detected is False
    assert state.link_speed is None


def test_firmware_banks_initial_is_preserved_across_updates():
    """Checklist should keep first firmware snapshot for from->to display."""
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    manager.update_checklist(1, "firmware_banks", "bank1:7.19|bank2:7.19|active:1")
    manager.update_checklist(1, "firmware_banks", "bank1:7.20.8|bank2:7.20.8|active:1")

    checklist = manager.port_states[1].checklist
    assert checklist.firmware_banks_initial == "bank1:7.19|bank2:7.19|active:1"
    assert checklist.firmware_banks == "bank1:7.20.8|bank2:7.20.8|active:1"


def test_port_configs_include_mikrotik_secondary_source_ip():
    """Each provisioning VLAN should carry the shared MikroTik /32 source IP by default."""
    manager = PortManager(num_ports=2)
    manager._generate_port_configs()

    for port_num in (1, 2):
        cfg = manager.ports[port_num]
        assert cfg.secondary_ips is not None
        assert "192.168.88.11/32" in cfg.secondary_ips
