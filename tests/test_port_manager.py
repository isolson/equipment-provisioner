"""Tests for port manager state transitions."""

from unittest.mock import AsyncMock, patch

import pytest

from provisioner.port_manager import DeviceLinkLocalIP, PortManager


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


# ============================================================================
# MikroTik ARP detection invariants
# ============================================================================


@pytest.mark.asyncio
async def test_ping_device_uses_arp_not_icmp_for_mikrotik_ip():
    """192.168.88.1 must use ARP-only detection, never ICMP.

    The pinned /32 management route sends ICMP to the switch (VLAN 1990),
    not the provisioning VLAN where the device lives.  ARP works at L2
    and bypasses kernel routing entirely.
    """
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    arp_calls = []

    async def mock_arp_probe(interface, ip, source_ip=None):
        arp_calls.append({"interface": interface, "ip": ip, "source_ip": source_ip})
        return True

    manager._arp_probe = mock_arp_probe  # type: ignore[method-assign]

    # _ping_device for MikroTik IP should call _arp_probe, not spawn ping
    result = await manager._ping_device("eth0.1992", DeviceLinkLocalIP.MIKROTIK)
    assert result is True
    assert len(arp_calls) == 1
    assert arp_calls[0]["ip"] == "192.168.88.1"
    assert arp_calls[0]["source_ip"] == "192.168.88.11"


@pytest.mark.asyncio
async def test_ping_device_arp_fallback_false_skips_mikrotik():
    """With arp_fallback=False, 192.168.88.1 should return False immediately.

    Boot pings use arp_fallback=False for quick liveness checks.  Since
    ICMP can't reach 192.168.88.1 on provisioning VLANs, and ARP is
    explicitly disabled, the result must be False.
    """
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    result = await manager._ping_device("eth0.1992", DeviceLinkLocalIP.MIKROTIK, arp_fallback=False)
    assert result is False


@pytest.mark.asyncio
async def test_arp_probe_includes_source_ip_in_command():
    """arping must use -s 192.168.88.11 so the ARP request comes from the same /24.

    Without the correct source IP, arping uses the first address on the
    interface (169.254.x.x) which MikroTik devices ignore because it's
    in a different subnet.
    """
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    captured_cmd = []

    async def mock_create_subprocess_exec(*cmd, **kwargs):
        captured_cmd.extend(cmd)
        proc = AsyncMock()
        proc.returncode = 1  # miss
        proc.communicate = AsyncMock(return_value=(b"", b""))
        return proc

    with patch("asyncio.create_subprocess_exec", side_effect=mock_create_subprocess_exec):
        await manager._arp_probe("eth0.1992", "192.168.88.1", source_ip="192.168.88.11")

    assert "-s" in captured_cmd
    s_idx = captured_cmd.index("-s")
    assert captured_cmd[s_idx + 1] == "192.168.88.11"
    assert "192.168.88.1" in captured_cmd  # target IP at end


# ============================================================================
# API / status field completeness
# ============================================================================


def test_get_single_port_status_includes_link_speed():
    """link_speed must be present in the status dict returned to the API.

    A missing field here silently breaks the web UI speed display because
    Pydantic defaults Optional fields to None rather than raising.
    """
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    state = manager.port_states[1]
    state.link_up = True
    state.link_speed = "1Gbps"

    status = manager._get_single_port_status(1)
    assert "link_speed" in status
    assert status["link_speed"] == "1Gbps"


def test_get_single_port_status_link_speed_none_when_unset():
    """link_speed should be None (not missing) when no speed is known."""
    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    status = manager._get_single_port_status(1)
    assert "link_speed" in status
    assert status["link_speed"] is None
