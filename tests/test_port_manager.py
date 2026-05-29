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


@pytest.mark.asyncio
async def test_disconnect_during_grace_then_expiry_clears_last_result():
    """A disconnect inside the post-provisioning grace window preserves
    last_result so the UI keeps COMPLETE while a device that just changed
    networks comes back. Once grace expires with the link still down, the
    polling loop must clear the stale state — otherwise the COMPLETE badge
    lingers until the next link-up or service restart.
    """
    import time

    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    state = manager.port_states[1]
    state.link_up = True
    state.last_result = "complete"
    state.provisioning_ended = time.time()
    state.checklist.login = True
    state.checklist.config_upload = True

    # Disconnect inside grace — last_result must survive.
    await manager.handle_switch_port_event("ether1", link_up=False, speed=None)
    assert state.link_up is False
    assert state.last_result == "complete"
    assert state.provisioning_ended is not None

    # Advance past the grace window.
    state.provisioning_ended = time.time() - manager.PROVISIONING_GRACE_PERIOD - 1

    async def no_ping(_iface, _ip, **kw):
        return False

    async def no_detect(_port_num):
        return None

    manager._ping_device = no_ping  # type: ignore[method-assign]
    manager._detect_device_on_port = no_detect  # type: ignore[method-assign]

    await manager._check_all_ports_parallel()

    assert state.last_result is None
    assert state.last_error is None
    assert state.provisioning_ended is None
    assert state.checklist.login is None
    assert state.checklist.config_upload is None


@pytest.mark.asyncio
async def test_post_grace_sweep_leaves_connected_complete_port_alone():
    """A device still plugged in after a successful run should keep its
    COMPLETE state even after grace expires — the sweep only fires on
    link-down. Otherwise we'd wipe the badge for a freshly provisioned
    device that's quietly running.
    """
    import time

    manager = PortManager(num_ports=1)
    manager._generate_port_configs()

    state = manager.port_states[1]
    state.link_up = True
    state.device_detected = True
    state.device_ip = "192.168.88.1"
    state.last_result = "complete"
    state.provisioning_ended = time.time() - manager.PROVISIONING_GRACE_PERIOD - 1
    state.checklist.login = True

    async def ping_ok(_iface, _ip, **kw):
        return True

    async def no_detect(_port_num):
        return None

    manager._ping_device = ping_ok  # type: ignore[method-assign]
    manager._detect_device_on_port = no_detect  # type: ignore[method-assign]

    await manager._check_all_ports_parallel()

    assert state.last_result == "complete"
    assert state.checklist.login is True


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


@pytest.mark.asyncio
async def test_passive_detection_sniff_timeout_at_least_10s():
    """Detection sniff window must be wide enough to cover ED router flap gaps.

    ED Plume routers retry cloud-registration ~every 146s with brief link
    drops. A 4s sniff window often coincided with a flap, captured zero
    frames, and detection failed. The sniff window stays >=10s so we still
    catch a frame between flaps.
    """
    manager = PortManager(num_ports=6)
    manager._generate_port_configs()

    captured_timeouts = []

    async def fake_passive(port_num, config, state, timeout_sec):
        captured_timeouts.append(timeout_sec)

    async def fake_ping(*_args, **_kwargs):
        return False

    manager._try_passive_detection = fake_passive  # type: ignore[method-assign]
    manager._ping_device = fake_ping  # type: ignore[method-assign]

    await manager._detect_device_on_port(3)

    assert captured_timeouts, "expected passive sniff to be invoked"
    assert all(t >= 10 for t in captured_timeouts), (
        f"sniff timeouts must be >=10s, got {captured_timeouts}"
    )


@pytest.mark.asyncio
async def test_passive_detection_skips_when_switch_link_down():
    """Sniff must not run on a VLAN sub-interface whose switch port is down.

    The MikroTik switch can flood/leak broadcast frames across VLANs, so a
    cable plugged into ether5 may surface its source MAC on eth0.1992 too.
    Without this guard, passive detection would phantom-mark ports 1/2/4/6
    as "detected ED router" with link_up=True even though no cable is
    physically connected to those switch ports.
    """
    manager = PortManager(num_ports=6)
    manager._generate_port_configs()

    sniff_calls = []

    async def fake_sniff(self, interface, timeout_sec, pi_mac=None):
        sniff_calls.append(interface)
        return "84:01:12:42:95:fe"  # would match ED if we got here

    config = manager.ports[2]
    state = manager.port_states[2]
    state.link_up = False  # switch never reported link-up for port 2

    with patch(
        "provisioner.fingerprint.DeviceFingerprinter.sniff_for_known_mac",
        new=fake_sniff,
    ):
        await manager._try_passive_detection(2, config, state, timeout_sec=10)

    assert sniff_calls == [], "must not sniff when switch link is down"
    assert state.device_detected is False
    assert state.device_type is None
    assert state.device_mac is None


@pytest.mark.asyncio
async def test_passive_detection_does_not_force_link_up():
    """A sniff match must not promote link_up from False to True.

    Link state is owned by switch events. Passive detection only confirms
    *what* is on a port whose switch already reports link-up — it must not
    invent a link-up state from a stray VLAN-tagged frame.
    """
    manager = PortManager(num_ports=6)
    manager._generate_port_configs()

    async def fake_sniff(self, interface, timeout_sec, pi_mac=None):
        return "84:01:12:42:95:fe"

    config = manager.ports[2]
    state = manager.port_states[2]
    state.link_up = False

    with patch(
        "provisioner.fingerprint.DeviceFingerprinter.sniff_for_known_mac",
        new=fake_sniff,
    ):
        await manager._try_passive_detection(2, config, state, timeout_sec=10)

    assert state.link_up is False, "passive detection must not force link_up"


@pytest.mark.asyncio
async def test_passive_detection_discards_match_if_link_drops_during_sniff():
    """If the link goes down while we're sniffing, drop any match we got.

    The frame may have been leaked from another VLAN before the link-down
    event arrived, so we shouldn't promote a port that's no longer up.
    """
    manager = PortManager(num_ports=6)
    manager._generate_port_configs()

    config = manager.ports[3]
    state = manager.port_states[3]
    state.link_up = True  # switch reports link is up at sniff start

    async def fake_sniff(self, interface, timeout_sec, pi_mac=None):
        # Simulate a link-down event arriving while we were blocked.
        state.link_up = False
        return "84:01:12:42:95:fe"

    with patch(
        "provisioner.fingerprint.DeviceFingerprinter.sniff_for_known_mac",
        new=fake_sniff,
    ):
        await manager._try_passive_detection(3, config, state, timeout_sec=10)

    assert state.device_detected is False
    assert state.device_type is None
    assert state.device_mac is None


@pytest.mark.asyncio
async def test_passive_detection_marks_detected_when_link_up_and_match():
    """Happy path: switch link is up and sniff caught an ED MAC."""
    manager = PortManager(num_ports=6)
    manager._generate_port_configs()

    config = manager.ports[5]
    state = manager.port_states[5]
    state.link_up = True

    async def fake_sniff(self, interface, timeout_sec, pi_mac=None):
        return "84:01:12:42:95:fe"

    with patch(
        "provisioner.fingerprint.DeviceFingerprinter.sniff_for_known_mac",
        new=fake_sniff,
    ):
        await manager._try_passive_detection(5, config, state, timeout_sec=10)

    assert state.device_detected is True
    assert state.device_type == "evolution_digital"
    assert state.device_mac == "84:01:12:42:95:fe"
