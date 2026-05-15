"""Regression tests for the MikroTik BOOTP auto-trigger pipeline.

Covers three integration points introduced by the auto-trigger feature:
  1. The BOOTP frame parser in fingerprint.DeviceFingerprinter
  2. The per-port octet derivation that keeps concurrent Netinstalls
     on distinct /24s
  3. The port_manager listener loop's idempotency gates
     (provision_attempted / last_provisioned_mac / REPROVISION_COOLDOWN)
"""

import struct
import time
from unittest.mock import AsyncMock

import pytest

from provisioner.fingerprint import DeviceFingerprinter
from provisioner.handlers.mikrotik import MikrotikHandler
from provisioner.port_manager import PortManager


# ---------------------------------------------------------------------------
# BOOTP frame parser
# ---------------------------------------------------------------------------


def _build_bootp_request(client_mac: bytes, broken: str = "") -> bytes:
    """Build a valid Ethernet/IPv4/UDP/BOOTP request frame.

    Parameters
    ----------
    client_mac : 6-byte client hardware address to embed in chaddr.
    broken : optional sentinel to corrupt one field for negative tests:
        "ethertype"   — non-IPv4 ethertype
        "ip-proto"    — IPv4 protocol != UDP
        "udp-ports"   — wrong UDP src/dst ports
        "bootp-op"    — BOOTP op != 1
    """
    assert len(client_mac) == 6
    # Ethernet header
    dst_mac = b"\xff\xff\xff\xff\xff\xff"
    src_mac = client_mac
    ethertype = b"\x08\x00" if broken != "ethertype" else b"\x86\xdd"

    # IPv4 header (20 bytes, IHL=5)
    version_ihl = 0x45
    dscp_ecn = 0
    total_length = 0  # will fix
    ident = 0
    flags_frag = 0
    ttl = 64
    proto = 17 if broken != "ip-proto" else 6  # 17=UDP, 6=TCP
    checksum = 0
    src_ip = b"\x00\x00\x00\x00"
    dst_ip = b"\xff\xff\xff\xff"

    # UDP header (8 bytes)
    udp_src = 68 if broken != "udp-ports" else 12345
    udp_dst = 67 if broken != "udp-ports" else 54321
    udp_length = 0  # will fix
    udp_checksum = 0

    # BOOTP (300 bytes total; we only need first 44 for chaddr)
    bootp_op = 1 if broken != "bootp-op" else 2
    bootp_htype = 1
    bootp_hlen = 6
    bootp_hops = 0
    bootp_xid = 0xDEADBEEF
    bootp_secs = 0
    bootp_flags = 0x8000  # broadcast
    bootp_ciaddr = b"\x00\x00\x00\x00"
    bootp_yiaddr = b"\x00\x00\x00\x00"
    bootp_siaddr = b"\x00\x00\x00\x00"
    bootp_giaddr = b"\x00\x00\x00\x00"
    bootp_chaddr = client_mac + b"\x00" * 10  # 16 bytes total
    bootp_sname = b"\x00" * 64
    bootp_file = b"\x00" * 128
    bootp_vend = b"\x00" * 64  # truncated

    bootp = struct.pack(
        "!BBBBLHH",
        bootp_op, bootp_htype, bootp_hlen, bootp_hops,
        bootp_xid, bootp_secs, bootp_flags,
    ) + bootp_ciaddr + bootp_yiaddr + bootp_siaddr + bootp_giaddr + bootp_chaddr + bootp_sname + bootp_file + bootp_vend

    udp_length = 8 + len(bootp)
    udp_header = struct.pack("!HHHH", udp_src, udp_dst, udp_length, udp_checksum)

    total_length = 20 + udp_length
    ip_header = struct.pack(
        "!BBHHHBBH",
        version_ihl, dscp_ecn, total_length, ident, flags_frag, ttl, proto, checksum,
    ) + src_ip + dst_ip

    return dst_mac + src_mac + ethertype + ip_header + udp_header + bootp


class TestParseBootpRequestMac:
    def test_parses_valid_bootp_request(self):
        mac_bytes = bytes.fromhex("04f41cc20680")
        frame = _build_bootp_request(mac_bytes)
        assert DeviceFingerprinter.parse_bootp_request_mac(frame) == "04:f4:1c:c2:06:80"

    def test_rejects_non_ipv4_ethertype(self):
        frame = _build_bootp_request(b"\x04\xf4\x1c\xc2\x06\x80", broken="ethertype")
        assert DeviceFingerprinter.parse_bootp_request_mac(frame) is None

    def test_rejects_non_udp_ip(self):
        frame = _build_bootp_request(b"\x04\xf4\x1c\xc2\x06\x80", broken="ip-proto")
        assert DeviceFingerprinter.parse_bootp_request_mac(frame) is None

    def test_rejects_wrong_udp_ports(self):
        frame = _build_bootp_request(b"\x04\xf4\x1c\xc2\x06\x80", broken="udp-ports")
        assert DeviceFingerprinter.parse_bootp_request_mac(frame) is None

    def test_rejects_bootp_reply(self):
        frame = _build_bootp_request(b"\x04\xf4\x1c\xc2\x06\x80", broken="bootp-op")
        assert DeviceFingerprinter.parse_bootp_request_mac(frame) is None

    def test_rejects_short_frame(self):
        assert DeviceFingerprinter.parse_bootp_request_mac(b"\x00" * 50) is None

    def test_rejects_zero_chaddr(self):
        frame = _build_bootp_request(b"\x00\x00\x00\x00\x00\x00")
        assert DeviceFingerprinter.parse_bootp_request_mac(frame) is None


# ---------------------------------------------------------------------------
# Per-port octet derivation
# ---------------------------------------------------------------------------


class TestNetinstallOctetForInterface:
    def test_distinct_octet_per_vlan(self):
        # All current per-port VLANs (1991-1996) must map to distinct octets so
        # concurrent Netinstalls don't share kernel routes.
        octets = {
            MikrotikHandler._netinstall_octet_for_interface(f"eno1.{v}")
            for v in range(1991, 1997)
        }
        assert len(octets) == 6

    def test_legacy_fallback_for_non_vlan_interface(self):
        assert MikrotikHandler._netinstall_octet_for_interface("eth0") == 5

    def test_handles_malformed_vlan_id(self):
        assert MikrotikHandler._netinstall_octet_for_interface("eno1.notanumber") == 5

    def test_octet_stays_in_byte_range(self):
        for vlan in (0, 255, 256, 1995, 4095):
            octet = MikrotikHandler._netinstall_octet_for_interface(f"eno1.{vlan}")
            assert 0 <= octet <= 255


# ---------------------------------------------------------------------------
# Listener-loop idempotency gates
#
# We don't run the real sniff socket here; instead we hand the loop a stub
# sniffer that yields a sequence of MACs, then assert which iterations fire
# the callback.
# ---------------------------------------------------------------------------


class _FakeFingerprinter:
    """Replaces DeviceFingerprinter inside _bootp_listener_loop.

    Yields one MAC per sniff call from a queue; stops the surrounding loop
    by returning None and flipping the manager's _running flag once drained.
    """

    def __init__(self, manager: PortManager, macs):
        self._manager = manager
        self._macs = list(macs)

    def __call__(self, interface=None):  # mimic the constructor signature
        return self

    async def sniff_for_bootp_request(self, interface, timeout_sec):
        if self._macs:
            return self._macs.pop(0)
        # Drained — stop the listener cleanly.
        self._manager._running = False
        return None


@pytest.fixture
def manager():
    pm = PortManager(num_ports=2)
    pm._generate_port_configs()
    pm._running = True
    return pm


@pytest.mark.asyncio
async def test_listener_fires_callback_on_first_bootp(manager, monkeypatch):
    fake = _FakeFingerprinter(manager, ["aa:bb:cc:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []

    async def cb(port_num, mac):
        fired.append((port_num, mac))

    manager.on_device_in_bootp(cb)

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == [(1, "aa:bb:cc:00:00:01")]
    state = manager.port_states[1]
    assert state.provision_attempted is True


@pytest.mark.asyncio
async def test_listener_skips_when_already_provisioning(manager, monkeypatch):
    fake = _FakeFingerprinter(manager, ["aa:bb:cc:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []
    manager.on_device_in_bootp(AsyncMock(side_effect=lambda p, m: fired.append(m)))

    manager.port_states[1].provisioning = True

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == []
    # provisioning lock should not have toggled provision_attempted
    assert manager.port_states[1].provision_attempted is False


@pytest.mark.asyncio
async def test_listener_respects_cooldown_for_same_mac(manager, monkeypatch):
    fake = _FakeFingerprinter(manager, ["aa:bb:cc:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []
    manager.on_device_in_bootp(AsyncMock(side_effect=lambda p, m: fired.append(m)))

    state = manager.port_states[1]
    state.last_provisioned_at = time.time() - 60  # 1 min ago, inside 30-min cooldown
    state.last_provisioned_mac = "AA:BB:CC:00:00:01"

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == []
    assert state.provision_attempted is True  # marked so we don't keep re-checking


@pytest.mark.asyncio
async def test_listener_bypasses_cooldown_for_new_mac(manager, monkeypatch):
    fake = _FakeFingerprinter(manager, ["aa:bb:cc:99:99:99"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []

    async def cb(port_num, mac):
        fired.append((port_num, mac))

    manager.on_device_in_bootp(cb)

    state = manager.port_states[1]
    state.last_provisioned_at = time.time() - 60
    state.last_provisioned_mac = "00:00:00:00:00:00"  # different device

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == [(1, "aa:bb:cc:99:99:99")]


@pytest.mark.asyncio
async def test_listener_skips_when_provision_already_attempted_same_mac(manager, monkeypatch):
    """If we already fired for this MAC and it's still BOOTPing, don't refire."""
    fake = _FakeFingerprinter(manager, ["aa:bb:cc:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []
    manager.on_device_in_bootp(AsyncMock(side_effect=lambda p, m: fired.append(m)))

    state = manager.port_states[1]
    state.provision_attempted = True
    state.last_provisioned_mac = "aa:bb:cc:00:00:01"

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == []


@pytest.mark.asyncio
async def test_listener_skips_after_recent_failed_fire(manager, monkeypatch):
    """A recent BOOTP fire (e.g. a Netinstall failure that left no
    last_provisioned_mac) must throttle the next attempt — without this
    a stuck device would re-trigger every BOOTP_SNIFF_WINDOW_SEC."""
    fake = _FakeFingerprinter(manager, ["aa:bb:cc:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []
    manager.on_device_in_bootp(AsyncMock(side_effect=lambda p, m: fired.append(m)))

    state = manager.port_states[1]
    # Simulate: previous Netinstall fired, failed, and reset provision_attempted.
    # last_provisioned_at/_mac stayed None (failure path), but last_bootp_fired_at
    # was set when the previous fire happened a moment ago.
    state.last_bootp_fired_at = time.time() - 5

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == []


@pytest.mark.asyncio
async def test_listener_refires_after_retry_cooldown_expires(manager, monkeypatch):
    fake = _FakeFingerprinter(manager, ["aa:bb:cc:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []

    async def cb(port_num, mac):
        fired.append((port_num, mac))

    manager.on_device_in_bootp(cb)

    state = manager.port_states[1]
    # Older than BOOTP_RETRY_COOLDOWN_SEC — retry should be allowed.
    state.last_bootp_fired_at = time.time() - manager.BOOTP_RETRY_COOLDOWN_SEC - 1

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == [(1, "aa:bb:cc:00:00:01")]
