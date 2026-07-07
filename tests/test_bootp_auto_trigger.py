"""Regression tests for the MikroTik BOOTP auto-trigger pipeline.

Covers three integration points introduced by the auto-trigger feature:
  1. The BOOTP frame parser in fingerprint.DeviceFingerprinter
  2. The per-port octet derivation that keeps concurrent Netinstalls
     on distinct /24s
  3. The port_manager listener loop's idempotency gates
     (provision_attempted / last_provisioned_mac / BOOTP same-MAC retry block)
"""

import struct
import time
from unittest.mock import AsyncMock

import pytest

from provisioner.fingerprint import DeviceFingerprinter, is_mikrotik_oui
from provisioner.handlers.mikrotik import MikrotikHandler
from provisioner.port_manager import PortManager


class TestMikrotikOuiAllowlist:
    """The OUI allowlist gates destructive auto-netinstall, so it must cover
    MikroTik's full set of registered prefixes — including newer blocks."""

    def test_recognizes_newer_mikrotik_ouis(self):
        # Verified against the IEEE OUI registry (Routerboard.com / Mikrotikls).
        for mac in (
            "04:f4:1c:c2:06:80",  # hAP ax S bench unit that was being skipped
            "48:a9:8a:00:00:01",
            "d0:ea:11:00:00:01",
            "d4:01:c3:00:00:01",
            "f4:1e:57:00:00:01",
        ):
            assert is_mikrotik_oui(mac), f"{mac} should be recognized as MikroTik"

    def test_rejects_non_mikrotik_oui(self):
        assert not is_mikrotik_oui("ac:8b:a9:00:00:01")  # Ubiquiti
        assert not is_mikrotik_oui("")
        assert not is_mikrotik_oui("zz")


# ---------------------------------------------------------------------------
# BOOTP frame parser
# ---------------------------------------------------------------------------


def _build_bootp_request(
    client_mac: bytes,
    broken: str = "",
    vendor_payload: bytes = b"",
) -> bytes:
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
    bootp_vend = (vendor_payload + b"\x00" * 64)[:64]  # truncated

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

    def test_rejects_treehouse_cpe_bootp_probe(self):
        frame = _build_bootp_request(
            b"\x04\xf4\x1c\xc2\x06\x80",
            vendor_payload=b"\x63\x82\x53\x63\x3c\x0dTreehouse-CPE\xff",
        )
        assert DeviceFingerprinter.parse_bootp_request_mac(frame) is None

    def test_rejects_managed_fleet_hostname_bootp_probe(self):
        frame = _build_bootp_request(
            b"\x04\xf4\x1c\xc2\x06\x80",
            vendor_payload=b"\x63\x82\x53\x63\x0c\x16fleet-init-HKC0APZE4XT\xff",
        )
        assert DeviceFingerprinter.parse_bootp_request_mac(frame) is None

    def test_rejects_booted_routeros_dhcp_discover(self):
        """A booted (or factory-default) RouterOS device runs a DHCP client and
        broadcasts DHCP DISCOVER — BOOTP op=1 with the magic cookie + option 53.
        netinstall-cli ignores it ("Waiting for RouterBOARD..." → 300s timeout),
        so it must NOT trigger auto-netinstall. Captured on the bench from a
        genuine MikroTik OUI (04:f4:1c) stuck re-broadcasting DISCOVER.
        """
        # magic cookie + opt53=DISCOVER(1) + opt12 hostname "MikroTik" + END
        discover = (
            b"\x63\x82\x53\x63"      # DHCP magic cookie
            b"\x35\x01\x01"          # option 53 (message-type) = 1 (DISCOVER)
            b"\x0c\x08MikroTik"      # option 12 (hostname) = "MikroTik"
            b"\xff"                  # END
        )
        frame = _build_bootp_request(
            b"\x04\xf4\x1c\xc5\x4c\x83", vendor_payload=discover
        )
        assert DeviceFingerprinter.parse_bootp_request_mac(frame) is None

    def test_rejects_booted_routeros_dhcp_request(self):
        """DHCP REQUEST (option 53 = 3) is likewise a booted client, not a
        RouterBOOT Netinstall beacon."""
        request = b"\x63\x82\x53\x63\x35\x01\x03\xff"  # cookie + opt53=REQUEST + END
        frame = _build_bootp_request(
            b"\x04\xf4\x1c\xc5\x4c\x83", vendor_payload=request
        )
        assert DeviceFingerprinter.parse_bootp_request_mac(frame) is None

    def test_accepts_bare_bootp_with_cookie_but_no_message_type(self):
        """A bare BOOTP with the magic cookie but no DHCP message-type (the
        RouterBOOT Netinstall shape) must still match — we only reject frames
        that positively identify as a DHCP client via option 53."""
        vendor = b"\x63\x82\x53\x63\xff"  # cookie + END, no options
        frame = _build_bootp_request(
            b"\x04\xf4\x1c\xc2\x06\x80", vendor_payload=vendor
        )
        assert (
            DeviceFingerprinter.parse_bootp_request_mac(frame)
            == "04:f4:1c:c2:06:80"
        )


class TestDhcpMessageType:
    """Unit coverage for the DHCP option-53 extractor used to distinguish a
    booted DHCP client from a bare RouterBOOT Netinstall request."""

    def test_none_without_magic_cookie(self):
        assert DeviceFingerprinter._dhcp_message_type(b"") is None
        assert DeviceFingerprinter._dhcp_message_type(b"\x00" * 32) is None

    def test_none_when_cookie_present_but_no_option_53(self):
        # hostname option only, no message-type
        assert DeviceFingerprinter._dhcp_message_type(
            b"\x63\x82\x53\x63\x0c\x08MikroTik\xff"
        ) is None

    def test_extracts_discover_after_leading_options(self):
        # opt55 (param req list) before opt53 — must still be found via TLV walk
        vend = b"\x63\x82\x53\x63\x37\x03\x01\x03\x06\x35\x01\x01\xff"
        assert DeviceFingerprinter._dhcp_message_type(vend) == 1

    def test_handles_pad_and_truncation(self):
        # PAD bytes (0x00) then opt53=REQUEST; then truncated (no END)
        assert DeviceFingerprinter._dhcp_message_type(
            b"\x63\x82\x53\x63\x00\x00\x35\x01\x03"
        ) == 3


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
    fake = _FakeFingerprinter(manager, ["74:4d:28:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []

    async def cb(port_num, mac):
        fired.append((port_num, mac))

    manager.on_device_in_bootp(cb)

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == [(1, "74:4d:28:00:00:01")]
    state = manager.port_states[1]
    assert state.provision_attempted is True


@pytest.mark.asyncio
async def test_listener_skips_when_already_provisioning(manager, monkeypatch):
    fake = _FakeFingerprinter(manager, ["74:4d:28:00:00:01"])
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
    fake = _FakeFingerprinter(manager, ["74:4d:28:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []
    manager.on_device_in_bootp(AsyncMock(side_effect=lambda p, m: fired.append(m)))

    state = manager.port_states[1]
    state.last_provisioned_at = time.time() - 60  # 1 min ago, inside 30-min cooldown
    state.last_provisioned_mac = "74:4D:28:00:00:01"

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == []
    assert state.provision_attempted is True  # marked so we don't keep re-checking


@pytest.mark.asyncio
async def test_listener_bypasses_cooldown_for_new_mac(manager, monkeypatch):
    fake = _FakeFingerprinter(manager, ["74:4d:28:99:99:99"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []

    async def cb(port_num, mac):
        fired.append((port_num, mac))

    manager.on_device_in_bootp(cb)

    state = manager.port_states[1]
    state.last_provisioned_at = time.time() - 60
    state.last_provisioned_mac = "00:00:00:00:00:00"  # different device

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == [(1, "74:4d:28:99:99:99")]


@pytest.mark.asyncio
async def test_listener_skips_when_provision_already_attempted_same_mac(manager, monkeypatch):
    """If we already fired for this MAC and it's still BOOTPing, don't refire."""
    fake = _FakeFingerprinter(manager, ["74:4d:28:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []
    manager.on_device_in_bootp(AsyncMock(side_effect=lambda p, m: fired.append(m)))

    state = manager.port_states[1]
    state.provision_attempted = True
    state.last_provisioned_mac = "74:4d:28:00:00:01"

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == []


@pytest.mark.asyncio
async def test_listener_skips_same_mac_after_failed_fire(manager, monkeypatch):
    """A failed BOOTP-triggered Netinstall must not retry the same stuck unit.

    The field tech can remove/reinsert the device to clear port state. Without
    this gate, a unit left in BOOTP mode loops Netinstall attempts forever.
    """
    fake = _FakeFingerprinter(manager, ["74:4d:28:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []
    manager.on_device_in_bootp(AsyncMock(side_effect=lambda p, m: fired.append(m)))

    state = manager.port_states[1]
    # Simulate: previous Netinstall fired, failed, and reset provision_attempted.
    # last_provisioned_at/_mac stayed None (failure path), but last_bootp_fired_at
    # and last_bootp_fired_mac were set when the previous fire happened.
    state.last_bootp_fired_at = time.time() - 3600
    state.last_bootp_fired_mac = "74:4d:28:00:00:01"

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == []


@pytest.mark.asyncio
async def test_listener_refires_after_failed_fire_for_different_mac(manager, monkeypatch):
    fake = _FakeFingerprinter(manager, ["74:4d:28:00:00:02"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []

    async def cb(port_num, mac):
        fired.append((port_num, mac))

    manager.on_device_in_bootp(cb)

    state = manager.port_states[1]
    state.last_bootp_fired_at = time.time() - 5
    state.last_bootp_fired_mac = "74:4d:28:00:00:01"

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == [(1, "74:4d:28:00:00:02")]


@pytest.mark.asyncio
async def test_listener_skips_non_mikrotik_oui(manager, monkeypatch):
    """BOOTP from a non-MikroTik OUI must NOT trigger auto-netinstall.

    Netinstall is destructive (full reflash) and BOOTP isn't MikroTik-
    exclusive — Ubiquiti Wave U-Boot transmits BOOTP during boot too. The
    OUI allowlist gates the trigger before any callbacks fire.
    """
    # Ubiquiti OUI ac:8b:a9 — what triggered the original incident.
    fake = _FakeFingerprinter(manager, ["ac:8b:a9:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []
    manager.on_device_in_bootp(AsyncMock(side_effect=lambda p, m: fired.append(m)))

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == []
    # OUI gate should NOT mark the port as attempted — that's reserved for
    # actual fires so the BOOTP cooldown logic doesn't get confused.
    assert manager.port_states[1].provision_attempted is False


@pytest.mark.asyncio
async def test_listener_skips_non_mikrotik_oui_even_if_fingerprinted_as_other(manager, monkeypatch):
    """If the port is already fingerprinted as a non-MikroTik vendor, skip
    regardless of MAC OUI — covers the race where a slow BOOTP arrives
    after the vendor has been identified.
    """
    # Even with a real MikroTik OUI, if the port has been fingerprinted as
    # a different vendor, we don't run netinstall against it.
    fake = _FakeFingerprinter(manager, ["74:4d:28:00:00:01"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []
    manager.on_device_in_bootp(AsyncMock(side_effect=lambda p, m: fired.append(m)))

    manager.port_states[1].device_type = "ubiquiti"

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == []
    assert manager.port_states[1].provision_attempted is False


@pytest.mark.asyncio
async def test_listener_skips_stale_mikrotik_tag_with_non_mikrotik_oui(manager, monkeypatch):
    """A stale device_type=="mikrotik" must NOT authorize netinstall of a
    different, non-MikroTik device.

    Regression for the port-4 Wave Pico incident: a real MikroTik was
    netinstalled on the port (which set device_type="mikrotik" via the fire
    path), the tag was never cleared when that unit was removed, then a
    Ubiquiti Wave Pico was plugged into the same port. Its boot-time BOOTP
    (non-MikroTik OUI) must be ignored — the MikroTik OUI check is
    unconditional and does not exempt a lingering "mikrotik" tag. In the
    BOOTP window a MikroTik can't be live-fingerprinted (no services up), so
    a pre-fire "mikrotik" tag is always stale/auto, never trustworthy.
    """
    # Ubiquiti Wave Pico OUI 9c:05:d6 — the device from the incident.
    fake = _FakeFingerprinter(manager, ["9c:05:d6:b4:ad:cf"])
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []
    manager.on_device_in_bootp(AsyncMock(side_effect=lambda p, m: fired.append(m)))

    # Stale tag left over from the previous MikroTik on this port.
    manager.port_states[1].device_type = "mikrotik"

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == []
    # The OUI gate must not mark the port attempted (reserved for real fires).
    assert manager.port_states[1].provision_attempted is False


@pytest.mark.asyncio
async def test_listener_fires_for_mikrotik_oui_even_with_mikrotik_tag(manager, monkeypatch):
    """A genuine MikroTik OUI still fires even when the port already carries a
    "mikrotik" tag (e.g. from a prior fire) — the hardened OUI gate only
    blocks the non-MikroTik-OUI case.
    """
    fake = _FakeFingerprinter(manager, ["74:4d:28:00:00:01"])  # MikroTik OUI
    monkeypatch.setattr("provisioner.fingerprint.DeviceFingerprinter", fake)

    fired = []

    async def cb(port_num, mac):
        fired.append((port_num, mac))

    manager.on_device_in_bootp(cb)

    manager.port_states[1].device_type = "mikrotik"

    await manager._bootp_listener_loop(port_num=1, interface="eno1.1991")

    assert fired == [(1, "74:4d:28:00:00:01")]
