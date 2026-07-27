"""Canonical vendor link-local / default IP registry (Story #74).

Single source of truth for "which IPs do we probe to find a freshly-plugged
device". Lives in its own module so both ``port_manager`` (which probes) and
``config`` (which exposes the values for reference) can import it without a
cycle and without dragging the heavier port-management dependencies into
config loading.

Adding a vendor means adding one row to :data:`DeviceLinkLocalIP.ALL` — the
boot-ping list and the per-vendor config defaults both derive from it. A
vendor missing here costs ~120s of detection delay per device.
"""

from typing import Dict, List, Tuple


class DeviceLinkLocalIP:
    """Known link-local/default IPs for device types."""

    CAMBIUM = "169.254.1.1"
    TACHYON = "169.254.1.1"
    TACHYON_ALT = "192.168.1.1"  # Some Tachyon devices use this
    TARANA = "169.254.100.1"
    MIKROTIK = "192.168.88.1"  # Mikrotik default, but often uses DHCP
    UBIQUITI = "192.168.1.20"  # Ubiquiti AirMax and Wave default

    #: The registry. Every consumer derives from this — do not hand-maintain
    #: a parallel list. Order is the probe order.
    ALL: List[Tuple[str, List[str]]] = [
        ("169.254.1.1", ["cambium", "tachyon"]),
        ("192.168.1.1", ["tachyon"]),  # Tachyon alternate IP
        ("192.168.1.20", ["ubiquiti"]),  # Ubiquiti AirMax/Wave default
        ("169.254.100.1", ["tarana"]),
        ("192.168.88.1", ["mikrotik"]),
    ]

    # Some MikroTik units may be reset with different default LAN subnets.
    # We only probe these if standard defaults do not match.
    MIKROTIK_FALLBACKS = [
        "192.168.0.1",
        "10.0.0.1",
    ]

    @classmethod
    def probe_ips(cls) -> List[str]:
        """Every IP to probe, in registry order.

        Used by both device detection and the boot-wait liveness ping, which
        previously kept its own hand-maintained copy of this list.
        """
        return [ip for ip, _vendors in cls.ALL]

    @classmethod
    def primary_ip_by_vendor(cls) -> Dict[str, str]:
        """Vendor -> first IP in the registry that vendor answers on.

        Registry order decides the winner, so a vendor listed against
        several IPs (Tachyon) reports the one probed first.
        """
        primary: Dict[str, str] = {}
        for ip, vendors in cls.ALL:
            for vendor in vendors:
                primary.setdefault(vendor, ip)
        return primary
