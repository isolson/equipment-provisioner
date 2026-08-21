"""Single registry for vendor link-local / factory-default device IPs.

Story 4 of the vendor-isolation epic (#74). This module is the one place
that defines which link-local IPs each vendor's factory-default devices
answer on. Three previously drifting copies now derive from it:

- ``DeviceLinkLocalIP`` constants and ``DeviceLinkLocalIP.ALL``
  (``port_manager.py``) — the device-detection probe list.
- The boot-wait quick-ping list (``DeviceLinkLocalIP.BOOT_PING``,
  previously an inline ``ips_to_try`` literal in ``port_manager.py``).
- ``DeviceIPsConfig`` field defaults (``config.py``) — the user-overridable
  ``ports.device_ips`` section of ``config.yaml``.

The mapping is many-to-many: one IP can serve several vendors
(``169.254.1.1`` answers for both Cambium and Tachyon — disambiguated
later by fingerprinting/content sniffing), and one vendor can have several
IPs (Tachyon also ships at ``192.168.1.1``).

Order is load-bearing (see #74 "probe order matters"):

- **Dict insertion order is the detection-probe order.** ``ALL`` derives
  by walking vendors in registry order; the first vendor listed for a
  shared IP is the first disambiguation candidate. Do not reorder without
  fixture-backed verification.
- **Inner list order:** the first IP is the vendor's primary/default
  address (used for ``DeviceIPsConfig`` defaults); later entries are
  alternates (e.g. Tachyon's ``192.168.1.1``).
- The boot-ping list historically used a slightly different order (the
  MikroTik default before Tarana); ``_BOOT_PING_VENDOR_ORDER`` below
  preserves it exactly.

A vendor missing from this registry is silently undetectable at link-up
and costs ~120 s of detection delay per device (S2 failure mode — see
``docs/ARCHITECTURE_ISOLATION_REVIEW.md``). ``tests/test_vendor_registry.py``
asserts this registry covers the canonical vendor set.

MikroTik's *fallback* LAN subnets (``192.168.0.1``, ``10.0.0.1``) are
deliberately NOT in this registry: they are only probed after every
standard probe misses, so they stay in
``port_manager.DeviceLinkLocalIP.MIKROTIK_FALLBACKS`` (behavior, not
enumeration).
"""

from typing import Dict, List, Tuple

# vendor -> ordered list of link-local/default IPs.
# THE single source of truth — add or change vendor IPs here only.
VENDOR_LINK_LOCAL_IPS = {
    "cambium": ["169.254.1.1"],
    "tachyon": ["169.254.1.1", "192.168.1.1"],  # 192.168.1.1: some Tachyon devices use this
    "ubiquiti": ["192.168.1.20"],  # Ubiquiti AirMax and Wave default
    "tarana": ["169.254.100.1"],
    "mikrotik": ["192.168.88.1"],  # Mikrotik default, but often uses DHCP
}  # type: Dict[str, List[str]]

# Historical boot-wait quick-ping vendor order, preserved exactly per #74's
# zero-behavior-change requirement. It differs from the detection-probe
# order (registry insertion order) only in trying the MikroTik default
# before Tarana. Order metadata only — the IPs still come from
# VENDOR_LINK_LOCAL_IPS. Registry vendors missing from this tuple are
# appended in registry order, so adding a vendor needs only a
# VENDOR_LINK_LOCAL_IPS edit; a consistency test rejects stale (removed)
# vendors here.
_BOOT_PING_VENDOR_ORDER = ("cambium", "tachyon", "ubiquiti", "mikrotik", "tarana")


def probe_ip_candidates():
    # type: () -> List[Tuple[str, List[str]]]
    """Ordered ``(ip, [candidate vendors])`` list for device detection.

    Derivation: walk vendors in registry order; the first vendor that
    lists an IP fixes that IP's probe position, and later vendors sharing
    the IP append to its candidate list. This reproduces the historical
    ``DeviceLinkLocalIP.ALL`` exactly (order and candidate order).
    """
    ordered = []  # type: List[Tuple[str, List[str]]]
    by_ip = {}  # type: Dict[str, List[str]]
    for vendor, ips in VENDOR_LINK_LOCAL_IPS.items():
        for ip in ips:
            if ip not in by_ip:
                candidates = []  # type: List[str]
                by_ip[ip] = candidates
                ordered.append((ip, candidates))
            if vendor not in by_ip[ip]:
                by_ip[ip].append(vendor)
    return ordered


def boot_ping_ips():
    # type: () -> List[str]
    """Ordered, de-duplicated IP list for the boot-wait liveness ping.

    Same IP set as :func:`probe_ip_candidates` (a consistency test
    enforces this), in the historical boot-ping order
    (``_BOOT_PING_VENDOR_ORDER``); vendors added to the registry after
    that order was frozen are appended in registry order.
    """
    ordered_vendors = [v for v in _BOOT_PING_VENDOR_ORDER if v in VENDOR_LINK_LOCAL_IPS]
    ordered_vendors += [v for v in VENDOR_LINK_LOCAL_IPS if v not in _BOOT_PING_VENDOR_ORDER]
    ips = []  # type: List[str]
    for vendor in ordered_vendors:
        for ip in VENDOR_LINK_LOCAL_IPS[vendor]:
            if ip not in ips:
                ips.append(ip)
    return ips


def primary_ip(vendor):
    # type: (str) -> str
    """The vendor's primary/default link-local IP (first registry entry)."""
    return VENDOR_LINK_LOCAL_IPS[vendor][0]


# Historical DeviceIPsConfig field declaration order (the pre-registry typed
# class in config.py), preserved so config serialization order stays
# byte-identical (PR #124 review). Cosmetic order metadata only — same
# partial-order semantics as _BOOT_PING_VENDOR_ORDER: registry vendors
# missing from this tuple are appended in registry order, so adding a
# vendor still needs only a VENDOR_LINK_LOCAL_IPS edit.
_DEVICE_IPS_FIELD_ORDER = ("cambium", "tachyon", "tarana", "ubiquiti", "mikrotik")


def device_ips_vendors():
    # type: () -> List[str]
    """Vendor order for DeviceIPsConfig fields (historical order first,
    then any registry vendors added since, in registry order)."""
    ordered = [v for v in _DEVICE_IPS_FIELD_ORDER if v in VENDOR_LINK_LOCAL_IPS]
    ordered += [v for v in VENDOR_LINK_LOCAL_IPS if v not in _DEVICE_IPS_FIELD_ORDER]
    return ordered
