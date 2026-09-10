"""Golden-value lock for every vendor-derived view (Story 6 / #76).

The VendorSpec registry refactor must be a ZERO-behavior change: every
derived view (handler map, firmware source map, firmware filename
patterns, credential defaults, link-local IPs and their probe orders,
config field defaults, kiosk UI metadata) must remain byte-identical to
the pre-registry values. This file locks those values as literals,
captured on main *before* the refactor, so the derivation change is
provably behavior-preserving.

Unlike tests/test_vendor_registry.py (which asserts the registries agree
with *each other* and will evolve with the registry), this file asserts
the registries agree with *history*. If a vendor is legitimately added,
removed, or has its data intentionally changed, update the literals here
in the same commit — that is the point: the diff makes the behavioral
change explicit and reviewable.

Ordering notes (why the tests assert list(…) and not just ==):

- ``VENDOR_LINK_LOCAL_IPS`` insertion order IS the detection-probe order
  (#74); ``probe_ip_candidates``/``boot_ping_ips`` derive from it.
- ``_default_credentials`` / ``_default_firmware_sources`` /
  ``DeviceIPsConfig`` orders are user-visible in config serialization.
- ``vendor_ui_metadata`` order is the injection order of the kiosk's
  ``deviceVendors`` literal.
- ``HANDLER_MAP`` order is the registration order.
- ``SOURCE_MAP`` and ``BUILTIN_CREDENTIALS`` are lookup-only (``.get``),
  so plain equality is asserted for them.
"""

from provisioner.config import (
    DeviceIPsConfig,
    _default_credentials,
    _default_firmware_sources,
)
from provisioner.fingerprint import DeviceType
from provisioner.firmware import FirmwareManager
from provisioner.firmware_checker import FirmwareChecker
from provisioner.handler_manager import HandlerManager, provisionable_device_types
from provisioner.vendor_ips import (
    VENDOR_LINK_LOCAL_IPS,
    boot_ping_ips,
    device_ips_vendors,
    probe_ip_candidates,
)
from provisioner.web.api import BUILTIN_CREDENTIALS, vendor_ui_metadata


def test_handler_map_golden():
    assert [
        (dt.value, "{}.{}".format(cls.__module__, cls.__name__))
        for dt, cls in HandlerManager.HANDLER_MAP.items()
    ] == [
        ("mikrotik", "provisioner.handlers.mikrotik.MikrotikHandler"),
        ("cambium", "provisioner.handlers.cambium.CambiumHandler"),
        ("tachyon", "provisioner.handlers.tachyon.TachyonHandler"),
        ("tarana", "provisioner.handlers.tarana.TaranaHandler"),
        ("ubiquiti", "provisioner.handlers.ubiquiti.UbiquitiHandler"),
    ]
    # Keys are DeviceType members (not plain strings) — get_handler looks
    # up fingerprint.device_type directly.
    assert all(isinstance(dt, DeviceType) for dt in HandlerManager.HANDLER_MAP)


def test_source_map_golden():
    assert {
        vendor: "{}.{}".format(cls.__module__, cls.__name__)
        for vendor, cls in FirmwareChecker.SOURCE_MAP.items()
    } == {
        "tachyon": "provisioner.firmware_sources.tachyon.TachyonFirmwareSource",
        "ubiquiti": "provisioner.firmware_sources.ubiquiti.UbiquitiFirmwareSource",
        "cambium": "provisioner.firmware_sources.cambium.CambiumFirmwareSource",
        "mikrotik": "provisioner.firmware_sources.mikrotik.MikrotikFirmwareSource",
    }


def test_model_firmware_patterns_golden():
    expected = {
        # Cambium
        "epmp 4518": ["epmp-ax", "epmp_ax"],
        "epmp 4525": ["epmp-ax", "epmp_ax"],
            "epmp 4600": ["epmp-ax", "epmp_ax"],
            "epmp 4600c": ["epmp-ax", "epmp_ax"],
            "epmp 4616": ["epmp-ax", "epmp_ax"],
            "epmp 4625": ["epmp-ax", "epmp_ax"],
        "force 300-25": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300-19": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300-16": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300-13": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "force 300 csm": ["epmp-ac", "epmp_ac", "force300", "force-300"],
        "epmp 3000": ["epmp-ac", "epmp_ac"],
        "epmp 3000l": ["epmp-ac", "epmp_ac"],
        "epmp 3000 mp": ["epmp-ac", "epmp_ac"],
        "epmp 2000": ["epmp-nongps", "epmp2000"],
        "epmp 1000": ["epmp1000", "epmp-nongps"],
        # Tachyon
        "tna-303x": ["tna-30x", "tna30x"],
        "tna-301": ["tna-30x", "tna30x"],
        "tna-302": ["tna-30x", "tna30x"],
        "tna-303l": ["tna-303l", "tna303l"],
        "tna-303l-65": ["tna-303l", "tna303l"],
        "tna-303l-lib": ["tna-303l", "tna303l"],
        "tna-305a": ["tna-305", "tna305"],
        "tna-305x": ["tna-305", "tna305"],
        "tns-100": ["tns-100", "tns100"],
        # Ubiquiti
        "wave-pro": ["75ba-wave", "gmc"],
        "wave-ap": ["75ba-wave", "gmc"],
        "wave-ap-micro": ["75ba-wave", "gmc"],
        "wave-pico": ["75ba-wave", "gmc"],
        "wave-nano": ["02da-wave", "mgmp"],
        "wave-micro": ["02da-wave", "mgmp"],
        "wave-lr": ["02da-wave", "mgmp"],
        "rocket": ["airmax"],
        "nanostation": ["airmax"],
        "litebeam": ["airmax"],
        "powerbeam": ["airmax"],
        "nanobeam": ["airmax"],
        "af-5xhd": ["322c-airfiber"],
        "af60-lr": ["airfiber"],
        "af60-xr": ["airfiber"],
        "af60-hd": ["airfiber"],
        "af-11fx": ["airfiber"],
    }
    actual = FirmwareManager.MODEL_FIRMWARE_PATTERNS
    assert actual == expected
    assert list(actual) == list(expected)


def test_default_credentials_golden():
    dumped = {v: c.model_dump() for v, c in _default_credentials().items()}
    assert dumped == {
        "cambium": {
            "username": "admin", "password": "admin", "backup_password": "",
            "bootstrap_password": "", "onboarding_password": "",
            "wpa_key": "", "snmp_community": "",
        },
        "mikrotik": {
            "username": "admin", "password": "", "backup_password": "",
            "bootstrap_password": "", "onboarding_password": "",
            "wpa_key": "", "snmp_community": "",
        },
        "tachyon": {
            "username": "root", "password": "admin", "backup_password": "",
            "bootstrap_password": "", "onboarding_password": "",
            "wpa_key": "", "snmp_community": "",
        },
        "tarana": {
            "username": "admin", "password": "", "backup_password": "",
            "bootstrap_password": "", "onboarding_password": "",
            "wpa_key": "", "snmp_community": "",
        },
        "ubiquiti": {
            "username": "ubnt", "password": "ubnt", "backup_password": "",
            "bootstrap_password": "", "onboarding_password": "",
            "wpa_key": "", "snmp_community": "",
        },
    }
    assert list(_default_credentials()) == [
        "cambium", "mikrotik", "tachyon", "tarana", "ubiquiti",
    ]


def test_default_firmware_sources_golden():
    dumped = {v: c.model_dump() for v, c in _default_firmware_sources().items()}
    assert dumped == {
        "tachyon": {
            "enabled": True, "check_interval": 86400, "auto_download": True,
            "channel": "release", "include_beta": False, "models": [],
        },
        "mikrotik": {
            "enabled": True, "check_interval": 86400, "auto_download": True,
            "channel": "long-term", "include_beta": False, "models": [],
        },
        "ubiquiti": {
            "enabled": False, "check_interval": 86400, "auto_download": False,
            "channel": "release", "include_beta": False, "models": [],
        },
        "cambium": {
            "enabled": False, "check_interval": 86400, "auto_download": False,
            "channel": "release", "include_beta": False, "models": [],
        },
    }
    assert list(_default_firmware_sources()) == [
        "tachyon", "mikrotik", "ubiquiti", "cambium",
    ]


def test_vendor_ips_golden():
    assert VENDOR_LINK_LOCAL_IPS == {
        "cambium": ["169.254.1.1"],
        "tachyon": ["169.254.1.1", "192.168.1.1"],
        "ubiquiti": ["192.168.1.20"],
        "tarana": ["169.254.100.1"],
        "mikrotik": ["192.168.88.1"],
    }
    # Insertion order IS the detection-probe order (#74) — assert it too.
    assert list(VENDOR_LINK_LOCAL_IPS) == [
        "cambium", "tachyon", "ubiquiti", "tarana", "mikrotik",
    ]


def test_probe_and_boot_ping_orders_golden():
    assert probe_ip_candidates() == [
        ("169.254.1.1", ["cambium", "tachyon"]),
        ("192.168.1.1", ["tachyon"]),
        ("192.168.1.20", ["ubiquiti"]),
        ("169.254.100.1", ["tarana"]),
        ("192.168.88.1", ["mikrotik"]),
    ]
    assert boot_ping_ips() == [
        "169.254.1.1", "192.168.1.1", "192.168.1.20",
        "192.168.88.1", "169.254.100.1",
    ]


def test_device_ips_config_golden():
    assert device_ips_vendors() == [
        "cambium", "tachyon", "tarana", "ubiquiti", "mikrotik",
    ]
    dump = DeviceIPsConfig().model_dump()
    assert dump == {
        "cambium": "169.254.1.1",
        "tachyon": "169.254.1.1",
        "tarana": "169.254.100.1",
        "ubiquiti": "192.168.1.20",
        "mikrotik": "192.168.88.1",
    }
    assert list(dump) == ["cambium", "tachyon", "tarana", "ubiquiti", "mikrotik"]


def test_builtin_credentials_golden():
    assert BUILTIN_CREDENTIALS == {
        "cambium": [{"username": "admin", "password": "admin"}],
        "mikrotik": [{"username": "admin", "password": ""}],
        "tachyon": [{"username": "root", "password": "admin"}],
        "tarana": [{"username": "admin", "password": "admin123"}],
        "ubiquiti": [{"username": "ubnt", "password": "ubnt"}],
    }


def test_vendor_ui_metadata_golden():
    metadata = vendor_ui_metadata()
    assert metadata == {
        "cambium": {
            "name": "Cambium", "color": "#1A73E9",
            "defaultUser": "admin", "icon": "/static/vendor-icons/cambium.png",
        },
        "mikrotik": {
            "name": "MikroTik", "color": "#0E0E10",
            "defaultUser": "admin", "icon": "/static/vendor-icons/mikrotik.png",
        },
        "tachyon": {
            "name": "Tachyon", "color": "#a855f7",
            "defaultUser": "root", "icon": "/static/vendor-icons/tachyon.png",
        },
        "tarana": {
            "name": "Tarana", "color": "#d97706",
            "defaultUser": "admin", "icon": "/static/vendor-icons/tarana.png",
        },
        "ubiquiti": {
            "name": "Ubiquiti", "color": "#0559C9",
            "defaultUser": "ubnt", "icon": "/static/vendor-icons/ubiquiti.png",
        },
        "evolution_digital": {
            "name": "Evolution", "color": "#ec4899",
            "defaultUser": "", "icon": "/static/vendor-icons/evolution_digital.png",
        },
        "unknown": {
            "name": "Unknown", "color": "#6b7280",
            "defaultUser": "admin", "icon": "",
        },
    }
    assert list(metadata) == [
        "cambium", "mikrotik", "tachyon", "tarana", "ubiquiti",
        "evolution_digital", "unknown",
    ]


def test_provisionable_device_types_golden():
    assert provisionable_device_types() == [
        "cambium", "mikrotik", "tachyon", "tarana", "ubiquiti",
    ]
