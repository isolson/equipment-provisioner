"""Snapshot tests for the five flow-control properties on each handler.

These lock in the current property values per (handler, model) so that
accidental changes during a refactor are caught immediately. Update the
expected values here intentionally when behavior is meant to change.

Properties under test (defined on ``BaseHandler`` and overridden per vendor):

* ``supports_dual_bank``
* ``update_triggers_reboot``
* ``verify_active_bank``       (default: returns ``update_triggers_reboot``)
* ``config_after_all_firmware``
* ``fw2_skips_reboot``
"""

import pytest

from provisioner.handlers.base import DeviceInfo
from provisioner.handlers.cambium import CambiumHandler
from provisioner.handlers.mikrotik import MikrotikHandler
from provisioner.handlers.tachyon import TachyonHandler
from provisioner.handlers.tarana import TaranaHandler
from provisioner.handlers.ubiquiti import UbiquitiHandler


CREDS = {"username": "admin", "password": "admin"}

PROPERTY_NAMES = (
    "supports_dual_bank",
    "update_triggers_reboot",
    "verify_active_bank",
    "config_after_all_firmware",
    "fw2_skips_reboot",
)


def _props(handler):
    return {name: getattr(handler, name) for name in PROPERTY_NAMES}


def _set_model(handler, model):
    handler._device_info = DeviceInfo(device_type=handler.device_type, model=model)


# ---------------------------------------------------------------------------
# Cambium — dual-bank only, recent commit added ePMP 3000 MP (SKU 62)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("model", [None, "ePMP 3000", "ePMP 3000 MP", "ePMP Force 4525"])
def test_cambium_properties(model):
    handler = CambiumHandler(ip="192.0.2.1", credentials=CREDS)
    if model:
        _set_model(handler, model)
    assert _props(handler) == {
        "supports_dual_bank": True,
        "update_triggers_reboot": False,
        "verify_active_bank": False,
        "config_after_all_firmware": False,
        "fw2_skips_reboot": False,
    }


@pytest.mark.parametrize(
    "model,expected",
    [
        # ePMP-AX (WiFi 6) models get the extended first-boot ceiling...
        ("ePMP 4525", 360),
        ("ePMP 4600C", 360),
        ("ePMP 4616", 360),
        ("Cambium ePMP 4625", 360),
        ("ePMP AX (SKU 53999)", 360),
        # ...including marketing variants that carry an AX model number.
        ("ePMP Force 4525", 360),
        # Non-AX models (and unknown) keep the default.
        ("ePMP 3000", 180),
        ("ePMP 3000 MP", 180),
        ("Force 300-25", 180),
        (None, 180),
    ],
)
def test_cambium_firmware_reboot_timeout(model, expected):
    handler = CambiumHandler(ip="192.0.2.1", credentials=CREDS)
    if model:
        _set_model(handler, model)
    assert handler.firmware_reboot_timeout == expected


# ---------------------------------------------------------------------------
# MikroTik — single-bank, no special flow
# ---------------------------------------------------------------------------


def test_mikrotik_properties():
    handler = MikrotikHandler(ip="192.0.2.1", credentials=CREDS)
    assert _props(handler) == {
        "supports_dual_bank": False,
        "update_triggers_reboot": False,
        "verify_active_bank": False,
        "config_after_all_firmware": False,
        "fw2_skips_reboot": False,
    }


def test_mikrotik_standard_step_plan_uses_routeros_labels():
    handler = MikrotikHandler(ip="192.0.2.1", credentials=CREDS)
    plan = handler.provisioning_step_plan(
        has_config=True,
        dual_bank=True,
        need_fw1=True,
        need_fw2=False,
    )
    labels = {item["key"]: item["label"] for item in plan}
    assert labels["firmware_banks"] == "Software check"
    assert labels["firmware_update_1"] == "RouterOS software"
    assert labels["verify"] == "Software verify"
    assert "firmware_update_2" not in labels


# ---------------------------------------------------------------------------
# Tachyon — auto-reboot; config_after_all_firmware is conditional on TNS- models
# ---------------------------------------------------------------------------


def test_tachyon_properties_default_no_model():
    """Without a model set, config_after_all_firmware is False."""
    handler = TachyonHandler(ip="192.0.2.1", credentials=CREDS)
    assert _props(handler) == {
        "supports_dual_bank": True,
        "update_triggers_reboot": True,
        "verify_active_bank": True,  # default = update_triggers_reboot
        "config_after_all_firmware": False,
        "fw2_skips_reboot": False,
    }


@pytest.mark.parametrize(
    "model,expected_deferred",
    [
        ("TNA-301", False),
        ("TNA-303L-65", False),
        ("TNS-100", True),
        ("tns-100", True),
        ("TNS-200", True),
    ],
)
def test_tachyon_config_after_all_firmware_by_model(model, expected_deferred):
    handler = TachyonHandler(ip="192.0.2.1", credentials=CREDS)
    _set_model(handler, model)
    assert handler.config_after_all_firmware is expected_deferred


@pytest.mark.parametrize(
    "model,expected_role",
    [
        ("TNA-301", "AP"),
        ("TNA-301-rev-a", "AP"),
        ("TNA-302", "SM"),
        ("TNA-302-rev-a", "SM"),
        ("TNA-303X", None),
        ("TNA-303L-65", "SM"),
        (None, None),
    ],
)
def test_tachyon_upload_role_is_model_specific(model, expected_role):
    assert TachyonHandler.upload_role_for_model(model) == expected_role


# ---------------------------------------------------------------------------
# Tarana — verify active bank + skip reboot on FW2
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("model", [None, "TNA-303L-65", "G1 RN", "G1 BN"])
def test_tarana_properties(model):
    handler = TaranaHandler(ip="192.0.2.1", credentials=CREDS)
    if model:
        _set_model(handler, model)
    assert _props(handler) == {
        "supports_dual_bank": True,
        "update_triggers_reboot": False,
        "verify_active_bank": True,
        "config_after_all_firmware": False,
        "fw2_skips_reboot": True,
    }


# ---------------------------------------------------------------------------
# Ubiquiti — properties depend on _api_style (set during connect())
# ---------------------------------------------------------------------------


def test_ubiquiti_properties_before_connect():
    """Before connect() sets _api_style, Ubiquiti looks single-bank."""
    handler = UbiquitiHandler(ip="192.0.2.1", credentials=CREDS)
    assert _props(handler) == {
        "supports_dual_bank": False,
        "update_triggers_reboot": False,
        "verify_active_bank": False,
        "config_after_all_firmware": False,
        "fw2_skips_reboot": False,
    }


def test_ubiquiti_wave_properties():
    """Wave devices report supports_dual_bank=True once detected."""
    handler = UbiquitiHandler(ip="192.0.2.1", credentials=CREDS)
    handler._api_style = "wave"
    assert _props(handler) == {
        "supports_dual_bank": True,
        "update_triggers_reboot": False,
        "verify_active_bank": False,
        "config_after_all_firmware": False,
        "fw2_skips_reboot": False,
    }


def test_ubiquiti_airos_properties():
    """AirOS devices stay single-bank."""
    handler = UbiquitiHandler(ip="192.0.2.1", credentials=CREDS)
    handler._api_style = "airos"
    assert _props(handler) == {
        "supports_dual_bank": False,
        "update_triggers_reboot": False,
        "verify_active_bank": False,
        "config_after_all_firmware": False,
        "fw2_skips_reboot": False,
    }


# ---------------------------------------------------------------------------
# firmware_lookup_key — handler-owned key for model-specific firmware lookup
# (base default: device model; MikroTik prefers the RouterOS architecture)
# ---------------------------------------------------------------------------

from provisioner.handlers.mock import MockHandler


@pytest.mark.parametrize(
    "handler_class",
    [CambiumHandler, TachyonHandler, TaranaHandler, UbiquitiHandler],
)
def test_firmware_lookup_key_default_is_model(handler_class):
    """Non-MikroTik vendors key firmware lookup by model, even when a
    hardware_version happens to be populated."""
    handler = handler_class(ip="192.0.2.1", credentials=CREDS)
    info = DeviceInfo(
        device_type=handler.device_type,
        model="MODEL-X",
        hardware_version="hw-rev-9",
    )
    assert handler.firmware_lookup_key(info) == "MODEL-X"


@pytest.mark.parametrize(
    "handler_class",
    [CambiumHandler, MikrotikHandler, TachyonHandler, TaranaHandler, UbiquitiHandler],
)
def test_firmware_lookup_key_none_device_info(handler_class):
    """No device_info yet ⇒ no key (and no crash), for every vendor."""
    handler = handler_class(ip="192.0.2.1", credentials=CREDS)
    assert handler.firmware_lookup_key(None) is None


def test_mikrotik_firmware_lookup_key_prefers_hardware_version():
    """RouterOS packages are per-architecture; get_info() stores the
    architecture in hardware_version."""
    handler = MikrotikHandler(ip="192.0.2.1", credentials=CREDS)
    info = DeviceInfo(device_type="mikrotik", model="hAP ax lite", hardware_version="arm")
    assert handler.firmware_lookup_key(info) == "arm"


@pytest.mark.parametrize("hardware_version", [None, ""])
def test_mikrotik_firmware_lookup_key_falsy_arch_falls_back_to_model(hardware_version):
    handler = MikrotikHandler(ip="192.0.2.1", credentials=CREDS)
    info = DeviceInfo(
        device_type="mikrotik",
        model="hAP ax lite",
        hardware_version=hardware_version,
    )
    assert handler.firmware_lookup_key(info) == "hAP ax lite"


def test_mikrotik_firmware_lookup_key_no_model_no_arch_is_none():
    handler = MikrotikHandler(ip="192.0.2.1", credentials=CREDS)
    info = DeviceInfo(device_type="mikrotik")
    assert handler.firmware_lookup_key(info) is None


def test_mock_simulating_mikrotik_uses_base_lookup():
    """MockHandler is not a vendor and never reports a hardware_version, so it
    keys firmware lookup by model even when simulating mikrotik. (The old
    vendor-string branch in base.py matched the mock's device_type but always
    fell through to model because hardware_version was never set.)"""
    handler = MockHandler(ip="192.0.2.1", credentials=CREDS, device_type="mikrotik")
    info = DeviceInfo(device_type="mikrotik", model="hAP ac2")
    assert handler.firmware_lookup_key(info) == "hAP ac2"
    assert handler.firmware_lookup_key(None) is None


# ---------------------------------------------------------------------------
# Class-level traits — consulted via HANDLER_MAP before instantiation
# (config-template lookup in config_store.py, model preflight in main.py)
# ---------------------------------------------------------------------------

from provisioner.handler_manager import HandlerManager
from provisioner.handlers.base import BaseHandler

TRAIT_NAMES = (
    "allows_prefixed_config_exports",
    "allows_arbitrary_template_fallback",
    "config_alias_prefix_matching",
    "requires_model_preflight",
)


def _traits(handler_class):
    return {name: getattr(handler_class, name) for name in TRAIT_NAMES}


def test_base_handler_trait_defaults():
    assert _traits(BaseHandler) == {
        "allows_prefixed_config_exports": False,
        "allows_arbitrary_template_fallback": True,
        "config_alias_prefix_matching": False,
        "requires_model_preflight": False,
    }


def test_tachyon_trait_overrides():
    assert _traits(TachyonHandler) == {
        "allows_prefixed_config_exports": True,
        "allows_arbitrary_template_fallback": False,
        "config_alias_prefix_matching": True,
        "requires_model_preflight": True,
    }


@pytest.mark.parametrize("handler_class", [MikrotikHandler, TaranaHandler, UbiquitiHandler])
def test_other_vendors_keep_trait_defaults(handler_class):
    assert _traits(handler_class) == _traits(BaseHandler)


def test_cambium_trait_overrides():
    # Every Cambium model maps to a family tree, so the vendor-root fallback
    # (which holds AP/PTP mode templates) is refused.
    assert _traits(CambiumHandler) == dict(_traits(BaseHandler), allows_arbitrary_template_fallback=False)


def test_handler_class_for_resolves_vendor_strings():
    assert HandlerManager.handler_class_for("tachyon") is TachyonHandler
    assert HandlerManager.handler_class_for("mikrotik") is MikrotikHandler


@pytest.mark.parametrize("device_type", ["unknown", "evolution_digital", "not-a-vendor", ""])
def test_handler_class_for_unmapped_types_return_none(device_type):
    assert HandlerManager.handler_class_for(device_type) is None
