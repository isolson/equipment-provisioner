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
