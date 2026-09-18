"""Tests for the business-router Netinstall dispatch + class selection.

The business flow is a second Netinstall flavor alongside the WiFi-gateway/ZTP
pipeline. These tests pin the parts that must not regress the gateway path:
  1. Port-level class selection (set / consume-once / cleared on disconnect)
  2. Class normalization + validation
  3. `_run_netinstall` dispatch (default → gateway; business → business; the
     port pre-selection is consumed once)
  4. `apply_network_mode(from_clean_flash=True)` skips the from-factory
     precondition but keeps the handler's import path
  5. The #167 credential seam is deferred (returns None), not a local substitute
"""

import types
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from provisioner.port_manager import PortManager
from provisioner.web import api


def _pm(num_ports=1):
    pm = PortManager(num_ports=num_ports)
    pm._generate_port_configs()
    return pm


# ---------------------------------------------------------------------------
# 1. Port-level class selection
# ---------------------------------------------------------------------------


def test_set_and_take_netinstall_class_is_consume_once():
    pm = _pm(2)
    pm.set_netinstall_class(1, "business_router")
    assert pm.port_states[1].netinstall_class == "business_router"

    # take_* returns the value and resets so it cannot re-route the next device.
    assert pm.take_netinstall_class(1) == "business_router"
    assert pm.port_states[1].netinstall_class is None
    assert pm.take_netinstall_class(1) is None


def test_armed_class_survives_disconnect_powercycle():
    # Entering BOOTP requires a power-cycle (disconnect). An armed selection
    # must survive it so the ensuing BOOTP routes to the business flow; only
    # the consume-once on the actual netinstall fire resets it.
    pm = _pm(1)
    pm.set_netinstall_class(1, "business_switch")
    pm._clear_port_state_on_disconnect(1)
    assert pm.port_states[1].netinstall_class == "business_switch"


def test_take_netinstall_class_unknown_port_is_none():
    pm = _pm(1)
    assert pm.take_netinstall_class(99) is None


# ---------------------------------------------------------------------------
# 2. Class normalization + validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", [None, "", "gateway"])
def test_resolve_gateway_variants_are_none(raw):
    assert api._resolve_netinstall_class(raw) is None


@pytest.mark.parametrize("raw", ["business_router", "business_switch"])
def test_resolve_business_classes_pass_through(raw):
    assert api._resolve_netinstall_class(raw) == raw


@pytest.mark.parametrize("raw", [None, "gateway"])
def test_validated_gateway_normalizes_to_none(raw):
    assert api._validated_netinstall_class(raw) is None


def test_validated_business_class_ok():
    assert api._validated_netinstall_class("business_router") == "business_router"


def test_validated_rejects_unknown_class():
    with pytest.raises(HTTPException) as exc:
        api._validated_netinstall_class("infra_router")
    assert exc.value.status_code == 400


def test_business_modes_map_onto_handler_mode_names():
    # The class map must not invent mode names — every mapped mode must be a
    # real business network mode owned by the handler module.
    from provisioner.handlers import mikrotik_business

    for mode in api._BUSINESS_NETINSTALL_MODES.values():
        assert mode in mikrotik_business.MANAGEMENT_IPS


# ---------------------------------------------------------------------------
# 3. Dispatch
# ---------------------------------------------------------------------------


def _provisioner_with(pm):
    return types.SimpleNamespace(port_manager=pm)


@pytest.mark.asyncio
async def test_dispatch_defaults_to_gateway():
    pm = _pm(1)
    prov = _provisioner_with(pm)
    with patch.object(api, "_run_gateway_netinstall", new=AsyncMock()) as gw, \
         patch.object(api, "_run_business_netinstall", new=AsyncMock()) as biz:
        await api._run_netinstall(prov, 1)
    gw.assert_awaited_once_with(prov, 1)
    biz.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("cls,mode", [
    ("business_router", "router"),
    ("business_switch", "switch"),
])
async def test_dispatch_explicit_business_class(cls, mode):
    pm = _pm(1)
    prov = _provisioner_with(pm)
    with patch.object(api, "_run_gateway_netinstall", new=AsyncMock()) as gw, \
         patch.object(api, "_run_business_netinstall", new=AsyncMock()) as biz:
        await api._run_netinstall(prov, 1, cls)
    biz.assert_awaited_once_with(prov, 1, mode)
    gw.assert_not_awaited()


@pytest.mark.asyncio
async def test_dispatch_consumes_port_preselection():
    pm = _pm(1)
    pm.set_netinstall_class(1, "business_router")
    prov = _provisioner_with(pm)
    with patch.object(api, "_run_gateway_netinstall", new=AsyncMock()) as gw, \
         patch.object(api, "_run_business_netinstall", new=AsyncMock()) as biz:
        # Auto-BOOTP path: called with no explicit class.
        await api._run_netinstall(prov, 1)
    biz.assert_awaited_once_with(prov, 1, "router")
    gw.assert_not_awaited()
    # Consumed: a second run with no selection falls back to gateway.
    assert pm.port_states[1].netinstall_class is None


@pytest.mark.asyncio
async def test_explicit_gateway_clears_stale_port_preselection():
    pm = _pm(1)
    pm.set_netinstall_class(1, "business_router")
    prov = _provisioner_with(pm)
    with patch.object(api, "_run_gateway_netinstall", new=AsyncMock()) as gw, \
         patch.object(api, "_run_business_netinstall", new=AsyncMock()) as biz:
        await api._run_netinstall(prov, 1, "gateway")
    gw.assert_awaited_once_with(prov, 1)
    biz.assert_not_awaited()
    assert pm.port_states[1].netinstall_class is None


# ---------------------------------------------------------------------------
# 4. apply_network_mode(from_clean_flash=True)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_network_mode_clean_flash_skips_layout_precondition():
    from provisioner.handlers.mikrotik import MikrotikHandler

    handler = MikrotikHandler(
        ip="192.168.88.1",
        credentials={"username": "admin", "password": ""},
        interface="eth0.1991",
    )
    # network_mode_state() would require a live SSH session; it must NOT be
    # called on the clean-flash path.
    handler.network_mode_state = AsyncMock(
        side_effect=AssertionError("layout precondition must be skipped")
    )
    with patch("provisioner.handlers.mikrotik_business.apply",
               new=AsyncMock(return_value={"mode": "router", "checks": {"x": True}})) as ap:
        result = await handler.apply_network_mode("router", from_clean_flash=True)
    ap.assert_awaited_once_with(handler, "router")
    assert result["mode"] == "router"


@pytest.mark.asyncio
async def test_apply_network_mode_rejects_unknown_mode_before_flash_branch():
    from provisioner.handlers.mikrotik import MikrotikHandler

    handler = MikrotikHandler(
        ip="192.168.88.1",
        credentials={"username": "admin", "password": ""},
        interface="eth0.1991",
    )
    with pytest.raises(ValueError):
        await handler.apply_network_mode("bogus", from_clean_flash=True)


# ---------------------------------------------------------------------------
# 5. #167 credential seam
# ---------------------------------------------------------------------------


def test_credential_seam_is_deferred_not_local_substitute():
    # Until the Ops render backend exists, the seam returns None so the flow
    # reports credentials deferred rather than generating/storing a substitute.
    assert api._resolve_intended_business_credentials(
        config=object(), serial="ABC123", mode="router"
    ) is None
