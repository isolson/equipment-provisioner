"""The business wired modes allow the latest long-term release and the bench-qualified one."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from provisioner.firmware_sources import mikrotik as source_module
from provisioner.firmware_sources.mikrotik import MikrotikFirmwareSource, latest_known_version
from provisioner.handlers import mikrotik_business
from provisioner.handlers.mikrotik import MikrotikHandler


@pytest.fixture(autouse=True)
def clean_cache(monkeypatch):
    monkeypatch.setattr(source_module, "_latest_known", {})


def known(version):
    source_module._latest_known["long-term"] = version


def test_latest_long_term_is_allowed():
    known("7.23.8")
    assert mikrotik_business.firmware_refusal("7.23.8") is None
    assert mikrotik_business.evidence_firmware("7.23.8") == "7.23.5"


def test_qualified_release_is_still_allowed():
    known("7.23.8")
    assert mikrotik_business.firmware_refusal("7.23.5") is None
    assert mikrotik_business.evidence_firmware("7.23.5") == "7.23.5"


@pytest.mark.parametrize("firmware", ["7.23.7", "7.24.1", "", None])
def test_other_release_is_refused(firmware):
    known("7.23.8")
    reason = mikrotik_business.firmware_refusal(firmware)
    assert "latest long-term 7.23.8" in reason and "7.23.5" in reason
    assert mikrotik_business.evidence_firmware(firmware) is None


def test_unknown_latest_falls_back_to_qualified_list():
    assert latest_known_version("long-term") is None
    assert mikrotik_business.firmware_refusal("7.23.5") is None
    reason = mikrotik_business.firmware_refusal("7.23.8")
    assert "unknown" in reason and "only bench-qualified 7.23.5" in reason


def test_version_suffix_is_parsed():
    known("7.23.8")
    assert mikrotik_business.firmware_refusal("7.23.8 (long-term)") is None
    assert mikrotik_business.firmware_refusal("7.23.5 (long-term)") is None
    assert mikrotik_business.evidence_firmware("7.23.8 (long-term)") == "7.23.5"


def business_state(firmware):
    return {"profile": "business-v1", "model": "hEX S", "architecture": "arm",
            "firmware": firmware, "checks": {"physical_ports": True}}


def test_layout_validation_follows_the_gate():
    known("7.23.8")
    MikrotikHandler._validate_network_mode_layout(business_state("7.23.8"))
    MikrotikHandler._validate_network_mode_layout(business_state("7.23.5"))
    with pytest.raises(ValueError, match="7.24.1"):
        MikrotikHandler._validate_network_mode_layout(business_state("7.24.1"))
    state = business_state("7.23.8")
    state["architecture"] = "mmips"
    with pytest.raises(ValueError, match="hardware"):
        MikrotikHandler._validate_network_mode_layout(state)


def test_handler_exposes_the_gate_to_the_web_flow():
    known("7.23.8")
    assert MikrotikHandler.network_mode_firmware_refusal("7.23.8") is None
    assert MikrotikHandler.network_mode_evidence_firmware("7.23.8") == "7.23.5"
    assert "not allowed" in MikrotikHandler.network_mode_firmware_refusal("7.24.1")


def test_web_flow_shows_the_refusal_and_uses_the_bench_record(monkeypatch):
    from test_network_mode_api import setup_client
    from provisioner.web import network_modes
    client, handler, _ = setup_client(monkeypatch)
    handler.network_mode_firmware_refusal = MikrotikHandler.network_mode_firmware_refusal
    handler.network_mode_evidence_firmware = MikrotikHandler.network_mode_evidence_firmware
    looked_up = []
    monkeypatch.setattr(network_modes, "qualified_modes",
                        lambda kind, model, firmware, *a: looked_up.append(firmware) or ("router", "switch"))

    known("7.23.8")
    handler.network_mode_state.return_value = {"model": "hEX S", "firmware": "7.23.8 (long-term)", "mode": "router"}
    response = client.get("/api/network-modes/1")
    assert response.status_code == 200
    assert response.json()["firmware"] == "7.23.8"
    assert looked_up == ["7.23.5"]

    source_module._latest_known.clear()
    response = client.get("/api/network-modes/1")
    assert response.status_code == 409
    assert "only bench-qualified 7.23.5" in response.json()["detail"]


@pytest.mark.asyncio
async def test_apply_refuses_before_any_write(monkeypatch):
    known("7.23.8")
    handler = MikrotikHandler("192.0.2.1", {}, interface="test0")
    monkeypatch.setattr(mikrotik_business, "ensure_source", AsyncMock())
    handler.get_info = AsyncMock(return_value=SimpleNamespace(
        serial_number="TEST-UNIT", model="hEX S", hardware_version="arm", firmware_version="7.24.1"))
    handler._ssh = None
    handler._run_command = AsyncMock()
    with pytest.raises(ValueError, match="not allowed"):
        await mikrotik_business.apply(handler, "router")
    handler._run_command.assert_not_awaited()


@pytest.mark.asyncio
async def test_source_records_long_term_on_another_channel(monkeypatch):
    source = MikrotikFirmwareSource({"channel": "stable", "models": ["arm"]})

    async def fake_fetch(_session, channel):
        return ("7.24.1" if channel == "stable" else "7.23.8 (long-term)"), None

    monkeypatch.setattr(source, "_fetch_latest_version", fake_fetch)
    monkeypatch.setattr(source, "_firmware_url_exists", AsyncMock(return_value=True))
    await source.check_for_updates()
    assert latest_known_version("long-term") == "7.23.8"
    assert latest_known_version("stable") == "7.24.1"


@pytest.mark.asyncio
async def test_failed_lookup_keeps_unknown(monkeypatch):
    source = MikrotikFirmwareSource({"models": ["arm"]})

    async def fake_fetch(_session, _channel):
        return None, None

    monkeypatch.setattr(source, "_fetch_latest_version", fake_fetch)
    assert await source.check_for_updates() == []
    assert latest_known_version("long-term") is None
