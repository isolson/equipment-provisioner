"""Tests for MikroTik firmware source behavior."""

import pytest

from provisioner.firmware_sources.mikrotik import MikrotikFirmwareSource


@pytest.mark.asyncio
async def test_mikrotik_source_defaults_to_long_term_channel(monkeypatch):
    source = MikrotikFirmwareSource({"models": ["arm", "mipsbe"]})

    async def fake_fetch(_session, _channel):
        return "7.20.8", "2026-02-07"

    async def fake_exists(_session, url):
        return "routeros-arm-7.20.8.npk" in url

    monkeypatch.setattr(source, "_fetch_latest_version", fake_fetch)
    monkeypatch.setattr(source, "_firmware_url_exists", fake_exists)

    updates = await source.check_for_updates()

    assert len(updates) == 1
    assert updates[0].model == "arm"
    assert updates[0].version == "7.20.8"
    assert updates[0].channel == "long-term"


@pytest.mark.asyncio
async def test_mikrotik_source_accepts_lts_alias(monkeypatch):
    source = MikrotikFirmwareSource({"channel": "lts", "models": ["arm64"]})

    async def fake_fetch(_session, channel):
        assert channel == "long-term"
        return "7.20.8", "2026-02-07"

    async def fake_exists(_session, _url):
        return True

    monkeypatch.setattr(source, "_fetch_latest_version", fake_fetch)
    monkeypatch.setattr(source, "_firmware_url_exists", fake_exists)

    updates = await source.check_for_updates()

    assert len(updates) == 1
    assert updates[0].model == "arm64"
    assert updates[0].channel == "long-term"


@pytest.mark.asyncio
async def test_mikrotik_source_maps_release_alias_to_stable(monkeypatch):
    source = MikrotikFirmwareSource({"channel": "release", "models": ["all"]})

    async def fake_fetch(_session, channel):
        assert channel == "stable"
        return "7.21.2", "2026-02-07"

    async def fake_exists(_session, url):
        return "routeros-arm64-7.21.2.npk" in url

    monkeypatch.setattr(source, "_fetch_latest_version", fake_fetch)
    monkeypatch.setattr(source, "_firmware_url_exists", fake_exists)

    updates = await source.check_for_updates()

    assert len(updates) == 1
    assert updates[0].model == "arm64"
    assert updates[0].channel == "stable"

