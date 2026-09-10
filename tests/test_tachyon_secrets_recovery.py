"""303L recovery, profile secrets, and fail-closed readback regressions."""
from copy import deepcopy
from unittest.mock import AsyncMock

import pytest
from provisioner.handlers.tachyon import TachyonHandler


@pytest.mark.asyncio
@pytest.mark.parametrize('transient', [False, True])
async def test_secret_apply_recovers_and_verifies_all_profiles(monkeypatch, transient):
    handler = TachyonHandler(ip='192.0.2.1', credentials={})
    basis = {'system': {'hostname': 'baseline'}}
    handler._last_applied_config = basis
    live = {'services': {}, 'wireless': {'radios': {'wlan0': {'vaps': [
        {'sta_profiles': {'profiles': [{'ssid': 'test-a'}, {'ssid': 'test-b'}]}}
    ]}}}}
    attempts = []

    async def request(*args, **kwargs):
        attempts.append(True)
        if transient and len(attempts) == 1:
            raise OSError('temporary reload')
        return deepcopy(live)

    async def apply(config):
        live.clear()
        live.update(deepcopy(config))
        handler._last_applied_config = config
        return True

    monkeypatch.setattr(handler, '_api_request', request)
    monkeypatch.setattr(handler, 'apply_config', apply)
    monkeypatch.setattr('provisioner.handlers.tachyon.asyncio.sleep', AsyncMock())
    assert await handler._apply_network_secrets({'snmp_community': 'test-community', 'wpa_key': 'test-passphrase'}) is True
    assert handler._last_applied_config is basis
    profiles = live['wireless']['radios']['wlan0']['vaps'][0]['sta_profiles']['profiles']
    assert len(profiles) == 2
    assert all(p['security']['wpapsk']['passphrase'] == 'test-passphrase' for p in profiles)


@pytest.mark.asyncio
async def test_secret_apply_fails_closed_when_config_never_returns(monkeypatch):
    handler = TachyonHandler(ip='192.0.2.1', credentials={})
    monkeypatch.setattr(handler, '_api_request', AsyncMock(side_effect=OSError('unavailable')))
    monkeypatch.setattr(handler, 'refresh_connection', AsyncMock(return_value=False))
    monkeypatch.setattr('provisioner.handlers.tachyon.asyncio.sleep', AsyncMock())
    apply = AsyncMock()
    monkeypatch.setattr(handler, 'apply_config', apply)
    assert await handler._apply_network_secrets({'snmp_community': 'test-community'}) is False
    apply.assert_not_awaited()


@pytest.mark.asyncio
async def test_secret_apply_does_not_hide_write_failure(monkeypatch):
    handler = TachyonHandler(ip='192.0.2.1', credentials={})
    basis = {'system': {'hostname': 'baseline'}}
    handler._last_applied_config = basis
    monkeypatch.setattr(handler, '_api_request', AsyncMock(return_value={'services': {}}))
    monkeypatch.setattr(handler, 'apply_config', AsyncMock(return_value=False))
    assert await handler._apply_network_secrets({'snmp_community': 'test-community'}) is False
    assert handler._last_applied_config is basis


@pytest.mark.asyncio
async def test_successful_post_with_unchanged_secret_is_failure(monkeypatch):
    handler = TachyonHandler(ip='192.0.2.1', credentials={})
    monkeypatch.setattr(handler, '_api_request', AsyncMock(return_value={'services': {}}))
    monkeypatch.setattr(handler, 'apply_config', AsyncMock(return_value=True))
    assert await handler._apply_network_secrets({'snmp_community': 'test-community'}) is False


@pytest.mark.asyncio
async def test_missing_station_profiles_refuses_secret_apply(monkeypatch):
    handler = TachyonHandler(ip='192.0.2.1', credentials={})
    monkeypatch.setattr(handler, '_api_request', AsyncMock(return_value={'services': {}}))
    apply = AsyncMock()
    monkeypatch.setattr(handler, 'apply_config', apply)
    assert await handler._apply_network_secrets({'wpa_key': 'test-passphrase'}) is False
    apply.assert_not_awaited()


@pytest.mark.asyncio
async def test_sm_baseline_merges_and_keeps_device_accounts(monkeypatch):
    from pathlib import Path
    from provisioner.config_templates import load_config_template
    path = Path(__file__).resolve().parents[1] / "configs/templates/tachyon/TNA-303L-65/SM/default.tar"
    baseline = load_config_template(str(path)).config
    handler = TachyonHandler(ip="192.0.2.1", credentials={})
    assert not handler.is_full_config_export(baseline)
    live = {"version": 3, "system": {"users": [{"name": "test-account"}]},
            "wireless": {"radios": {"wlan0": {"vaps": [{"sta_profiles": {"profiles": []}}]}}}}
    monkeypatch.setattr(handler, "_api_request", AsyncMock(return_value=live))
    apply = AsyncMock(return_value=True)
    monkeypatch.setattr(handler, "apply_config", apply)
    assert await handler.apply_config_file(str(path)) is True
    sent = apply.call_args.args[0]
    assert sent["system"]["users"] == live["system"]["users"]
    assert sent["version"] == 3
    assert len(sent["wireless"]["radios"]["wlan0"]["vaps"][0]["sta_profiles"]["profiles"]) == 4


@pytest.mark.asyncio
async def test_first_config_post_includes_host_key_for_new_profiles(monkeypatch):
    handler = TachyonHandler(ip="192.0.2.1", credentials={"wpa_key": "test-passphrase", "snmp_community": "test-community"}, interface="test0")
    config = {"system": {"hostname": "baseline"}, "wireless": {"radios": {"wlan0": {"vaps": [
        {"sta_profiles": {"profiles": [{"ssid": "test-a"}, {"ssid": "test-b"}]}}
    ]}}}}
    async def post(sent):
        assert sent["services"]["snmp"]["v2"]["ro"]["community"] == "test-community"
        profiles = sent["wireless"]["radios"]["wlan0"]["vaps"][0]["sta_profiles"]["profiles"]
        assert all(p["security"]["wpapsk"]["passphrase"] == "test-passphrase" for p in profiles)
        return True
    monkeypatch.setattr(handler, "_apply_config_curl", post)
    monkeypatch.setattr(handler, "_read_config_after_apply", AsyncMock(side_effect=lambda: deepcopy(config)))
    assert await handler.apply_config(config) is True


@pytest.mark.asyncio
async def test_secrets_already_present_do_not_trigger_second_config_post(monkeypatch):
    handler = TachyonHandler(ip="192.0.2.1", credentials={})
    live = {"services": {"snmp": {"v2": {"ro": {"community": "test-community"}}}},
            "wireless": {"radios": {"wlan0": {"vaps": [{"sta_profiles": {"profiles": [
                {"ssid": "test-a", "security": {"mode": "wpapsk", "wpapsk": {"passphrase": "test-passphrase"}}}
            ]}}]}}}}
    monkeypatch.setattr(handler, "_api_request", AsyncMock(return_value=deepcopy(live)))
    post = AsyncMock(side_effect=OSError("web service reloading"))
    monkeypatch.setattr(handler, "apply_config", post)
    assert await handler._apply_network_secrets({"snmp_community": "test-community", "wpa_key": "test-passphrase"}) is True
    post.assert_not_awaited()


@pytest.mark.asyncio
async def test_final_config_verification_recovers_from_reload(monkeypatch):
    handler = TachyonHandler(ip="192.0.2.1", credentials={})
    expected = {"system": {"hostname": "baseline"}}
    handler._last_applied_config = expected
    monkeypatch.setattr(handler, "refresh_connection", AsyncMock(return_value=True))
    monkeypatch.setattr(handler, "get_firmware_banks", AsyncMock(return_value={"bank1": "1.15.1", "bank2": "1.15.1", "active": 1}))
    monkeypatch.setattr(handler, "_api_request", AsyncMock(side_effect=[OSError("temporary reload"), expected]))
    monkeypatch.setattr("provisioner.handlers.tachyon.asyncio.sleep", AsyncMock())
    assert await handler.verify_config() is True


@pytest.mark.asyncio
async def test_partial_template_never_posts_without_live_config(monkeypatch):
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "configs/templates/tachyon/TNA-303L-65/SM/default.tar"
    handler = TachyonHandler(ip="192.0.2.1", credentials={})
    monkeypatch.setattr(handler, "_api_request", AsyncMock(side_effect=OSError("unavailable")))
    monkeypatch.setattr(handler, "refresh_connection", AsyncMock(return_value=False))
    monkeypatch.setattr("provisioner.handlers.tachyon.asyncio.sleep", AsyncMock())
    apply = AsyncMock()
    monkeypatch.setattr(handler, "apply_config", apply)
    assert await handler.apply_config_file(str(path)) is False
    apply.assert_not_awaited()
