"""Regression tests for Ubiquiti (Wave) config apply honesty.

Two confirmed false-positives:
  - ``_apply_config_curl`` (interface-bound path) PUTs the config and returns
    ``True`` with NO read-back at all.
  - the aiohttp path captures expected hostname/SSID but, if the read-back GET
    returns non-200, silently falls through to ``return True``.

Both must fail closed: a config that can't be confirmed is not "applied".
"""

import json

from provisioner.handlers.ubiquiti import UbiquitiHandler
from stubs import StubResponse


def _wave_handler(interface=None) -> UbiquitiHandler:
    h = UbiquitiHandler(
        ip="192.168.1.20",
        credentials={"username": "ubnt", "password": "ubnt"},
        interface=interface,
    )
    h._api_style = "wave"
    h._base_url = "https://192.168.1.20"
    h._auth_token = "tok"
    return h


async def test_curl_apply_config_reads_back_and_fails_on_mismatch(fake_curl, fast_sleep):
    """RED today: the interface-bound curl path applies config with no
    read-back and returns True even when the device didn't take the config."""
    h = _wave_handler(interface="eth0")
    config = {"system": {"hostname": "AP-1"}}

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method == "PUT":
            return (0, json.dumps({"error": 0}))
        # read-back GET (added by the fix) reports a different hostname
        return (0, json.dumps({"system": {"hostname": "WRONG"}}))

    fake_curl.set_handler(route)
    assert await h.apply_config(config) is False


async def test_aiohttp_apply_config_fails_when_readback_non_200(
    monkeypatch, stub_aiohttp, fast_sleep
):
    """RED today: a non-200 read-back must fail the apply, not fall through to
    True."""
    h = _wave_handler()  # no interface -> aiohttp path
    config = {"system": {"hostname": "AP-1"}}

    def router(method, url, kwargs):
        if method == "PUT":
            return StubResponse(200, json.dumps({"error": 0}))
        if method == "GET":
            return StubResponse(500, json.dumps({}))
        return None

    session = stub_aiohttp(router=router)

    async def _get_session():
        return session

    monkeypatch.setattr(h, "_get_session", _get_session)
    assert await h.apply_config(config) is False


async def test_aiohttp_apply_config_true_on_match(monkeypatch, stub_aiohttp, fast_sleep):
    """Happy path lock-in: read-back confirms the hostname -> True."""
    h = _wave_handler()
    config = {"system": {"hostname": "AP-1"}}

    def router(method, url, kwargs):
        if method == "PUT":
            return StubResponse(200, json.dumps({"error": 0}))
        if method == "GET":
            return StubResponse(200, json.dumps({"system": {"hostname": "AP-1"}}))
        return None

    session = stub_aiohttp(router=router)

    async def _get_session():
        return session

    monkeypatch.setattr(h, "_get_session", _get_session)
    assert await h.apply_config(config) is True
