"""Regression tests for Tachyon config apply / verify honesty.

These pin the exact false-positive that shipped: ``apply_config`` read back the
config over curl, and on ANY read-back failure logged a warning and returned
``True`` anyway — reporting "config applied" when it was never confirmed.
``verify_config`` likewise returned ``True`` after only a reconnect + firmware
bank check, never comparing the config that was sent.

Tests marked "RED today" fail against the pre-fix handler and pass once
verification is made fail-closed (Wave 2).
"""

import json

from provisioner.handlers.tachyon import TachyonHandler


def _curl_handler() -> TachyonHandler:
    """A handler wired for the interface-bound curl transport (no network)."""
    h = TachyonHandler(
        ip="169.254.1.1",
        credentials={"username": "root", "password": "admin"},
        interface="eth0",
    )
    h._use_curl = True
    h._api_token = "tok"
    h._connected = True
    return h


# ---------------------------------------------------------------------------
# apply_config read-back
# ---------------------------------------------------------------------------


async def test_apply_config_false_when_readback_curl_fails(fake_curl, fast_sleep):
    """RED today: a failed read-back GET must fail the apply, not be swallowed.

    The POST succeeds but the read-back GET fails at the curl layer (the exact
    shape of the tachyon incident). The pre-fix code caught the resulting
    RuntimeError and returned True.
    """
    h = _curl_handler()
    config = {"system": {"hostname": "AP-1"}}

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method == "POST":
            return (0, json.dumps({"reboot_required": False}))
        return (1, "", "curl: (7) Failed to connect")  # read-back GET fails

    fake_curl.set_handler(route)
    assert await h.apply_config(config) is False


async def test_apply_config_false_on_hostname_mismatch(fake_curl, fast_sleep):
    """The device echoes a different hostname than we sent -> not applied."""
    h = _curl_handler()
    config = {"system": {"hostname": "AP-1"}}

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method == "POST":
            return (0, json.dumps({}))
        return (0, json.dumps({"system": {"hostname": "WRONG"}}))

    fake_curl.set_handler(route)
    assert await h.apply_config(config) is False


async def test_apply_config_true_on_full_match(fake_curl, fast_sleep):
    """Happy path lock-in: read-back confirms hostname AND ssid -> True."""
    h = _curl_handler()
    config = {
        "system": {"hostname": "AP-1"},
        "wireless": {"radios": {"wlan0": {"vaps": [{"ssid": "NET"}]}}},
    }

    def route(argv):
        method = argv[argv.index("-X") + 1]
        if method == "POST":
            return (0, json.dumps({}))
        return (0, json.dumps(config))  # device echoes exactly what we sent

    fake_curl.set_handler(route)
    assert await h.apply_config(config) is True


# ---------------------------------------------------------------------------
# verify_config
# ---------------------------------------------------------------------------


def _stub_reconnect(monkeypatch, h):
    """Make verify_config's reconnect + bank check succeed without a network."""

    async def ok_connect():
        h._connected = True
        return True

    async def noop_disconnect():
        h._connected = False

    async def banks():
        return {"bank1": "v1", "bank2": "v1", "active": 1}

    monkeypatch.setattr(h, "connect", ok_connect)
    monkeypatch.setattr(h, "disconnect", noop_disconnect)
    monkeypatch.setattr(h, "get_firmware_banks", banks)


async def test_verify_config_false_when_readback_hostname_mismatches(monkeypatch, fast_sleep):
    """RED today: verify_config must compare the config, not just reconnect."""
    h = _curl_handler()
    h._last_applied_config = {"system": {"hostname": "AP-1"}}
    _stub_reconnect(monkeypatch, h)

    async def readback():
        return {"system": {"hostname": "WRONG"}}

    monkeypatch.setattr(h, "_get_config_curl", readback, raising=False)
    assert await h.verify_config() is False


async def test_verify_config_false_when_readback_unavailable(monkeypatch, fast_sleep):
    """RED today: if the config can't be read back, verify cannot claim success."""
    h = _curl_handler()
    h._last_applied_config = {"system": {"hostname": "AP-1"}}
    _stub_reconnect(monkeypatch, h)

    async def readback():
        return {}

    monkeypatch.setattr(h, "_get_config_curl", readback, raising=False)
    assert await h.verify_config() is False


async def test_verify_config_true_on_match(monkeypatch, fast_sleep):
    """Happy path lock-in: read-back hostname matches what was applied."""
    h = _curl_handler()
    h._last_applied_config = {"system": {"hostname": "AP-1"}}
    _stub_reconnect(monkeypatch, h)

    async def readback():
        return {"system": {"hostname": "AP-1"}}

    monkeypatch.setattr(h, "_get_config_curl", readback, raising=False)
    assert await h.verify_config() is True
