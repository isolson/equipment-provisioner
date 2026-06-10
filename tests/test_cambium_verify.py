"""Regression tests for Cambium config verification honesty.

Cambium already has the correct fail-closed *shape* (verify_config returns
False after exhausting retries) — these lock that in — but ``_check_config_values``
returns ``True`` when there is nothing to compare, so a verify with no expected
values reports success without confirming anything.
"""

from provisioner.handlers.cambium import CambiumHandler


def _handler() -> CambiumHandler:
    h = CambiumHandler(
        ip="192.168.0.1",
        credentials={"username": "admin", "password": "admin"},
    )
    h._stok = "stok"
    h._cookie_file = "/tmp/does-not-matter"
    return h


async def test_verify_config_not_success_with_nothing_to_compare(monkeypatch, fast_sleep):
    """RED today: read-back succeeds but there are no expected values to check.

    ``verify_config`` must not report a plain success — it has confirmed
    nothing. Expected post-fix: an 'unverified' signal, not True.
    """
    h = _handler()
    h._last_applied_config = {}  # nothing to derive expectations from

    async def readback():
        return {"snmpSystemName": "whatever"}

    monkeypatch.setattr(h, "_get_config_curl", readback)
    result = await h.verify_config()
    assert result is not True


async def test_verify_config_false_when_readback_empty(monkeypatch, fast_sleep):
    """Lock-in: an unreadable config must fail closed (already correct)."""
    h = _handler()
    h._last_applied_config = {"snmpSystemName": "AP-1"}

    async def empty_readback():
        return {}

    async def fail_connect():
        return False

    async def noop_disconnect():
        return None

    monkeypatch.setattr(h, "_get_config_curl", empty_readback)
    monkeypatch.setattr(h, "connect", fail_connect)
    monkeypatch.setattr(h, "disconnect", noop_disconnect)
    assert await h.verify_config() is False


async def test_verify_config_true_on_match(monkeypatch, fast_sleep):
    """Lock-in: read-back hostname matches the applied config -> True."""
    h = _handler()
    h._last_applied_config = {"snmpSystemName": "AP-1"}

    async def readback():
        return {"snmpSystemName": "AP-1"}

    monkeypatch.setattr(h, "_get_config_curl", readback)
    assert await h.verify_config() is True
