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


class _CurlResult:
    returncode = 0

    def __init__(self, stdout=b'{"success":1}\n200'):
        self.stdout = stdout

    async def communicate(self):
        return self.stdout, b""


def test_curl_http_response_split_keeps_body_separate_from_status():
    h = _handler()

    body, status = h._split_curl_http_response(b'{"status":7}\n200')

    assert body == b'{"status":7}'
    assert status == 200


async def test_upload_status_fails_immediately_on_http_error(monkeypatch):
    h = _handler()
    h.interface = "eth0.1996"

    async def fake_exec(*args, **kwargs):
        return _CurlResult(b"Not found\n404")

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

    assert await h._poll_upload_status_curl("test-session", timeout=300) is False


async def test_upload_status_fails_immediately_on_non_json_body(monkeypatch):
    h = _handler()
    h.interface = "eth0.1996"

    async def fake_exec(*args, **kwargs):
        return _CurlResult(b"<html>login</html>\n200")

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

    assert await h._poll_upload_status_curl("test-session", timeout=300) is False


async def test_firmware_upload_fails_when_ready_status_is_not_confirmed(
    monkeypatch, tmp_path
):
    """A status timeout must stop the run before Cambium is rebooted.

    The old fail-open path returned success after an unconfirmed five-minute
    poll, which caused the bench to reboot unchanged firmware and fail later.
    """
    h = _handler()
    h.interface = "eth0.1996"
    firmware = tmp_path / "ePMP-AX-v5.11.1.img"
    firmware.write_bytes(b"firmware")

    async def fake_exec(*args, **kwargs):
        return _CurlResult()

    async def not_ready(*args, **kwargs):
        return False

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr(h, "_poll_upload_status_curl", not_ready)

    assert await h._upload_firmware_curl(str(firmware)) is False


async def test_alt_bank_upload_fails_when_upgrade_status_is_not_confirmed(
    monkeypatch, tmp_path
):
    """The confirmed alternate-bank endpoint sequence is also fail closed."""
    h = _handler()
    h.interface = "eth0.1996"
    firmware = tmp_path / "ePMP-AX-v5.11.1.img"
    firmware.write_bytes(b"firmware")

    async def fake_exec(*args, **kwargs):
        return _CurlResult()

    async def not_ready(*args, **kwargs):
        return False

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr(h, "_poll_upgrade_status_curl", not_ready)

    assert await h._upload_firmware_curl_alt_bank(str(firmware)) is False
