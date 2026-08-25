"""Regression tests for Cambium config verification honesty."""

from provisioner.handlers.base import UNVERIFIED, DeviceInfo
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
    """A readable config with no expected values remains explicitly unverified."""
    h = _handler()
    h._last_applied_config = {}  # nothing to derive expectations from

    async def readback():
        return {"snmpSystemName": "whatever"}

    monkeypatch.setattr(h, "_get_config_curl", readback)
    result = await h.verify_config()
    assert result == UNVERIFIED


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


async def test_verify_config_confirms_native_import_properties(monkeypatch, fast_sleep):
    """Native SM imports must verify their operational properties, too."""
    h = _handler()
    h._last_applied_config = {
        "networkMode": "2",
        "mgmtVLANVID": "12",
        "cambiumSSHServerEnable": "1",
        # Never use secret-shaped fields as verification expectations.
        "wirelessInterfaceEncryptionKey": "not-an-expectation",
    }

    async def readback():
        return {
            "networkMode": 2,
            "mgmtVLANVID": 12,
            "cambiumSSHServerEnable": True,
            "wirelessInterfaceEncryptionKey": "different-value",
        }

    monkeypatch.setattr(h, "_get_config_curl", readback)
    assert await h.verify_config() is True


async def test_verify_config_is_unverified_when_native_readback_is_incomplete(monkeypatch, fast_sleep):
    h = _handler()
    h._last_applied_config = {
        "networkMode": "2",
        "mgmtVLANVID": "12",
    }

    async def readback():
        return {"networkMode": "2"}

    monkeypatch.setattr(h, "_get_config_curl", readback)
    assert await h.verify_config() == UNVERIFIED


class _CurlResult:
    returncode = 0

    def __init__(self, stdout=b'{"success":1}\n200'):
        self.stdout = stdout
        self.stdin = None

    async def communicate(self, stdin=None):
        self.stdin = stdin
        return self.stdout, b""


def test_curl_http_response_split_keeps_body_separate_from_status():
    h = _handler()

    body, status = h._split_curl_http_response(b'{"status":7}\n200')

    assert body == b'{"status":7}'
    assert status == 200


def test_curl_application_result_rejects_success_zero():
    h = _handler()

    result = h._curl_application_success(
        "test",
        b'{"success":0,"msg":"rejected"}',
    )

    assert result is False


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


async def test_ax_bank_one_uses_explicit_upgrade_sequence(monkeypatch, tmp_path):
    h = _handler()
    h.interface = "eth0.1996"
    h._device_info = DeviceInfo(device_type="cambium", model="ePMP AX (SKU 53560)")
    firmware = tmp_path / "ePMP-AX-v5.11.1.img"
    firmware.write_bytes(b"firmware")
    calls = []

    async def explicit(path):
        calls.append(path)
        return True

    async def legacy(path):
        raise AssertionError("AX must not use local_upload_image")

    monkeypatch.setattr(h, "_upload_firmware_curl_alt_bank", explicit)
    monkeypatch.setattr(h, "_upload_firmware_curl", legacy)

    assert await h.upload_firmware(str(firmware), bank=1) is True
    assert calls == [str(firmware)]


async def test_force_bank_one_keeps_legacy_first_pass(monkeypatch, tmp_path):
    h = _handler()
    h.interface = "eth0.1996"
    h._device_info = DeviceInfo(device_type="cambium", model="Force 300-25")
    firmware = tmp_path / "ePMP-v5.11.1.img"
    firmware.write_bytes(b"firmware")
    calls = []

    async def legacy(path):
        calls.append(path)
        return True

    async def explicit(path):
        raise AssertionError("Force bank one must keep the confirmed legacy path")

    monkeypatch.setattr(h, "_upload_firmware_curl", legacy)
    monkeypatch.setattr(h, "_upload_firmware_curl_alt_bank", explicit)

    assert await h.upload_firmware(str(firmware), bank=1) is True
    assert calls == [str(firmware)]


async def test_ax_explicit_upgrade_matches_har_request(monkeypatch, tmp_path):
    h = _handler()
    h.interface = "eth0.1996"
    firmware = tmp_path / "ePMP-AX-v5.11.1.img"
    firmware.write_bytes(b"firmware")
    process_args = []
    poll_args = []

    async def fake_exec(*args, **kwargs):
        process_args.append(args)
        return _CurlResult()

    async def ready(*args, **kwargs):
        poll_args.append((args, kwargs))
        return True

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr(h, "_poll_upgrade_status_curl", ready)

    assert await h._upload_firmware_curl_alt_bank(str(firmware)) is True
    assert any("type=device&debug=true" in args for args in process_args)
    assert any("X-Requested-With: XMLHttpRequest" in args for args in process_args)
    assert all(";stok=" not in arg for args in process_args for arg in args)
    assert poll_args[0][1]["debug_value"] == "true"


async def test_curl_stdin_config_keeps_url_and_form_data_out_of_argv(monkeypatch):
    h = _handler()
    process_args = []
    results = []

    async def fake_exec(*args, **kwargs):
        process_args.append(args)
        result = _CurlResult()
        results.append(result)
        return result

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

    secret_url = "https://device/cgi-bin/luci/;stok=session-secret/admin/test"
    secret_form = "password=password-secret"
    await h._run_curl_with_stdin_config(
        ["curl", "-s", "-X", "POST"],
        secret_url,
        form_data=secret_form,
    )

    argv = process_args[0]
    assert all("session-secret" not in arg for arg in argv)
    assert all("password-secret" not in arg for arg in argv)
    assert secret_url.encode() in results[0].stdin
    assert secret_form.encode() in results[0].stdin


async def test_cambium_login_keeps_credentials_out_of_curl_argv(monkeypatch):
    h = _handler()
    h.interface = "eth0.1996"
    h.credentials = {"username": "unit-user", "password": "unit-password"}
    process_args = []
    results = []

    async def fake_exec(*args, **kwargs):
        process_args.append(args)
        result = _CurlResult(b'{"stok":"session-token"}')
        results.append(result)
        return result

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

    assert await h._try_cgi_login_curl("unit-user", "unit-password") == (True, False)

    argv = process_args[0]
    assert all("unit-password" not in arg for arg in argv)
    assert b"username=unit-user" in results[0].stdin
    assert b"password=unit-password" in results[0].stdin


async def test_upgrade_poll_accepts_har_terminal_status(monkeypatch, fast_sleep):
    h = _handler()
    h.interface = "eth0.1996"
    replies = iter([
        _CurlResult(b'{"success":1,"status":0,"error":0}\n200'),
        _CurlResult(b'{"success":1,"status":7,"error":0}\n200'),
    ])

    async def fake_exec(*args, **kwargs):
        return next(replies)

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

    assert await h._poll_upgrade_status_curl(
        "session-secret",
        timeout=10,
        debug_value="true",
    ) is True


async def test_explicit_upgrade_stops_on_application_upload_failure(
    monkeypatch,
    tmp_path,
):
    h = _handler()
    h.interface = "eth0.1996"
    firmware = tmp_path / "ePMP-AX-v5.11.1.img"
    firmware.write_bytes(b"firmware")
    process_args = []

    async def fake_exec(*args, **kwargs):
        process_args.append(args)
        return _CurlResult(b'{"success":0,"msg":"rejected"}\n200')

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)

    assert await h._upload_firmware_curl_alt_bank(str(firmware)) is False
    assert len(process_args) == 1


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
