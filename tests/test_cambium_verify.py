"""Regression tests for Cambium config verification honesty."""

import json
from pathlib import Path

import pytest

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


def _full_export():
    return {
        "device_props": {
            "wirelessInterfaceSSID": "captured-ssid",
            "centerFrequency": "5180",
            "wirelessInterfaceScanFrequencyListEighty": "5180,5200",
            "wirelessInterfaceScanFrequencyBandwidth": "51",
            "networkBridgeIPAddr": "192.0.2.10",
            "networkBridgeNetmask": "255.255.255.0",
            "mgmtIFEnable": "1",
            "mgmtIFVLAN": "99",
            "systemConfigDeviceName": "captured-name",
            "cambiumCNSDeviceAgentID": "captured-agent-id",
            "wirelessInterfaceTDDAntennaGain": "25",
            "mgmtVLANVID": "99",
        },
        "template_props": {"version": "5.11.1"},
    }


def test_cambium_shared_export_normalization_keeps_policy_and_removes_identity():
    normalized = CambiumHandler.normalize_field_export(_full_export(), "SM")
    props = normalized["device_props"]
    assert props["mgmtVLANVID"] == "12"
    assert props["mgmtIFEnable"] == "0"
    assert "mgmtIFVLAN" not in props
    assert props["networkBridgeIPAddressMode"] == "2"
    assert props["wirelessInterfaceScanFrequencyBandwidth"] == "51"
    assert props["wirelessInterfaceTDDAntennaGain"] == "17"
    assert props["wirelessInterfaceScanFrequencyListEighty"] == "5180,5200"
    assert "wirelessInterfaceSSID" not in props
    assert "centerFrequency" not in props
    assert "networkBridgeIPAddr" not in props
    assert "networkBridgeNetmask" not in props
    assert "systemConfigDeviceName" not in props
    assert "cambiumCNSDeviceAgentID" not in props


@pytest.mark.parametrize(
    "model,expected",
    [
        ("Force 300-25", "19"),
        ("ePMP 3000", "19"),
        ("ePMP 4600C", "51"),
        ("ePMP 4518", "51"),
        ("unknown", "51"),
    ],
)
def test_cambium_shared_export_projects_scan_mask_by_model(model, expected):
    normalized = CambiumHandler.normalize_field_export(_full_export(), "SM")
    prepared = CambiumHandler.prepare_field_export_for_model(normalized, model)
    assert prepared["device_props"]["wirelessInterfaceScanFrequencyBandwidth"] == expected


async def test_cambium_full_export_never_uses_set_param(monkeypatch):
    h = _handler()
    called = False

    async def fail_if_called(_props):
        nonlocal called
        called = True
        return True

    monkeypatch.setattr(h, "_apply_config_settings_curl", fail_if_called)
    assert await h.apply_config(_full_export()) is False
    assert called is False


async def test_cambium_full_export_uses_native_import_and_skip_illegal(tmp_path, monkeypatch):
    h = _handler()
    h.interface = "eth0.1996"
    h._device_info = DeviceInfo(device_type="cambium", model="Force 300-25")
    config_path = tmp_path / "field-export.json"
    config_path.write_text(json.dumps(_full_export()))
    commands = []
    uploaded = {}

    class FakeProcess:
        returncode = 0

        def __init__(self, output):
            self.output = output

        async def communicate(self):
            return self.output, b""

    async def fake_exec(*args, **kwargs):
        commands.append(args)
        if "config_import" in args[-1]:
            image_arg = next(argument for argument in args if argument.startswith("image=@"))
            image_path = image_arg.split("@", 1)[1].split(";", 1)[0]
            uploaded.update(json.loads(Path(image_path).read_text()))
            return FakeProcess(b'{"success":1}')
        return FakeProcess(b'{"template_props":{"applyFinished":1}}')

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    assert await h.apply_config_file(str(config_path)) is True
    import_command = next(command for command in commands if "config_import" in command[-1])
    assert "-F" in import_command
    assert "skipIllegal=1" in import_command
    assert "set_param" not in " ".join(import_command)
    assert uploaded["device_props"]["wirelessInterfaceScanFrequencyBandwidth"] == "19"


async def test_cambium_connectorized_gain_defaults_and_overrides(monkeypatch):
    h = _handler()
    seen = []

    async def fake_set(props):
        seen.append(props)
        return True

    monkeypatch.setattr(h, "_apply_config_settings_curl", fake_set)
    assert await h.apply_antenna_gain(model="ePMP 4600C") is True
    assert await h.apply_antenna_gain(18, model="ePMP 4600C") is True
    assert seen == [
        {"wirelessInterfaceTDDAntennaGain": "23"},
        {"wirelessInterfaceTDDAntennaGain": "18"},
    ]


async def test_cambium_integrated_gain_is_not_injected(monkeypatch):
    h = _handler()
    called = False

    async def fail_if_called(_props):
        nonlocal called
        called = True
        return True

    monkeypatch.setattr(h, "_apply_config_settings_curl", fail_if_called)
    assert await h.apply_antenna_gain(23, model="Force 300-25") is True
    assert called is False


async def test_mode_config_uses_native_import_and_verifies(monkeypatch):
    h = _handler()
    h.interface = "eth0.1996"
    seen = {}

    async def fake_apply_config_file(path):
        path_obj = Path(path)
        seen["path"] = path_obj
        seen["exists_during_import"] = path_obj.is_file()
        seen["payload"] = json.loads(path_obj.read_text())
        h._last_applied_config = seen["payload"]["device_props"]
        return True

    async def fake_verify_config(expected_values=None):
        seen["expected_values"] = expected_values
        return True

    async def fake_wait_for_reboot(timeout):
        seen["wait_timeout"] = timeout
        return True

    monkeypatch.setattr(h, "apply_config_file", fake_apply_config_file)
    monkeypatch.setattr(h, "verify_config", fake_verify_config)
    monkeypatch.setattr(h, "wait_for_reboot", fake_wait_for_reboot)

    assert await h.apply_mode_config(
        {
            "device_props": {
                "wirelessInterfacePTPMode": "1",
                "wirelessInterfaceTXPower": "20",
            }
        }
    ) is True
    assert seen["exists_during_import"] is True
    assert seen["payload"] == {
        "device_props": {
            "wirelessInterfacePTPMode": "1",
            "wirelessInterfaceTXPower": "20",
        }
    }
    assert seen["expected_values"] == {
        "wirelessInterfacePTPMode": "1",
    }
    assert seen["wait_timeout"] == 120
    assert not seen["path"].exists()


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
