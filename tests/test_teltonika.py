"""Local checks for TSW202 registration and its runner integration."""

import asyncio
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

from provisioner.fingerprint import DeviceFingerprinter, DeviceType
from provisioner.firmware_sources.teltonika import TeltonikaFirmwareSource
from provisioner.handlers.teltonika import (
    FIRMWARE,
    READBACK_CHECK_COUNT,
    TeltonikaHandler,
)


def _load_runner():
    path = Path(__file__).resolve().parents[1] / "scripts/tsw202_business_switch.py"
    spec = importlib.util.spec_from_file_location("tsw202_business_switch_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tsw202_oui_routes_to_handler_for_namespace_model_check():
    result = asyncio.run(DeviceFingerprinter().fingerprint("192.168.1.2", "20:97:27:00:00:01"))

    assert result.device_type is DeviceType.TELTONIKA
    assert result.model is None


def test_tsw202_missing_label_password_requests_credentials():
    handler = TeltonikaHandler("192.168.1.2", {"username": "admin", "password": ""})
    handler.business_switch_site = "lakeview"
    handler.business_switch_unit = 2

    result = asyncio.run(handler.provision())

    assert not result.success
    assert result.needs_credentials
    assert "label credentials" in result.error_message


def test_tsw202_firmware_source_matches_profile():
    entries = asyncio.run(TeltonikaFirmwareSource({}).check_for_updates())

    assert len(entries) == 1
    assert entries[0].version == FIRMWARE["version"]
    assert entries[0].filename == FIRMWARE["filename"]
    assert entries[0].download_url == FIRMWARE["url"]
    assert entries[0].extra["md5"] == FIRMWARE["md5"]


def test_runner_without_serial_pins_certificate_after_authenticated_serial(monkeypatch, tmp_path):
    runner = _load_runner()
    parsed_args = runner.parse_args(["--cred-file", "unused", "--unit", "2"])
    assert parsed_args.serial is None
    fingerprint = "a" * 64
    args = SimpleNamespace(
        dry_run=False,
        unit=2,
        site="lakeview",
        cred_file="unused",
        serial=None,
        pin_file=str(tmp_path / "pins.json"),
        trust_new_cert=False,
        cert_sha256=None,
    )

    class FakeApi:
        def __init__(self, host, _username, _password, _fingerprint):
            self.base = "https://" + host

        def login(self):
            return None

        def get(self, path):
            assert path == "/api/system/device/status"
            return {"mnfinfo": {"serial": "BENCH-SERIAL"}}

    monkeypatch.setattr(runner, "load_env", lambda _path: {"TSW202_LABEL_PASSWORD": "test-only"})
    monkeypatch.setattr(runner, "peer_fingerprint", lambda _host: fingerprint)
    monkeypatch.setattr(runner, "probe", lambda _host, _pin: {"device_model": "TSW202"})
    monkeypatch.setattr(runner, "Api", FakeApi)
    with open(runner.DEFAULT_PROFILE) as profile_file:
        profile = json.load(profile_file)

    instance = runner.Runner(args, profile)
    assert instance.connect() == "192.168.10.3"
    assert args.serial == "BENCH-SERIAL"
    assert json.loads(Path(args.pin_file).read_text()) == {"BENCH-SERIAL": fingerprint}


def test_handler_runs_tool_in_subprocess_retries_drop_and_removes_credentials(
    monkeypatch, tmp_path
):
    handler = TeltonikaHandler(
        "192.168.1.2", {"username": "admin", "password": "test-only"}, "eth0.1991"
    )
    credential_dir = tmp_path / "run"
    credential_dir.mkdir(mode=0o700)
    monkeypatch.setattr("provisioner.handlers.teltonika.CREDENTIAL_DIR", credential_dir)
    calls = []
    output = _passing_readback_output()
    assert TeltonikaHandler._readbacks_passed(output)
    assert not TeltonikaHandler._readbacks_passed("RESULT: PASS")

    class Completed:
        returncode = 0
        stdout = output

    def fake_run(command, **kwargs):
        calls.append(command)
        assert "--serial" not in command
        assert "--pin-file" not in command
        assert "--backup-dir" not in command
        assert "--unit" in command and command[command.index("--unit") + 1] == "2"
        assert command[command.index("--iface") + 1] == "eth0.1991"
        credential_path = Path(command[command.index("--cred-file") + 1])
        assert credential_path.exists()
        assert credential_path.stat().st_mode & 0o777 == 0o600
        assert "TSW202_LABEL_PASSWORD=" in credential_path.read_text()
        if len(calls) == 1:
            return SimpleNamespace(returncode=1, stdout="RemoteDisconnected")
        return Completed()

    monkeypatch.setattr("provisioner.handlers.teltonika.subprocess.run", fake_run)
    result = handler._run_profile("lakeview", 2, "admin", "test-only", "/var/tmp/tsw202")

    assert len(calls) == 2
    assert calls[0] == calls[1]
    assert result == output
    assert list(credential_dir.iterdir()) == []


def _passing_readback_output():
    checks = ["check {}".format(index) for index in range(READBACK_CHECK_COUNT)]
    sections = []
    for number in (1, 2):
        sections.append("read-back {}:".format(number))
        sections.extend("  PASS  {}".format(name) for name in checks)
    sections.append("RESULT: PASS")
    return "\n".join(sections)
