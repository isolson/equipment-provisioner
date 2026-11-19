"""Provision the TSW202 business-switch profile.

The API paths, payloads, field values, and stage order come from the
TSW202/RutOS 00.01.10.4 capture and its bench runner. See
bench-evidence/teltonika/TSW202/TSW2_R_00.01.10.4/capture-summary.md.
"""

import asyncio
import importlib.util
import json
import os
import shlex
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

from .base import BaseHandler, DeviceInfo, ProvisioningResult

PROFILE_PATH = Path(__file__).resolve().parents[2] / "scripts/tsw202_business_switch_profile.json"
RUNNER_PATH = Path(__file__).resolve().parents[2] / "scripts/tsw202_business_switch.py"
PIN_FILE = Path("/var/lib/provisioner/tsw202-pins.json")
BACKUP_DIR = Path("/var/lib/provisioner/tsw202-backups")
FIRMWARE = {
    "version": "TSW2_R_00.01.10.4",
    "filename": "TSW2_R_00.01.10.4_WEBUI.bin",
    "url": "https://firmware.teltonika-networks.com/1.10.4/TSW2/TSW2_R_00.01.10.4_WEBUI.bin",
    "md5": "b2a4da07cb055ed198434d3e60c62fef",
}


def _load_runner():
    spec = importlib.util.spec_from_file_location("tsw202_business_switch_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("TSW202 runner is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TeltonikaHandler(BaseHandler):
    """Apply the bench-verified profile to a site-assigned TSW202."""

    needs_site_job = True
    max_hostname_length = None
    DEFAULT_CREDENTIALS = {"username": "admin", "password": ""}
    PROFILE = FIRMWARE

    def __init__(
        self,
        ip: str,
        credentials: Dict[str, str],
        interface: Optional[str] = None,
        alternate_credentials: list = None,
    ):
        super().__init__(ip, credentials, interface)
        self._device_ip = ip
        self.business_switch_site: Optional[str] = None
        self.business_switch_unit: Optional[int] = None
        self._info: Optional[DeviceInfo] = None
        self.login_error: Optional[str] = None

    @property
    def device_type(self) -> str:
        return "teltonika"

    async def connect(self) -> bool:
        # The bench runner performs the serial pin check before login and
        # keeps the factory address inside its handler-local network namespace.
        return self._connected

    async def disconnect(self) -> None:
        self._connected = False

    async def get_info(self) -> DeviceInfo:
        if self._info:
            return self._info
        self._info = DeviceInfo(
            device_type=self.device_type, model="TSW202", ip_address=self._device_ip
        )
        return self._info

    async def backup_config(self) -> bytes:
        return b""

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        return False

    async def apply_config_file(self, config_path: str) -> bool:
        return False

    async def get_firmware_version(self) -> str:
        return self._info.firmware_version if self._info and self._info.firmware_version else ""

    async def upload_firmware(self, firmware_path: str, bank: Optional[int] = None) -> bool:
        return False

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        return False

    async def reboot(self) -> bool:
        return False

    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        return False

    async def provision(self, *args: Any, **kwargs: Any) -> ProvisioningResult:
        """Run the complete profile because the management move is ordered."""
        result = ProvisioningResult(success=False)
        site = self.business_switch_site
        unit = self.business_switch_unit
        if not site or not isinstance(unit, int) or not 1 <= unit <= 8:
            result.error_message = "Business-switch site and unit are required (unit 1-8)"
            return result
        password = (self.credentials or {}).get("password")
        username = (self.credentials or {}).get("username") or "admin"
        if not password:
            result.error_message = "TSW202 label credentials are required"
            result.needs_credentials = True
            return result
        firmware_path = kwargs.get("firmware_path")
        firmware_dir = str(Path(firmware_path).parent) if firmware_path else "/var/tmp/tsw202"
        try:
            info, old_firmware = await asyncio.to_thread(
                self._run_profile, site, unit, username, password, firmware_dir
            )
        except Exception as exc:
            message = str(exc)
            result.error_message = message
            if "login failed" in message.lower() or "credential" in message.lower():
                result.needs_credentials = True
            return result
        self._info = info
        result.success = True
        result.device_info = info
        result.old_firmware = old_firmware
        result.new_firmware = FIRMWARE["version"]
        result.config_applied = "business-switch"
        return result

    def _run_profile(
        self, site: str, unit: int, username: str, password: str, firmware_dir: str
    ) -> tuple[DeviceInfo, Optional[str]]:
        if not self.interface:
            raise RuntimeError("TSW202 requires a provisioning VLAN interface")
        runner = _load_runner()
        with PROFILE_PATH.open() as profile_file:
            profile = json.load(profile_file)
        credential_fd, credential_path = tempfile.mkstemp(prefix="tsw202-", suffix=".env")
        os.fchmod(credential_fd, 0o600)
        try:
            with os.fdopen(credential_fd, "w") as credential_file:
                if "\n" in username or "\n" in password:
                    raise RuntimeError("TSW202 credentials cannot contain newlines")
                credential_file.write("TSW202_LABEL_USERNAME=" + shlex.quote(username) + "\n")
                credential_file.write("TSW202_LABEL_PASSWORD=" + shlex.quote(password) + "\n")
            args = SimpleNamespace(
                dry_run=False,
                unit=unit,
                site=site,
                cred_file=credential_path,
                serial="",
                pin_file=str(PIN_FILE),
                trust_new_cert=False,
                cert_sha256=None,
                backup_dir=str(BACKUP_DIR),
                firmware_dir=firmware_dir,
            )
            addresses = [profile["factory_netns_address"], profile["management"]["netns_address"]]
            runner.netns_up(self.interface, addresses)
            try:
                serial, fingerprint = self._identify_serial(runner)
                args.serial = serial
                pins = runner._read_pins(args.pin_file)
                args.trust_new_cert = serial not in pins
                if args.trust_new_cert:
                    args.cert_sha256 = fingerprint
                api_runner = runner.Runner(args, profile)
                api_runner.connect()
                old_firmware = api_runner.api.get("/api/firmware/device/status").get("version")
                api_runner.backup()
                api_runner.firmware()
                for attempt in (1, 2):
                    try:
                        api_runner.hardening()
                        break
                    except runner.StepError as exc:
                        if attempt == 2 or "HTTPS request failed" not in str(exc):
                            raise
                        api_runner.connect(quiet=True)
                api_runner.vlans()
                api_runner.move()
                results = []
                for index in (0, 1):
                    if index:
                        import time

                        time.sleep(30)
                        api_runner.connect(quiet=True)
                    results.extend(api_runner.readback())
                if not results or any(not passed for _name, passed, _detail in results):
                    raise RuntimeError("TSW202 read-back failed")
                data = api_runner.api.get("/api/system/device/status")
                return (
                    DeviceInfo(
                        device_type=self.device_type,
                        model="TSW202",
                        serial_number=serial,
                        mac_address=data.get("mac"),
                        hostname=api_runner.hostname,
                        firmware_version=FIRMWARE["version"],
                        ip_address=api_runner.mgmt_ip,
                    ),
                    old_firmware,
                )
            finally:
                runner.netns_down()
        finally:
            try:
                os.unlink(credential_path)
            except FileNotFoundError:
                pass

    @staticmethod
    def _identify_serial(runner: Any):
        import urllib.request

        host = "192.168.1.2"
        fingerprint = runner.peer_fingerprint(host)
        opener = urllib.request.build_opener(
            runner._PinnedHTTPSHandler(fingerprint), runner._RefuseRedirect()
        )
        with opener.open("https://%s/api/unauthorized/status" % host, timeout=5) as response:
            payload = json.loads(response.read())
        data = payload.get("data") or {}
        if data.get("device_model") != "TSW202":
            raise RuntimeError("unauthenticated status did not identify a TSW202")
        serial = data.get("serial") or (data.get("mnfinfo") or {}).get("serial")
        if not serial:
            raise RuntimeError("TSW202 status did not return a serial for TLS pinning")
        return str(serial), fingerprint
