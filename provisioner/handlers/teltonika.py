"""Provision the TSW202 business-switch profile through its bench runner.

The API paths, payloads, field values, and stage order come from the
TSW202/RutOS 00.01.10.4 capture and its bench runner. See
bench-evidence/teltonika/TSW202/TSW2_R_00.01.10.4/capture-summary.md.
"""

import asyncio
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from .base import BaseHandler, DeviceInfo, ProvisioningResult

RUNNER_PATH = Path(__file__).resolve().parents[2] / "scripts/tsw202_business_switch.py"
CREDENTIAL_DIR = Path("/run/provisioner")
FIRMWARE = {
    "version": "TSW2_R_00.01.10.4",
    "filename": "TSW2_R_00.01.10.4_WEBUI.bin",
    "url": "https://firmware.teltonika-networks.com/1.10.4/TSW2/TSW2_R_00.01.10.4_WEBUI.bin",
    "md5": "b2a4da07cb055ed198434d3e60c62fef",
}
READBACK_CHECK_COUNT = 22


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
        return False

    async def disconnect(self) -> None:
        self._connected = False

    async def get_info(self) -> DeviceInfo:
        if self._info:
            return self._info
        return DeviceInfo(device_type=self.device_type, model="TSW202", ip_address=self._device_ip)

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
            output = await asyncio.to_thread(
                self._run_profile, site, unit, username, password, firmware_dir
            )
        except Exception as exc:
            result.error_message = str(exc)
            return result

        if self._login_rejected(output):
            result.error_message = "TSW202 label credentials were rejected"
            result.needs_credentials = True
            return result
        if not self._readbacks_passed(output):
            if self._is_connection_drop(output):
                result.error_message = "TSW202 connection failed after one retry"
            else:
                result.error_message = "TSW202 runner did not return two passing read-backs"
            return result

        old_version = self._old_firmware(output)
        self._info = DeviceInfo(
            device_type=self.device_type,
            model="TSW202",
            hostname="th.{}.sw{:02d}".format(site, unit),
            firmware_version=FIRMWARE["version"],
            ip_address="192.168.10.{}".format(1 + unit),
        )
        result.success = True
        result.device_info = self._info
        result.old_firmware = old_version
        result.new_firmware = FIRMWARE["version"]
        result.config_applied = "business-switch"
        return result

    def _run_profile(
        self, site: str, unit: int, username: str, password: str, firmware_dir: str
    ) -> str:
        if not self.interface:
            raise RuntimeError("TSW202 requires a provisioning VLAN interface")
        if "\n" in username or "\n" in password:
            raise RuntimeError("TSW202 credentials cannot contain newlines")

        CREDENTIAL_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory_stat = CREDENTIAL_DIR.stat()
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
            or directory_stat.st_mode & 0o077
        ):
            raise RuntimeError("TSW202 credential directory must be owner-only")

        fd, credential_path = tempfile.mkstemp(
            prefix="tsw202-", suffix=".env", dir=str(CREDENTIAL_DIR)
        )
        os.fchmod(fd, 0o600)
        try:
            with os.fdopen(fd, "w") as credential_file:
                credential_file.write("TSW202_LABEL_USERNAME=" + shlex.quote(username) + "\n")
                credential_file.write("TSW202_LABEL_PASSWORD=" + shlex.quote(password) + "\n")
            command = [
                sys.executable,
                str(RUNNER_PATH),
                "--cred-file",
                credential_path,
                "--unit",
                str(unit),
                "--site",
                site,
                "--iface",
                self.interface,
                "--firmware-dir",
                firmware_dir,
            ]
            for attempt in (1, 2):
                try:
                    completed = subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        check=False,
                        timeout=1800,
                    )
                    output = completed.stdout or ""
                except subprocess.TimeoutExpired as exc:
                    output = exc.stdout or ""
                    if isinstance(output, bytes):
                        output = output.decode(errors="replace")
                    if attempt == 1 and self._is_connection_drop(output):
                        continue
                    return output + "\nRUNNER TIMEOUT"
                if completed.returncode == 0 or not self._is_connection_drop(output):
                    return output
            return output
        finally:
            try:
                os.unlink(credential_path)
            except FileNotFoundError:
                pass

    @staticmethod
    def _is_connection_drop(output: str) -> bool:
        lowered = output.lower()
        return any(
            marker in lowered
            for marker in (
                "remotedisconnected",
                "connectionreseterror",
                "https request failed",
            )
        )

    @staticmethod
    def _login_rejected(output: str) -> bool:
        lowered = output.lower()
        return "login failed (http 401)" in lowered or "login failed (http 403)" in lowered

    @staticmethod
    def _readbacks_passed(output: str) -> bool:
        final_line = output.rstrip().splitlines()[-1].strip() if output.strip() else ""
        blocks = []
        active = None
        results = []
        for line in output.splitlines():
            header = re.match(r"^read-back ([12]):", line.strip())
            if header:
                active = []
                blocks.append(active)
                continue
            if line.startswith("RESULT:"):
                results.append(line.strip())
                active = None
                continue
            if active is not None:
                check = re.match(r"^\s+(PASS|FAIL)\s{2}(.+)$", line)
                if check:
                    text = re.split(r"\s{2}\(", check.group(2), maxsplit=1)[0]
                    active.append((check.group(1), text))
        return (
            bool(results)
            and results[-1] == "RESULT: PASS"
            and final_line == "RESULT: PASS"
            and len(blocks) == 2
            and all(len(block) == READBACK_CHECK_COUNT for block in blocks)
            and all(status == "PASS" for block in blocks for status, _name in block)
            and [name for _status, name in blocks[0]] == [name for _status, name in blocks[1]]
        )

    @staticmethod
    def _old_firmware(output: str) -> Optional[str]:
        match = re.search(r"^firmware: device ([^,]+), target ", output, re.MULTILINE)
        return match.group(1) if match else None
