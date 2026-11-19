"""SwOS Lite HTTP handler for the GPEN21 business-switch profile."""

import asyncio
import hashlib
import ipaddress
import os
import re
from typing import Any, Dict, Optional

from .base import BaseHandler, ConnectionFailureKind, DeviceInfo


class SwosRequestError(RuntimeError):
    """A SwOS Lite request failed without exposing its response body."""


class SwosMovedAddressError(SwosRequestError):
    """The old connection ended while the device changed its address."""


class MikrotikSwosLiteHandler(BaseHandler):
    """Provision a GPEN21 through its SwOS Lite HTTP API."""

    needs_site_job = True
    max_hostname_length = 15
    requires_config_apply = True
    connection_retry_attempts = 1
    firmware_reboot_timeout = 180

    _FWD_FIELDS = (
        "i10",
        "i11",
        "i1f",
        "i1a",
        "i1b",
        "i1d",
        "i1e",
        "i15",
        "i17",
        "i18",
        "i19",
    )
    _SYS_FIELDS = (
        "i0a",
        "i09",
        "i05",
        "i19",
        "i1a",
        "i12",
        "i1b",
        "i0d",
        "i08",
        "i21",
        "i1c",
    )

    def __init__(self, ip: str, credentials: Dict[str, str], interface: Optional[str] = None):
        super().__init__(ip, credentials, interface)
        self._namespace: Optional[str] = None
        self._macvlan: Optional[str] = None

    @property
    def device_type(self) -> str:
        return "mikrotik_swos_lite"

    @staticmethod
    def _parse_page(body: str) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        pattern = re.compile(
            r"['\"]?(i[0-9a-f]{2})['\"]?\s*:\s*("
            r"\[[^\]]*\]|'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\"|"
            r"0x[0-9a-f]+|-?\d+)",
            re.I,
        )
        for match in pattern.finditer(body):
            value = match.group(2).strip()
            if value.startswith("["):
                fields[match.group(1).lower()] = [
                    MikrotikSwosLiteHandler._scalar(item)
                    for item in value[1:-1].split(",")
                    if item.strip()
                ]
            else:
                fields[match.group(1).lower()] = MikrotikSwosLiteHandler._scalar(value)
        rows = []
        for match in re.finditer(r"\{([^{}]+)\}", body):
            row = MikrotikSwosLiteHandler._parse_page(match.group(1))
            if "i01" in row and "i02" in row and "i03" in row:
                rows.append(row)
        if rows:
            fields["rows"] = rows
        return fields

    @staticmethod
    def _scalar(value: str) -> Any:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            return value[1:-1]
        if value.lower().startswith("0x"):
            return int(value, 16)
        if re.fullmatch(r"-?\d+", value):
            return int(value)
        return value

    @staticmethod
    def _hex(value: int) -> str:
        digits = format(int(value), "x")
        if len(digits) % 2:
            digits = "0" + digits
        return "0x" + digits

    @staticmethod
    def _quote(value: str) -> str:
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"

    @classmethod
    def _encode_fields(cls, fields: Any) -> str:
        def encode(value: Any) -> str:
            if isinstance(value, dict):
                return (
                    "{"
                    + ",".join("%s:%s" % (key, encode(item)) for key, item in value.items())
                    + "}"
                )
            if isinstance(value, list):
                return "[" + ",".join(encode(item) for item in value) + "]"
            if isinstance(value, str):
                return cls._quote(value)
            return cls._hex(value)

        if isinstance(fields, list):
            return encode(fields)
        return "{" + ",".join("%s:%s" % (key, encode(value)) for key, value in fields.items()) + "}"

    @staticmethod
    def _decode_hex_ascii(value: Any) -> str:
        if not isinstance(value, str):
            return ""
        try:
            return bytes.fromhex(value).decode("ascii").rstrip("\x00")
        except (ValueError, UnicodeDecodeError):
            return value

    @staticmethod
    def _address_from_little_endian(value: Any) -> str:
        number = int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)
        return str(ipaddress.IPv4Address(number.to_bytes(4, "little")))

    def _netns_names(self) -> tuple[str, str]:
        suffix = hashlib.sha1((self.interface or "").encode("utf-8")).hexdigest()[:6]
        return "swos-" + suffix, "swmv" + suffix

    async def _ip(self, *args: str, check: bool = True) -> None:
        process = await asyncio.create_subprocess_exec(
            "ip",
            *args,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        status = await process.wait()
        if check and status:
            raise SwosRequestError("Could not prepare the isolated SwOS Lite network path")

    async def _ensure_netns(self) -> None:
        if self._namespace:
            return
        if not self.interface:
            raise SwosRequestError("A provisioning interface is required for GPEN21 access")
        self._namespace, self._macvlan = self._netns_names()
        await self._ip("netns", "del", self._namespace, check=False)
        await self._ip("netns", "add", self._namespace)
        try:
            await self._ip(
                "link",
                "add",
                self._macvlan,
                "link",
                self.interface,
                "type",
                "macvlan",
                "mode",
                "bridge",
            )
            await self._ip("link", "set", self._macvlan, "netns", self._namespace)
            for address in ("192.168.88.250/24", "192.168.10.250/24"):
                await self._ip(
                    "netns",
                    "exec",
                    self._namespace,
                    "ip",
                    "addr",
                    "add",
                    address,
                    "dev",
                    self._macvlan,
                )
            await self._ip(
                "netns", "exec", self._namespace, "ip", "link", "set", self._macvlan, "up"
            )
            await self._ip("netns", "exec", self._namespace, "ip", "link", "set", "lo", "up")
        except Exception:
            await self._remove_netns()
            raise

    async def _remove_netns(self) -> None:
        if self._namespace:
            await self._ip("netns", "del", self._namespace, check=False)
        self._namespace = None
        self._macvlan = None

    async def _request(
        self,
        method: str,
        path: str,
        body: Optional[str] = None,
        upload_path: Optional[str] = None,
        allow_redirect: bool = False,
    ) -> tuple[int, str]:
        await self._ensure_netns()
        username = str(self.credentials.get("username", "admin"))
        password = str(self.credentials.get("password", ""))

        def config_value(value: str) -> str:
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return '"' + escaped + '"'

        config_lines = [
            "silent",
            "show-error",
            'max-time = "30"',
            "digest",
            "user = " + config_value(username + ":" + password),
            "request = " + config_value(method),
            'write-out = "\\n%{http_code}"',
            "url = " + config_value("http://%s/%s" % (self.ip, path.lstrip("/"))),
        ]
        if not allow_redirect:
            config_lines.append('max-redirs = "0"')
        if upload_path:
            config_lines.append("form = " + config_value("blob=@" + os.path.abspath(upload_path)))
        else:
            config_lines.append("header = " + config_value("Content-Type: text/plain"))
            if body is not None:
                config_lines.append("data-binary = " + config_value(body))
        args = ["ip", "netns", "exec", self._namespace, "curl", "--config", "-"]
        stdin = "\n".join(config_lines) + "\n"
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            output, _ = await process.communicate(stdin.encode("utf-8"))
        except OSError as exc:
            raise SwosRequestError("SwOS Lite request could not run") from exc
        try:
            response, status_text = output.decode("latin-1").rsplit("\n", 1)
            status = int(status_text.strip())
        except (ValueError, UnicodeDecodeError):
            raise SwosRequestError("SwOS Lite returned an invalid HTTP response") from None
        if status == 0:
            raise SwosMovedAddressError(
                "SwOS Lite connection ended during the management address move"
            )
        if status == 401:
            self.set_connection_failure(ConnectionFailureKind.AUTHENTICATION)
            raise SwosRequestError("SwOS Lite credentials were rejected")
        if status >= 400 or process.returncode:
            raise SwosRequestError("SwOS Lite request failed with HTTP %d" % status)
        return status, response

    async def _get_page(self, page: str) -> Dict[str, Any]:
        _, body = await self._request("GET", page)
        return self._parse_page(body)

    async def _post_page(self, page: str, fields: Any) -> tuple[int, str]:
        return await self._request("POST", page, body=self._encode_fields(fields))

    async def connect(self) -> bool:
        self.login_error = None
        try:
            sys_page = await self._get_page("sys.b")
            if self._decode_hex_ascii(sys_page.get("i07")) != "GPEN21":
                self.login_error = "Detected SwOS Lite board is not GPEN21"
                self.set_connection_failure(ConnectionFailureKind.INVALID_RESPONSE)
                return False
            self._connected = True
            self.set_connection_failure(None)
            return True
        except SwosRequestError as exc:
            self.login_error = str(exc)
            if self.connection_failure_kind != ConnectionFailureKind.AUTHENTICATION:
                self.set_connection_failure(ConnectionFailureKind.TRANSPORT)
            return False

    async def disconnect(self) -> None:
        self._connected = False
        await self._remove_netns()

    async def get_info(self) -> DeviceInfo:
        fields = await self._get_page("sys.b")
        model = self._decode_hex_ascii(fields.get("i07"))
        if model != "GPEN21":
            raise SwosRequestError("Detected SwOS Lite board is not GPEN21")
        version = self._decode_hex_ascii(fields.get("i06"))
        return DeviceInfo(
            device_type=self.device_type, model=model, firmware_version=version, ip_address=self.ip
        )

    async def backup_config(self) -> bytes:
        pages = {}
        for page in ("sys.b", "vlan.b", "fwd.b", "snmp.b"):
            pages[page] = await self._get_page(page)
        pages["snmp.b"].pop("i02", None)
        for field in ("i03", "i04", "i05", "i09"):
            pages["sys.b"].pop(field, None)
        return repr(pages).encode("utf-8")

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        site = getattr(self, "business_switch_site", None)
        unit = getattr(self, "business_switch_unit", None)
        if not site or unit is None:
            raise ValueError("GPEN21 provisioning requires a site and unit")
        unit = int(unit)
        identity = "th.%s.sw%02d" % (site, unit)
        if len(identity) > self.max_hostname_length:
            raise ValueError("Derived GPEN21 identity exceeds the 15-character limit")
        new_ip = "192.168.10.%d" % (1 + unit)

        vlan_rows = [{"i01": vlan, "i02": 7} for vlan in (10, 20, 40, 70)]
        await self._post_page("vlan.b", vlan_rows)

        fwd = await self._get_page("fwd.b")
        fwd = {key: fwd[key] for key in self._FWD_FIELDS}
        fwd.update(
            {
                "i1f": 4,
                "i15": [2, 2, 2],
                "i17": [0, 0, 0],
                "i18": [10, 10, 10],
            }
        )
        await self._post_page("fwd.b", fwd)

        snmp = await self._get_page("snmp.b")
        snmp = {key: snmp[key] for key in ("i01", "i02", "i03", "i04")}
        snmp["i01"] = 0
        await self._post_page("snmp.b", snmp)

        system = await self._get_page("sys.b")
        system = {key: system[key] for key in self._SYS_FIELDS}
        system.update(
            {
                "i0a": 1,
                "i09": int.from_bytes(ipaddress.IPv4Address(new_ip).packed, "little"),
                "i05": identity.encode("ascii").hex(),
                "i19": 0,
                "i1a": 0,
                "i12": 7,
                "i1b": 10,
                "i0d": 1,
                "i08": 7,
                "i21": 0,
                "i1c": 0,
            }
        )
        try:
            await self._post_page("sys.b", system)
        except SwosMovedAddressError:
            pass
        self.ip = new_ip
        await self.disconnect()
        if not await self.ensure_connected("GPEN21 management address move"):
            raise SwosRequestError("GPEN21 did not reconnect at its new management address")

        system = await self._get_page("sys.b")
        system = {key: system[key] for key in self._SYS_FIELDS}
        system["i05"] = identity.encode("ascii").hex()
        await self._post_page("sys.b", system)
        return True

    async def apply_config_file(self, config_path: str) -> bool:
        return await self.apply_config({})

    async def verify_config(self, expected_values: Optional[Dict[str, Any]] = None):
        if not await self.ensure_connected("GPEN21 profile read-back"):
            return False
        site = getattr(self, "business_switch_site", None)
        unit = getattr(self, "business_switch_unit", None)
        identity = "th.%s.sw%02d" % (site, int(unit))
        expected_ip = "192.168.10.%d" % (1 + int(unit))
        for _ in range(2):
            sys_page = await self._get_page("sys.b")
            fwd = await self._get_page("fwd.b")
            snmp = await self._get_page("snmp.b")
            vlan = await self._get_page("vlan.b")
            vlan_values = vlan.get("rows", vlan)
            checks = {
                "identity": self._decode_hex_ascii(sys_page.get("i05")) == identity,
                "static management address": sys_page.get("i0a") == 1
                and self._address_from_little_endian(sys_page.get("i09")) == expected_ip,
                "mgmt VLAN 10": sys_page.get("i1b") == 10,
                "PoE out mode": sys_page.get("i1c") == 0,
                "SFP1 uplink": fwd.get("i1f") == 4,
                "VLAN mode strict": fwd.get("i15") == [2, 2, 2],
                "default VLAN 10": fwd.get("i18") == [10, 10, 10],
                "VLANs 10/20/40/70 all ports": [
                    (row.get("i01"), row.get("i02")) for row in vlan_values if isinstance(row, dict)
                ]
                == [(10, 7), (20, 7), (40, 7), (70, 7)],
                "SNMP off": snmp.get("i01") == 0,
            }
            if not all(checks.values()):
                self.last_verify_mismatches = [
                    name for name, passed in checks.items() if not passed
                ]
                return False
        self.last_verify_mismatches = []
        return True

    async def upload_firmware(self, firmware_path: str, bank: Optional[int] = None) -> bool:
        status, _ = await self._request("POST", "pboot", body="*", allow_redirect=True)
        if status not in (200, 303):
            return False
        status, _ = await self._request("POST", "upgrade", upload_path=firmware_path)
        return status == 200

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        fields = await self._get_page("sys.b")
        return fields.get("i0c") == 1

    async def reboot(self) -> bool:
        status, _ = await self._request("POST", "reboot", body="*", allow_redirect=True)
        self._connected = False
        return status in (200, 303)

    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        await self.disconnect()
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if await self.ensure_connected("GPEN21 reboot check"):
                return True
            await self.disconnect()
            await asyncio.sleep(3)
        return False

    async def get_firmware_version(self) -> str:
        fields = await self._get_page("sys.b")
        return self._decode_hex_ascii(fields.get("i06"))
