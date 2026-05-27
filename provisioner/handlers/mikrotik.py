"""MikroTik RouterOS device handler."""

import asyncio
import ipaddress
import logging
import os
import re
import socket
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp

from .base import BaseHandler, DeviceInfo

logger = logging.getLogger(__name__)


_NPK_FAMILY_RE = re.compile(r"^([a-z][a-z-]*?)-\d", re.IGNORECASE)


def _npk_package_family(filename: str) -> Optional[str]:
    """Extract the package family from an .npk filename.

    `wifi-mediatek-7.22.3-arm.npk` -> `wifi-mediatek`
    `routeros-arm-7.22.3.npk`      -> `routeros`
    """
    match = _NPK_FAMILY_RE.match(filename)
    return match.group(1).lower() if match else None


class MikrotikHandler(BaseHandler):
    """Handler for MikroTik RouterOS devices."""

    # Try common MikroTik defaults before failing to UI prompt
    DEFAULT_CREDENTIALS = [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": ""},
    ]

    def __init__(
        self,
        ip: str,
        credentials: Dict[str, str],
        interface: Optional[str] = None,
        alternate_credentials: Optional[list] = None,
    ):
        super().__init__(ip, credentials, interface)
        self._ssh = None
        self._bind_ip_cache: Optional[str] = None
        self._credentials_confirmed = False
        self._alternate_credentials = alternate_credentials or []
        self.login_error: Optional[str] = None

    @property
    def device_type(self) -> str:
        return "mikrotik"

    @property
    def supports_dual_bank(self) -> bool:
        # RouterOS is single-bank from provisioning perspective.
        return False

    def validate_firmware_for_model(self, firmware_path: str, model: str) -> tuple[bool, str]:
        """Validate RouterOS package before upload."""
        filename = Path(firmware_path).name.lower()
        if not filename.endswith(".npk"):
            return False, f"Firmware mismatch: expected .npk for MikroTik, got '{filename}'"
        if "routeros" not in filename:
            return False, f"Firmware mismatch: expected RouterOS package, got '{filename}'"

        # If architecture is known, ensure package matches it (e.g., mipsbe, arm, arm64).
        arch = None
        if self._device_info and self._device_info.hardware_version:
            arch = self._device_info.hardware_version.lower()
        if arch and arch not in filename:
            return False, (
                f"Firmware mismatch: device architecture '{arch}' not found in filename '{filename}'"
            )
        return True, ""

    async def connect(self) -> bool:
        """Connect to MikroTik over SSH and confirm login."""
        self.login_error = None
        last_error = None
        saw_auth_error = False

        for creds in self._credential_candidates():
            username = creds.get("username", "admin")
            password = creds.get("password", "")
            try:
                conn = await self._open_ssh_connection(username=username, password=password)
                probe = await conn.run("/system identity print", check=False)
                if probe.exit_status == 0:
                    self._ssh = conn
                    self.credentials = {"username": username, "password": password}
                    self._connected = True
                    self._credentials_confirmed = True
                    logger.info(f"Connected to MikroTik at {self.ip} as {username}")
                    return True

                conn.close()
                await conn.wait_closed()
                if probe.stderr:
                    last_error = probe.stderr.strip()

            except Exception as exc:
                last_error = str(exc)
                err = last_error.lower()
                if any(x in err for x in ("permission denied", "authentication", "invalid password")):
                    saw_auth_error = True
                logger.debug(f"MikroTik connect attempt failed for {self.ip}: {exc}")

        if saw_auth_error:
            self.login_error = "Invalid credentials - please enter correct password"
        else:
            self.login_error = last_error or "Device not reachable"
        logger.error(f"Failed to connect to MikroTik at {self.ip}: {self.login_error}")
        return False

    async def disconnect(self) -> None:
        """Disconnect from the device."""
        if self._ssh:
            try:
                self._ssh.close()
                await self._ssh.wait_closed()
            except Exception:
                pass
            self._ssh = None

        self._connected = False
        logger.info(f"Disconnected from MikroTik at {self.ip}")

    async def get_info(self) -> DeviceInfo:
        """Get device information from RouterOS."""
        resource = self._parse_kv_output(await self._run_command("/system resource print as-value"))
        identity = self._parse_kv_output(await self._run_command("/system identity print as-value"))
        routerboard = self._parse_kv_output(
            await self._run_command("/system routerboard print as-value", allow_failure=True)
        )

        # RouterOS CLI output can vary across versions/terminal modes.
        # Fall back to direct getters so architecture/version are always available.
        arch_name = resource.get("architecture-name") or (
            await self._run_command(":put [/system resource get architecture-name]", allow_failure=True)
        ).strip()
        ros_version = resource.get("version") or (
            await self._run_command(":put [/system resource get version]", allow_failure=True)
        ).strip()
        board_name = resource.get("board-name") or (
            await self._run_command(":put [/system resource get board-name]", allow_failure=True)
        ).strip()
        identity_name = identity.get("name") or (
            await self._run_command(":put [/system identity get name]", allow_failure=True)
        ).strip()

        info = DeviceInfo(
            device_type=self.device_type,
            ip_address=self.ip,
            model=board_name or None,
            firmware_version=self._normalize_version(ros_version) or None,
            hardware_version=arch_name or None,
            hostname=identity_name or None,
        )

        if resource.get("uptime"):
            info.uptime = self._parse_uptime(resource["uptime"])

        info.extra["cpu"] = resource.get("cpu")
        info.extra["memory_total"] = resource.get("total-memory")
        info.extra["memory_free"] = resource.get("free-memory")

        if routerboard:
            info.serial_number = routerboard.get("serial-number")
            info.extra["current_firmware"] = routerboard.get("current-firmware")
            info.extra["upgrade_firmware"] = routerboard.get("upgrade-firmware")

        # Same fallback pattern as architecture/version above: the bridge-bootstrap
        # topology + as-value parsing can drop serial-number on some firmwares;
        # the direct getter is always reliable. Contract registration requires
        # a real serial — UNKNOWN must never reach the wifi-api.
        if not info.serial_number:
            fallback_serial = (
                await self._run_command(
                    ":put [/system/routerboard/get serial-number]", allow_failure=True
                )
            ).strip()
            if fallback_serial:
                info.serial_number = fallback_serial

        mac = await self._run_command(
            ":put [/interface ethernet get [find default-name=ether1] mac-address]",
            allow_failure=True,
        )
        if mac:
            info.mac_address = mac.strip().upper()
        else:
            iface_dump = await self._run_command("/interface ethernet print as-value", allow_failure=True)
            match = re.search(r"mac-address=([0-9A-Fa-f:]{17})", iface_dump)
            if match:
                info.mac_address = match.group(1).upper()

        self._device_info = info
        return info

    async def get_firmware_banks(self) -> Dict[str, Any]:
        """Return RouterOS + RouterBOOT versions for UI visibility."""
        resource = self._parse_kv_output(await self._run_command("/system resource print as-value"))
        routerboard = self._parse_kv_output(
            await self._run_command("/system routerboard print as-value", allow_failure=True)
        )

        ros_version_raw = resource.get("version") or (
            await self._run_command(":put [/system resource get version]", allow_failure=True)
        ).strip() or "unknown"
        ros_version = self._normalize_version(ros_version_raw) or "unknown"
        rb_current = self._normalize_version(routerboard.get("current-firmware") if routerboard else None)
        rb_upgrade = self._normalize_version(routerboard.get("upgrade-firmware") if routerboard else None)
        rb_version = rb_current or ros_version

        bank2_display = rb_version
        if rb_current and rb_upgrade and rb_current != rb_upgrade:
            bank2_display = f"{rb_current} -> {rb_upgrade}"

        return {
            "bank1": ros_version,           # RouterOS package version
            "bank2": rb_version,            # RouterBOOT firmware version
            "active": 1,                    # Single-bank from UI perspective
            "bank1_display": ros_version_raw,
            "bank2_display": bank2_display,
        }

    @staticmethod
    def _normalize_version(version: Optional[str]) -> str:
        """Normalize RouterOS/RouterBOOT version for comparisons."""
        if not version:
            return ""
        # RouterOS can report values like "7.20.8 (long-term)".
        return version.strip().split()[0]

    def _parse_uptime(self, uptime_str: str) -> int:
        """Parse RouterOS uptime string like 1w2d3h4m5s to seconds."""
        total = 0
        patterns = [
            (r"(\d+)w", 604800),
            (r"(\d+)d", 86400),
            (r"(\d+)h", 3600),
            (r"(\d+)m", 60),
            (r"(\d+)s", 1),
        ]
        for pattern, multiplier in patterns:
            match = re.search(pattern, uptime_str)
            if match:
                total += int(match.group(1)) * multiplier
        return total

    async def backup_config(self) -> bytes:
        """Export RouterOS configuration."""
        config = await self._run_command("/export hide-sensitive")
        return config.encode("utf-8")

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration dictionary.

        MikroTik provisioning should use .rsc templates; inline dict config
        isn't a stable cross-model contract.
        """
        logger.error("Inline MikroTik config dict is not supported; use a .rsc config file")
        return False

    async def apply_config_file(self, config_path: str) -> bool:
        """Upload and import .rsc config file."""
        config_file = Path(config_path)
        if not config_file.exists():
            logger.error(f"Config file not found: {config_path}")
            return False

        try:
            await self._ensure_ssh()

            remote_name = "provision-config.rsc"
            async with self._ssh.start_sftp_client() as sftp:
                await sftp.put(config_path, remote_name)

            result = await self._ssh.run(f"/import file-name={remote_name}", check=False)
            output = ((result.stdout or "") + "\n" + (result.stderr or "")).lower()
            if result.exit_status != 0 or "failure" in output or "error" in output:
                logger.error(f"Config import failed on {self.ip}: {output.strip()}")
                return False

            logger.info(f"Config file applied to {self.ip}")
            return True
        except Exception as exc:
            logger.error(f"Failed to apply config file: {exc}")
            return False

    async def upload_firmware(self, firmware_path: str) -> bool:
        """Upload RouterOS package to device."""
        firmware_file = Path(firmware_path)
        if not firmware_file.exists():
            logger.error(f"Firmware file not found: {firmware_path}")
            return False

        try:
            await self._ensure_ssh()
            async with self._ssh.start_sftp_client() as sftp:
                await sftp.put(firmware_path, firmware_file.name)

            logger.info(f"Firmware uploaded to {self.ip}: {firmware_file.name}")
            return True
        except Exception as exc:
            logger.error(f"Failed to upload firmware: {exc}")
            return False

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """Stage RouterBOARD firmware upgrade (RouterOS package is applied on reboot)."""
        try:
            rb = self._parse_kv_output(
                await self._run_command("/system routerboard print as-value", allow_failure=True)
            )
            if rb:
                current = rb.get("current-firmware")
                upgrade = rb.get("upgrade-firmware")
                if current and upgrade and current != upgrade:
                    await self._run_command("/system routerboard upgrade")
                    logger.info(f"RouterBOARD firmware upgrade scheduled on {self.ip}: {current} -> {upgrade}")
            return True
        except Exception as exc:
            logger.error(f"Failed to schedule firmware update on {self.ip}: {exc}")
            return False

    async def reboot(self) -> bool:
        """Reboot device."""
        try:
            await self._run_command("/system reboot", allow_failure=True)
            logger.info(f"Reboot initiated on {self.ip}")
            return True
        except Exception as exc:
            # SSH disconnect is expected during reboot.
            err = str(exc).lower()
            if any(x in err for x in ("disconnect", "connection", "closed")):
                return True
            logger.error(f"Failed to reboot {self.ip}: {exc}")
            return False

    async def get_firmware_version(self) -> str:
        """Get current RouterOS version."""
        resource = self._parse_kv_output(await self._run_command("/system resource print as-value"))
        return self._normalize_version(resource.get("version")) or "unknown"

    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        """Wait for device to reboot and accept SSH again.

        Distinguishes "network down" (connection-refused / timeout — device
        rebooting) from "network up, auth failed" (PermissionDenied — device
        booted but credentials are wrong). The latter means the device IS
        back; we just can't log in, so we surface a different failure note.
        """
        import asyncssh

        logger.info(f"Waiting for {self.ip} to come back online...")
        await asyncio.sleep(3)

        start = asyncio.get_event_loop().time()
        saw_offline = False
        last_auth_failure = False

        while asyncio.get_event_loop().time() - start < timeout:
            try:
                conn = await self._open_ssh_connection(
                    username=self.credentials.get("username", "admin"),
                    password=self.credentials.get("password", ""),
                )
                conn.close()
                await conn.wait_closed()

                # If we observed a disconnect period, this is a real post-reboot return.
                elapsed = asyncio.get_event_loop().time() - start
                if saw_offline or elapsed >= 20:
                    logger.info(f"{self.ip} is back online")
                    return True
            except asyncssh.PermissionDenied:
                # Device is reachable but our credentials don't work. That's
                # a "back online" signal for connectivity purposes, but the
                # caller will still fail at the next step (connect()). Track
                # so the timeout message can be more informative.
                last_auth_failure = True
                saw_offline = True
            except Exception:
                saw_offline = True

            await asyncio.sleep(5)

        if last_auth_failure:
            logger.error(
                f"{self.ip} is reachable but rejected credentials within {timeout}s "
                f"(user={self.credentials.get('username')!r}) — check post-flash auth setup"
            )
        else:
            logger.error(f"{self.ip} did not come back online within {timeout}s")
        return False

    def _credential_candidates(self) -> list[Dict[str, str]]:
        """Build ordered credential attempts with de-duplication."""
        candidates: list[Dict[str, str]] = []

        def add(creds: Optional[Dict[str, str]]):
            if not creds:
                return
            candidate = {
                "username": creds.get("username", "admin"),
                "password": creds.get("password", ""),
            }
            if candidate not in candidates:
                candidates.append(candidate)

        configured = {
            "username": self.credentials.get("username", "admin"),
            "password": self.credentials.get("password", ""),
        }

        if self._credentials_confirmed:
            add(configured)
            for default in self.DEFAULT_CREDENTIALS:
                add(default)
        else:
            default_passwords = {d["password"] for d in self.DEFAULT_CREDENTIALS}
            configured_is_custom = configured["password"] not in default_passwords
            if configured_is_custom:
                add(configured)
            for default in self.DEFAULT_CREDENTIALS:
                add(default)
            if not configured_is_custom:
                add(configured)

        for alt in self._alternate_credentials:
            add(alt)

        return candidates

    async def _ensure_ssh(self) -> None:
        """Ensure active SSH connection."""
        if self._ssh:
            return
        if not await self.connect():
            raise RuntimeError(self.login_error or "Failed to connect")

    async def _open_ssh_connection(self, username: str, password: str):
        """Open SSH session, binding traffic to the selected VLAN interface when configured."""
        import asyncssh

        kwargs: Dict[str, Any] = {
            "username": username,
            "password": password,
            "known_hosts": None,
            "client_keys": None,
            "agent_path": None,
            "connect_timeout": 10,
        }

        if self.interface:
            sock = await self._create_bound_socket(port=22)
            kwargs["sock"] = sock

        return await asyncssh.connect(self.ip, **kwargs)

    async def _create_bound_socket(self, port: int) -> socket.socket:
        """Create and connect a socket bound to the configured interface."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode())
        except OSError as exc:
            logger.warning(f"Could not bind socket to {self.interface}: {exc}")

        bind_ip = await self._get_interface_bind_ip()
        if bind_ip:
            try:
                sock.bind((bind_ip, 0))
            except OSError as exc:
                logger.warning(f"Could not bind source IP {bind_ip} for {self.ip}: {exc}")

        try:
            await asyncio.to_thread(sock.connect, (self.ip, port))
            sock.setblocking(False)
            return sock
        except Exception:
            sock.close()
            raise

    async def _get_interface_bind_ip(self) -> Optional[str]:
        """Pick best source IP from interface addresses for this target device IP."""
        if self._bind_ip_cache:
            return self._bind_ip_cache

        if not self.interface:
            return None

        proc = await asyncio.create_subprocess_exec(
            "ip", "-4", "-o", "addr", "show", "dev", self.interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            return None

        addrs = []
        for line in stdout.decode().splitlines():
            match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", line)
            if match:
                addrs.append(match.group(1))

        if not addrs:
            return None

        target = ipaddress.ip_address(self.ip)

        def same_24(candidate: str) -> bool:
            try:
                return ipaddress.ip_address(candidate) in ipaddress.ip_network(f"{target}/24", strict=False)
            except Exception:
                return False

        # Prefer same /24 for default CPE subnets (e.g., 192.168.88.x).
        for addr in addrs:
            if same_24(addr):
                self._bind_ip_cache = addr
                return addr

        # Then prefer common provisioning subnet ranges.
        for prefix in ("192.168.88.", "192.168.1.", "169.254."):
            for addr in addrs:
                if addr.startswith(prefix):
                    self._bind_ip_cache = addr
                    return addr

        self._bind_ip_cache = addrs[0]
        return addrs[0]

    async def _run_command(self, command: str, allow_failure: bool = False) -> str:
        """Run a RouterOS CLI command over SSH."""
        await self._ensure_ssh()
        result = await self._ssh.run(command, check=False)

        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        if result.exit_status != 0 and not allow_failure:
            raise RuntimeError(stderr or stdout or f"Command failed: {command}")
        return stdout

    # ------------------------------------------------------------------
    # Netinstall (flash device in BOOTP mode)
    # ------------------------------------------------------------------

    NETINSTALL_CLI = "/opt/provisioner/tools/netinstall-cli"
    NETINSTALL_TIMEOUT = 300  # 5 minutes
    # netinstall-cli requires the client IP to live in a subnet on the bound
    # interface. Per-port VLAN interfaces only carry 192.168.88.11/32 (port
    # isolation), which fails that check. We add a transient /24 in unused
    # 10.255.<vlan>.0/24 space — derived from the VLAN id so that concurrent
    # Netinstalls on different ports get distinct subnets and don't share a
    # kernel route. No collision with management VLAN's 192.168.88.0/24.
    # Cleared in a finally block so the iface stays clean.
    NETINSTALL_HOST_ADDR_FMT = "10.255.{octet}.11/24"
    NETINSTALL_CLIENT_IP_FMT = "10.255.{octet}.1"

    BOOTSTRAP_USER = "fleet-bootstrap"

    # `-sm <modescript>` (netinstall-cli 7.22+) takes a file path to a
    # RouterScript that runs once on first boot, before the device is
    # network-accessible. We use it to set device-mode=advanced so that the
    # canonical base-flash's scheduler / `/tool/fetch` /
    # `dont-require-permissions=yes` constructs are permitted. Format
    # confirmed against tikoci/netinstall reference implementation.
    MODE_SCRIPT_BODY = "/system/device-mode update mode=advanced\n"

    @staticmethod
    def _escape_routeros_string(value: str) -> str:
        """Escape a value for embedding inside a RouterOS double-quoted string.

        Inside `"..."`, RouterOS interprets `$name` as variable substitution
        and `[cmd]` as command substitution, in addition to `\\` and `"` as
        escape characters. A literal value must escape all four.
        """
        return (
            value
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("$", "\\$")
            .replace("[", "\\[")
        )

    @classmethod
    def _netinstall_octet_for_interface(cls, interface: str) -> int:
        """Derive a unique /24 octet (0-255) per VLAN sub-interface.

        eno1.1995 → 1995 → 1995 mod 256 = 203
        Distinct for any two VLAN IDs ≤ 255 apart, which covers all per-port
        VLANs we currently provision.
        """
        if "." not in interface:
            return 5  # legacy fallback for non-VLAN callers
        try:
            vlan = int(interface.rsplit(".", 1)[1])
        except ValueError:
            return 5
        return vlan % 256

    async def netinstall(
        self,
        firmware_paths: List[str],
        interface: str,
        bootstrap_password: Optional[str] = None,
        on_progress=None,
    ) -> bool:
        """Flash a MikroTik device in BOOTP/Netinstall mode.

        The device must be in Netinstall mode (reset button held during power-on).
        Runs netinstall-cli to flash RouterOS firmware onto the device.

        Args:
            firmware_paths: All RouterOS .npk files to offer. netinstall-cli picks
                the arch matching the BOOTP request, so pass every arch you have.
            interface: VLAN interface to use (e.g. eth0.1991)
            bootstrap_password: If set, runs a -s user-script after install that
                creates a non-admin user (fleet-bootstrap) with this password.
                Required for RouterOS 7.20+ where default-config admin sits in
                a 'must change password on first login' state that prevents SSH
                login even after /user/set on admin.
            on_progress: Optional async callback for progress updates
        """
        if not Path(self.NETINSTALL_CLI).exists():
            logger.error(f"netinstall-cli not found at {self.NETINSTALL_CLI}")
            return False

        if not firmware_paths:
            logger.error("No firmware paths provided to netinstall")
            return False

        missing = [p for p in firmware_paths if not Path(p).exists()]
        if missing:
            logger.error(f"Firmware files not found: {missing}")
            return False

        octet = self._netinstall_octet_for_interface(interface)
        host_addr = self.NETINSTALL_HOST_ADDR_FMT.format(octet=octet)
        client_ip = self.NETINSTALL_CLIENT_IP_FMT.format(octet=octet)

        cmd = [
            self.NETINSTALL_CLI,
            "-i", interface,
            "-a", client_ip,
            "-c",  # allow concurrent netinstall servers across ports
        ]

        # Debug toggles for hAP ax S WiFi-radio diagnostic.
        # Precedence: USE_E > NO_R > default(-r).
        # -e: empty config (no DefConf, no factory default script). Pairs
        #     cleanly with our -s replacing customized.default.rsc.
        # No flag: keep existing config (preserves prior state).
        # -r (default): apply factory DefConf — conflicts semantically with
        #     -s which replaces default-config. Suspected of leaving radios
        #     unbound on hAP ax S when DefConf's wifi-gen step fails.
        if os.environ.get("MIKROTIK_NETINSTALL_USE_E", "").lower() in ("1", "true", "yes"):
            logger.warning(
                "MIKROTIK_NETINSTALL_USE_E set — using -e (empty config) instead of -r"
            )
            cmd.append("-e")
        elif os.environ.get("MIKROTIK_NETINSTALL_NO_R", "").lower() in ("1", "true", "yes"):
            logger.warning(
                "MIKROTIK_NETINSTALL_NO_R set — omitting -r flag from netinstall-cli"
            )
        else:
            cmd.append("-r")

        # `-sm` requires netinstall-cli 7.22+. Older binaries will reject
        # the flag and abort the run — surface that as a "tool too old"
        # error rather than silently leaving the device in `home` mode
        # (which would break the canonical base-flash downstream).
        modescript_path: Optional[str] = None
        fd = tempfile.NamedTemporaryFile(
            mode="w", suffix=".rsc", prefix="netinstall-modescript-", delete=False
        )
        fd.write(self.MODE_SCRIPT_BODY)
        fd.close()
        modescript_path = fd.name
        cmd.extend(["-sm", modescript_path])

        userscript_path: Optional[str] = None
        if bootstrap_password:
            escaped = self._escape_routeros_string(bootstrap_password)
            # `-s` REPLACES default-config, so we must explicitly bring up
            # the management IP (192.168.88.1) and a bridge over all ether
            # ports, otherwise the device boots with no L3 and the
            # provisioner can't reach it post-flash. The /user/add gets us a
            # login that bypasses RouterOS 7.20+ admin-first-login lockout.
            script_body = (
                ':do {/interface/bridge/remove [find name=bridge-bootstrap]} on-error={}\n'
                '/interface/bridge/add name=bridge-bootstrap comment=netinstall-bootstrap\n'
                ':foreach iface in=[/interface/ethernet/find] do={\n'
                '    :do {/interface/bridge/port/add bridge=bridge-bootstrap interface=$iface} on-error={}\n'
                '}\n'
                ':do {/ip/address/remove [find comment=netinstall-bootstrap]} on-error={}\n'
                '/ip/address/add address=192.168.88.1/24 interface=bridge-bootstrap comment=netinstall-bootstrap\n'
                f':do {{/user/remove [find name="{self.BOOTSTRAP_USER}"]}} on-error={{}}\n'
                f'/user/add name="{self.BOOTSTRAP_USER}" password="{escaped}" group=full\n'
                f':log info "ZTP: {self.BOOTSTRAP_USER} user + bridge-bootstrap created by netinstall user-script"\n'
            )
            fd = tempfile.NamedTemporaryFile(
                mode="w", suffix=".rsc", prefix="netinstall-userscript-", delete=False
            )
            fd.write(script_body)
            fd.close()
            userscript_path = fd.name
            cmd.extend(["-s", userscript_path])

        cmd.extend(firmware_paths)

        # Redact -s contents from logged cmd; keep paths.
        loggable = " ".join(cmd)
        logger.info(f"Starting Netinstall on {interface}: {loggable}")
        if on_progress:
            await on_progress("netinstall", "running", "Waiting for device in BOOTP mode...")

        addr_added = False
        try:
            addr_added = await self._add_netinstall_addr(interface, host_addr)
            if not addr_added:
                # Subnet check inside netinstall-cli would reject `-a` with a
                # confusing error otherwise; surface the underlying failure.
                logger.error(
                    f"Aborting Netinstall on {interface}: could not assign {host_addr}"
                )
                if on_progress:
                    await on_progress("netinstall", False, "Failed to assign install IP")
                return False

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.NETINSTALL_TIMEOUT
            )

            stdout_text = stdout.decode() if stdout else ""
            stderr_text = stderr.decode() if stderr else ""

            if proc.returncode == 0:
                logger.info(f"Netinstall completed on {interface}: {stdout_text.strip()}")
                if on_progress:
                    await on_progress("netinstall", True, "Firmware flashed successfully")
                return True
            else:
                logger.error(f"Netinstall failed (rc={proc.returncode}): {stderr_text or stdout_text}")
                if on_progress:
                    await on_progress("netinstall", False, stderr_text[:100] or "Unknown error")
                return False

        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.error(f"Netinstall timed out after {self.NETINSTALL_TIMEOUT}s")
            if on_progress:
                await on_progress("netinstall", False, "Timed out waiting for device")
            return False
        except Exception as exc:
            logger.error(f"Netinstall error: {exc}")
            if on_progress:
                await on_progress("netinstall", False, str(exc)[:100])
            return False
        finally:
            if addr_added:
                await self._remove_netinstall_addr(interface, host_addr)
            for path in (userscript_path, modescript_path):
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass

    async def _add_netinstall_addr(self, interface: str, host_addr: str) -> bool:
        """Add the transient /24 needed by netinstall-cli's subnet check."""
        proc = await asyncio.create_subprocess_exec(
            "ip", "addr", "add", host_addr, "dev", interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode == 0:
            return True
        err = stderr.decode().strip()
        if "File exists" in err:
            # Leftover from an aborted prior run; keep it and reuse.
            return True
        logger.error(f"Failed to add {host_addr} to {interface}: {err}")
        return False

    async def _remove_netinstall_addr(self, interface: str, host_addr: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "ip", "addr", "del", host_addr, "dev", interface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        if proc.returncode != 0:
            logger.warning(
                f"Failed to remove {host_addr} from {interface}: "
                f"{stderr.decode().strip()}"
            )

    # ------------------------------------------------------------------
    # Sequenced extra-package install (post-netinstall)
    # ------------------------------------------------------------------
    #
    # On hAP ax / ax² / ax³ / ax S, net-installing routeros + wifi-qcom
    # in the same flash leaves /interface/wifi/radio/print empty — the
    # driver loads but the radio chip never binds. Boot log shows
    # `DefConf gen: Unable to find wifi radio data` + a critical "script
    # interrupted" error. Manual `/system upgrade` to the same versions
    # preserves wifi, so it's specifically the simultaneous-install path
    # that breaks radio binding. Forum fix path:
    # https://forum.mikrotik.com/t/hap-ax-lite-no-wifi-in-default-config-solved/172882
    #
    # The provisioner ships only `routeros-*-<arch>.npk` via netinstall-cli,
    # then SCP-uploads `wifi-qcom-<ver>-<arch>.npk` post-boot and reboots
    # to install onto an already-running OS. A final `/system
    # reset-configuration` triggers a fresh DefConf gen with wifi-qcom
    # now properly bound, populating `/interface/wifi/radio`.

    async def install_extra_npks_and_reboot(
        self,
        local_npk_paths: List[str],
        timeout: int = 240,
    ) -> bool:
        """SFTP-upload one or more .npks to device root and reboot to install them.

        RouterOS auto-installs any .npk it finds at `/` on next boot, then
        removes the file. Multiple drivers (e.g. wifi-qcom + wifi-mediatek)
        can be shipped together — only the one matching the device's
        actual radio chip will bind; the others are inert.

        Used post-netinstall so packages install onto a fully-booted OS
        rather than during the netinstall first-boot sequence (which
        breaks radio binding on hAP ax hardware).
        """
        if not local_npk_paths:
            return True
        await self._ensure_ssh()
        names = [Path(p).name for p in local_npk_paths]

        try:
            async with self._ssh.start_sftp_client() as sftp:
                for path, name in zip(local_npk_paths, names):
                    await sftp.put(path, name)
                    logger.info(
                        f"Uploaded {name} to {self.ip} for next-boot install"
                    )
        except Exception as exc:
            logger.error(f"SFTP upload to {self.ip} failed: {exc}")
            return False

        # Reboot — SSH session will drop mid-command, which is expected.
        try:
            await self._ssh.run("/system reboot", timeout=4, check=False)
        except Exception:
            pass
        try:
            await self.disconnect()
        except Exception:
            pass

        # Let the device begin shutdown before we start polling.
        await asyncio.sleep(10)

        if not await self.wait_for_reboot(timeout=timeout):
            logger.error(
                f"{self.ip} did not come back online after extra-package install reboot"
            )
            return False

        if not await self.connect():
            logger.error(
                f"Could not reconnect after extra-package install: {self.login_error}"
            )
            return False

        # Confirm at least one of the uploaded packages now appears installed.
        # We don't fail if any individual one is missing because not every
        # uploaded driver applies to the device's chip — wifi-qcom and
        # wifi-mediatek are mutually exclusive at install time on a given
        # device. RouterOS will install only the matching one.
        result = await self._ssh.run(
            "/system package print", timeout=10, check=False
        )
        installed_output = (result.stdout or "").lower()
        installed_count = 0
        for name in names:
            # filename prefix up through the last "-<arch>" delimiter is the
            # package family (e.g. "wifi-mediatek-7.22.3-arm.npk" -> "wifi-mediatek").
            pkg_family = _npk_package_family(name)
            if pkg_family and pkg_family in installed_output:
                installed_count += 1
                logger.info(f"{pkg_family} installed on {self.ip}")
        if installed_count == 0:
            logger.error(
                f"After install reboot, none of {names} appear in /system package print on {self.ip}"
            )
            return False
        return True

    async def factory_reset_and_reconnect(
        self,
        timeout: int = 240,
    ) -> bool:
        """Issue `/system reset-configuration` and wait for SSH back.

        After reset, RouterOS re-runs the customized.default.rsc that
        netinstall-cli's `-s` flag installed — which rebuilds
        bridge-bootstrap + the fleet-bootstrap user — and the wifi-qcom
        DefConf gen runs fresh with radios now bound, populating
        `/interface/wifi/radio`. Used right after `install_extra_npk_and_reboot`.
        """
        await self._ensure_ssh()

        try:
            await self._ssh.run(
                "/system reset-configuration skip-backup=yes",
                timeout=4,
                check=False,
            )
        except Exception:
            pass
        try:
            await self.disconnect()
        except Exception:
            pass

        # Reset-configuration is more involved than a plain reboot (full
        # storage reset + script replay). Allow extra settle time.
        await asyncio.sleep(15)

        if not await self.wait_for_reboot(timeout=timeout):
            logger.error(
                f"{self.ip} did not come back online after /system reset-configuration"
            )
            return False

        if not await self.connect():
            logger.error(
                f"Could not reconnect after reset-configuration: {self.login_error}"
            )
            return False

        logger.info(
            f"Reset-configuration completed on {self.ip}; "
            f"reconnected as {self.credentials.get('username')}"
        )
        return True

    # ------------------------------------------------------------------
    # ZTP base-flash (fetch canonical script + verify post-import note)
    # ------------------------------------------------------------------
    #
    # The provisioner does NOT author a base-flash. The canonical script
    # lives at GET <ztp_api_url>/ztp/mikrotik/base-flash.rsc on the wifi
    # service and owns phone-home, schedulers, default-configuration
    # recovery, and role self-detection. Our job is fetch -> prepend the
    # per-device :local parameters -> /import -> verify -> register.

    BASE_FLASH_PATH = "/ztp/mikrotik/base-flash.rsc"
    BASE_FLASH_VERSION = "universal-v1"
    BASE_FLASH_FETCH_TIMEOUT = 15  # seconds

    @staticmethod
    async def fetch_base_flash(ztp_api_url: str) -> str:
        """Fetch the canonical base-flash.rsc from the wifi-api.

        Per contract: plain-text RouterScript, no auth, no secrets. Fetched
        per install so version drift is impossible — no caching.
        """
        url = ztp_api_url.rstrip("/") + MikrotikHandler.BASE_FLASH_PATH
        timeout = aiohttp.ClientTimeout(total=MikrotikHandler.BASE_FLASH_FETCH_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise RuntimeError(
                        f"base-flash fetch {url} returned {resp.status}: {body[:200]}"
                    )
                return await resp.text()

    @staticmethod
    def build_import_script(
        serial: str,
        bootstrap_pass: str,
        base_flash_body: str,
        onboarding_pass: Optional[str] = None,
    ) -> str:
        """Prepend per-device `:local` declarations to the canonical script.

        The canonical script consumes `$serial`, `$bootstrapPass`, and
        `$onboardingPass`. Per contract, onboarding-pass defaults to the
        bootstrap pass.
        """
        bp = MikrotikHandler._escape_routeros_string(bootstrap_pass)
        op = MikrotikHandler._escape_routeros_string(onboarding_pass or bootstrap_pass)
        ser = MikrotikHandler._escape_routeros_string(serial)
        prelude = (
            f':local serial "{ser}"\n'
            f':local bootstrapPass "{bp}"\n'
            f':local onboardingPass "{op}"\n'
        )
        return prelude + base_flash_body

    async def verify_base_flash_applied(self) -> bool:
        """Verify post-import that the canonical base-flash actually ran.

        Reads `/system/note` and checks for the
        `base_flash_version=universal-v1` marker the canonical script writes.
        Per contract: absence means the script did not run cleanly and
        registration must be skipped.
        """
        note = await self._run_command(
            ":put [/system/note/get note]", allow_failure=True
        )
        marker = f"base_flash_version={self.BASE_FLASH_VERSION}"
        return marker in (note or "")

    async def wait_for_base_flash_applied(
        self, timeout: float = 360.0, interval: float = 2.0
    ) -> bool:
        """Wait for RouterOS to finish applying the imported base-flash script.

        On RouterOS 7.22, `/import file-name=...` can return before all
        imported commands are visible to follow-up SSH reads. Polling the note
        marker avoids falsely failing a device that is still applying the
        script. hAP ax S units have taken more than four minutes to expose the
        marker after import, so keep this window comfortably above that.
        """
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            if await self.verify_base_flash_applied():
                return True
            if asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(interval)

    async def verify_ztp_ready(self, expected_serial: str) -> tuple[bool, str]:
        """Verify the post-Netinstall device can phone home after handoff.

        The note marker proves the script reached the end. These checks prove
        the RouterOS features and artifacts required for first internet
        contact are present before we register the device as provisioned.
        """
        mode_output = await self._run_command(
            "/system/device-mode/print", allow_failure=True
        )
        device_mode = self._parse_kv_output(mode_output)
        fetch = device_mode.get("fetch", "").lower()
        scheduler = device_mode.get("scheduler", "").lower()
        mode = device_mode.get("mode", "").lower() or "unknown"

        if fetch != "yes" or scheduler != "yes":
            return (
                False,
                "device-mode blocks ZTP: mode=%s fetch=%s scheduler=%s"
                % (mode, fetch or "unknown", scheduler or "unknown"),
            )

        note = await self._run_command(
            ":put [/system/note/get note]", allow_failure=True
        )
        marker = f"base_flash_version={self.BASE_FLASH_VERSION}"
        if marker not in (note or ""):
            return False, f"missing {marker} marker"

        identity = (
            await self._run_command(
                ":put [/system/identity/get name]", allow_failure=True
            )
        ).strip()
        allowed_prefixes = ("fleet-init-", "fleet-gw-", "fleet-ext-", "fleet-rtr-")
        if not identity.startswith(allowed_prefixes) or expected_serial not in identity:
            return False, f"unexpected identity after base-flash: {identity or 'empty'}"

        phone_home_count = await self._run_count(
            "/system/script/find name=phone-home"
        )
        if phone_home_count < 1:
            return False, "missing phone-home script"

        boot_scheduler_count = await self._run_count(
            "/system/scheduler/find name=phone-home-boot"
        )
        adaptive_scheduler_count = await self._run_count(
            "/system/scheduler/find name=phone-home-adaptive"
        )
        if boot_scheduler_count < 1 or adaptive_scheduler_count < 1:
            return False, "missing phone-home scheduler"

        dhcp_probe_count = await self._run_count(
            "/ip/dhcp-client/find comment=th-wan-probe"
        )
        if dhcp_probe_count < 1:
            return False, "missing WAN DHCP probe clients"

        return True, "ZTP-ready: device-mode, phone-home, schedulers, WAN probes verified"

    async def _run_count(self, routeros_find_command: str) -> int:
        """Run a RouterOS find expression and return the result count."""
        output = await self._run_command(
            f":put [:len [{routeros_find_command}]]", allow_failure=True
        )
        try:
            return int((output or "0").strip())
        except ValueError:
            return 0

    @staticmethod
    def _parse_kv_output(output: str) -> Dict[str, str]:
        """Parse RouterOS print/as-value output into a key/value map."""
        parsed: Dict[str, str] = {}
        if not output:
            return parsed

        for key, value in re.findall(r"([A-Za-z0-9_-]+)=((?:\"[^\"]*\")|(?:\S+))", output):
            parsed[key] = value.strip("\"")

        # Fallback for classic `key: value` output.
        for line in output.splitlines():
            if ":" in line and "=" not in line:
                key, value = line.split(":", 1)
                parsed[key.strip().replace(" ", "-")] = value.strip()

        return parsed
