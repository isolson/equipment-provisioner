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

from .base import BaseHandler, DeviceInfo

logger = logging.getLogger(__name__)


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
            "-r",
            "-c",  # allow concurrent netinstall servers across ports
        ]

        userscript_path: Optional[str] = None
        if bootstrap_password:
            escaped = bootstrap_password.replace("\\", "\\\\").replace('"', '\\"')
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

        addr_added = await self._add_netinstall_addr(interface, host_addr)

        try:
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
            if userscript_path:
                try:
                    os.unlink(userscript_path)
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
    # ZTP base-flash script generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_base_flash_script(
        serial: str,
        role: str = "gateway",
        bootstrap_pass: str = "",
        ztp_api_url: str = "https://api.infra.treehouse.mn",
    ) -> str:
        """Generate a parameterized base-flash.rsc for MikroTik ZTP.

        This script sets up the device for zero-touch field deployment:
        - Sets system identity to fleet-{role}-{serial}
        - Creates fleet-bootstrap user with shared password
        - Disables unnecessary services
        - Enables DHCP on ether1 (WAN)
        - Embeds phone-home script that contacts the ZTP API
        - Sets up schedulers for boot + periodic phone-home
        - Stores factory-reset recovery in NVRAM
        """
        role_abbrev = "ext" if role == "extender" else "gw"
        device_name = f"fleet-{role_abbrev}-{serial}"

        # Escape for RouterOS string embedding
        bp = bootstrap_pass.replace("\\", "\\\\").replace('"', '\\"')
        api_url = ztp_api_url.rstrip("/")

        return f"""\
# MikroTik ZTP Base Flash — generated by network-provisioner
# Device: {device_name} | Serial: {serial} | Role: {role}

# ── System identity ────────────────────────────────────────────────────
/system/identity/set name={device_name}

# ── Bootstrap user ─────────────────────────────────────────────────────
# fleet-bootstrap was already created by netinstall's -s user-script with the
# same password, and we're currently logged in as fleet-bootstrap (so we can't
# remove ourselves). Just ensure the password is current and that any leftover
# 'admin' (e.g. from a re-import on a previously-configured device) is gone.
:do {{/user/remove [find name=admin]}} on-error={{}}
/user/set [find name=fleet-bootstrap] password="{bp}" group=full

# ── Disable unnecessary services ───────────────────────────────────────
/ip/service/set telnet disabled=yes
/ip/service/set ftp disabled=yes
/ip/service/set www disabled=yes
/ip/service/set api disabled=yes
/ip/service/set api-ssl disabled=yes
/tool/bandwidth-server/set enabled=no
/ip/service/set ssh disabled=no
/ip/service/set winbox disabled=no

# ── Network: DHCP client on ether1 (WAN) ──────────────────────────────
# Note: ether1 is currently a slave of bridge-bootstrap (set up by netinstall
# -s). Adding a DHCP client here will succeed at command level even if DHCP
# doesn't get a lease while ether1 is bridged; the eventual customer config
# (delivered via phone-home) is responsible for converting to the real
# WAN/LAN topology and tearing down bridge-bootstrap. Tearing it down here
# would kill our own SSH session mid-import.
:do {{/ip/dhcp-client/remove [find interface=ether1]}} on-error={{}}
/ip/dhcp-client/add interface=ether1 disabled=no add-default-route=yes use-peer-dns=no
/ip/dns/set servers=1.1.1.1,1.0.0.1

# ── Disable WiFi (customer config enables it) ─────────────────────────
:do {{/interface/wifi/set [find] disabled=yes}} on-error={{}}

# Note: Phone-home script + schedulers + /tool/fetch are gated by RouterOS 7.x
# device-mode (default `home` mode blocks scheduler, fetch, and
# dont-require-permissions scripts). They are intentionally omitted here.
# Until device-mode is set to `advanced` (which currently requires physical
# reset-button confirmation, or RouterOS 7.22+ netinstall -sm flag), the
# provisioner will manage post-base-flash steps over SSH using
# fleet-bootstrap credentials rather than relying on device-side phone-home.
#
# Note: /system/default-configuration/set (factory-reset recovery hook) was a
# RouterOS 6 feature and is not available in 7.x. If a device is hard-reset in
# the field, it falls back to the RouterOS factory default-config and will
# need a fresh netinstall to re-join the fleet.


:log info "ZTP: Base flash complete. Identity={device_name}, role={role}, serial={serial}"
:log info "ZTP: Device ready for field deployment."
"""

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
