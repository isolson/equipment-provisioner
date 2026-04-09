"""MikroTik RouterOS device handler."""

import asyncio
import ipaddress
import logging
import re
import socket
from pathlib import Path
from typing import Any, Dict, Optional

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
        """Wait for device to reboot and accept SSH again."""
        logger.info(f"Waiting for {self.ip} to come back online...")
        await asyncio.sleep(3)

        start = asyncio.get_event_loop().time()
        saw_offline = False

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
            except Exception:
                saw_offline = True

            await asyncio.sleep(5)

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

    async def netinstall(
        self,
        firmware_path: str,
        interface: str,
        assign_ip: str = "192.168.88.1",
        on_progress=None,
    ) -> bool:
        """Flash a MikroTik device in BOOTP/Netinstall mode.

        The device must be in Netinstall mode (reset button held during power-on).
        Runs netinstall-cli to flash RouterOS firmware onto the device.

        Args:
            firmware_path: Path to the RouterOS .npk file
            interface: VLAN interface to use (e.g. eth0.1991)
            assign_ip: IP address to assign to the device during install
            on_progress: Optional async callback for progress updates
        """
        if not Path(self.NETINSTALL_CLI).exists():
            logger.error(f"netinstall-cli not found at {self.NETINSTALL_CLI}")
            return False

        if not Path(firmware_path).exists():
            logger.error(f"Firmware file not found: {firmware_path}")
            return False

        cmd = [
            self.NETINSTALL_CLI,
            "-i", interface,
            "-r",  # Reset configuration
            "-a", assign_ip,
            firmware_path,
        ]

        logger.info(f"Starting Netinstall on {interface}: {' '.join(cmd)}")
        if on_progress:
            await on_progress("netinstall", "running", "Waiting for device in BOOTP mode...")

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
:do {{/user/remove [find name=admin]}} on-error={{}}
:do {{/user/remove [find name=fleet-bootstrap]}} on-error={{}}
/user/add name=fleet-bootstrap password="{bp}" group=full

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
:do {{/ip/dhcp-client/remove [find interface=ether1]}} on-error={{}}
/ip/dhcp-client/add interface=ether1 disabled=no add-default-route=yes use-peer-dns=no
/ip/dns/set servers=1.1.1.1,1.0.0.1

# ── Disable WiFi (customer config enables it) ─────────────────────────
:do {{/interface/wifi/set [find] disabled=yes}} on-error={{}}

# ── Phone-home script ─────────────────────────────────────────────────
:do {{/system/script/remove [find name=phone-home]}} on-error={{}}
:do {{/system/scheduler/remove [find name=phone-home-boot]}} on-error={{}}
:do {{/system/scheduler/remove [find name=phone-home-periodic]}} on-error={{}}

/system/script/add name=phone-home dont-require-permissions=yes source={{
:local ztpUrl "{api_url}/ztp/mikrotik"
:local maxWait 120
:local retryDelays {{5; 10; 20; 40; 60}}

:local serial [/system/routerboard/get serial-number]
:local identity [/system/identity/get name]

:local role "gateway"
:if ([:find $identity "fleet-ext-" -1] = 0 || [:find $identity "reset-ext-" -1] = 0) do={{
    :set role "extender"
}}

:local wanIp ""
:local waited 0
:while ($wanIp = "" && $waited < $maxWait) do={{
    :do {{
        :set wanIp [/ip/address/get [find interface=ether1 dynamic=yes] address]
        :set wanIp [:pick $wanIp 0 [:find $wanIp "/"]]
    }} on-error={{
        :set wanIp ""
    }}
    :if ($wanIp = "") do={{
        :delay 5s
        :set waited ($waited + 5)
    }}
}}

:if ($wanIp = "") do={{
    :log warning "ZTP: No WAN IP after $maxWait seconds, aborting"
    :error "No WAN IP"
}}

:local mac [/interface/ethernet/get [find name=ether1] mac-address]

:local upstreamIp ""
:do {{
    :set upstreamIp [/ip/route/get [find dst-address="0.0.0.0/0" active=yes] gateway]
}} on-error={{
    :log warning "ZTP: Could not determine default gateway"
}}

:local configHash ""
:do {{
    :local note [/system/note/get note]
    :if ([:find $note "config_hash=" -1] >= 0) do={{
        :local start ([:find $note "config_hash=" -1] + 12)
        :set configHash [:pick $note $start ($start + 16)]
    }}
}} on-error={{}}

:local hashField ""
:if ($configHash != "") do={{
    :set hashField ",\\"config_hash\\":\\"$configHash\\""
}}

:local jsonBody "{{\\\"serial\\\":\\\"$serial\\\",\\\"mac\\\":\\\"$mac\\\",\\\"wan_ip\\\":\\\"$wanIp\\\",\\\"role\\\":\\\"$role\\\",\\\"upstream_device_ip\\\":\\\"$upstreamIp\\\"$hashField}}"

:local fetchOk false
:local attempt 0
:local responseFile "ztp-response.json"

:foreach delay in=$retryDelays do={{
    :set attempt ($attempt + 1)
    :if (!$fetchOk) do={{
        :do {{
            /tool/fetch url="$ztpUrl/checkin" \\
                http-method=post \\
                http-header-field="Content-Type: application/json" \\
                http-data=$jsonBody \\
                output=file \\
                dst-path=$responseFile
            :set fetchOk true
        }} on-error={{
            :log info "ZTP: Checkin attempt $attempt failed, retrying in ${{delay}}s"
            :delay ($delay . "s")
        }}
    }}
}}

:if (!$fetchOk) do={{
    :log error "ZTP: All checkin attempts failed"
    :error "Checkin failed"
}}

:local responseData [/file/get $responseFile contents]
/file/remove $responseFile

:local parsed [:deserialize from=json $responseData]
:local action ($parsed->"action")
:local configReady ($parsed->"config_ready")
:local configUrl ($parsed->"config_url")

:log info "ZTP: action=$action config_ready=$configReady"

:if ($configReady != true) do={{
    :log info "ZTP: Config not ready ($action), will retry next run"
    :return
}}

:if ([:len $configUrl] = 0) do={{
    :log error "ZTP: config_ready=true but no config_url"
    :error "Missing config_url"
}}

:local fullConfigUrl ""
:if ([:find $configUrl "http" -1] = 0) do={{
    :set fullConfigUrl $configUrl
}} else={{
    :set fullConfigUrl "{api_url}$configUrl"
}}

:local configFile "ztp-config.rsc"

:do {{
    /tool/fetch url=$fullConfigUrl output=file dst-path=$configFile
}} on-error={{
    :log error "ZTP: Config download failed"
    :error "Config download failed"
}}

:log info "ZTP: Importing config..."
:do {{
    /import file-name=$configFile
    :log info "ZTP: Config imported successfully"
}} on-error={{
    :log error "ZTP: Config import failed"
}}

:do {{/file/remove $configFile}} on-error={{}}
:log info "ZTP: Provisioning complete for serial=$serial"
}}

# ── Schedulers ─────────────────────────────────────────────────────────
/system/scheduler/add name=phone-home-boot on-event="/system/script/run phone-home" \\
    start-time=startup interval=0
/system/scheduler/add name=phone-home-periodic on-event="/system/script/run phone-home" \\
    interval=6h

# ── Default configuration (factory-reset recovery) ────────────────────
/system/default-configuration/set script="\\
:local serial [/system/routerboard/get serial-number]\\r\\n\\
:local deviceName \\"reset-{role_abbrev}-\\$serial\\"\\r\\n\\
/system/identity/set name=\\$deviceName\\r\\n\\
:do {{/user/remove [find name=admin]}} on-error={{}}\\r\\n\\
:do {{/user/remove [find name=fleet-bootstrap]}} on-error={{}}\\r\\n\\
/user/add name=fleet-bootstrap password=\\"{bp}\\" group=full\\r\\n\\
/ip/service/set telnet disabled=yes\\r\\n\\
/ip/service/set ftp disabled=yes\\r\\n\\
/ip/service/set www disabled=yes\\r\\n\\
/ip/service/set api disabled=yes\\r\\n\\
/ip/service/set api-ssl disabled=yes\\r\\n\\
/tool/bandwidth-server/set enabled=no\\r\\n\\
:do {{/ip/dhcp-client/remove [find interface=ether1]}} on-error={{}}\\r\\n\\
/ip/dhcp-client/add interface=ether1 disabled=no add-default-route=yes use-peer-dns=no\\r\\n\\
/ip/dns/set servers=1.1.1.1,1.0.0.1\\r\\n\\
:do {{/interface/wifi/set [find] disabled=yes}} on-error={{}}\\r\\n\\
:log warning \\"RESET RECOVERY: Device \\$serial recovered from factory reset. Fetching bootstrap...\\"\\r\\n\\
:delay 30s\\r\\n\\
:do {{\\r\\n\\
    /tool/fetch url=\\"{api_url}/ztp/mikrotik/recovery-bootstrap.rsc\\" dst-path=recovery.rsc\\r\\n\\
    /import file-name=recovery.rsc\\r\\n\\
    /file/remove recovery.rsc\\r\\n\\
}} on-error={{\\r\\n\\
    :log error \\"RESET RECOVERY: Could not fetch bootstrap. Will retry on next boot via scheduler.\\"\\r\\n\\
}}\\r\\n\\
"

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
