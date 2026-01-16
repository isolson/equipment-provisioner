"""Mikrotik RouterOS device handler."""

import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from .base import BaseHandler, DeviceInfo

logger = logging.getLogger(__name__)


class MikrotikHandler(BaseHandler):
    """Handler for Mikrotik RouterOS devices."""

    def __init__(self, ip: str, credentials: Dict[str, str], interface: Optional[str] = None):
        super().__init__(ip, credentials, interface)
        self._api = None
        self._ssh = None

    @property
    def device_type(self) -> str:
        return "mikrotik"

    @property
    def supports_dual_bank(self) -> bool:
        # RouterOS doesn't use traditional dual-bank, it has package system
        return False

    async def connect(self) -> bool:
        """Connect to Mikrotik device via RouterOS API."""
        try:
            import librouteros
        except ImportError:
            logger.error("librouteros not installed")
            return False

        try:
            # Try API connection
            self._api = librouteros.connect(
                host=self.ip,
                username=self.credentials.get("username", "admin"),
                password=self.credentials.get("password", ""),
                timeout=10.0,
            )
            self._connected = True
            logger.info(f"Connected to Mikrotik at {self.ip}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to Mikrotik at {self.ip}: {e}")
            return False

    async def disconnect(self) -> None:
        """Disconnect from the device."""
        if self._api:
            try:
                self._api.close()
            except Exception:
                pass
            self._api = None

        if self._ssh:
            try:
                self._ssh.close()
            except Exception:
                pass
            self._ssh = None

        self._connected = False
        logger.info(f"Disconnected from Mikrotik at {self.ip}")

    async def get_info(self) -> DeviceInfo:
        """Get device information from RouterOS."""
        if not self._api:
            raise RuntimeError("Not connected")

        info = DeviceInfo(device_type=self.device_type, ip_address=self.ip)

        try:
            # Get system resource info
            resource = list(self._api.path("/system/resource").select())
            if resource:
                r = resource[0]
                info.firmware_version = r.get("version")
                info.model = r.get("board-name")
                info.hardware_version = r.get("architecture-name")
                info.uptime = self._parse_uptime(r.get("uptime", "0s"))
                info.extra["cpu"] = r.get("cpu")
                info.extra["memory_total"] = r.get("total-memory")
                info.extra["memory_free"] = r.get("free-memory")

            # Get system identity
            identity = list(self._api.path("/system/identity").select())
            if identity:
                info.hostname = identity[0].get("name")

            # Get system routerboard info
            try:
                rb = list(self._api.path("/system/routerboard").select())
                if rb:
                    info.serial_number = rb[0].get("serial-number")
                    info.extra["current_firmware"] = rb[0].get("current-firmware")
                    info.extra["upgrade_firmware"] = rb[0].get("upgrade-firmware")
            except Exception:
                pass  # Not all devices have routerboard

            # Get MAC address from first interface
            interfaces = list(self._api.path("/interface/ethernet").select())
            if interfaces:
                info.mac_address = interfaces[0].get("mac-address", "").upper()

        except Exception as e:
            logger.error(f"Failed to get device info: {e}")

        self._device_info = info
        return info

    def _parse_uptime(self, uptime_str: str) -> int:
        """Parse RouterOS uptime string to seconds."""
        # Format: 1w2d3h4m5s
        import re
        total = 0
        patterns = [
            (r"(\d+)w", 604800),  # weeks
            (r"(\d+)d", 86400),   # days
            (r"(\d+)h", 3600),    # hours
            (r"(\d+)m", 60),      # minutes
            (r"(\d+)s", 1),       # seconds
        ]
        for pattern, multiplier in patterns:
            match = re.search(pattern, uptime_str)
            if match:
                total += int(match.group(1)) * multiplier
        return total

    async def backup_config(self) -> bytes:
        """Export RouterOS configuration."""
        if not self._api:
            raise RuntimeError("Not connected")

        try:
            # Create export via SSH since API doesn't support direct export
            config = await self._run_command("/export")
            return config.encode("utf-8")
        except Exception as e:
            logger.error(f"Failed to backup config: {e}")
            raise

    async def _run_command(self, command: str) -> str:
        """Run a command via SSH and return output."""
        import asyncssh

        if not self._ssh:
            self._ssh = await asyncssh.connect(
                self.ip,
                username=self.credentials.get("username", "admin"),
                password=self.credentials.get("password", ""),
                known_hosts=None,
            )

        result = await self._ssh.run(command)
        return result.stdout

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration via API."""
        if not self._api:
            raise RuntimeError("Not connected")

        try:
            # Configuration is applied as individual commands
            for section, items in config.items():
                path = self._api.path(section)

                if isinstance(items, list):
                    for item in items:
                        if "_action" in item:
                            action = item.pop("_action")
                            if action == "add":
                                path.add(**item)
                            elif action == "set":
                                path.update(**item)
                            elif action == "remove":
                                # Find and remove
                                pass
                        else:
                            path.add(**item)
                elif isinstance(items, dict):
                    path.update(**items)

            logger.info(f"Configuration applied to {self.ip}")
            return True

        except Exception as e:
            logger.error(f"Failed to apply config: {e}")
            return False

    async def apply_config_file(self, config_path: str) -> bool:
        """Apply configuration from .rsc file."""
        if not self._api:
            raise RuntimeError("Not connected")

        try:
            # Read the .rsc file
            config_file = Path(config_path)
            if not config_file.exists():
                logger.error(f"Config file not found: {config_path}")
                return False

            # Upload and run via SSH
            import asyncssh

            if not self._ssh:
                self._ssh = await asyncssh.connect(
                    self.ip,
                    username=self.credentials.get("username", "admin"),
                    password=self.credentials.get("password", ""),
                    known_hosts=None,
                )

            # Upload file
            async with self._ssh.start_sftp_client() as sftp:
                await sftp.put(config_path, "/flash/provision-config.rsc")

            # Import the config
            result = await self._ssh.run("/import file-name=provision-config.rsc")

            if result.returncode == 0:
                logger.info(f"Config file applied to {self.ip}")
                return True
            else:
                logger.error(f"Config import failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Failed to apply config file: {e}")
            return False

    async def upload_firmware(self, firmware_path: str) -> bool:
        """Upload firmware package to the device."""
        try:
            import asyncssh

            firmware_file = Path(firmware_path)
            if not firmware_file.exists():
                logger.error(f"Firmware file not found: {firmware_path}")
                return False

            if not self._ssh:
                self._ssh = await asyncssh.connect(
                    self.ip,
                    username=self.credentials.get("username", "admin"),
                    password=self.credentials.get("password", ""),
                    known_hosts=None,
                )

            # Upload to device
            async with self._ssh.start_sftp_client() as sftp:
                remote_path = f"/flash/{firmware_file.name}"
                await sftp.put(firmware_path, remote_path)

            logger.info(f"Firmware uploaded to {self.ip}")
            return True

        except Exception as e:
            logger.error(f"Failed to upload firmware: {e}")
            return False

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """Schedule firmware update (happens on reboot)."""
        # RouterOS updates happen automatically on reboot when package is present
        # Check for routerboard firmware upgrade
        if self._api:
            try:
                rb = list(self._api.path("/system/routerboard").select())
                if rb:
                    current = rb[0].get("current-firmware")
                    upgrade = rb[0].get("upgrade-firmware")
                    if upgrade and current != upgrade:
                        # Upgrade routerboard firmware
                        self._api.path("/system/routerboard").call("upgrade")
                        logger.info(f"Routerboard firmware upgrade scheduled on {self.ip}")
            except Exception as e:
                logger.debug(f"Routerboard upgrade check failed: {e}")

        return True

    async def reboot(self) -> bool:
        """Reboot the device."""
        if not self._api:
            raise RuntimeError("Not connected")

        try:
            # Schedule reboot
            self._api.path("/system").call("reboot")
            logger.info(f"Reboot initiated on {self.ip}")
            return True
        except Exception as e:
            # Connection may drop immediately
            if "connection" in str(e).lower():
                return True
            logger.error(f"Failed to reboot: {e}")
            return False

    async def get_firmware_version(self) -> str:
        """Get current firmware version."""
        if not self._api:
            await self.connect()

        resource = list(self._api.path("/system/resource").select())
        if resource:
            return resource[0].get("version", "unknown")
        return "unknown"

    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        """Wait for device to come back online after reboot."""
        import socket

        logger.info(f"Waiting for {self.ip} to come back online...")

        # First wait for device to go down
        await asyncio.sleep(10)

        # Then wait for it to come back
        start_time = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start_time < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((self.ip, 8728))
                sock.close()

                if result == 0:
                    # Port is open, wait a bit more for services to stabilize
                    await asyncio.sleep(10)
                    logger.info(f"{self.ip} is back online")
                    return True

            except Exception:
                pass

            await asyncio.sleep(5)

        logger.error(f"{self.ip} did not come back online within {timeout}s")
        return False
