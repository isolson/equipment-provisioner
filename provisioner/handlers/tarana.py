"""Tarana Wireless RN (Radio Node) device handler."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import aiohttp

from .base import BaseHandler, DeviceInfo

logger = logging.getLogger(__name__)


class TaranaHandler(BaseHandler):
    """Handler for Tarana Wireless G1 Radio Nodes.

    Uses REST API for device management.
    """

    def __init__(self, ip: str, credentials: Dict[str, str], interface: Optional[str] = None):
        super().__init__(ip, credentials, interface)
        self._session: Optional[aiohttp.ClientSession] = None
        self._auth_token: Optional[str] = None
        self._base_url = f"https://{ip}"

    @property
    def device_type(self) -> str:
        return "tarana"

    @property
    def supports_dual_bank(self) -> bool:
        return True

    async def connect(self) -> bool:
        """Connect to Tarana device via REST API."""
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            self._session = aiohttp.ClientSession(connector=connector)

            # Login to get auth token
            login_url = f"{self._base_url}/api/v1/auth/login"
            payload = {
                "username": self.credentials.get("username", "admin"),
                "password": self.credentials.get("password", ""),
            }

            async with self._session.post(login_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    self._auth_token = data.get("token") or data.get("access_token")
                    self._connected = True
                    logger.info(f"Connected to Tarana at {self.ip}")
                    return True
                else:
                    # Try alternate login endpoint
                    return await self._try_alternate_auth()

        except aiohttp.ClientError as e:
            logger.error(f"Failed to connect to Tarana at {self.ip}: {e}")
            return False

    async def _try_alternate_auth(self) -> bool:
        """Try alternate authentication methods."""
        try:
            # Try basic auth
            auth = aiohttp.BasicAuth(
                self.credentials.get("username", "admin"),
                self.credentials.get("password", "")
            )

            async with self._session.get(
                f"{self._base_url}/api/v1/system",
                auth=auth
            ) as response:
                if response.status == 200:
                    self._connected = True
                    logger.info(f"Connected to Tarana at {self.ip} (basic auth)")
                    return True

        except Exception as e:
            logger.debug(f"Alternate auth failed: {e}")

        return False

    async def disconnect(self) -> None:
        """Disconnect from the device."""
        if self._session and self._auth_token:
            try:
                logout_url = f"{self._base_url}/api/v1/auth/logout"
                await self._session.post(
                    logout_url,
                    headers=self._get_auth_headers()
                )
            except Exception:
                pass

        if self._session:
            await self._session.close()
            self._session = None

        self._auth_token = None
        self._connected = False
        logger.info(f"Disconnected from Tarana at {self.ip}")

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication."""
        headers = {"Content-Type": "application/json"}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return headers

    async def _api_get(self, endpoint: str) -> Dict[str, Any]:
        """Make authenticated GET request."""
        if not self._session:
            raise RuntimeError("Not connected")

        url = f"{self._base_url}{endpoint}"
        async with self._session.get(url, headers=self._get_auth_headers()) as response:
            response.raise_for_status()
            return await response.json()

    async def _api_post(self, endpoint: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make authenticated POST request."""
        if not self._session:
            raise RuntimeError("Not connected")

        url = f"{self._base_url}{endpoint}"
        async with self._session.post(
            url,
            headers=self._get_auth_headers(),
            json=data
        ) as response:
            response.raise_for_status()
            try:
                return await response.json()
            except Exception:
                return {"status": "ok"}

    async def _api_put(self, endpoint: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make authenticated PUT request."""
        if not self._session:
            raise RuntimeError("Not connected")

        url = f"{self._base_url}{endpoint}"
        async with self._session.put(
            url,
            headers=self._get_auth_headers(),
            json=data
        ) as response:
            response.raise_for_status()
            try:
                return await response.json()
            except Exception:
                return {"status": "ok"}

    async def get_info(self) -> DeviceInfo:
        """Get device information from Tarana API."""
        info = DeviceInfo(device_type=self.device_type, ip_address=self.ip)

        try:
            # Get system info
            system_data = await self._api_get("/api/v1/system")

            info.model = system_data.get("model") or system_data.get("product_name") or "G1"
            info.serial_number = system_data.get("serial_number") or system_data.get("serial")
            info.mac_address = system_data.get("mac_address", "").upper()
            info.hostname = system_data.get("hostname") or system_data.get("device_name")
            info.firmware_version = system_data.get("software_version") or system_data.get("firmware")
            info.hardware_version = system_data.get("hardware_version")

            # Get additional status
            try:
                status_data = await self._api_get("/api/v1/status")
                info.uptime = status_data.get("uptime")
                info.extra["link_status"] = status_data.get("link_status")
                info.extra["connected_base"] = status_data.get("connected_base")
                info.extra["signal_quality"] = status_data.get("signal_quality")
            except Exception:
                pass

        except Exception as e:
            logger.error(f"Failed to get device info: {e}")

        self._device_info = info
        return info

    async def backup_config(self) -> bytes:
        """Backup device configuration."""
        if not self._session:
            raise RuntimeError("Not connected")

        try:
            url = f"{self._base_url}/api/v1/config/export"
            async with self._session.get(url, headers=self._get_auth_headers()) as response:
                response.raise_for_status()
                return await response.read()
        except Exception as e:
            logger.error(f"Failed to backup config: {e}")
            raise

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration via API."""
        try:
            await self._api_put("/api/v1/config", config)
            logger.info(f"Configuration applied to {self.ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to apply config: {e}")
            return False

    async def apply_config_file(self, config_path: str) -> bool:
        """Apply configuration from JSON file."""
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                logger.error(f"Config file not found: {config_path}")
                return False

            with open(config_file, "r") as f:
                config = json.load(f)

            return await self.apply_config(config)

        except Exception as e:
            logger.error(f"Failed to apply config file: {e}")
            return False

    async def upload_firmware(self, firmware_path: str) -> bool:
        """Upload firmware to the device."""
        if not self._session:
            raise RuntimeError("Not connected")

        try:
            firmware_file = Path(firmware_path)
            if not firmware_file.exists():
                logger.error(f"Firmware file not found: {firmware_path}")
                return False

            url = f"{self._base_url}/api/v1/firmware/upload"

            with open(firmware_file, "rb") as f:
                data = aiohttp.FormData()
                data.add_field(
                    "file",
                    f,
                    filename=firmware_file.name,
                    content_type="application/octet-stream"
                )

                headers = self._get_auth_headers()
                del headers["Content-Type"]

                async with self._session.post(url, headers=headers, data=data) as response:
                    if response.status in (200, 201, 202):
                        logger.info(f"Firmware uploaded to {self.ip}")
                        return True
                    else:
                        logger.error(f"Firmware upload failed with status {response.status}")
                        return False

        except Exception as e:
            logger.error(f"Failed to upload firmware: {e}")
            return False

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """Trigger firmware update on specified bank."""
        try:
            data = {}
            if bank is not None:
                data["bank"] = bank

            await self._api_post("/api/v1/firmware/upgrade", data)
            logger.info(f"Firmware update initiated on {self.ip}" +
                       (f" (bank {bank})" if bank else ""))
            return True

        except Exception as e:
            logger.error(f"Failed to initiate firmware update: {e}")
            return False

    async def reboot(self) -> bool:
        """Reboot the device."""
        try:
            await self._api_post("/api/v1/system/reboot")
            logger.info(f"Reboot initiated on {self.ip}")
            return True
        except aiohttp.ClientError:
            return True
        except Exception as e:
            logger.error(f"Failed to reboot: {e}")
            return False

    async def get_firmware_version(self) -> str:
        """Get current firmware version."""
        if not self._connected:
            await self.connect()

        info = await self.get_info()
        return info.firmware_version or "unknown"

    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        """Wait for device to come back online after reboot."""
        logger.info(f"Waiting for {self.ip} to come back online...")

        await asyncio.sleep(15)

        start_time = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start_time < timeout:
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(
                        f"{self._base_url}/api/v1/system",
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        if response.status in (200, 302, 401, 403):
                            await asyncio.sleep(10)
                            logger.info(f"{self.ip} is back online")
                            return True
            except Exception:
                pass

            await asyncio.sleep(5)

        logger.error(f"{self.ip} did not come back online within {timeout}s")
        return False

    async def get_link_status(self) -> Dict[str, Any]:
        """Get current link status and signal quality."""
        try:
            return await self._api_get("/api/v1/link/status")
        except Exception as e:
            logger.error(f"Failed to get link status: {e}")
            return {}
