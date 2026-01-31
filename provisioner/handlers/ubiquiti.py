"""Ubiquiti AirMax and Wave device handler.

Supports Ubiquiti AirMax (Rocket, NanoStation, LiteBeam, PowerBeam, etc.)
and Wave (Wave AP, Wave Nano, Wave Pico, etc.) devices.

Both device families default to 192.168.1.20 with credentials ubnt/ubnt.
Ubiquiti devices use a web UI with no documented JSON API, so the full
config/firmware implementation requires HAR capture analysis.

Phase 1: Detection, login, and device info gathering.
Phase 2+: Config application, firmware upload (pending HAR analysis).
"""

import asyncio
import logging
import re
import ssl
from typing import Dict, Any, Optional

import aiohttp

from .base import BaseHandler, DeviceInfo

logger = logging.getLogger(__name__)


class UbiquitiHandler(BaseHandler):
    """Handler for Ubiquiti AirMax and Wave devices.

    Both AirMax (airOS) and Wave products are handled here.
    If HAR analysis reveals fundamentally different APIs, this can be
    split into separate handlers later.
    """

    DEFAULT_IP = "192.168.1.20"
    LOCAL_BIND_IP = "192.168.1.2"  # Pi's IP on the same /24 as the device
    DEFAULT_CREDENTIALS = {"username": "ubnt", "password": "ubnt"}

    # Known login endpoints to try (varies by firmware/product line)
    LOGIN_ENDPOINTS = [
        "/api/auth",           # Newer airOS / Wave
        "/login.cgi",          # Classic airOS
        "/api/auth/login",     # Some Wave firmware
    ]

    # Info endpoints to try
    INFO_ENDPOINTS = [
        "/status.cgi",         # Classic airOS
        "/api/v1/status",      # Newer airOS
        "/api/status",         # Wave
        "/api/v1/system",      # Some firmware versions
    ]

    # Try both HTTP and HTTPS — older airOS is HTTP-only
    SCHEMES = ["https", "http"]

    def __init__(self, ip: str, credentials: Dict[str, str],
                 interface: Optional[str] = None,
                 alternate_credentials: list = None):
        super().__init__(ip, credentials, interface)
        self._alternate_credentials = alternate_credentials or []
        self._session: Optional[aiohttp.ClientSession] = None
        self._base_url: Optional[str] = None  # Set during connect (http or https)
        self._auth_cookie: Optional[str] = None
        self._auth_token: Optional[str] = None
        self._api_style: Optional[str] = None  # "airos" or "wave" once detected
        self.login_error: Optional[str] = None

    @property
    def device_type(self) -> str:
        return "ubiquiti"

    @property
    def supports_dual_bank(self) -> bool:
        # TBD — needs HAR analysis to confirm
        return False

    @property
    def supports_password_change(self) -> bool:
        # TBD — needs HAR analysis
        return False

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create permissive SSL context for self-signed device certs."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session bound to the VLAN interface."""
        if self._session is None or self._session.closed:
            # Bind to local IP on the same /24 as the device so traffic
            # routes correctly through the isolated VLAN interface.
            local_addr = None
            if self.interface:
                local_addr = (self.LOCAL_BIND_IP, 0)
                logger.info(f"Ubiquiti: binding to {self.LOCAL_BIND_IP} for {self.interface}")

            connector = aiohttp.TCPConnector(
                ssl=self._create_ssl_context(),
                local_addr=local_addr,
            )
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            )
        return self._session

    async def connect(self) -> bool:
        """Connect and authenticate to the Ubiquiti device.

        Tries both HTTP and HTTPS, and multiple login endpoints,
        since airOS and Wave use different APIs and protocols.
        """
        self.login_error = None
        session = await self._get_session()

        # Build credential list: configured first, then defaults, then alternates
        creds_to_try = []
        if self.credentials.get("password"):
            creds_to_try.append(self.credentials)
        creds_to_try.append(self.DEFAULT_CREDENTIALS)
        for alt in self._alternate_credentials:
            if alt not in creds_to_try:
                creds_to_try.append(alt)

        last_error = None
        for creds in creds_to_try:
            username = creds.get("username", "ubnt")
            password = creds.get("password", "ubnt")

            for scheme in self.SCHEMES:
                for endpoint in self.LOGIN_ENDPOINTS:
                    try:
                        url = f"{scheme}://{self.ip}{endpoint}"
                        payload = {"username": username, "password": password}

                        async with session.post(url, json=payload,
                                                allow_redirects=False) as resp:
                            if resp.status in (200, 302):
                                # Store auth cookies
                                for cookie in resp.cookies.values():
                                    if cookie.key.lower() in ("ubnt", "airos_sessionid",
                                                              "session", "auth"):
                                        self._auth_cookie = f"{cookie.key}={cookie.value}"

                                # Check for token in response body
                                try:
                                    body = await resp.json(content_type=None)
                                    if isinstance(body, dict):
                                        token = body.get("token") or body.get("auth_token")
                                        if token:
                                            self._auth_token = token
                                except Exception:
                                    pass

                                self._connected = True
                                self._base_url = f"{scheme}://{self.ip}"
                                self.credentials = creds  # Remember working creds
                                logger.info(f"Ubiquiti login OK via {scheme} {endpoint} at {self.ip}")
                                return True

                            elif resp.status in (401, 403):
                                last_error = f"Invalid credentials for {username}"
                            else:
                                last_error = f"HTTP {resp.status} from {endpoint}"

                    except aiohttp.ClientConnectorError:
                        last_error = f"Connection refused at {self.ip} ({scheme})"
                    except asyncio.TimeoutError:
                        last_error = f"Connection timeout at {self.ip} ({scheme})"
                    except Exception as e:
                        last_error = f"Login error: {e}"

        self.login_error = last_error or "Failed to authenticate"
        logger.warning(f"Ubiquiti login failed at {self.ip}: {self.login_error}")
        return False

    async def disconnect(self) -> None:
        """Close the session."""
        if self._session and not self._session.closed:
            try:
                await self._session.close()
            except Exception:
                pass
        self._session = None
        self._connected = False
        self._auth_cookie = None
        self._auth_token = None

    def _auth_headers(self) -> Dict[str, str]:
        """Build auth headers for requests."""
        headers = {}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        if self._auth_cookie:
            headers["Cookie"] = self._auth_cookie
        return headers

    async def get_info(self) -> DeviceInfo:
        """Get device information (model, MAC, firmware, etc.).

        Tries multiple status/info endpoints to extract device details.
        """
        session = await self._get_session()
        headers = self._auth_headers()
        base_url = self._base_url or f"https://{self.ip}"

        info = DeviceInfo(device_type="ubiquiti")

        for endpoint in self.INFO_ENDPOINTS:
            try:
                url = f"{base_url}{endpoint}"
                async with session.get(url, headers=headers) as resp:
                    if resp.status != 200:
                        continue

                    content_type = resp.headers.get("Content-Type", "")

                    if "json" in content_type:
                        data = await resp.json(content_type=None)
                        info = self._parse_json_info(data, info)
                        if info.model:
                            break
                    else:
                        text = await resp.text()
                        info = self._parse_html_info(text, info)
                        if info.model:
                            break

            except Exception as e:
                logger.debug(f"Info endpoint {endpoint} failed: {e}")

        info.ip_address = self.ip
        self._device_info = info
        return info

    def _parse_json_info(self, data: dict, info: DeviceInfo) -> DeviceInfo:
        """Extract device info from JSON response."""
        if not isinstance(data, dict):
            return info

        # Flatten nested structures (airOS nests under "host", Wave under "device")
        flat = {}
        for key, val in data.items():
            if isinstance(val, dict):
                for k, v in val.items():
                    flat[k.lower()] = v
            else:
                flat[key.lower()] = val

        info.model = (flat.get("devmodel") or flat.get("device_model")
                       or flat.get("model") or flat.get("board")
                       or info.model)
        info.firmware_version = (flat.get("fwversion") or flat.get("firmware")
                                  or flat.get("version") or info.firmware_version)
        info.mac_address = (flat.get("mac") or flat.get("hwaddr")
                             or flat.get("mac_address") or info.mac_address)
        info.hostname = (flat.get("hostname") or flat.get("device_name")
                          or info.hostname)
        info.serial_number = flat.get("serial") or info.serial_number
        info.hardware_version = flat.get("hwversion") or info.hardware_version

        return info

    def _parse_html_info(self, html: str, info: DeviceInfo) -> DeviceInfo:
        """Extract device info from HTML/CGI response."""
        # Common patterns in airOS status pages
        patterns = {
            "model": [r'"devmodel"\s*:\s*"([^"]+)"', r'DeviceModel["\s:]+([^"<,]+)'],
            "firmware": [r'"fwversion"\s*:\s*"([^"]+)"', r'FirmwareVersion["\s:]+([^"<,]+)'],
            "mac": [r'"hwaddr"\s*:\s*"([0-9A-Fa-f:]{17})"', r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})'],
            "hostname": [r'"hostname"\s*:\s*"([^"]+)"'],
        }

        for field, pats in patterns.items():
            for pat in pats:
                m = re.search(pat, html)
                if m:
                    val = m.group(1).strip()
                    if field == "model" and not info.model:
                        info.model = val
                    elif field == "firmware" and not info.firmware_version:
                        info.firmware_version = val
                    elif field == "mac" and not info.mac_address:
                        info.mac_address = val
                    elif field == "hostname" and not info.hostname:
                        info.hostname = val
                    break

        return info

    async def backup_config(self) -> bytes:
        """Backup device configuration.

        Not yet implemented — needs HAR analysis to determine export mechanism.
        """
        raise NotImplementedError("Ubiquiti config backup not yet implemented (needs HAR analysis)")

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration to the device.

        Not yet implemented — needs HAR analysis to determine config API.
        """
        logger.warning("Ubiquiti apply_config not yet implemented (needs HAR analysis)")
        return False

    async def apply_config_file(self, config_path: str) -> bool:
        """Apply configuration from a file.

        Not yet implemented — needs HAR analysis.
        """
        logger.warning("Ubiquiti apply_config_file not yet implemented (needs HAR analysis)")
        return False

    async def upload_firmware(self, firmware_path: str) -> bool:
        """Upload firmware to the device.

        Not yet implemented — needs HAR analysis to determine upload mechanism.
        """
        logger.warning("Ubiquiti upload_firmware not yet implemented (needs HAR analysis)")
        return False

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """Trigger firmware update.

        Not yet implemented — needs HAR analysis.
        """
        logger.warning("Ubiquiti update_firmware not yet implemented (needs HAR analysis)")
        return False

    async def reboot(self) -> bool:
        """Reboot the device.

        Not yet implemented — needs HAR analysis.
        """
        logger.warning("Ubiquiti reboot not yet implemented (needs HAR analysis)")
        return False

    async def get_firmware_version(self) -> str:
        """Get the current firmware version."""
        if self._device_info and self._device_info.firmware_version:
            return self._device_info.firmware_version

        try:
            info = await self.get_info()
            return info.firmware_version or "unknown"
        except Exception:
            return "unknown"

    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        """Wait for device to come back online after reboot.

        Not yet implemented — needs HAR analysis.
        """
        logger.warning("Ubiquiti wait_for_reboot not yet implemented (needs HAR analysis)")
        return False
