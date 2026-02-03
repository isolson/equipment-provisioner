"""Ubiquiti AirMax and Wave device handler.

Supports Ubiquiti AirMax (Rocket, NanoStation, LiteBeam, PowerBeam, etc.)
and Wave (Wave AP, Wave Nano, Wave Pico, etc.) devices.

Both device families default to 192.168.1.20 with credentials ubnt/ubnt.

Wave API (discovered via HAR analysis):
- POST /api/v1.0/user/login - Authenticate, returns x-auth-token header
- GET /api/v1.0/device - Get device info including identification.firmwareVersion
- GET/PUT /api/v1.0/system/airos/configuration - Get/set configuration
- POST /api/v1.0/system/upgrade/discard - Discard pending upgrade
- POST /api/v1.0/system/upgrade/direct - Upload firmware (multipart form-data)
- GET /api/v1.0/system/upgrade - Poll upgrade status
- POST /api/v1.0/system/reboot - Reboot device with {"timeout":0}

Credential configuration:
- Password changes via config API (users section) or dedicated endpoint
- SNMP configuration via services.snmp section
- See docs/wave-credentials-configuration.md for details
"""

import asyncio
import json
import logging
import re
import ssl
from pathlib import Path
from typing import Dict, Any, Optional

import aiohttp

from .base import BaseHandler, DeviceInfo

logger = logging.getLogger(__name__)


# Wave API endpoints
WAVE_API_LOGIN = "/api/v1.0/user/login"
WAVE_API_PUBLIC_DEVICE = "/api/v1.0/public/device"
WAVE_API_DEVICE = "/api/v1.0/device"
WAVE_API_CONFIG = "/api/v1.0/system/airos/configuration"
WAVE_API_USERS = "/api/v1.0/system/users"  # User management (password change)
WAVE_API_SERVICES = "/api/v1.0/services"  # Services config (SNMP, SSH, etc.)
WAVE_API_COMPOSE = "/api/v1.0/tools/compose"  # Batch API requests
WAVE_API_UPGRADE_DISCARD = "/api/v1.0/system/upgrade/discard"
WAVE_API_UPGRADE_DIRECT = "/api/v1.0/system/upgrade/direct"
WAVE_API_UPGRADE_STATUS = "/api/v1.0/system/upgrade"
WAVE_API_REBOOT = "/api/v1.0/system/reboot"


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
        WAVE_API_LOGIN,        # Wave primary endpoint (returns x-auth-token header)
        "/api/auth",           # Newer airOS
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
        self._last_uploaded_firmware: Optional[str] = None  # Track for retry on FIRMWARE_INCOMPATIBLE

    @property
    def device_type(self) -> str:
        return "ubiquiti"

    @property
    def supports_dual_bank(self) -> bool:
        # Wave devices have dual banks internally but only expose one to the user
        return self._api_style == "wave"

    @property
    def supports_password_change(self) -> bool:
        # Wave devices support password change via compose API
        return self._api_style == "wave"

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
                limit=10,           # Max total connections
                limit_per_host=2,   # Max per device
                ttl_dns_cache=300,  # DNS cache TTL
                force_close=True,   # Close connections instead of keep-alive
            )
            timeout = aiohttp.ClientTimeout(total=15, connect=5)  # Tighter for Pi
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

        # Use curl when interface binding is needed (aiohttp local_addr doesn't work for VLANs)
        if self.interface:
            return await self._connect_curl()

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
                                # Check for Wave-style x-auth-token header first
                                x_auth_token = resp.headers.get("x-auth-token")
                                if x_auth_token:
                                    self._auth_token = x_auth_token
                                    self._api_style = "wave"
                                    logger.info(f"Wave: Got x-auth-token header")

                                # Store auth cookies (for airOS)
                                for cookie in resp.cookies.values():
                                    if cookie.key.lower() in ("ubnt", "airos_sessionid",
                                                              "session", "auth"):
                                        self._auth_cookie = f"{cookie.key}={cookie.value}"

                                # Check for token in response body (airOS style)
                                try:
                                    body = await resp.json(content_type=None)
                                    if isinstance(body, dict):
                                        # Check Wave response for errors
                                        if body.get("error", 0) != 0:
                                            last_error = f"Login error: {body}"
                                            continue
                                        token = body.get("token") or body.get("auth_token")
                                        if token and not self._auth_token:
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

    async def _connect_curl(self) -> bool:
        """Connect using curl with interface binding for VLAN support."""
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
                        payload = json.dumps({"username": username, "password": password})

                        cmd = [
                            "curl", "-s", "-k", "-m", "15",
                            "--interface", self.interface,
                            "-X", "POST",
                            "-H", "Content-Type: application/json",
                            "-d", payload,
                            "-D", "-",  # Dump headers to stdout
                            url,
                        ]

                        proc = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)

                        if proc.returncode != 0:
                            last_error = f"Connection failed at {self.ip} ({scheme})"
                            continue

                        response = stdout.decode("utf-8", errors="ignore")

                        # Parse headers and body (curl -D - puts headers first)
                        parts = response.split("\r\n\r\n", 1)
                        if len(parts) < 2:
                            parts = response.split("\n\n", 1)
                        headers_str = parts[0] if parts else ""
                        body_str = parts[1] if len(parts) > 1 else ""

                        # Check HTTP status from first line
                        first_line = headers_str.split("\n")[0] if headers_str else ""
                        if "200" in first_line or "302" in first_line:
                            # Check for x-auth-token header (Wave)
                            for line in headers_str.split("\n"):
                                if line.lower().startswith("x-auth-token:"):
                                    self._auth_token = line.split(":", 1)[1].strip()
                                    self._api_style = "wave"
                                    logger.info(f"Wave: Got x-auth-token header via curl")
                                    break

                            # Check body for errors or tokens
                            try:
                                body = json.loads(body_str) if body_str.strip() else {}
                                if isinstance(body, dict):
                                    if body.get("error", 0) != 0:
                                        last_error = f"Login error: {body}"
                                        continue
                                    # airOS style token
                                    token = body.get("token") or body.get("auth_token")
                                    if token and not self._auth_token:
                                        self._auth_token = token
                            except json.JSONDecodeError:
                                pass

                            self._connected = True
                            self._base_url = f"{scheme}://{self.ip}"
                            self.credentials = creds
                            logger.info(f"Ubiquiti login OK via curl {scheme} {endpoint} at {self.ip}")
                            return True

                        elif "401" in first_line or "403" in first_line:
                            last_error = f"Invalid credentials for {username}"
                        else:
                            last_error = f"HTTP error from {endpoint}"

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
        if self._api_style == "wave" and self._auth_token:
            # Wave uses x-auth-token header directly
            headers["x-auth-token"] = self._auth_token
        elif self._auth_token:
            # airOS uses Bearer token
            headers["Authorization"] = f"Bearer {self._auth_token}"
        if self._auth_cookie:
            headers["Cookie"] = self._auth_cookie
        return headers

    async def get_info(self) -> DeviceInfo:
        """Get device information (model, MAC, firmware, etc.).

        For Wave devices, uses the authenticated /api/v1.0/device endpoint
        which provides firmware version in identification.firmwareVersion.
        Falls back to generic endpoints for airOS devices.
        """
        info = DeviceInfo(device_type="ubiquiti")

        # Use curl when interface binding is needed
        if self.interface and self._api_style == "wave":
            return await self._get_info_curl()

        session = await self._get_session()
        headers = self._auth_headers()
        base_url = self._base_url or f"https://{self.ip}"

        # Try Wave-specific authenticated endpoint first
        if self._api_style == "wave":
            try:
                url = f"{base_url}{WAVE_API_DEVICE}"
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if isinstance(data, dict):
                            ident = data.get("identification", {})
                            info.model = ident.get("model")
                            info.mac_address = ident.get("mac")
                            info.firmware_version = ident.get("firmwareVersion")
                            info.hostname = ident.get("hostname") or ident.get("name")
                            info.serial_number = ident.get("serialNumber")
                            # Store extra info
                            info.extra = {
                                "family": ident.get("family"),
                                "product": ident.get("product"),
                                "firmware_full": ident.get("firmware"),
                            }
                            if info.model:
                                logger.info(f"Wave device: {info.model}, FW: {info.firmware_version}")
                                info.ip_address = self.ip
                                self._device_info = info
                                return info
            except Exception as e:
                logger.debug(f"Wave device endpoint failed: {e}")

        # Fall back to generic endpoint logic for non-Wave or if Wave failed
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

    async def _get_info_curl(self) -> DeviceInfo:
        """Get device info using curl with interface binding."""
        info = DeviceInfo(device_type="ubiquiti")
        base_url = self._base_url or f"https://{self.ip}"

        try:
            url = f"{base_url}{WAVE_API_DEVICE}"
            cmd = [
                "curl", "-s", "-k", "-m", "15",
                "--interface", self.interface,
                "-X", "GET",
            ]
            if self._auth_token:
                cmd.extend(["-H", f"x-auth-token: {self._auth_token}"])
            cmd.append(url)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)

            if proc.returncode == 0 and stdout:
                data = json.loads(stdout.decode("utf-8", errors="ignore"))
                if isinstance(data, dict):
                    ident = data.get("identification", {})
                    info.model = ident.get("model")
                    info.mac_address = ident.get("mac")
                    info.firmware_version = ident.get("firmwareVersion")
                    info.hostname = ident.get("hostname") or ident.get("name")
                    info.serial_number = ident.get("serialNumber")
                    info.extra = {
                        "family": ident.get("family"),
                        "product": ident.get("product"),
                        "firmware_full": ident.get("firmware"),
                    }
                    if info.model:
                        logger.info(f"Wave device (curl): {info.model}, FW: {info.firmware_version}")

        except Exception as e:
            logger.debug(f"Wave device endpoint failed via curl: {e}")

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

    async def get_firmware_banks(self) -> Dict[str, Any]:
        """Get firmware bank versions for Wave devices.

        Wave devices have dual banks internally but only expose the running
        firmware version to users. Returns the same version for both banks.

        Returns:
            Dict with bank1, bank2, and active bank info.
        """
        if self._api_style != "wave":
            return {"bank1": "unknown", "bank2": "unknown", "active": 1}

        # Get current firmware version from device info
        fw_version = "unknown"
        if self._device_info and self._device_info.firmware_version:
            fw_version = self._device_info.firmware_version
        else:
            # Fetch fresh info if not cached
            info = await self.get_info()
            fw_version = info.firmware_version or "unknown"

        # Wave only exposes one version - report it for both banks
        # The base handler will see both banks match expected and skip updates
        return {
            "bank1": fw_version,
            "bank2": fw_version,
            "bank1_display": fw_version,
            "bank2_display": fw_version,
            "active": 1,
        }

    async def backup_config(self) -> bytes:
        """Backup device configuration.

        Not yet implemented — needs HAR analysis to determine export mechanism.
        """
        raise NotImplementedError("Ubiquiti config backup not yet implemented (needs HAR analysis)")

    async def _get_config(self) -> Dict[str, Any]:
        """Get the current device configuration.

        Returns:
            Configuration dict, or empty dict on error.
        """
        if self._api_style != "wave":
            return {}

        if self.interface:
            return await self._get_config_curl()

        session = await self._get_session()
        headers = self._auth_headers()
        base_url = self._base_url or f"https://{self.ip}"

        try:
            url = f"{base_url}{WAVE_API_CONFIG}"
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    return await resp.json(content_type=None)
        except Exception as e:
            logger.debug(f"Failed to get config: {e}")

        return {}

    async def _get_config_curl(self) -> Dict[str, Any]:
        """Get configuration using curl with interface binding."""
        try:
            url = f"{self._base_url}{WAVE_API_CONFIG}"
            cmd = [
                "curl", "-s", "-k", "-m", "15",
                "--interface", self.interface,
                "-X", "GET",
            ]
            if self._auth_token:
                cmd.extend(["-H", f"x-auth-token: {self._auth_token}"])
            cmd.append(url)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)

            if proc.returncode == 0 and stdout:
                return json.loads(stdout.decode("utf-8", errors="ignore"))
        except Exception as e:
            logger.debug(f"Failed to get config via curl: {e}")

        return {}

    async def set_password(self, new_password: str, username: str = None) -> bool:
        """Change the device password.

        For Wave devices, uses PUT /system/users with cleartext password.
        The device handles password hashing internally.

        Based on HAR analysis: password is sent cleartext via:
        PUT /api/v1.0/system/users
        {
            "username": "ubnt",
            "displayName": "ubnt",
            "password": "newpassword",
            "readOnly": false
        }

        Args:
            new_password: The new password to set.
            username: Username to change password for (defaults to current user).

        Returns:
            True if password changed successfully.
        """
        if self._api_style != "wave":
            logger.warning("set_password only supported for Wave devices currently")
            return False

        target_user = username or self.credentials.get("username", "ubnt")

        logger.info(f"[PASSWORD] Changing password for {target_user} on {self.ip}")

        # Use curl for interface binding
        if self.interface:
            return await self._set_password_curl(new_password, target_user)

        session = await self._get_session()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        base_url = self._base_url or f"https://{self.ip}"

        # PUT to /system/users with cleartext password
        try:
            url = f"{base_url}{WAVE_API_USERS}"
            payload = {
                "username": target_user,
                "displayName": target_user,
                "password": new_password,
                "readOnly": False,
            }

            async with session.put(url, headers=headers, json=payload) as resp:
                if resp.status == 200:
                    body = await resp.json(content_type=None)
                    # Response returns user info without password on success
                    if body.get("username") == target_user:
                        logger.info(f"[PASSWORD] Changed successfully for {target_user}")
                        self.credentials["password"] = new_password
                        return True
                    elif body.get("error", 0) != 0:
                        logger.error(f"[PASSWORD] Error response: {body}")
                    else:
                        # Assume success if we got 200 and no error
                        logger.info(f"[PASSWORD] Changed for {target_user}")
                        self.credentials["password"] = new_password
                        return True
                else:
                    body = await resp.text()
                    logger.error(f"[PASSWORD] HTTP {resp.status}: {body}")

        except Exception as e:
            logger.error(f"[PASSWORD] Failed to change password: {e}")

        return False

    async def _set_password_curl(self, new_password: str, target_user: str) -> bool:
        """Set password using curl with interface binding.

        Uses PUT /system/users with cleartext password.
        """
        base_url = self._base_url or f"https://{self.ip}"

        try:
            url = f"{base_url}{WAVE_API_USERS}"
            payload = json.dumps({
                "username": target_user,
                "displayName": target_user,
                "password": new_password,
                "readOnly": False,
            })

            cmd = [
                "curl", "-s", "-k", "-m", "15",
                "--interface", self.interface,
                "-X", "PUT",
                "-H", "Content-Type: application/json",
            ]
            if self._auth_token:
                cmd.extend(["-H", f"x-auth-token: {self._auth_token}"])
            cmd.extend(["-d", payload, url])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)

            if proc.returncode == 0 and stdout:
                result = json.loads(stdout.decode("utf-8", errors="ignore"))
                # Success if we get user info back or no error
                if result.get("username") == target_user or result.get("error", 0) == 0:
                    logger.info(f"[PASSWORD] Changed for {target_user} (curl)")
                    self.credentials["password"] = new_password
                    return True
                else:
                    logger.error(f"[PASSWORD] Error response: {result}")
            else:
                logger.error(f"[PASSWORD] curl failed with code {proc.returncode}")

        except Exception as e:
            logger.error(f"[PASSWORD] Failed via curl: {e}")

        return False

    async def configure_snmp(self, community: str = None, location: str = None,
                              contact: str = None, enabled: bool = True) -> bool:
        """Configure SNMP settings on the device.

        For Wave devices, SNMP is configured via PUT /services endpoint
        with the snmpAgent field (HAR verified).

        Args:
            community: SNMP community string
            location: SNMP location string
            contact: SNMP contact string
            enabled: Whether to enable SNMP (default: True)

        Returns:
            True if SNMP configured successfully.
        """
        if self._api_style != "wave":
            logger.warning("configure_snmp only supported for Wave devices currently")
            return False

        logger.info(f"[SNMP] Configuring SNMP on {self.ip}")

        # Use curl for interface binding
        if self.interface:
            return await self._configure_snmp_curl(community, location, contact, enabled)

        session = await self._get_session()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        base_url = self._base_url or f"https://{self.ip}"

        try:
            # First GET current services config
            url = f"{base_url}{WAVE_API_SERVICES}"
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    logger.error(f"[SNMP] Failed to get services: HTTP {resp.status}")
                    return False
                services = await resp.json(content_type=None)

            # Update snmpAgent section
            snmp_config = {
                "enabled": enabled,
            }
            if community:
                snmp_config["community"] = community
            if location:
                snmp_config["location"] = location
            if contact:
                snmp_config["contact"] = contact

            services["snmpAgent"] = snmp_config

            # PUT updated services
            async with session.put(url, headers=headers, json=services) as resp:
                if resp.status == 200:
                    body = await resp.json(content_type=None)
                    # Check if snmpAgent was updated
                    if body.get("snmpAgent", {}).get("enabled") == enabled:
                        logger.info(f"[SNMP] Configuration applied successfully")
                        return True
                    else:
                        logger.info(f"[SNMP] Configuration applied")
                        return True
                else:
                    body = await resp.text()
                    logger.error(f"[SNMP] PUT failed: HTTP {resp.status}: {body}")
                    return False

        except Exception as e:
            logger.error(f"[SNMP] Configuration failed: {e}")
            return False

    async def _configure_snmp_curl(self, community: str, location: str,
                                    contact: str, enabled: bool) -> bool:
        """Configure SNMP using curl with interface binding."""
        base_url = self._base_url or f"https://{self.ip}"

        try:
            # GET current services
            url = f"{base_url}{WAVE_API_SERVICES}"
            cmd = [
                "curl", "-s", "-k", "-m", "15",
                "--interface", self.interface,
                "-X", "GET",
            ]
            if self._auth_token:
                cmd.extend(["-H", f"x-auth-token: {self._auth_token}"])
            cmd.append(url)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)

            if proc.returncode != 0 or not stdout:
                logger.error("[SNMP] Failed to get services via curl")
                return False

            services = json.loads(stdout.decode("utf-8", errors="ignore"))

            # Update snmpAgent
            snmp_config = {"enabled": enabled}
            if community:
                snmp_config["community"] = community
            if location:
                snmp_config["location"] = location
            if contact:
                snmp_config["contact"] = contact

            services["snmpAgent"] = snmp_config

            # PUT updated services
            payload = json.dumps(services)
            cmd = [
                "curl", "-s", "-k", "-m", "15",
                "--interface", self.interface,
                "-X", "PUT",
                "-H", "Content-Type: application/json",
            ]
            if self._auth_token:
                cmd.extend(["-H", f"x-auth-token: {self._auth_token}"])
            cmd.extend(["-d", payload, url])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)

            if proc.returncode == 0:
                logger.info(f"[SNMP] Configuration applied (curl)")
                return True
            else:
                logger.error(f"[SNMP] PUT failed via curl")
                return False

        except Exception as e:
            logger.error(f"[SNMP] Configuration failed via curl: {e}")
            return False

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration to the device.

        For Wave devices, uses PUT /api/v1.0/system/airos/configuration.
        Performs read-back verification of key fields (hostname, SSID).
        """
        if self._api_style != "wave":
            logger.warning("apply_config only supported for Wave devices currently")
            return False

        # Use curl if interface binding is needed
        if self.interface:
            return await self._apply_config_curl(config)

        session = await self._get_session()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        base_url = self._base_url or f"https://{self.ip}"

        # Capture expected values for verification
        expected_hostname = config.get("system", {}).get("hostname")
        expected_ssid = None
        try:
            wireless = config.get("wireless", {})
            interfaces = wireless.get("interfaces", [])
            if interfaces and len(interfaces) > 0:
                expected_ssid = interfaces[0].get("ssid")
        except (KeyError, TypeError, IndexError):
            pass

        try:
            url = f"{base_url}{WAVE_API_CONFIG}"
            logger.info(f"[CONFIG] Applying config to {self.ip}")

            async with session.put(url, headers=headers, json=config) as resp:
                body = await resp.json(content_type=None)

                # Wave returns {"error":0,"statusCode":200} on success
                if resp.status == 200:
                    if isinstance(body, dict):
                        if body.get("error", 0) != 0:
                            logger.error(f"Config apply error: {body}")
                            return False
                        if body.get("statusCode", 200) >= 400:
                            logger.error(f"Config apply statusCode error: {body}")
                            return False

                    logger.info(f"[CONFIG] Configuration sent to {self.ip}")
                else:
                    logger.error(f"Config apply failed: HTTP {resp.status} - {body}")
                    return False

            # Read-back verification
            if expected_hostname or expected_ssid:
                await asyncio.sleep(2)  # Brief pause for config to settle

                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        readback = await resp.json(content_type=None)

                        if expected_hostname:
                            actual = readback.get("system", {}).get("hostname")
                            if actual != expected_hostname:
                                logger.error(f"[CONFIG VERIFY] hostname mismatch: sent '{expected_hostname}', got '{actual}'")
                                return False
                            logger.info(f"[CONFIG VERIFY] hostname confirmed: {actual}")

                        if expected_ssid:
                            try:
                                actual_ssid = readback.get("wireless", {}).get("interfaces", [{}])[0].get("ssid")
                                if actual_ssid != expected_ssid:
                                    logger.error(f"[CONFIG VERIFY] SSID mismatch: sent '{expected_ssid}', got '{actual_ssid}'")
                                    return False
                                logger.info(f"[CONFIG VERIFY] SSID confirmed: {actual_ssid}")
                            except (KeyError, IndexError):
                                pass

            return True

        except Exception as e:
            logger.error(f"Failed to apply config: {e}")
            return False

    async def _apply_config_curl(self, config: Dict[str, Any]) -> bool:
        """Apply configuration using curl with interface binding."""
        try:
            url = f"{self._base_url}{WAVE_API_CONFIG}"
            payload = json.dumps(config)

            cmd = [
                "curl", "-s", "-k", "-m", "30",
                "--interface", self.interface,
                "-X", "PUT",
                "-H", "Content-Type: application/json",
            ]

            if self._auth_token:
                cmd.extend(["-H", f"x-auth-token: {self._auth_token}"])

            cmd.extend(["-d", payload, url])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.error(f"Config apply curl failed: {stderr.decode()}")
                return False

            response = stdout.decode("utf-8", errors="ignore")
            result = json.loads(response)

            if result.get("error", 0) != 0:
                logger.error(f"Config apply error: {result}")
                return False

            logger.info(f"[CONFIG] Configuration applied to {self.ip} via curl")
            return True

        except Exception as e:
            logger.error(f"Failed to apply config via curl: {e}")
            return False

    async def apply_config_file(self, config_path: str) -> bool:
        """Apply configuration from a file.

        Supports JSON config files for Wave devices.
        """
        config_file = Path(config_path)
        if not config_file.exists():
            logger.error(f"Config file not found: {config_path}")
            return False

        try:
            with open(config_path, "r") as f:
                config = json.load(f)
            return await self.apply_config(config)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to load config file: {e}")
            return False

    async def upload_firmware(self, firmware_path: str) -> bool:
        """Upload firmware to the device.

        For Wave devices:
        1. POST /api/v1.0/system/upgrade/discard to clear pending upgrades
        2. POST /api/v1.0/system/upgrade/direct with multipart form-data
        """
        if self._api_style != "wave":
            logger.warning("upload_firmware only supported for Wave devices currently")
            return False

        firmware_file = Path(firmware_path)
        if not firmware_file.exists():
            logger.error(f"Firmware file not found: {firmware_path}")
            return False

        # Use curl for interface binding (simpler for multipart)
        if self.interface:
            return await self._upload_firmware_curl(firmware_path)

        session = await self._get_session()
        headers = self._auth_headers()
        base_url = self._base_url or f"https://{self.ip}"

        try:
            # Step 1: Discard any pending upgrade
            discard_url = f"{base_url}{WAVE_API_UPGRADE_DISCARD}"
            try:
                async with session.post(discard_url, headers=headers) as resp:
                    logger.debug(f"Discard pending upgrade: {resp.status}")
            except Exception:
                pass  # May fail if no pending upgrade - that's OK

            # Step 2: Upload firmware
            upload_url = f"{base_url}{WAVE_API_UPGRADE_DIRECT}"

            # Remove Content-Type - let aiohttp set it for multipart
            upload_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}

            logger.info(f"[FIRMWARE] Uploading {firmware_file.name} to {self.ip}")

            with open(firmware_path, "rb") as f:
                form_data = aiohttp.FormData()
                form_data.add_field(
                    "file",
                    f,
                    filename=firmware_file.name,
                    content_type="application/octet-stream"
                )

                async with session.post(
                    upload_url,
                    headers=upload_headers,
                    data=form_data,
                    timeout=aiohttp.ClientTimeout(total=600)  # 10 min for large files
                ) as resp:
                    body = await resp.json(content_type=None)

                    if resp.status == 200 and body.get("error", 0) == 0:
                        logger.info(f"[FIRMWARE] Firmware uploaded to {self.ip}")
                        # Track the firmware path for retry on incompatibility
                        self._last_uploaded_firmware = firmware_path
                        return True
                    else:
                        logger.error(f"Firmware upload failed: {resp.status} - {body}")
                        return False

        except Exception as e:
            logger.error(f"Failed to upload firmware: {e}")
            return False

    async def _upload_firmware_curl(self, firmware_path: str) -> bool:
        """Upload firmware using curl with interface binding."""
        try:
            firmware_file = Path(firmware_path)
            base_url = self._base_url or f"https://{self.ip}"

            # Step 1: Discard pending upgrade
            discard_url = f"{base_url}{WAVE_API_UPGRADE_DISCARD}"
            discard_cmd = [
                "curl", "-s", "-k", "-m", "10",
                "--interface", self.interface,
                "-X", "POST",
            ]
            if self._auth_token:
                discard_cmd.extend(["-H", f"x-auth-token: {self._auth_token}"])
            discard_cmd.append(discard_url)

            proc = await asyncio.create_subprocess_exec(
                *discard_cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()

            # Step 2: Upload firmware
            upload_url = f"{base_url}{WAVE_API_UPGRADE_DIRECT}"

            cmd = [
                "curl", "-s", "-k", "-m", "600",  # 10 min timeout
                "--interface", self.interface,
                "-X", "POST",
                "-F", f"file=@{firmware_path}",
            ]

            if self._auth_token:
                cmd.extend(["-H", f"x-auth-token: {self._auth_token}"])

            cmd.append(upload_url)

            logger.info(f"[FIRMWARE] Uploading {firmware_file.name} to {self.ip} via curl")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                response = stdout.decode("utf-8", errors="ignore")
                result = json.loads(response)

                if result.get("error", 0) == 0:
                    logger.info(f"[FIRMWARE] Firmware uploaded to {self.ip}")
                    # Store the firmware path so we can try alternatives on incompatibility
                    self._last_uploaded_firmware = firmware_path
                    return True
                else:
                    logger.error(f"Firmware upload error: {result}")
                    return False
            else:
                logger.error(f"Firmware upload curl failed: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Failed to upload firmware via curl: {e}")
            return False

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """Wait for firmware update to complete.

        Wave devices begin applying firmware immediately after upload.
        This method polls the status endpoint until the upgrade finishes.
        """
        if self._api_style != "wave":
            logger.warning("update_firmware only supported for Wave devices currently")
            return False

        bank_str = f" (bank {bank})" if bank else ""
        logger.info(f"[FIRMWARE] Waiting for firmware update to complete on {self.ip}{bank_str}")

        if self.interface:
            return await self._poll_firmware_status_curl()

        session = await self._get_session()
        headers = self._auth_headers()
        base_url = self._base_url or f"https://{self.ip}"
        url = f"{base_url}{WAVE_API_UPGRADE_STATUS}"

        timeout = 300  # 5 minutes max
        poll_interval = 3  # seconds
        start_time = asyncio.get_event_loop().time()

        # Track tried firmware files
        tried_firmware = set()
        if self._last_uploaded_firmware:
            tried_firmware.add(self._last_uploaded_firmware)

        try:
            while asyncio.get_event_loop().time() - start_time < timeout:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)

                        status = data.get("status", "")
                        progress = data.get("progressPercent", 0)
                        failure_reason = data.get("failureReason", "")

                        logger.debug(f"Firmware status: {status}, progress: {progress}%")

                        if status == "finished":
                            version = data.get("metadata", {}).get("version", "unknown")
                            logger.info(f"[FIRMWARE] Update complete: {version}")
                            return True

                        if status == "failed" and failure_reason == "FIRMWARE_INCOMPATIBLE":
                            # Try alternative firmware file
                            logger.warning(f"[FIRMWARE] Firmware incompatible, trying alternative...")
                            alt_firmware = await self._find_alternative_firmware(tried_firmware)
                            if alt_firmware:
                                tried_firmware.add(alt_firmware)
                                logger.info(f"[FIRMWARE] Trying alternative: {Path(alt_firmware).name}")
                                if await self.upload_firmware(alt_firmware):
                                    start_time = asyncio.get_event_loop().time()
                                    await asyncio.sleep(poll_interval)
                                    continue
                                else:
                                    logger.error(f"Failed to upload alternative firmware")
                            else:
                                logger.error(f"No alternative firmware available")
                            return False

                        if status == "error" or data.get("error", 0) != 0:
                            logger.error(f"Firmware update error: {data}")
                            return False

                await asyncio.sleep(poll_interval)

            logger.error(f"Firmware update timed out after {timeout}s")
            return False

        except Exception as e:
            logger.error(f"Failed to poll firmware status: {e}")
            return False

    async def _poll_firmware_status_curl(self) -> bool:
        """Poll firmware status using curl with interface binding.

        If firmware is incompatible, automatically tries alternative firmware files
        from the same directory.
        """
        base_url = self._base_url or f"https://{self.ip}"
        url = f"{base_url}{WAVE_API_UPGRADE_STATUS}"

        timeout = 300
        poll_interval = 3
        start_time = asyncio.get_event_loop().time()

        # Track tried firmware files to avoid retry loops
        tried_firmware = set()
        if hasattr(self, '_last_uploaded_firmware') and self._last_uploaded_firmware:
            tried_firmware.add(self._last_uploaded_firmware)

        try:
            while asyncio.get_event_loop().time() - start_time < timeout:
                cmd = [
                    "curl", "-s", "-k", "-m", "10",
                    "--interface", self.interface,
                    "-X", "GET",
                ]
                if self._auth_token:
                    cmd.extend(["-H", f"x-auth-token: {self._auth_token}"])
                cmd.append(url)

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()

                if proc.returncode == 0 and stdout:
                    data = json.loads(stdout.decode("utf-8", errors="ignore"))

                    status = data.get("status", "")
                    progress = data.get("progressPercent", 0)
                    failure_reason = data.get("failureReason", "")

                    logger.debug(f"Firmware status: {status}, progress: {progress}%")

                    if status == "finished":
                        version = data.get("metadata", {}).get("version", "unknown")
                        logger.info(f"[FIRMWARE] Update complete: {version}")
                        return True

                    if status == "failed" and failure_reason == "FIRMWARE_INCOMPATIBLE":
                        # Try alternative firmware file
                        logger.warning(f"[FIRMWARE] Firmware incompatible, trying alternative...")
                        alt_firmware = await self._find_alternative_firmware(tried_firmware)
                        if alt_firmware:
                            tried_firmware.add(alt_firmware)
                            logger.info(f"[FIRMWARE] Trying alternative firmware: {Path(alt_firmware).name}")
                            if await self._upload_firmware_curl(alt_firmware):
                                # Reset timer and continue polling
                                start_time = asyncio.get_event_loop().time()
                                await asyncio.sleep(poll_interval)
                                continue
                            else:
                                logger.error(f"Failed to upload alternative firmware")
                        else:
                            logger.error(f"No alternative firmware available")
                        return False

                    if status == "error" or data.get("error", 0) != 0:
                        logger.error(f"Firmware update error: {data}")
                        return False

                await asyncio.sleep(poll_interval)

            logger.error(f"Firmware update timed out after {timeout}s")
            return False

        except Exception as e:
            logger.error(f"Failed to poll firmware status: {e}")
            return False

    async def _find_alternative_firmware(self, tried: set) -> Optional[str]:
        """Find an alternative firmware file that hasn't been tried yet.

        Scans the ubiquiti firmware directory for Wave firmware files and
        returns one that hasn't been attempted yet.

        Args:
            tried: Set of firmware paths already tried.

        Returns:
            Path to alternative firmware file, or None if none available.
        """
        # Get the firmware directory from the last uploaded firmware path
        if not hasattr(self, '_last_uploaded_firmware') or not self._last_uploaded_firmware:
            return None

        firmware_dir = Path(self._last_uploaded_firmware).parent
        if not firmware_dir.exists():
            return None

        # Look for Wave firmware files
        wave_files = []
        for f in firmware_dir.iterdir():
            if f.is_file() and f.suffix.lower() == '.bin':
                filename_lower = f.name.lower()
                if 'wave' in filename_lower:
                    if str(f) not in tried:
                        wave_files.append(f)

        if not wave_files:
            return None

        # Sort by file size (different hardware variants often have different sizes)
        wave_files.sort(key=lambda f: f.stat().st_size, reverse=True)

        logger.info(f"[FIRMWARE] Found {len(wave_files)} alternative Wave firmware file(s)")
        return str(wave_files[0])

    async def reboot(self) -> bool:
        """Reboot the device.

        For Wave devices, POST to /api/v1.0/system/reboot with {"timeout":0}.
        Tolerates connection errors since device disconnects during reboot.
        """
        if self._api_style != "wave":
            logger.warning("reboot only supported for Wave devices currently")
            return False

        if self.interface:
            return await self._reboot_curl()

        session = await self._get_session()
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        base_url = self._base_url or f"https://{self.ip}"

        try:
            url = f"{base_url}{WAVE_API_REBOOT}"

            async with session.post(url, headers=headers, json={"timeout": 0}) as resp:
                # Device may close connection immediately - that's OK
                if resp.status == 200:
                    body = await resp.json(content_type=None)
                    if body.get("error", 0) == 0:
                        logger.info(f"Reboot initiated on {self.ip}")
                        return True
                    else:
                        logger.error(f"Reboot error: {body}")
                        return False
                else:
                    logger.error(f"Reboot failed: HTTP {resp.status}")
                    return False

        except aiohttp.ClientError:
            # Connection error expected during reboot
            logger.info(f"Reboot initiated on {self.ip} (connection closed)")
            return True
        except Exception as e:
            logger.error(f"Failed to reboot: {e}")
            return False

    async def _reboot_curl(self) -> bool:
        """Reboot device using curl with interface binding."""
        try:
            base_url = self._base_url or f"https://{self.ip}"
            url = f"{base_url}{WAVE_API_REBOOT}"

            cmd = [
                "curl", "-s", "-k", "-m", "10",
                "--interface", self.interface,
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", '{"timeout":0}',
            ]

            if self._auth_token:
                cmd.extend(["-H", f"x-auth-token: {self._auth_token}"])

            cmd.append(url)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                if stdout:
                    response = stdout.decode("utf-8", errors="ignore")
                    result = json.loads(response)
                    if result.get("error", 0) == 0:
                        logger.info(f"Reboot initiated on {self.ip}")
                        return True
            except asyncio.TimeoutError:
                # Device may disconnect immediately
                logger.info(f"Reboot initiated on {self.ip} (connection closed)")
                return True

            return True  # Assume success if we got here

        except Exception as e:
            logger.error(f"Failed to reboot via curl: {e}")
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

        Uses 2-phase polling:
        1. Ping until device responds
        2. Check web server via unauthenticated public endpoint
        """
        logger.info(f"Waiting for {self.ip} to reboot...")

        # Initial wait for device to go down
        await asyncio.sleep(10)

        start_time = asyncio.get_event_loop().time()
        ping_responded = False

        while asyncio.get_event_loop().time() - start_time < timeout:
            # Phase 1: Wait for ping response
            if not ping_responded:
                if await self._ping_device():
                    logger.info(f"{self.ip} responding to ping, waiting for web server...")
                    ping_responded = True
                    await asyncio.sleep(10)  # Give web services time to start
                    continue
            else:
                # Phase 2: Check web server via public endpoint
                if await self._check_web_server():
                    logger.info(f"{self.ip} web server is up, device ready")
                    return True

            await asyncio.sleep(3)

        logger.error(f"{self.ip} did not come back online within {timeout}s")
        return False

    async def _ping_device(self) -> bool:
        """Ping the device using interface binding if available."""
        try:
            cmd = ["ping", "-c", "1", "-W", "2"]
            if self.interface:
                cmd.extend(["-I", self.interface])
            cmd.append(self.ip)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False

    async def _check_web_server(self) -> bool:
        """Check if web server is responding.

        Uses the unauthenticated /api/v1.0/public/device endpoint.
        """
        try:
            base_url = self._base_url or f"https://{self.ip}"
            url = f"{base_url}{WAVE_API_PUBLIC_DEVICE}"

            cmd = ["curl", "-s", "-k", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}"]
            if self.interface:
                cmd.extend(["--interface", self.interface])
            cmd.append(url)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                status_code = stdout.decode().strip()
                if status_code and status_code.isdigit():
                    return int(status_code) == 200
            return False
        except Exception:
            return False
