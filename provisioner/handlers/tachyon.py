"""Tachyon Networks 30x series device handler.

API Endpoints (discovered via browser inspection):
- POST /cgi.lua/login - Authenticate, returns {"level":0,"token":"...","auth":true}
- GET /cgi.lua/config - Get device configuration
- POST /cgi.lua/config - Update device configuration
- GET /cgi.lua/status?type=system - Get system info
- GET /cgi.lua/bootbank - Get firmware bank info {"backup":{...},"active":{...}}
- GET /cgi.lua/firmwares - Get available firmware versions
- PUT /cgi.lua/update - Upload firmware (multipart form-data: fw=binary, force=false)
                        Returns {"version":"unknown"}
- POST /cgi.lua/update - Trigger firmware install (JSON: {reset:false, force:false})
                         Device reboots after this call
- POST /cgi.lua/reboot - Reboot the device
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import aiohttp

from provisioner.config_templates import ConfigTemplateError, load_config_template

from .base import BaseHandler, DeviceInfo, UNVERIFIED

logger = logging.getLogger(__name__)


class TachyonHandler(BaseHandler):
    """Handler for Tachyon Networks 301, 302, 303L, and 30x series devices.

    Uses the official REST API for device management.
    Default credentials: root/admin
    Default IP: 169.254.1.1
    """

    # API endpoints
    API_LOGIN = "/cgi.lua/login"
    API_CONFIG = "/cgi.lua/config"
    API_STATUS = "/cgi.lua/status"
    API_BOOTBANK = "/cgi.lua/bootbank"
    API_FIRMWARES = "/cgi.lua/firmwares"
    API_UPDATE = "/cgi.lua/update"
    API_REBOOT = "/cgi.lua/reboot"

    # Default credentials (factory default)
    DEFAULT_CREDENTIALS = {"username": "root", "password": "admin"}

    def __init__(self, ip: str, credentials: Dict[str, str], interface: Optional[str] = None,
                 alternate_credentials: list = None):
        super().__init__(ip, credentials, interface)
        self._session: Optional[aiohttp.ClientSession] = None
        self._api_token: Optional[str] = None
        self._cookies: Dict[str, str] = {}
        self._base_url = f"https://{ip}"  # Tachyon devices use HTTPS
        self._use_curl = False  # Set True when using curl for interface binding
        self.login_error: Optional[str] = None  # Stores login failure reason
        self._credentials_confirmed: bool = False  # True after successful login (for reconnect)
        # Store alternate credentials for fallback
        self._alternate_credentials = alternate_credentials or []
        # Last config dict passed to apply_config — verify_config reads it back
        # and confirms key fields actually landed on the device.
        self._last_applied_config: Optional[Dict[str, Any]] = None

    @property
    def device_type(self) -> str:
        return "tachyon"

    @property
    def supports_dual_bank(self) -> bool:
        return True

    @property
    def supports_password_change(self) -> bool:
        return True

    @property
    def update_triggers_reboot(self) -> bool:
        """Tachyon devices reboot automatically after POST /update."""
        return True

    @property
    def config_after_all_firmware(self) -> bool:
        """TNS switches change management VLAN/DHCP, making device unreachable."""
        model = getattr(self._device_info, 'model', '') or ''
        return model.lower().startswith('tns-')

    # Firmware pattern mappings for model validation
    MODEL_FIRMWARE_PATTERNS = {
        # TNA-30x standard 60 GHz series uses tna-30x firmware
        "tna-301": ["tna-30x", "tna30x"],
        "tna-302": ["tna-30x", "tna30x"],
        "tna-303x": ["tna-30x", "tna30x"],
        # TNA-303L series uses tna-303l firmware
        "tna-303l": ["tna-303l", "tna303l"],
        "tna-303l-65": ["tna-303l", "tna303l"],
        "tna-303l-lib": ["tna-303l", "tna303l"],
        # TNA-305 series uses tna-305 firmware
        "tna-305a": ["tna-305", "tna305"],
        "tna-305x": ["tna-305", "tna305"],
        # TNS-100 series uses tns-100 firmware
        "tns-100": ["tns-100", "tns100"],
    }

    def validate_firmware_for_model(self, firmware_path: str, model: str) -> tuple[bool, str]:
        """Validate that firmware file is compatible with the Tachyon model.

        Args:
            firmware_path: Path to firmware file.
            model: Device model string (e.g., "TNA-303L-65").

        Returns:
            Tuple of (is_valid, error_message). error_message is empty if valid.
        """
        import os
        filename = os.path.basename(firmware_path).lower()
        model_key = model.lower()

        # Look up expected patterns for this model
        patterns = self.MODEL_FIRMWARE_PATTERNS.get(model_key)
        if not patterns:
            # No specific pattern known - allow any tachyon firmware
            logger.debug(f"No firmware pattern defined for model {model}, allowing any firmware")
            return True, ""

        # Check if firmware matches any expected pattern
        for pattern in patterns:
            if pattern in filename:
                logger.debug(f"Firmware {filename} matches pattern {pattern} for model {model}")
                return True, ""

        # Mismatch - provide helpful error
        expected = " or ".join(patterns)
        return False, f"Firmware mismatch: model {model} requires firmware with '{expected}' in filename, but got '{filename}'"

    async def connect(self) -> bool:
        """Connect to Tachyon device via REST API.

        Tries credentials in order (max 2 attempts to avoid lockout):
        1. If reconnecting after successful login, try confirmed creds first
        2. Default credentials (root/admin)
        3. Single tagged Tachyon credential from UI (if configured)
        4. If all fail, returns False with credential error to prompt UI for manual entry

        Sets self.login_error with details if login fails.
        """
        self.login_error = None
        logger.info(f"[CREDS] ========== TACHYON CONNECT START for {self.ip} ==========")

        # Get single custom credential from UI (tagged for Tachyon)
        custom_cred = self._get_custom_credential()
        logger.info(f"[CREDS] Tagged Tachyon credential loaded: {custom_cred is not None}")

        # Build credential list (max 2 to avoid lockout)
        creds_to_try = []

        # If we've already connected successfully, try those credentials first (reconnect after reboot)
        if self._credentials_confirmed:
            logger.info(f"[CREDS] Reconnect mode - using previously confirmed credentials first")
            creds_to_try.append(self.credentials.copy())
            creds_to_try.append(self.DEFAULT_CREDENTIALS.copy())
        else:
            # Fresh device - try default first, then tagged credential
            # 1. Always try default credentials first (root/admin)
            creds_to_try.append(self.DEFAULT_CREDENTIALS.copy())
            logger.info(f"[CREDS] Added default credentials (root/admin)")

            # 2. Add tagged Tachyon credential from UI if different from default
            if custom_cred and custom_cred.get("password") != self.DEFAULT_CREDENTIALS["password"]:
                creds_to_try.append(custom_cred)
                logger.info(f"[CREDS] Added tagged Tachyon credential from UI")

        logger.info(f"[CREDS] Will try {len(creds_to_try)} credential set(s)")

        # Track if device responded (vs connection failure)
        any_creds_rejected = False

        # Try each credential set
        for i, creds in enumerate(creds_to_try):
            username = creds.get("username", "root")
            password = creds.get("password", "")
            logger.info(f"[CREDS] Attempt {i+1}/{len(creds_to_try)}: Trying {username}/{'*' * len(password) if password else '(empty)'}")

            self.credentials = creds.copy()
            self.login_error = None
            self._cookies = {}
            self._api_token = None

            if self.interface:
                success = await self._connect_curl()
            else:
                success = await self._connect_aiohttp()

            if success:
                self._credentials_confirmed = True
                logger.info(f"[CREDS] SUCCESS! Logged in with {username}")
                logger.info(f"[CREDS] ========== TACHYON CONNECT END (success) ==========")
                return True

            # Check if device responded (credential rejection vs connection failure)
            if self.login_error and "credentials" in self.login_error.lower():
                any_creds_rejected = True

            # If not a credential error (e.g., connection failure), don't try more
            if self.login_error and "credentials" not in self.login_error.lower():
                logger.warning(f"[CREDS] Non-credential error, stopping: {self.login_error}")
                logger.info(f"[CREDS] ========== TACHYON CONNECT END (connection error) ==========")
                return False

        # All credentials failed - set error message to prompt for manual entry
        if any_creds_rejected:
            self.login_error = "Invalid credentials - please enter correct password"
            logger.error(f"[CREDS] FAILED for {self.ip} - credentials rejected, prompting for manual entry")
        else:
            self.login_error = "Device not responding - check network connectivity"
            logger.error(f"[CREDS] FAILED for {self.ip} - device did not respond")
        logger.info(f"[CREDS] ========== TACHYON CONNECT END (failed) ==========")
        return False

    def _update_credentials_from_config(self, config: Dict[str, Any]) -> None:
        """Extract password from config and update self.credentials.

        Tachyon config stores user credentials at system.users[N].password.
        If the config being applied changes the password, we must update our
        stored credentials so that verify_config() can reconnect after the
        config-triggered reboot.
        """
        try:
            users = config.get("system", {}).get("users", [])
            if not users:
                return

            # Find the user matching our current username (usually "root" at index 0 or 1)
            current_user = self.credentials.get("username", "root")
            new_password = None

            for user in users:
                if isinstance(user, dict) and user.get("name") == current_user:
                    new_password = user.get("password")
                    break

            # Fallback: if no name match, use the first user with a password
            if new_password is None:
                for user in users:
                    if isinstance(user, dict) and "password" in user:
                        new_password = user["password"]
                        break

            if new_password and new_password != self.credentials.get("password"):
                # Skip hashed passwords — config files store hashes like "$1$..." or "$6$..."
                # which can't be used for login. Only update if it looks like plaintext.
                if new_password.startswith("$") or len(new_password) > 30:
                    logger.info(f"[CONFIG] Config contains hashed password ({len(new_password)} chars) — keeping current credentials")
                else:
                    logger.info(f"[CONFIG] Config changes device password — updating credentials for reconnect")
                    self.credentials["password"] = new_password
        except Exception as e:
            logger.warning(f"[CONFIG] Could not extract password from config: {e}")

    def _get_custom_credential(self) -> Optional[Dict[str, str]]:
        """Get custom credential for Tachyon devices from credentials.json.

        Always reads fresh from file to pick up UI changes without restart.
        """
        try:
            # Always read fresh from credentials file (not cached)
            settings_paths = [
                Path("/var/lib/provisioner/repo/credentials.json"),
                Path("/var/lib/provisioner/credentials.json"),
                Path("/opt/provisioner/credentials.json"),
                Path.home() / ".provisioner" / "credentials.json",
            ]

            for path in settings_paths:
                if path.exists():
                    with open(path) as f:
                        data = json.load(f)
                        tachyon_creds = data.get("tachyon")

                        if isinstance(tachyon_creds, dict):
                            logger.info(f"Loaded custom Tachyon credential from {path}")
                            return tachyon_creds
                        elif isinstance(tachyon_creds, list) and len(tachyon_creds) > 0:
                            logger.info(f"Loaded Tachyon credential from {path}: {tachyon_creds[0].get('username', 'unknown')}")
                            return tachyon_creds[0]

        except Exception as e:
            logger.warning(f"Error loading custom credentials: {e}")

        return None

    async def _connect_aiohttp(self) -> bool:
        """Connect using aiohttp (no interface binding)."""
        self.login_error = None  # Reset on each attempt

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )

            # Authenticate via API
            login_url = f"{self._base_url}{self.API_LOGIN}"
            payload = {
                "username": self.credentials.get("username", "root"),
                "password": self.credentials.get("password", "admin"),
            }

            async with self._session.post(
                login_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status == 200:
                    # Parse response to check for errors
                    try:
                        data = await response.json()
                        # Check for error in JSON response (200 status but login failed)
                        if data.get("statusCode") == 401 or "Authorization Failed" in str(data):
                            self.login_error = "Invalid credentials - wrong username or password"
                            logger.warning(f"Tachyon login failed: {self.login_error}")
                            return False
                    except Exception:
                        pass

                    # Save cookies for auth - token comes from Set-Cookie, not JSON body
                    self._cookies = {c.key: c.value for c in response.cookies.values()}
                    self._api_token = self._cookies.get("token")

                    if not self._api_token:
                        logger.warning("No token cookie received from login")

                    self._connected = True
                    logger.info(f"Connected to Tachyon at {self.ip}")
                    return True
                elif response.status == 401:
                    self.login_error = "Invalid credentials - wrong username or password"
                    logger.warning(f"Tachyon login failed: {self.login_error}")
                    return False
                else:
                    text = await response.text()
                    self.login_error = f"Login failed ({response.status}): {text[:100]}"
                    logger.error(f"Login failed ({response.status}): {text}")
                    return False

        except aiohttp.ClientError as e:
            self.login_error = f"Connection error: {e}"
            logger.error(f"Failed to connect to Tachyon at {self.ip}: {e}")
            return False

    async def _connect_curl(self) -> bool:
        """Connect to Tachyon device using curl with interface binding."""
        import tempfile

        self.login_error = None  # Reset on each attempt
        try:
            login_url = f"{self._base_url}{self.API_LOGIN}"
            payload = json.dumps({
                "username": self.credentials.get("username", "root"),
                "password": self.credentials.get("password", "admin"),
            })

            # Create temp file for cookie jar (cleaner than parsing stdout mix)
            cookie_fd = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
            cookie_file = cookie_fd.name
            cookie_fd.close()

            try:
                # Use curl with interface binding and cookie jar file
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-k", "-m", "10",  # -k for self-signed certs
                    "--interface", self.interface,
                    "-X", "POST",
                    "-H", "Content-Type: application/json",
                    "-c", cookie_file,  # Save cookies to file
                    "-d", payload,
                    login_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode == 0:
                    response = stdout.decode("utf-8", errors="ignore")
                    logger.info(f"Tachyon login response length: {len(response)}")

                    # Parse JSON response to check for errors
                    json_data = None
                    try:
                        json_data = json.loads(response)
                        logger.debug(f"Parsed login JSON keys: {list(json_data.keys()) if isinstance(json_data, dict) else type(json_data).__name__}")
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse login JSON: {e}")

                    # Check for authentication failure in response
                    if json_data:
                        if json_data.get("statusCode") == 401 or "Authorization Failed" in str(json_data):
                            self.login_error = "Invalid credentials - wrong username or password"
                            logger.warning(f"Tachyon login failed: {self.login_error}")
                            return False
                        if json_data.get("auth") is False:
                            self.login_error = "Invalid credentials - wrong username or password"
                            logger.warning(f"Tachyon login failed: auth=false in response")
                            return False

                    # Also check raw response for error messages
                    if "Authorization Failed" in response or "Invalid credentials" in response:
                        self.login_error = "Invalid credentials - wrong username or password"
                        logger.warning(f"Tachyon login failed: {self.login_error}")
                        return False

                    # Read cookies from file
                    logger.info(f"Reading cookies from {cookie_file}")
                    with open(cookie_file, 'r') as f:
                        cookie_content = f.read()
                    logger.debug(f"Cookie file lines: {len(cookie_content.splitlines())}")

                    for line in cookie_content.split("\n"):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split("\t")
                            if len(parts) >= 7:
                                # Cookie jar format: domain, flag, path, secure, expiry, name, value
                                self._cookies[parts[5]] = parts[6]
                                logger.info(f"Found cookie: {parts[5]}")

                    # Extract token from cookies
                    self._api_token = self._cookies.get("token")
                    logger.info(f"Extracted token: {'present' if self._api_token else 'None'}")

                    if not self._api_token:
                        self.login_error = "Invalid credentials - no session token received"
                        logger.warning(f"No token cookie received from login - credentials likely incorrect")
                        return False

                    self._connected = True
                    self._use_curl = True
                    logger.info(f"Connected to Tachyon at {self.ip} via {self.interface} (token: present)")
                    return True
                else:
                    self.login_error = f"Connection failed: {stderr.decode()}"
                    logger.error(f"Tachyon login curl failed: {stderr.decode()}")
                    return False

            finally:
                # Clean up temp cookie file
                try:
                    Path(cookie_file).unlink()
                except Exception:
                    pass

        except Exception as e:
            self.login_error = f"Connection error: {e}"
            logger.error(f"Failed to connect to Tachyon via curl: {e}")
            return False

    async def disconnect(self) -> None:
        """Disconnect from the device."""
        if self._session:
            try:
                # Logout via DELETE to login endpoint
                await self._session.delete(
                    f"{self._base_url}{self.API_LOGIN}",
                    cookies=self._cookies,
                    headers=self._get_headers()
                )
            except Exception:
                pass
            await self._session.close()
            self._session = None

        self._cookies = {}
        self._api_token = None
        self._connected = False
        logger.debug(f"Disconnected from Tachyon at {self.ip}")

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for authenticated requests.

        Note: Tachyon uses cookie-based auth, not Bearer tokens.
        The token cookie is passed via cookies param, not headers.
        """
        return {"Content-Type": "application/json"}

    async def _api_request(
        self,
        method: str,
        endpoint: str,
        data: Dict[str, Any] = None,
        params: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """Make authenticated API request."""
        # Use curl when interface binding is needed
        if self._use_curl:
            return await self._api_request_curl(method, endpoint, data, params)

        if not self._session:
            raise RuntimeError("Not connected")

        url = f"{self._base_url}{endpoint}"
        headers = self._get_headers()

        # Ensure token cookie is included
        cookies = dict(self._cookies)
        if self._api_token:
            cookies["token"] = self._api_token

        async with self._session.request(
            method,
            url,
            json=data if data else None,
            params=params,
            cookies=cookies,
            headers=headers
        ) as response:
            text = await response.text()

            if response.status >= 400:
                raise aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=response.status,
                    message=text
                )

            try:
                data = json.loads(text)
                # Check for auth failure in JSON body (API returns 200 but statusCode: 401)
                if isinstance(data, dict) and data.get("statusCode") == 401:
                    self._connected = False
                    self.login_error = "Session expired or invalid credentials"
                    logger.warning(f"Auth failed on {endpoint}: statusCode 401 in response")
                    raise PermissionError("Invalid credentials - session rejected (401)")
                return data
            except json.JSONDecodeError:
                return {"raw": text, "status": response.status}

    async def _api_request_curl(
        self,
        method: str,
        endpoint: str,
        data: Dict[str, Any] = None,
        params: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """Make API request using curl with interface binding."""
        url = f"{self._base_url}{endpoint}"

        # Add query params
        if params:
            param_str = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{param_str}"

        # Build curl command
        cmd = [
            "curl", "-s", "-k", "-m", "30",  # -k for self-signed certs
            "--interface", self.interface,
            "-X", method,
        ]

        # Add headers
        cmd.extend(["-H", "Content-Type: application/json"])

        # Tachyon uses 'token' cookie for auth
        if self._api_token:
            cmd.extend(["-H", f"Cookie: token={self._api_token}"])
            logger.debug(f"Using token: {self._api_token[:30]}...")
        else:
            logger.warning(f"No token for API request to {endpoint}")

        # Add data for POST/PUT
        if data and method in ("POST", "PUT", "PATCH"):
            cmd.extend(["-d", json.dumps(data)])

        cmd.append(url)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            error_msg = stderr.decode("utf-8", errors="ignore")
            logger.error(f"API request failed: {method} {endpoint}: {error_msg}")
            raise RuntimeError(f"curl request failed: {error_msg}")

        text = stdout.decode("utf-8", errors="ignore")

        try:
            data = json.loads(text)
            # Check for auth failure in JSON body (API returns 200 but statusCode: 401)
            if isinstance(data, dict) and data.get("statusCode") == 401:
                self._connected = False
                self.login_error = "Session expired or invalid credentials"
                logger.warning(f"Auth failed on {endpoint}: statusCode 401 in response")
                raise PermissionError("Invalid credentials - session rejected (401)")
            return data
        except json.JSONDecodeError:
            return {"raw": text, "status": 200}

    async def get_info(self) -> DeviceInfo:
        """Get device information from system status and bootbank."""
        info = DeviceInfo(device_type=self.device_type, ip_address=self.ip)

        try:
            # Get system status - this has most of what we need
            data = await self._api_request("GET", self.API_STATUS, params={"type": "system"})
            logger.info(f"Tachyon status response type: {type(data)}, keys: {data.keys() if isinstance(data, dict) else 'N/A'}")

            if isinstance(data, dict):
                system = data.get("system", data)
                logger.info(f"Tachyon system keys: {system.keys() if isinstance(system, dict) else type(system)}")

                # Extract model and serial directly from system
                info.model = system.get("model")  # e.g., "TNA-301"
                info.serial_number = system.get("serial")  # e.g., "TNA3011012300013"
                logger.info(f"Tachyon extracted model={info.model}, serial={info.serial_number}")

                # Hostname is in general section
                general = system.get("general", {})
                info.hostname = general.get("hostname") or general.get("name") or system.get("hostname")

                # Firmware version from version section
                version = system.get("version", {})
                firmux = version.get("firmux", "")  # e.g., "1.12.3 rev 54970"
                info.firmware_version = firmux.split(" rev")[0].strip() if firmux else None

                # Store extra info
                info.extra = {
                    "uptime": system.get("uptime"),
                    "temperature": system.get("temperature"),
                    "model_id": system.get("model_id"),
                    "board": system.get("board"),
                }

            # Get bootbank info for dual-bank display
            try:
                bootbank = await self._api_request("GET", self.API_BOOTBANK)
                logger.debug(f"Tachyon bootbank response: {bootbank}")

                if isinstance(bootbank, dict) and info.extra:
                    info.extra["bootbanks"] = bootbank
            except Exception as e:
                logger.debug(f"Could not get bootbank info: {e}")

            # Try to get MAC from interfaces/ethernet status
            try:
                iface_data = await self._api_request("GET", self.API_STATUS, params={"type": "interfaces,ethernet"})
                logger.info(f"Tachyon interfaces status response keys: {iface_data.keys() if isinstance(iface_data, dict) else type(iface_data)}")
                if isinstance(iface_data, dict):
                    # Log what we got to debug MAC extraction
                    interfaces = iface_data.get("interfaces", {})
                    ethernet = iface_data.get("ethernet", {})
                    logger.info(f"Interfaces keys: {interfaces.keys() if isinstance(interfaces, dict) else 'N/A'}")
                    logger.info(f"Ethernet keys: {ethernet.keys() if isinstance(ethernet, dict) else 'N/A'}")
                    if "eth0" in interfaces:
                        logger.info(f"eth0 data: {interfaces.get('eth0')}")

                    # MAC is at interfaces.eth0.mac_address or ethernet.ports.eth0.mac
                    mac = (
                        iface_data.get("interfaces", {}).get("eth0", {}).get("mac_address") or
                        iface_data.get("ethernet", {}).get("ports", {}).get("eth0", {}).get("mac") or
                        ""
                    )
                    if mac and mac != "00:00:00:00:00:00":
                        info.mac_address = mac.upper()  # Keep colons like Cambium
                        logger.info(f"Got MAC address from Tachyon: {info.mac_address}")
                    else:
                        logger.warning(f"MAC address not found or invalid: '{mac}'")
            except Exception as e:
                logger.warning(f"Could not get MAC from interfaces status: {e}")

        except Exception as e:
            logger.error(f"Failed to get device info: {e}")

        self._device_info = info
        return info

    async def get_firmware_banks(self) -> Dict[str, Any]:
        """Get firmware bank versions for dual-bank display.

        Returns dict with bank1, bank2, and active bank number.
        Versions are normalized to "x.y.z.rev" format for comparison with firmware filenames.

        Example: Device reports "1.12.3 rev 54970" -> normalized to "1.12.3.54970"
        This matches firmware filename format: tna-30x-1.12.3-r54970-... -> "1.12.3.54970"
        """
        try:
            bootbank = await self._api_request("GET", self.API_BOOTBANK)
            logger.info(f"Tachyon bootbank response: {bootbank}")

            if isinstance(bootbank, dict):
                active = bootbank.get("active", {})
                backup = bootbank.get("backup", {})

                # Get raw firmux strings (e.g., "1.12.3 rev 54970")
                active_raw = active.get("firmux", "unknown")
                backup_raw = backup.get("firmux", "unknown")

                # Normalize to "x.y.z.rev" format for comparison with firmware filenames
                # "1.12.3 rev 54970" -> "1.12.3.54970"
                active_ver = self._normalize_firmware_version(active_raw)
                backup_ver = self._normalize_firmware_version(backup_raw)

                active_bank = active.get("bootbank", 1)

                result = {
                    "bank1": active_ver if active_bank == 1 else backup_ver,
                    "bank2": backup_ver if active_bank == 1 else active_ver,
                    "active": active_bank,
                    # Include raw versions for display
                    "bank1_display": active_raw if active_bank == 1 else backup_raw,
                    "bank2_display": backup_raw if active_bank == 1 else active_raw,
                }
                logger.info(f"Tachyon firmware banks result: {result}")
                return result

        except Exception as e:
            logger.error(f"Failed to get firmware banks: {e}")

        return {"bank1": "unknown", "bank2": "unknown", "active": 1}

    def _normalize_firmware_version(self, version_str: str) -> str:
        """Normalize Tachyon firmware version string to comparable format.

        Converts "1.12.3 rev 54970" to "1.12.3.54970" to match firmware filename format.

        Args:
            version_str: Raw version string from device (e.g., "1.12.3 rev 54970")

        Returns:
            Normalized version string (e.g., "1.12.3.54970")
        """
        if not version_str or version_str == "unknown":
            return "unknown"

        # Parse "1.12.3 rev 54970" format
        if " rev " in version_str:
            parts = version_str.split(" rev ")
            base_version = parts[0].strip()
            revision = parts[1].strip() if len(parts) > 1 else ""
            if revision:
                return f"{base_version}.{revision}"
            return base_version

        return version_str.strip()

    async def backup_config(self) -> bytes:
        """Backup device configuration as JSON."""
        if not self._connected:
            raise RuntimeError("Not connected")

        try:
            config = await self._api_request("GET", self.API_CONFIG)
            return json.dumps(config, indent=2).encode("utf-8")

        except Exception as e:
            logger.error(f"Failed to backup config: {e}")
            raise

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration via API.

        After a successful POST, reads back the config and compares selected
        authoritative fields to confirm the device actually accepted the
        changes.

        Args:
            config: Configuration dictionary to apply
        """
        self._normalize_config_for_apply(config)

        # Extract password from config before applying — if the config changes
        # the device password, we need the new one for reconnect after reboot.
        self._update_credentials_from_config(config)

        # Use curl when interface binding is needed
        if self.interface:
            ok = await self._apply_config_curl(config)
        else:
            try:
                # Post full config directly (API expects raw config, not wrapped)
                result = await self._api_request(
                    "POST",
                    self.API_CONFIG,
                    data=config
                )

                logger.info(f"Configuration applied to {self.ip}")

                # Check if reboot is required
                if isinstance(result, dict):
                    if result.get("reboot_required"):
                        logger.info("Configuration requires reboot")
                    if result.get("warnings"):
                        for warning in result["warnings"]:
                            logger.warning(f"Config warning: {warning}")
                    if result.get("errors"):
                        for error in result["errors"]:
                            logger.error(f"Config error: {error}")
                        return False

                ok = True

            except Exception as e:
                logger.error(f"Failed to apply config: {e}")
                return False

        if not ok:
            return False

        # Remember what we applied so verify_config() can re-confirm it later.
        self._last_applied_config = config

        # Read back config and verify selected fields match what we sent. This
        # is FAIL-CLOSED: if we cannot read the config back, or it does not
        # match, we report failure. We never claim success we could not confirm.
        if self._has_verifiable_config_fields(config):
            await asyncio.sleep(2)  # Brief pause for config to settle
            readback = await self._get_config_curl()
            if not readback:
                logger.error(
                    f"[CONFIG VERIFY] Could not read back config on {self.ip} — failing closed"
                )
                return False

            mismatches = self._config_verification_mismatches(config, readback)
            if mismatches:
                logger.error(
                    "[CONFIG VERIFY] Config read-back mismatch on %s: %s",
                    self.ip,
                    "; ".join(mismatches[:5]),
                )
                return False
            logger.info(f"[CONFIG VERIFY] Config confirmed on {self.ip}")

        return True

    def _normalize_config_for_apply(self, config: Dict[str, Any]) -> None:
        """Fill Tachyon API-required defaults omitted by older config exports."""
        try:
            system = config.get("system", {})
            services = config.get("services", {})
            radios = config.get("wireless", {}).get("radios", {})
        except AttributeError:
            return

        if isinstance(system, dict):
            for key, default in (
                ("description", ""),
                ("latitude", 0),
                ("longitude", 0),
            ):
                if key not in system:
                    system[key] = default
                    logger.info(
                        "Added default system.%s=%r for Tachyon config apply",
                        key,
                        default,
                    )

        if isinstance(services, dict):
            if "cloud" not in services:
                services["cloud"] = {"enabled": False}
                logger.info("Added default services.cloud.enabled=false for Tachyon config apply")

            snmp_traps = services.get("snmp_traps")
            if isinstance(snmp_traps, dict) and "port" not in snmp_traps:
                snmp_traps["port"] = 162
                logger.info("Added default services.snmp_traps.port=162 for Tachyon config apply")

            ssh = services.get("ssh")
            if isinstance(ssh, dict) and "password_login" not in ssh:
                ssh["password_login"] = True
                logger.info("Added default services.ssh.password_login=true for Tachyon config apply")

            snmp = services.get("snmp")
            snmp_v3 = snmp.get("v3", {}) if isinstance(snmp, dict) else {}
            snmp_v3_ro = snmp_v3.get("ro", {}) if isinstance(snmp_v3, dict) else {}
            if isinstance(snmp_v3_ro, dict) and "encryption_mode" not in snmp_v3_ro:
                snmp_v3_ro["encryption_mode"] = "aes"
                logger.info(
                    "Added default services.snmp.v3.ro.encryption_mode=aes for Tachyon config apply"
                )

        network = config.get("network", {}) if isinstance(config.get("network"), dict) else {}
        wan = network.get("zones", {}).get("wan", {}) if isinstance(network.get("zones"), dict) else {}
        if isinstance(wan, dict):
            if "lldp_forward" not in wan:
                wan["lldp_forward"] = False
                logger.info(
                    "Added default network.zones.wan.lldp_forward=false for Tachyon config apply"
                )
            if "carrier_drop" not in wan:
                wan["carrier_drop"] = {
                    "enabled": False,
                    "rssi_threshold": -68,
                    "down_time": 3,
                    "start_delay": 300,
                }
                logger.info("Added default network.zones.wan.carrier_drop for Tachyon config apply")
            dhcp = wan.get("dhcp")
            if isinstance(dhcp, dict) and "enabled_options" not in dhcp:
                dhcp["enabled_options"] = {
                    "log_server": True,
                    "ntp_server": True,
                    "timezone_offset": True,
                }
                logger.info(
                    "Added default network.zones.wan.dhcp.enabled_options for Tachyon config apply"
                )

        ethernet_ports = (
            config.get("ethernet", {}).get("ports", {})
            if isinstance(config.get("ethernet"), dict)
            else {}
        )
        try:
            wlan0_mode = radios.get("wlan0", {}).get("vaps", [{}])[0].get("mode")
        except (AttributeError, IndexError, TypeError):
            wlan0_mode = None
        eth0 = ethernet_ports.get("eth0") if isinstance(ethernet_ports, dict) else None
        eth0_network = eth0.get("network") if isinstance(eth0, dict) else None
        if wlan0_mode == "sta" and isinstance(eth0_network, dict):
            if "mgmt_vlan_enabled" not in eth0_network:
                eth0_network["mgmt_vlan_enabled"] = True
                logger.info(
                    "Added default ethernet.ports.eth0.network.mgmt_vlan_enabled=true for Tachyon config apply"
                )

        if not isinstance(radios, dict):
            return

        for radio_name, radio in radios.items():
            if not isinstance(radio, dict):
                continue
            if radio.get("enabled") is True and "isolation" not in radio:
                radio["isolation"] = False
                logger.info(
                    "Added default wireless.radios.%s.isolation=false for Tachyon config apply",
                    radio_name,
                )
            vaps = radio.get("vaps", [])
            if not isinstance(vaps, list):
                continue
            for index, vap in enumerate(vaps):
                if not isinstance(vap, dict):
                    continue
                if vap.get("enabled") is True and "isolate" not in vap:
                    vap["isolate"] = False
                    logger.info(
                        "Added default wireless.radios.%s.vaps[%s].isolate=false for Tachyon config apply",
                        radio_name,
                        index,
                    )
                network = vap.get("network")
                if isinstance(network, dict) and "mgmt_vlan_enabled" not in network:
                    network["mgmt_vlan_enabled"] = False
                    logger.info(
                        "Added default wireless.radios.%s.vaps[%s].network.mgmt_vlan_enabled=false for Tachyon config apply",
                        radio_name,
                        index,
                    )

    def _is_full_config_export(self, config: Dict[str, Any]) -> bool:
        """Return True when a JSON template looks like a full Tachyon export."""
        if not isinstance(config, dict):
            return False
        keys = set(config.keys())
        return (
            {"ethernet", "network", "version"}.issubset(keys)
            or {"network", "wireless", "system", "version"}.issubset(keys)
        )

    def _has_verifiable_config_fields(self, config: Dict[str, Any]) -> bool:
        if not isinstance(config, dict):
            return False
        if isinstance(config.get("ethernet", {}).get("ports"), dict):
            return True
        if isinstance(config.get("network", {}).get("zones", {}).get("wan"), dict):
            return True
        if isinstance(config.get("services"), dict):
            return True
        system = config.get("system", {})
        if isinstance(system, dict) and (system.get("hostname") or system.get("name")):
            return True
        try:
            vaps = config.get("wireless", {}).get("radios", {}).get("wlan0", {}).get("vaps", [])
            return bool(vaps and isinstance(vaps[0], dict) and vaps[0].get("ssid"))
        except (KeyError, IndexError, TypeError, AttributeError):
            return False

    def _config_verification_mismatches(self, expected: Dict[str, Any], actual: Dict[str, Any]):
        """Compare selected non-secret fields that prove a Tachyon export landed."""
        mismatches = []

        expected_system = expected.get("system", {}) if isinstance(expected.get("system"), dict) else {}
        actual_system = actual.get("system", {}) if isinstance(actual.get("system"), dict) else {}
        for key in ("hostname", "name"):
            if key in expected_system and expected_system.get(key) != actual_system.get(key):
                mismatches.append(f"system.{key}")

        expected_ports = expected.get("ethernet", {}).get("ports")
        actual_ports = actual.get("ethernet", {}).get("ports")
        if isinstance(expected_ports, dict):
            if not isinstance(actual_ports, dict):
                mismatches.append("ethernet.ports missing")
            elif set(expected_ports.keys()) != set(actual_ports.keys()):
                mismatches.append("ethernet.ports key set")
            else:
                self._append_expected_value_mismatches(
                    mismatches, "ethernet.ports", expected_ports, actual_ports
                )

        expected_wan = expected.get("network", {}).get("zones", {}).get("wan")
        actual_wan = actual.get("network", {}).get("zones", {}).get("wan")
        if isinstance(expected_wan, dict):
            if not isinstance(actual_wan, dict):
                mismatches.append("network.zones.wan missing")
            else:
                if ("vlans" in expected_wan) != ("vlans" in actual_wan):
                    mismatches.append("network.zones.wan.vlans presence")
                self._append_expected_value_mismatches(
                    mismatches, "network.zones.wan", expected_wan, actual_wan
                )

        expected_services = expected.get("services")
        actual_services = actual.get("services")
        if isinstance(expected_services, dict):
            if not isinstance(actual_services, dict):
                mismatches.append("services missing")
            elif set(expected_services.keys()) != set(actual_services.keys()):
                mismatches.append("services key set")
            else:
                self._append_service_toggle_mismatches(mismatches, expected_services, actual_services)

        self._append_wireless_mismatches(mismatches, expected, actual)
        return mismatches

    def _append_expected_value_mismatches(self, mismatches, prefix: str, expected: Any, actual: Any) -> None:
        if self._is_sensitive_path(prefix):
            return
        if isinstance(expected, dict):
            if not isinstance(actual, dict):
                mismatches.append(prefix)
                return
            for key, value in expected.items():
                next_prefix = f"{prefix}.{key}"
                self._append_expected_value_mismatches(
                    mismatches, next_prefix, value, actual.get(key)
                )
        elif isinstance(expected, list):
            if expected != actual:
                mismatches.append(prefix)
        elif expected != actual:
            mismatches.append(prefix)

    def _append_service_toggle_mismatches(self, mismatches, expected: Dict[str, Any], actual: Dict[str, Any]) -> None:
        def walk(expected_value, actual_value, path):
            if self._is_sensitive_path(path):
                return
            if isinstance(expected_value, dict):
                if not isinstance(actual_value, dict):
                    mismatches.append(path)
                    return
                for key, value in expected_value.items():
                    next_path = f"{path}.{key}" if path else key
                    walk(value, actual_value.get(key), next_path)
            elif path.endswith(".enabled") or path.endswith(".port") or path.endswith(".password_login"):
                if expected_value != actual_value:
                    mismatches.append(f"services.{path}")

        walk(expected, actual, "")

    def _append_wireless_mismatches(self, mismatches, expected: Dict[str, Any], actual: Dict[str, Any]) -> None:
        expected_wlan0 = expected.get("wireless", {}).get("radios", {}).get("wlan0", {})
        actual_wlan0 = actual.get("wireless", {}).get("radios", {}).get("wlan0", {})
        if not isinstance(expected_wlan0, dict):
            return

        expected_vaps = expected_wlan0.get("vaps", [])
        actual_vaps = actual_wlan0.get("vaps", []) if isinstance(actual_wlan0, dict) else []
        if not expected_vaps:
            return
        if not actual_vaps or not isinstance(expected_vaps[0], dict) or not isinstance(actual_vaps[0], dict):
            mismatches.append("wireless.radios.wlan0.vaps[0]")
            return

        expected_vap = expected_vaps[0]
        actual_vap = actual_vaps[0]
        if "ssid" in expected_vap and expected_vap.get("ssid") != actual_vap.get("ssid"):
            mismatches.append("wireless.radios.wlan0.vaps[0].ssid")

        expected_profiles = expected_vap.get("sta_profiles", {}).get("profiles", [])
        actual_profiles = actual_vap.get("sta_profiles", {}).get("profiles", [])
        if expected_profiles:
            expected_ssids = [
                profile.get("ssid")
                for profile in expected_profiles
                if isinstance(profile, dict)
            ]
            actual_ssids = [
                profile.get("ssid")
                for profile in actual_profiles
                if isinstance(profile, dict)
            ]
            if expected_ssids != actual_ssids:
                mismatches.append("wireless.radios.wlan0.vaps[0].sta_profiles.profiles.ssid")

    def _is_sensitive_path(self, path: str) -> bool:
        sensitive_parts = ("password", "passphrase", "private_key", "public_key", "community")
        return any(part in path.lower() for part in sensitive_parts)

    async def _get_config_curl(self) -> Dict[str, Any]:
        """Read the device config back for verification.

        Routes over the SAME transport apply used: ``_api_request`` dispatches to
        curl (interface-bound) when ``self._use_curl`` is set, else aiohttp.
        Returns ``{}`` on any failure and never raises, so callers can treat an
        empty dict as "could not confirm" and fail closed.
        """
        try:
            result = await self._api_request("GET", self.API_CONFIG)
            if isinstance(result, dict) and "raw" not in result:
                return result
            logger.warning(f"[CONFIG VERIFY] Read-back returned no usable config from {self.ip}")
            return {}
        except Exception as e:
            logger.warning(f"[CONFIG VERIFY] Read-back request failed: {e}")
            return {}

    async def _apply_config_curl(self, config: Dict[str, Any]) -> bool:
        """Apply configuration using curl with interface binding."""
        import asyncio

        try:
            url = f"{self._base_url}{self.API_CONFIG}"
            payload = json.dumps(config)  # API expects raw config, not wrapped

            # Log config keys being applied (not values - may contain sensitive data)
            config_keys = list(config.keys()) if isinstance(config, dict) else "non-dict"
            logger.info(f"Applying config to {self.ip} via {self.interface}, keys: {config_keys}")

            # Build curl command with interface binding
            cmd = [
                "curl", "-s", "-k", "-m", "30",  # -k for self-signed certs
                "--interface", self.interface,
                "-X", "POST",
                "-H", "Content-Type: application/json",
            ]

            # Add auth - Tachyon uses 'token' cookie
            if self._api_token:
                cmd.extend(["-H", f"Cookie: token={self._api_token}"])

            cmd.extend(["-d", payload, url])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                response = stdout.decode("utf-8", errors="ignore")
                logger.info(f"Config apply response: {response[:500]}")

                # Try to parse as JSON
                try:
                    result = json.loads(response)

                    # Check for Tachyon API error format: {"statusCode":400,"error":{...}}
                    if result.get("statusCode") and result.get("statusCode") >= 400:
                        error_details = result.get("error", {}).get("details", "Unknown error")
                        logger.error(f"Config apply failed with status {result['statusCode']}: {error_details}")
                        return False

                    # Check for error field
                    if result.get("error"):
                        error_details = result["error"].get("details", str(result["error"]))
                        logger.error(f"Config apply error: {error_details}")
                        return False

                    if result.get("errors"):
                        for error in result["errors"]:
                            logger.error(f"Config error: {error}")
                        return False

                    if result.get("reboot_required"):
                        logger.info("Configuration requires reboot")
                    if result.get("warnings"):
                        for warning in result["warnings"]:
                            logger.warning(f"Config warning: {warning}")

                    # Log success details
                    logger.info(f"Config apply result: {result}")
                except json.JSONDecodeError:
                    logger.warning(f"Config apply returned non-JSON response")

                logger.info(f"Configuration applied to {self.ip} via {self.interface}")
                return True
            else:
                logger.error(f"Config apply curl failed: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Failed to apply config via curl: {e}")
            return False

    def _deep_merge(self, base: dict, overlay: dict) -> dict:
        """Recursively merge overlay into base. Overlay values win on conflict."""
        merged = base.copy()
        for key, value in overlay.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged

    async def apply_config_file(self, config_path: str) -> bool:
        """Apply configuration from JSON file or tarball.

        Supports:
        - Plain JSON files (.json)
        - Tarball files (.tar, .tar.gz, .tgz) containing config.json
        """
        try:
            logger.info(f"Loading config from file: {config_path}")

            loaded_template = load_config_template(config_path)
            config = loaded_template.config
            logger.info(
                "Loaded config template: source=%s, keys=%s",
                loaded_template.source_type,
                loaded_template.top_level_keys,
            )

            if loaded_template.source_type == "tar" or self._is_full_config_export(config):
                logger.info("Applying Tachyon config export as authoritative full config")
            else:
                # Partial JSON templates remain patch-like and merge into the
                # live config before apply.
                try:
                    current_config = await self._api_request("GET", self.API_CONFIG)
                    if isinstance(current_config, dict):
                        config = self._deep_merge(current_config, config)
                        logger.info(f"Merged partial template config into current device config")
                except Exception as e:
                    logger.warning(f"Could not GET current config for merge, applying template as-is: {e}")

            return await self.apply_config(config)

        except ConfigTemplateError as e:
            logger.error(str(e))
            return False
        except Exception as e:
            logger.error(f"Failed to apply config file: {e}")
            return False

    async def upload_firmware(self, firmware_path: str, bank: Optional[int] = None) -> bool:
        """Upload firmware file to device via multipart form-data.

        Args:
            firmware_path: Path to local firmware file
        """
        if not self._connected:
            raise RuntimeError("Not connected")

        firmware_file = Path(firmware_path)
        if not firmware_file.exists():
            logger.error(f"Firmware file not found: {firmware_path}")
            return False

        # Use curl for multipart upload (handles interface binding too)
        if self._use_curl or self.interface:
            return await self._upload_firmware_curl(firmware_path)

        try:
            url = f"{self._base_url}{self.API_UPDATE}"

            # Create multipart form data
            with open(firmware_path, "rb") as f:
                form_data = aiohttp.FormData()
                form_data.add_field("fw", f, filename=firmware_file.name)
                form_data.add_field("force", "false")

                # Build cookies dict with token
                cookies = dict(self._cookies)
                if self._api_token:
                    cookies["token"] = self._api_token

                async with self._session.put(  # Tachyon uses PUT for firmware upload
                    url,
                    data=form_data,
                    cookies=cookies,
                ) as response:
                    if response.status == 200:
                        logger.info(f"Firmware uploaded to {self.ip}")
                        return True
                    else:
                        text = await response.text()
                        logger.error(f"Firmware upload failed ({response.status}): {text}")
                        return False

        except Exception as e:
            logger.error(f"Failed to upload firmware: {e}")
            return False

    async def _upload_firmware_curl(self, firmware_path: str) -> bool:
        """Upload firmware using curl with multipart form-data.

        Uses PUT method as required by Tachyon API.
        """
        try:
            url = f"{self._base_url}{self.API_UPDATE}"
            firmware_file = Path(firmware_path)

            cmd = [
                "curl", "-s", "-k", "-m", "300",  # 5 min timeout for upload
            ]

            if self.interface:
                cmd.extend(["--interface", self.interface])

            cmd.extend([
                "-X", "PUT",  # Tachyon uses PUT for firmware upload
                "-F", f"fw=@{firmware_path}",
                "-F", "force=false",
            ])

            # Add auth - Tachyon uses 'token' cookie
            if self._api_token:
                cmd.extend(["-H", f"Cookie: token={self._api_token}"])

            cmd.append(url)

            logger.info(f"Uploading firmware {firmware_file.name} to {self.ip}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                response = stdout.decode("utf-8", errors="ignore")
                logger.info(f"Firmware upload response: {response[:500]}")

                # Try to parse response to check for errors
                try:
                    result = json.loads(response)
                    if isinstance(result, dict):
                        if result.get("error") or result.get("statusCode", 200) >= 400:
                            logger.error(f"Firmware upload API error: {result}")
                            return False
                        logger.info(f"Firmware upload API result: {result}")
                except json.JSONDecodeError:
                    logger.debug(f"Non-JSON firmware upload response: {response[:200]}")

                logger.info(f"Firmware uploaded to {self.ip}")
                return True
            else:
                logger.error(f"Firmware upload failed: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Failed to upload firmware via curl: {e}")
            return False

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """Trigger firmware update after upload.

        Sends POST to /cgi.lua/update with reset/force flags to apply
        the uploaded firmware. Tachyon devices automatically write to
        the inactive bank.

        Args:
            bank: Target bank number (1 or 2). Used for logging only -
                  Tachyon automatically targets the inactive bank.
        """
        try:
            # Trigger the update with reset=false, force=false
            bank_str = f" (bank {bank})" if bank else ""
            logger.info(f"Triggering firmware update on {self.ip}{bank_str}")

            result = await self._api_request(
                "POST",
                self.API_UPDATE,
                data={"reset": False, "force": False}
            )

            logger.info(f"Firmware update API response: {result}")

            # Check for errors in response
            if isinstance(result, dict):
                if result.get("error"):
                    logger.error(f"Firmware update API error: {result.get('error')}")
                    return False
                if result.get("statusCode", 200) >= 400:
                    logger.error(f"Firmware update failed with status: {result}")
                    return False

            logger.info(f"Firmware update triggered on {self.ip}{bank_str}")
            return True

        except Exception as e:
            logger.error(f"Failed to trigger firmware update: {e}")
            return False

    async def reboot(self) -> bool:
        """Reboot the device."""
        try:
            await self._api_request("POST", self.API_REBOOT)
            logger.info(f"Reboot initiated on {self.ip}")
            return True

        except aiohttp.ClientError:
            # Connection error expected during reboot
            logger.info(f"Reboot initiated on {self.ip} (connection closed)")
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
        """Wait for device to come back online after reboot.

        Uses interface-bound ping and curl to verify connectivity.
        This ensures proper routing on VLAN-isolated provisioning ports.
        """
        logger.info(f"Waiting for {self.ip} to reboot...")

        # Initial wait for device to go down
        await asyncio.sleep(10)

        start_time = asyncio.get_event_loop().time()
        ping_responded = False

        while asyncio.get_event_loop().time() - start_time < timeout:
            # Phase 1: Wait for device to respond to ping
            if not ping_responded:
                if await self._ping_device():
                    logger.info(f"{self.ip} responding to ping, waiting for web server...")
                    ping_responded = True
                    # Wait a bit for web services to initialize
                    await asyncio.sleep(10)
                    continue
            else:
                # Phase 2: Check if web server is up via curl
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
        """Check if web server is responding using curl with interface binding."""
        try:
            cmd = ["curl", "-s", "-k", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}"]
            if self.interface:
                cmd.extend(["--interface", self.interface])
            cmd.append(f"https://{self.ip}/")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                status_code = stdout.decode().strip()
                # Any HTTP response means web server is up
                if status_code and status_code.isdigit():
                    return int(status_code) > 0
            return False
        except Exception:
            return False

    async def verify_firmware_upgrade(self, expected_version: str) -> bool:
        """Verify firmware version after upgrade.

        Re-authenticates and checks that the firmware version matches expected.
        """
        try:
            # Reconnect after reboot
            if not await self.connect():
                logger.error("Failed to reconnect after reboot")
                return False

            # Get current version
            info = await self.get_info()
            current_version = info.firmware_version

            if current_version == expected_version:
                logger.info(f"Firmware upgrade verified: {current_version}")
                return True
            else:
                logger.warning(
                    f"Firmware version mismatch: expected {expected_version}, "
                    f"got {current_version}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to verify firmware upgrade: {e}")
            return False

    async def set_hostname(self, hostname: str) -> bool:
        """Set the device hostname."""
        try:
            # Get current config
            config = await self._api_request("GET", self.API_CONFIG)

            if not isinstance(config, dict):
                logger.error("Failed to get current config")
                return False

            # Update hostname
            config["hostname"] = hostname

            # Apply updated config
            return await self.apply_config(config)

        except Exception as e:
            logger.error(f"Failed to set hostname: {e}")
            return False

    async def set_password(self, new_password: str, username: str = None) -> bool:
        """Change the device password.

        Tachyon devices use the config API to manage user credentials.
        The password is changed by updating the user configuration.

        Args:
            new_password: The new password to set.
            username: Username to change password for (defaults to 'root').

        Returns:
            True if password changed successfully.
        """
        try:
            target_user = username or self.credentials.get("username", "root")

            # Try user management endpoint first (newer firmware)
            try:
                result = await self._api_request(
                    "POST",
                    "/cgi.lua/user",
                    data={
                        "username": target_user,
                        "password": new_password,
                    }
                )
                if isinstance(result, dict) and not result.get("error"):
                    logger.info(f"Password changed for {target_user} on {self.ip}")
                    return True
            except Exception:
                pass

            # Fall back to config-based password change
            try:
                config = await self._api_request("GET", self.API_CONFIG)

                if isinstance(config, dict):
                    # Common config structures for user/auth settings
                    if "users" in config:
                        # Array of users
                        for user in config.get("users", []):
                            if user.get("username") == target_user or user.get("name") == target_user:
                                user["password"] = new_password
                                break
                        else:
                            # User not found, add or update root
                            config["users"] = [{"username": target_user, "password": new_password}]
                    elif "auth" in config:
                        config["auth"]["password"] = new_password
                    elif "system" in config:
                        if "auth" not in config["system"]:
                            config["system"]["auth"] = {}
                        config["system"]["auth"]["password"] = new_password
                    else:
                        # Try top-level password field
                        config["password"] = new_password

                    if await self.apply_config(config):
                        logger.info(f"Password changed via config for {target_user} on {self.ip}")
                        return True
            except Exception as e:
                logger.debug(f"Config-based password change failed: {e}")

            logger.error(f"Failed to change password on {self.ip}")
            return False

        except Exception as e:
            logger.error(f"Failed to change password: {e}")
            return False

    async def apply_ap_naming(self, hostname: str, ssid: str) -> bool:
        """Apply AP naming by merging into current config.

        This is safer than replacing the whole config - it:
        1. GETs the current config from the device
        2. Merges in just the hostname/name/ssid changes
        3. POSTs the merged config

        Args:
            hostname: Hostname to set (e.g., "tw24-north")
            ssid: SSID to set (e.g., "NORTH")

        Returns:
            True if config applied successfully
        """
        logger.info(f"Applying AP naming to {self.ip}: hostname={hostname}, ssid={ssid}")

        try:
            # GET current config
            logger.info(f"Getting current config from {self.ip}")
            current_config = await self._api_request("GET", self.API_CONFIG)

            if not isinstance(current_config, dict):
                logger.error(f"Failed to get current config from {self.ip}")
                return False

            # Merge in our changes
            # system.hostname and system.name
            if "system" not in current_config:
                current_config["system"] = {}
            current_config["system"]["hostname"] = hostname
            current_config["system"]["name"] = hostname

            # wireless.radios.wlan0.vaps[0].ssid
            try:
                if "wireless" in current_config:
                    radios = current_config["wireless"].get("radios", {})
                    if "wlan0" in radios:
                        vaps = radios["wlan0"].get("vaps", [])
                        if vaps:
                            vaps[0]["ssid"] = ssid
                            logger.info(f"Set SSID to {ssid} in vaps[0]")
            except (KeyError, IndexError, TypeError) as e:
                logger.warning(f"Could not set SSID in wireless config: {e}")

            # POST merged config
            logger.info(f"Applying merged config to {self.ip}")
            return await self.apply_config(current_config)

        except Exception as e:
            logger.error(f"Failed to apply AP naming: {e}")
            return False

    async def verify_config(self, expected_values: Optional[Dict[str, Any]] = None):
        """Post-config verification: reconnect, then re-confirm the config.

        Reconnects, checks firmware banks, and — fail-closed — reads the config
        back and compares selected non-secret fields against the config we
        applied. If the config cannot be read back, returns ``False`` rather
        than claiming a success we cannot confirm. Returns :data:`UNVERIFIED`
        only when there is nothing recorded to compare against.

        Returns:
            ``True`` / ``False`` / :data:`UNVERIFIED`.
        """
        logger.info(f"[CONFIG VERIFY] Verifying Tachyon device state on {self.ip}")
        await self.disconnect()

        # Reconnect
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                logger.info(f"[CONFIG VERIFY] Login attempt {attempt}/{max_attempts} for {self.ip}")
                if await self.connect():
                    break
                login_err = self.login_error or ""
                auth_keywords = ["credentials", "password", "locked", "session", "unauthorized"]
                if any(kw in login_err.lower() for kw in auth_keywords):
                    logger.error(f"[CONFIG VERIFY] Auth/lockout error, stopping: {login_err}")
                    return False
                logger.warning(f"[CONFIG VERIFY] Reconnect attempt {attempt} failed: {login_err}")
            except Exception as e:
                logger.warning(f"[CONFIG VERIFY] Attempt {attempt} error: {e}")
                await self.disconnect()
            if attempt < max_attempts:
                await asyncio.sleep(10)
        else:
            logger.error(f"[CONFIG VERIFY] All {max_attempts} login attempts failed for {self.ip}")
            return False

        # Check firmware banks (informational signal, not the verification gate)
        try:
            banks = await self.get_firmware_banks()
            bank1 = banks.get("bank1", "unknown")
            bank2 = banks.get("bank2", "unknown")
            active = banks.get("active", "?")
            logger.info(f"[CONFIG VERIFY] Firmware banks: bank1={bank1}, bank2={bank2}, active={active}")
            if bank1 != bank2:
                logger.warning(f"[CONFIG VERIFY] Firmware bank mismatch: bank1={bank1}, bank2={bank2}")
        except Exception as e:
            logger.warning(f"[CONFIG VERIFY] Could not check firmware banks: {e}")

        # Re-confirm the config actually landed by reading it back and comparing
        # against what we applied. This is the real gate (fail-closed).
        expected = self._last_applied_config or {}
        if not self._has_verifiable_config_fields(expected):
            # Nothing recorded to compare — connectivity confirmed, config not.
            logger.info(f"[CONFIG VERIFY] Device accessible on {self.ip}; no config fields to confirm")
            return UNVERIFIED

        readback = await self._get_config_curl()
        if not readback:
            logger.error(f"[CONFIG VERIFY] Could not read back config on {self.ip} — failing closed")
            return False

        mismatches = self._config_verification_mismatches(expected, readback)
        if mismatches:
            logger.error(
                "[CONFIG VERIFY] Config read-back mismatch on %s: %s",
                self.ip,
                "; ".join(mismatches[:5]),
            )
            return False

        logger.info(f"[CONFIG VERIFY] Config confirmed on {self.ip}")
        return True
