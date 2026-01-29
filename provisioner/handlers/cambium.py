"""Cambium ePMP device handler."""

import asyncio
import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import urllib.parse

import aiohttp

from .base import BaseHandler, DeviceInfo

logger = logging.getLogger(__name__)


class CambiumHandler(BaseHandler):
    """Handler for Cambium ePMP and PMP devices.

    Supports ePMP 1000/2000/3000/Force series via web API.
    The ePMP web interface uses a combination of CGI endpoints and
    JSON API calls depending on firmware version.
    """

    # Default credentials (tried first)
    DEFAULT_CREDENTIALS = {"username": "admin", "password": "admin"}

    # API endpoints - ePMP uses multiple patterns depending on firmware
    CGI_ENDPOINTS = {
        "login": "/cgi-bin/luci",
        "status": "/cgi-bin/status.cgi",
        "config": "/cgi-bin/config.cgi",
        "firmware": "/cgi-bin/firmware.cgi",
        "reboot": "/cgi-bin/reboot.cgi",
        "backup": "/cgi-bin/backup.cgi",
    }

    API_ENDPOINTS = {
        "login": "/api/auth/login",
        "logout": "/api/auth/logout",
        "status": "/api/status",
        "system": "/api/system/info",
        "config": "/api/config",
        "config_get": "/api/config/get",
        "config_set": "/api/config/set",
        "firmware": "/api/firmware/upload",
        "firmware_status": "/api/firmware/status",
        "firmware_upgrade": "/api/firmware/upgrade",
        "reboot": "/api/system/reboot",
        "backup": "/api/config/backup",
        "restore": "/api/config/restore",
    }

    def __init__(self, ip: str, credentials: Dict[str, str], interface: Optional[str] = None,
                 alternate_credentials: list = None):
        super().__init__(ip, credentials, interface)
        self._alternate_credentials = alternate_credentials or []
        self._session: Optional[aiohttp.ClientSession] = None
        self._auth_token: Optional[str] = None
        self._session_cookie: Optional[str] = None
        self._stok: Optional[str] = None  # Session token from CGI login
        self._cookie_file: Optional[str] = None  # Path to cookie file for curl requests
        self._base_url = f"https://{ip}"
        self._api_version: Optional[str] = None
        self._use_cgi = False  # Fall back to CGI for older firmware
        self._account_locked_until: Optional[float] = None  # Track account lockout
        self.login_error: Optional[str] = None  # Human-readable login error for UI
        self._credentials_confirmed: bool = False  # True after successful login (for reconnect)
        self._password_change_required: bool = False  # Device requires password change on first login
        self._last_applied_config: Optional[Dict[str, str]] = None  # Flat keys applied via set_param

    @property
    def device_type(self) -> str:
        return "cambium"

    @property
    def supports_dual_bank(self) -> bool:
        return True

    @property
    def supports_password_change(self) -> bool:
        return True

    async def connect(self) -> bool:
        """Connect to Cambium device via REST API or CGI.

        Tries credential sets in order to avoid account lockout:
        1. Default credentials (admin/admin) - if password change required, auto-changes it
        2. Custom credentials from credentials.json (if configured)
        3. Backup password from config (if configured)

        Sets self.login_error with details if login fails.
        """
        self.login_error = None  # Clear previous error
        self._password_change_required = False

        logger.info(f"[CREDS] ========== CAMBIUM CONNECT START for {self.ip} ==========")

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(connector=connector, timeout=timeout)

            # Check if account is locked from previous attempt
            if self._account_locked_until:
                wait_time = self._account_locked_until - asyncio.get_event_loop().time()
                if wait_time > 0:
                    self.login_error = f"Account locked, {int(wait_time)}s until unlock"
                    logger.warning(f"[CREDS] Account locked on {self.ip}, {wait_time:.0f}s until unlock")
                    return False

            # Get custom credential for password change target
            custom_cred = self._get_custom_credential()
            target_password = custom_cred["password"] if custom_cred else None
            logger.info(f"[CREDS] Custom credential loaded: {custom_cred is not None}")

            # Build credential list
            creds_to_try = []

            # Check for backup password in credentials
            backup_password = self.credentials.get("backup_password")

            # If we've already connected successfully, try those credentials first (reconnect after reboot)
            if self._credentials_confirmed:
                logger.info(f"[CREDS] Reconnect mode - using previously confirmed credentials first")
                creds_to_try.append(self.credentials.copy())
                creds_to_try.append(self.DEFAULT_CREDENTIALS.copy())
            else:
                # Fresh device - try default first, then custom
                # 1. Always try default credentials first (admin/admin)
                creds_to_try.append(self.DEFAULT_CREDENTIALS.copy())
                logger.info(f"[CREDS] Added default credentials (admin/admin)")

                # 2. Add custom credential from credentials.json if different from default
                if custom_cred and custom_cred.get("password") != self.DEFAULT_CREDENTIALS["password"]:
                    creds_to_try.append(custom_cred)
                    logger.info(f"[CREDS] Added custom credential from credentials.json")

                # 3. Add backup password as third option if configured and different
                if backup_password and backup_password != self.DEFAULT_CREDENTIALS["password"]:
                    backup_cred = {"username": self.credentials.get("username", "admin"), "password": backup_password}
                    if backup_cred not in creds_to_try:
                        creds_to_try.append(backup_cred)
                        logger.info(f"[CREDS] Added backup credential")

            logger.info(f"[CREDS] Will try {len(creds_to_try)} credential set(s)")

            # Save original credentials so we can restore on failure
            saved_credentials = self.credentials.copy()

            # Track if we got any response from device (vs connection failure)
            device_responded = False
            any_creds_rejected = False

            # Try each credential set
            for i, creds in enumerate(creds_to_try):
                username = creds["username"]
                password = creds["password"]
                logger.info(f"[CREDS] Attempt {i+1}/{len(creds_to_try)}: Trying {username}/{'*' * len(password) if password else '(empty)'} for {self.ip}")

                # Temporarily set credentials for this login attempt
                self.credentials["username"] = username
                self.credentials["password"] = password

                # Try CGI login (most reliable for ePMP)
                success, creds_rejected = await self._try_cgi_login()
                if creds_rejected:
                    device_responded = True
                    any_creds_rejected = True
                if success:
                    self._use_cgi = True
                    self._credentials_confirmed = True
                    logger.info(f"[CREDS] SUCCESS! Logged in with {username} (CGI mode)")

                    # Check if password change is required and we have a target password
                    if self._password_change_required and target_password:
                        logger.info(f"[CREDS] Device requires password change, changing from default to configured password")
                        if await self._change_default_password(target_password):
                            logger.info(f"[CREDS] Password changed successfully on {self.ip}")
                            # Update credentials to new password
                            self.credentials["password"] = target_password
                        else:
                            logger.warning(f"[CREDS] Failed to change password on {self.ip}, continuing anyway")

                    logger.info(f"[CREDS] ========== CAMBIUM CONNECT END (success) ==========")
                    return True

                # Check for lockout - stop immediately
                if self._account_locked_until:
                    self.login_error = "Account locked due to failed login attempts"
                    logger.error(f"Account locked on {self.ip}")
                    return False

                # If credentials were rejected, try next set
                if creds_rejected:
                    logger.info(f"[CREDS] Credentials REJECTED for {self.ip}, trying next...")
                    continue

                # Try API login as fallback
                success, creds_rejected = await self._try_api_login()
                if creds_rejected:
                    device_responded = True
                    any_creds_rejected = True
                if success:
                    self._use_cgi = False
                    self._credentials_confirmed = True
                    logger.info(f"[CREDS] SUCCESS! Logged in with {username} (API mode)")

                    # Check if password change is required
                    if self._password_change_required and target_password:
                        logger.info(f"[CREDS] Device requires password change, changing from default to configured password")
                        if await self._change_default_password(target_password):
                            logger.info(f"[CREDS] Password changed successfully on {self.ip}")
                            self.credentials["password"] = target_password
                        else:
                            logger.warning(f"[CREDS] Failed to change password on {self.ip}, continuing anyway")

                    logger.info(f"[CREDS] ========== CAMBIUM CONNECT END (success) ==========")
                    return True

                if self._account_locked_until:
                    self.login_error = "Account locked due to failed login attempts"
                    logger.error(f"Account locked on {self.ip}")
                    return False

            # All attempts failed — restore original credentials to prevent corruption
            self.credentials.update(saved_credentials)

            # Determine failure reason (don't overwrite specific error already set by handler)
            if not self.login_error:
                if any_creds_rejected:
                    self.login_error = "Invalid credentials - please enter correct password"
                    logger.error(f"[CREDS] FAILED for {self.ip} - all {len(creds_to_try)} credential sets rejected")
                else:
                    self.login_error = "Device not responding - check network connectivity"
                    logger.error(f"[CREDS] FAILED for {self.ip} - device did not respond (connection issue)")
            else:
                logger.error(f"[CREDS] FAILED for {self.ip} - {self.login_error}")
            logger.info(f"[CREDS] ========== CAMBIUM CONNECT END (failed) ==========")
            return False

        except Exception as e:
            self.login_error = f"Connection error: {str(e)}"
            logger.error(f"Failed to connect to Cambium at {self.ip}: {e}")
            return False

    async def _change_default_password(self, new_password: str, wpa_key: str = None) -> bool:
        """Change the default password on first login using set_param endpoint.

        Called automatically when device requires password change (first-boot setup).
        This uses the /admin/set_param endpoint which sets both admin password and WPA key.

        Args:
            new_password: The new admin password to set
            wpa_key: The WPA key to set (required for first-boot). If not provided,
                     will try to get from credentials or use a default.
        """
        try:
            if not self._stok:
                logger.error("No STOK token available for password change")
                return False

            # Get WPA key - try credentials first, then use a default
            if not wpa_key:
                wpa_key = self.credentials.get("wpa_key", "")
            if not wpa_key:
                # Use the new password as WPA key if not specified (will be overwritten by config)
                wpa_key = new_password
                logger.warning(f"No WPA key provided, using password as temporary WPA key")

            # Use set_param endpoint for first-boot setup (confirmed working)
            set_param_url = f"{self._base_url}/cgi-bin/luci/;stok={self._stok}/admin/set_param"

            # Build the payload matching browser behavior
            changed_elements = json.dumps({
                "device_props": {
                    "admin_password": new_password,
                    "crashReporterEnable": "1",
                    "wirelessInterfaceEncryptionKey": wpa_key
                },
                "template_props": {
                    "config_id": "0"
                }
            })

            form_data = f"changed_elements={urllib.parse.quote(changed_elements)}&debug=true"

            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-k", "-m", "15",
                "--interface", self.interface,
                "-b", self._cookie_file,
                "-X", "POST",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "-d", form_data,
                set_param_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                response = stdout.decode("utf-8", errors="ignore")
                logger.debug(f"set_param response: {response}")
                # Check for success
                if "success" in response.lower() or '"err":""' in response or proc.returncode == 0:
                    logger.info(f"First-boot setup completed via set_param on {self.ip}")
                    return True

            # Fallback: try older password change methods
            logger.warning(f"set_param failed, trying fallback methods")
            old_password = self.DEFAULT_CREDENTIALS["password"]

            # Method 2: REST API password change
            change_url = f"{self._base_url}/api/system/password"
            payload = {
                "oldPassword": old_password,
                "newPassword": new_password,
            }
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-k", "-m", "10",
                "--interface", self.interface,
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json.dumps(payload),
                change_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                response = stdout.decode("utf-8", errors="ignore")
                if "success" in response.lower() or "200" in response:
                    return True

            return False

        except Exception as e:
            logger.error(f"Error changing default password: {e}")
            return False

    def _get_custom_credential(self) -> Optional[Dict[str, str]]:
        """Get ONE custom credential for Cambium devices.

        Returns the first custom credential found, or None if not configured.
        Only returns one to avoid account lockout (max 2 total attempts).
        Always reads fresh from file to pick up UI changes without restart.
        """
        try:
            # Always read fresh from credentials file (not cached)
            settings_paths = [
                # Primary: repo data path (where web API saves)
                Path("/var/lib/provisioner/repo/credentials.json"),
                # Fallback paths
                Path("/var/lib/provisioner/credentials.json"),
                Path("/opt/provisioner/credentials.json"),
                Path.home() / ".provisioner" / "credentials.json",
            ]

            for path in settings_paths:
                if path.exists():
                    with open(path) as f:
                        data = json.load(f)
                        cambium_creds = data.get("cambium")

                        # Handle different formats - only return first credential
                        if isinstance(cambium_creds, dict):
                            logger.info(f"Loaded custom Cambium credential from {path}")
                            return cambium_creds
                        elif isinstance(cambium_creds, list) and len(cambium_creds) > 0:
                            logger.info(f"Loaded Cambium credential from {path}: {cambium_creds[0].get('username', 'unknown')}")
                            return cambium_creds[0]  # Only first one

            return None
        except Exception as e:
            logger.warning(f"Could not load custom credential: {e}")
            return None

    async def _try_api_login(self) -> Tuple[bool, bool]:
        """Try modern JSON API login.

        Returns:
            Tuple of (success, credentials_rejected) - if credentials_rejected is True,
            caller should not retry with same credentials via other methods.
        """
        try:
            login_url = f"{self._base_url}{self.API_ENDPOINTS['login']}"
            payload = {
                "username": self.credentials.get("username", "admin"),
                "password": self.credentials.get("password", "admin"),
            }

            async with self._session.post(login_url, json=payload) as response:
                text = await response.text()

                # Check for credential rejection in response
                rejection_patterns = [
                    "user_or_pass_is_not_correct",
                    "invalid_user_or_password",
                    "incorrect password",
                    "invalid credentials",
                    "authentication failed",
                    "unauthorized",
                ]
                for pattern in rejection_patterns:
                    if pattern.lower() in text.lower():
                        logger.warning(f"API credentials rejected by {self.ip}: {pattern}")
                        return False, True

                # Check for account lockout
                lockout_match = re.search(r'account is locked.*?(\d+)\s*minutes?\s*left', text, re.IGNORECASE)
                if lockout_match:
                    lockout_minutes = int(lockout_match.group(1))
                    logger.warning(f"Account locked on {self.ip}, {lockout_minutes} minutes until unlock")
                    self._account_locked_until = asyncio.get_event_loop().time() + (lockout_minutes * 60)
                    return False, True

                if response.status == 200:
                    try:
                        data = json.loads(text)
                        self._auth_token = data.get("token") or data.get("sessionId") or data.get("session_id")
                        if self._auth_token:
                            self._connected = True
                            logger.info(f"Connected to Cambium at {self.ip} (API mode)")
                            return True, False
                    except json.JSONDecodeError:
                        pass

                # Try alternate endpoint
                login_url = f"{self._base_url}/api/login"
                async with self._session.post(login_url, json=payload) as response:
                    text = await response.text()

                    # Check rejection on alternate endpoint too
                    for pattern in rejection_patterns:
                        if pattern.lower() in text.lower():
                            logger.warning(f"API credentials rejected by {self.ip}: {pattern}")
                            return False, True

                    if response.status == 200:
                        try:
                            data = json.loads(text)
                            self._auth_token = data.get("token") or data.get("sessionId")
                            if self._auth_token:
                                self._connected = True
                                logger.info(f"Connected to Cambium at {self.ip} (API mode)")
                                return True, False
                        except json.JSONDecodeError:
                            pass

        except Exception as e:
            logger.debug(f"API login failed: {e}")

        return False, False

    async def _try_cgi_login(self) -> Tuple[bool, bool]:
        """Try CGI/form-based login for ePMP devices.

        Returns:
            Tuple of (success, credentials_rejected) - if credentials_rejected is True,
            caller should not retry with same credentials via other methods.
        """
        username = self.credentials.get("username", "admin")
        password = self.credentials.get("password", "admin")

        # Use curl when interface binding is needed
        if self.interface:
            return await self._try_cgi_login_curl(username, password)

        # Use aiohttp when no interface binding needed
        try:
            login_url = f"{self._base_url}/cgi-bin/luci"
            payload = {
                "username": username,
                "password": password,
            }

            async with self._session.post(
                login_url,
                data=payload,
                allow_redirects=False
            ) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        if "stok" in data:
                            self._stok = data["stok"]
                            self._connected = True
                            logger.info(f"Connected to Cambium at {self.ip} (CGI mode, stok={self._stok[:8]}...)")
                            return True, False
                    except Exception:
                        pass

                    cookies = response.cookies
                    if cookies:
                        self._session_cookie = str(cookies)
                        self._connected = True
                        logger.info(f"Connected to Cambium at {self.ip} (CGI mode)")
                        return True, False

        except Exception as e:
            logger.debug(f"CGI login failed: {e}")

        return False, False

    async def _try_cgi_login_curl(self, username: str, password: str) -> Tuple[bool, bool]:
        """Try CGI login using curl with interface binding.

        Returns:
            Tuple of (success, credentials_rejected) - if credentials_rejected is True,
            caller should not retry with same credentials via other methods.
        """
        import tempfile

        try:
            login_url = f"{self._base_url}/cgi-bin/luci"
            logger.info(f"Attempting CGI login to {login_url} via interface {self.interface}")

            # Create cookie file if not already exists
            if not self._cookie_file:
                cookie_fd = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
                self._cookie_file = cookie_fd.name
                cookie_fd.close()

            # Use curl with interface binding and save cookies
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-k", "-m", "10",
                "--interface", self.interface,
                "-c", self._cookie_file, "-b", self._cookie_file,
                "-X", "POST",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "-d", f"username={username}&password={password}",
                login_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            logger.info(f"CGI login curl returncode: {proc.returncode}, stdout len: {len(stdout) if stdout else 0}, stderr: {stderr.decode() if stderr else ''}")

            if proc.returncode == 0 and stdout:
                response = stdout.decode("utf-8", errors="ignore")
                logger.info(f"CGI login response: {response[:300]}")

                # Check for explicit credential rejection
                rejection_patterns = [
                    "user_or_pass_is_not_correct",
                    "invalid_user_or_password",
                    "incorrect password",
                    "invalid credentials",
                    "authentication failed",
                    "auth_failed",  # Cambium returns {"msg":"auth_failed","success":0}
                ]
                for pattern in rejection_patterns:
                    if pattern.lower() in response.lower():
                        logger.warning(f"Credentials rejected by {self.ip}: {pattern}")
                        return False, True

                # Check for software upgrade in progress - device is still applying firmware.
                # Don't spin here — wait_for_reboot() handles the full boot-up check.
                # Just signal that the device isn't ready yet (not a credential rejection).
                if "sw_upgrade_is_in_progress" in response.lower():
                    logger.info(f"Device {self.ip} firmware upgrade still in progress, not ready for login")
                    return False, False

                # Check for factory reset state — device needs reboot after firmware flash.
                # Cambium returns {"msg":"reset_has_been_done","success":0} when firmware
                # was written to flash but device hasn't rebooted yet. Send a reboot now.
                if "reset_has_been_done" in response.lower():
                    logger.warning(f"Device {self.ip} reports reset_has_been_done — sending reboot to complete firmware update")
                    await self._send_bare_reboot()
                    self.login_error = "Device rebooting to complete firmware update (reset_has_been_done)"
                    return False, False

                # Check for max users reached (too many active sessions)
                # Treat as lockout (not credential rejection) to prevent connect() from
                # rotating to the next credential set and corrupting self.credentials
                if "max_user_number_reached" in response.lower():
                    logger.warning(f"Device {self.ip} has too many active sessions - treating as lockout")
                    self.login_error = "Too many active sessions on device - wait for timeout or reboot device"
                    self._account_locked_until = asyncio.get_event_loop().time() + 60
                    return False, False

                # Check for account lockout
                lockout_match = re.search(r'account is locked.*?(\d+)\s*minutes?\s*left', response, re.IGNORECASE)
                if lockout_match:
                    lockout_minutes = int(lockout_match.group(1))
                    logger.warning(f"Account locked on {self.ip}, {lockout_minutes} minutes until unlock")
                    # Store lockout info for later handling
                    self._account_locked_until = asyncio.get_event_loop().time() + (lockout_minutes * 60)
                    return False, True

                # Check for forced password change requirement (common on first login with default creds)
                # Don't return immediately - check if we still got a session we can use
                password_change_patterns = [
                    "password_change_required",
                    "must change password",
                    "change your password",
                    "password must be changed",
                    "password_expired",
                    "changePassword",
                    "newPasswordRequired",
                ]
                password_change_detected = False
                for pattern in password_change_patterns:
                    if pattern.lower() in response.lower():
                        logger.warning(f"Device {self.ip} requires password change on first login")
                        self._password_change_required = True
                        password_change_detected = True
                        break

                # Try to parse as JSON (modern firmware returns JSON with stok)
                try:
                    # Response might have cookie jar at the start, try to find JSON
                    for line in response.split("\n"):
                        line = line.strip()
                        if line.startswith("{"):
                            data = json.loads(line)
                            if "stok" in data:
                                self._stok = data["stok"]
                                self._connected = True
                                logger.info(f"Connected to Cambium at {self.ip} via {self.interface} (CGI mode, stok={self._stok[:8]}...)")
                                return True, False
                except json.JSONDecodeError:
                    pass

                # Check if login succeeded by presence of userRole or clientIpAddr
                if "userRole" in response or "clientIpAddr" in response:
                    self._connected = True
                    logger.info(f"Connected to Cambium at {self.ip} via {self.interface} (CGI mode)")
                    return True, False

                # If password change was detected but we couldn't get a session,
                # the device may not allow any operations until password is changed manually
                if password_change_detected:
                    self.login_error = "Device requires password change - may need manual login first"
                    return False, True

            logger.debug(f"CGI login curl failed: returncode={proc.returncode}, stderr={stderr.decode()}")

        except Exception as e:
            logger.debug(f"CGI login curl exception: {e}")

        return False, False

    async def disconnect(self) -> None:
        """Disconnect from the device and release session."""
        try:
            # Logout CGI mode session (using stok)
            if self._stok and self.interface:
                logout_url = f"{self._base_url}/cgi-bin/luci/;stok={self._stok}/admin/logout"
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-k", "-m", "5",
                    "--interface", self.interface,
                    "-X", "POST",
                    "-d", "",  # Empty body required to avoid 411 Length Required
                    logout_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
                logger.debug(f"Sent CGI logout for {self.ip}")

            # Logout API mode session
            if self._session and self._auth_token:
                try:
                    logout_url = f"{self._base_url}{self.API_ENDPOINTS['logout']}"
                    await self._session.post(logout_url, headers=self._get_auth_headers())
                except Exception:
                    pass

            if self._session:
                await self._session.close()
                self._session = None

            # Clean up cookie file
            if self._cookie_file:
                try:
                    import os
                    os.unlink(self._cookie_file)
                except Exception:
                    pass
                self._cookie_file = None

        except Exception as e:
            logger.debug(f"Error during disconnect: {e}")

        self._auth_token = None
        self._session_cookie = None
        self._stok = None
        self._connected = False
        logger.info(f"Disconnected from Cambium at {self.ip}")

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
            headers["X-Auth-Token"] = self._auth_token
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
            except:
                return {"status": "ok", "text": await response.text()}

    async def _cgi_get(self, endpoint: str) -> str:
        """Make CGI GET request."""
        if not self._session:
            raise RuntimeError("Not connected")

        url = f"{self._base_url}{endpoint}"
        async with self._session.get(url) as response:
            return await response.text()

    async def _cgi_post(self, endpoint: str, data: Dict[str, Any] = None) -> str:
        """Make CGI POST request."""
        if not self._session:
            raise RuntimeError("Not connected")

        url = f"{self._base_url}{endpoint}"
        async with self._session.post(url, data=data) as response:
            return await response.text()

    async def get_info(self) -> DeviceInfo:
        """Get device information from Cambium device."""
        info = DeviceInfo(device_type=self.device_type, ip_address=self.ip)

        try:
            # Use curl when interface binding is needed (VLAN mode)
            if self.interface and self._stok:
                return await self._get_info_curl()

            if not self._use_cgi:
                # Modern API
                system_data = await self._api_get(self.API_ENDPOINTS["system"])
                info.model = (
                    system_data.get("model") or
                    system_data.get("productName") or
                    system_data.get("product_name")
                )
                info.serial_number = (
                    system_data.get("serialNumber") or
                    system_data.get("serial_number") or
                    system_data.get("sn")
                )
                info.mac_address = system_data.get("macAddress", system_data.get("mac", "")).upper()
                info.hostname = (
                    system_data.get("deviceName") or
                    system_data.get("device_name") or
                    system_data.get("hostname")
                )
                info.firmware_version = (
                    system_data.get("softwareVersion") or
                    system_data.get("software_version") or
                    system_data.get("firmwareVersion") or
                    system_data.get("firmware_version")
                )
                info.hardware_version = system_data.get("hardwareVersion", system_data.get("hardware_version"))

                # Get status
                try:
                    status_data = await self._api_get(self.API_ENDPOINTS["status"])
                    info.uptime = status_data.get("uptime")
                    info.extra["link_status"] = status_data.get("linkStatus", status_data.get("link_status"))
                    info.extra["signal_strength"] = status_data.get("signalStrength", status_data.get("rssi"))
                    info.extra["connected_aps"] = status_data.get("connectedAPs")
                    info.extra["mode"] = status_data.get("deviceMode", status_data.get("mode"))
                except Exception:
                    pass

            else:
                # CGI mode - parse HTML/text response
                status_text = await self._cgi_get("/cgi-bin/status.cgi")
                info = self._parse_cgi_status(status_text, info)

        except Exception as e:
            logger.error(f"Failed to get device info: {e}")

        self._device_info = info
        return info

    async def _get_info_curl(self) -> DeviceInfo:
        """Get device info using curl with interface binding.

        For ePMP devices in VLAN mode. Note: Modern ePMP firmware uses WebSockets
        for data transfer, not REST API. Device info retrieval is limited to:
        - MAC address: from ARP table (after communicating with device)
        - Model: from SKU code in /js/cambium_sku.js
        - Firmware: from /js/cambium_sku.js
        - Serial: NOT available via HTTP (WebSocket only)
        """
        info = DeviceInfo(device_type=self.device_type, ip_address=self.ip)

        # 1. Get MAC address from ARP table (populated after login/curl communication)
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "neigh", "show", "dev", self.interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0 and stdout:
                arp_output = stdout.decode("utf-8", errors="ignore")
                # Look for: 169.254.1.1 lladdr bc:e6:7c:77:ff:13 REACHABLE
                for line in arp_output.split("\n"):
                    if self.ip in line and "lladdr" in line:
                        parts = line.split()
                        lladdr_idx = parts.index("lladdr") if "lladdr" in parts else -1
                        if lladdr_idx >= 0 and lladdr_idx + 1 < len(parts):
                            info.mac_address = parts[lladdr_idx + 1].upper().replace("-", ":")
                            logger.info(f"Got MAC from ARP: {info.mac_address}")
                            break
        except Exception as e:
            logger.debug(f"ARP lookup failed: {e}")

        # 2. Get SKU and firmware from cambium_sku.js (doesn't require auth)
        # Format: window.sku = 53544; window.systemConfigLanguage = 'en';
        #         window.cambiumFWVersion = 'Version 5.10.4';
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-k", "-m", "10",
                "--interface", self.interface,
                f"{self._base_url}/js/cambium_sku.js",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0 and stdout:
                sku_content = stdout.decode("utf-8", errors="ignore")
                logger.debug(f"SKU file content: {sku_content}")

                # Extract firmware version: window.cambiumFWVersion = 'Version 5.10.4';
                fw_match = re.search(r'cambiumFWVersion\s*=\s*["\'](?:Version\s*)?([^"\']+)', sku_content)
                if fw_match:
                    info.firmware_version = fw_match.group(1).strip()
                    logger.info(f"Got firmware version from SKU: {info.firmware_version}")

                # Extract SKU code: window.sku = 53544;
                sku_match = re.search(r'window\.sku\s*=\s*(\d+)', sku_content)
                if sku_match:
                    sku_code = sku_match.group(1)
                    info.extra["sku"] = sku_code
                    # Known SKU mappings (add more as discovered)
                    # These map Cambium internal SKU codes to human-readable model names
                    sku_to_model = {
                        "35": "Force 300-25",
                        "49": "Force 300-19",
                        "53544": "ePMP 4518",
                        # Add more SKU mappings here as discovered
                    }
                    if sku_code in sku_to_model:
                        info.model = sku_to_model[sku_code]
                    else:
                        info.model = f"Cambium ePMP (SKU {sku_code})"
                    logger.info(f"Got SKU code {sku_code}: {info.model}")

        except Exception as e:
            logger.debug(f"SKU file fetch failed: {e}")

        # 3. Try SNMP if available (common OIDs) - usually disabled on Cambium
        try:
            # sysDescr.0
            proc = await asyncio.create_subprocess_exec(
                "snmpget", "-v2c", "-c", "public", "-t", "2", "-r", "1",
                self.ip, "1.3.6.1.2.1.1.1.0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0 and stdout:
                snmp_output = stdout.decode("utf-8", errors="ignore")
                # Parse sysDescr for model/version info
                if "STRING:" in snmp_output:
                    sys_descr = snmp_output.split("STRING:")[1].strip().strip('"')
                    info.extra["snmp_sysdescr"] = sys_descr
                    # Try to extract model from sysDescr
                    model_match = re.search(r'(ePMP\s*\d+|PMP\s*\d+|Force\s*\d+)', sys_descr, re.IGNORECASE)
                    if model_match:
                        info.model = model_match.group(1)
                    # Try to extract version
                    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', sys_descr)
                    if version_match:
                        info.firmware_version = version_match.group(1)
                    logger.info(f"Got device info from SNMP: model={info.model}, fw={info.firmware_version}")
        except FileNotFoundError:
            logger.debug("snmpget not available")
        except Exception as e:
            logger.debug(f"SNMP query failed: {e}")

        # 4. Fallback to generic model if we couldn't determine specific
        if not info.model:
            info.model = "Cambium ePMP"

        logger.info(f"Device info for {self.ip}: model={info.model}, fw={info.firmware_version}")
        self._device_info = info
        return info

    def _parse_json_info(self, data: dict, info: DeviceInfo) -> DeviceInfo:
        """Parse device info from JSON response (various formats)."""
        # Handle nested structures
        if "result" in data:
            data = data["result"]
        if "data" in data:
            data = data["data"]
        if "system" in data:
            system = data["system"]
            data.update(system)

        # Extract model
        info.model = (
            data.get("model") or
            data.get("productName") or
            data.get("product_name") or
            data.get("deviceModel") or
            data.get("device_model") or
            data.get("product")
        )

        # Extract serial number
        info.serial_number = (
            data.get("serialNumber") or
            data.get("serial_number") or
            data.get("serial") or
            data.get("sn") or
            data.get("msn")
        )

        # Extract MAC address
        mac = (
            data.get("macAddress") or
            data.get("mac_address") or
            data.get("mac") or
            data.get("ethMac") or
            data.get("wlanMac")
        )
        if mac:
            info.mac_address = mac.upper().replace("-", ":")

        # Extract hostname
        info.hostname = (
            data.get("deviceName") or
            data.get("device_name") or
            data.get("hostname") or
            data.get("name") or
            data.get("systemName")
        )

        # Extract firmware version
        info.firmware_version = (
            data.get("softwareVersion") or
            data.get("software_version") or
            data.get("firmwareVersion") or
            data.get("firmware_version") or
            data.get("firmware") or
            data.get("version") or
            data.get("swVersion")
        )

        # Extract hardware version
        info.hardware_version = (
            data.get("hardwareVersion") or
            data.get("hardware_version") or
            data.get("hwVersion")
        )

        # Extract uptime
        info.uptime = data.get("uptime") or data.get("systemUptime")

        # Extra info
        for key in ["linkStatus", "link_status", "signalStrength", "rssi", "snr", "mode", "deviceMode"]:
            if key in data:
                info.extra[key] = data[key]

        return info

    def _parse_cgi_status(self, html: str, info: DeviceInfo) -> DeviceInfo:
        """Parse device info from CGI HTML response."""
        # Common patterns in ePMP status pages
        patterns = {
            "model": r"(?:Product|Model|Device).*?:\s*([^\n<]+)",
            "serial": r"(?:Serial|SN).*?:\s*([A-Z0-9]+)",
            "mac": r"(?:MAC|Ethernet).*?:\s*([0-9A-Fa-f:]{17})",
            "firmware": r"(?:Firmware|Software|Version).*?:\s*([\d.]+)",
            "hostname": r"(?:Device Name|Hostname).*?:\s*([^\n<]+)",
        }

        for field, pattern in patterns.items():
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if field == "model":
                    info.model = value
                elif field == "serial":
                    info.serial_number = value
                elif field == "mac":
                    info.mac_address = value.upper()
                elif field == "firmware":
                    info.firmware_version = value
                elif field == "hostname":
                    info.hostname = value

        return info

    async def backup_config(self) -> bytes:
        """Backup device configuration."""
        if not self._session:
            raise RuntimeError("Not connected")

        try:
            if not self._use_cgi:
                url = f"{self._base_url}{self.API_ENDPOINTS['backup']}"
                async with self._session.get(url, headers=self._get_auth_headers()) as response:
                    response.raise_for_status()
                    return await response.read()
            else:
                url = f"{self._base_url}{self.CGI_ENDPOINTS['backup']}"
                async with self._session.get(url) as response:
                    return await response.read()

        except Exception as e:
            logger.error(f"Failed to backup config: {e}")
            raise

    async def get_config(self) -> Dict[str, Any]:
        """Get current device configuration."""
        if not self._use_cgi:
            return await self._api_get(self.API_ENDPOINTS["config_get"])
        else:
            text = await self._cgi_get(self.CGI_ENDPOINTS["config"])
            try:
                return json.loads(text)
            except:
                return {"raw": text}

    async def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration via set_param endpoint.

        Accepts flat Cambium device_props keys (e.g. wirelessInterfaceSSID).
        Strips metadata keys and delegates to _apply_config_settings_curl.
        """
        try:
            # Strip metadata keys
            props = {k: v for k, v in config.items()
                     if not k.startswith("_") and k not in ("device_props", "template_props")}

            # If config is already wrapped in device_props, unwrap it
            if "device_props" in config and isinstance(config["device_props"], dict):
                props = config["device_props"]

            if not props:
                logger.warning(f"No config properties to apply on {self.ip}")
                return True

            return await self._apply_config_settings_curl(props)

        except Exception as e:
            logger.error(f"Failed to apply config: {e}")
            return False

    async def apply_config_file(self, config_path: str) -> bool:
        """Apply configuration from JSON file.

        For Cambium devices, this uploads the config file as a restore operation.
        Credentials are NOT updated here — connect() handles credential rotation.
        """
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                logger.error(f"Config file not found: {config_path}")
                return False

            # Use curl-based restore when interface binding is needed
            if self.interface:
                success = await self._apply_config_file_curl(config_path)
            else:
                # Read and apply via aiohttp
                with open(config_file, "r") as f:
                    config = json.load(f)
                success = await self.apply_config(config)

            # Don't update self.credentials here — the password change from
            # the config template may not take effect immediately. The connect()
            # method has credential rotation that will try both default and
            # custom passwords, so let it figure out which one works.
            return success

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file {config_path}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to apply config file: {e}")
            return False

    async def _apply_config_file_curl(self, config_path: str) -> bool:
        """Apply config file using curl with interface binding.

        Handles both:
        - JSON config files: Parsed and applied via API endpoints
        - TAR archives: Restored via LuCI flashops endpoint
        """
        config_file = Path(config_path)

        # Check file type and route appropriately
        if config_file.suffix.lower() == '.json':
            return await self._apply_json_config_curl(config_path)
        else:
            return await self._apply_tar_config_curl(config_path)

    async def _apply_json_config_curl(self, config_path: str) -> bool:
        """Apply JSON config file via config_import endpoint.

        CONFIRMED via browser HAR capture (2026-01-28):
        - POST /admin/config_import as multipart/form-data
        - Fields: skipIllegal=1, image=@file.json
        - Response: {"success":1,"filepath":"/tmp/uploaded_file","err":""}
        - Then poll get_param with act=status&applyStatusNeeded=true
        - Apply is done when response contains template_props.applyFinished=1

        See docs/cambium-config.md for full reference.
        """
        try:
            if not self._stok:
                logger.error(f"No stok available for config_import on {self.ip}")
                return False

            config_import_url = (
                f"{self._base_url}/cgi-bin/luci/;stok={self._stok}/admin/config_import"
            )

            logger.info(f"Uploading JSON config to {self.ip} via config_import: {config_path}")

            # Upload the JSON file with skipIllegal=1
            cmd = [
                "curl", "-s", "-k", "-m", "30",
                "--interface", self.interface,
                "-b", self._cookie_file,
                "-X", "POST",
                "-F", "skipIllegal=1",
                "-F", f"image=@{config_path};type=application/json",
                config_import_url,
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.error(
                    f"config_import curl failed: rc={proc.returncode}, "
                    f"stderr={stderr.decode() if stderr else ''}"
                )
                return False

            response = stdout.decode("utf-8", errors="ignore")
            logger.info(f"config_import response: {response[:500]}")

            # Check upload success
            try:
                resp_data = json.loads(response)
                success_val = resp_data.get("success")
                if success_val != 1 and success_val != "1":
                    err = resp_data.get("err", "")
                    logger.error(
                        f"config_import failed on {self.ip}: success={success_val}, err={err!r}"
                    )
                    return False
            except json.JSONDecodeError:
                logger.error(f"config_import returned non-JSON: {response[:500]}")
                return False

            logger.info(f"Config uploaded to {self.ip}, waiting for apply to finish...")

            # Poll for applyFinished
            applied = await self._poll_config_apply_status()
            if applied:
                logger.info(f"Configuration applied successfully on {self.ip}")
                # Store that we applied a config (for verification)
                try:
                    with open(config_path, "r") as f:
                        config_data = json.load(f)
                    # Extract flat keys for verification
                    if "device_props" in config_data:
                        flat_keys = config_data["device_props"]
                    else:
                        flat_keys = {k: v for k, v in config_data.items()
                                     if not k.startswith("_")}
                    self._last_applied_config = flat_keys
                except Exception:
                    pass
            else:
                logger.error(f"Config apply did not finish on {self.ip}")

            return applied

        except Exception as e:
            logger.error(f"Failed to apply JSON config via config_import: {e}")
            return False

    async def _poll_config_apply_status(self, timeout: int = 60, interval: float = 3.0) -> bool:
        """Poll get_param until config apply finishes.

        After config_import, the device applies config asynchronously.
        Poll with act=status&applyStatusNeeded=true until the response
        contains template_props.applyFinished == 1.

        CONFIRMED via HAR capture: the UI polls this same way.
        """
        get_param_url = (
            f"{self._base_url}/cgi-bin/luci/;stok={self._stok}/admin/get_param"
        )

        elapsed = 0.0
        while elapsed < timeout:
            cmd = [
                "curl", "-s", "-k", "-m", "10",
                "--interface", self.interface,
                "-b", self._cookie_file,
                "-X", "POST",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "-d", "act=status&applyStatusNeeded=true&debug=true",
                get_param_url,
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                try:
                    resp = json.loads(stdout.decode("utf-8", errors="ignore"))
                    template_props = resp.get("template_props", {})
                    if template_props.get("applyFinished") == 1:
                        logger.info(f"Config apply finished on {self.ip} after {elapsed:.0f}s")
                        return True
                    # Log progress
                    initiator = resp.get("device_props", {}).get("initiatorState", {})
                    if isinstance(initiator, dict) and initiator.get("import"):
                        logger.debug(f"Config import still in progress on {self.ip}...")
                except (json.JSONDecodeError, KeyError):
                    pass

            await asyncio.sleep(interval)
            elapsed += interval

        logger.error(f"Config apply timed out after {timeout}s on {self.ip}")
        return False

    # Keys that cannot be set via set_param (read-only, table types, certificates)
    _SKIP_KEYS_SUFFIXES = (
        "Table", "Certificate", "Pem",
        "MacAddress", "SerialNumber",
    )
    _SKIP_KEYS_PREFIXES = (
        # Read-only system/hardware info
        "cambiumCurrent", "cambiumConnected", "cambiumEffective",
        "cambiumSystem", "cambiumHardware", "cambiumLicense",
        # Counters and statistics
        "sysUpTime", "ethTx", "ethRx", "wireless80211",
    )
    _SKIP_KEYS_EXACT = frozenset({
        # Read-only firmware/system info
        "cambiumCurrentuImageVersion", "cambiumCurrentuImageIVersion",
        "cambiumCurrentuImageDate", "cambiumCurrentuImageIDate",
        # Certificate blobs
        "uhttpdMainPem", "wirelessRadiusUser1Certificate",
        "wirelessRadiusUser2Certificate",
        # Hardware identifiers
        "systemConfigSWLockBit", "systemConfigHWLockBit",
        "cambiumDeviceMode", "cambiumDeviceType",
        # Network state (DHCP-assigned, not settable directly)
        "networkInterfaceIPMethod",
    })
    # Essential provisioning keys — used as fallback if full config set fails
    _ESSENTIAL_KEYS = (
        "wirelessInterfaceSSID", "snmpSystemName", "systemConfigDeviceName",
        "admin_password", "wirelessInterfaceEncryptionKey",
        "crashReporterEnable",
    )

    def _filter_settable_props(self, props: dict) -> dict:
        """Filter out keys that cannot be set via set_param.

        Removes:
        - Table keys (value is list/dict, or key ends with 'Table')
        - Certificate/PEM/MAC/serial keys
        - Known read-only prefixes (cambiumCurrent*, cambiumConnected*, etc.)
        - Known read-only exact keys
        - Keys with None values
        """
        filtered = {}
        skipped = []
        for key, value in props.items():
            # Skip None values
            if value is None:
                skipped.append(key)
                continue
            # Skip table/complex values (lists, dicts)
            if isinstance(value, (list, dict)):
                skipped.append(key)
                continue
            # Skip known suffixes
            if any(key.endswith(s) for s in self._SKIP_KEYS_SUFFIXES):
                skipped.append(key)
                continue
            # Skip known read-only prefixes
            if any(key.startswith(p) for p in self._SKIP_KEYS_PREFIXES):
                skipped.append(key)
                continue
            # Skip known read-only keys
            if key in self._SKIP_KEYS_EXACT:
                skipped.append(key)
                continue
            filtered[key] = value

        if skipped:
            logger.info(f"Filtered {len(skipped)} non-settable keys: {skipped[:15]}{'...' if len(skipped) > 15 else ''}")

        return filtered

    async def _apply_config_settings_curl(self, config_props: dict) -> bool:
        """Apply config properties via set_param endpoint.

        Wraps flat key/value pairs into the device_props format and POSTs
        to /admin/set_param as form-encoded data. No reboot required.

        Non-settable keys (tables, certificates, read-only) are filtered
        out automatically before sending.

        If the full property set fails, retries with only essential
        provisioning keys (SSID, hostname, device name, password).

        Args:
            config_props: Flat dict of Cambium device_props keys to values.

        Returns:
            True if set_param returned success.
        """
        if not self._stok:
            logger.error(f"No stok available for set_param on {self.ip}")
            return False

        if not config_props:
            logger.warning(f"No config properties to apply on {self.ip}")
            return True

        # Filter out non-settable keys
        settable = self._filter_settable_props(config_props)
        if not settable:
            logger.warning(f"All config properties were filtered out on {self.ip}")
            return True

        logger.info(f"Sending {len(settable)} settable properties (from {len(config_props)} total)")

        success = await self._send_set_param(settable)
        if success:
            return True

        # Fallback: retry with only essential provisioning keys
        essential = {k: v for k, v in settable.items() if k in self._ESSENTIAL_KEYS}
        if essential and len(essential) < len(settable):
            logger.warning(
                f"Full config set failed ({len(settable)} keys). "
                f"Retrying with {len(essential)} essential keys: {list(essential.keys())}"
            )
            success = await self._send_set_param(essential)
            if success:
                logger.info(f"Essential-only config applied on {self.ip}")
                return True
            logger.error(f"Essential-only config also failed on {self.ip}")

        return False

    async def _send_set_param(self, props: dict) -> bool:
        """Send a set_param request with the given properties.

        Writes the form data to a temp file to handle large payloads
        reliably, then POSTs via curl.

        Args:
            props: Flat dict of settable device_props keys to values.

        Returns:
            True if set_param returned success.
        """
        # Build the changed_elements JSON
        changed_elements = json.dumps({
            "device_props": props,
            "template_props": {"config_id": "0"},
        })

        form_data = f"changed_elements={urllib.parse.quote(changed_elements)}&debug=true"

        set_param_url = f"{self._base_url}/cgi-bin/luci/;stok={self._stok}/admin/set_param"
        logger.info(f"POST set_param to {self.ip} ({len(props)} keys, {len(form_data)} bytes)")

        # Write form data to temp file to avoid command-line length issues
        data_file = None
        try:
            data_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="cambium_setparam_"
            )
            data_file.write(form_data)
            data_file.close()

            cmd = [
                "curl", "-s", "-k", "-m", "30",
                "--interface", self.interface,
                "-b", self._cookie_file,
                "-X", "POST",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "--data-binary", f"@{data_file.name}",
                set_param_url,
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        finally:
            if data_file:
                try:
                    os.unlink(data_file.name)
                except OSError:
                    pass

        if proc.returncode != 0:
            logger.error(f"set_param curl failed: rc={proc.returncode}, stderr={stderr.decode() if stderr else ''}")
            return False

        response = stdout.decode("utf-8", errors="ignore")

        # Check for success
        try:
            resp_data = json.loads(response)
            success_val = resp_data.get("success")
            if success_val == 1 or success_val == "1":
                logger.info(f"set_param succeeded on {self.ip} ({len(props)} keys)")
                # Store applied config for verification
                self._last_applied_config = dict(props)
                return True
            else:
                err = resp_data.get("err", "")
                # Log full response for debugging
                logger.error(
                    f"set_param failed on {self.ip}: success={success_val}, err={err!r}, "
                    f"full_response={response[:2000]}"
                )
                return False
        except json.JSONDecodeError:
            # Non-JSON response — check for HTML error page
            if response.strip().startswith("<!DOCTYPE") or response.strip().startswith("<html"):
                logger.error(f"set_param returned HTML error page (session expired?)")
                return False
            # Some firmware returns plain text success
            if "success" in response.lower():
                self._last_applied_config = dict(props)
                return True
            logger.error(f"set_param returned non-JSON: {response[:500]}")
            return False

    async def _apply_tar_config_curl(self, config_path: str) -> bool:
        """Apply TAR archive config using curl with interface binding.

        Cambium ePMP devices use LuCI for config restore. The process requires:
        1. Login to get session cookies and stok token (or reuse existing)
        2. POST to flashops with archive file and restore button field

        The config file should be a tar archive (LuCI backup format).
        """
        import tempfile

        try:
            logger.info(f"Applying TAR config to {self.ip} via {self.interface}")

            # Reuse existing stok from connect() if available
            stok = self._stok
            if stok:
                logger.debug(f"Reusing existing stok for TAR config: {stok[:16]}...")
            else:
                # No existing session, need to login via curl
                logger.debug(f"No existing stok, logging in via curl for TAR config...")
                cookie_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
                cookie_path = cookie_file.name
                cookie_file.close()

                username = self.credentials.get("username", "admin")
                password = self.credentials.get("password", "admin")
                login_url = f"{self._base_url}/cgi-bin/luci"

                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-k", "-m", "10",
                    "--interface", self.interface,
                    "-c", cookie_path, "-b", cookie_path,
                    "-X", "POST",
                    "-d", f"username={username}&password={password}",
                    login_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    logger.error(f"Login failed: {stderr.decode()}")
                    return False

                response = stdout.decode("utf-8", errors="ignore")
                try:
                    match = re.search(r'"stok":"([^"]+)"', response)
                    if match:
                        stok = match.group(1)
                        self._stok = stok  # Save for future use
                except Exception:
                    pass

                if not stok:
                    logger.error(f"Failed to get stok token: {response[:200]}")
                    return False

                logger.debug(f"Got new stok: {stok[:16]}...")

            # POST config to flashops
            url = f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/system/flashops"

            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-k", "-m", "60",
                "--interface", self.interface,
                "-X", "POST",
                "-F", f"archive=@{config_path}",
                "-F", "restore=Upload archive...",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                response = stdout.decode("utf-8", errors="ignore")
                logger.debug(f"Config restore response: {response[:500]}")

                # Check for success - LuCI shows "Rebooting" or "Changes applied" on success
                if "Rebooting" in response or "Changes applied" in response:
                    logger.info(f"Configuration applied to {self.ip} via {self.interface} - device rebooting")
                    return True

                # Check for error indicators
                if "error" in response.lower() or "failed" in response.lower():
                    if "session_expired" in response.lower():
                        logger.error(f"Config restore failed: session expired")
                    else:
                        logger.error(f"Config restore failed: {response[:200]}")
                    return False

                # Accept HTML response as likely success (page reload)
                if "<!DOCTYPE" in response or "<html" in response:
                    logger.info(f"Configuration applied to {self.ip} via {self.interface}")
                    return True

                logger.info(f"Configuration applied to {self.ip} via {self.interface}")
                return True
            else:
                logger.error(f"Config restore curl failed: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Failed to apply TAR config via curl: {e}")
            return False

    async def restore_config(self, backup_data: bytes) -> bool:
        """Restore configuration from backup."""
        if not self._session:
            raise RuntimeError("Not connected")

        try:
            if not self._use_cgi:
                url = f"{self._base_url}{self.API_ENDPOINTS['restore']}"
                data = aiohttp.FormData()
                data.add_field("file", backup_data, filename="config.backup")

                headers = self._get_auth_headers()
                del headers["Content-Type"]

                async with self._session.post(url, headers=headers, data=data) as response:
                    return response.status in (200, 201, 202)
            else:
                url = f"{self._base_url}/cgi-bin/restore.cgi"
                data = aiohttp.FormData()
                data.add_field("file", backup_data, filename="config.backup")

                async with self._session.post(url, data=data) as response:
                    return response.status in (200, 201, 202)

        except Exception as e:
            logger.error(f"Failed to restore config: {e}")
            return False

    async def upload_firmware(self, firmware_path: str) -> bool:
        """Upload firmware to the device."""
        try:
            firmware_file = Path(firmware_path)
            if not firmware_file.exists():
                logger.error(f"Firmware file not found: {firmware_path}")
                return False

            logger.info(f"Uploading firmware {firmware_file.name} to {self.ip}...")

            # Use curl when interface binding is needed (VLAN mode)
            if self.interface:
                return await self._upload_firmware_curl(firmware_path)

            # Use aiohttp when no interface binding needed
            if not self._session:
                raise RuntimeError("Not connected")

            if not self._use_cgi:
                url = f"{self._base_url}{self.API_ENDPOINTS['firmware']}"
            else:
                url = f"{self._base_url}{self.CGI_ENDPOINTS['firmware']}"

            with open(firmware_file, "rb") as f:
                data = aiohttp.FormData()
                data.add_field(
                    "file",
                    f,
                    filename=firmware_file.name,
                    content_type="application/octet-stream"
                )

                headers = self._get_auth_headers()
                if "Content-Type" in headers:
                    del headers["Content-Type"]

                async with self._session.post(
                    url,
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=600)  # 10 min for large files
                ) as response:
                    if response.status in (200, 201, 202):
                        logger.info(f"Firmware uploaded to {self.ip}")
                        return True
                    else:
                        text = await response.text()
                        logger.error(f"Firmware upload failed: {response.status} - {text}")
                        return False

        except Exception as e:
            logger.error(f"Failed to upload firmware: {e}")
            return False

    async def _upload_firmware_curl(self, firmware_path: str) -> bool:
        """Upload firmware using curl with interface binding.

        For Cambium ePMP devices in VLAN mode, we need to bind to the specific
        VLAN interface. This uses the LuCI sysupgrade endpoint.
        """
        import tempfile

        try:
            firmware_file = Path(firmware_path)
            logger.info(f"Uploading firmware {firmware_file.name} to {self.ip} via {self.interface}")

            # Track which cookie file to use
            cookie_path = None

            # Reuse existing stok from connect() if available
            stok = self._stok
            if stok:
                logger.debug(f"Reusing existing stok for firmware upload: {stok[:16]}...")
                cookie_path = self._cookie_file  # Use cookie file from connect()
            else:
                # No existing session, need to login via curl
                logger.debug(f"No existing stok, logging in via curl for firmware upload...")
                cookie_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
                cookie_path = cookie_file.name
                cookie_file.close()

                username = self.credentials.get("username", "admin")
                password = self.credentials.get("password", "admin")
                login_url = f"{self._base_url}/cgi-bin/luci"

                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-k", "-m", "10",
                    "--interface", self.interface,
                    "-c", cookie_path, "-b", cookie_path,
                    "-X", "POST",
                    "-d", f"username={username}&password={password}",
                    login_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    logger.error(f"Login failed: {stderr.decode()}")
                    return False

                response = stdout.decode("utf-8", errors="ignore")
                try:
                    match = re.search(r'"stok":"([^"]+)"', response)
                    if match:
                        stok = match.group(1)
                        self._stok = stok  # Save for future use
                except Exception:
                    pass

                if not stok:
                    logger.error(f"Failed to get stok token for firmware upload")
                    return False

                logger.debug(f"Got new stok: {stok[:16]}...")

            # Upload firmware to local_upload_image endpoint (confirmed from Cambium web UI)
            # Field name is "image", not "file"
            url = f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/local_upload_image"

            # Build curl command with cookies - LuCI requires both stok AND session cookies
            curl_args = [
                "curl", "-s", "-k", "-m", "600",  # 10 min timeout for large files
                "--interface", self.interface,
                "-X", "POST",
                "-F", f"image=@{firmware_path}",
            ]
            if cookie_path:
                curl_args.extend(["-b", cookie_path])
            curl_args.append(url)

            proc = await asyncio.create_subprocess_exec(
                *curl_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                response = stdout.decode("utf-8", errors="ignore")
                logger.debug(f"Firmware upload response: {response[:500]}")

                # Check for error indicators
                if "error" in response.lower() and "success" not in response.lower():
                    logger.error(f"Firmware upload failed: {response[:200]}")
                    return False

                # Poll upload status until ready
                logger.info(f"Firmware uploaded, polling status...")
                ready = await self._poll_upload_status_curl(stok, cookie_file=cookie_path)

                if ready:
                    logger.info(f"Firmware ready on {self.ip} via {self.interface}")
                    return True
                else:
                    logger.warning(f"Firmware upload status unclear, assuming success")
                    return True
            else:
                # Clean up cookie file on error
                try:
                    import os
                    os.unlink(cookie_path)
                except Exception:
                    pass
                logger.error(f"Firmware upload curl failed: {stderr.decode()}")
                return False

        except Exception as e:
            logger.error(f"Failed to upload firmware via curl: {e}")
            return False

    async def _poll_upload_status_curl(self, stok: str, timeout: int = 300, cookie_file: Optional[str] = None) -> bool:
        """Poll /admin/get_upload_status until firmware is ready.

        Args:
            stok: Session token
            timeout: Max seconds to wait
            cookie_file: Path to cookie file for session auth

        Returns:
            True if firmware is ready, False if timeout or error
        """
        import time
        start_time = time.time()
        url = f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/get_upload_status"

        while time.time() - start_time < timeout:
            try:
                # Build curl command with optional cookies
                curl_args = [
                    "curl", "-s", "-k", "-m", "10",
                    "--interface", self.interface,
                    "-X", "POST",
                    "-d", "",
                ]
                if cookie_file:
                    curl_args.extend(["-b", cookie_file])
                curl_args.append(url)

                proc = await asyncio.create_subprocess_exec(
                    *curl_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()

                if proc.returncode == 0 and stdout:
                    response = stdout.decode("utf-8", errors="ignore")
                    logger.debug(f"Upload status: {response}")

                    try:
                        data = json.loads(response)
                        # Status 7 = firmware unpacked and ready for reboot (confirmed from Cambium web UI)
                        if data.get("status") == 7:
                            logger.info(f"Firmware unpacked and ready (status=7)")
                            return True
                        # Also check legacy indicators
                        if data.get("success") == 1 and data.get("status") in (7, "complete", "ready"):
                            return True
                        if data.get("percent") == 100 or data.get("progress") == 100:
                            return True
                        # Check for error (error field > 0 indicates failure)
                        if data.get("error") and data.get("error") != 0:
                            logger.error(f"Upload status error: {data}")
                            return False
                        # Log current status while waiting
                        current_status = data.get("status", "unknown")
                        logger.debug(f"Firmware unpack in progress (status={current_status})")
                    except json.JSONDecodeError:
                        pass

                await asyncio.sleep(2)

            except Exception as e:
                logger.debug(f"Status poll error: {e}")
                await asyncio.sleep(2)

        logger.warning(f"Upload status poll timed out after {timeout}s")
        return False

    async def get_firmware_status(self) -> Dict[str, Any]:
        """Get firmware bank status."""
        try:
            if not self._use_cgi:
                return await self._api_get(self.API_ENDPOINTS["firmware_status"])
            else:
                text = await self._cgi_get("/cgi-bin/firmware_status.cgi")
                try:
                    return json.loads(text)
                except:
                    return {"raw": text}
        except Exception as e:
            logger.error(f"Failed to get firmware status: {e}")
            return {}

    async def get_firmware_banks(self) -> Dict[str, str]:
        """Get firmware versions for both banks.

        Returns:
            Dict with 'bank1', 'bank2', and 'active' keys.
        """
        result = {"bank1": "unknown", "bank2": "unknown", "active": 1}

        try:
            # Use get_param endpoint (POST) which has both bank versions
            # Requires form body: act=config_regular&debug=true
            if self._use_cgi and self._stok:
                url = f"{self._base_url}/cgi-bin/luci/;stok={self._stok}/admin/get_param"
                cmd = [
                    "curl", "-s", "-k", "-m", "10",
                    "--interface", self.interface,
                    "-X", "POST",
                    "-H", "Content-Type: application/x-www-form-urlencoded",
                    "-d", "act=config_regular&debug=true",
                ]
                if self._cookie_file:
                    cmd.extend(["-b", self._cookie_file])
                cmd.append(url)
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()

                if stdout:
                    text = stdout.decode()
                    if not text.strip().startswith('<!DOCTYPE'):
                        try:
                            data = json.loads(text)
                            # Response wraps config in device_props
                            props = data.get("device_props", data)
                            # Log all version-related keys for debugging
                            version_keys = [k for k in props.keys() if 'version' in k.lower() or 'image' in k.lower()]
                            logger.debug(f"get_param version keys: {version_keys}")
                            for key in version_keys:
                                logger.debug(f"  {key} = {props.get(key)}")

                            # cambiumCurrentuImageVersion = active bank
                            # cambiumCurrentuImageIVersion = inactive bank (I = Inactive)
                            active_ver = props.get("cambiumCurrentuImageVersion")
                            inactive_ver = props.get("cambiumCurrentuImageIVersion")

                            if active_ver:
                                result["bank1"] = active_ver
                                # Only use active version as fallback if inactive is truly not available
                                if inactive_ver and inactive_ver != active_ver:
                                    result["bank2"] = inactive_ver
                                    logger.info(f"Firmware banks: active={active_ver}, inactive={inactive_ver}")
                                elif inactive_ver:
                                    result["bank2"] = inactive_ver
                                    logger.info(f"Firmware banks: both at {active_ver}")
                                else:
                                    # Inactive version not available - don't assume it's the same
                                    result["bank2"] = "unknown"
                                    logger.warning(f"Firmware banks: active={active_ver}, inactive=unknown (not in API response)")
                                result["active"] = 1
                        except json.JSONDecodeError:
                            logger.debug(f"get_param not JSON")

            # Fallback: use get_info for active bank
            if result["bank1"] == "unknown":
                info = await self.get_info()
                if info.firmware_version:
                    result["bank1"] = info.firmware_version
                    result["bank2"] = info.firmware_version  # Assume same
                    logger.info(f"Using get_info fallback: {info.firmware_version}")

        except Exception as e:
            logger.error(f"Failed to get firmware banks: {e}")

        return result

    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """No-op for Cambium ePMP — flash write happens during upload_firmware().

        The upload_firmware() flow is:
        1. POST to local_upload_image (uploads firmware file)
        2. Poll get_upload_status until status=7 (flash write completes during polling)

        After this returns, the firmware is written to flash and ready.
        A reboot (from base.py) will boot into the new bank.
        """
        bank_str = f" (bank {bank})" if bank else ""
        logger.info(f"Firmware already written to flash on {self.ip}{bank_str}, ready for reboot")
        return True

    async def reboot(self) -> bool:
        """Reboot the device."""
        # Use curl when interface binding is needed
        if self.interface:
            return await self._reboot_curl()

        try:
            if not self._use_cgi:
                await self._api_post(self.API_ENDPOINTS["reboot"])
            else:
                await self._cgi_post(self.CGI_ENDPOINTS["reboot"])

            logger.info(f"Reboot initiated on {self.ip}")
            return True

        except aiohttp.ClientError:
            # Connection may drop immediately - this is expected
            logger.info(f"Reboot initiated on {self.ip} (connection closed)")
            return True
        except Exception as e:
            logger.error(f"Failed to reboot: {e}")
            return False

    async def _send_bare_reboot(self) -> None:
        """Send a reboot command without requiring a valid session.

        Used when device is in reset_has_been_done state — firmware was flashed
        but device never rebooted. Tries multiple reboot URL patterns since we
        may not have a valid stok.
        """
        reboot_urls = []
        # Try with existing stok if we have one
        if self._stok:
            reboot_urls.append(f"{self._base_url}/cgi-bin/luci/;stok={self._stok}/admin/reboot")
        # Try without stok (some firmware versions accept it)
        reboot_urls.append(f"{self._base_url}/cgi-bin/luci/admin/reboot")
        # Try the bare /reboot endpoint
        reboot_urls.append(f"{self._base_url}/reboot")

        for url in reboot_urls:
            try:
                curl_args = [
                    "curl", "-s", "-k", "-m", "10",
                    "--interface", self.interface,
                    "-X", "POST",
                    "-d", "debug=true",
                ]
                if self._cookie_file:
                    curl_args.extend(["-b", self._cookie_file])
                curl_args.append(url)

                proc = await asyncio.create_subprocess_exec(
                    *curl_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                    if stdout:
                        resp = stdout.decode("utf-8", errors="ignore")
                        logger.info(f"Bare reboot response from {url}: {resp[:200]}")
                        if '"success":1' in resp or "success" in resp.lower():
                            logger.info(f"Bare reboot succeeded via {url}")
                            return
                except asyncio.TimeoutError:
                    logger.info(f"Bare reboot request timed out for {url} (device may be rebooting)")
                    return
            except Exception as e:
                logger.debug(f"Bare reboot attempt failed for {url}: {e}")

        logger.warning(f"All bare reboot attempts failed for {self.ip} — device may need manual reboot")

    async def _reboot_curl(self) -> bool:
        """Reboot device using curl with interface binding."""
        import tempfile

        try:
            logger.info(f"Rebooting {self.ip} via {self.interface}")

            cookie_path = None  # Only set if we create a new login session below

            # Reuse existing stok from connect() if available
            stok = self._stok
            if stok:
                logger.debug(f"Reusing existing stok for reboot: {stok[:16]}...")
            else:
                # No existing session, need to login via curl
                logger.debug(f"No existing stok, logging in via curl for reboot...")
                cookie_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
                cookie_path = cookie_file.name
                cookie_file.close()

                username = self.credentials.get("username", "admin")
                password = self.credentials.get("password", "admin")
                login_url = f"{self._base_url}/cgi-bin/luci"

                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-k", "-m", "10",
                    "--interface", self.interface,
                    "-c", cookie_path, "-b", cookie_path,
                    "-X", "POST",
                    "-d", f"username={username}&password={password}",
                    login_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode != 0:
                    logger.error(f"Login failed for reboot: {stderr.decode()}")
                    return False

                response = stdout.decode("utf-8", errors="ignore")
                try:
                    match = re.search(r'"stok":"([^"]+)"', response)
                    if match:
                        stok = match.group(1)
                        self._stok = stok  # Save for future use
                except Exception:
                    pass

                if not stok:
                    logger.error(f"Failed to get stok for reboot")
                    return False

                logger.debug(f"Got new stok: {stok[:16]}...")

            # Trigger reboot via /admin/reboot endpoint (with debug=true as per browser)
            url = f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/reboot"

            curl_args = [
                "curl", "-s", "-k", "-m", "10",
                "--interface", self.interface,
                "-X", "POST",
                "-d", "debug=true",
            ]
            # Must pass session cookies — stok in URL alone is not sufficient
            if self._cookie_file:
                curl_args.extend(["-b", self._cookie_file])
            elif cookie_path:
                curl_args.extend(["-b", cookie_path])
            curl_args.append(url)

            proc = await asyncio.create_subprocess_exec(
                *curl_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                if stdout:
                    response = stdout.decode("utf-8", errors="ignore")
                    logger.info(f"Reboot response: {response[:200]}")
            except asyncio.TimeoutError:
                # Expected - device is rebooting and drops connection
                logger.info(f"Reboot request timed out (expected — device is rebooting)")

            # Session will be invalid after reboot
            self._stok = None

            logger.info(f"Reboot initiated on {self.ip} via {self.interface}")
            return True

        except Exception as e:
            logger.error(f"Failed to reboot via curl: {e}")
            return False

    async def get_firmware_version(self) -> str:
        """Get current firmware version."""
        if not self._connected:
            await self.connect()

        info = await self.get_info()
        return info.firmware_version or "unknown"

    async def _get_link_speed(self) -> Optional[int]:
        """Get the current ethernet link speed in Mbps.

        Returns:
            Link speed in Mbps (e.g., 1000 for 1Gbps), or None if unable to detect.
        """
        if not self.interface:
            return None

        try:
            import platform
            system = platform.system()

            if system == "Linux":
                # Try reading from sysfs first (fastest)
                speed_path = f"/sys/class/net/{self.interface}/speed"
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "cat", speed_path,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await proc.communicate()
                    if proc.returncode == 0:
                        speed = int(stdout.decode().strip())
                        if speed > 0:
                            return speed
                except Exception:
                    pass

                # Fallback to ethtool
                proc = await asyncio.create_subprocess_exec(
                    "ethtool", self.interface,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    output = stdout.decode()
                    # Look for "Speed: 1000Mb/s" or similar
                    import re
                    match = re.search(r'Speed:\s*(\d+)Mb/s', output)
                    if match:
                        return int(match.group(1))

            elif system == "Darwin":
                # macOS: use networksetup or system_profiler
                # Try to get the hardware port name for the interface
                proc = await asyncio.create_subprocess_exec(
                    "networksetup", "-listallhardwareports",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    output = stdout.decode()
                    # Parse to find the hardware port for our interface
                    lines = output.split('\n')
                    hardware_port = None
                    for i, line in enumerate(lines):
                        if f"Device: {self.interface}" in line:
                            # Look back for Hardware Port line
                            for j in range(i-1, max(0, i-3), -1):
                                if "Hardware Port:" in lines[j]:
                                    hardware_port = lines[j].split("Hardware Port:")[1].strip()
                                    break
                            break

                    if hardware_port:
                        # Get media info
                        proc = await asyncio.create_subprocess_exec(
                            "networksetup", "-getMedia", hardware_port,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, _ = await proc.communicate()
                        if proc.returncode == 0:
                            output = stdout.decode()
                            # Look for "1000baseT" or "100baseTX" etc
                            if "1000base" in output:
                                return 1000
                            elif "100base" in output:
                                return 100
                            elif "10base" in output:
                                return 10

                # Fallback: use ifconfig and check status
                proc = await asyncio.create_subprocess_exec(
                    "ifconfig", self.interface,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0:
                    output = stdout.decode()
                    # Check media line for speed
                    if "1000baseT" in output or "1 Gb" in output:
                        return 1000
                    elif "100baseTX" in output or "100 Mb" in output:
                        return 100
                    elif "active" in output.lower():
                        # Link is up but speed unknown, assume 1Gbps
                        return 1000

        except Exception as e:
            logger.debug(f"Error getting link speed: {e}")

        return None

    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        """Wait for device to come back online after reboot.

        Waits for:
        1. Ping response (device is network-reachable)
        2. Web server responding (HTTP layer up)
        3. Login-ready (not mid-upgrade or initializing)

        Uses interface-bound ping and curl for VLAN-isolated provisioning ports.
        HAR analysis shows normal reboot takes ~51 seconds.

        Args:
            timeout: Maximum time to wait in seconds (default 180s / 3 minutes)
        """
        logger.info(f"Waiting for {self.ip} to reboot...")

        # Wait for device to go down
        await asyncio.sleep(10)

        start_time = asyncio.get_event_loop().time()
        phase = "ping"  # ping -> web -> login_ready

        while asyncio.get_event_loop().time() - start_time < timeout:
            elapsed = int(asyncio.get_event_loop().time() - start_time)

            if phase == "ping":
                if await self._ping_device():
                    logger.info(f"{self.ip} responding to ping after {elapsed}s, waiting for web server...")
                    phase = "web"
                    await asyncio.sleep(5)
                    continue

            elif phase == "web":
                if await self._check_web_server():
                    logger.info(f"{self.ip} web server is up after {elapsed}s, checking login-ready...")
                    phase = "login_ready"
                    await asyncio.sleep(3)
                    continue

            elif phase == "login_ready":
                ready, status = await self._check_login_ready()
                if ready:
                    logger.info(f"{self.ip} is login-ready after {elapsed}s")
                    return True
                elif status == "upgrade_in_progress":
                    logger.info(f"{self.ip} upgrade in progress post-reboot ({elapsed}s elapsed)...")
                    await asyncio.sleep(15)
                    continue
                else:
                    logger.info(f"{self.ip} not login-ready yet ({status}), waiting...")

            await asyncio.sleep(5)

        logger.error(f"{self.ip} did not come back online within {timeout}s")
        return False

    async def _check_login_ready(self) -> tuple:
        """Probe the login endpoint to check if the device is ready to accept logins.

        Returns:
            Tuple of (ready: bool, status: str) where status describes what we saw.
        """
        import tempfile
        try:
            login_url = f"{self._base_url}/cgi-bin/luci"
            username = self.credentials.get("username", "admin")
            password = self.credentials.get("password", "admin")

            if not self._cookie_file:
                cookie_fd = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
                self._cookie_file = cookie_fd.name
                cookie_fd.close()

            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-k", "-m", "10",
                "--interface", self.interface,
                "-c", self._cookie_file, "-b", self._cookie_file,
                "-X", "POST",
                "-H", "Content-Type: application/x-www-form-urlencoded",
                "-d", f"username={username}&password={password}",
                login_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0 or not stdout:
                return False, "no_response"

            response = stdout.decode("utf-8", errors="ignore").lower()

            if "sw_upgrade_is_in_progress" in response:
                return False, "upgrade_in_progress"

            if "auth_failed" in response:
                # After reboot, auth_failed could mean the device is still
                # initializing its auth subsystem. But it could also mean
                # credentials are wrong. We return True here because the
                # device IS responding to login attempts — connect() will
                # handle credential rotation properly.
                return True, "auth_responding"

            # Any other response (stok, password_change_required, lockout, etc.)
            # means the device is ready for a real login attempt
            return True, "ready"

        except Exception as e:
            logger.debug(f"Login-ready check failed: {e}")
            return False, f"error: {e}"

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
            cmd.append(f"{self._base_url}/")

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

    async def get_active_bank(self) -> int:
        """Get the currently active firmware bank."""
        try:
            status = await self.get_firmware_status()
            return status.get("activeBank", status.get("active_bank", 1))
        except Exception:
            return 1

    async def get_inactive_bank(self) -> int:
        """Get the inactive firmware bank number."""
        active = await self.get_active_bank()
        return 2 if active == 1 else 1

    async def set_device_name(self, name: str) -> bool:
        """Set device name."""
        return await self.apply_config({"system": {"deviceName": name}})

    async def set_management_ip(
        self,
        mode: str = "dhcp",
        ip: str = "",
        netmask: str = "",
        gateway: str = ""
    ) -> bool:
        """Set management IP configuration."""
        config = {
            "network": {
                "management": {
                    "ipMode": mode,
                    "ip": ip,
                    "netmask": netmask,
                    "gateway": gateway,
                }
            }
        }
        return await self.apply_config(config)

    async def set_password(self, new_password: str, username: str = None) -> bool:
        """Change the device password.

        Cambium ePMP devices support password change via the user management API
        or through configuration updates.

        Args:
            new_password: The new password to set.
            username: Username to change password for (defaults to 'admin').

        Returns:
            True if password changed successfully.
        """
        try:
            target_user = username or self.credentials.get("username", "admin")

            if not self._use_cgi:
                # Modern API - try user management endpoint
                try:
                    result = await self._api_post(
                        "/api/user/password",
                        {
                            "username": target_user,
                            "password": new_password,
                            "newPassword": new_password,
                        }
                    )
                    if result.get("status") == "ok" or result.get("success"):
                        logger.info(f"Password changed for {target_user} on {self.ip}")
                        return True
                except Exception:
                    pass

                # Try alternate API endpoint
                try:
                    result = await self._api_post(
                        "/api/system/password",
                        {
                            "username": target_user,
                            "oldPassword": self.credentials.get("password", ""),
                            "newPassword": new_password,
                        }
                    )
                    if result.get("status") == "ok" or result.get("success"):
                        logger.info(f"Password changed for {target_user} on {self.ip}")
                        return True
                except Exception:
                    pass

                # Try config-based approach
                try:
                    result = await self._api_post(
                        self.API_ENDPOINTS["config_set"],
                        {
                            "system": {
                                "users": [{
                                    "username": target_user,
                                    "password": new_password,
                                }]
                            }
                        }
                    )
                    if result.get("status") == "ok" or result.get("success"):
                        logger.info(f"Password changed via config for {target_user} on {self.ip}")
                        return True
                except Exception:
                    pass

            else:
                # CGI mode - use form-based password change
                try:
                    result = await self._cgi_post(
                        "/cgi-bin/password.cgi",
                        {
                            "username": target_user,
                            "old_password": self.credentials.get("password", ""),
                            "new_password": new_password,
                            "confirm_password": new_password,
                        }
                    )
                    if "success" in result.lower() or "changed" in result.lower():
                        logger.info(f"Password changed for {target_user} on {self.ip}")
                        return True
                except Exception:
                    pass

                # Try alternate CGI endpoint
                try:
                    result = await self._cgi_post(
                        "/cgi-bin/luci/admin/system/password",
                        {
                            "cbid.system._pass.pw1": new_password,
                            "cbid.system._pass.pw2": new_password,
                        }
                    )
                    if "success" in result.lower() or "200" in result:
                        logger.info(f"Password changed for {target_user} on {self.ip}")
                        return True
                except Exception:
                    pass

            logger.error(f"Failed to change password on {self.ip}")
            return False

        except Exception as e:
            logger.error(f"Failed to change password: {e}")
            return False

    async def apply_ap_naming(self, hostname: str, ssid: str) -> bool:
        """Apply AP naming via set_param.

        Sets wirelessInterfaceSSID, snmpSystemName, and systemConfigDeviceName
        directly through the set_param endpoint. No reboot required.

        Args:
            hostname: Hostname to set (e.g., "tw24-north")
            ssid: SSID to set (e.g., "tw24-north" for Cambium)

        Returns:
            True if config applied successfully
        """
        logger.info(f"Applying AP naming to {self.ip}: hostname={hostname}, ssid={ssid}")

        try:
            props = {
                "wirelessInterfaceSSID": ssid,
                "snmpSystemName": hostname,
                "systemConfigDeviceName": hostname,
            }
            return await self._apply_config_settings_curl(props)

        except Exception as e:
            logger.error(f"Failed to apply AP naming: {e}")
            return False

    async def verify_config(self, expected_values: Optional[Dict[str, Any]] = None) -> bool:
        """Verify that configuration was applied correctly.

        Cambium config apply via native template (set_param) does NOT trigger
        a reboot — the config is applied in-place. So we skip the wait-for-down
        phase entirely and read config directly using the existing session.

        Falls back to disconnect/reconnect if the existing session is stale.

        Args:
            expected_values: Optional dict of field names to expected values.

        Returns:
            True if config verification passed.
        """
        logger.info(f"[CONFIG VERIFY] Verifying Cambium config on {self.ip}")

        # Build expected_values from last applied config if not provided
        if not expected_values and self._last_applied_config:
            expected_values = {}
            # Map device_props keys to the field names _check_config_values expects
            key_map = {
                "wirelessInterfaceSSID": "ssid",
                "snmpSystemName": "hostname",
                "systemConfigDeviceName": "devicename",
            }
            for prop_key, verify_key in key_map.items():
                if prop_key in self._last_applied_config:
                    expected_values[verify_key] = self._last_applied_config[prop_key]
            if expected_values:
                logger.info(f"[CONFIG VERIFY] Built expected values from last applied config: {expected_values}")

        # Try reading config with the existing session first (no reboot expected)
        if self._stok and self._cookie_file:
            logger.info(f"[CONFIG VERIFY] Trying existing session for config read")
            config = await self._get_config_curl()
            if isinstance(config, dict) and config:
                return self._check_config_values(config, expected_values)
            logger.warning(f"[CONFIG VERIFY] Existing session failed, will reconnect")

        # Fallback: disconnect and reconnect with credential rotation
        await self.disconnect()

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                logger.info(f"[CONFIG VERIFY] Login attempt {attempt}/{max_attempts} for {self.ip}")
                if not await self.connect():
                    login_err = self.login_error or ""
                    auth_keywords = ["credentials", "password", "locked", "session", "unauthorized"]
                    if any(kw in login_err.lower() for kw in auth_keywords):
                        logger.error(f"[CONFIG VERIFY] Auth/lockout error, stopping retries: {login_err}")
                        return False
                    logger.warning(f"[CONFIG VERIFY] Reconnect attempt {attempt} failed: {login_err}")
                    if attempt < max_attempts:
                        await asyncio.sleep(10)
                    continue

                config = await self._get_config_curl()

                if not isinstance(config, dict) or not config:
                    logger.warning(f"[CONFIG VERIFY] Attempt {attempt}: failed to read config from {self.ip}")
                    await self.disconnect()
                    if attempt < max_attempts:
                        await asyncio.sleep(10)
                    continue

                return self._check_config_values(config, expected_values)

            except Exception as e:
                logger.warning(f"[CONFIG VERIFY] Attempt {attempt} error: {e}")
                await self.disconnect()
                if attempt < max_attempts:
                    await asyncio.sleep(10)

        logger.error(f"[CONFIG VERIFY] All {max_attempts} login attempts failed for {self.ip}")
        return False

    def _check_config_values(self, config: Dict[str, Any], expected_values: Optional[Dict[str, Any]] = None) -> bool:
        """Check config dict against expected values. Returns True if OK."""
        actual_ssid = config.get("wirelessInterfaceSSID")
        actual_snmp_name = config.get("snmpSystemName")
        actual_device_name = config.get("systemConfigDeviceName")

        logger.info(f"[CONFIG VERIFY] Read back: ssid={actual_ssid}, snmpName={actual_snmp_name}, deviceName={actual_device_name}")

        if expected_values:
            for field, expected in expected_values.items():
                if field == "ssid" and actual_ssid != expected:
                    logger.error(f"[CONFIG VERIFY] SSID mismatch: expected {expected}, got {actual_ssid}")
                    return False
                elif field == "hostname" and actual_snmp_name != expected:
                    logger.error(f"[CONFIG VERIFY] snmpSystemName mismatch: expected {expected}, got {actual_snmp_name}")
                    return False
                elif field == "devicename" and actual_device_name != expected:
                    logger.error(f"[CONFIG VERIFY] deviceName mismatch: expected {expected}, got {actual_device_name}")
                    return False

            logger.info(f"[CONFIG VERIFY] All expected values verified successfully")
        else:
            logger.info(f"[CONFIG VERIFY] Config readable, no specific values to verify")

        return True

    async def _get_config_curl(self) -> Dict[str, Any]:
        """Read device config using curl with interface binding.

        Uses the get_param endpoint which returns full config as JSON.
        Requires an active stok session from connect().

        The endpoint requires form body: act=config_regular&debug=true
        Response format: {"success":"1", "device_props": {...}, "template_props": {...}, ...}
        Returns the device_props dict (flat key/value config).
        """
        if not self._stok:
            logger.warning(f"[CONFIG VERIFY] No stok available for config read")
            return {}

        url = f"{self._base_url}/cgi-bin/luci/;stok={self._stok}/admin/get_param"
        cmd = [
            "curl", "-s", "-k", "-m", "10",
            "--interface", self.interface,
            "-b", self._cookie_file,
            "-X", "POST",
            "-H", "Content-Type: application/x-www-form-urlencoded",
            "-d", "act=config_regular&debug=true",
            url
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0 and stdout:
                text = stdout.decode("utf-8", errors="ignore")
                stripped = text.strip()
                if stripped.startswith("<?xml") or stripped.startswith("<!DOCTYPE") or stripped.startswith("<html"):
                    logger.warning(f"[CONFIG VERIFY] get_param returned HTML/XML error page")
                    return {}
                try:
                    data = json.loads(text)
                    # Response wraps config in device_props
                    device_props = data.get("device_props", {})
                    if device_props:
                        logger.info(f"[CONFIG VERIFY] Config read OK, {len(device_props)} keys in device_props")
                        return device_props
                    # Fallback: maybe flat keys at top level
                    if data.get("success") == "1" or data.get("success") == 1:
                        logger.info(f"[CONFIG VERIFY] Config read OK, {len(data)} top-level keys")
                        return data
                    logger.warning(f"[CONFIG VERIFY] get_param response missing device_props: {list(data.keys())[:10]}")
                    return {}
                except json.JSONDecodeError:
                    logger.warning(f"[CONFIG VERIFY] get_param returned non-JSON: {text[:200]}")
                    return {}
            else:
                logger.warning(f"[CONFIG VERIFY] curl get_param failed: rc={proc.returncode}, stderr={stderr.decode() if stderr else ''}")
                return {}
        except Exception as e:
            logger.error(f"[CONFIG VERIFY] _get_config_curl error: {e}")
            return {}
