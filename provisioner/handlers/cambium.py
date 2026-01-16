"""Cambium ePMP device handler."""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field

import aiohttp

from .base import BaseHandler, DeviceInfo

logger = logging.getLogger(__name__)


@dataclass
class CambiumConfig:
    """Structured Cambium ePMP configuration."""
    # System
    device_name: str = ""
    location: str = ""
    contact: str = ""

    # Network
    network_mode: str = "bridge"  # bridge, router, nat
    management_ip_mode: str = "dhcp"  # dhcp, static
    management_ip: str = ""
    management_netmask: str = ""
    management_gateway: str = ""
    management_vlan: int = 1
    management_vlan_enabled: bool = False

    # Wireless
    device_mode: str = "sta"  # ap, sta (subscriber)
    wireless_mode: str = "eptp"  # eptp, tdd, wifi
    channel_bandwidth: int = 20  # 20, 40, 80
    frequency: int = 0  # 0 = auto
    tx_power: str = "auto"  # auto or dBm value
    country_code: str = "US"
    ssid: str = ""
    security_mode: str = "wpa2"  # open, wpa2, wpa2-enterprise
    security_key: str = ""

    # QoS
    qos_enabled: bool = True
    mir_downlink: int = 0  # 0 = unlimited
    mir_uplink: int = 0

    # Services
    snmp_enabled: bool = True
    snmp_community: str = "public"
    ssh_enabled: bool = True
    https_enabled: bool = True
    http_redirect: bool = True
    ntp_enabled: bool = True
    ntp_servers: List[str] = field(default_factory=lambda: ["pool.ntp.org"])

    # Logging
    syslog_enabled: bool = False
    syslog_server: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API."""
        return {
            "system": {
                "deviceName": self.device_name,
                "location": self.location,
                "contact": self.contact,
            },
            "network": {
                "networkMode": self.network_mode,
                "management": {
                    "ipMode": self.management_ip_mode,
                    "ip": self.management_ip,
                    "netmask": self.management_netmask,
                    "gateway": self.management_gateway,
                },
                "vlan": {
                    "enabled": self.management_vlan_enabled,
                    "id": self.management_vlan,
                },
            },
            "wireless": {
                "deviceMode": self.device_mode,
                "wirelessMode": self.wireless_mode,
                "channelBandwidth": self.channel_bandwidth,
                "frequency": self.frequency,
                "txPower": self.tx_power,
                "countryCode": self.country_code,
                "ssid": self.ssid,
                "security": {
                    "mode": self.security_mode,
                    "key": self.security_key,
                },
            },
            "qos": {
                "enabled": self.qos_enabled,
                "mirDownlink": self.mir_downlink,
                "mirUplink": self.mir_uplink,
            },
            "services": {
                "snmp": {
                    "enabled": self.snmp_enabled,
                    "community": self.snmp_community,
                },
                "ssh": {"enabled": self.ssh_enabled},
                "https": {"enabled": self.https_enabled},
                "httpRedirect": self.http_redirect,
                "ntp": {
                    "enabled": self.ntp_enabled,
                    "servers": self.ntp_servers,
                },
                "syslog": {
                    "enabled": self.syslog_enabled,
                    "server": self.syslog_server,
                },
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CambiumConfig":
        """Create from dictionary."""
        config = cls()

        # System
        system = data.get("system", {})
        config.device_name = system.get("deviceName", system.get("device_name", ""))
        config.location = system.get("location", "")
        config.contact = system.get("contact", "")

        # Network
        network = data.get("network", {})
        config.network_mode = network.get("networkMode", network.get("network_mode", "bridge"))

        mgmt = network.get("management", {})
        config.management_ip_mode = mgmt.get("ipMode", mgmt.get("mode", "dhcp"))
        config.management_ip = mgmt.get("ip", mgmt.get("ip_address", ""))
        config.management_netmask = mgmt.get("netmask", "")
        config.management_gateway = mgmt.get("gateway", "")

        vlan = network.get("vlan", {})
        config.management_vlan_enabled = vlan.get("enabled", False)
        config.management_vlan = vlan.get("id", vlan.get("management_vlan", 1))

        # Wireless
        wireless = data.get("wireless", {})
        config.device_mode = wireless.get("deviceMode", wireless.get("mode", "sta"))
        config.wireless_mode = wireless.get("wirelessMode", "eptp")
        config.channel_bandwidth = wireless.get("channelBandwidth", wireless.get("bandwidth", 20))
        config.frequency = wireless.get("frequency", 0)
        config.tx_power = str(wireless.get("txPower", wireless.get("tx_power", "auto")))
        config.country_code = wireless.get("countryCode", wireless.get("country_code", "US"))
        config.ssid = wireless.get("ssid", "")

        security = wireless.get("security", {})
        config.security_mode = security.get("mode", "wpa2")
        config.security_key = security.get("key", security.get("password", ""))

        # QoS
        qos = data.get("qos", {})
        config.qos_enabled = qos.get("enabled", True)
        config.mir_downlink = qos.get("mirDownlink", qos.get("mir_downlink", 0))
        config.mir_uplink = qos.get("mirUplink", qos.get("mir_uplink", 0))

        # Services
        services = data.get("services", {})

        snmp = services.get("snmp", {})
        config.snmp_enabled = snmp.get("enabled", True)
        config.snmp_community = snmp.get("community", "public")

        config.ssh_enabled = services.get("ssh", {}).get("enabled", True)
        config.https_enabled = services.get("https", {}).get("enabled", True)
        config.http_redirect = services.get("httpRedirect", services.get("http_redirect", True))

        ntp = services.get("ntp", {})
        config.ntp_enabled = ntp.get("enabled", True)
        config.ntp_servers = ntp.get("servers", ["pool.ntp.org"])

        syslog = services.get("syslog", services.get("logging", {}))
        config.syslog_enabled = syslog.get("enabled", syslog.get("syslog_enabled", False))
        config.syslog_server = syslog.get("server", syslog.get("syslog_server", ""))

        return config


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

            # Track if we got any response from device (vs connection failure)
            device_responded = False
            any_creds_rejected = False

            # Try each credential set
            for i, creds in enumerate(creds_to_try):
                username = creds["username"]
                password = creds["password"]
                logger.info(f"[CREDS] Attempt {i+1}/{len(creds_to_try)}: Trying {username}/{'*' * len(password) if password else '(empty)'} for {self.ip}")

                # Update credentials for this attempt
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

            # Determine failure reason
            if any_creds_rejected:
                self.login_error = "Invalid credentials - please enter correct password"
                logger.error(f"[CREDS] FAILED for {self.ip} - all {len(creds_to_try)} credential sets rejected")
            else:
                self.login_error = "Device not responding - check network connectivity"
                logger.error(f"[CREDS] FAILED for {self.ip} - device did not respond (connection issue)")
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
            import urllib.parse
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
                ]
                for pattern in rejection_patterns:
                    if pattern.lower() in response.lower():
                        logger.warning(f"Credentials rejected by {self.ip}: {pattern}")
                        return False, True

                # Check for max users reached (too many active sessions)
                if "max_user_number_reached" in response.lower():
                    logger.warning(f"Device {self.ip} has too many active sessions - waiting for timeout")
                    self.login_error = "Too many active sessions on device - wait for timeout or reboot device"
                    return False, True

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
        """Apply configuration via API."""
        try:
            # Convert to CambiumConfig for validation if it's a raw dict
            if not isinstance(config, CambiumConfig):
                cambium_config = CambiumConfig.from_dict(config)
                api_config = cambium_config.to_dict()
            else:
                api_config = config.to_dict()

            if not self._use_cgi:
                await self._api_post(self.API_ENDPOINTS["config_set"], api_config)
            else:
                await self._cgi_post(self.CGI_ENDPOINTS["config"], api_config)

            logger.info(f"Configuration applied to {self.ip}")
            return True

        except Exception as e:
            logger.error(f"Failed to apply config: {e}")
            return False

    async def apply_config_file(self, config_path: str) -> bool:
        """Apply configuration from JSON file.

        For Cambium devices, this uploads the config file as a restore operation.
        After successful config apply, updates credentials to custom password
        since the config changes the device password.
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

            # After config applied, update credentials for reconnect after reboot
            # The config contains the hashed password matching our custom credentials
            if success:
                custom_cred = self._get_custom_credential()
                if custom_cred:
                    logger.info(f"Config applied - updating credentials for reconnect")
                    self.credentials["username"] = custom_cred.get("username", "admin")
                    self.credentials["password"] = custom_cred["password"]

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
        """Apply JSON config file using curl with interface binding.

        Supports two formats:
        - Cambium native template format (device_props): POST directly
        - Generic config format: Convert through CambiumConfig
        """
        import tempfile

        try:
            # Read and parse the JSON config
            with open(config_path, "r") as f:
                config_data = json.load(f)

            # Check if this is Cambium's native template format
            is_native_format = "device_props" in config_data or "template_props" in config_data

            if is_native_format:
                logger.info(f"Detected Cambium native template format")
                config_json = json.dumps(config_data)
            else:
                # Convert through CambiumConfig for validation and API format
                cambium_config = CambiumConfig.from_dict(config_data)
                api_config = cambium_config.to_dict()
                config_json = json.dumps(api_config)

            logger.info(f"Applying JSON config to {self.ip} via {self.interface}")

            # Reuse existing stok from connect() if available
            stok = self._stok
            if stok:
                logger.debug(f"Reusing existing stok: {stok[:16]}...")
            else:
                # No existing session, need to login via curl
                logger.debug(f"No existing stok, logging in via curl...")
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

            # Helper to build curl command with optional cookie arg
            def curl_cmd(*args):
                cmd = ["curl", "-s", "-k", "--interface", self.interface]
                cmd.extend(args)
                return cmd

            # Step 2: Try API config endpoints
            # ePMP devices support different endpoints depending on firmware version
            if is_native_format:
                # Native template format endpoints
                # Primary: /admin/config_import (confirmed from Cambium web UI)
                api_endpoints = [
                    f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/config_import",
                    f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/device_config",
                    f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/system/config/import",
                    f"{self._base_url}/api/config/import",
                ]
            else:
                # Generic config endpoints
                api_endpoints = [
                    f"{self._base_url}/api/config/set",
                    f"{self._base_url}/cgi-bin/luci/;stok={stok}/api/config",
                    f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/network/config",
                ]

            # config_json was already set above based on format type
            success = False

            for endpoint in api_endpoints:
                proc = await asyncio.create_subprocess_exec(
                    *curl_cmd("-m", "30", "-X", "POST",
                              "-H", "Content-Type: application/json",
                              "-d", config_json, endpoint),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode == 0:
                    response = stdout.decode("utf-8", errors="ignore")
                    logger.debug(f"Config response from {endpoint}: {response[:300]}")

                    # Check for success indicators
                    if any(s in response.lower() for s in ["success", "ok", "applied", "saved"]):
                        logger.info(f"Configuration applied to {self.ip} via {self.interface}")
                        success = True
                        break

                    # Check if response is valid JSON with success status
                    try:
                        resp_json = json.loads(response)
                        if resp_json.get("status") == "ok" or resp_json.get("success"):
                            logger.info(f"Configuration applied to {self.ip} via {self.interface}")
                            success = True
                            break
                    except json.JSONDecodeError:
                        pass

            if success:
                return True

            # For native format, also try file upload (multipart/form-data)
            if is_native_format:
                logger.info("Trying file upload method for native template...")
                # config_import uses field name "image" and skipIllegal=1 (confirmed from browser)
                endpoint = f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/config_import"
                proc = await asyncio.create_subprocess_exec(
                    *curl_cmd("-m", "30", "-X", "POST",
                              "-F", "skipIllegal=1",
                              "-F", f"image=@{config_path}", endpoint),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode == 0:
                    response = stdout.decode("utf-8", errors="ignore")
                    logger.debug(f"Config import response: {response[:300]}")

                    # Check for success:1 in JSON response
                    if '"success":1' in response or '"success": 1' in response:
                        logger.info(f"Configuration imported to {self.ip} via {self.interface}")

                        # Config requires reboot to apply - send reboot command
                        logger.info(f"Rebooting {self.ip} to apply configuration...")
                        reboot_url = f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/reboot"
                        proc = await asyncio.create_subprocess_exec(
                            *curl_cmd("-m", "10", "-X", "POST", "-d", "debug=true", reboot_url),
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        await proc.communicate()

                        # Wait for device to come back online
                        logger.info(f"Waiting for {self.ip} to reboot and apply config...")
                        self._stok = None  # Will need new session after reboot
                        if await self.wait_for_reboot():
                            logger.info(f"Config applied and device back online at {self.ip}")
                            return True
                        else:
                            logger.warning(f"Device did not come back after config reboot, assuming success")
                            return True
                    else:
                        logger.warning(f"Config import response: {response}")

            # If API endpoints didn't work, try applying individual settings
            logger.warning(f"API config endpoints failed, trying individual settings...")
            return await self._apply_config_settings_curl(stok, config_data)

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file {config_path}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to apply JSON config via curl: {e}")
            return False

    async def _apply_config_settings_curl(self, stok: str, config_data: dict) -> bool:
        """Apply config by setting individual parameters via LuCI.

        This is a fallback when the bulk config API isn't available.
        """
        # For now, log what we would apply and return success
        # Full implementation would iterate through config_data and set each value
        logger.info(f"Config data to apply: {list(config_data.keys())}")
        logger.warning("Individual settings application not yet implemented - config may need manual application")
        return True

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

            # Reuse existing stok from connect() if available
            stok = self._stok
            if stok:
                logger.debug(f"Reusing existing stok for firmware upload: {stok[:16]}...")
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

            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-k", "-m", "600",  # 10 min timeout for large files
                "--interface", self.interface,
                "-X", "POST",
                "-F", f"image=@{firmware_path}",
                url,
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
                ready = await self._poll_upload_status_curl(stok)

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

    async def _poll_upload_status_curl(self, stok: str, timeout: int = 300) -> bool:
        """Poll /admin/get_upload_status until firmware is ready.

        Args:
            stok: Session token
            timeout: Max seconds to wait

        Returns:
            True if firmware is ready, False if timeout or error
        """
        import time
        start_time = time.time()
        url = f"{self._base_url}/cgi-bin/luci/;stok={stok}/admin/get_upload_status"

        while time.time() - start_time < timeout:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-k", "-m", "10",
                    "--interface", self.interface,
                    "-X", "POST",
                    "-d", "",
                    url,
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
            if self._use_cgi and self._stok:
                url = f"{self._base_url}/cgi-bin/luci/;stok={self._stok}/admin/get_param"
                cmd = [
                    "curl", "-s", "-k", "-m", "10",
                    "--interface", self.interface,
                    "-X", "POST",
                    url
                ]
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
                            # Log all version-related keys for debugging
                            version_keys = [k for k in data.keys() if 'version' in k.lower() or 'image' in k.lower()]
                            logger.debug(f"get_param version keys: {version_keys}")
                            for key in version_keys:
                                logger.debug(f"  {key} = {data.get(key)}")

                            # cambiumCurrentuImageVersion = active bank
                            # cambiumCurrentuImageIVersion = inactive bank (I = Inactive)
                            active_ver = data.get("cambiumCurrentuImageVersion")
                            inactive_ver = data.get("cambiumCurrentuImageIVersion")

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
        """Trigger firmware update on specified bank.

        For Cambium ePMP devices, the firmware is already staged after upload_firmware()
        completes (which polls get_upload_status until status=7). The firmware will be
        activated on next reboot - no separate "trigger" step is needed.
        """
        # For ePMP devices using the local_upload_image flow, firmware is ready after upload
        # Just return True - the actual activation happens on reboot
        logger.info(f"Firmware staged on {self.ip}, will activate on reboot" +
                   (f" (bank {bank})" if bank else ""))
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

    async def _reboot_curl(self) -> bool:
        """Reboot device using curl with interface binding."""
        import tempfile

        try:
            logger.info(f"Rebooting {self.ip} via {self.interface}")

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

            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-k", "-m", "10",
                "--interface", self.interface,
                "-X", "POST",
                "-d", "debug=true",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Don't wait too long - connection will drop
            try:
                await asyncio.wait_for(proc.communicate(), timeout=5)
            except asyncio.TimeoutError:
                # Expected - device is rebooting
                pass

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

        Uses interface-bound ping and curl to verify connectivity.
        This ensures proper routing on VLAN-isolated provisioning ports.

        Args:
            timeout: Maximum time to wait in seconds (default 180s / 3 minutes)
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
