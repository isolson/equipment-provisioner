"""Handler manager for routing devices to appropriate handlers."""

import logging
from typing import Dict, Optional, Type, Callable, Awaitable

from .fingerprint import DeviceType, DeviceFingerprint
from .handlers.base import BaseHandler, ProvisioningResult
from .handlers.mikrotik import MikrotikHandler
from .handlers.cambium import CambiumHandler
from .handlers.tachyon import TachyonHandler
from .handlers.tarana import TaranaHandler

logger = logging.getLogger(__name__)


class HandlerManager:
    """Manages device handlers and routes provisioning requests."""

    # Map device types to handler classes
    HANDLER_MAP: Dict[DeviceType, Type[BaseHandler]] = {
        DeviceType.MIKROTIK: MikrotikHandler,
        DeviceType.CAMBIUM: CambiumHandler,
        DeviceType.TACHYON: TachyonHandler,
        DeviceType.TARANA: TaranaHandler,
    }

    def __init__(self, credentials: Dict[str, Dict[str, str]],
                 alternate_credentials: Dict[str, list] = None):
        """Initialize the handler manager.

        Args:
            credentials: Dict mapping device type to credentials dict.
                         e.g., {"mikrotik": {"username": "admin", "password": "pass"}}
            alternate_credentials: Dict mapping device type to list of alternate credential dicts.
                         e.g., {"tachyon": [{"username": "root", "password": "custom"}]}
        """
        self.credentials = credentials
        self.alternate_credentials = alternate_credentials or {}

    def get_handler(
        self,
        fingerprint: DeviceFingerprint,
        ip: str,
        interface: Optional[str] = None,
        custom_credentials: Optional[Dict[str, str]] = None,
    ) -> Optional[BaseHandler]:
        """Get the appropriate handler for a device.

        Args:
            fingerprint: Device fingerprint with type information.
            ip: IP address of the device.
            interface: Network interface to bind to (e.g., 'eth0.1994').
            custom_credentials: Optional credentials from UI override.

        Returns:
            Handler instance or None if device type not supported.
        """
        device_type = fingerprint.device_type

        if device_type == DeviceType.UNKNOWN:
            logger.warning(f"Cannot provision unknown device at {ip}")
            return None

        handler_class = self.HANDLER_MAP.get(device_type)
        if not handler_class:
            logger.warning(f"No handler for device type {device_type.value}")
            return None

        # Get credentials for this device type
        # If custom credentials provided via UI, use those as primary
        if custom_credentials:
            creds = custom_credentials.copy()
            logger.info(f"Using custom credentials from UI for {device_type.value}")
        else:
            creds = self.credentials.get(device_type.value, {})
            if not creds:
                logger.warning(f"No credentials configured for {device_type.value}")
                creds = {"username": "admin", "password": ""}

        # Get alternate credentials if available
        alt_creds = self.alternate_credentials.get(device_type.value, [])

        # Pass alternate credentials to handlers that support it
        if hasattr(handler_class, 'DEFAULT_CREDENTIALS'):
            return handler_class(ip=ip, credentials=creds, interface=interface,
                                alternate_credentials=alt_creds)
        return handler_class(ip=ip, credentials=creds, interface=interface)

    def get_supported_types(self) -> list[str]:
        """Get list of supported device types."""
        return [dt.value for dt in self.HANDLER_MAP.keys()]

    async def provision_device(
        self,
        fingerprint: DeviceFingerprint,
        ip: str,
        config: Optional[Dict] = None,
        config_path: Optional[str] = None,
        firmware_path: Optional[str] = None,
        expected_firmware: Optional[str] = None,
        dual_bank: bool = True,
        interface: Optional[str] = None,
        firmware_current: bool = False,
        on_progress: Optional[Callable[[str, bool, Optional[str]], Awaitable[None]]] = None,
        firmware_lookup_callback: Optional[Callable[[str, str], tuple]] = None,
        custom_credentials: Optional[Dict[str, str]] = None,
    ) -> ProvisioningResult:
        """Provision a device with configuration and/or firmware.

        Args:
            fingerprint: Device fingerprint.
            ip: Device IP address.
            config: Configuration dictionary.
            config_path: Path to configuration file.
            firmware_path: Path to firmware file.
            expected_firmware: Expected firmware version after update.
            dual_bank: Whether to update both firmware banks.
            interface: Network interface to bind to (e.g., 'eth0.1994').
            firmware_current: If True, firmware is already current (skip updates).
            on_progress: Optional callback for progress updates (step, success, detail).
            firmware_lookup_callback: Callback to re-lookup firmware by (device_type, model).

        Returns:
            ProvisioningResult with outcome details.
        """
        handler = self.get_handler(fingerprint, ip, interface=interface,
                                    custom_credentials=custom_credentials)

        if not handler:
            return ProvisioningResult(
                success=False,
                error_message=f"No handler for device type {fingerprint.device_type.value}"
            )

        logger.info(f"Starting provisioning for {fingerprint.device_type.value} at {ip}")

        result = await handler.provision(
            config=config,
            config_path=config_path,
            firmware_path=firmware_path,
            expected_firmware=expected_firmware,
            dual_bank=dual_bank,
            firmware_current=firmware_current,
            on_progress=on_progress,
            firmware_lookup_callback=firmware_lookup_callback,
        )

        if result.success:
            logger.info(f"Successfully provisioned {fingerprint.device_type.value} at {ip}")
        else:
            logger.error(f"Failed to provision {ip}: {result.error_message}")

        return result

    async def login_and_get_info(
        self,
        fingerprint: DeviceFingerprint,
        ip: str,
        interface: Optional[str] = None,
    ) -> ProvisioningResult:
        """DEBUG: Only connect, login, and get device info - no config or firmware.

        This is for debugging login/connection issues without risking config changes.

        Args:
            fingerprint: Device fingerprint.
            ip: Device IP address.
            interface: Network interface to bind to (e.g., 'eth0.1994').

        Returns:
            ProvisioningResult with device info or error.
        """
        from datetime import datetime
        from .handlers.base import ProvisioningPhase

        handler = self.get_handler(fingerprint, ip, interface=interface)

        if not handler:
            return ProvisioningResult(
                success=False,
                error_message=f"No handler for device type {fingerprint.device_type.value}"
            )

        result = ProvisioningResult(
            success=False,
            started_at=datetime.now(),
            phases_completed=[],
        )

        logger.info(f"DEBUG: Login-only test for {fingerprint.device_type.value} at {ip} via {interface}")

        try:
            # Connect (login)
            if not await handler.connect():
                result.error_message = getattr(handler, 'login_error', None) or "Failed to connect to device"
                result.needs_credentials = "credentials" in result.error_message.lower() or "password" in result.error_message.lower()
                logger.error(f"DEBUG: Login failed - {result.error_message}")
                return result
            result.phases_completed.append(ProvisioningPhase.CONNECTING)
            logger.info(f"DEBUG: Login successful for {fingerprint.device_type.value} at {ip}")

            # Get device info
            try:
                result.device_info = await handler.get_info()
                result.old_firmware = result.device_info.firmware_version
                result.phases_completed.append(ProvisioningPhase.GATHERING_INFO)
                logger.info(f"DEBUG: Got device info - model: {result.device_info.model}, "
                           f"firmware: {result.device_info.firmware_version}, "
                           f"MAC: {result.device_info.mac_address}")
            except Exception as e:
                logger.warning(f"DEBUG: get_info failed: {e}")

            # Success - we connected and got info (but NOT provisioned)
            result.success = True
            result.config_applied = "DEBUG: login only"  # Mark as debug mode
            result.phases_completed.append(ProvisioningPhase.GATHERING_INFO)  # Don't add COMPLETED
            logger.info(f"DEBUG: Login-only test PASSED for {fingerprint.device_type.value} at {ip}")

        except Exception as e:
            result.error_message = str(e)
            result.phases_completed.append(ProvisioningPhase.FAILED)
            logger.exception(f"DEBUG: Error during login test")

        finally:
            result.completed_at = datetime.now()
            await handler.disconnect()

        return result
