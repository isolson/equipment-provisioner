"""Abstract base handler for network device provisioning."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, Callable, Awaitable


class ProvisioningPhase(str, Enum):
    """Current phase of the provisioning process."""
    CONNECTING = "connecting"
    GATHERING_INFO = "gathering_info"
    BACKING_UP = "backing_up"
    CHANGING_PASSWORD = "changing_password"
    CONFIGURING = "configuring"
    UPLOADING_FIRMWARE = "uploading_firmware"
    UPDATING_FIRMWARE = "updating_firmware"
    REBOOTING = "rebooting"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class DeviceInfo:
    """Information about a connected device."""
    device_type: str
    model: Optional[str] = None
    serial_number: Optional[str] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    firmware_version: Optional[str] = None
    hardware_version: Optional[str] = None
    uptime: Optional[int] = None  # seconds
    ip_address: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvisioningResult:
    """Result of a provisioning operation."""
    success: bool
    device_info: Optional[DeviceInfo] = None
    old_firmware: Optional[str] = None
    new_firmware: Optional[str] = None
    config_applied: Optional[str] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    phases_completed: list[ProvisioningPhase] = field(default_factory=list)
    needs_credentials: bool = False  # True if provisioning failed due to invalid credentials


class BaseHandler(ABC):
    """Abstract base class for device handlers.

    Each device type (Mikrotik, Cambium, etc.) implements this interface
    to provide provisioning functionality.
    """

    def __init__(self, ip: str, credentials: Dict[str, str], interface: Optional[str] = None):
        """Initialize the handler.

        Args:
            ip: IP address of the device
            credentials: Dict with 'username' and 'password' keys
            interface: Network interface to bind to (e.g., 'eth0.1994')
        """
        self.ip = ip
        self.credentials = credentials
        self.interface = interface
        self._connected = False
        self._device_info: Optional[DeviceInfo] = None

    @property
    def device_type(self) -> str:
        """Return the device type identifier."""
        raise NotImplementedError

    @property
    def is_connected(self) -> bool:
        """Check if currently connected to the device."""
        return self._connected

    @abstractmethod
    async def connect(self) -> bool:
        """Connect to the device.

        Returns:
            True if connection successful, False otherwise.
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the device."""
        pass

    @abstractmethod
    async def get_info(self) -> DeviceInfo:
        """Get device information.

        Returns:
            DeviceInfo object with device details.
        """
        pass

    @abstractmethod
    async def backup_config(self) -> bytes:
        """Backup the current device configuration.

        Returns:
            Configuration data as bytes.
        """
        pass

    @abstractmethod
    async def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration to the device.

        Args:
            config: Configuration dictionary to apply.

        Returns:
            True if configuration applied successfully.
        """
        pass

    @abstractmethod
    async def apply_config_file(self, config_path: str) -> bool:
        """Apply configuration from a file.

        Args:
            config_path: Path to the configuration file.

        Returns:
            True if configuration applied successfully.
        """
        pass

    @abstractmethod
    async def upload_firmware(self, firmware_path: str) -> bool:
        """Upload firmware to the device.

        Args:
            firmware_path: Path to the firmware file.

        Returns:
            True if upload successful.
        """
        pass

    @abstractmethod
    async def update_firmware(self, bank: Optional[int] = None) -> bool:
        """Trigger firmware update.

        For dual-bank devices, specify which bank to update.

        Args:
            bank: Bank number to update (None for automatic).

        Returns:
            True if update initiated successfully.
        """
        pass

    @abstractmethod
    async def reboot(self) -> bool:
        """Reboot the device.

        Returns:
            True if reboot command sent successfully.
        """
        pass

    @abstractmethod
    async def get_firmware_version(self) -> str:
        """Get the current firmware version.

        Returns:
            Firmware version string.
        """
        pass

    async def verify_firmware(self, expected_version: str) -> bool:
        """Verify the firmware version after update.

        Args:
            expected_version: Expected firmware version.

        Returns:
            True if firmware matches expected version.
        """
        current = await self.get_firmware_version()
        return current == expected_version

    async def set_password(self, new_password: str, username: str = None) -> bool:
        """Change the device password.

        This is typically called during initial provisioning to change
        the device from its factory default password.

        Args:
            new_password: The new password to set.
            username: Username to change password for (defaults to current user).

        Returns:
            True if password changed successfully.

        Note:
            Subclasses should override this method. The default implementation
            returns False (not supported).
        """
        return False

    @property
    def supports_password_change(self) -> bool:
        """Whether this device type supports password change via API."""
        return False

    @abstractmethod
    async def wait_for_reboot(self, timeout: int = 180) -> bool:
        """Wait for device to come back online after reboot.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            True if device came back online within timeout.
        """
        pass

    def validate_firmware_for_model(self, firmware_path: str, model: str) -> tuple[bool, str]:
        """Validate that firmware file is compatible with the device model.

        Subclasses can override this to implement model-specific validation.
        Default implementation returns True (no validation).

        Args:
            firmware_path: Path to firmware file.
            model: Device model string.

        Returns:
            Tuple of (is_valid, error_message). error_message is empty if valid.
        """
        return True, ""

    async def provision(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: Optional[str] = None,
        firmware_path: Optional[str] = None,
        expected_firmware: Optional[str] = None,
        dual_bank: bool = True,
        new_password: Optional[str] = None,
        firmware_current: bool = False,
        on_progress: Optional[Callable[[str, bool, Optional[str]], Awaitable[None]]] = None,
        firmware_lookup_callback: Optional[Callable[[str, str], tuple]] = None,
    ) -> ProvisioningResult:
        """Run the full provisioning workflow.

        Flow:
        1. Login
        2. Get device info (model, MAC, serial, firmware banks)
        3. Determine which banks need updates (compare each bank to expected_firmware)
        4. If bank1 needs update: FW1 upload + stage → reboot → verify → mark FW1 green
           If bank1 is current: mark FW1 green immediately
        5. Config apply
        6. If bank2 needs update: FW2 upload + stage → reboot → verify → mark FW2 green
           If bank2 is current: mark FW2 green immediately
        7. Final verification

        Args:
            config: Configuration dictionary to apply.
            config_path: Path to configuration file (alternative to config).
            firmware_path: Path to firmware file.
            expected_firmware: Expected firmware version after update.
            dual_bank: Whether to update both banks for dual-bank devices.
            new_password: New password to set (changes from factory default).
            firmware_current: Hint that firmware is already current (from fingerprint).
            on_progress: Callback for UI updates: (step_name, success, detail).
            firmware_lookup_callback: Callback to re-lookup firmware by (device_type, model).
                Returns tuple of (firmware_path, expected_version) or (None, None).

        Returns:
            ProvisioningResult with outcome details.
        """
        import logging
        _logger = logging.getLogger(__name__)

        result = ProvisioningResult(
            success=False,
            started_at=datetime.now(),
            phases_completed=[],
        )

        async def notify(step: str, success, detail: Optional[str] = None):
            """Call progress callback if set."""
            if on_progress:
                try:
                    await on_progress(step, success, detail)
                except Exception:
                    pass  # Don't let callback errors break provisioning

        try:
            # ================================================================
            # PHASE 1: LOGIN
            # ================================================================
            _logger.info(f"[PROVISION] Phase 1: Login to {self.ip}")
            if not await self.connect():
                result.error_message = getattr(self, 'login_error', None) or "Failed to connect to device"
                result.needs_credentials = "credentials" in result.error_message.lower() or "password" in result.error_message.lower()
                await notify("login", False, result.error_message)
                return result
            result.phases_completed.append(ProvisioningPhase.CONNECTING)
            await notify("login", True, None)

            # ================================================================
            # PHASE 2: GET DEVICE INFO + DETERMINE FIRMWARE NEEDS
            # ================================================================
            _logger.info(f"[PROVISION] Phase 2: Get device info")
            result.device_info = await self.get_info()
            result.old_firmware = result.device_info.firmware_version
            result.phases_completed.append(ProvisioningPhase.GATHERING_INFO)

            model_name = result.device_info.model if result.device_info else None
            await notify("model_confirmed", True, model_name)

            if result.device_info:
                info_str = f"mac:{result.device_info.mac_address or ''}|serial:{result.device_info.serial_number or ''}"
                await notify("device_info", True, info_str)

            # Get firmware bank versions and determine which need updates
            bank1_ver = "unknown"
            bank2_ver = "unknown"
            need_fw1 = True  # Default: assume update needed
            need_fw2 = True  # Default: assume update needed (if dual-bank)

            if hasattr(self, 'get_firmware_banks'):
                try:
                    banks = await self.get_firmware_banks()
                    # Use normalized versions for comparison
                    bank1_ver = banks.get("bank1", "unknown")
                    bank2_ver = banks.get("bank2", "unknown")
                    # Use display versions for UI if available (includes full version string)
                    bank1_display = banks.get("bank1_display", bank1_ver)
                    bank2_display = banks.get("bank2_display", bank2_ver)
                    bank_info = f"bank1:{bank1_display}|bank2:{bank2_display}|active:{banks.get('active', 1)}"
                    _logger.info(f"[PROVISION] Initial firmware banks: {bank_info}")
                    await notify("firmware_banks", True, bank_info)

                    # Determine which banks need updates (using normalized versions)
                    if expected_firmware:
                        need_fw1 = (bank1_ver != expected_firmware)
                        need_fw2 = (bank2_ver != expected_firmware)
                        _logger.info(f"[PROVISION] Firmware check: expected={expected_firmware}, bank1={bank1_ver} (need_update={need_fw1}), bank2={bank2_ver} (need_update={need_fw2})")
                    else:
                        # No expected version - skip updates if firmware_current hint is set
                        if firmware_current:
                            need_fw1 = False
                            need_fw2 = False
                except Exception as e:
                    _logger.error(f"[PROVISION] get_firmware_banks exception: {e}")
            elif firmware_current:
                # No get_firmware_banks method but firmware_current hint is set
                need_fw1 = False
                need_fw2 = False

            # TODO: Config backup disabled for now - add storage location before re-enabling
            # try:
            #     backup_data = await self.backup_config()
            #     # Need to save backup_data somewhere...
            #     result.phases_completed.append(ProvisioningPhase.BACKING_UP)
            # except Exception:
            #     pass

            # Change password from factory default if requested
            if new_password and self.supports_password_change:
                if await self.set_password(new_password):
                    self.credentials["password"] = new_password
                    result.phases_completed.append(ProvisioningPhase.CHANGING_PASSWORD)

            # ================================================================
            # PHASE 3-5: FIRMWARE UPDATE 1 (bank 1)
            # ================================================================
            if not need_fw1:
                # Bank 1 already at expected version
                _logger.info(f"[PROVISION] Bank 1 already at {bank1_ver}, skipping FW1 update")
                await notify("firmware_update_1", True, bank1_ver)
            else:
                # Bank 1 needs update
                if not firmware_path:
                    result.error_message = "No firmware file found for this device model"
                    await notify("firmware_update_1", False, result.error_message)
                    return result

                # Validate firmware matches discovered model
                if model_name:
                    is_valid, error_msg = self.validate_firmware_for_model(firmware_path, model_name)
                    if not is_valid:
                        # Try to re-lookup firmware with the now-known model
                        if firmware_lookup_callback:
                            _logger.info(f"[PROVISION] Firmware mismatch, re-looking up for model {model_name}")
                            new_path, new_version = firmware_lookup_callback(self.device_type, model_name)
                            if new_path:
                                _logger.info(f"[PROVISION] Found correct firmware: {new_path} (version {new_version})")
                                firmware_path = new_path
                                expected_firmware = new_version
                                # Re-validate with new firmware
                                is_valid, error_msg = self.validate_firmware_for_model(firmware_path, model_name)

                                # Recalculate if update is still needed with correct firmware
                                if self.update_triggers_reboot:
                                    # For auto-reboot devices, check active bank
                                    active_bank = banks.get("active", 1)
                                    active_ver = bank1_ver if active_bank == 1 else bank2_ver
                                    need_fw1 = (active_ver != expected_firmware)
                                    _logger.info(f"[PROVISION] After re-lookup: active bank {active_bank}={active_ver}, need_fw1={need_fw1}")
                                else:
                                    need_fw1 = (bank1_ver != expected_firmware)
                                    _logger.info(f"[PROVISION] After re-lookup: bank1={bank1_ver}, need_fw1={need_fw1}")

                                # If firmware no longer needed, skip the upload
                                if not need_fw1:
                                    _logger.info(f"[PROVISION] Firmware already matches after re-lookup, skipping FW1 update")

                        if not is_valid:
                            result.error_message = error_msg
                            await notify("firmware_update_1", False, result.error_message)
                            return result

                # After validation/re-lookup, check if FW1 is still needed
                if not need_fw1:
                    _logger.info(f"[PROVISION] Skipping FW1 upload - firmware matches after re-lookup")
                    await notify("firmware_update_1", True, expected_firmware)
                else:
                    _logger.info(f"[PROVISION] Phase 3: Firmware update 1 (bank 1)")
                    _logger.info(f"    Firmware path: {firmware_path}")
                    _logger.info(f"    Expected version: {expected_firmware}")
                    _logger.info(f"    Current bank1: {bank1_ver}")

                    await notify("firmware_update_1", "loading", None)

                    if not await self.upload_firmware(firmware_path):
                        result.error_message = "Failed to upload firmware (update 1)"
                        await notify("firmware_update_1", False, result.error_message)
                        return result

                    if not await self.update_firmware(bank=1 if self.supports_dual_bank else None):
                        result.error_message = "Failed to stage firmware (update 1)"
                        await notify("firmware_update_1", False, result.error_message)
                        return result
                    _logger.info(f"[PROVISION] Firmware update 1 staged")

                    # ================================================================
                    # PHASE 4: REBOOT #1
                    # ================================================================
                    _logger.info(f"[PROVISION] Phase 4: Reboot #1")
                    # Some devices (e.g., Tachyon) reboot automatically after update_firmware()
                    if getattr(self, 'update_triggers_reboot', False):
                        _logger.info(f"[PROVISION] Device reboots automatically after firmware update")
                    else:
                        if not await self.reboot():
                            result.error_message = "Failed to reboot device"
                            await notify("reboot", False, result.error_message)
                            return result
                    await notify("reboot", "loading", None)

                    _logger.info(f"[PROVISION] Waiting for device to come back online...")
                    if not await self.wait_for_reboot():
                        result.error_message = "Device did not come back online after reboot"
                        await notify("firmware_update_1", False, result.error_message)
                        return result

                    # ================================================================
                    # PHASE 5: VERIFY FIRMWARE UPDATE 1
                    # ================================================================
                    _logger.info(f"[PROVISION] Phase 5: Verify firmware update 1")
                    if not await self.connect():
                        result.error_message = "Failed to reconnect after reboot"
                        await notify("firmware_update_1", False, result.error_message)
                        return result

                    # Check firmware version
                    fw1_verified = False
                    if hasattr(self, 'get_firmware_banks'):
                        try:
                            banks = await self.get_firmware_banks()
                            bank1_ver = banks.get("bank1", "")
                            bank2_ver = banks.get("bank2", "")
                            active_bank = banks.get("active", 1)
                            # Use display versions for UI if available
                            bank1_display = banks.get("bank1_display", bank1_ver)
                            bank2_display = banks.get("bank2_display", bank2_ver)
                            bank_info = f"bank1:{bank1_display}|bank2:{bank2_display}|active:{active_bank}"
                            _logger.info(f"[PROVISION] After reboot #1, firmware banks: {bank_info}")
                            await notify("firmware_banks", True, bank_info)

                            # Determine which bank to verify based on device behavior
                            # Devices with update_triggers_reboot write to inactive bank and reboot into it,
                            # so we should verify the ACTIVE bank, not specifically bank1
                            if self.update_triggers_reboot:
                                # Check the active bank (the one just updated and rebooted into)
                                active_ver = bank1_ver if active_bank == 1 else bank2_ver
                                if expected_firmware and active_ver == expected_firmware:
                                    fw1_verified = True
                                    _logger.info(f"[PROVISION] Firmware update 1 verified: active bank {active_bank}={expected_firmware}")
                                elif not expected_firmware:
                                    fw1_verified = True  # No expected version to check
                            else:
                                # Traditional devices: check bank1 specifically
                                if expected_firmware and bank1_ver == expected_firmware:
                                    fw1_verified = True
                                    _logger.info(f"[PROVISION] Firmware update 1 verified: bank1={expected_firmware}")
                                elif not expected_firmware:
                                    fw1_verified = True  # No expected version to check

                            # Update need_fw2 based on current bank2 state (using normalized versions)
                            # For auto-reboot devices, after FW1 the inactive bank needs update
                            if expected_firmware:
                                if self.update_triggers_reboot:
                                    # The inactive bank (not active) needs update
                                    inactive_ver = bank2_ver if active_bank == 1 else bank1_ver
                                    need_fw2 = (inactive_ver != expected_firmware)
                                    _logger.info(f"[PROVISION] After FW1, inactive bank={inactive_ver}, need_fw2={need_fw2}")
                                else:
                                    need_fw2 = (bank2_ver != expected_firmware)
                                    _logger.info(f"[PROVISION] After FW1, bank2={bank2_ver}, need_fw2={need_fw2}")
                        except Exception as e:
                            _logger.error(f"[PROVISION] get_firmware_banks exception: {e}")

                    if fw1_verified:
                        await notify("firmware_update_1", True, expected_firmware)
                    else:
                        result.error_message = f"Firmware update 1 verification failed"
                        await notify("firmware_update_1", False, result.error_message)
                        return result

            result.phases_completed.append(ProvisioningPhase.UPLOADING_FIRMWARE)

            # ================================================================
            # PHASE 6: CONFIG APPLY
            # ================================================================
            _logger.info(f"[PROVISION] Phase 6: Apply config")
            if config or config_path:
                if config:
                    success = await self.apply_config(config)
                else:
                    success = await self.apply_config_file(config_path)

                if not success:
                    result.error_message = "Failed to apply configuration"
                    await notify("config_upload", False, result.error_message)
                    return result

                result.config_applied = config_path or "inline"
                result.phases_completed.append(ProvisioningPhase.CONFIGURING)
                await notify("config_upload", True, None)
            else:
                await notify("config_upload", "skipped", "No config specified")

            # ================================================================
            # PHASE 7-9: FIRMWARE UPDATE 2 (bank 2, if dual-bank)
            # ================================================================
            if dual_bank and self.supports_dual_bank:
                if not need_fw2:
                    # Bank 2 already at expected version
                    _logger.info(f"[PROVISION] Bank 2 already at {bank2_ver}, skipping FW2 update")
                    await notify("firmware_update_2", True, bank2_ver)
                else:
                    # Bank 2 needs update
                    if not firmware_path:
                        result.error_message = "No firmware file found for this device model"
                        await notify("firmware_update_2", False, result.error_message)
                        return result

                    _logger.info(f"[PROVISION] Phase 7: Firmware update 2 (bank 2)")
                    _logger.info(f"    Current bank2: {bank2_ver}")
                    await notify("firmware_update_2", "loading", None)

                    if not await self.upload_firmware(firmware_path):
                        result.error_message = "Failed to upload firmware (update 2)"
                        await notify("firmware_update_2", False, result.error_message)
                        return result

                    if not await self.update_firmware(bank=2):
                        result.error_message = "Failed to stage firmware (update 2)"
                        await notify("firmware_update_2", False, result.error_message)
                        return result
                    _logger.info(f"[PROVISION] Firmware update 2 staged")

                    # ================================================================
                    # PHASE 8: REBOOT #2
                    # ================================================================
                    _logger.info(f"[PROVISION] Phase 8: Reboot #2")
                    # Some devices (e.g., Tachyon) reboot automatically after update_firmware()
                    if getattr(self, 'update_triggers_reboot', False):
                        _logger.info(f"[PROVISION] Device reboots automatically after firmware update")
                    else:
                        if not await self.reboot():
                            result.error_message = "Failed to reboot device"
                            await notify("reboot", False, result.error_message)
                            return result
                    await notify("reboot", "loading", None)

                    _logger.info(f"[PROVISION] Waiting for device to come back online...")
                    if not await self.wait_for_reboot():
                        result.error_message = "Device did not come back online after reboot"
                        await notify("firmware_update_2", False, result.error_message)
                        return result

                    # ================================================================
                    # PHASE 9: VERIFY FIRMWARE UPDATE 2
                    # ================================================================
                    _logger.info(f"[PROVISION] Phase 9: Verify firmware update 2")
                    if not await self.connect():
                        result.error_message = "Failed to reconnect after reboot"
                        await notify("firmware_update_2", False, result.error_message)
                        return result

                    # Check bank 2 has expected firmware
                    fw2_verified = False
                    if hasattr(self, 'get_firmware_banks'):
                        try:
                            banks = await self.get_firmware_banks()
                            bank1_ver = banks.get("bank1", "")
                            bank2_ver = banks.get("bank2", "")
                            active_bank = banks.get("active", 1)
                            # Use display versions for UI if available
                            bank1_display = banks.get("bank1_display", bank1_ver)
                            bank2_display = banks.get("bank2_display", bank2_ver)
                            bank_info = f"bank1:{bank1_display}|bank2:{bank2_display}|active:{active_bank}"
                            _logger.info(f"[PROVISION] After reboot #2, firmware banks: {bank_info}")
                            await notify("firmware_banks", True, bank_info)

                            # For FW2, verify both banks have expected firmware (dual-bank complete)
                            if expected_firmware:
                                if bank1_ver == expected_firmware and bank2_ver == expected_firmware:
                                    fw2_verified = True
                                    _logger.info(f"[PROVISION] Firmware update 2 verified: both banks={expected_firmware}")
                                elif self.update_triggers_reboot:
                                    # For auto-reboot devices, at minimum the active bank should match
                                    active_ver = bank1_ver if active_bank == 1 else bank2_ver
                                    if active_ver == expected_firmware:
                                        fw2_verified = True
                                        _logger.info(f"[PROVISION] Firmware update 2 verified: active bank {active_bank}={expected_firmware}")
                            else:
                                fw2_verified = True  # No expected version to check
                        except Exception as e:
                            _logger.error(f"[PROVISION] get_firmware_banks exception: {e}")

                    if fw2_verified:
                        await notify("firmware_update_2", True, expected_firmware)
                    else:
                        result.error_message = f"Firmware update 2 verification failed"
                        await notify("firmware_update_2", False, result.error_message)
                        return result

            result.phases_completed.append(ProvisioningPhase.UPDATING_FIRMWARE)
            result.phases_completed.append(ProvisioningPhase.REBOOTING)

            # ================================================================
            # PHASE 10: FINAL VERIFICATION
            # ================================================================
            _logger.info(f"[PROVISION] Phase 10: Final verification")
            result.new_firmware = await self.get_firmware_version()
            await notify("verify", True, result.new_firmware)
            await notify("reboot", True, None)
            result.phases_completed.append(ProvisioningPhase.VERIFYING)

            result.success = True
            result.phases_completed.append(ProvisioningPhase.COMPLETED)

        except Exception as e:
            result.error_message = str(e)
            result.phases_completed.append(ProvisioningPhase.FAILED)
            _logger.error(f"[PROVISION] Exception: {e}")

        finally:
            result.completed_at = datetime.now()
            await self.disconnect()

        return result

    @property
    def supports_dual_bank(self) -> bool:
        """Whether this device type supports dual-bank firmware."""
        return False

    @property
    def update_triggers_reboot(self) -> bool:
        """Whether update_firmware() triggers automatic reboot.

        If True, the provisioning flow will skip the explicit reboot() call
        after update_firmware() since the device reboots on its own.
        """
        return False
