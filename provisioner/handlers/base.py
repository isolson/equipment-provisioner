"""Abstract base handler for network device provisioning."""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, Callable, Awaitable

_logger = logging.getLogger(__name__)

# Tri-state result for verify_config(). Verification is HONEST / fail-closed:
#   True        -> device state positively confirmed to match what was applied
#   False       -> read-back succeeded but did NOT match (real failure -> abort)
#   UNVERIFIED  -> could not confirm (no read-back capability, or the device
#                  changed networks and is unreachable). Surfaced to the UI as a
#                  distinct amber state — never reported as a green success.
# A handler's verify_config may return any of these; the provision() flow maps
# them to checklist states. Plain True/False handlers keep working unchanged.
UNVERIFIED = "unverified"


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

    # Class-level traits, consulted via HANDLER_MAP *before* a handler is
    # instantiated (config-template lookup, pre-provision model preflight).
    # Instance @property overrides (which may depend on self._device_info)
    # remain the mechanism for flow control inside provision().

    #: Accept timestamp-prefixed config exports when matching model
    #: templates (e.g. ``20260424.143334.TNA-303L-65.tar`` for model
    #: ``TNA-303L-65``).
    allows_prefixed_config_exports = False

    #: Fall back to an arbitrary template file in the vendor's template dir
    #: when no model/alias/default template matches. Vendors with
    #: product-family templates should disable this so a config for one
    #: product line cannot cross-apply to another.
    allows_arbitrary_template_fallback = True

    #: Match CONFIG_MODEL_ALIASES keys as model-name prefixes
    #: (``tna-305`` also covers ``tna-305-xyz``), not just exact names.
    config_alias_prefix_matching = False

    #: Run a read-only login/get-info preflight before asset lookup when
    #: fingerprinting identified the vendor but not the model. Enable for
    #: vendors whose firmware/config assets are model-specific.
    requires_model_preflight = False

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

    async def _read_back_config(self) -> Optional[Dict[str, Any]]:
        """Read the device's current config for verification.

        Override in handlers that can read state back from the device. The
        default returns ``None`` meaning "this handler has no read-back
        capability" — which the default ``verify_config`` treats as
        :data:`UNVERIFIED` (honest: we cannot confirm), never as success.
        """
        return None

    async def verify_config(self, expected_values: Optional[Dict[str, Any]] = None):
        """Verify that configuration was applied correctly (fail-closed).

        Reconnects to the device, then — when ``expected_values`` are supplied —
        reads the config back via :meth:`_read_back_config` and compares. The
        result is HONEST:

          - returns ``True`` only when read-back positively matched
          - returns ``False`` when read-back ran but a value did not match
          - returns :data:`UNVERIFIED` when there is nothing to compare or the
            handler cannot read state back (connectivity confirmed, config not)

        Override in device-specific handlers for vendor-specific read-back.

        Args:
            expected_values: Optional dict of field names to expected values.
                            If None, only device accessibility is confirmed.

        Returns:
            ``True`` / ``False`` / :data:`UNVERIFIED`.
        """
        # Config apply does not trigger a reboot, so the device should still be up.
        _logger.info(f"[CONFIG VERIFY] Default verification - reconnecting to {self.ip}")
        await self.disconnect()

        # Try to reconnect first.
        connected = False
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                _logger.info(f"[CONFIG VERIFY] Login attempt {attempt}/{max_attempts}")
                if await self.connect():
                    connected = True
                    break

                # Check for auth/lockout errors — stop immediately, don't burn attempts
                login_err = getattr(self, 'login_error', None) or ""
                auth_keywords = ["credentials", "password", "locked", "session", "unauthorized"]
                if any(kw in login_err.lower() for kw in auth_keywords):
                    _logger.error(f"[CONFIG VERIFY] Auth/lockout error, stopping retries: {login_err}")
                    return False

                _logger.warning(f"[CONFIG VERIFY] Reconnect attempt {attempt} failed: {login_err}")
            except Exception as e:
                _logger.warning(f"[CONFIG VERIFY] Attempt {attempt} error: {e}")

            if attempt < max_attempts:
                await asyncio.sleep(10)

        if not connected:
            _logger.error(f"[CONFIG VERIFY] All {max_attempts} login attempts failed")
            return False

        # Reconnect confirmed the device is reachable. Without specific values to
        # check, that is all we can honestly assert — connectivity, not config.
        if not expected_values:
            _logger.info(f"[CONFIG VERIFY] Device accessible; no specific values to confirm")
            return UNVERIFIED

        # Expected values were requested — read state back and compare.
        readback = await self._read_back_config()
        if readback is None:
            _logger.warning(
                f"[CONFIG VERIFY] No read-back capability on {self.ip} — reporting UNVERIFIED"
            )
            return UNVERIFIED

        for field_name, expected in expected_values.items():
            actual = readback.get(field_name)
            if actual != expected:
                _logger.error(
                    f"[CONFIG VERIFY] {field_name} mismatch: expected {expected!r}, got {actual!r}"
                )
                return False

        _logger.info(f"[CONFIG VERIFY] All expected values confirmed on {self.ip}")
        return True

    @abstractmethod
    async def upload_firmware(self, firmware_path: str, bank: Optional[int] = None) -> bool:
        """Upload firmware to the device.

        For dual-bank devices, ``bank`` indicates which bank update is in
        progress (1 = first pass, 2 = second pass). Most vendors flash the
        inactive bank regardless of the pass number — they can ignore the
        argument. Some vendors (Cambium ePMP) use a different endpoint
        for the second-pass flash and need this to switch paths.

        Args:
            firmware_path: Path to the firmware file.
            bank: 1 for the first firmware-update pass, 2 for the second.
                  None means "vendor decides".

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
        config_backup: bool = False,
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
            config_backup: Whether to backup config before provisioning (feature flag).

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

            def firmware_lookup_key() -> Optional[str]:
                """Select best key for model-specific firmware lookup."""
                if (
                    self.device_type == "mikrotik"
                    and result.device_info
                    and result.device_info.hardware_version
                ):
                    return result.device_info.hardware_version
                return model_name

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

            # Config backup (gated by feature flag)
            if config_backup:
                try:
                    backup_data = await self.backup_config()
                    result.phases_completed.append(ProvisioningPhase.BACKING_UP)
                except NotImplementedError:
                    _logger.debug("Config backup not implemented for this device type")
                except Exception as e:
                    _logger.warning(f"Config backup failed: {e}")

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
                    lookup_model = firmware_lookup_key()
                    if firmware_lookup_callback and lookup_model:
                        _logger.info(f"[PROVISION] No initial firmware path, re-looking up for model {lookup_model}")
                        new_path, new_version = firmware_lookup_callback(self.device_type, lookup_model)
                        if new_path:
                            firmware_path = new_path
                            expected_firmware = new_version
                            need_fw1 = (bank1_ver != expected_firmware) if expected_firmware else need_fw1
                            need_fw2 = (bank2_ver != expected_firmware) if expected_firmware else need_fw2
                            _logger.info(f"[PROVISION] Re-lookup selected firmware: {firmware_path} ({expected_firmware})")

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
                            lookup_model = firmware_lookup_key()
                            _logger.info(f"[PROVISION] Firmware mismatch, re-looking up for model {lookup_model}")
                            new_path, new_version = firmware_lookup_callback(self.device_type, lookup_model)
                            if new_path:
                                _logger.info(f"[PROVISION] Found correct firmware: {new_path} (version {new_version})")
                                firmware_path = new_path
                                expected_firmware = new_version
                                # Re-validate with new firmware
                                is_valid, error_msg = self.validate_firmware_for_model(firmware_path, model_name)

                                # Recalculate if updates are still needed with correct firmware
                                if self.update_triggers_reboot:
                                    # For auto-reboot devices, check active bank for FW1
                                    active_bank = banks.get("active", 1)
                                    active_ver = bank1_ver if active_bank == 1 else bank2_ver
                                    inactive_ver = bank2_ver if active_bank == 1 else bank1_ver
                                    need_fw1 = (active_ver != expected_firmware)
                                    need_fw2 = (inactive_ver != expected_firmware)
                                    _logger.info(f"[PROVISION] After re-lookup: active bank {active_bank}={active_ver}, inactive={inactive_ver}")
                                    _logger.info(f"[PROVISION] After re-lookup: need_fw1={need_fw1}, need_fw2={need_fw2}")
                                else:
                                    need_fw1 = (bank1_ver != expected_firmware)
                                    need_fw2 = (bank2_ver != expected_firmware)
                                    _logger.info(f"[PROVISION] After re-lookup: bank1={bank1_ver}, bank2={bank2_ver}")
                                    _logger.info(f"[PROVISION] After re-lookup: need_fw1={need_fw1}, need_fw2={need_fw2}")

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

                    if not await self.upload_firmware(firmware_path, bank=1):
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
                    await notify("reboot_started", True, None)
                    # Some devices (e.g., Tachyon) reboot automatically after update_firmware()
                    if getattr(self, 'update_triggers_reboot', False):
                        _logger.info(f"[PROVISION] Device reboots automatically after firmware update")
                    else:
                        if not await self.reboot():
                            await notify("reboot_ended", True, None)
                            result.error_message = "Failed to reboot device"
                            await notify("firmware_update_1", False, result.error_message)
                            return result

                    _logger.info(f"[PROVISION] Waiting for device to come back online...")
                    if not await self.wait_for_reboot(timeout=self.firmware_reboot_timeout):
                        await notify("reboot_ended", True, None)
                        result.error_message = "Device did not come back online after reboot"
                        await notify("firmware_update_1", False, result.error_message)
                        return result
                    await notify("reboot_ended", True, None)

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
                            # Devices that install to the inactive bank and activate it
                            # should verify the ACTIVE bank, not specifically bank1
                            if self.verify_active_bank:
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
                                if self.verify_active_bank:
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
            # CONFIG + FW2 PHASE ORDERING
            # Most devices: Config → Verify → FW2
            # config_after_all_firmware devices: FW2 → Config (skip verify)
            #   Used when config changes the management network, making the
            #   device unreachable for subsequent operations.
            # ================================================================

            if not self.config_after_all_firmware:
                # --- DEFAULT ORDER: Config → Verify → FW2 ---

                # PHASE 6: CONFIG APPLY
                _logger.info(f"[PROVISION] Phase 6: Apply config")
                _logger.info(f"[PROVISION] Config path: {config_path}, inline config: {bool(config)}")
                if config or config_path:
                    if config:
                        _logger.info(f"[PROVISION] Applying inline config with {len(config)} keys")
                        success = await self.apply_config(config)
                    else:
                        _logger.info(f"[PROVISION] Applying config from file: {config_path}")
                        success = await self.apply_config_file(config_path)

                    if not success:
                        result.error_message = "Failed to apply configuration"
                        await notify("config_upload", False, result.error_message)
                        return result

                    result.config_applied = config_path or "inline"
                    result.phases_completed.append(ProvisioningPhase.CONFIGURING)
                    await notify("config_upload", True, None)
                    _logger.info(f"[PROVISION] Config applied successfully")

                    # PHASE 6b: CONFIG VERIFICATION
                    _logger.info(f"[PROVISION] Phase 6b: Verify config applied")
                    await notify("config_verify", "loading", None)

                    verify_result = await self.verify_config()
                    if verify_result is False:
                        result.error_message = "Config verification failed - device may not have applied config correctly"
                        await notify("config_verify", False, result.error_message)
                        return result
                    elif verify_result == UNVERIFIED:
                        # Connectivity confirmed but config state could not be read
                        # back. Surface honestly (amber) instead of a false green.
                        # NOTE: pass NO detail. Some progress sinks store
                        # `detail if detail else success` (web/api.py on_progress),
                        # so a detail string here would overwrite the "unverified"
                        # status and the UI would render it green. The reason is in
                        # the log line below.
                        await notify("config_verify", UNVERIFIED, None)
                        _logger.info(f"[PROVISION] Config applied but device state could not be confirmed (UNVERIFIED)")
                    else:
                        await notify("config_verify", True, None)
                        _logger.info(f"[PROVISION] Config verification passed")
                else:
                    _logger.info(f"[PROVISION] No config to apply - skipping")
                    await notify("config_upload", "skipped", "No config specified")

            # PHASE 7-9: FIRMWARE UPDATE 2 (bank 2, if dual-bank)
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

                    # Ensure fresh session before FW2 upload.
                    # Config verify disconnects/reconnects and the session may
                    # be stale, especially after a config-triggered reboot.
                    _logger.info(f"[PROVISION] Reconnecting before FW2 upload...")
                    try:
                        await self.disconnect()
                    except Exception:
                        pass
                    if not await self.connect():
                        result.error_message = "Failed to reconnect before firmware update 2"
                        await notify("firmware_update_2", False, result.error_message)
                        return result

                    if not await self.upload_firmware(firmware_path, bank=2):
                        result.error_message = "Failed to upload firmware (update 2)"
                        await notify("firmware_update_2", False, result.error_message)
                        return result

                    if not await self.update_firmware(bank=2):
                        result.error_message = "Failed to stage firmware (update 2)"
                        await notify("firmware_update_2", False, result.error_message)
                        return result
                    _logger.info(f"[PROVISION] Firmware update 2 staged")

                    if self.fw2_skips_reboot:
                        # Device flashed the inactive bank without activating it.
                        # No reboot needed — preserves auto-discovered state
                        # (azimuth, location, etc.) on the active bank.
                        _logger.info(f"[PROVISION] FW2 installed without activation — skipping reboot")
                        await notify("reboot_started", True, None)
                        await notify("reboot_ended", True, None)
                    else:
                        # PHASE 8: REBOOT #2
                        _logger.info(f"[PROVISION] Phase 8: Reboot #2")
                        await notify("reboot_started", True, None)
                        # Some devices (e.g., Tachyon) reboot automatically after update_firmware()
                        if getattr(self, 'update_triggers_reboot', False):
                            _logger.info(f"[PROVISION] Device reboots automatically after firmware update")
                        else:
                            if not await self.reboot():
                                await notify("reboot_ended", True, None)
                                result.error_message = "Failed to reboot device"
                                await notify("firmware_update_2", False, result.error_message)
                                return result

                        _logger.info(f"[PROVISION] Waiting for device to come back online...")
                        if not await self.wait_for_reboot(timeout=self.firmware_reboot_timeout):
                            await notify("reboot_ended", True, None)
                            result.error_message = "Device did not come back online after reboot"
                            await notify("firmware_update_2", False, result.error_message)
                            return result
                        await notify("reboot_ended", True, None)

                    # PHASE 9: VERIFY FIRMWARE UPDATE 2
                    _logger.info(f"[PROVISION] Phase 9: Verify firmware update 2")
                    if not self.fw2_skips_reboot:
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
                            _logger.info(f"[PROVISION] After FW2, firmware banks: {bank_info}")
                            await notify("firmware_banks", True, bank_info)

                            # For FW2, verify both banks have expected firmware (dual-bank complete)
                            if expected_firmware:
                                if bank1_ver == expected_firmware and bank2_ver == expected_firmware:
                                    fw2_verified = True
                                    _logger.info(f"[PROVISION] Firmware update 2 verified: both banks={expected_firmware}")
                                elif self.verify_active_bank:
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

            # PHASE 10: FINAL VERIFICATION
            _logger.info(f"[PROVISION] Phase 10: Final verification")
            result.new_firmware = await self.get_firmware_version()
            did_firmware_update = need_fw1 or need_fw2
            if did_firmware_update:
                await notify("reboot", True, None)
                await notify("verify", True, result.new_firmware)
            result.phases_completed.append(ProvisioningPhase.VERIFYING)

            if self.config_after_all_firmware:
                # --- DEFERRED CONFIG: apply after all firmware is done ---
                # Used when config changes the management network, making the
                # device unreachable for subsequent operations.
                _logger.info(f"[PROVISION] Applying config after all firmware (config_after_all_firmware=True)")
                _logger.info(f"[PROVISION] Config path: {config_path}, inline config: {bool(config)}")
                if config or config_path:
                    # Ensure fresh session before config apply
                    _logger.info(f"[PROVISION] Reconnecting before config apply...")
                    try:
                        await self.disconnect()
                    except Exception:
                        pass
                    if not await self.connect():
                        result.error_message = "Failed to reconnect before config apply"
                        await notify("config_upload", False, result.error_message)
                        return result

                    if config:
                        _logger.info(f"[PROVISION] Applying inline config with {len(config)} keys")
                        success = await self.apply_config(config)
                    else:
                        _logger.info(f"[PROVISION] Applying config from file: {config_path}")
                        success = await self.apply_config_file(config_path)

                    if not success:
                        result.error_message = "Failed to apply configuration"
                        await notify("config_upload", False, result.error_message)
                        return result

                    result.config_applied = config_path or "inline"
                    result.phases_completed.append(ProvisioningPhase.CONFIGURING)
                    await notify("config_upload", True, None)
                    _logger.info(f"[PROVISION] Config applied successfully")

                    # Config cannot be read back in-band — applying it changes the
                    # management network (VLAN, DHCP mode), so the device leaves the
                    # link we provisioned it on. Report this honestly as UNVERIFIED
                    # (amber), NOT as a green success: "sent, not confirmed".
                    # NOTE: pass NO detail — see the matching note above; a detail
                    # string would be stored in place of the "unverified" status by
                    # `detail if detail else success` progress sinks and render green.
                    _logger.info(f"[PROVISION] Config sent but not read back — device changed management network (UNVERIFIED)")
                    await notify("config_verify", UNVERIFIED, None)
                else:
                    _logger.info(f"[PROVISION] No config to apply - skipping")
                    await notify("config_upload", "skipped", "No config specified")

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

    @property
    def verify_active_bank(self) -> bool:
        """Whether firmware verification should check the active bank.

        Devices that always install to the inactive bank and activate it
        should return True so verification checks the bank the device
        actually booted into, rather than assuming bank1.
        """
        return self.update_triggers_reboot

    @property
    def config_after_all_firmware(self) -> bool:
        """Whether config should be applied after all firmware updates.

        When True, the provisioning flow becomes: FW1 → FW2 → Config (no verify).
        Used for devices where config changes the management network (VLAN, DHCP),
        making the device unreachable for subsequent operations.
        """
        return False

    @property
    def fw2_skips_reboot(self) -> bool:
        """Whether the second firmware update skips activation and reboot.

        When True, the FW2 update writes firmware to the inactive bank
        without activating it, so no reboot is needed.  This preserves
        auto-discovered device state (e.g. azimuth, location) that would
        be lost if the device switched banks again.
        """
        return False

    @property
    def firmware_reboot_timeout(self) -> int:
        """Seconds to wait for the device to come back after a firmware reboot.

        A firmware-applying reboot writes the new image to flash and runs
        first-boot init, which can take far longer than a plain reboot.
        Handlers may override (optionally conditional on model) when a device's
        post-upgrade boot exceeds the default. Plain reboots are unaffected.
        """
        return 180
