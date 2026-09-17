"""Abstract base handler for network device provisioning."""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, Callable, Awaitable, List, Tuple

from ..field_ownership import OwnershipContract, get_path, parse_path

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


class ConnectionFailureKind(str, Enum):
    """Stable connection-failure classes for workflow retry decisions."""

    AUTHENTICATION = "authentication"
    TRANSPORT = "transport"
    DEVICE_BUSY = "device_busy"
    INVALID_RESPONSE = "invalid_response"
    UNKNOWN = "unknown"


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

    Each device type implements this interface (in its vendor handler
    module) to provide provisioning functionality.
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

    #: The config resolver may compose role/replacement overlays for this
    #: vendor. False ⇒ overlays are refused with an operator-visible note
    #: (base-only resolution). Enable per vendor only after bench
    #: verification. See docs/design-config-resolution.md.
    supports_config_overlays = False

    #: Post-provisioning deployment modes that are production-qualified for
    #: this handler. Declare a mode only after its vendor-specific template,
    #: identity/radio-role fields, apply path, and hardware result have been
    #: verified. A template or theoretical capability alone is not enough.
    qualified_post_provision_modes = ()  # type: Tuple[str, ...]

    #: The handler's field ownership contract (see ``field_ownership.py``).
    #: Shared code lints templates and derives verification expectations from
    #: it. ``None`` means the vendor has not declared a contract yet; the flow
    #: then behaves exactly as before (handler-private verification).
    FIELD_OWNERSHIP = None  # type: Optional[OwnershipContract]

    def applied_config_expectations(self) -> Optional[Dict[str, Any]]:
        """Return the read-back expectations for the config just applied.

        The default returns ``None`` so :meth:`verify_config` keeps its
        handler-private behavior. Handlers with a ``FIELD_OWNERSHIP`` contract
        override this to return ``field_ownership.expected_values(...)`` for
        the configuration they applied.
        """
        return None

    def pending_secrets(self) -> Dict[str, str]:
        """Return secret-owned values that must be written after config.

        Secrets never live in a template. They arrive through the host
        credentials (for example ``wpa_key`` and ``snmp_community``). The
        default reads those two keys; a handler may override.
        """
        values = dict(getattr(self, "_secret_values", {}) or {})
        for key in ("wpa_key", "snmp_community"):
            if isinstance(self.credentials, dict) and self.credentials.get(key):
                values[key] = self.credentials[key]
        return values

    async def apply_secrets(self, secrets: Dict[str, str]) -> bool:
        """Write secret-owned fields. The default has nothing to write."""
        return True

    def required_secrets(self) -> List[str]:
        """Secret keys the standard run cannot finish without.

        A handler lists a key here when the baseline leaves a field empty on
        purpose (for example the SM profile passphrase). The run fails before
        the config step when the host credentials do not provide it, so a
        unit never leaves the bench with an empty secret.
        """
        return []

    def missing_required_secrets(self) -> List[str]:
        pending = self.pending_secrets()
        return [key for key in self.required_secrets() if not pending.get(key)]

    @classmethod
    def upload_role_for_model(
        cls, model: Optional[str] = None
    ) -> Optional[str]:
        """Return a model's known structured-upload role, when available.

        This is used only while packaging or locating a structured upload
        asset. A model may support more than one role, or the role may not be
        known from the model alone; those handlers return ``None`` and the
        caller must provide an explicit mode. Standard provisioning keeps
        its existing baseline behavior and does not use this hint to bypass
        an explicit post-provision mode workflow.
        """
        return None

    @classmethod
    def qualified_post_provision_modes_for_model(
        cls, model: Optional[str] = None
    ) -> Tuple[str, ...]:
        """Return qualified post-provision modes for a detected model.

        Vendors may narrow a class-level qualification to hardware that has
        completed its bench verification.  The default preserves the legacy
        class-level capability contract.
        """
        return cls.qualified_post_provision_modes

    #: Baseline deployment mode that must be applied and verified during the
    #: standard provisioning run before the unit is deployable or eligible
    #: for a post-provision mode conversion. ``None`` means the handler has no
    #: such prerequisite. This is a handler trait so shared workflow code does
    #: not maintain a vendor allowlist.
    required_baseline_mode = None  # type: Optional[str]

    #: PTP mode needs a vendor-native settings profile in addition to the
    #: generated link identity.  Handlers set this when naming-only fallback
    #: would not produce a working radio link.
    requires_ptp_settings = False

    @classmethod
    def requires_ptp_settings_for_model(cls, model: Optional[str] = None) -> bool:
        """Return whether PTP needs a complete vendor settings profile."""
        return bool(cls.requires_ptp_settings)

    @classmethod
    def generate_ptp_settings(
        cls,
        config: Dict[str, Any],
        side: str,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate or generate vendor PTP settings before mode apply.

        The default keeps the existing behavior for handlers that do not
        advertise qualified PTP.  Vendors that require a native PTP profile
        must override this hook and raise ``ValueError`` when the profile is
        incomplete.
        """
        return config

    #: Whether the kiosk may expose this handler's manual recovery workflow.
    #: The recovery implementation remains vendor-local; the shared UI only
    #: consumes this capability flag.
    supports_manual_netinstall = False
    manual_netinstall_label = "Recovery (Netinstall)"

    #: Number of attempts that :meth:`ensure_connected` makes for transient
    #: failures. The default preserves the existing single-attempt behavior.
    #: A handler can increase this value after bench verification.
    connection_retry_attempts = 1

    #: Delay before each retry from :meth:`ensure_connected`. A handler can
    #: override :meth:`connection_retry_delay` for progressive backoff.
    connection_retry_delay_seconds = 0.0

    @staticmethod
    def is_full_config_export(config: Dict[str, Any]) -> bool:
        """Return True when a loaded JSON config is a full device export
        (applied replace-not-merge, so partial overlays must not be
        composed over it).

        Method-shaped (unlike the plain attribute traits) because the
        answer depends on the loaded config's *content*, not on the vendor
        alone — but still callable before instantiation, via
        ``HandlerManager.handler_class_for``.
        """
        return False

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
        self._connection_failure_kind: Optional[ConnectionFailureKind] = None
        #: Field names (never values) that mismatched in the last verify.
        self.last_verify_mismatches: List[str] = []
        #: Secret-owned device values from the host credentials, captured
        #: here because handlers may replace ``self.credentials`` with a
        #: login candidate during connect().
        self._secret_values: Dict[str, str] = {
            key: credentials[key]
            for key in ("wpa_key", "snmp_community")
            if isinstance(credentials, dict) and credentials.get(key)
        }

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

    @property
    def connection_failure_kind(self) -> ConnectionFailureKind:
        """Return the structured class for the last connection failure.

        Handlers can call :meth:`set_connection_failure` when their transport
        gives a precise result. The fallback classifies the existing
        ``login_error`` text so current handlers remain compatible.
        """
        if self._connection_failure_kind is not None:
            return self._connection_failure_kind

        error = str(getattr(self, "login_error", "") or "").lower()
        if any(
            marker in error
            for marker in (
                "credential",
                "password",
                "unauthorized",
                "forbidden",
                "account locked",
                "statuscode 401",
                "http 401",
                "http 403",
            )
        ):
            return ConnectionFailureKind.AUTHENTICATION
        if any(
            marker in error
            for marker in (
                "too many active sessions",
                "device busy",
                "rebooting",
                "temporarily unavailable",
                "http 429",
                "http 503",
            )
        ):
            return ConnectionFailureKind.DEVICE_BUSY
        if any(
            marker in error
            for marker in (
                "connection",
                "not responding",
                "not reachable",
                "timeout",
                "timed out",
            )
        ):
            return ConnectionFailureKind.TRANSPORT
        if error:
            return ConnectionFailureKind.INVALID_RESPONSE
        return ConnectionFailureKind.UNKNOWN

    def set_connection_failure(
        self, kind: Optional[ConnectionFailureKind]
    ) -> None:
        """Record a connection result without logging credentials or payloads."""
        self._connection_failure_kind = kind

    def connection_retry_delay(self, failed_attempt: int) -> float:
        """Return the delay after a failed connection attempt."""
        return float(self.connection_retry_delay_seconds)

    async def ensure_connected(self, reason: str = "operation") -> bool:
        """Reuse a valid session or make bounded connection attempts.

        A successful operation that verifies device state must leave
        ``is_connected`` true. The shared flow calls this method before the
        next in-band operation. It does not discard a verified session.

        Authentication failures stop immediately. Other failures use the
        handler retry contract.
        """
        if self.is_connected:
            _logger.debug(
                "[SESSION] Reusing the verified session for %s", reason
            )
            return True

        attempts = max(1, int(self.connection_retry_attempts))
        for attempt in range(1, attempts + 1):
            self.set_connection_failure(None)
            try:
                connected = await self.connect()
            except Exception as exc:
                connected = False
                if self._connection_failure_kind is None:
                    self.set_connection_failure(ConnectionFailureKind.UNKNOWN)
                _logger.warning(
                    "[SESSION] Connection raised for %s: error=%s",
                    reason,
                    type(exc).__name__,
                )

            if connected:
                self._connected = True
                self.set_connection_failure(None)
                return True

            self._connected = False
            kind = self.connection_failure_kind
            _logger.warning(
                "[SESSION] Connection failed for %s: kind=%s attempt=%s/%s",
                reason,
                kind.value,
                attempt,
                attempts,
            )
            if kind == ConnectionFailureKind.AUTHENTICATION:
                return False
            if attempt < attempts:
                delay = max(0.0, self.connection_retry_delay(attempt))
                if delay:
                    await asyncio.sleep(delay)

        return False

    async def refresh_connection(self, reason: str = "operation") -> bool:
        """Discard a stale session and apply the bounded retry contract."""
        try:
            await self.disconnect()
        except Exception as exc:
            _logger.debug(
                "[SESSION] Disconnect failed before %s: %s", reason, exc
            )
        return await self.ensure_connected(reason)

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

    async def apply_mode_config(self, config: Dict[str, Any]) -> bool:
        """Apply a rendered AP/PTP mode configuration.

        Most handlers can use their normal configuration API for mode changes.
        A handler with a vendor-native import path can override this hook while
        keeping that behavior out of the shared mode orchestration.
        """
        return await self.apply_config(config)

    async def apply_antenna_gain(
        self, gain_db: Optional[int] = None, model: Optional[str] = None
    ) -> bool:
        """Apply an optional post-provision antenna setting.

        Vendors that do not need this setting keep the no-op default.  The
        A vendor handler owns its connectorized-radio detection and write path.
        """
        return True

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

        Reuses the active device session, then — when ``expected_values`` are
        supplied — reads the config back via :meth:`_read_back_config` and compares. The
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
        # Config apply does not trigger a reboot. Keep its valid session.
        _logger.info(
            "[CONFIG VERIFY] Default verification on active session for %s",
            self.ip,
        )
        if not await self.ensure_connected("config verification"):
            _logger.error(
                "[CONFIG VERIFY] Could not establish a session for %s: kind=%s",
                self.ip,
                self.connection_failure_kind.value,
            )
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

        self.last_verify_mismatches = []
        for field_name, expected in expected_values.items():
            found, actual = get_path(readback, parse_path(field_name))
            if not found or actual != expected:
                # Field names only. Values may be sensitive.
                self.last_verify_mismatches.append(field_name)
                _logger.error(f"[CONFIG VERIFY] {field_name} mismatch on {self.ip}")
        if self.last_verify_mismatches:
            return False

        _logger.info(f"[CONFIG VERIFY] All expected values confirmed on {self.ip}")
        return True

    @abstractmethod
    async def upload_firmware(self, firmware_path: str, bank: Optional[int] = None) -> bool:
        """Upload firmware to the device.

        For dual-bank devices, ``bank`` indicates which bank update is in
        progress (1 = first pass, 2 = second pass). Most vendors flash the
        inactive bank regardless of the pass number — they can ignore the
        argument. Some vendors use a different endpoint for the
        second-pass flash and need this to switch paths.

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

    def firmware_lookup_key(self, device_info: Optional[DeviceInfo]) -> Optional[str]:
        """Select the key used for model-specific firmware lookup.

        The provisioning flow passes this key to ``firmware_lookup_callback``
        (which resolves it against ``firmware.py`` ``MODEL_FIRMWARE_PATTERNS``).
        Subclasses can override this when firmware files are keyed by
        something other than the model string (for example, a hardware
        architecture stored in ``device_info.hardware_version``).

        Args:
            device_info: The device info gathered by ``get_info()``, or None
                if not available yet.

        Returns:
            The lookup key, or None if no key can be determined.
        """
        return device_info.model if device_info else None

    def provisioning_step_plan(
        self,
        has_config: bool,
        dual_bank: bool,
        need_fw1: bool,
        need_fw2: bool,
    ) -> list[Dict[str, str]]:
        """Build the validation plan for this concrete provisioning run.

        The plan is derived from handler capabilities and the work selected
        for the job. It is presentation metadata only; the properties that
        drive :meth:`provision` remain the source of truth for behavior.
        """
        labels = {
            "login": "Login",
            "model_confirmed": "Model",
            "firmware_banks": "Firmware check",
            "firmware_update_1": "Firmware bank 1",
            "config_upload": "Config",
            "config_verify": "Config verify",
            "secrets": "Secrets",
            "firmware_update_2": "Firmware bank 2",
            "reboot": "Reboot",
            "verify": "Firmware verify",
        }
        keys = ["login", "model_confirmed"]
        if hasattr(self, "get_firmware_banks"):
            keys.append("firmware_banks")

        firmware_steps = ["firmware_update_1"]
        if dual_bank and self.supports_dual_bank:
            firmware_steps.append("firmware_update_2")

        config_steps = ["config_upload"]
        if has_config:
            config_steps.append("config_verify")
        if has_config and (self.pending_secrets() or self.required_secrets()):
            config_steps.append("secrets")

        if self.config_after_all_firmware:
            keys.extend(firmware_steps)
            if need_fw1 or (dual_bank and self.supports_dual_bank and need_fw2):
                keys.extend(["reboot", "verify"])
            keys.extend(config_steps)
        else:
            keys.append(firmware_steps[0])
            keys.extend(config_steps)
            keys.extend(firmware_steps[1:])
            if need_fw1 or (dual_bank and self.supports_dual_bank and need_fw2):
                keys.extend(["reboot", "verify"])

        return [{"key": key, "label": labels[key]} for key in keys]

    async def provision(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: Optional[str] = None,
        firmware_path: Optional[str] = None,
        expected_firmware: Optional[str] = None,
        dual_bank: bool = True,
        new_password: Optional[str] = None,
        firmware_current: bool = False,
        on_progress: Optional[Callable[[str, Any, Optional[Any]], Awaitable[None]]] = None,
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

        async def notify(step: str, success, detail: Optional[Any] = None):
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
            if not await self.ensure_connected("initial login"):
                result.error_message = getattr(self, 'login_error', None) or "Failed to connect to device"
                result.needs_credentials = (
                    self.connection_failure_kind
                    == ConnectionFailureKind.AUTHENTICATION
                )
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

            await notify(
                "step_plan",
                True,
                self.provisioning_step_plan(
                    has_config=bool(config or config_path),
                    dual_bank=dual_bank,
                    need_fw1=need_fw1,
                    need_fw2=need_fw2,
                ),
            )

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
                    lookup_model = self.firmware_lookup_key(result.device_info)
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
                            lookup_model = self.firmware_lookup_key(result.device_info)
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
                    # Some devices reboot automatically after update_firmware()
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
                    if not await self.refresh_connection(
                        "firmware update 1 verification"
                    ):
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

            missing_secrets = self.missing_required_secrets() if (config or config_path) else []
            if missing_secrets:
                result.error_message = (
                    "Required secret not configured on the host: %s "
                    "(set it under credentials.%s in config.yaml)"
                    % (", ".join(missing_secrets), self.device_type)
                )
                _logger.error("[PROVISION] %s", result.error_message)
                await notify("secrets", False, result.error_message)
                return result

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

                    verify_result = await self.verify_config(
                        self.applied_config_expectations()
                    )
                    if verify_result is False:
                        mismatches = list(getattr(self, "last_verify_mismatches", []) or [])
                        result.error_message = "Config verification failed"
                        if mismatches:
                            # Field names only. Never values.
                            result.error_message += ": mismatch " + ", ".join(mismatches[:6])
                        else:
                            result.error_message += " - device may not have applied config correctly"
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

                # PHASE 6c: SECRETS (never in a template; presence only)
                secrets = self.pending_secrets()
                if secrets:
                    await notify("secrets", "loading", None)
                    if not await self.apply_secrets(secrets):
                        result.error_message = "Failed to apply device secrets"
                        await notify("secrets", False, result.error_message)
                        return result
                    await notify("secrets", True, None)

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

                    # Config verification must leave a usable session. Reuse
                    # that session instead of forcing another device login.
                    _logger.info(
                        "[PROVISION] Preparing the verified session before FW2 upload..."
                    )
                    if not await self.ensure_connected("firmware update 2 upload"):
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
                        # Some devices reboot automatically after update_firmware()
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
                        if not await self.refresh_connection(
                            "firmware update 2 verification"
                        ):
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
            did_firmware_update = need_fw1 or (
                dual_bank and self.supports_dual_bank and need_fw2
            )
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
                    _logger.info(
                        "[PROVISION] Preparing the verified session before config apply..."
                    )
                    if not await self.ensure_connected("deferred config apply"):
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

                # Deferred flows still owe the secret-owned fields. The device
                # may have left the bench network; apply_secrets reports
                # honestly when it cannot reach it.
                secrets = self.pending_secrets()
                if secrets:
                    await notify("secrets", "loading", None)
                    if not await self.apply_secrets(secrets):
                        result.error_message = "Failed to apply device secrets"
                        await notify("secrets", False, result.error_message)
                        return result
                    await notify("secrets", True, None)

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
