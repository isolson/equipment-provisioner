#!/usr/bin/env python3
"""
Network Device Auto-Provisioner

Main entry point and orchestrator for automatic network device provisioning.
"""

import argparse
import asyncio
import json
import logging
import logging.handlers
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from rich.console import Console
from rich.logging import RichHandler

from .config import load_config, set_config, Config
from .db import init_db, close_db, ProvisioningRecord, ProvisioningStatus
from .detector import DeviceDetector, DiscoveredDevice
from .fingerprint import identify_device, DeviceType
from .firmware import FirmwareManager
from .config_store import init_store, get_store
from .mode_config import init_mode_config_manager
from .gpio import init_gpio, cleanup_gpio, get_gpio
from .handler_manager import HandlerManager
from .notifier import init_notifier, get_notifier
from .firmware_checker import init_firmware_checker, get_firmware_checker
from .port_manager import PortManager, init_port_manager, DeviceLinkLocalIP, ManagementConfig
from . import telemetry

logger = logging.getLogger(__name__)
console = Console()


class Provisioner:
    """Main provisioning orchestrator.

    Supports two modes:
    - VLAN mode: Each switch port has its own VLAN, devices accessed via link-local IPs
    - Simple mode: Single port, devices detected via DHCP/ARP scanning
    """

    def __init__(self, config: Config):
        self.config = config
        self.detector: Optional[DeviceDetector] = None
        self.port_manager: Optional[PortManager] = None
        self.handler_manager: Optional[HandlerManager] = None
        self.firmware_manager: Optional[FirmwareManager] = None
        self._running = False
        self._provisioning_semaphore = asyncio.Semaphore(8)  # Max concurrent
        self._use_vlan_mode = config.network.mode == "vlan"

    async def setup(self) -> None:
        """Initialize all components."""
        logger.info("Initializing provisioner...")
        logger.info(f"Mode: {'VLAN (multi-port)' if self._use_vlan_mode else 'Simple (single port)'}")

        # Initialize database
        await init_db(self.config.logging.db)

        # Initialize GPIO
        if self.config.gpio.enabled:
            gpio = init_gpio(
                green_led=self.config.gpio.green_led,
                red_led=self.config.gpio.red_led,
                yellow_led=self.config.gpio.yellow_led,
                buzzer=self.config.gpio.buzzer,
                enabled=self.config.gpio.enabled,
            )
            await gpio.startup_pattern()
        else:
            gpio = None

        # Initialize notifier
        init_notifier(
            slack_webhook=self.config.notifications.slack_webhook,
            discord_webhook=self.config.notifications.discord_webhook,
            gpio_controller=gpio,
        )

        # Initialize local config/firmware store
        store = init_store(self.config.data.local_path)
        store.ensure_directories()

        # Initialize mode config manager (AP/PTP template loading)
        init_mode_config_manager(str(store.templates_path))

        # Initialize firmware manager
        self.firmware_manager = FirmwareManager(
            firmware_path=str(store.firmware_path),
            manifest_path=str(store.local_path / "manifest.yaml"),
        )

        # Always initialize firmware checker so it can be toggled via API
        self.firmware_checker = init_firmware_checker(
            config=self.config.firmware.checker.model_dump(),
            firmware_manager=self.firmware_manager,
            firmware_path=store.firmware_path,
            notifier=get_notifier(),
        )
        logger.info("Firmware checker initialized (enabled=%s)", self.config.firmware.checker.enabled)

        # Initialize handler manager with credentials
        credentials = {
            "mikrotik": {
                "username": self.config.credentials.mikrotik.username,
                "password": self.config.credentials.mikrotik.password,
            },
            "cambium": {
                "username": self.config.credentials.cambium.username,
                "password": self.config.credentials.cambium.password,
            },
            "tachyon": {
                "username": self.config.credentials.tachyon.username,
                "password": self.config.credentials.tachyon.password,
            },
            "tarana": {
                "username": self.config.credentials.tarana.username,
                "password": self.config.credentials.tarana.password,
            },
            "ubiquiti": {
                "username": self.config.credentials.ubiquiti.username,
                "password": self.config.credentials.ubiquiti.password,
            },
        }

        # Load alternate credentials from credentials.json
        alternate_credentials = {}
        creds_path = Path(self.config.data.local_path) / "credentials.json"
        if creds_path.exists():
            try:
                with open(creds_path) as f:
                    alternate_credentials = json.load(f)
                logger.info(f"Loaded alternate credentials for: {list(alternate_credentials.keys())}")
            except Exception as e:
                logger.warning(f"Failed to load alternate credentials: {e}")

        self.handler_manager = HandlerManager(credentials, alternate_credentials)

        # Initialize detection based on mode
        if self._use_vlan_mode:
            # VLAN mode: use port manager
            # Build management config from network settings
            mgmt_config = None
            if hasattr(self.config.network, 'management'):
                mgmt = self.config.network.management
                mgmt_config = ManagementConfig(
                    enabled=mgmt.enabled,
                    ip=mgmt.ip,
                    netmask=mgmt.netmask,
                    switch_ip=getattr(mgmt, 'switch_ip', None) or getattr(mgmt, 'gateway', None),
                    vlan=mgmt.vlan,
                )

            self.port_manager = init_port_manager(
                base_interface=self.config.network.interface,
                vlan_start=self.config.ports.vlan_start,
                num_ports=self.config.ports.num_ports,
                local_ip_base=self.config.ports.local_ip,
                management=mgmt_config,
            )
            await self.port_manager.setup()
            self.port_manager.on_device_detected(self._on_port_device_detected)
        else:
            # Simple mode: use ARP detector
            self.detector = DeviceDetector(
                interface=self.config.network.interface,
                subnet=self.config.simple_mode.subnet,
                scan_delay=self.config.network.scan_delay,
                device_boot_timeout=self.config.network.device_boot_timeout,
            )
            self.detector.on_device_discovered(self._on_device_discovered)

        # Initialize telemetry
        telemetry.init(self.config.analytics)

        logger.info("Provisioner initialized successfully")

    async def run(self) -> None:
        """Start the provisioner main loop."""
        self._running = True

        # Start background tasks based on mode
        tasks = []

        if self._use_vlan_mode:
            tasks.append(asyncio.create_task(self.port_manager.start_monitoring()))
            logger.info(f"Provisioner running - monitoring {self.config.ports.num_ports} ports")
            console.print(f"[green]Provisioner active on {self.config.network.interface}[/green]")
            console.print(f"[dim]Mode: VLAN ({self.config.ports.num_ports} ports)[/dim]")
            console.print(f"[dim]VLANs: {self.config.ports.vlan_start}-{self.config.ports.vlan_start + self.config.ports.num_ports - 1}[/dim]")
        else:
            tasks.append(asyncio.create_task(self.detector.start()))
            logger.info(f"Provisioner running - monitoring {self.config.network.interface}")
            console.print(f"[green]Provisioner active on {self.config.network.interface}[/green]")
            console.print(f"[dim]Mode: Simple (subnet {self.config.simple_mode.subnet})[/dim]")

        # Start firmware checker if enabled in config
        if self.firmware_checker and self.config.firmware.checker.enabled:
            tasks.append(asyncio.create_task(self.firmware_checker.start()))

        console.print("[dim]Waiting for devices...[/dim]")

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Provisioner stopping...")

    async def stop(self) -> None:
        """Stop the provisioner."""
        self._running = False

        if self.detector:
            self.detector.stop()

        if self.port_manager:
            await self.port_manager.stop_monitoring()
            await self.port_manager.cleanup()

        if self.firmware_checker:
            await self.firmware_checker.stop()

        cleanup_gpio()
        await telemetry.close()
        await close_db()

        logger.info("Provisioner stopped")

    async def _on_port_device_detected(self, port_num: int, device_type: str, device_ip: str) -> None:
        """Handle device detected on a VLAN port.

        Spawns provisioning as a separate task so it can be cancelled
        if the device is unexpectedly unplugged.
        """
        logger.info(f"Device detected on port {port_num}: {device_type} at {device_ip}")

        # Wake display if configured
        from .display import get_display
        display = get_display()
        if display and display.wake_on_connect and display.is_sleeping():
            logger.info("Waking display on device connect")
            await display.wake()
            # Notify clients of wake
            from .web.websocket import notify_display_state
            await notify_display_state(sleeping=False)

        # Spawn provisioning as a cancellable task
        task = asyncio.create_task(self._run_port_provisioning(port_num, device_type, device_ip))

        # Store task reference for cancellation on unexpected unplug
        if port_num in self.port_manager.port_states:
            self.port_manager.port_states[port_num].provisioning_task = task

    async def _run_port_provisioning(self, port_num: int, device_type: str, device_ip: str) -> None:
        """Run provisioning for a port device as a cancellable task."""
        self.port_manager.mark_port_provisioning(port_num, True)
        cancelled = False

        success = False
        try:
            async with self._provisioning_semaphore:
                success = await self._provision_port_device(port_num, device_type, device_ip)
        except asyncio.CancelledError:
            logger.warning(f"Provisioning cancelled for port {port_num} (device unplugged)")
            cancelled = True
            success = False
        finally:
            if port_num in self.port_manager.port_states:
                state = self.port_manager.port_states[port_num]
                state.provisioning_task = None
                state.expecting_reboot = False
            # Don't overwrite state if cancelled — link-down handler already reset everything
            if not cancelled:
                self.port_manager.mark_port_provisioning(port_num, False, success=success)

    async def _provision_port_device(
        self, port_num: int, device_type: str, device_ip: str,
        custom_credentials: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Provision a device detected on a VLAN port.

        Unlike _provision_device, we already know the device type from port detection.
        """
        from .db import get_db
        from .web.websocket import (
            notify_provisioning_started,
            notify_provisioning_progress,
            notify_provisioning_completed,
            notify_port_change,
        )
        from typing import Optional, Union

        notifier = get_notifier()
        db = await get_db()

        # Get the VLAN interface for this port
        interface = self.port_manager.get_interface_for_port(port_num)
        logger.info(f"Provisioning {device_type} on port {port_num} via {interface}")

        # Reset checklist for new provisioning attempt
        self.port_manager.reset_checklist(port_num)

        # Create job record first (needed for progress notifications)
        record = ProvisioningRecord(
            port_number=port_num,
            device_type=device_type,
            mac_address="unknown",  # Will be updated after connection
            ip_address=device_ip,
            status=ProvisioningStatus.STARTED,
            started_at=datetime.now(),
        )
        job_id = await db.create_job(record)

        # Create progress callback to update checklist in real-time
        async def on_checklist_progress(step: str, success: Union[bool, str], detail: Optional[str] = None):
            """Update checklist as each step completes."""
            logger.debug(f"Checklist progress: port={port_num} step={step} success={success} detail={detail}")

            # Track reboot state so unexpected link-loss can cancel provisioning
            if step == "reboot_started":
                self.port_manager.set_expecting_reboot(port_num, True)
                return  # Internal signal, don't update checklist or UI
            elif step == "reboot_ended":
                self.port_manager.set_expecting_reboot(port_num, False)
                return  # Internal signal, don't update checklist or UI

            # Send provisioning progress to update status bar in UI
            await notify_provisioning_progress(port_num, job_id, step)

            if step == "model_confirmed":
                # For model_confirmed, always store the model name (detail), not the boolean
                # This prevents "true" showing up when model is None
                self.port_manager.update_checklist(port_num, step, detail)
            elif step == "device_info" and detail:
                # Parse device info: "mac:XX:XX:XX|serial:YYYY"
                mac = None
                serial = None
                for part in detail.split("|"):
                    if part.startswith("mac:"):
                        mac = part[4:] if part[4:] else None
                    elif part.startswith("serial:"):
                        serial = part[7:] if part[7:] else None
                if mac or serial:
                    self.port_manager.update_port_device_info(port_num, mac=mac, serial=serial)
                # Broadcast update and return (don't add device_info to checklist display)
                port_status = self.port_manager._get_single_port_status(port_num)
                await notify_port_change(port_num, port_status)
                return
            elif step == "firmware_status":
                # Store firmware status with version detail
                # success can be "current", detail is version like "v5.10.4"
                self.port_manager.update_checklist(port_num, step, detail if detail else success)
            elif step == "firmware_banks" and detail:
                # Parse firmware banks: "bank1:5.10.4|bank2:5.10.4|active:1"
                # Store as-is for UI - no need to reformat
                self.port_manager.update_checklist(port_num, "firmware_banks", detail)
            else:
                self.port_manager.update_checklist(port_num, step, success)

            # Also update device info for model if available
            if step == "model_confirmed" and detail:
                self.port_manager.update_port_device_info(port_num, model=detail)

            # Broadcast the updated port status to UI
            port_status = self.port_manager._get_single_port_status(port_num)
            await notify_port_change(port_num, port_status)

        try:
            # Notify started via WebSocket and notifier
            await notify_provisioning_started(port_num, device_type, job_id)
            await notifier.notify_started(
                ip=device_ip,
                device_type=device_type,
                mac="unknown",
            )

            # Get config and firmware paths
            store = get_store()

            # For VLAN mode, we need to probe the device to get model info
            # since we only know the general type (cambium, tachyon, etc.)
            await db.update_job(job_id, status=ProvisioningStatus.DETECTING)
            await notify_provisioning_progress(port_num, job_id, "detecting", 10)

            # Get the interface for this port to ensure we probe the correct VLAN
            interface = self.port_manager.get_interface_for_port(port_num)

            # Use fingerprint module to get detailed device info
            fingerprint = await identify_device(device_ip, mac=None, interface=interface)

            # If re-fingerprint returned "unknown" but port detection already identified
            # the device type, fall back to the detected type. This happens when devices
            # (e.g., Tarana with gRPC-web) don't expose traditional HTTP signatures.
            if fingerprint.device_type == DeviceType.UNKNOWN and device_type:
                logger.warning(
                    f"Re-fingerprint returned unknown for {device_ip}, "
                    f"falling back to detected type: {device_type}"
                )
                fingerprint.device_type = DeviceType(device_type)

            # Update record with fingerprint info
            await db.update_job(
                job_id,
                device_model=fingerprint.model,
            )

            # Push fingerprint info to port state for immediate UI display
            if fingerprint.model:
                self.port_manager.update_port_device_info(port_num, model=fingerprint.model)
                # Broadcast the update so UI shows model immediately
                port_status = self.port_manager._get_single_port_status(port_num)
                await notify_port_change(port_num, port_status)

            config_path = store.get_config_template(
                device_type,
                fingerprint.model,
            )

            # Check for device-specific override (requires MAC, get it from handler)
            override = None

            # Get firmware info
            firmware_info = self.firmware_manager.get_firmware_file(
                device_type,
                fingerprint.model,
            )
            logger.info(f"Firmware lookup for {device_type}/{fingerprint.model}: {firmware_info}")

            expected_firmware = None
            firmware_path = None
            firmware_current = False

            if firmware_info:
                # Always pass firmware path and expected version to handler
                # The handler will check individual bank versions and decide what to update
                firmware_path = str(firmware_info.path)
                expected_firmware = firmware_info.version

                # Check if running firmware matches expected (hint for handler)
                if fingerprint.firmware_version:
                    if not self.firmware_manager.needs_update(
                        device_type,
                        fingerprint.firmware_version,
                        fingerprint.model,
                    ):
                        logger.info(f"Running firmware {fingerprint.firmware_version} matches expected {expected_firmware}")
                        firmware_current = True
                    else:
                        logger.info(f"Running firmware {fingerprint.firmware_version} differs from expected {expected_firmware}")

                logger.info(f"Firmware file: {firmware_path} (expected version: {expected_firmware})")
            else:
                logger.warning(f"No firmware file found for {device_type}/{fingerprint.model}")

            # Run provisioning
            await db.update_job(job_id, status=ProvisioningStatus.CONFIGURING)
            await notify_provisioning_progress(port_num, job_id, "configuring", 30)

            # Create firmware lookup callback for model-specific re-lookup
            def firmware_lookup(device_type: str, model: str) -> tuple:
                fw_info = self.firmware_manager.get_firmware_file(device_type, model)
                if fw_info:
                    return str(fw_info.path), fw_info.version
                return None, None

            result = await self.handler_manager.provision_device(
                fingerprint=fingerprint,
                ip=device_ip,
                config=override,
                config_path=str(config_path) if config_path else None,
                firmware_path=firmware_path,
                expected_firmware=expected_firmware,
                dual_bank=self.config.firmware.dual_bank_update,
                interface=interface,
                firmware_current=firmware_current,
                on_progress=on_checklist_progress,
                firmware_lookup_callback=firmware_lookup,
                custom_credentials=custom_credentials,
            )

            # Update MAC address and serial in checklist and DB if we got device info
            if result.device_info:
                if result.device_info.mac_address:
                    await db.update_job(job_id, mac_address=result.device_info.mac_address)
                    self.port_manager.update_port_device_info(
                        port_num,
                        mac=result.device_info.mac_address,
                        serial=result.device_info.serial_number,
                        model=result.device_info.model,
                    )

                # TODO: Re-enable override provisioning when ready
                # # Now check for override with real MAC
                # override = sync.get_device_override(result.device_info.mac_address)
                # if override:
                #     logger.info(
                #         f"Found device override for {result.device_info.mac_address}, "
                #         "applying additional config"
                #     )
                #     # Re-apply with override config
                #     await self.handler_manager.provision_device(
                #         fingerprint=fingerprint,
                #         ip=device_ip,
                #         config=override,
                #         config_path=None,  # Only apply override
                #         firmware_path=None,  # Already updated
                #         expected_firmware=None,
                #         dual_bank=False,
                #         interface=interface,
                #     )

            # Update job record
            if result.success:
                await db.update_job(
                    job_id,
                    status=ProvisioningStatus.COMPLETED,
                    old_firmware=result.old_firmware,
                    new_firmware=result.new_firmware,
                    config_applied=result.config_applied,
                    completed_at=datetime.now(),
                )

                # Update inventory
                if result.device_info:
                    await db.update_inventory(
                        mac_address=result.device_info.mac_address or "unknown",
                        device_type=result.device_info.device_type,
                        device_model=result.device_info.model,
                        serial_number=result.device_info.serial_number,
                        firmware=result.new_firmware or result.old_firmware,
                        config=result.config_applied,
                    )

                await notify_provisioning_completed(port_num, job_id, True, {
                    "device_type": device_type,
                    "firmware": result.new_firmware or result.old_firmware,
                    "config": result.config_applied,
                })
                await notifier.notify_completed(result)

                await telemetry.emit({
                    "event": "provisioning_completed",
                    "device_type": device_type,
                    "device_model": result.device_info.model if result.device_info else None,
                    "success": True,
                })

                logger.info(f"Provisioning completed for {device_type} on port {port_num}")
                return True

            else:
                await db.update_job(
                    job_id,
                    status=ProvisioningStatus.FAILED,
                    error_message=result.error_message,
                    completed_at=datetime.now(),
                )

                # If credentials failed, send special notification to prompt UI
                if result.needs_credentials:
                    from .web.websocket import notify_credentials_required
                    await notify_credentials_required(
                        port_num, device_type, device_ip, result.error_message
                    )

                await notify_provisioning_completed(port_num, job_id, False, {
                    "error": result.error_message,
                    "needs_credentials": result.needs_credentials,
                })
                await notifier.notify_failed(result, device_ip)

                await telemetry.emit({
                    "event": "provisioning_completed",
                    "device_type": device_type,
                    "device_model": result.device_info.model if result.device_info else None,
                    "success": False,
                })

                logger.error(f"Provisioning failed for {device_type} on port {port_num}: {result.error_message}")
                return False

        except Exception as e:
            logger.exception(f"Provisioning error for {device_type} on port {port_num}")
            await db.update_job(
                job_id,
                status=ProvisioningStatus.FAILED,
                error_message=str(e),
                completed_at=datetime.now(),
            )
            await notify_provisioning_completed(port_num, job_id, False, {
                "error": str(e),
            })

            from .handlers.base import ProvisioningResult
            result = ProvisioningResult(success=False, error_message=str(e))
            await notifier.notify_failed(result, device_ip)
            return False

    async def _on_device_discovered(self, device: DiscoveredDevice) -> None:
        """Handle a newly discovered device."""
        logger.info(f"New device discovered: {device.ip_address} ({device.mac_address})")

        # Wake display if configured
        from .display import get_display
        display = get_display()
        if display and display.wake_on_connect and display.is_sleeping():
            logger.info("Waking display on device connect")
            await display.wake()
            from .web.websocket import notify_display_state
            await notify_display_state(sleeping=False)

        # Use semaphore to limit concurrent provisioning
        async with self._provisioning_semaphore:
            await self._provision_device(device)

    async def _provision_device(self, device: DiscoveredDevice) -> None:
        """Provision a discovered device."""
        from .db import get_db

        notifier = get_notifier()
        db = await get_db()

        # Create job record
        record = ProvisioningRecord(
            device_type="unknown",
            mac_address=device.mac_address,
            ip_address=device.ip_address,
            status=ProvisioningStatus.STARTED,
            started_at=datetime.now(),
        )
        job_id = await db.create_job(record)

        try:
            # Fingerprint device
            await db.update_job(job_id, status=ProvisioningStatus.DETECTING)
            fingerprint = await identify_device(device.ip_address, device.mac_address)

            if fingerprint.device_type == DeviceType.UNKNOWN:
                logger.warning(f"Could not identify device at {device.ip_address}")
                await db.update_job(
                    job_id,
                    status=ProvisioningStatus.FAILED,
                    error_message="Could not identify device type",
                )
                await telemetry.emit({
                    "event": "unknown_model_detected",
                    "device_type": "unknown",
                    "device_model": None,
                })
                return

            await db.update_job(
                job_id,
                device_type=fingerprint.device_type.value,
                device_model=fingerprint.model,
            )

            # Notify started
            await notifier.notify_started(
                ip=device.ip_address,
                device_type=fingerprint.device_type.value,
                mac=device.mac_address,
            )

            # Get config and firmware paths
            store = get_store()

            config_path = store.get_config_template(
                fingerprint.device_type.value,
                fingerprint.model,
            )

            # Check for device-specific override
            override = store.get_device_override(device.mac_address)
            if override:
                logger.info(f"Found device override for {device.mac_address}")

            # Get firmware info
            firmware_info = self.firmware_manager.get_firmware_file(
                fingerprint.device_type.value,
                fingerprint.model,
            )

            expected_firmware = None
            firmware_path = None

            if firmware_info:
                # Check if update needed
                if fingerprint.firmware_version:
                    if self.firmware_manager.needs_update(
                        fingerprint.device_type.value,
                        fingerprint.firmware_version,
                        fingerprint.model,
                    ):
                        firmware_path = str(firmware_info.path)
                        expected_firmware = firmware_info.version
                        logger.info(f"Firmware update needed: {fingerprint.firmware_version} → {expected_firmware}")
                    else:
                        logger.info(f"Firmware is current: {fingerprint.firmware_version}")
                else:
                    # Unknown current version, update anyway
                    firmware_path = str(firmware_info.path)
                    expected_firmware = firmware_info.version

            # Run provisioning
            await db.update_job(job_id, status=ProvisioningStatus.CONFIGURING)

            # Create firmware lookup callback for model-specific re-lookup
            def firmware_lookup(device_type: str, model: str) -> tuple:
                fw_info = self.firmware_manager.get_firmware_file(device_type, model)
                if fw_info:
                    return str(fw_info.path), fw_info.version
                return None, None

            result = await self.handler_manager.provision_device(
                fingerprint=fingerprint,
                ip=device.ip_address,
                config=override,
                config_path=str(config_path) if config_path else None,
                firmware_path=firmware_path,
                expected_firmware=expected_firmware,
                dual_bank=self.config.firmware.dual_bank_update,
                firmware_lookup_callback=firmware_lookup,
            )

            # Update job record
            if result.success:
                await db.update_job(
                    job_id,
                    status=ProvisioningStatus.COMPLETED,
                    old_firmware=result.old_firmware,
                    new_firmware=result.new_firmware,
                    config_applied=result.config_applied,
                    completed_at=datetime.now(),
                )

                # Update inventory
                if result.device_info:
                    await db.update_inventory(
                        mac_address=device.mac_address,
                        device_type=result.device_info.device_type,
                        device_model=result.device_info.model,
                        serial_number=result.device_info.serial_number,
                        firmware=result.new_firmware or result.old_firmware,
                        config=result.config_applied,
                    )

                await notifier.notify_completed(result)

            else:
                await db.update_job(
                    job_id,
                    status=ProvisioningStatus.FAILED,
                    error_message=result.error_message,
                    completed_at=datetime.now(),
                )
                await notifier.notify_failed(result, device.ip_address)

        except Exception as e:
            logger.exception(f"Provisioning error for {device.ip_address}")
            await db.update_job(
                job_id,
                status=ProvisioningStatus.FAILED,
                error_message=str(e),
                completed_at=datetime.now(),
            )

            from .handlers.base import ProvisioningResult
            result = ProvisioningResult(success=False, error_message=str(e))
            await notifier.notify_failed(result, device.ip_address)


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Configure logging."""
    handlers = [
        RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
        )
    ]

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=50 * 1024 * 1024,  # 50 MB per file
            backupCount=3,
        ))

    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(message)s",
        handlers=handlers,
    )


async def async_main(config_path: str) -> None:
    """Async main entry point."""
    # Load configuration
    try:
        config = load_config(config_path)
        set_config(config)
    except Exception as e:
        console.print(f"[red]Failed to load configuration: {e}[/red]")
        sys.exit(1)

    # Setup logging
    setup_logging(config.logging.level, config.logging.file)

    # Create and run provisioner
    provisioner = Provisioner(config)

    # Handle shutdown signals
    loop = asyncio.get_event_loop()

    def shutdown_handler():
        logger.info("Shutdown signal received")
        asyncio.create_task(provisioner.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_handler)

    try:
        await provisioner.setup()
        await provisioner.run()
    except KeyboardInterrupt:
        pass
    finally:
        await provisioner.stop()


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Network Device Auto-Provisioner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    args = parser.parse_args()

    console.print("[bold blue]Network Device Auto-Provisioner[/bold blue]")
    console.print()

    asyncio.run(async_main(args.config))


if __name__ == "__main__":
    main()
