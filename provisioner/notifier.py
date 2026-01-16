"""Notification services for provisioning status updates."""

import asyncio
import logging
from datetime import datetime
from typing import Optional, Dict, Any

import aiohttp

from .handlers.base import DeviceInfo, ProvisioningResult, ProvisioningPhase
from .db import ProvisioningStatus

logger = logging.getLogger(__name__)


class NotificationLevel:
    """Notification severity levels."""
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


class Notifier:
    """Handles notifications via webhooks and physical indicators."""

    def __init__(
        self,
        slack_webhook: Optional[str] = None,
        discord_webhook: Optional[str] = None,
        gpio_controller: Optional[Any] = None,
    ):
        """Initialize the notifier.

        Args:
            slack_webhook: Slack incoming webhook URL.
            discord_webhook: Discord webhook URL.
            gpio_controller: GPIO controller for LED/buzzer.
        """
        self.slack_webhook = slack_webhook
        self.discord_webhook = discord_webhook
        self.gpio = gpio_controller

    async def notify_started(self, ip: str, device_type: str, mac: str) -> None:
        """Notify that provisioning has started."""
        message = f"Started provisioning {device_type} device at {ip} ({mac})"

        await self._send_notifications(
            title="Provisioning Started",
            message=message,
            level=NotificationLevel.INFO,
            fields={
                "IP Address": ip,
                "Device Type": device_type,
                "MAC Address": mac,
            }
        )

        if self.gpio:
            await self.gpio.set_status("in_progress")

    async def notify_progress(self, ip: str, phase: ProvisioningPhase, details: str = "") -> None:
        """Notify of provisioning progress."""
        phase_names = {
            ProvisioningPhase.CONNECTING: "Connecting",
            ProvisioningPhase.GATHERING_INFO: "Gathering device info",
            ProvisioningPhase.BACKING_UP: "Backing up config",
            ProvisioningPhase.CONFIGURING: "Applying configuration",
            ProvisioningPhase.UPLOADING_FIRMWARE: "Uploading firmware",
            ProvisioningPhase.UPDATING_FIRMWARE: "Updating firmware",
            ProvisioningPhase.REBOOTING: "Rebooting device",
            ProvisioningPhase.VERIFYING: "Verifying update",
        }

        phase_name = phase_names.get(phase, phase.value)
        message = f"{ip}: {phase_name}"
        if details:
            message += f" - {details}"

        logger.info(message)

        # Only send webhook for major phases
        if phase in (ProvisioningPhase.UPLOADING_FIRMWARE, ProvisioningPhase.REBOOTING):
            await self._send_notifications(
                title="Provisioning Progress",
                message=message,
                level=NotificationLevel.INFO,
            )

    async def notify_completed(self, result: ProvisioningResult) -> None:
        """Notify that provisioning completed successfully."""
        device_info = result.device_info or DeviceInfo(device_type="unknown")

        fields = {
            "Device Type": device_info.device_type,
            "Model": device_info.model or "N/A",
            "IP Address": device_info.ip_address or "N/A",
            "MAC Address": device_info.mac_address or "N/A",
            "Serial": device_info.serial_number or "N/A",
        }

        if result.old_firmware and result.new_firmware:
            fields["Firmware"] = f"{result.old_firmware} → {result.new_firmware}"
        elif result.new_firmware:
            fields["Firmware"] = result.new_firmware

        if result.config_applied:
            fields["Config Applied"] = result.config_applied

        if result.started_at and result.completed_at:
            duration = (result.completed_at - result.started_at).total_seconds()
            fields["Duration"] = f"{duration:.1f}s"

        message = f"Successfully provisioned {device_info.device_type}"
        if device_info.model:
            message += f" {device_info.model}"
        message += f" at {device_info.ip_address}"

        await self._send_notifications(
            title="Provisioning Complete",
            message=message,
            level=NotificationLevel.SUCCESS,
            fields=fields,
        )

        if self.gpio:
            await self.gpio.set_status("success")
            await self.gpio.beep(count=1, duration=0.2)

    async def notify_failed(self, result: ProvisioningResult, ip: str = "") -> None:
        """Notify that provisioning failed."""
        device_info = result.device_info or DeviceInfo(device_type="unknown")

        fields = {
            "Device Type": device_info.device_type,
            "IP Address": ip or device_info.ip_address or "N/A",
            "Error": result.error_message or "Unknown error",
        }

        if result.phases_completed:
            fields["Last Phase"] = result.phases_completed[-1].value

        message = f"Failed to provision device at {ip or device_info.ip_address}: {result.error_message}"

        await self._send_notifications(
            title="Provisioning Failed",
            message=message,
            level=NotificationLevel.ERROR,
            fields=fields,
        )

        if self.gpio:
            await self.gpio.set_status("error")
            await self.gpio.beep(count=3, duration=0.5)

    async def _send_notifications(
        self,
        title: str,
        message: str,
        level: str = NotificationLevel.INFO,
        fields: Optional[Dict[str, str]] = None,
    ) -> None:
        """Send notifications to all configured channels."""
        tasks = []

        if self.slack_webhook:
            tasks.append(self._send_slack(title, message, level, fields))

        if self.discord_webhook:
            tasks.append(self._send_discord(title, message, level, fields))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_slack(
        self,
        title: str,
        message: str,
        level: str,
        fields: Optional[Dict[str, str]] = None,
    ) -> None:
        """Send notification to Slack."""
        # Color mapping
        colors = {
            NotificationLevel.INFO: "#2196F3",
            NotificationLevel.SUCCESS: "#4CAF50",
            NotificationLevel.WARNING: "#FF9800",
            NotificationLevel.ERROR: "#F44336",
        }

        # Build attachment
        attachment = {
            "color": colors.get(level, "#808080"),
            "title": title,
            "text": message,
            "ts": int(datetime.now().timestamp()),
        }

        if fields:
            attachment["fields"] = [
                {"title": k, "value": v, "short": True}
                for k, v in fields.items()
            ]

        payload = {
            "attachments": [attachment],
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.slack_webhook,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 200:
                        logger.error(f"Slack notification failed: {response.status}")
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")

    async def _send_discord(
        self,
        title: str,
        message: str,
        level: str,
        fields: Optional[Dict[str, str]] = None,
    ) -> None:
        """Send notification to Discord."""
        # Color mapping (Discord uses decimal colors)
        colors = {
            NotificationLevel.INFO: 2201331,    # Blue
            NotificationLevel.SUCCESS: 5025616,  # Green
            NotificationLevel.WARNING: 16750848, # Orange
            NotificationLevel.ERROR: 16007990,   # Red
        }

        # Build embed
        embed = {
            "title": title,
            "description": message,
            "color": colors.get(level, 8421504),
            "timestamp": datetime.now().isoformat(),
        }

        if fields:
            embed["fields"] = [
                {"name": k, "value": v, "inline": True}
                for k, v in fields.items()
            ]

        payload = {
            "embeds": [embed],
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.discord_webhook,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status not in (200, 204):
                        logger.error(f"Discord notification failed: {response.status}")
        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")


# Global notifier instance
_notifier: Optional[Notifier] = None


def get_notifier() -> Notifier:
    """Get the global notifier instance."""
    if _notifier is None:
        raise RuntimeError("Notifier not initialized. Call init_notifier() first.")
    return _notifier


def init_notifier(
    slack_webhook: Optional[str] = None,
    discord_webhook: Optional[str] = None,
    gpio_controller: Optional[Any] = None,
) -> Notifier:
    """Initialize the global notifier instance."""
    global _notifier
    _notifier = Notifier(
        slack_webhook=slack_webhook,
        discord_webhook=discord_webhook,
        gpio_controller=gpio_controller,
    )
    return _notifier
