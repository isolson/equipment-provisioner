"""Background firmware checker service.

Periodically checks vendor firmware sources for new versions,
optionally downloads them, and updates the local manifest.
"""

import asyncio
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Type

import aiohttp
import yaml

from .firmware import FirmwareManager
from .firmware_sources.base import BaseFirmwareSource, RemoteFirmwareInfo
from .firmware_sources.tachyon import TachyonFirmwareSource
from .firmware_sources.ubiquiti import UbiquitiFirmwareSource
from .firmware_sources.cambium import CambiumFirmwareSource

logger = logging.getLogger(__name__)


class FirmwareChecker:
    """Background service that periodically checks for firmware updates.

    Follows the same singleton pattern as Notifier and telemetry.
    """

    # Registry of vendor source classes
    SOURCE_MAP: Dict[str, Type[BaseFirmwareSource]] = {
        "tachyon": TachyonFirmwareSource,
        "ubiquiti": UbiquitiFirmwareSource,
        "cambium": CambiumFirmwareSource,
    }

    def __init__(
        self,
        config: dict,
        firmware_manager: FirmwareManager,
        firmware_path: Path,
        notifier=None,
    ):
        """Initialize the firmware checker.

        Args:
            config: FirmwareCheckerConfig as dict with keys:
                    enabled, default_check_interval, default_auto_download, sources.
            firmware_manager: Existing FirmwareManager for version comparison.
            firmware_path: Base path to firmware directory (e.g. /var/lib/provisioner/repo/firmware).
            notifier: Optional Notifier for sending update notifications.
        """
        self.config = config
        self.firmware_manager = firmware_manager
        self.firmware_path = Path(firmware_path)
        self.notifier = notifier

        self._sources: Dict[str, BaseFirmwareSource] = {}
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_check: Dict[str, Optional[str]] = {}
        self._available_updates: list[RemoteFirmwareInfo] = []

        # Initialize enabled sources
        sources_config = config.get("sources", {})
        for vendor, source_config in sources_config.items():
            if not source_config.get("enabled", True):
                continue
            source_class = self.SOURCE_MAP.get(vendor)
            if source_class:
                self._sources[vendor] = source_class(source_config)
                logger.info(f"Firmware source enabled: {vendor}")
            else:
                logger.warning(f"Unknown firmware source vendor: {vendor}")

    async def start(self) -> None:
        """Start the background check loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._check_loop())
        logger.info(
            f"Firmware checker started with {len(self._sources)} source(s): "
            f"{', '.join(self._sources.keys())}"
        )

    async def stop(self) -> None:
        """Stop checking."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Firmware checker stopped")

    async def _check_loop(self) -> None:
        """Main loop: check each vendor on its configured interval."""
        # Initial delay to let the provisioner finish startup
        await asyncio.sleep(10)

        while self._running:
            for vendor, source in self._sources.items():
                interval = source.config.get(
                    "check_interval",
                    self.config.get("default_check_interval", 3600),
                )
                last = self._last_check.get(vendor)
                if last:
                    elapsed = (datetime.now() - datetime.fromisoformat(last)).total_seconds()
                    if elapsed < interval:
                        continue

                try:
                    await self._check_vendor(vendor, source)
                except Exception as e:
                    logger.error(f"Firmware check failed for {vendor}: {e}")

                self._last_check[vendor] = datetime.now().isoformat()

            # Sleep between poll cycles (check if any vendor is due every 60s)
            await asyncio.sleep(60)

    async def _check_vendor(self, vendor: str, source: BaseFirmwareSource) -> None:
        """Check a single vendor for updates."""
        logger.info(f"Checking {vendor} for firmware updates...")
        remote_list = await source.check_for_updates()

        if not remote_list:
            logger.debug(f"No firmware found from {vendor} source")
            return

        new_count = 0
        for remote_fw in remote_list:
            # Compare with local firmware
            local_version = self.firmware_manager.get_latest_version(
                vendor, remote_fw.model
            )

            if local_version and self.firmware_manager._compare_versions(
                remote_fw.version, local_version
            ) <= 0:
                continue  # Already have this version or newer

            logger.info(
                f"New firmware available: {vendor}/{remote_fw.model} "
                f"{remote_fw.version} (local: {local_version or 'none'})"
            )
            new_count += 1

            auto_download = source.config.get(
                "auto_download",
                self.config.get("default_auto_download", False),
            )

            if auto_download:
                await self._download_firmware(vendor, remote_fw, source)
            else:
                self._available_updates.append(remote_fw)
                await self._notify_update_available(vendor, remote_fw, local_version)

        if new_count:
            logger.info(f"{vendor}: {new_count} new firmware version(s) found")
        else:
            logger.info(f"{vendor}: all firmware is up to date")

    async def _download_firmware(
        self,
        vendor: str,
        remote_fw: RemoteFirmwareInfo,
        source: BaseFirmwareSource,
    ) -> None:
        """Download firmware and update manifest."""
        vendor_dir = self.firmware_path / vendor
        vendor_dir.mkdir(parents=True, exist_ok=True)
        dest_path = vendor_dir / remote_fw.filename

        if dest_path.exists():
            logger.info(f"Firmware file already exists: {dest_path}")
            return

        # Download to temp file then rename (atomic)
        tmp_path = dest_path.with_suffix(dest_path.suffix + ".tmp")
        try:
            success = await source.download(remote_fw, tmp_path)
            if not success:
                tmp_path.unlink(missing_ok=True)
                return

            tmp_path.rename(dest_path)
            logger.info(f"Downloaded firmware: {dest_path}")

            # Update manifest.yaml
            self._update_manifest(vendor, remote_fw)

            # Reload manifest in FirmwareManager
            self.firmware_manager.reload_manifest()

            # Remove from pending updates if it was there
            self._available_updates = [
                u for u in self._available_updates
                if not (u.vendor == vendor and u.model == remote_fw.model
                        and u.version == remote_fw.version)
            ]

            # Notify about successful download
            await self._notify_firmware_downloaded(vendor, remote_fw)

        except Exception as e:
            logger.error(f"Failed to download {remote_fw.filename}: {e}")
            tmp_path.unlink(missing_ok=True)

    def _update_manifest(self, vendor: str, remote_fw: RemoteFirmwareInfo) -> None:
        """Add/update entry in manifest.yaml."""
        manifest_path = self.firmware_path.parent / "manifest.yaml"
        manifest = {}
        if manifest_path.exists():
            with open(manifest_path) as f:
                manifest = yaml.safe_load(f) or {}

        firmware_section = manifest.setdefault("firmware", {})
        vendor_section = firmware_section.setdefault(vendor, {})

        key = remote_fw.model or "default"
        vendor_section[key] = {
            "version": remote_fw.version,
            "file": remote_fw.filename,
        }
        if remote_fw.sha256:
            vendor_section[key]["sha256"] = remote_fw.sha256
        vendor_section[key]["auto_downloaded"] = True
        vendor_section[key]["downloaded_at"] = datetime.now().isoformat()

        with open(manifest_path, "w") as f:
            yaml.dump(manifest, f, default_flow_style=False, sort_keys=False)

        logger.info(f"Updated manifest: {vendor}/{key} -> {remote_fw.version}")

    async def _notify_update_available(
        self,
        vendor: str,
        remote_fw: RemoteFirmwareInfo,
        local_version: Optional[str],
    ) -> None:
        """Send notification about available firmware update."""
        if not self.notifier:
            return

        try:
            await self.notifier._send_notifications(
                title="New Firmware Available",
                message=(
                    f"{vendor} {remote_fw.model}: {remote_fw.version} "
                    f"(current: {local_version or 'none'})"
                ),
                level="info",
                fields={
                    "Vendor": vendor,
                    "Model": remote_fw.model,
                    "Version": remote_fw.version,
                    "Current": local_version or "none",
                    "Download URL": remote_fw.download_url,
                },
            )
        except Exception as e:
            logger.debug(f"Failed to send update notification: {e}")

    async def _notify_firmware_downloaded(
        self,
        vendor: str,
        remote_fw: RemoteFirmwareInfo,
    ) -> None:
        """Send notification about downloaded firmware."""
        if not self.notifier:
            return

        try:
            await self.notifier._send_notifications(
                title="Firmware Downloaded",
                message=f"Downloaded {vendor} {remote_fw.model} {remote_fw.version}",
                level="success",
                fields={
                    "Vendor": vendor,
                    "Model": remote_fw.model,
                    "Version": remote_fw.version,
                    "File": remote_fw.filename,
                },
            )
        except Exception as e:
            logger.debug(f"Failed to send download notification: {e}")

    async def check_now(self, vendor: Optional[str] = None) -> list[RemoteFirmwareInfo]:
        """Manually trigger firmware check.

        Args:
            vendor: Optional vendor to check. None = check all.

        Returns:
            List of new firmware found.
        """
        results = []
        sources = (
            {vendor: self._sources[vendor]}
            if vendor and vendor in self._sources
            else self._sources
        )

        for v, source in sources.items():
            try:
                remote_list = await source.check_for_updates()
                for remote_fw in remote_list:
                    local_version = self.firmware_manager.get_latest_version(
                        v, remote_fw.model
                    )
                    if local_version and self.firmware_manager._compare_versions(
                        remote_fw.version, local_version
                    ) <= 0:
                        continue
                    results.append(remote_fw)
                self._last_check[v] = datetime.now().isoformat()
            except Exception as e:
                logger.error(f"Manual firmware check failed for {v}: {e}")

        return results

    async def download_specific(
        self,
        vendor: str,
        model: str,
        version: str,
    ) -> bool:
        """Download a specific firmware that was found during check.

        Args:
            vendor: Vendor name.
            model: Model/product identifier.
            version: Version string.

        Returns:
            True if download succeeded.
        """
        # Find in available updates
        target = None
        for fw in self._available_updates:
            if fw.vendor == vendor and fw.model == model and fw.version == version:
                target = fw
                break

        if not target:
            logger.error(f"Firmware not found in available updates: {vendor}/{model}/{version}")
            return False

        source = self._sources.get(vendor)
        if not source:
            logger.error(f"No source configured for vendor: {vendor}")
            return False

        await self._download_firmware(vendor, target, source)
        return True

    @staticmethod
    def _get_source_channel(source: BaseFirmwareSource) -> str:
        """Get the effective channel for a source, handling both dict and model configs."""
        if isinstance(source.config, dict):
            if source.config.get("include_beta", False):
                return "all"
            return source.config.get("channel", "release")
        if hasattr(source.config, "effective_channel"):
            return source.config.effective_channel
        return getattr(source.config, "channel", "release")

    def get_status(self) -> dict:
        """Return current status for API."""
        return {
            "enabled": self.config.get("enabled", False),
            "running": self._running,
            "sources": {
                vendor: {
                    "enabled": source.config.get("enabled", True) if isinstance(source.config, dict) else getattr(source.config, "enabled", True),
                    "last_check": self._last_check.get(vendor),
                    "auto_download": source.config.get(
                        "auto_download",
                        self.config.get("default_auto_download", False),
                    ) if isinstance(source.config, dict) else getattr(source.config, "auto_download", False),
                    "channel": self._get_source_channel(source),
                    "include_beta": self._get_source_channel(source) in ("beta", "all"),
                }
                for vendor, source in self._sources.items()
            },
            "available_updates": [
                {
                    "vendor": fw.vendor,
                    "model": fw.model,
                    "version": fw.version,
                    "filename": fw.filename,
                    "download_url": fw.download_url,
                    "channel": fw.channel,
                }
                for fw in self._available_updates
            ],
        }


# Singleton pattern (matches notifier.py, telemetry.py)
_checker: Optional[FirmwareChecker] = None


def init_firmware_checker(
    config: dict,
    firmware_manager: FirmwareManager,
    firmware_path,
    notifier=None,
) -> FirmwareChecker:
    """Initialize the global firmware checker instance."""
    global _checker
    _checker = FirmwareChecker(
        config=config,
        firmware_manager=firmware_manager,
        firmware_path=firmware_path,
        notifier=notifier,
    )
    return _checker


def get_firmware_checker() -> Optional[FirmwareChecker]:
    """Get the global firmware checker instance."""
    return _checker
