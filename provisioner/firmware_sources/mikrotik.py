"""MikroTik RouterOS firmware source."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from .base import BaseFirmwareSource, RemoteFirmwareInfo

logger = logging.getLogger(__name__)

LATEST_VERSION_URL = "https://upgrade.mikrotik.com/routeros/NEWESTa7.{channel}"
DOWNLOAD_URL = "https://download.mikrotik.com/routeros/{version}/{filename}"


class MikrotikFirmwareSource(BaseFirmwareSource):
    """Firmware source for MikroTik RouterOS packages."""

    vendor = "mikrotik"
    SUPPORTED_CHANNELS = ("long-term", "stable", "testing")
    CHANNEL_ALIASES = {
        "lts": "long-term",
        "longterm": "long-term",
        "long_term": "long-term",
        "release": "stable",  # Backward-compatible with existing configs/UI
        "beta": "testing",
    }
    DEFAULT_ARCHITECTURES = (
        "arm",
        "arm64",
        "mipsbe",
        "mmips",
        "smips",
        "ppc",
        "x86",
        "x86_64",
    )

    def normalize_channel(self, channel: Optional[str]) -> str:
        """Normalize channel with backward-compatible aliases."""
        if not channel:
            return "long-term"
        normalized = self.CHANNEL_ALIASES.get(channel.strip().lower(), channel.strip().lower())
        if normalized not in self.SUPPORTED_CHANNELS:
            return "long-term"
        return normalized

    def get_supported_channels(self) -> list[str]:
        """Return supported MikroTik channels."""
        return list(self.SUPPORTED_CHANNELS)

    def _configured_channel(self) -> str:
        """Read channel from config and normalize it."""
        if isinstance(self.config, dict):
            raw_channel = self.config.get("channel", "long-term")
        else:
            raw_channel = getattr(self.config, "channel", "long-term")
        return self.normalize_channel(raw_channel)

    def _configured_architectures(self) -> list[str]:
        """Read architecture filter from config.models (empty means defaults)."""
        if isinstance(self.config, dict):
            models = self.config.get("models", [])
        else:
            models = getattr(self.config, "models", [])

        if not models:
            return list(self.DEFAULT_ARCHITECTURES)

        if isinstance(models, str):
            models = [models]

        normalized = []
        for value in models:
            if not value:
                continue
            item = str(value).strip().lower()
            if item in {"*", "all"}:
                return list(self.DEFAULT_ARCHITECTURES)
            if item not in normalized:
                normalized.append(item)

        return normalized or list(self.DEFAULT_ARCHITECTURES)

    async def check_for_updates(self) -> list[RemoteFirmwareInfo]:
        """Query MikroTik update metadata and return available architecture packages."""
        channel = self._configured_channel()
        architectures = self._configured_architectures()

        async with aiohttp.ClientSession() as session:
            version, release_date = await self._fetch_latest_version(session, channel)
            if not version:
                logger.warning("Could not resolve latest MikroTik version for channel '%s'", channel)
                return []

            tasks = [
                self._build_firmware_info(session, channel, version, architecture, release_date)
                for architecture in architectures
            ]
            resolved = await asyncio.gather(*tasks, return_exceptions=True)

        results: list[RemoteFirmwareInfo] = []
        for item in resolved:
            if isinstance(item, Exception):
                logger.debug("Skipping MikroTik firmware candidate due to error: %s", item)
                continue
            if item:
                results.append(item)

        logger.info(
            "MikroTik firmware check found %d package(s) for channel=%s version=%s",
            len(results),
            channel,
            version,
        )
        return results

    async def _build_firmware_info(
        self,
        session: aiohttp.ClientSession,
        channel: str,
        version: str,
        architecture: str,
        release_date: Optional[str],
    ) -> Optional[RemoteFirmwareInfo]:
        """Build one firmware entry if the package exists."""
        filename = f"routeros-{architecture}-{version}.npk"
        url = DOWNLOAD_URL.format(version=version, filename=filename)

        exists = await self._firmware_url_exists(session, url)
        if not exists:
            logger.debug("MikroTik package not found: %s", url)
            return None

        return RemoteFirmwareInfo(
            vendor="mikrotik",
            model=architecture,
            version=version,
            download_url=url,
            filename=filename,
            release_date=release_date,
            channel=channel,
            extra={"architecture": architecture},
        )

    async def _fetch_latest_version(
        self,
        session: aiohttp.ClientSession,
        channel: str,
    ) -> tuple[Optional[str], Optional[str]]:
        """Fetch latest version for a channel from upgrade.mikrotik.com."""
        url = LATEST_VERSION_URL.format(channel=channel)
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    logger.warning("MikroTik latest version lookup failed (%s): HTTP %s", url, resp.status)
                    return None, None
                body = (await resp.text()).strip()
        except Exception as exc:
            logger.error("MikroTik latest version lookup error (%s): %s", url, exc)
            return None, None

        tokens = body.split()
        if not tokens:
            return None, None

        version = tokens[0].strip()
        release_date = None
        if len(tokens) > 1:
            try:
                release_date = datetime.fromtimestamp(int(tokens[1]), tz=timezone.utc).date().isoformat()
            except Exception:
                release_date = None
        return version, release_date

    async def _firmware_url_exists(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Check if package URL exists."""
        try:
            async with session.head(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    return True
                if resp.status == 404:
                    return False
        except Exception:
            pass

        # Some endpoints may reject HEAD; probe with a tiny GET fallback.
        try:
            async with session.get(
                url,
                headers={"Range": "bytes=0-0"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                return resp.status in (200, 206)
        except Exception:
            return False
