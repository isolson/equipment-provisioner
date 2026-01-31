"""Tachyon Networks firmware source.

Scrapes firmware download links from Tachyon's Freshdesk support pages.

Firmware URL pattern:
    https://tachyon-networks.com/fw/{product}/{version}/{filename}

Freshdesk article pages:
    - Index:   https://tachyon-networks.freshdesk.com/support/solutions/articles/67000714399
    - TNA-30x: https://tachyon-networks.freshdesk.com/support/solutions/articles/67000710575
    - TNA-303L: https://tachyon-networks.freshdesk.com/a/solutions/articles/67000745898
    - TNS-100: https://tachyon-networks.freshdesk.com/support/solutions/articles/67000719270
"""

import logging
import re
from typing import Optional

import aiohttp

from .base import BaseFirmwareSource, RemoteFirmwareInfo

logger = logging.getLogger(__name__)

# Freshdesk article URLs for each product line
FIRMWARE_PAGES = {
    "tna-30x": "https://tachyon-networks.freshdesk.com/support/solutions/articles/67000710575-tna-30x-firmware-releases",
    "tna-303l": "https://tachyon-networks.freshdesk.com/support/solutions/articles/67000745898-tna-303l-firmware-releases",
    "tns-100": "https://tachyon-networks.freshdesk.com/support/solutions/articles/67000719270-tns-100-firmware-releases",
}

# Regex to match Tachyon firmware download URLs
# Examples:
#   https://tachyon-networks.com/fw/tna-30x/1.12.3/tna-30x-1.12.3-r54970-...-sysupgrade.bin
#   https://tachyon-networks.com/fw/tns-100/1.12.8/tns-1.12.8-r54729-...-sysupgrade.bin
FIRMWARE_URL_PATTERN = re.compile(
    r'https://tachyon-networks\.com/fw/'
    r'(?P<product>[\w-]+)/'
    r'(?P<version>[\d.]+)/'
    r'(?P<filename>[^\s"<>]+\.bin)'
)

# Extract version and revision from filenames like:
#   tna-30x-1.12.3-r54970-20260115-...-sysupgrade.bin
#   tns-1.12.8-r54729-20251121-...-sysupgrade.bin
VERSION_PATTERN = re.compile(
    r'(?:tna-\w+|tns)-(\d+\.\d+\.\d+)-r(\d+)'
)


class TachyonFirmwareSource(BaseFirmwareSource):
    """Firmware source for Tachyon Networks devices.

    Scrapes firmware download links from Tachyon's Freshdesk knowledge base.
    """

    vendor = "tachyon"

    async def check_for_updates(self) -> list[RemoteFirmwareInfo]:
        """Scrape Tachyon Freshdesk pages for firmware downloads."""
        # Support both dict and Pydantic model configs
        if hasattr(self.config, "effective_channel"):
            channel = self.config.effective_channel
        else:
            # Dict config: check include_beta toggle, then fall back to channel
            if self.config.get("include_beta", False):
                channel = "all"
            else:
                channel = self.config.get("channel", "release")
        model_filter = self.config.get("models", []) if isinstance(self.config, dict) else (self.config.models if hasattr(self.config, "models") else [])
        results = []

        async with aiohttp.ClientSession() as session:
            for product, url in FIRMWARE_PAGES.items():
                # Skip products not in model filter (if filter is set)
                if model_filter and product not in model_filter:
                    continue

                try:
                    firmwares = await self._scrape_page(session, product, url, channel)
                    results.extend(firmwares)
                except Exception as e:
                    logger.error(f"Failed to scrape {product} firmware page: {e}")

        logger.info(f"Tachyon firmware check found {len(results)} firmware files")
        return results

    async def _scrape_page(
        self,
        session: aiohttp.ClientSession,
        product: str,
        url: str,
        channel: str,
    ) -> list[RemoteFirmwareInfo]:
        """Scrape a single Freshdesk article page for firmware links.

        Args:
            session: aiohttp session.
            product: Product identifier (tna-30x, tna-303l, tns-100).
            url: Freshdesk article URL.
            channel: "release", "beta", or "all".

        Returns:
            List of RemoteFirmwareInfo for each firmware found.
        """
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                logger.warning(f"HTTP {resp.status} fetching {url}")
                return []

            html = await resp.text()

        # Find all firmware download URLs in the page
        firmwares = []
        seen_versions = set()

        for match in FIRMWARE_URL_PATTERN.finditer(html):
            download_url = match.group(0)
            filename = match.group("filename")
            url_version = match.group("version")

            # Extract detailed version from filename (includes revision)
            version = self._extract_version(filename)
            if not version:
                version = url_version

            # Deduplicate by version
            if version in seen_versions:
                continue
            seen_versions.add(version)

            # Determine if this is beta based on page context
            is_beta = self._is_beta(html, download_url)

            # Channel filtering: "all" includes everything
            if channel != "all":
                if channel == "release" and is_beta:
                    continue
                if channel == "beta" and not is_beta:
                    continue

            firmwares.append(RemoteFirmwareInfo(
                vendor="tachyon",
                model=product,
                version=version,
                download_url=download_url,
                filename=filename,
                channel="beta" if is_beta else "release",
                extra={"product": product, "url_version": url_version},
            ))

        logger.debug(f"Found {len(firmwares)} {product} firmware files (channel={channel})")
        return firmwares

    def _extract_version(self, filename: str) -> Optional[str]:
        """Extract normalized version from firmware filename.

        Produces versions like "1.12.3.54970" matching what the device
        reports and what FirmwareManager expects.
        """
        m = VERSION_PATTERN.search(filename)
        if m:
            return f"{m.group(1)}.{m.group(2)}"
        return None

    def _is_beta(self, html: str, download_url: str) -> bool:
        """Check if a firmware link is in a beta section of the page.

        Looks for "beta" text near the download URL in the HTML.
        """
        idx = html.find(download_url)
        if idx < 0:
            return False
        # Check surrounding context (500 chars before the link)
        context = html[max(0, idx - 500):idx].lower()
        return "beta" in context
