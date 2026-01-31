"""Ubiquiti firmware source (stub).

Ubiquiti publishes firmware metadata at:
    https://fw-update.ubnt.com/api/firmware-latest?filter=eq~~product.name~~airmax&filter=eq~~channel~~release

This returns JSON with download URLs, versions, and SHA256 checksums
for all AirMax products.

TODO: Implement full parsing of the Ubiquiti firmware API response.
"""

import logging

from .base import BaseFirmwareSource, RemoteFirmwareInfo

logger = logging.getLogger(__name__)

# Known API endpoint for AirMax firmware
AIRMAX_FIRMWARE_API = (
    "https://fw-update.ubnt.com/api/firmware-latest"
    "?filter=eq~~product.name~~airmax"
    "&filter=eq~~channel~~{channel}"
)


class UbiquitiFirmwareSource(BaseFirmwareSource):
    """Firmware source for Ubiquiti AirMax devices.

    Uses the public fw-update.ubnt.com API to discover available firmware.
    """

    vendor = "ubiquiti"

    async def check_for_updates(self) -> list[RemoteFirmwareInfo]:
        """Query Ubiquiti firmware API for available updates.

        Returns:
            Empty list (stub). Will return firmware list when implemented.
        """
        logger.info("Ubiquiti firmware source not yet implemented")
        return []
