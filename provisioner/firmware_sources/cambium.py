"""Cambium Networks firmware source (stub).

Cambium distributes firmware through cnMaestro (cloud management platform)
and direct downloads. The cnMaestro API requires an API key.

TODO: Implement Cambium firmware API integration.
"""

import logging

from .base import BaseFirmwareSource, RemoteFirmwareInfo

logger = logging.getLogger(__name__)


class CambiumFirmwareSource(BaseFirmwareSource):
    """Firmware source for Cambium Networks devices.

    Uses cnMaestro API or direct download endpoints to discover firmware.
    """

    vendor = "cambium"

    async def check_for_updates(self) -> list[RemoteFirmwareInfo]:
        """Query Cambium for available firmware updates.

        Returns:
            Empty list (stub). Will return firmware list when implemented.
        """
        logger.info("Cambium firmware source not yet implemented")
        return []
