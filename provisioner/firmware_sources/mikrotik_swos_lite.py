"""Firmware source for SwOS Lite GPEN21 images."""

import re

import aiohttp

from .base import BaseFirmwareSource, RemoteFirmwareInfo

LATEST_URL = "http://upgrade.mikrotik.com/swoslite/gpen21/LATEST"
IMAGE_URL = "http://upgrade.mikrotik.com/swoslite/gpen21/swos-gpen21-{version}.bin"


class MikrotikSwosLiteFirmwareSource(BaseFirmwareSource):
    """Resolve the latest GPEN21 image from the vendor update endpoint."""

    vendor = "mikrotik_swos_lite"

    async def check_for_updates(self) -> list[RemoteFirmwareInfo]:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(LATEST_URL) as response:
                if response.status != 200:
                    return []
                version = (await response.text()).strip()
        if not re.fullmatch(r"\d+\.\d+", version):
            return []
        filename = "swos-gpen21-%s.bin" % version
        return [
            RemoteFirmwareInfo(
                vendor=self.vendor,
                model="GPEN21",
                version=version,
                download_url=IMAGE_URL.format(version=version),
                filename=filename,
            )
        ]
