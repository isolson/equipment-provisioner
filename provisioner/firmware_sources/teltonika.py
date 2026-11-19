"""Pinned TSW202 firmware release recorded in the bench profile."""

from .base import BaseFirmwareSource, RemoteFirmwareInfo


class TeltonikaFirmwareSource(BaseFirmwareSource):
    vendor = "teltonika"

    async def check_for_updates(self) -> list[RemoteFirmwareInfo]:
        return [
            RemoteFirmwareInfo(
                vendor=self.vendor,
                model="TSW202",
                version="TSW2_R_00.01.10.4",
                download_url=(
                    "https://firmware.teltonika-networks.com/1.10.4/TSW2/"
                    "TSW2_R_00.01.10.4_WEBUI.bin"
                ),
                filename="TSW2_R_00.01.10.4_WEBUI.bin",
                extra={"md5": "b2a4da07cb055ed198434d3e60c62fef"},
            )
        ]
