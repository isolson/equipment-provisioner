"""Base class for vendor firmware sources."""

import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class RemoteFirmwareInfo:
    """Firmware metadata from a remote source."""

    vendor: str
    model: str  # e.g., "tna-30x", "epmp-ax", "LBE-5AC-Gen2"
    version: str
    download_url: str
    filename: str
    sha256: Optional[str] = None
    file_size: Optional[int] = None
    release_date: Optional[str] = None
    channel: str = "release"  # release, beta, etc.
    release_notes: Optional[str] = None
    extra: dict = field(default_factory=dict)


class BaseFirmwareSource(ABC):
    """Abstract base class for vendor firmware sources.

    Each vendor implements check_for_updates() to query their firmware
    distribution channel (API, web page, etc.) and return available firmware.
    """

    vendor: str  # "tachyon", "ubiquiti", "cambium"

    def __init__(self, config: dict):
        """Initialize with vendor-specific config dict.

        Args:
            config: Dict from FirmwareSourceConfig with keys like
                    enabled, check_interval, auto_download, channel, models, etc.
        """
        self.config = config

    @abstractmethod
    async def check_for_updates(self) -> list[RemoteFirmwareInfo]:
        """Query the vendor source and return available firmware.

        Returns all available firmware versions from the source.
        The caller decides which are new by comparing with local manifest.
        """
        ...

    async def download(
        self,
        firmware: RemoteFirmwareInfo,
        dest_path: Path,
        session: Optional[aiohttp.ClientSession] = None,
    ) -> bool:
        """Download firmware file to dest_path.

        Default implementation uses aiohttp GET with streaming writes.
        Override if vendor requires auth tokens or special headers.

        Args:
            firmware: Remote firmware info with download_url.
            dest_path: Where to save the file.
            session: Optional shared aiohttp session.

        Returns:
            True on success.
        """
        own_session = session is None
        if own_session:
            session = aiohttp.ClientSession()

        try:
            logger.info(f"Downloading {firmware.filename} from {firmware.download_url}")
            async with session.get(firmware.download_url, timeout=aiohttp.ClientTimeout(total=600)) as resp:
                if resp.status != 200:
                    logger.error(
                        f"Download failed for {firmware.filename}: HTTP {resp.status}"
                    )
                    return False

                dest_path.parent.mkdir(parents=True, exist_ok=True)
                sha256 = hashlib.sha256()
                total = 0

                with open(dest_path, "wb") as f:
                    async for chunk in resp.content.iter_chunked(8192):
                        f.write(chunk)
                        sha256.update(chunk)
                        total += len(chunk)

                logger.info(f"Downloaded {firmware.filename} ({total:,} bytes)")

                # Verify SHA256 if provided
                if firmware.sha256:
                    calculated = sha256.hexdigest().lower()
                    expected = firmware.sha256.lower()
                    if calculated != expected:
                        logger.error(
                            f"SHA256 mismatch for {firmware.filename}: "
                            f"expected {expected}, got {calculated}"
                        )
                        dest_path.unlink(missing_ok=True)
                        return False
                    logger.info(f"SHA256 verified for {firmware.filename}")

                return True

        except Exception as e:
            logger.error(f"Download error for {firmware.filename}: {e}")
            dest_path.unlink(missing_ok=True)
            return False
        finally:
            if own_session:
                await session.close()
