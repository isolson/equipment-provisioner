"""Equipment registry — push device metadata to a remote API after provisioning."""

import logging
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


async def register_equipment(
    url: str,
    api_key: Optional[str],
    serial: str,
    mac: str,
    device_type: str,
    model: Optional[str] = None,
    firmware_version: Optional[str] = None,
) -> bool:
    """POST device metadata to the configured equipment registry.

    Fire-and-forget: logs success/failure but never raises.
    Returns True on success, False on failure.
    """
    payload = {
        "serial": serial,
        "mac": mac,
        "device_type": device_type,
    }
    if model:
        payload["model"] = model
    if firmware_version:
        payload["firmware_version"] = firmware_version

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status < 300:
                    logger.info(f"Equipment registered: {serial} ({device_type}) -> {resp.status}")
                    return True
                else:
                    body = await resp.text()
                    logger.warning(f"Equipment registry returned {resp.status}: {body[:200]}")
                    return False
    except Exception as e:
        logger.warning(f"Equipment registry request failed: {e}")
        return False
