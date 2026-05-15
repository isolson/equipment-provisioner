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


REGISTER_MIKROTIK_PATH = "/ztp/mikrotik/register"
REGISTER_MIKROTIK_TIMEOUT = 15  # seconds


async def register_mikrotik(
    ztp_api_url: str,
    api_key: Optional[str],
    serial: str,
    mac: str,
    model: str,
    firmware_version: str,
    base_flash_version: str,
) -> bool:
    """POST contract-shaped MikroTik ZTP registration to the wifi-api.

    Per the equipment-provisioner contract, this is a distinct service from
    the generic equipment_registry webhook:
    - endpoint: `<ztp_api_url>/ztp/mikrotik/register`
    - auth: `X-API-Key`
    - idempotent by serial
    - role MUST NOT be sent — device self-detects on first phone-home

    Raises on non-2xx so the caller can fail the provisioning job loudly
    rather than silently succeeding with an unregistered device.
    """
    url = ztp_api_url.rstrip("/") + REGISTER_MIKROTIK_PATH
    payload = {
        "serial": serial,
        "mac": mac,
        "model": model,
        "firmware_version": firmware_version,
        "base_flash_version": base_flash_version,
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    timeout = aiohttp.ClientTimeout(total=REGISTER_MIKROTIK_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            if resp.status < 300:
                logger.info(
                    f"MikroTik registered: serial={serial} model={model} "
                    f"firmware={firmware_version} -> {resp.status}"
                )
                return True
            body = await resp.text()
            raise RuntimeError(
                f"MikroTik registration {url} returned {resp.status}: {body[:200]}"
            )
