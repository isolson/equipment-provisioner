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
CLEAR_ROLE_LOCK_PATH_FMT = "/ztp/mikrotik/devices/{serial}/clear-role-lock"
CLEAR_CHECKIN_SECRET_PATH_FMT = "/ztp/mikrotik/devices/{serial}/clear-checkin-secret"
REGISTER_MIKROTIK_TIMEOUT = 15  # seconds


async def register_mikrotik(
    ztp_api_url: str,
    api_key: Optional[str],
    serial: str,
    mac: str,
    model: str,
    firmware_version: str,
    base_flash_version: str,
) -> dict:
    """POST contract-shaped MikroTik ZTP registration to the wifi-api.

    Per the equipment-provisioner contract, this is a distinct service from
    the generic equipment_registry webhook:
    - endpoint: `<ztp_api_url>/ztp/mikrotik/register`
    - auth: `X-API-Key`
    - idempotent by serial
    - role MUST NOT be sent — device self-detects on first phone-home

    Returns the parsed response body. Backends with the ship-ready readback
    (wifi PR #255) include `role`, `customer_id`, `has_checkin_secret` for
    the caller to assert on; older backends just return the inventory row
    fields, and the caller treats that as legacy.

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
                try:
                    return await resp.json(content_type=None) or {}
                except Exception:
                    return {}
            body = await resp.text()
            raise RuntimeError(
                f"MikroTik registration {url} returned {resp.status}: {body[:200]}"
            )


async def _post_ztp_device_action(
    ztp_api_url: str, api_key: Optional[str], path: str, action: str
) -> dict:
    """POST an API-key-gated per-device ZTP action; raise on non-2xx."""
    url = ztp_api_url.rstrip("/") + path
    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key

    timeout = aiohttp.ClientTimeout(total=REGISTER_MIKROTIK_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, headers=headers) as resp:
            if resp.status < 300:
                logger.warning(f"MikroTik ZTP {action}: {url} -> {resp.status}")
                try:
                    return await resp.json(content_type=None) or {}
                except Exception:
                    return {}
            body = await resp.text()
            raise RuntimeError(f"{action} {url} returned {resp.status}: {body[:200]}")


async def clear_role_lock(ztp_api_url: str, api_key: Optional[str], serial: str) -> dict:
    """Clear a recycled unit's locked role + customer assignment.

    Contract remediation for a stale ship-ready readback (role != unknown or
    customer_id set). Detaches the old customer on the backend, which logs a
    lifecycle event on the former customer's timeline.
    """
    return await _post_ztp_device_action(
        ztp_api_url,
        api_key,
        CLEAR_ROLE_LOCK_PATH_FMT.format(serial=serial),
        "clear-role-lock",
    )


async def clear_checkin_secret(ztp_api_url: str, api_key: Optional[str], serial: str) -> dict:
    """Clear the server-side TOFU checkin secret for a reflashed unit.

    A reflash wipes the device's copy of the secret while the server keeps
    the hash — under CHECKIN_SECRET_ENFORCE that unit would be rejected at
    the customer home. Always required after netinstalling a previously
    enrolled unit; re-opens the first-contact window for this serial.
    """
    return await _post_ztp_device_action(
        ztp_api_url,
        api_key,
        CLEAR_CHECKIN_SECRET_PATH_FMT.format(serial=serial),
        "clear-checkin-secret",
    )
