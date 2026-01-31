"""Minimal telemetry for central analytics reporting.

Fire-and-forget HTTP POSTs to a configurable endpoint.
Never blocks provisioning — all errors are logged and swallowed.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from .config import AnalyticsConfig

logger = logging.getLogger(__name__)

_config: Optional[AnalyticsConfig] = None
_session: Optional[aiohttp.ClientSession] = None


def init(config: AnalyticsConfig) -> None:
    """Store analytics config. Session is created lazily on first emit."""
    global _config
    _config = config
    if config.enabled and config.url:
        logger.info(f"Telemetry enabled: site_id={config.site_id} url={config.url}")
    else:
        logger.info("Telemetry disabled")


async def emit(event: dict) -> None:
    """POST an event to the analytics endpoint.

    Fire-and-forget: logs warnings on failure, never raises.
    No-op if telemetry is disabled or not configured.
    """
    global _session

    if not _config or not _config.enabled or not _config.url:
        return

    # Add standard fields
    event.setdefault("site_id", _config.site_id)
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

    try:
        if _session is None or _session.closed:
            timeout = aiohttp.ClientTimeout(total=5)
            _session = aiohttp.ClientSession(timeout=timeout)

        headers = {"Content-Type": "application/json"}
        if _config.api_key:
            headers["Authorization"] = f"Bearer {_config.api_key}"

        async with _session.post(_config.url, json=event, headers=headers) as resp:
            if resp.status >= 400:
                logger.warning(f"Telemetry POST returned {resp.status}")
            else:
                logger.debug(f"Telemetry event sent: {event.get('event')}")

    except Exception as e:
        logger.warning(f"Telemetry POST failed: {e}")


async def close() -> None:
    """Close the shared HTTP session."""
    global _session
    if _session and not _session.closed:
        try:
            await _session.close()
        except Exception:
            pass
    _session = None
