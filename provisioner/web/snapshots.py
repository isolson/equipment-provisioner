"""Snapshot store web API (R3, epic #112, issue #116).

Read/delete surface for device-config snapshots. Every response body is
produced by the centralized redaction serializer
(``snapshot_store.redact_snapshot``) — this router never touches a full
snapshot document, so secret-classified fields (``identity.wireless.psk``,
the whole ``raw.content`` blob, and any unclassified identity field) cannot
appear in an HTTP response. See ``docs/design-config-resolution.md``
§3.3/§4.

There is deliberately NO HTTP write endpoint: the kiosk UI is
unauthenticated, and capture (R4) runs in-process via
``SnapshotStore.save()``.
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

from ..snapshot_store import (
    SnapshotNotFound,
    SnapshotSchemaMismatch,
    SnapshotStore,
    SnapshotUnreadable,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["snapshots"])


def _get_store(request: Request) -> SnapshotStore:
    """Resolve (and cache) the app's snapshot store.

    Built lazily from the provisioner config (``snapshots.path`` or the
    derived ``snapshots`` sibling of ``data.local_path``) so this module
    needs no changes to app/provisioner startup. R4's capture path may
    pre-set ``app.state.snapshot_store``; if so it is reused as-is.
    """
    store = getattr(request.app.state, "snapshot_store", None)
    if store is not None:
        return store
    provisioner = getattr(request.app.state, "provisioner", None)
    config = getattr(provisioner, "config", None) if provisioner else None
    if config is None:
        raise HTTPException(
            status_code=503, detail="Snapshot store unavailable (no provisioner config)"
        )
    store = SnapshotStore.from_config(config)
    request.app.state.snapshot_store = store
    return store


@router.get("/snapshots")
async def list_snapshots(
    request: Request,
    vendor: Optional[str] = Query(default=None),
    serial_number: Optional[str] = Query(default=None),
    mac_address: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """List snapshots (newest first), paginated and redacted.

    Corrupt or newer-schema files on disk are skipped (logged server-side);
    ``skipped_unreadable`` reports the count. No secret-classified field
    value ever appears in this response.
    """
    store = _get_store(request)
    return store.list_redacted(
        vendor=vendor,
        serial_number=serial_number,
        mac_address=mac_address,
        limit=limit,
        offset=offset,
    )


@router.get("/snapshots/{snapshot_id}")
async def get_snapshot(request: Request, snapshot_id: str):
    """Get one snapshot, masked per the R0 redaction map.

    Secrets never leave the server: ``identity.wireless.psk`` is replaced
    by ``psk_present``/``psk_length``, ``raw.content`` by
    ``content_present``. Full values are readable only by the internal
    apply path (``SnapshotStore.load_full``, R5/R6).
    """
    store = _get_store(request)
    try:
        return store.get_redacted(snapshot_id)
    except SnapshotNotFound:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    except SnapshotSchemaMismatch as e:
        raise HTTPException(status_code=409, detail=str(e))
    except SnapshotUnreadable:
        raise HTTPException(
            status_code=422,
            detail="Snapshot file is corrupt or unreadable; it can still be deleted",
        )


@router.delete("/snapshots/{snapshot_id}")
async def delete_snapshot(request: Request, snapshot_id: str):
    """Delete a snapshot — allowed even for corrupt or newer-schema files
    (manual cleanup must always work regardless of retention)."""
    store = _get_store(request)
    try:
        store.delete(snapshot_id)
    except SnapshotNotFound:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return {"message": "Snapshot %s deleted" % snapshot_id}
