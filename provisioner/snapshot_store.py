"""Device-config snapshot store (R3, epic #112, issue #116).

Persists one JSON document per captured device-config snapshot under the
data directory (default: a ``snapshots/`` sibling of ``data.local_path``,
i.e. ``/var/lib/provisioner/snapshots`` on the host — never hardcoded here,
always derived from config). Documents follow snapshot schema v1 from
``docs/design-config-resolution.md`` §3.

Security model (design doc §3.3/§4 — read before changing anything here):

- ``redact_snapshot()`` is the SINGLE serialization choke point for every
  external surface (HTTP list/get, UI, logs). It is allowlist-based: the
  ``identity`` block is default-secret — any identity field not explicitly
  classified public in the R0 redaction map is omitted. ``raw.content``
  (the vendor-native export) never leaves the server.
- ``load_full()`` is the only way to read secrets back and exists solely
  for the internal resolve/apply path (R5/R6). It must never feed an HTTP
  response or a log statement.
- This module logs snapshot ids, unit keys, field names, and counts only —
  never document contents.

Concurrency: a single lock serializes writes; ids are derived from
vendor + serial/MAC + UTC timestamp with a collision suffix, so six ports
capturing at the same second cannot collide (issue #116 edge case).

Corrupt or newer-schema files on disk are skipped with a logged warning —
they can never crash the service at boot.
"""

import json
import logging
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Snapshot document schema version this store reads and writes (design §3.1).
# Readers ignore unknown fields; documents with a NEWER version are refused.
SCHEMA_VERSION = 1

# Snapshot ids are used as filenames: constrain them hard (no separators,
# no dotfiles) so a crafted id can never traverse outside the store dir.
# Matched with fullmatch() and anchored with \Z, never $ — `$` matches
# before a trailing newline, which would let "advnl\n" become a filename
# and forge log lines (PR #129 review F2).
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z")

# Characters allowed in id components synthesized from serial/MAC/vendor.
_COMPONENT_STRIP_RE = re.compile(r"[^A-Za-z0-9_-]+")

# ---------------------------------------------------------------------------
# R0 §3.3 field-level redaction map (vendor-neutral).
#
# Top-level document metadata classified public:
PUBLIC_METADATA_FIELDS = (
    "schema_version",
    "id",
    "vendor",
    "model",
    "serial_number",
    "mac_address",
    "hostname",
    "firmware_at_capture",
    "captured_at",
    "source",
)

# identity.* paths classified public (everything else in identity is
# "secret until classified" — the default-secret rule).
#
# Paths are STRUCTURAL TUPLES, never joined dotted strings: a literal key
# that *contains* a dot (e.g. {"mgmt_ip.password": ...}) is a single opaque
# component that matches no tuple here, so it falls to default-secret —
# string joining would let such a key forge a public path (PR #129 review
# F1, the dotted-key spoof).
#
# Deliberate deviation from R0 §3.3's literal notation (review F3): the map
# writes `identity.mgmt_ip.*` / `identity.routing.*` as wildcards, but R0's
# own default-secret principle ("any identity field not explicitly listed is
# secret until classified") outranks its wildcard shorthand — so the
# schema-defined keys (§3.2) are enumerated here and an unknown key inside
# those containers is redacted like any other unclassified identity field.
# Flagged as a schema-note follow-up for the design doc.
PUBLIC_IDENTITY_PATHS = frozenset([
    ("wireless", "ssid"),
    ("mgmt_ip", "mode"),
    ("mgmt_ip", "address"),
    ("mgmt_ip", "prefix"),
    ("mgmt_ip", "gateway"),
    ("mgmt_ip", "vlan"),
    ("routing", "mode"),
    ("routing", "area"),
    ("ptp_role",),
    ("ptp_link_id",),
])

# identity.* secret path that gets a presence marker instead of silence:
# identity.wireless.psk -> psk_present: bool (+ psk_length). The value is
# still omitted everywhere. Tuple for the same structural-matching reason —
# a literal top-level "wireless.psk" key is default-secret, no marker.
_PSK_PATH = ("wireless", "psk")
# ---------------------------------------------------------------------------


class SnapshotStoreError(Exception):
    """Base error for snapshot-store operations."""


class SnapshotNotFound(SnapshotStoreError):
    """No snapshot with that id exists (or the id is not a valid id)."""


class SnapshotUnreadable(SnapshotStoreError):
    """The snapshot file exists but is corrupt/partial JSON."""


class SnapshotSchemaMismatch(SnapshotStoreError):
    """The snapshot's schema_version is newer than this code supports."""


def _utc_now_iso() -> str:
    """UTC ISO-8601 with Z suffix (Python 3.9: no datetime.UTC)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_utc(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp (Z suffix ok); None if unparseable."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _sanitize_component(value: str) -> str:
    """Reduce a serial/MAC/vendor string to filesystem-safe characters."""
    return _COMPONENT_STRIP_RE.sub("", value or "")


def _normalize_mac(value: str) -> str:
    """Lowercase a MAC and drop every separator (``:``/``-``/``.``)."""
    return re.sub(r"[^0-9A-Fa-f]", "", value or "").lower()


def _identity_path_has_public_descendants(path: Tuple[str, ...]) -> bool:
    """Should we recurse into this container looking for public fields?

    Tuple-prefix comparison (component by component) — a key containing a
    literal dot is one component and can never alias a deeper path.
    """
    depth = len(path)
    for public in PUBLIC_IDENTITY_PATHS:
        if len(public) > depth and public[:depth] == path:
            return True
    # Recurse toward the psk presence marker too.
    return len(_PSK_PATH) > depth and _PSK_PATH[:depth] == path


def _dotted(path: Tuple[str, ...]) -> str:
    """Display form for ``redacted_fields`` — names only, never values.

    Joining with '.' is display-only and plays no part in classification,
    so a key containing a dot merely renders ambiguously here; it cannot
    change what gets redacted.
    """
    return ".".join(("identity",) + path)


def _redact_identity(
    identity: Dict[str, Any], prefix: Tuple[str, ...] = ()
) -> Tuple[Dict[str, Any], List[str]]:
    """Allowlist-redact one identity (sub)tree.

    Returns (redacted subtree, names of omitted fields). Fields not
    explicitly classified public are OMITTED — default-secret per §3.3.
    Classification is by structural tuple path, so crafted keys containing
    dots cannot spoof a public path (PR #129 review F1).
    """
    result: Dict[str, Any] = {}
    dropped: List[str] = []
    for key in identity:
        value = identity[key]
        path = prefix + (key,)
        if path == _PSK_PATH:
            # Omitted; replaced by presence marker (+ length), never value.
            present = isinstance(value, str) and value != ""
            result["psk_present"] = present
            if present:
                result["psk_length"] = len(value)
            dropped.append(_dotted(path))
            continue
        if path in PUBLIC_IDENTITY_PATHS:
            result[key] = value
            continue
        if isinstance(value, dict) and _identity_path_has_public_descendants(path):
            sub, sub_dropped = _redact_identity(value, path)
            if path == _PSK_PATH[:-1] and "psk_present" not in sub:
                # Wireless block without a psk key: state absence explicitly
                # so the UI "PSK stored" badge has a definitive answer.
                sub["psk_present"] = False
            result[key] = sub
            dropped.extend(sub_dropped)
            continue
        dropped.append(_dotted(path))
    return result, dropped


def redact_snapshot(doc: Dict[str, Any]) -> Dict[str, Any]:
    """The centralized redaction serializer (design §3.3).

    Every snapshot representation that leaves the server process — API list
    and get responses, UI payloads, log summaries — MUST come through here.
    Never serialize a raw snapshot document on any external surface.

    Returns a new dict:
    - public document metadata copied through;
    - ``identity`` allowlist-filtered (default-secret for unclassified
      fields; ``psk`` replaced with ``psk_present``/``psk_length``);
    - ``raw`` reduced to format/encoding + ``content_present`` — the blob
      itself never leaves the server;
    - ``redacted_fields``: dotted names (never values) of what was omitted.
    """
    redacted: Dict[str, Any] = {}
    redacted_fields: List[str] = []

    for key in PUBLIC_METADATA_FIELDS:
        if key in doc:
            redacted[key] = doc[key]

    identity = doc.get("identity")
    if isinstance(identity, dict):
        redacted_identity, dropped = _redact_identity(identity)
        redacted["identity"] = redacted_identity
        redacted_fields.extend(dropped)
    elif identity is not None:
        redacted_fields.append("identity")

    raw = doc.get("raw")
    if isinstance(raw, dict):
        raw_meta: Dict[str, Any] = {"content_present": "content" in raw}
        for meta_key in ("format", "encoding"):
            if meta_key in raw:
                raw_meta[meta_key] = raw[meta_key]
        redacted["raw"] = raw_meta
        if "content" in raw:
            redacted_fields.append("raw.content")
    elif raw is not None:
        redacted_fields.append("raw")

    # Forward compatibility (§3.1): unknown top-level fields are ignored —
    # and, being unclassified, they are treated as secret and omitted.
    for key in doc:
        if key not in PUBLIC_METADATA_FIELDS and key not in ("identity", "raw"):
            redacted_fields.append(key)

    redacted["redacted_fields"] = sorted(set(redacted_fields))
    return redacted


class SnapshotStore:
    """One-JSON-file-per-snapshot store with retention and redaction.

    Directory layout: ``{base_path}/{id}.json`` — flat, filename stem is the
    snapshot id. Files are 0600 inside a 0700 directory (design §4 rule 1).
    The directory is only created on first write; read paths never create
    anything (so a read-only boot cannot fail on a missing/unwritable dir).
    """

    def __init__(
        self,
        base_path: str,
        max_per_unit: int = 5,
        max_total: int = 200,
    ):
        self.base_path = Path(base_path)
        self.max_per_unit = max(1, int(max_per_unit))
        self.max_total = max(1, int(max_total))
        self._lock = threading.Lock()

    # -- construction -------------------------------------------------------

    @classmethod
    def from_config(cls, config: Any) -> "SnapshotStore":
        """Build a store from the app Config.

        ``snapshots.path`` when set; otherwise derived as a ``snapshots``
        sibling of ``data.local_path`` (default config yields
        ``/var/lib/provisioner/snapshots``). No path is hardcoded here.
        """
        snapshots_cfg = getattr(config, "snapshots", None)
        path = getattr(snapshots_cfg, "path", None) if snapshots_cfg else None
        if not path:
            data_cfg = getattr(config, "data", None)
            local_path = getattr(data_cfg, "local_path", None) if data_cfg else None
            if not local_path:
                raise SnapshotStoreError(
                    "cannot derive snapshot path: config has no snapshots.path "
                    "and no data.local_path"
                )
            path = str(Path(local_path).parent / "snapshots")
        kwargs = {}
        if snapshots_cfg is not None:
            for knob in ("max_per_unit", "max_total"):
                value = getattr(snapshots_cfg, knob, None)
                if value is not None:
                    kwargs[knob] = value
        return cls(path, **kwargs)

    # -- write path (internal; R4 capture calls this) ------------------------

    def save(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Persist a snapshot document. Internal write path for R4 capture.

        Validates/synthesizes the required schema-v1 fields (design §3.2):
        ``vendor``, ``model``, ``source`` must be provided; ``id``,
        ``schema_version``, and ``captured_at`` are synthesized when absent.
        Returns the stored document (with the final ``id``).

        Never log or print the argument or return value — use the returned
        ``id`` for reporting.
        """
        if not isinstance(snapshot, dict):
            raise SnapshotStoreError("snapshot must be a dict")

        doc = dict(snapshot)

        for field in ("vendor", "model", "source"):
            value = doc.get(field)
            if not isinstance(value, str) or not value.strip():
                raise SnapshotStoreError(
                    "snapshot is missing required field %r" % field
                )

        version = doc.setdefault("schema_version", SCHEMA_VERSION)
        if not isinstance(version, int) or version < 1:
            raise SnapshotStoreError(
                "snapshot schema_version must be a positive integer"
            )
        if version > SCHEMA_VERSION:
            raise SnapshotSchemaMismatch(
                "snapshot schema_version %s is newer than supported (%s)"
                % (version, SCHEMA_VERSION)
            )

        if not doc.get("captured_at"):
            doc["captured_at"] = _utc_now_iso()

        provided_id = doc.get("id")
        if provided_id is not None and not (
            isinstance(provided_id, str) and _ID_RE.fullmatch(provided_id)
        ):
            raise SnapshotStoreError(
                "snapshot id must match %s" % _ID_RE.pattern
            )

        with self._lock:
            self._ensure_dir()
            snapshot_id = self._unique_id(provided_id or self._synthesize_id(doc))
            doc["id"] = snapshot_id
            self._atomic_write(self.base_path / (snapshot_id + ".json"), doc)
            logger.info(
                "Saved snapshot %s (vendor=%s, model=%s, source=%s)",
                snapshot_id, doc["vendor"], doc["model"], doc["source"],
            )
            self._enforce_retention(keep_id=snapshot_id)
        return doc

    # -- read paths ----------------------------------------------------------

    def list_redacted(
        self,
        vendor: Optional[str] = None,
        serial_number: Optional[str] = None,
        mac_address: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List snapshots, newest first, REDACTED via redact_snapshot().

        Corrupt or newer-schema files are skipped (with a logged warning);
        ``skipped_unreadable`` reports how many. Filters compare
        case-insensitively; MAC filters ignore ``:``/``-`` separators.
        """
        entries = []
        skipped = 0
        for snapshot_id, doc, _path in self._scan():
            if doc is None:
                skipped += 1
                continue
            if vendor and str(doc.get("vendor", "")).lower() != vendor.lower():
                continue
            if serial_number and str(doc.get("serial_number", "")).lower() != serial_number.lower():
                continue
            if mac_address and _normalize_mac(
                str(doc.get("mac_address", ""))
            ) != _normalize_mac(mac_address):
                continue
            entries.append(doc)

        entries.sort(key=lambda d: str(d.get("captured_at", "")), reverse=True)
        total = len(entries)
        page = entries[offset:offset + limit] if limit > 0 else []
        return {
            "snapshots": [redact_snapshot(doc) for doc in page],
            "total": total,
            "limit": limit,
            "offset": offset,
            "skipped_unreadable": skipped,
        }

    def get_redacted(self, snapshot_id: str) -> Dict[str, Any]:
        """Load one snapshot, REDACTED. The only per-snapshot read for HTTP/UI."""
        return redact_snapshot(self._load(snapshot_id))

    def load_full(self, snapshot_id: str) -> Dict[str, Any]:
        """INTERNAL APPLY PATH ONLY (design §3.3/§4 rule 2).

        Returns the full document including ``identity.wireless.psk`` and
        ``raw.content``. Callers: snapshot-derived config resolution and
        apply (R5/R6). NEVER return this from an HTTP endpoint, render it
        in a UI payload, or log any part of it.
        """
        return self._load(snapshot_id)

    def delete(self, snapshot_id: str) -> None:
        """Delete a snapshot by id — works even if the file is corrupt or a
        newer schema version (manual delete must always be possible)."""
        path = self._path_for(snapshot_id)
        if path is None or not path.is_file():
            raise SnapshotNotFound("no snapshot with id %r" % snapshot_id)
        with self._lock:
            try:
                path.unlink()
            except FileNotFoundError:
                raise SnapshotNotFound("no snapshot with id %r" % snapshot_id)
        logger.info("Deleted snapshot %s", snapshot_id)

    # -- internals -----------------------------------------------------------

    def _ensure_dir(self) -> None:
        self.base_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(str(self.base_path), 0o700)  # mkdir mode is umask-subject
        except OSError:  # pragma: no cover - permissions vary in tests/CI
            pass

    def _path_for(self, snapshot_id: str) -> Optional[Path]:
        """Map an id to its file path; None if the id is not a safe id."""
        if not isinstance(snapshot_id, str) or not _ID_RE.fullmatch(snapshot_id):
            return None
        return self.base_path / (snapshot_id + ".json")

    def _load(self, snapshot_id: str) -> Dict[str, Any]:
        path = self._path_for(snapshot_id)
        if path is None or not path.is_file():
            raise SnapshotNotFound("no snapshot with id %r" % snapshot_id)
        try:
            with open(path, "r") as f:
                doc = json.load(f)
        except (OSError, ValueError) as e:
            logger.warning("Snapshot %s is unreadable: %s", snapshot_id, e)
            raise SnapshotUnreadable(
                "snapshot %r is corrupt or unreadable" % snapshot_id
            )
        if not isinstance(doc, dict):
            logger.warning("Snapshot %s is not a JSON object", snapshot_id)
            raise SnapshotUnreadable(
                "snapshot %r is corrupt or unreadable" % snapshot_id
            )
        version = doc.get("schema_version")
        if isinstance(version, int) and version > SCHEMA_VERSION:
            raise SnapshotSchemaMismatch(
                "snapshot %r has schema_version %s, newer than supported (%s) "
                "— update the provisioner to read it" % (snapshot_id, version, SCHEMA_VERSION)
            )
        doc["id"] = snapshot_id  # filename stem is authoritative
        return doc

    def _scan(self) -> Iterator[Tuple[str, Optional[Dict[str, Any]], Path]]:
        """Yield (id, doc-or-None, path) for every *.json in the store.

        doc is None for corrupt/partial/newer-schema files — logged and
        skipped, never raised, so a bad file can never crash boot or list.
        """
        if not self.base_path.is_dir():
            return
        try:
            paths = sorted(self.base_path.glob("*.json"))
        except OSError as e:  # pragma: no cover - dir vanished mid-scan
            logger.warning("Snapshot scan failed for %s: %s", self.base_path, e)
            return
        for path in paths:
            snapshot_id = path.stem
            try:
                yield snapshot_id, self._load(snapshot_id), path
            except SnapshotStoreError as e:
                logger.warning("Skipping snapshot file %s: %s", path.name, e)
                yield snapshot_id, None, path

    def _synthesize_id(self, doc: Dict[str, Any]) -> str:
        """``{vendor}-{serial|mac}-{UTC timestamp}`` (design §3.2)."""
        vendor = _sanitize_component(str(doc.get("vendor", ""))) or "unknown"
        unit = _sanitize_component(str(doc.get("serial_number") or ""))
        if not unit:
            unit = _sanitize_component(str(doc.get("mac_address") or ""))
        if not unit:
            unit = "unit"
        parsed = _parse_iso_utc(doc.get("captured_at"))
        stamp = (parsed or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
        return "%s-%s-%s" % (vendor, unit, stamp)

    def _unique_id(self, snapshot_id: str) -> str:
        """Suffix -2, -3, ... if the id is already on disk (same unit, same
        second). Caller holds the lock."""
        candidate = snapshot_id
        counter = 2
        while (self.base_path / (candidate + ".json")).exists():
            candidate = "%s-%d" % (snapshot_id, counter)
            counter += 1
        return candidate

    def _atomic_write(self, path: Path, doc: Dict[str, Any]) -> None:
        """Temp file + fsync + rename, 0600 — a crash cannot leave a partial
        file under the final name (same pattern as config.py overrides)."""
        fd, tmp_path = tempfile.mkstemp(
            prefix=".snapshot.", suffix=".json.tmp", dir=str(self.base_path)
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(doc, f, indent=2, sort_keys=True)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _enforce_retention(self, keep_id: Optional[str] = None) -> None:
        """Cap + eviction (design D5 proposal): newest ``max_per_unit`` per
        (vendor, serial|mac) unit, newest ``max_total`` overall. Every
        eviction is logged (id + reason — public metadata only). Caller
        holds the lock. ``keep_id`` (the just-written snapshot) is exempt."""
        readable: List[Tuple[str, Dict[str, Any], Path]] = []
        for snapshot_id, doc, path in self._scan():
            if doc is not None:
                readable.append((snapshot_id, doc, path))

        def sort_key(item: Tuple[str, Dict[str, Any], Path]) -> str:
            return str(item[1].get("captured_at", ""))

        # Newest first within each unit.
        by_unit: Dict[Tuple[str, str], List[Tuple[str, Dict[str, Any], Path]]] = {}
        for item in readable:
            doc = item[1]
            unit = (
                str(doc.get("vendor", "")),
                str(doc.get("serial_number") or doc.get("mac_address") or "unknown"),
            )
            by_unit.setdefault(unit, []).append(item)

        evicted = set()
        for unit, items in by_unit.items():
            items.sort(key=sort_key, reverse=True)
            for snapshot_id, _doc, path in items[self.max_per_unit:]:
                if snapshot_id == keep_id:
                    continue
                self._evict(snapshot_id, path, "per-unit cap %d for %s/%s"
                            % (self.max_per_unit, unit[0], unit[1]))
                evicted.add(snapshot_id)

        remaining = [item for item in readable if item[0] not in evicted]
        if len(remaining) > self.max_total:
            remaining.sort(key=sort_key, reverse=True)
            for snapshot_id, _doc, path in remaining[self.max_total:]:
                if snapshot_id == keep_id:
                    continue
                self._evict(snapshot_id, path,
                            "total cap %d" % self.max_total)

    def _evict(self, snapshot_id: str, path: Path, reason: str) -> None:
        try:
            path.unlink()
        except OSError as e:  # pragma: no cover - already gone / perms
            logger.warning("Retention eviction of %s failed: %s", snapshot_id, e)
            return
        logger.info("Retention eviction: removed snapshot %s (%s)", snapshot_id, reason)
