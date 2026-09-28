"""Evidence-derived qualification matrix.

A post-provision mode (AP or PTP) is offered for a model and firmware only
after the bench recorded both directions of that transition as ``success``
in a committed evidence manifest (``bench-evidence/<vendor>/<model>/<firmware>/
manifest.yaml``, key ``transitions``). The standard SM baseline is
``baseline_qualified`` once ``fresh -> sm`` is recorded.

This module contains no vendor names. The handler advertises what a model
*could* do; this matrix returns what the bench has *proven*. An unknown
model or firmware proves nothing.

A bench override can open modes for one exact model and firmware before the
evidence exists, so that the bench can run the first transitions. The
override lives in one host file, names who set it, and carries an expiry of
at most ``OVERRIDE_MAX_HOURS``. Every check reads the file again. Once the
expiry passes, the check deletes the file, logs the re-lock, and offers only
the recorded modes. No person has to remember to remove it.
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

import yaml

Transition = Tuple[str, str]

#: Transitions each advertised mode needs, both directions.
MODE_REQUIREMENTS = {
    "ap": frozenset((("sm", "ap"), ("ap", "sm"))),
    "ptp": frozenset((("sm", "ptp"), ("ptp", "sm"))),
}  # type: Dict[str, FrozenSet[Transition]]
BASELINE_TRANSITION = ("fresh", "sm")  # type: Transition
TRANSITION_STATES = ("fresh", "sm", "ap", "ptp", "router", "switch")

_ENV_ROOT = "PROVISIONER_QUALIFICATION_ROOT"
_DEFAULT_ROOT = Path(__file__).resolve().parent.parent / "bench-evidence"
_ENV_OVERRIDE = "PROVISIONER_QUALIFICATION_OVERRIDE"
_DEFAULT_OVERRIDE = Path("/var/lib/provisioner/qualification-override.json")
OVERRIDE_MAX_HOURS = 24
logger = logging.getLogger(__name__)
_NORMALIZE_RE = re.compile(r"[^a-z0-9.]+")
_cache = {}  # type: Dict[str, Dict[Tuple[str, str, str], FrozenSet[Transition]]]


def normalize(value: Optional[str]) -> str:
    """Normalize a vendor, model, or firmware string for matching.

    ``"ePMP 4518"`` and ``"epmp-4518"`` match. ``"1.15.1 rev 8541"`` and
    ``"1.15.1-rev-8541"`` match. An empty value never matches anything.
    """
    if value is None:
        return ""
    text = str(value).strip().lower()
    text = _NORMALIZE_RE.sub("-", text).strip("-.")
    return text


def evidence_root() -> Path:
    return Path(os.environ.get(_ENV_ROOT) or _DEFAULT_ROOT)


def clear_cache() -> None:
    _cache.clear()


def load_matrix(root: Optional[Path] = None) -> Dict[Tuple[str, str, str], FrozenSet[Transition]]:
    """Return ``(vendor, model, firmware) -> successful transitions``.

    Only ``result: success`` rows count. A ``failure`` row for the same
    transition removes it, so a later failed bench run withdraws a mode.
    """
    root = Path(root) if root else evidence_root()
    key = str(root.resolve()) if root.exists() else str(root)
    if key in _cache:
        return _cache[key]
    matrix = {}  # type: Dict[Tuple[str, str, str], Set[Transition]]
    for manifest_path in sorted(root.glob("*/*/*/manifest.yaml")) if root.is_dir() else []:
        try:
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(manifest, dict):
            continue
        ident = (
            normalize(manifest.get("vendor")),
            normalize(manifest.get("model")),
            normalize(manifest.get("firmware")),
        )
        if not all(ident):
            continue
        successes = matrix.setdefault(ident, set())
        failures = set()  # type: Set[Transition]
        for row in manifest.get("transitions") or []:
            if not isinstance(row, dict):
                continue
            transition = (normalize(row.get("from")), normalize(row.get("to")))
            if transition[0] not in TRANSITION_STATES or transition[1] not in TRANSITION_STATES:
                continue
            if normalize(row.get("result")) == "success":
                successes.add(transition)
            else:
                failures.add(transition)
        successes.difference_update(failures)
    frozen = {ident: frozenset(value) for ident, value in matrix.items()}
    _cache[key] = frozen
    return frozen


def recorded_transitions(vendor: Optional[str], model: Optional[str], firmware: Optional[str]) -> FrozenSet[Transition]:
    """Return the successful transitions recorded for one exact model and firmware."""
    ident = (normalize(vendor), normalize(model), normalize(firmware))
    if not all(ident):
        return frozenset()
    return load_matrix().get(ident, frozenset())


def override_path() -> Path:
    return Path(os.environ.get(_ENV_OVERRIDE) or _DEFAULT_OVERRIDE)


def _parse_utc(value: object) -> Optional[datetime]:
    try:
        parsed = datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def write_override(
    vendor: str,
    model: str,
    firmware: str,
    modes: Iterable[str],
    set_by: str,
    hours: float,
    reason: str = "",
    now: Optional[datetime] = None,
    dry_run: bool = False,
) -> Dict[str, object]:
    """Write a bench override that expires after *hours* (at most 24).

    With *dry_run*, validate and return the record without writing it.
    """
    if not set_by.strip():
        raise ValueError("set_by is required")
    if not 0 < hours <= OVERRIDE_MAX_HOURS:
        raise ValueError("hours must be more than 0 and at most %d" % OVERRIDE_MAX_HOURS)
    wanted = sorted({str(mode).lower() for mode in modes})
    unknown = [mode for mode in wanted if mode not in MODE_REQUIREMENTS]
    if not wanted or unknown:
        raise ValueError("modes must be one or more of %s" % ", ".join(sorted(MODE_REQUIREMENTS)))
    start = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    record = {
        "vendor": vendor,
        "model": model,
        "firmware": firmware,
        "modes": wanted,
        "set_by": set_by.strip(),
        "reason": reason,
        "set_utc": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_utc": (start + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }  # type: Dict[str, object]
    if dry_run:
        return record
    path = override_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    os.chmod(str(path), 0o600)
    logger.warning(
        "Bench qualification override set by %s for %s %s %s (%s), expires %s",
        record["set_by"], vendor, model, firmware, ", ".join(wanted), record["expires_utc"],
    )
    return record


def clear_override(reason: str) -> bool:
    """Delete the override file. Return whether one existed."""
    path = override_path()
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    logger.warning("Bench qualification override removed: %s", reason)
    return True


def active_override(now: Optional[datetime] = None) -> Optional[Dict[str, object]]:
    """Return the unexpired override record, or None.

    An expired, unreadable, or malformed override is deleted, which re-locks
    the matrix. An expiry more than ``OVERRIDE_MAX_HOURS`` after the set time
    counts as malformed.
    """
    path = override_path()
    if not path.is_file():
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        clear_override("unreadable file")
        return None
    if not isinstance(record, dict):
        clear_override("malformed file")
        return None
    set_at = _parse_utc(record.get("set_utc"))
    expires = _parse_utc(record.get("expires_utc"))
    if (
        set_at is None
        or expires is None
        or not str(record.get("set_by") or "").strip()
        or expires - set_at > timedelta(hours=OVERRIDE_MAX_HOURS)
    ):
        clear_override("malformed file")
        return None
    if (now or datetime.now(timezone.utc)) >= expires:
        clear_override("expired at %s, set by %s" % (record["expires_utc"], record["set_by"]))
        return None
    return record


def override_modes(
    vendor: Optional[str], model: Optional[str], firmware: Optional[str]
) -> FrozenSet[str]:
    """Return the modes an active override opens for this exact device."""
    record = active_override()
    if record is None:
        return frozenset()
    ident = (normalize(vendor), normalize(model), normalize(firmware))
    target = tuple(normalize(str(record.get(key) or "")) for key in ("vendor", "model", "firmware"))
    if not all(ident) or ident != target:
        return frozenset()
    listed = record.get("modes")
    modes = frozenset(str(mode).lower() for mode in listed) if isinstance(listed, list) else frozenset()
    if modes:
        logger.warning(
            "Bench qualification override active for %s %s %s (%s): set by %s, expires %s",
            vendor, model, firmware, ", ".join(sorted(modes)), record["set_by"], record["expires_utc"],
        )
    return modes


def baseline_qualified(vendor: Optional[str], model: Optional[str], firmware: Optional[str]) -> bool:
    """Return whether ``fresh -> sm`` is recorded for this model and firmware."""
    return BASELINE_TRANSITION in recorded_transitions(vendor, model, firmware)


def qualified_modes(
    vendor: Optional[str],
    model: Optional[str],
    firmware: Optional[str],
    advertised: Iterable[str],
    requirements: Optional[Dict[str, FrozenSet[Transition]]] = None,
) -> Tuple[str, ...]:
    """Intersect the handler's advertised modes with the bench evidence.

    An active bench override adds its modes, but only modes the handler
    advertises.
    """
    recorded = recorded_transitions(vendor, model, firmware)
    opened = override_modes(vendor, model, firmware)
    qualified = []  # type: List[str]
    for mode in advertised:
        if str(mode).lower() in opened:
            qualified.append(mode)
            continue
        required = (MODE_REQUIREMENTS if requirements is None else requirements).get(str(mode).lower())
        if required is None:
            continue
        if required <= recorded:
            qualified.append(mode)
    return tuple(qualified)


def unqualified_reason(
    vendor: Optional[str], model: Optional[str], firmware: Optional[str], mode: str
) -> str:
    """Return a short operator-facing reason why *mode* is not offered."""
    label = str(mode).upper()
    if not model or not firmware:
        return "%s not qualified: model or firmware unknown" % label
    recorded = recorded_transitions(vendor, model, firmware)
    required = MODE_REQUIREMENTS.get(str(mode).lower(), frozenset())
    missing = sorted(required - recorded)
    if not recorded:
        return "%s not qualified for %s on %s: no bench evidence" % (label, model, firmware)
    if missing:
        paths = ", ".join("%s->%s" % pair for pair in missing)
        return "%s not qualified for %s on %s: missing %s" % (label, model, firmware, paths)
    return "%s qualified for %s on %s" % (label, model, firmware)


def transition_report(vendor: Optional[str], model: Optional[str], firmware: Optional[str]) -> Dict[str, bool]:
    """Return every known transition with its recorded state, for the UI."""
    recorded = recorded_transitions(vendor, model, firmware)
    known = {BASELINE_TRANSITION}  # type: Set[Transition]
    for required in MODE_REQUIREMENTS.values():
        known |= set(required)
    return {"%s->%s" % pair: pair in recorded for pair in sorted(known)}
