"""Evidence-derived qualification matrix.

A post-provision mode (AP or PTP) is offered for a model and firmware only
after the bench recorded both directions of that transition as ``success``
in a committed evidence manifest (``bench-evidence/<vendor>/<model>/<firmware>/
manifest.yaml``, key ``transitions``). The standard SM baseline is
``baseline_qualified`` once ``fresh -> sm`` is recorded.

This module contains no vendor names. The handler advertises what a model
*could* do; this matrix returns what the bench has *proven*. An unknown
model or firmware proves nothing.
"""

import os
import re
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
TRANSITION_STATES = ("fresh", "sm", "ap", "ptp")

_ENV_ROOT = "PROVISIONER_QUALIFICATION_ROOT"
_DEFAULT_ROOT = Path(__file__).resolve().parent.parent / "bench-evidence"
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


def baseline_qualified(vendor: Optional[str], model: Optional[str], firmware: Optional[str]) -> bool:
    """Return whether ``fresh -> sm`` is recorded for this model and firmware."""
    return BASELINE_TRANSITION in recorded_transitions(vendor, model, firmware)


def qualified_modes(
    vendor: Optional[str],
    model: Optional[str],
    firmware: Optional[str],
    advertised: Iterable[str],
) -> Tuple[str, ...]:
    """Intersect the handler's advertised modes with the bench evidence."""
    recorded = recorded_transitions(vendor, model, firmware)
    qualified = []  # type: List[str]
    for mode in advertised:
        required = MODE_REQUIREMENTS.get(str(mode).lower())
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
