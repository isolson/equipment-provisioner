"""Shared config deep-merge utility (vendor-neutral).

One merge rule for every config-layer composition in the tree, promoted from
the per-handler implementation that predates it (design:
``docs/design-config-resolution.md`` §2.2):

- dict ∧ dict  → recursive merge, later (overlay) value wins per key;
- everything else (lists, scalars, ``None``) → the overlay value replaces
  the base value wholesale.

The list rule is deliberate and hazardous: an overlay that touches a list
replaces the *entire* list, so hand-authored overlays must carry complete
list values — and therefore must never touch list-embedded identity or
secret fields (see the role-overlay rules in
``docs/HANDLER_DEVELOPMENT.md``).

This module must stay free of vendor names and vendor semantics.
"""

from typing import Any, Dict


def deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``overlay`` into ``base``; overlay wins on conflict.

    Neither input is mutated. Nested dicts are copied on write; values taken
    from either side are shared by reference (callers treat configs as
    read-only once merged).
    """
    merged = base.copy()
    for key, value in overlay.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged
