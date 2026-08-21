"""Vendor-neutral config resolution (the resolver seam).

The resolver answers one question — "which ordered config layers apply to
this device for this job?" — upstream of the provisioning engine. It
replaces exactly one call site in ``main.py`` (the single static
``get_config_template`` lookup). Design: ``docs/design-config-resolution.md``.

It never enumerates vendors: per-vendor knowledge is consulted exclusively
through class-level handler traits via
``HandlerManager.handler_class_for(device_type)``, the same mechanism
``config_store.py`` already uses. Roles are opaque strings; the available
role set is derived from the template tree on disk, never a hardcoded enum.

Backward compatibility is structural: with an empty :class:`JobContext`
(no role, no replacement snapshot), ``resolve()`` returns exactly the
single file-backed layer today's lookup produces — no file is read, no
artifact is written, no overlay trait is consulted — and
``as_provision_args()`` passes the path through byte-identically.
"""

import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config_merge import deep_merge
from .config_templates import load_config_template

logger = logging.getLogger(__name__)

#: Where composed multi-layer configs are materialized (job-scoped JSON
#: artifacts, mode 0600, removed via :meth:`ResolvedConfig.cleanup` after
#: the job). Deliberately outside the template/data repo so runtime
#: artifacts never pollute the synced template tree.
RESOLVED_CONFIG_DIR = Path("/var/lib/provisioner/run/resolved")

#: Subdirectory of a vendor's template dir that holds role overlays:
#: ``configs/templates/{device_type}/roles/{role}/{model|alias|default}.json``
ROLES_SUBDIR = "roles"

#: Roles come from operator input (API) and config.yaml, and become path
#: components — restrict them to a filesystem-safe shape.
_SAFE_ROLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: Role overlays are dict deltas deep-merged over a JSON base, so only
#: plain JSON files participate in overlay lookup. Full exports (tar) and
#: script-style configs cannot be composed (see the refusal rules below).
_OVERLAY_EXTENSIONS = [".json"]


def effective_role(request_role: Optional[str], default_role: Optional[str]) -> Optional[str]:
    """Pick the role for a job: explicit request wins, else the configured
    default. Blank/whitespace strings mean "unset"."""
    for candidate in (request_role, default_role):
        if candidate is not None and str(candidate).strip():
            return str(candidate).strip()
    return None


@dataclass
class JobContext:
    """Operator selections attached to one provisioning job.

    The default (both fields ``None``) is the backward-compatible no-op:
    resolution is byte-identical to today's single-template lookup.
    """

    role: Optional[str] = None                     # opaque string from the template tree
    replacement_snapshot_id: Optional[str] = None  # snapshot store key (R3+)


@dataclass
class ConfigLayer:
    kind: str                              # "base" | "role-overlay" | "replacement-overlay"
    path: Optional[Path] = None            # file-backed layer (templates, overlays)
    data: Optional[Dict[str, Any]] = None  # loaded layer content (composed paths only)
    source: str = ""                       # provenance for logs/UI — never secret values


@dataclass
class ResolvedConfig:
    """Ordered config layers plus operator-visible resolution notes."""

    layers: List[ConfigLayer] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    # Composition state (set by the resolver on multi-layer resolutions).
    _composed: Optional[Dict[str, Any]] = field(default=None, repr=False, compare=False)
    _label: str = field(default="config", repr=False, compare=False)
    _artifact_dir: Path = field(default=RESOLVED_CONFIG_DIR, repr=False, compare=False)
    _artifact_path: Optional[Path] = field(default=None, repr=False, compare=False)

    def as_provision_args(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Collapse layers into the ``(config, config_path)`` pair
        ``provision()`` already takes.

        - No layers → ``(None, None)`` (no config phase, same as today).
        - Single file-backed base layer → ``(None, str(path))`` — the
          pass-through fast path. The template file is not read, parsed,
          or re-serialized; byte identity with the pre-resolver lookup is
          structural, not best-effort.
        - Composed layers → ``(None, str(materialized_path))`` — the merged
          config is written as a job-scoped 0600 JSON artifact and handed
          to the handler as a file, keeping every vendor on its existing
          file-apply path (inline dicts would silently change apply
          semantics for some handlers).
        """
        if self._composed is not None:
            return None, str(self._materialize())
        if len(self.layers) == 1 and self.layers[0].path is not None:
            return None, str(self.layers[0].path)
        return None, None

    def _materialize(self) -> Path:
        if self._artifact_path is not None:
            return self._artifact_path

        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(self._artifact_dir), 0o700)
        except OSError:
            pass

        artifact = self._artifact_dir / "{}-{}.json".format(self._label, uuid.uuid4().hex)
        fd = os.open(str(artifact), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(self._composed, handle, indent=2)
            handle.write("\n")

        self._artifact_path = artifact
        logger.info(
            "Materialized composed config (%d layers) at %s",
            len(self.layers),
            artifact,
        )
        return artifact

    def cleanup(self) -> None:
        """Best-effort removal of the materialized artifact (call after the
        job finishes — composed artifacts are job-scoped)."""
        if self._artifact_path is None:
            return
        try:
            self._artifact_path.unlink()
        except OSError:
            pass
        self._artifact_path = None


class ConfigResolver:
    """Decides WHICH ordered config layers apply to a provisioning job.

    Layer order (later wins): base template → role overlay. (Replacement
    overlays are a later story.) The base layer is exactly today's
    ``ConfigStore.get_config_template`` result; role overlays are searched
    with the same model → alias → ``default`` chain, under
    ``templates/{device_type}/roles/{role}/``, with **no** arbitrary-file
    fallback (an accidental overlay is worse than none).
    """

    def __init__(self, store, handler_manager, artifact_dir: Optional[Path] = None):
        self._store = store                     # ConfigStore
        self._handler_manager = handler_manager  # HandlerManager (or None)
        self._artifact_dir = artifact_dir or RESOLVED_CONFIG_DIR

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve(
        self,
        device_type: str,
        model: Optional[str],
        context: Optional[JobContext] = None,
    ) -> ResolvedConfig:
        ctx = context or JobContext()
        resolved = ResolvedConfig(_label=device_type, _artifact_dir=self._artifact_dir)

        # Layer 1: the base template — DELEGATED to today's lookup, unchanged.
        base = self._store.get_config_template(device_type, model)
        if base is not None:
            resolved.layers.append(ConfigLayer(kind="base", path=base, source=base.name))

        if ctx.role is None and ctx.replacement_snapshot_id is None:
            return resolved  # fast path: exactly today's behavior

        if ctx.replacement_snapshot_id is not None:
            # R3+ (snapshot store / replacement overlays) — not implemented.
            resolved.notes.append(
                "replacement snapshot '{}' ignored: snapshot-based resolution "
                "is not implemented yet".format(ctx.replacement_snapshot_id)
            )

        if ctx.role is not None:
            self._apply_role_overlay(resolved, device_type, model, ctx.role)

        return resolved

    def available_roles(self) -> List[str]:
        """Roles available across the template tree — derived from
        ``templates/*/roles/*`` directories on disk, never an enum."""
        roles = set()
        templates_path = self._store.templates_path
        if templates_path.exists():
            for roles_dir in templates_path.glob("*/{}".format(ROLES_SUBDIR)):
                if not roles_dir.is_dir():
                    continue
                for entry in roles_dir.iterdir():
                    if entry.is_dir():
                        roles.add(entry.name)
        return sorted(roles)

    # ------------------------------------------------------------------
    # Role overlays
    # ------------------------------------------------------------------

    def _handler_class(self, device_type: str):
        """Class-level handler traits, with base defaults for types without
        a handler — the same fallback ``config_store`` uses."""
        from .handlers.base import BaseHandler

        handler_class = None
        if self._handler_manager is not None:
            handler_class = self._handler_manager.handler_class_for(device_type)
        return handler_class or BaseHandler

    def _apply_role_overlay(
        self,
        resolved: ResolvedConfig,
        device_type: str,
        model: Optional[str],
        role: str,
    ) -> None:
        display_model = model or "default"

        if not _SAFE_ROLE_RE.match(role):
            resolved.notes.append(
                "role '{}' ignored: not a valid role name".format(role)
            )
            return

        if not resolved.layers:
            resolved.notes.append(
                "role '{}' ignored: no base template for {}/{}".format(
                    role, device_type, display_model
                )
            )
            return

        overlay_path = self._find_role_overlay(device_type, model, role)
        if overlay_path is None:
            # Soft-proceed: roles roll out vendor-by-vendor; a missing
            # overlay resolves base-only with a visible note.
            resolved.notes.append(
                "no '{}' role overlay for {}/{}".format(role, device_type, display_model)
            )
            return

        handler_class = self._handler_class(device_type)
        base_layer = resolved.layers[0]
        base_path = base_layer.path

        if not handler_class.supports_config_overlays:
            resolved.notes.append(
                "role '{}' overlay refused: config overlays are not enabled "
                "for {} (supports_config_overlays is False)".format(role, device_type)
            )
            return

        # Full-export bases are applied replace-not-merge; composing a
        # partial delta over one is refused in v1 (soft-proceed, base-only).
        if base_path.suffix.lower() != ".json":
            resolved.notes.append(
                "role '{}' overlay refused: base template {} is not a "
                "composable JSON template".format(role, base_path.name)
            )
            return

        base_config = load_config_template(str(base_path)).config
        if handler_class.is_full_config_export(base_config):
            resolved.notes.append(
                "role '{}' overlay refused: base template {} is a full "
                "config export (replace-not-merge)".format(role, base_path.name)
            )
            return

        # Placeholder / JSON-object validation applies to overlays too;
        # a malformed overlay fails the job rather than silently applying
        # the wrong site config (ConfigTemplateError propagates).
        overlay_config = load_config_template(str(overlay_path)).config

        resolved.layers.append(
            ConfigLayer(
                kind="role-overlay",
                path=overlay_path,
                data=overlay_config,
                source="role {}: {}".format(role, overlay_path.name),
            )
        )
        resolved._composed = deep_merge(base_config, overlay_config)
        logger.info(
            "Composed role '%s' overlay %s over base %s for %s/%s",
            role,
            overlay_path.name,
            base_path.name,
            device_type,
            display_model,
        )

    def _find_role_overlay(
        self, device_type: str, model: Optional[str], role: str
    ) -> Optional[Path]:
        """Search ``templates/{device_type}/roles/{role}/`` with the same
        model → alias → default chain (and the same class traits) as the
        base template lookup. No arbitrary-file fallback."""
        role_dir = self._store.templates_path / device_type / ROLES_SUBDIR / role
        if not role_dir.exists() or not role_dir.is_dir():
            return None

        traits = self._handler_class(device_type)
        find = self._store._find_named_template

        model_names = []
        if model:
            model_names.append(model)
            model_lower = model.lower()
            if model_lower != model:
                model_names.append(model_lower)

        for model_name in model_names:
            overlay = find(
                role_dir,
                model_name,
                _OVERLAY_EXTENSIONS,
                allow_prefixed_export=traits.allows_prefixed_config_exports,
            )
            if overlay:
                return overlay

        model_alias = self._store._get_model_alias(device_type, model)
        if model_alias:
            overlay = find(
                role_dir,
                model_alias,
                _OVERLAY_EXTENSIONS,
                allow_prefixed_export=traits.allows_prefixed_config_exports,
            )
            if overlay:
                return overlay

        return find(role_dir, "default", _OVERLAY_EXTENSIONS)
