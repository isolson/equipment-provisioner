"""Tests for the config resolver seam (provisioner/config_resolver.py).

Covers the R1 regression plan from docs/design-config-resolution.md §5.3:

1. Delegation equivalence — every test_config_store.py lookup case re-run
   through ``resolve(dt, model, JobContext())``; the returned layer path
   must equal the direct ``get_config_template`` result, including None.
2. Pass-through byte test — with an empty context, ``as_provision_args()``
   returns ``(None, str(path))`` and the template file is never read or
   rewritten (spy on ``open``/``load_config_template`` + mtime check).
3. Seam test — lives in test_provision_flow.py.
4. No-new-enumeration — the resolver source contains no vendor names.

Plus the R1 role-overlay behavior: lookup chain reuse, composition via the
shared deep merge, and the refusal/soft-proceed rules (design D2/D3).
Role names used here ("tower", "office") are test fixtures only — the real
role vocabulary is an open product decision and the code is role-agnostic.
"""

import builtins
import json
import os
import stat

import pytest

from provisioner.config_resolver import (
    ConfigLayer,
    ConfigResolver,
    JobContext,
    ResolvedConfig,
    effective_role,
)
from provisioner.config_store import ConfigStore
from provisioner.config_templates import ConfigTemplateError
from provisioner.fingerprint import DeviceType
from provisioner.handlers.base import BaseHandler


def _write(path, content="{}"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _resolver(tmp_path, handler_class=None, artifact_dir=None):
    store = ConfigStore(str(tmp_path))
    manager = StubHandlerManager(handler_class) if handler_class else None
    return store, ConfigResolver(
        store, manager, artifact_dir=artifact_dir or (tmp_path / "run" / "resolved")
    )


class StubHandlerManager:
    """handler_class_for stand-in so overlay traits can be exercised
    without touching the real HANDLER_MAP."""

    def __init__(self, handler_class):
        self._handler_class = handler_class

    def handler_class_for(self, device_type):
        return self._handler_class


class OverlayHandler(BaseHandler):
    """Minimal handler class that opts in to config overlays."""

    supports_config_overlays = True


class FullExportOverlayHandler(BaseHandler):
    supports_config_overlays = True

    @staticmethod
    def is_full_config_export(config):
        return "version" in config


# ---------------------------------------------------------------------------
# §5.3 test 1 — delegation equivalence (golden, parametrized)
#
# One scenario per test case in tests/test_config_store.py (9 today). Each
# tuple: (files to create, device_type, model, expected template rel-path
# or None). The direct store lookup and the resolver fast path must agree.
# ---------------------------------------------------------------------------

T = "configs/templates"

STORE_SCENARIOS = [
    # test_tachyon_unknown_model_does_not_fall_back_to_tns100
    ([f"{T}/tachyon/tns-100.json"], "tachyon", None, None),
    # test_tachyon_tna_model_does_not_use_tns100_template
    ([f"{T}/tachyon/tns-100.json"], "tachyon", "TNA-303L-65", None),
    # test_tachyon_tna_model_uses_timestamped_export
    (
        [f"{T}/tachyon/20260424.143334.TNA-303L-65.tar", f"{T}/tachyon/tns-100.json"],
        "tachyon",
        "TNA-303L-65",
        f"{T}/tachyon/20260424.143334.TNA-303L-65.tar",
    ),
    # test_tachyon_305x_uses_tna305_family_template
    (
        [f"{T}/tachyon/tna-305.tar", f"{T}/tachyon/tna-30x.tar", f"{T}/tachyon/tns-100.json"],
        "tachyon",
        "TNA-305X",
        f"{T}/tachyon/tna-305.tar",
    ),
    # test_tachyon_305a_uses_tna305_family_template
    ([f"{T}/tachyon/tna-305.tar"], "tachyon", "TNA-305A", f"{T}/tachyon/tna-305.tar"),
    # test_tachyon_tns100_model_uses_exact_template_case_insensitive
    ([f"{T}/tachyon/tns-100.json"], "tachyon", "TNS-100", f"{T}/tachyon/tns-100.json"),
    # test_default_template_still_applies_without_model
    ([f"{T}/tachyon/default.json"], "tachyon", None, f"{T}/tachyon/default.json"),
    # test_non_tachyon_vendor_keeps_legacy_any_file_fallback
    (
        [f"{T}/cambium/f4518-sm-defaultconfig.json"],
        "cambium",
        None,
        f"{T}/cambium/f4518-sm-defaultconfig.json",
    ),
    # test_non_tachyon_timestamp_export_does_not_override_alias
    (
        [f"{T}/cambium/f4518-sm-defaultconfig.json", f"{T}/cambium/20260424.143334.ePMP 4518.tar"],
        "cambium",
        "ePMP 4518",
        f"{T}/cambium/f4518-sm-defaultconfig.json",
    ),
]


@pytest.mark.parametrize("files,device_type,model,expected_rel", STORE_SCENARIOS)
def test_empty_context_resolution_delegates_to_store_lookup(
    tmp_path, files, device_type, model, expected_rel
):
    for rel in files:
        _write(tmp_path / rel)
    store, resolver = _resolver(tmp_path)

    direct = store.get_config_template(device_type, model)
    resolved = resolver.resolve(device_type, model, JobContext())

    if expected_rel is None:
        assert direct is None
        assert resolved.layers == []
        assert resolved.as_provision_args() == (None, None)
    else:
        assert direct == tmp_path / expected_rel
        assert len(resolved.layers) == 1
        assert resolved.layers[0].kind == "base"
        assert resolved.layers[0].path == direct
        assert resolved.as_provision_args() == (None, str(direct))
    assert resolved.notes == []


def test_empty_context_when_no_context_object_passed(tmp_path):
    _write(tmp_path / T / "tachyon" / "tns-100.json")
    store, resolver = _resolver(tmp_path)

    resolved = resolver.resolve("tachyon", "TNS-100", None)

    assert resolved.as_provision_args() == (
        None,
        str(store.get_config_template("tachyon", "TNS-100")),
    )


# ---------------------------------------------------------------------------
# §5.3 test 2 — pass-through byte test (spy: the template is never read)
# ---------------------------------------------------------------------------

def test_pass_through_never_reads_or_rewrites_the_template(tmp_path, monkeypatch):
    template = tmp_path / T / "tachyon" / "tns-100.json"
    _write(template, '{"system": {"hostname": "keep-me"}}')
    store, resolver = _resolver(tmp_path)
    before = os.stat(str(template))

    # Spy 1: the resolver's template loader must not be invoked at all.
    def _fail_load(*args, **kwargs):
        raise AssertionError("load_config_template called on the pass-through fast path")

    monkeypatch.setattr("provisioner.config_resolver.load_config_template", _fail_load)

    # Spy 2: nothing may open() the template file.
    opened = []
    real_open = builtins.open

    def spy_open(file, *args, **kwargs):
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", spy_open)

    resolved = resolver.resolve("tachyon", "TNS-100", JobContext())
    args = resolved.as_provision_args()

    monkeypatch.setattr(builtins, "open", real_open)
    assert args == (None, str(template))
    assert str(template) not in opened
    after = os.stat(str(template))
    assert after.st_mtime_ns == before.st_mtime_ns
    assert after.st_size == before.st_size


# ---------------------------------------------------------------------------
# §5.3 test 4 — no vendor enumeration in the resolver
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module_rel", ["provisioner/config_resolver.py", "provisioner/config_merge.py"])
def test_resolver_source_contains_no_vendor_names(module_rel):
    from pathlib import Path

    repo_root = Path(__file__).resolve().parent.parent
    source = (repo_root / module_rel).read_text().lower()

    vendor_names = {dt.value for dt in DeviceType} - {"unknown"}
    for vendor in vendor_names:
        assert vendor not in source, (
            f"{module_rel} mentions vendor '{vendor}' — the resolver must stay "
            "vendor-neutral (class traits via handler_class_for only)."
        )
    assert "device_type ==" not in source


# ---------------------------------------------------------------------------
# Role overlays — composition
# ---------------------------------------------------------------------------

BASE_CONTENT = {"system": {"name": "base"}, "services": {"snmp": False}, "tags": [1, 2]}
OVERLAY_CONTENT = {"services": {"snmp": True}, "tags": [9]}
MERGED_CONTENT = {"system": {"name": "base"}, "services": {"snmp": True}, "tags": [9]}


def test_role_overlay_composes_over_base(tmp_path):
    base = tmp_path / T / "acme" / "widget-1.json"
    _write(base, json.dumps(BASE_CONTENT))
    _write(tmp_path / T / "acme" / "roles" / "tower" / "widget-1.json", json.dumps(OVERLAY_CONTENT))
    base_bytes = base.read_bytes()
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)

    resolved = resolver.resolve("acme", "widget-1", JobContext(role="tower"))

    assert [layer.kind for layer in resolved.layers] == ["base", "role-overlay"]
    assert resolved.notes == []
    assert "tower" in resolved.layers[1].source

    cfg, path = resolved.as_provision_args()
    assert cfg is None
    assert path is not None and path != str(base)
    artifact = os.stat(path)
    assert stat.S_IMODE(artifact.st_mode) == 0o600
    with open(path) as handle:
        assert json.load(handle) == MERGED_CONTENT

    # The base template itself is untouched.
    assert base.read_bytes() == base_bytes

    # Composed artifacts are job-scoped: cleanup removes them.
    resolved.cleanup()
    assert not os.path.exists(path)


def test_as_provision_args_materializes_once(tmp_path):
    _write(tmp_path / T / "acme" / "widget-1.json", json.dumps(BASE_CONTENT))
    _write(tmp_path / T / "acme" / "roles" / "tower" / "widget-1.json", json.dumps(OVERLAY_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)

    resolved = resolver.resolve("acme", "widget-1", JobContext(role="tower"))

    _, first = resolved.as_provision_args()
    _, second = resolved.as_provision_args()
    assert first == second


def test_role_overlay_default_file_used_when_no_model_match(tmp_path):
    _write(tmp_path / T / "acme" / "widget-1.json", json.dumps(BASE_CONTENT))
    _write(tmp_path / T / "acme" / "roles" / "tower" / "default.json", json.dumps(OVERLAY_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)

    resolved = resolver.resolve("acme", "widget-1", JobContext(role="tower"))

    assert [layer.kind for layer in resolved.layers] == ["base", "role-overlay"]
    assert resolved.layers[1].path.name == "default.json"


def test_role_overlay_reuses_alias_chain(tmp_path):
    """Overlay lookup goes through the same model → alias chain (and class
    traits) as the base lookup — here via the real CONFIG_MODEL_ALIASES."""
    from provisioner.handlers.tachyon import TachyonHandler

    class OverlayTachyon(TachyonHandler):
        supports_config_overlays = True

    _write(tmp_path / T / "tachyon" / "tna-305.json", json.dumps(BASE_CONTENT))
    _write(tmp_path / T / "tachyon" / "roles" / "tower" / "tna-305.json", json.dumps(OVERLAY_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=OverlayTachyon)

    resolved = resolver.resolve("tachyon", "TNA-305X", JobContext(role="tower"))

    assert [layer.kind for layer in resolved.layers] == ["base", "role-overlay"]
    assert resolved.layers[1].path.name == "tna-305.json"


def test_role_overlay_has_no_arbitrary_file_fallback(tmp_path):
    """An unrelated file in the role dir must never be picked up, even for
    vendors whose *base* lookup allows the historical arbitrary fallback."""
    base = tmp_path / T / "acme" / "widget-1.json"
    _write(base, json.dumps(BASE_CONTENT))
    _write(tmp_path / T / "acme" / "roles" / "tower" / "random-file.json", json.dumps(OVERLAY_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)

    resolved = resolver.resolve("acme", "widget-1", JobContext(role="tower"))

    assert [layer.kind for layer in resolved.layers] == ["base"]
    assert any("no 'tower' role overlay" in note for note in resolved.notes)
    assert resolved.as_provision_args() == (None, str(base))


# ---------------------------------------------------------------------------
# Role overlays — refusal / soft-proceed rules (design D2/D3)
# ---------------------------------------------------------------------------

def test_missing_role_overlay_soft_proceeds_with_note(tmp_path):
    base = tmp_path / T / "acme" / "widget-1.json"
    _write(base, json.dumps(BASE_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)

    resolved = resolver.resolve("acme", "widget-1", JobContext(role="office"))

    assert [layer.kind for layer in resolved.layers] == ["base"]
    assert any("office" in note for note in resolved.notes)
    assert resolved.as_provision_args() == (None, str(base))


def test_overlay_refused_when_handler_does_not_support_overlays(tmp_path):
    """supports_config_overlays defaults to False — overlays stay dark for
    every vendor until bench verification enables them."""
    base = tmp_path / T / "acme" / "widget-1.json"
    _write(base, json.dumps(BASE_CONTENT))
    _write(tmp_path / T / "acme" / "roles" / "tower" / "widget-1.json", json.dumps(OVERLAY_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=BaseHandler)

    resolved = resolver.resolve("acme", "widget-1", JobContext(role="tower"))

    assert [layer.kind for layer in resolved.layers] == ["base"]
    assert any("supports_config_overlays" in note for note in resolved.notes)
    assert resolved.as_provision_args() == (None, str(base))


def test_overlay_refused_on_tar_base(tmp_path):
    base = tmp_path / T / "acme" / "widget-2.tar"
    _write(base)  # content never read: refusal happens on the suffix
    _write(tmp_path / T / "acme" / "roles" / "tower" / "widget-2.json", json.dumps(OVERLAY_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)

    resolved = resolver.resolve("acme", "widget-2", JobContext(role="tower"))

    assert [layer.kind for layer in resolved.layers] == ["base"]
    assert any("refused" in note for note in resolved.notes)
    assert resolved.as_provision_args() == (None, str(base))


def test_overlay_refused_on_full_export_json_base(tmp_path):
    base = tmp_path / T / "acme" / "widget-1.json"
    _write(base, json.dumps({"version": 3, "system": {"name": "export"}}))
    _write(tmp_path / T / "acme" / "roles" / "tower" / "widget-1.json", json.dumps(OVERLAY_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=FullExportOverlayHandler)

    resolved = resolver.resolve("acme", "widget-1", JobContext(role="tower"))

    assert [layer.kind for layer in resolved.layers] == ["base"]
    assert any("full config export" in note for note in resolved.notes)
    assert resolved.as_provision_args() == (None, str(base))


def test_role_ignored_when_no_base_template(tmp_path):
    _write(tmp_path / T / "acme" / "roles" / "tower" / "default.json", json.dumps(OVERLAY_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)

    resolved = resolver.resolve("acme", "widget-1", JobContext(role="tower"))

    assert resolved.layers == []
    assert any("no base template" in note for note in resolved.notes)
    assert resolved.as_provision_args() == (None, None)


@pytest.mark.parametrize(
    "role",
    [
        "../evil",       # path traversal
        "a/b",           # separator
        "r" * 256,       # ext4 component limit boundary (ENAMETOOLONG territory)
        "r" * 5000,      # absurdly long operator input
    ],
)
def test_unsafe_role_name_is_ignored_with_note(tmp_path, role):
    """Roles come from operator input and become path components — path
    traversal shapes and overlong names are rejected *before* any
    filesystem lookup (an overlong component would otherwise raise
    OSError/ENAMETOOLONG and fail the job instead of soft-proceeding)."""
    base = tmp_path / T / "acme" / "widget-1.json"
    _write(base, json.dumps(BASE_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)

    resolved = resolver.resolve("acme", "widget-1", JobContext(role=role))

    assert [layer.kind for layer in resolved.layers] == ["base"]
    assert any("not a valid role name" in note for note in resolved.notes)
    assert resolved.as_provision_args() == (None, str(base))


def test_max_length_role_name_passes_the_guard(tmp_path):
    """A 63-char role is valid — it reaches overlay lookup and, absent an
    overlay, soft-proceeds with the missing-overlay note (not the
    invalid-name note)."""
    base = tmp_path / T / "acme" / "widget-1.json"
    _write(base, json.dumps(BASE_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)
    role = "r" * 63

    resolved = resolver.resolve("acme", "widget-1", JobContext(role=role))

    assert [layer.kind for layer in resolved.layers] == ["base"]
    assert any(f"no '{role}' role overlay" in note for note in resolved.notes)
    assert not any("not a valid role name" in note for note in resolved.notes)
    assert resolved.as_provision_args() == (None, str(base))


def test_overlay_with_placeholder_fails_loudly(tmp_path):
    """A malformed selected overlay is an error, not a missing role —
    silently skipping it could apply the wrong site config."""
    _write(tmp_path / T / "acme" / "widget-1.json", json.dumps(BASE_CONTENT))
    _write(
        tmp_path / T / "acme" / "roles" / "tower" / "widget-1.json",
        json.dumps({"system": {"name": "{{site_name}}"}}),
    )
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)

    with pytest.raises(ConfigTemplateError):
        resolver.resolve("acme", "widget-1", JobContext(role="tower"))


def test_replacement_snapshot_id_is_noted_and_ignored_in_r1(tmp_path):
    base = tmp_path / T / "acme" / "widget-1.json"
    _write(base, json.dumps(BASE_CONTENT))
    store, resolver = _resolver(tmp_path, handler_class=OverlayHandler)

    resolved = resolver.resolve(
        "acme", "widget-1", JobContext(replacement_snapshot_id="snap-123")
    )

    assert [layer.kind for layer in resolved.layers] == ["base"]
    assert any("snap-123" in note for note in resolved.notes)
    assert resolved.as_provision_args() == (None, str(base))


# ---------------------------------------------------------------------------
# Derived role set, role plumbing helpers, request/config schema
# ---------------------------------------------------------------------------

def test_available_roles_derived_from_template_tree(tmp_path):
    _write(tmp_path / T / "acme" / "roles" / "tower" / "default.json")
    _write(tmp_path / T / "acme" / "roles" / "office" / "default.json")
    _write(tmp_path / T / "other" / "roles" / "tower" / "default.json")
    _write(tmp_path / T / "other" / "not-roles" / "lab" / "default.json")
    store, resolver = _resolver(tmp_path)

    assert resolver.available_roles() == ["office", "tower"]


def test_available_roles_empty_tree(tmp_path):
    store, resolver = _resolver(tmp_path)
    assert resolver.available_roles() == []


def test_effective_role_request_wins_and_blank_means_unset():
    assert effective_role("tower", "office") == "tower"
    assert effective_role(None, "office") == "office"
    assert effective_role("  ", "office") == "office"
    assert effective_role("", None) is None
    assert effective_role(None, None) is None
    assert effective_role(" tower ", None) == "tower"


def test_provision_request_role_field_is_wire_compatible():
    from provisioner.web.api import ProvisionRequest

    assert ProvisionRequest(port_number=1).role is None  # old clients
    assert ProvisionRequest(port_number=1, role="tower").role == "tower"


def test_config_default_role_setting():
    from provisioner.config import Config

    assert Config().provisioning.default_role is None  # backward compatible
    loaded = Config(**{"provisioning": {"default_role": "tower"}})
    assert loaded.provisioning.default_role == "tower"
