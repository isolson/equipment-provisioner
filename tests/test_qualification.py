"""A mode is offered only after the bench proved both transition directions."""

import textwrap

import pytest

from provisioner import qualification
from provisioner.handler_manager import HandlerManager
from provisioner.vendor_registry import all_specs


def _manifest(root, vendor, model, firmware, transitions):
    directory = root / vendor / model.replace(" ", "_") / firmware
    directory.mkdir(parents=True, exist_ok=True)
    rows = "".join(
        "  - {from: %s, to: %s, result: %s}\n" % row for row in transitions
    )
    directory.joinpath("manifest.yaml").write_text(textwrap.dedent('''\
        vendor: %s
        model: %s
        firmware: %s
        config_role: SM
        artifact_purpose: hardware-validation
        reusable_template: false
        canonical_template_status: tracked-family-baseline
        transitions:
        ''') % (vendor, model, firmware) + rows)


@pytest.fixture
def evidence_root(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVISIONER_QUALIFICATION_ROOT", str(tmp_path))
    qualification.clear_cache()
    yield tmp_path
    qualification.clear_cache()


def test_normalize_matches_display_and_slug_forms():
    assert qualification.normalize("ePMP 4518") == qualification.normalize("epmp-4518")
    assert qualification.normalize("1.15.1 rev 8541") == qualification.normalize("1.15.1-rev-8541")
    assert qualification.normalize(None) == ""


def test_empty_evidence_root_qualifies_nothing(evidence_root):
    assert qualification.qualified_modes("cambium", "ePMP 4616", "5.11.1", ("ap", "ptp")) == ()
    assert qualification.baseline_qualified("cambium", "ePMP 4616", "5.11.1") is False
    assert "no bench evidence" in qualification.unqualified_reason("cambium", "ePMP 4616", "5.11.1", "ptp")


def test_both_directions_are_required(evidence_root):
    _manifest(evidence_root, "cambium", "ePMP 4616", "5.11.1", [("sm", "ptp", "success")])
    assert qualification.qualified_modes("cambium", "ePMP 4616", "5.11.1", ("ptp",)) == ()
    assert "missing ptp->sm" in qualification.unqualified_reason("cambium", "ePMP 4616", "5.11.1", "ptp")
    qualification.clear_cache()
    _manifest(
        evidence_root, "cambium", "ePMP 4616", "5.11.1",
        [("fresh", "sm", "success"), ("sm", "ptp", "success"), ("ptp", "sm", "success")],
    )
    assert qualification.qualified_modes("cambium", "ePMP 4616", "5.11.1", ("ap", "ptp")) == ("ptp",)
    assert qualification.baseline_qualified("cambium", "ePMP 4616", "5.11.1") is True
    assert qualification.transition_report("cambium", "ePMP 4616", "5.11.1") == {
        "ap->sm": False, "fresh->sm": True, "ptp->sm": True, "sm->ap": False, "sm->ptp": True,
    }


def test_a_recorded_failure_withdraws_the_transition(evidence_root):
    _manifest(
        evidence_root, "cambium", "ePMP 4616", "5.11.1",
        [("sm", "ptp", "success"), ("ptp", "sm", "success"), ("ptp", "sm", "failure")],
    )
    assert qualification.qualified_modes("cambium", "ePMP 4616", "5.11.1", ("ptp",)) == ()


def test_unknown_model_or_firmware_proves_nothing(evidence_root):
    _manifest(
        evidence_root, "cambium", "ePMP 4616", "5.11.1",
        [("sm", "ptp", "success"), ("ptp", "sm", "success")],
    )
    assert qualification.qualified_modes("cambium", "ePMP 4616", "5.12.0", ("ptp",)) == ()
    assert qualification.qualified_modes("cambium", "ePMP 4625", "5.11.1", ("ptp",)) == ()
    assert qualification.qualified_modes("cambium", "ePMP 4616", None, ("ptp",)) == ()


def test_handler_capabilities_intersect_with_evidence(evidence_root):
    before = HandlerManager.operator_capabilities_for("cambium", "ePMP 4616", "5.11.1")
    assert before["post_provision_modes"] == []
    assert before["baseline_qualified"] is False
    _manifest(
        evidence_root, "cambium", "ePMP 4616", "5.11.1",
        [("fresh", "sm", "success"), ("sm", "ptp", "success"), ("ptp", "sm", "success")],
    )
    qualification.clear_cache()
    after = HandlerManager.operator_capabilities_for("cambium", "ePMP 4616", "5.11.1")
    assert after["post_provision_modes"] == ["ptp"]
    assert after["baseline_qualified"] is True
    assert after["transitions"]["sm->ptp"] is True
    assert after["unqualified"] == {}
    # A mode the handler does not advertise is never listed as unqualified.
    assert "ap" not in after["advertised_modes"]


def test_no_handler_advertises_a_mode_without_evidence_in_the_repo():
    qualification.clear_cache()
    for spec in all_specs():
        if spec.handler_cls is None:
            continue
        for family in spec.config_families:
            for pattern in family.model_patterns:
                model = pattern.replace("*", "").strip()
                caps = HandlerManager.operator_capabilities_for(spec.device_type.value, model, "0.0.0")
                assert caps["post_provision_modes"] == [], (spec.device_type.value, model)


def test_module_has_no_vendor_names():
    source = open(qualification.__file__).read().lower()
    for vendor in ("cambium", "tachyon", "tarana", "mikrotik", "ubiquiti"):
        assert vendor not in source


def test_wired_requirements_do_not_change_radio_transition_report(evidence_root):
    _manifest(evidence_root, "mikrotik", "hEX S", "7.23.5", [
        ("router", "switch", "success"), ("switch", "router", "success"),
    ])
    requirements = {mode: frozenset((("router", "switch"), ("switch", "router")))
                    for mode in ("router", "switch")}
    assert qualification.qualified_modes("mikrotik", "hEX S", "7.23.5", requirements, requirements) == ("router", "switch")
    assert not any("router" in key or "switch" in key for key in qualification.transition_report("cambium", "ePMP 4518", "5.11.1"))


# --- time-boxed bench override -------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402

_ADVERTISED = ("ap", "ptp")


@pytest.fixture
def override_file(tmp_path, monkeypatch, evidence_root):
    path = tmp_path / "override" / "qualification-override.json"
    monkeypatch.setenv("PROVISIONER_QUALIFICATION_OVERRIDE", str(path))
    return path


def test_override_opens_only_its_modes_for_the_exact_device(override_file):
    qualification.write_override("tachyon", "TNA-303L-65", "1.15.1 rev 8541", ["ptp"], "isaac", 2)
    assert qualification.qualified_modes("tachyon", "TNA-303L-65", "1.15.1-rev-8541", _ADVERTISED) == ("ptp",)
    assert qualification.qualified_modes("tachyon", "TNA-303L-65", "1.15.0", _ADVERTISED) == ()
    assert qualification.qualified_modes("tachyon", "TNA-303X", "1.15.1 rev 8541", _ADVERTISED) == ()
    # A mode the handler does not advertise stays closed.
    assert qualification.qualified_modes("tachyon", "TNA-303L-65", "1.15.1 rev 8541", ("ap",)) == ()


def test_override_records_who_and_when_and_is_private(override_file):
    record = qualification.write_override(
        "tachyon", "TNA-303L-65", "1.15.1 rev 8541", ["ptp"], "isaac", 3,
        now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
    )
    assert record["set_by"] == "isaac"
    assert record["set_utc"] == "2026-09-28T12:00:00Z"
    assert record["expires_utc"] == "2026-09-28T15:00:00Z"
    assert oct(override_file.stat().st_mode & 0o777) == "0o600"


def test_expired_override_deletes_itself_and_relocks(override_file):
    qualification.write_override(
        "tachyon", "TNA-303L-65", "1.15.1 rev 8541", ["ptp"], "isaac", 1,
        now=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    assert override_file.exists()
    assert qualification.qualified_modes("tachyon", "TNA-303L-65", "1.15.1 rev 8541", _ADVERTISED) == ()
    assert not override_file.exists()


@pytest.mark.parametrize("hours", [0, -1, 24.5])
def test_override_rejects_hours_outside_the_box(override_file, hours):
    with pytest.raises(ValueError):
        qualification.write_override("tachyon", "TNA-303L-65", "1.15.1", ["ptp"], "isaac", hours)
    assert not override_file.exists()


def test_override_requires_a_name_and_known_modes(override_file):
    with pytest.raises(ValueError):
        qualification.write_override("tachyon", "TNA-303L-65", "1.15.1", ["ptp"], " ", 1)
    with pytest.raises(ValueError):
        qualification.write_override("tachyon", "TNA-303L-65", "1.15.1", ["router"], "isaac", 1)


def test_hand_edited_expiry_past_the_limit_relocks(override_file):
    override_file.parent.mkdir(parents=True)
    override_file.write_text(
        '{"vendor": "tachyon", "model": "TNA-303L-65", "firmware": "1.15.1", "modes": ["ptp"],'
        ' "set_by": "isaac", "set_utc": "2026-09-28T00:00:00Z", "expires_utc": "2099-01-01T00:00:00Z"}'
    )
    assert qualification.active_override() is None
    assert not override_file.exists()


def test_unreadable_override_relocks(override_file):
    override_file.parent.mkdir(parents=True)
    override_file.write_text("not json")
    assert qualification.override_modes("tachyon", "TNA-303L-65", "1.15.1") == frozenset()
    assert not override_file.exists()


def test_dry_run_writes_nothing(override_file):
    record = qualification.write_override("tachyon", "TNA-303L-65", "1.15.1", ["ptp"], "isaac", 1, dry_run=True)
    assert record["modes"] == ["ptp"]
    assert not override_file.exists()
