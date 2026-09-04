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
