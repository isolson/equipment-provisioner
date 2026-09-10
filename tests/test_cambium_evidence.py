"""Cambium template and handler values trace to bench-evidence fixtures.

No test in this file hardcodes a role value. The known-good fixtures are the
only source. A change to a value starts with a new fixture, not a chat.
"""

import json
from pathlib import Path

import pytest
import yaml

from provisioner.handlers.cambium import CambiumHandler
from provisioner.vendor_registry import config_family_for_model

EVIDENCE = Path("bench-evidence/cambium")


def _records(role="SM", witness=None):
    """Return (manifest, values) for committed records.

    ``fixture_witness: baseline`` records came from a unit that received our
    baseline, so they witness fleet policy and template values. ``role``
    records witness only the radio role set and device defaults.
    """
    records = []
    for manifest_path in sorted(EVIDENCE.glob("*/*/manifest.yaml")):
        manifest = yaml.safe_load(manifest_path.read_text())
        if str(manifest.get("config_role", "")).upper() != role:
            continue
        if witness and str(manifest.get("fixture_witness", "role")) != witness:
            continue
        fixture = json.loads((manifest_path.parent / "known-good.structure.json").read_text())
        records.append((manifest, fixture["values"]))
    return records


def test_there_is_sm_evidence_for_both_4k_bands():
    models = {manifest["model"] for manifest, _ in _records()}
    assert {"ePMP 4518", "ePMP 4616"} <= models


def _ids():
    return [manifest["model"] for manifest, _ in _records()]


@pytest.mark.parametrize("manifest,values", _records(), ids=_ids())
def test_handler_role_table_matches_every_sm_fixture(manifest, values):
    for key, expected in CambiumHandler.SM_ROLE_VALUES.items():
        assert str(values[key]) == expected, (manifest["model"], key)


def _baseline_ids():
    return [manifest["model"] for manifest, _ in _records(witness="baseline")]


@pytest.mark.parametrize("manifest,values", _records(witness="baseline"), ids=_baseline_ids())
def test_handler_fleet_policy_matches_every_baseline_fixture(manifest, values):
    for key, expected in CambiumHandler.SM_FLEET_POLICY.items():
        assert key in values, (manifest["model"], key, "fleet policy field not witnessed")
        assert str(values[key]) == expected, (manifest["model"], key)


@pytest.mark.parametrize("family", ["ePMP-4K", "ePMP-3K"])
def test_tracked_sm_template_values_trace_to_family_baseline_fixtures(family):
    props = json.loads(
        Path("configs/templates/cambium/%s/5.11.1/SM/default.json" % family).read_text()
    )["device_props"]
    fixtures = [
        values
        for manifest, values in _records(witness="baseline")
        if config_family_for_model("cambium", manifest["model"]).directory == family
    ]
    if not fixtures:
        pytest.skip("no baseline witness for %s yet; the template is unqualified" % family)
    for key, value in props.items():
        witnesses = [str(values[key]) for values in fixtures if key in values]
        assert witnesses, "template field %s has no fixture witness" % key
        assert all(w == value for w in witnesses), (family, key)


def test_device_defaults_differ_across_models_so_they_are_never_written():
    by_model = {manifest["model"]: values for manifest, values in _records()}
    gains = {model: str(values["wirelessInterfaceTDDAntennaGain"]) for model, values in by_model.items()}
    assert len(set(gains.values())) > 1, gains
    for model, values in by_model.items():
        assert str(values["wirelessInterfaceTDDAntennaGain"]) == str(values["systemConfigMinAntGain"]), model
    gps = {str(values.get("cambiumGPSConfigPrioritizeUSB")) for values in by_model.values()}
    assert len(gps) > 1, "GPS USB priority is a device default; fixtures must show it varies"


def test_fixtures_carry_no_secret_or_identity_values():
    for _, values in _records():
        for key in values:
            lowered = key.lower()
            for marker in ("password", "passphrase", "psk", "community", "ssid", "serial", "macaddress", "encryptionkey"):
                assert marker not in lowered, key


def _no_config_values(model):
    for manifest_path in sorted(EVIDENCE.glob("*/*/manifest.yaml")):
        manifest = yaml.safe_load(manifest_path.read_text())
        if manifest.get("model") == model and str(manifest.get("no_config_backup", "")) == "captured":
            return json.loads((manifest_path.parent / "no-config.structure.json").read_text())["values"]
    pytest.skip("no captured no-config backup for %s" % model)


def test_4518_factory_radio_role_is_already_sm():
    """The factory export proves the SM role set is the vendor default."""
    values = _no_config_values("ePMP 4518")
    for key, expected in CambiumHandler.SM_ROLE_VALUES.items():
        assert str(values[key]) == expected, key


def test_4518_clean_device_result_cannot_pass_by_accident():
    """SOP: a clean-device result must not pass only because the device already
    had the required values. At least some fleet policy must differ at factory."""
    values = _no_config_values("ePMP 4518")
    differing = [
        key for key, expected in CambiumHandler.SM_FLEET_POLICY.items()
        if str(values.get(key)) != expected
    ]
    assert len(differing) >= 5, differing
    assert "mgmtVLANVID" in differing and "cambiumDeviceAgentCNSURL" in differing


def test_4518_device_defaults_are_unchanged_by_provisioning():
    """Device defaults read the same before (factory) and after (known-good)."""
    from provisioner.field_ownership import unchanged_expectations

    factory = _no_config_values("ePMP 4518")
    known_good = next(values for manifest, values in _records() if manifest["model"] == "ePMP 4518")
    expectations = unchanged_expectations(CambiumHandler.FIELD_OWNERSHIP, factory)
    assert expectations, "no device-default witnesses in the factory fixture"
    for key in ("wirelessInterfaceTDDAntennaGain", "systemConfigMinAntGain", "cambiumGPSConfigPrioritizeUSB"):
        assert key in expectations, key
        assert str(known_good[key]) == str(expectations[key]), key
    # The scan mask is family fleet policy: factory 3 (20 and 40 MHz) cannot
    # follow an 80 MHz access point, so the template sets it and the fixture
    # witnesses it.
    assert "wirelessInterfaceScanFrequencyBandwidth" in CambiumHandler.FAMILY_FLEET_POLICY_FIELDS
    assert str(factory["wirelessInterfaceScanFrequencyBandwidth"]) == "3"
    assert str(known_good["wirelessInterfaceScanFrequencyBandwidth"]) == "51"


@pytest.mark.parametrize("family,mask", [("ePMP-4K", "51"), ("ePMP-3K", "19")])
def test_family_scan_mask_traces_to_that_family_fixtures(family, mask):
    from provisioner.vendor_registry import config_family_for_model

    props = json.loads(Path("configs/templates/cambium/%s/5.11.1/SM/default.json" % family).read_text())["device_props"]
    assert props["wirelessInterfaceScanFrequencyBandwidth"] == mask
    witnesses = [
        str(values["wirelessInterfaceScanFrequencyBandwidth"])
        for manifest, values in _records()
        if config_family_for_model("cambium", manifest["model"]).directory == family
        and "wirelessInterfaceScanFrequencyBandwidth" in values
    ]
    assert witnesses and all(w == mask for w in witnesses), (family, witnesses)
