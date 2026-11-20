"""AP mode is advertised for the ePMP 4600 only, behind the evidence gate.

The 4600 AP profile traces to the model's own field AP reference
(``bench-evidence/cambium/ePMP_4600/5.10.4``). Every other ePMP model, the
SM baseline, and the family-wide AP templates keep their behavior. AP is
offered only after the 4600's manifest records ``sm->ap`` and ``ap->sm``,
or while a bench override is active for the exact model and firmware.
"""

import json
import shutil
import textwrap
from pathlib import Path

import pytest
import yaml

from provisioner import qualification
from provisioner.field_ownership import Owner, classify, expected_values, parse_path, template_violations
from provisioner.handler_manager import HandlerManager
from provisioner.handlers.cambium import CambiumHandler
from provisioner.mode_config import ModeConfigManager

TEMPLATES = Path("configs/templates")
FAMILY = TEMPLATES / "cambium" / "ePMP-4K" / "5.11.1"
PROFILE = FAMILY / "AP" / "ePMP_4600" / "default.json"
SM_TEMPLATE = FAMILY / "SM" / "default.json"
REFERENCE = Path("bench-evidence/cambium/ePMP_4600/5.10.4")
NEW_AP_FIELDS = ("wirelessStaIsolate", "networkLLDP", "networkLLDPMode", "wirelessInterfaceSyncSource")

OTHER_MODELS = (
    "ePMP 4600C", "ePMP 4518", "ePMP 4525", "ePMP 4616", "ePMP 4625",
    "ePMP 3000", "ePMP 3000L", "Force 300-25", "Force 300-19",
)


def _props(path):
    return json.loads(Path(path).read_text())["device_props"]


def _manifest(root, model, firmware, transitions):
    directory = root / "cambium" / model.replace(" ", "_") / firmware
    directory.mkdir(parents=True, exist_ok=True)
    rows = "".join("  - {from: %s, to: %s, result: %s}\n" % row for row in transitions)
    directory.joinpath("manifest.yaml").write_text(textwrap.dedent('''\
        vendor: cambium
        model: %s
        firmware: %s
        config_role: AP
        artifact_purpose: hardware-validation
        reusable_template: false
        canonical_template_status: model-specific-ap-profile
        transitions:
        ''') % (model, firmware) + rows)
    qualification.clear_cache()


@pytest.fixture
def evidence_root(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVISIONER_QUALIFICATION_ROOT", str(tmp_path / "evidence"))
    monkeypatch.setenv("PROVISIONER_QUALIFICATION_OVERRIDE", str(tmp_path / "override.json"))
    (tmp_path / "evidence").mkdir()
    qualification.clear_cache()
    yield tmp_path / "evidence"
    qualification.clear_cache()


# --- advertisement ------------------------------------------------------------

def test_4600_advertises_ap_ahead_of_ptp():
    assert CambiumHandler.qualified_post_provision_modes_for_model("ePMP 4600") == ("ap", "ptp")
    assert CambiumHandler.qualified_post_provision_modes_for_model("Cambium ePMP 4600") == ("ap", "ptp")


@pytest.mark.parametrize("model", OTHER_MODELS)
def test_other_epmp_models_keep_ptp_only(model):
    assert CambiumHandler.qualified_post_provision_modes_for_model(model) == ("ptp",)
    assert CambiumHandler.model_mode_profile_dir(model, "ap") is None


def test_unknown_model_advertises_nothing():
    assert CambiumHandler.qualified_post_provision_modes_for_model(None) == ()
    assert CambiumHandler.qualified_post_provision_modes_for_model("ePMP 1000") == ()


def test_only_the_ap_profile_is_model_scoped():
    assert CambiumHandler.model_mode_profile_dir("ePMP 4600", "ap") == "ePMP_4600"
    assert CambiumHandler.model_mode_profile_dir("ePMP 4600", "ptp") is None
    assert CambiumHandler.model_mode_profile_dir("ePMP 4600", "ptp-a") is None


# --- qualification gate -------------------------------------------------------

def test_4600_ap_stays_gated_without_recorded_transitions(evidence_root):
    caps = HandlerManager.operator_capabilities_for("cambium", "ePMP 4600", "5.11.1")
    assert caps["advertised_modes"] == ["ap", "ptp"]
    assert caps["post_provision_modes"] == []
    assert caps["unqualified"]["ap"] == "AP not qualified for ePMP 4600 on 5.11.1: no bench evidence"


def test_4600_ap_needs_both_directions(evidence_root):
    _manifest(evidence_root, "ePMP 4600", "5.11.1", [("sm", "ap", "success")])
    caps = HandlerManager.operator_capabilities_for("cambium", "ePMP 4600", "5.11.1")
    assert "ap" not in caps["post_provision_modes"]
    assert "missing ap->sm" in caps["unqualified"]["ap"]


def test_4600_ap_is_offered_once_both_transitions_are_recorded(evidence_root):
    _manifest(evidence_root, "ePMP 4600", "5.11.1", [("sm", "ap", "success"), ("ap", "sm", "success")])
    caps = HandlerManager.operator_capabilities_for("cambium", "ePMP 4600", "5.11.1")
    assert caps["post_provision_modes"] == ["ap"]
    # Other firmware proves nothing.
    other = HandlerManager.operator_capabilities_for("cambium", "ePMP 4600", "5.10.4")
    assert other["post_provision_modes"] == []


def test_a_recorded_ap_failure_withdraws_the_offer(evidence_root):
    _manifest(evidence_root, "ePMP 4600", "5.11.1", [
        ("sm", "ap", "success"), ("ap", "sm", "success"), ("ap", "sm", "failure"),
    ])
    caps = HandlerManager.operator_capabilities_for("cambium", "ePMP 4600", "5.11.1")
    assert "ap" not in caps["post_provision_modes"]


@pytest.mark.parametrize("model", ("ePMP 4600C", "ePMP 4518", "ePMP 4616"))
def test_ap_evidence_for_another_model_offers_nothing(evidence_root, model):
    _manifest(evidence_root, model, "5.11.1", [("sm", "ap", "success"), ("ap", "sm", "success")])
    caps = HandlerManager.operator_capabilities_for("cambium", model, "5.11.1")
    assert "ap" not in caps["post_provision_modes"]
    assert "ap" not in caps["advertised_modes"]


def test_the_field_reference_does_not_qualify_ap():
    qualification.clear_cache()
    manifest = yaml.safe_load((REFERENCE / "manifest.yaml").read_text())
    assert manifest["transitions"] == []
    caps = HandlerManager.operator_capabilities_for("cambium", "ePMP 4600", "5.11.1")
    assert "ap" not in caps["post_provision_modes"]


def test_bench_override_opens_ap_for_the_exact_4600_only(evidence_root):
    qualification.write_override("cambium", "ePMP 4600", "5.11.1", ["ap"], "bench", 2)
    caps = HandlerManager.operator_capabilities_for("cambium", "ePMP 4600", "5.11.1")
    assert caps["post_provision_modes"] == ["ap"]
    assert HandlerManager.operator_capabilities_for("cambium", "ePMP 4600", "5.10.4")["post_provision_modes"] == []
    qualification.write_override("cambium", "ePMP 4518", "5.11.1", ["ap"], "bench", 2)
    assert "ap" not in HandlerManager.operator_capabilities_for("cambium", "ePMP 4518", "5.11.1")["post_provision_modes"]


# --- template resolution ------------------------------------------------------

@pytest.mark.parametrize("direction", ("North", "East", "South", "West", None))
def test_4600_resolves_its_own_ap_profile(direction):
    path = ModeConfigManager(str(TEMPLATES)).get_template_path(
        "cambium", "ap", "ePMP 4600", profile=direction, firmware="5.11.1",
        require_firmware_match=True,
    )
    assert path == PROFILE


def test_other_models_keep_the_family_ap_profiles():
    mcm = ModeConfigManager(str(TEMPLATES))
    assert mcm.get_template_path("cambium", "ap", "ePMP 4518", profile="North", firmware="5.11.1") == (
        FAMILY / "AP" / "North" / "default.json"
    )
    assert mcm.get_template_path("cambium", "ap", "ePMP 4616", firmware="5.11.1") == FAMILY / "AP" / "default.json"


def test_4600_never_falls_back_to_the_family_ap_profile(tmp_path):
    shutil.copytree(TEMPLATES / "cambium", tmp_path / "cambium")
    shutil.rmtree(tmp_path / "cambium" / "ePMP-4K" / "5.11.1" / "AP" / "ePMP_4600")
    mcm = ModeConfigManager(str(tmp_path))
    assert mcm.get_template_path("cambium", "ap", "ePMP 4600", profile="North", firmware="5.11.1") is None
    assert mcm.get_template_path("cambium", "ap", "ePMP 4518", profile="North", firmware="5.11.1") is not None


def test_4600_ptp_resolution_is_unchanged():
    mcm = ModeConfigManager(str(TEMPLATES))
    assert mcm.get_template_path("cambium", "ptp-a", "ePMP 4600", link_profile="tw01-tw02", firmware="5.11.1") == (
        mcm.get_template_path("cambium", "ptp-a", "ePMP 4616", link_profile="tw01-tw02", firmware="5.11.1")
    )


def test_rendered_4600_profile_carries_workflow_identity():
    mcm = ModeConfigManager(str(TEMPLATES))
    template = mcm.load_template("cambium", "ap", model="ePMP 4600", profile="North", firmware="5.11.1",
                                 require_firmware_match=True)
    naming = mcm.generate_ap_naming(38, "north", "cambium")
    props = mcm.render_template(template, naming, "cambium")["device_props"]
    assert props["wirelessInterfaceSSID"] == "tw38-north"
    assert props["systemConfigDeviceName"] == "tw38-north"
    assert props["wirelessInterfaceMode"] == "1"


# --- profile content ----------------------------------------------------------

def test_4600_profile_lints_as_an_ap_template():
    config = json.loads(PROFILE.read_text())
    assert template_violations(CambiumHandler.FIELD_OWNERSHIP, config, "AP", "ePMP-4K") == []


def test_4600_profile_values_trace_to_the_field_reference():
    props = _props(PROFILE)
    fixture = json.loads((REFERENCE / "known-good.structure.json").read_text())["values"]
    witness = yaml.safe_load((REFERENCE / "manifest.yaml").read_text())["ap_profile_witness"]
    contract = CambiumHandler.FIELD_OWNERSHIP
    for key, value in props.items():
        owner = classify(contract, parse_path(key))
        if owner is Owner.MODE_ACTION:
            assert witness[key] == value, key
        else:
            assert owner in (Owner.FLEET_POLICY, Owner.ROLE), key
            assert fixture[key] == value, key


def test_4600_profile_leaves_site_rf_and_flagged_values_to_the_operator():
    props = _props(PROFILE)
    for key in (
        "wirelessInterfaceSSID", "systemConfigDeviceName", "snmpSystemName", "sysLocation",
        "centerFrequency", "centerFrequency2", "wirelessInterfaceTXPower",
        "wirelessInterfaceTDDAntennaGain", "watchdogTargetIPAddress", "watchdogEnable",
        "systemDeviceLocLatitude", "systemDeviceLocLongitude",
    ):
        assert key not in props, key
    assert not CambiumHandler._contains_secret_value(json.loads(PROFILE.read_text()))


# --- SM baseline unchanged ----------------------------------------------------

def test_sm_baseline_does_not_carry_the_new_ap_fields():
    props = _props(SM_TEMPLATE)
    for key in NEW_AP_FIELDS:
        assert key not in props
        assert key not in CambiumHandler.SM_FLEET_POLICY
    assert template_violations(
        CambiumHandler.FIELD_OWNERSHIP, json.loads(SM_TEMPLATE.read_text()), "SM", "ePMP-4K"
    ) == []


def test_sm_verification_set_ignores_the_new_ap_fields():
    contract = CambiumHandler.FIELD_OWNERSHIP
    applied = {"device_props": dict(_props(SM_TEMPLATE), **{key: "1" for key in NEW_AP_FIELDS})}
    sm_expected = expected_values(contract, applied)
    assert not any(key.endswith(field) for key in sm_expected for field in NEW_AP_FIELDS)
    mode_expected = expected_values(contract, applied, include_mode_action=True)
    assert all(any(key.endswith(field) for key in mode_expected) for field in NEW_AP_FIELDS)


# --- apply-mode planning ------------------------------------------------------

def _api_client(monkeypatch, tmp_path, with_profile):
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    from provisioner.config import Config
    from provisioner.web.app import create_app

    templates = tmp_path / "data" / "configs" / "templates"
    shutil.copytree(TEMPLATES / "cambium", templates / "cambium")
    if not with_profile:
        shutil.rmtree(templates / "cambium" / "ePMP-4K" / "5.11.1" / "AP" / "ePMP_4600")
    config = Config()
    config.features.mode_config = True
    config.data.local_path = str(tmp_path / "data")
    monkeypatch.setattr("provisioner.config._config", config)
    status = {
        "vlan_id": 1992, "link_up": True, "device_detected": True,
        "device_type": "cambium", "device_ip": "169.254.1.1",
        "device_mac": "00:00:00:00:00:02", "device_model": "ePMP 4600",
        "firmware_version": "5.11.1", "provisioning": False, "last_result": "success",
        "checklist": {"config_upload": True, "config_verify": True}, "device_mode": None,
    }
    port_manager = SimpleNamespace(get_port_status=lambda: {2: dict(status)})
    return TestClient(create_app(provisioner=SimpleNamespace(config=config, port_manager=port_manager)))


def test_ap_preview_is_refused_until_qualified(monkeypatch, tmp_path, evidence_root):
    client = _api_client(monkeypatch, tmp_path, with_profile=True)
    response = client.post("/api/ports/2/mode-preview", json={"mode": "ap", "tower": 38, "direction": "north"})
    assert response.status_code == 400
    assert response.json()["detail"].startswith("AP not qualified for ePMP 4600 on 5.11.1")


def test_ap_preview_uses_the_4600_profile_once_qualified(monkeypatch, tmp_path, evidence_root):
    _manifest(evidence_root, "ePMP 4600", "5.11.1", [("sm", "ap", "success"), ("ap", "sm", "success")])
    client = _api_client(monkeypatch, tmp_path, with_profile=True)
    response = client.post("/api/ports/2/mode-preview", json={"mode": "ap", "tower": 38, "direction": "north"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["template_found"] is True
    assert body["naming"]["ssid"] == "tw38-north"


def test_ap_preview_refuses_a_missing_4600_profile(monkeypatch, tmp_path, evidence_root):
    qualification.write_override("cambium", "ePMP 4600", "5.11.1", ["ap"], "bench", 2)
    client = _api_client(monkeypatch, tmp_path, with_profile=False)
    response = client.post("/api/ports/2/mode-preview", json={"mode": "ap", "tower": 38, "direction": "north"})
    assert response.status_code == 409
    assert "model-specific AP profile" in response.json()["detail"]
