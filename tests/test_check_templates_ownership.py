"""The template lint enforces the field ownership contract."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import check_templates  # noqa: E402


def _write(path: Path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))


def _sm_baseline():
    from provisioner.handlers.cambium import CambiumHandler

    props = dict(CambiumHandler.SM_FLEET_POLICY)
    props.update(CambiumHandler.SM_ROLE_VALUES)
    return {"device_props": props}


def test_tracked_templates_pass_the_ownership_lint():
    assert check_templates.check_ownership("configs/templates", strict=True) == []


def test_sm_baseline_with_secret_device_default_or_identity_fails(tmp_path):
    doc = _sm_baseline()
    doc["device_props"]["wirelessInterfaceEncryptionKey"] = "x"
    doc["device_props"]["cambiumGPSConfigPrioritizeUSB"] = "1"
    doc["device_props"]["wirelessInterfaceSSID"] = "site"
    doc["device_props"]["someNewThing"] = "0"
    _write(tmp_path / "cambium" / "ePMP-4K" / "5.11.1" / "SM" / "default.json", doc)
    problems = {p for _, p in check_templates.check_ownership(str(tmp_path), strict=True)}
    assert problems == {
        "ownership: wirelessInterfaceEncryptionKey is secret",
        "ownership: cambiumGPSConfigPrioritizeUSB is device_default",
        "ownership: wirelessInterfaceSSID is mode_action",
        "ownership: someNewThing is unclassified",
    }
    # Runtime roots tolerate unclassified fields but never classified violations.
    relaxed = {p for _, p in check_templates.check_ownership(str(tmp_path), strict=False)}
    assert "ownership: someNewThing is unclassified" not in relaxed
    assert "ownership: wirelessInterfaceEncryptionKey is secret" in relaxed


def test_sm_baseline_missing_a_role_field_fails(tmp_path):
    doc = _sm_baseline()
    del doc["device_props"]["wirelessInterfaceProtocolMode"]
    _write(tmp_path / "cambium" / "ePMP-4K" / "5.11.1" / "SM" / "default.json", doc)
    problems = [p for _, p in check_templates.check_ownership(str(tmp_path))]
    assert problems == ["ownership: wirelessInterfaceProtocolMode is missing_role_field"]


def test_ap_template_may_carry_mode_action_fields(tmp_path):
    doc = _sm_baseline()
    doc["device_props"]["wirelessInterfaceMode"] = "1"
    doc["device_props"]["wirelessInterfaceSSID"] = "tw05-north"
    _write(tmp_path / "cambium" / "ePMP-4K" / "5.11.1" / "AP" / "North" / "default.json", doc)
    assert check_templates.check_ownership(str(tmp_path)) == []


def test_vendor_without_contract_is_skipped(tmp_path):
    _write(tmp_path / "tarana" / "default.json", {"operator_id": "x", "anything": 1})
    assert check_templates.check_ownership(str(tmp_path)) == []


def test_role_is_read_from_path_or_legacy_basename():
    assert check_templates._template_role(("cambium", "ePMP-4K", "5.11.1", "SM", "default.json")) == "SM"
    assert check_templates._template_role(("cambium", "ptp-b.json")) == "PTP"
    assert check_templates._template_role(("tachyon", "tns-100.json")) == "SM"
    assert check_templates._template_role(("cambium", "x", "y", "default.json")) is None


def test_main_runs_ownership_with_runtime_root(tmp_path, capsys):
    _write(tmp_path / "cambium" / "ePMP-4K" / "5.11.1" / "SM" / "default.json", _sm_baseline())
    assert check_templates.main(["check_templates.py", "--runtime-root", str(tmp_path)]) == 0
    doc = _sm_baseline()
    doc["device_props"]["wirelessInterfaceEncryptionKey"] = "SECRETVALUE-9f3a"
    _write(tmp_path / "cambium" / "ePMP-4K" / "5.11.1" / "SM" / "default.json", doc)
    assert check_templates.main(["check_templates.py", "--runtime-root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "wirelessInterfaceEncryptionKey is secret" in out
    assert "SECRETVALUE-9f3a" not in out
