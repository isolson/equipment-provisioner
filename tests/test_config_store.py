from pathlib import Path

import pytest

from provisioner.config_store import ConfigStore


def _write(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")


def test_tachyon_unknown_model_does_not_fall_back_to_tns100(tmp_path):
    store = ConfigStore(str(tmp_path))
    _write(tmp_path / "configs" / "templates" / "tachyon" / "tns-100.json")

    assert store.get_config_template("tachyon", None) is None


def test_tachyon_tna_model_does_not_use_tns100_template(tmp_path):
    store = ConfigStore(str(tmp_path))
    _write(tmp_path / "configs" / "templates" / "tachyon" / "tns-100.json")

    assert store.get_config_template("tachyon", "TNA-303L-65") is None


def test_tachyon_tna_model_uses_timestamped_export(tmp_path):
    store = ConfigStore(str(tmp_path))
    export_template = (
        tmp_path
        / "configs"
        / "templates"
        / "tachyon"
        / "20260424.143334.TNA-303L-65.tar"
    )
    _write(export_template)
    _write(tmp_path / "configs" / "templates" / "tachyon" / "tns-100.json")

    assert store.get_config_template("tachyon", "TNA-303L-65") == export_template


def test_tachyon_301_role_hint_does_not_change_sm_provisioning_baseline(tmp_path):
    store = ConfigStore(str(tmp_path))
    sm_template = tmp_path / "configs/templates/tachyon/TNA-301-302/SM/default.tar"
    ap_template = tmp_path / "configs/templates/tachyon/TNA-301-302/AP/North/default.tar"
    _write(sm_template)
    _write(ap_template)

    # TNA-301's AP role is used when packaging a model-specific upload. The
    # standard provisioning path remains the verified SM baseline.
    assert store.get_config_template("tachyon", "TNA-301") == sm_template


def test_tachyon_bare_303l_uses_303l_65_sm_baseline(tmp_path):
    """A unit that reports the bare model "TNA-303L" gets the TNA-303L-65 SM template."""
    store = ConfigStore(str(tmp_path))
    sm_template = tmp_path / "configs/templates/tachyon/TNA-303L-65/SM/default.tar"
    _write(sm_template)

    assert store.get_config_template("tachyon", "TNA-303L") == sm_template


def test_tachyon_bare_303l_uses_committed_303l_65_sm_baseline():
    """The provisioning lookup finds the committed SM template for a bare TNA-303L."""
    repo_root = Path(__file__).resolve().parents[1]
    store = ConfigStore(str(repo_root))
    expected = repo_root / "configs/templates/tachyon/TNA-303L-65/SM/default.tar"

    assert expected.is_file()
    assert store.get_config_template("tachyon", "TNA-303L") == expected


def test_tachyon_305x_uses_tna305_family_template(tmp_path):
    store = ConfigStore(str(tmp_path))
    tna305_template = tmp_path / "configs" / "templates" / "tachyon" / "tna-305.tar"
    _write(tna305_template)
    _write(tmp_path / "configs" / "templates" / "tachyon" / "tna-30x.tar")
    _write(tmp_path / "configs" / "templates" / "tachyon" / "tns-100.json")

    assert store.get_config_template("tachyon", "TNA-305X") == tna305_template


def test_tachyon_305a_uses_tna305_family_template(tmp_path):
    store = ConfigStore(str(tmp_path))
    tna305_template = tmp_path / "configs" / "templates" / "tachyon" / "tna-305.tar"
    _write(tna305_template)

    assert store.get_config_template("tachyon", "TNA-305A") == tna305_template


def test_tachyon_tns100_model_uses_exact_template_case_insensitive(tmp_path):
    store = ConfigStore(str(tmp_path))
    tns_template = tmp_path / "configs" / "templates" / "tachyon" / "tns-100.json"
    _write(tns_template)

    assert store.get_config_template("tachyon", "TNS-100") == tns_template


def test_default_template_still_applies_without_model(tmp_path):
    store = ConfigStore(str(tmp_path))
    default_template = tmp_path / "configs" / "templates" / "tachyon" / "default.json"
    _write(default_template)

    assert store.get_config_template("tachyon", None) == default_template


def test_vendors_without_family_trees_keep_legacy_any_file_fallback(tmp_path):
    """Ubiquiti has no family tree, so an arbitrary vendor-dir file still applies."""
    store = ConfigStore(str(tmp_path))
    fallback_template = tmp_path / "configs" / "templates" / "ubiquiti" / "wave-nano-baseline.json"
    _write(fallback_template)

    assert store.get_config_template("ubiquiti", None) == fallback_template


def test_cambium_refuses_the_any_file_fallback(tmp_path):
    """Cambium's vendor root holds mode templates only; an unknown model fails closed."""
    store = ConfigStore(str(tmp_path))
    _write(tmp_path / "configs" / "templates" / "cambium" / "f4518-sm-defaultconfig.json")

    assert store.get_config_template("cambium", None) is None


def test_non_tachyon_timestamp_export_does_not_override_alias(tmp_path):
    store = ConfigStore(str(tmp_path))
    alias_template = tmp_path / "configs" / "templates" / "cambium" / "f4518-sm-defaultconfig.json"
    cambium_export = (
        tmp_path
        / "configs"
        / "templates"
        / "cambium"
        / "20260424.143334.ePMP 4518.tar"
    )
    _write(alias_template)
    _write(cambium_export)

    assert store.get_config_template("cambium", "ePMP 4518") == alias_template


def test_cambium_never_falls_back_to_a_vendor_root_mode_template(tmp_path):
    """The vendor root holds ap.json / ptp-*.json. They must never become a
    standard baseline for a model without a family SM template."""
    root = tmp_path / "configs" / "templates" / "cambium"
    _write(root / "ptp-a.json")
    _write(root / "ap.json")
    store = ConfigStore(str(tmp_path))

    assert store.get_config_template("cambium", "Force 300-25") is None
    assert store.get_config_template("cambium", "ePMP 4518") is None
    assert store.get_config_template("cambium", "Cambium ePMP (SKU 9)") is None


def test_force_300_models_belong_to_the_epmp_3k_family():
    from provisioner.vendor_registry import config_family_for_model

    for model in ("Force 300-25", "Force 300-16", "Force 300-19", "Force 300 CSM", "ePMP 3000"):
        assert config_family_for_model("cambium", model).directory == "ePMP-3K", model


@pytest.mark.parametrize("model,family", [
    ("TNA-301", "TNA-301-302"),
    ("TNA-302", "TNA-301-302"),
    ("TNA-303X", "TNA-303X"),
])
def test_registered_tachyon_sm_templates_include_fleet_profiles(model, family):
    """The real resolver must select the corrected family asset on a fresh unit.

    A model-named directory that the registry never selects previously left
    the 302 without profiles. Family coverage here is not hardware qualification.
    """
    from provisioner.config_templates import load_config_template

    repo = Path(__file__).resolve().parents[1]
    path = ConfigStore(str(repo)).get_config_template("tachyon", model)
    assert path == repo / "configs" / "templates" / "tachyon" / family / "SM" / "default.tar"
    config = load_config_template(str(path)).config
    profiles = config["wireless"]["radios"]["wlan0"]["vaps"][0]["sta_profiles"]["profiles"]
    assert len(profiles) == 4
    assert all(profile["security"]["mode"] == "wpapsk" for profile in profiles)
    assert all(not profile["security"].get("wpapsk", {}).get("passphrase") for profile in profiles)
