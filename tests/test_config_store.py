from pathlib import Path

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


def test_non_tachyon_vendor_keeps_legacy_any_file_fallback(tmp_path):
    store = ConfigStore(str(tmp_path))
    fallback_template = tmp_path / "configs" / "templates" / "cambium" / "f4518-sm-defaultconfig.json"
    _write(fallback_template)

    assert store.get_config_template("cambium", None) == fallback_template


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
