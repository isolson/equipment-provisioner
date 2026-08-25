"""Tests for the family/mode configuration asset library."""

import io
import json
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from provisioner.config import Config
from provisioner.config_assets import ConfigAssetCatalog
from provisioner.config_store import ConfigStore
from provisioner.mode_config import ModeConfigManager
from provisioner.vendor_registry import config_family_for_model
from provisioner.web.app import create_app


class DummyProvisioner:
    def __init__(self, config):
        self.config = config
        self.port_manager = None


def make_client(tmp_path):
    data_path = tmp_path / "repo"
    config = Config()
    config.data.local_path = str(data_path)
    return TestClient(create_app(provisioner=DummyProvisioner(config))), data_path


def test_registry_maps_approved_models_to_families():
    assert config_family_for_model("cambium", "ePMP 3000").directory == "ePMP-3K"
    assert config_family_for_model("cambium", "ePMP 4518").directory == "ePMP-4K"
    assert config_family_for_model("tachyon", "TNA-301").directory == "TNA-301-302"
    assert config_family_for_model("tachyon", "TNA-303X").directory == "TNA-303X"
    assert config_family_for_model("tachyon", "TNA-303L-65").directory == "TNA-303L-65"
    assert config_family_for_model("tachyon", "TNS-100") is None


def test_catalog_parses_versioned_and_unversioned_trees(tmp_path):
    root = tmp_path / "repo"
    cambium = root / "configs/templates/cambium/ePMP-4K/5.11.1/AP/North"
    tachyon = root / "configs/templates/tachyon/TNA-303X/AP/North"
    cambium.mkdir(parents=True)
    tachyon.mkdir(parents=True)
    (cambium / "default.json").write_text("{}")
    (tachyon / "default.tar").write_bytes(b"tar")

    assets = ConfigAssetCatalog(root).list_assets(device_type="cambium")
    assert len(assets) == 1
    assert assets[0].family == "ePMP-4K"
    assert assets[0].firmware == "5.11.1"
    assert assets[0].role == "AP"
    assert assets[0].mode == "ap"
    assert assets[0].profile == "North"

    tachyon_asset = ConfigAssetCatalog(root).list_assets(device_type="tachyon")[0]
    assert tachyon_asset.firmware is None
    assert tachyon_asset.editable is False


def test_catalog_rejects_path_traversal(tmp_path):
    catalog = ConfigAssetCatalog(tmp_path)
    with pytest.raises(ValueError):
        catalog.resolve("configs/templates/cambium/../../outside.json")


def test_family_store_uses_sm_baseline_without_cross_family_fallback(tmp_path):
    base = tmp_path / "configs/templates/cambium/ePMP-3K/5.11.1/SM"
    base.mkdir(parents=True)
    (base / "default.json").write_text("{}")
    store = ConfigStore(str(tmp_path))

    assert store.get_config_template("cambium", "ePMP 3000") == base / "default.json"
    assert store.get_config_template("cambium", "ePMP 4518") is None


def test_mode_profile_and_ptp_side_resolution(tmp_path):
    root = tmp_path / "configs/templates/tachyon/TNA-303X"
    (root / "AP/North").mkdir(parents=True)
    (root / "PTP/twXX-twXX/Main").mkdir(parents=True)
    (root / "PTP/twXX-twXX/SM").mkdir(parents=True)
    (root / "AP/North/default.tar").write_bytes(b"tar")
    (root / "PTP/twXX-twXX/Main/default.tar").write_bytes(b"tar")
    (root / "PTP/twXX-twXX/SM/default.tar").write_bytes(b"tar")
    (root / "PTP/tw05-tw12/Main").mkdir(parents=True)
    (root / "PTP/tw05-tw12/Main/default.tar").write_bytes(b"exact")

    manager = ModeConfigManager(str(tmp_path / "configs/templates"))
    assert manager.get_template_path("tachyon", "ap", "TNA-303X", profile="North").name == "default.tar"
    assert manager.get_template_path(
        "tachyon", "ptp-a", "TNA-303X", link_profile="tw05-tw12"
    ).read_bytes() == b"exact"
    assert manager.get_template_path(
        "tachyon", "ptp-a", "TNA-303X", link_profile="tw06-tw13"
    ).parts[-3:] == ("twXX-twXX", "Main", "default.tar")
    assert manager.get_template_path("tachyon", "ptp-a", "TNA-303X").parts[-2] == "Main"
    assert manager.get_template_path("tachyon", "ptp-b", "TNA-303X").parts[-2] == "SM"


def test_mode_loader_ignores_macos_tar_metadata(tmp_path):
    root = tmp_path / "configs/templates/tachyon/TNA-303X/PTP/twXX-twXX/Main"
    root.mkdir(parents=True)
    tar_path = root / "default.tar"
    config = b'{"system": {"hostname": "ptp-main"}}'
    metadata = b"not a UTF-8 JSON document"

    with tarfile.open(tar_path, "w") as archive:
        metadata_info = tarfile.TarInfo("._config.json")
        metadata_info.size = len(metadata)
        archive.addfile(metadata_info, io.BytesIO(metadata))
        config_info = tarfile.TarInfo("config.json")
        config_info.size = len(config)
        archive.addfile(config_info, io.BytesIO(config))

    manager = ModeConfigManager(str(tmp_path / "configs/templates"))
    assert manager.load_template(
        "tachyon", "ptp-a", "TNA-303X", link_profile="twXX-twXX"
    ) == {"system": {"hostname": "ptp-main"}}


def test_mode_family_missing_asset_does_not_fall_back_to_flat_template(tmp_path):
    family_root = tmp_path / "configs/templates/cambium/ePMP-3K"
    family_root.mkdir(parents=True)
    (tmp_path / "configs/templates/cambium/ap.json").write_text("{}")

    manager = ModeConfigManager(str(tmp_path / "configs/templates"))
    assert manager.get_template_path("cambium", "ap", "ePMP 3000", profile="North") is None


def test_cambium_mode_injection_updates_wrapped_device_props():
    manager = ModeConfigManager("unused")
    rendered = manager.render_template(
        {"device_props": {"wirelessInterfaceSSID": "old"}},
        {"ssid": "tw05-north", "hostname": "tw05-north"},
        "cambium",
    )
    assert rendered["device_props"]["wirelessInterfaceSSID"] == "tw05-north"
    assert rendered["device_props"]["snmpSystemName"] == "tw05-north"
    assert "wirelessInterfaceSSID" not in rendered


def test_config_asset_api_lists_and_uploads_structured_assets(tmp_path):
    client, data_path = make_client(tmp_path)
    existing = data_path / "configs/templates/cambium/ePMP-3K/5.11.1/SM/default.json"
    existing.parent.mkdir(parents=True)
    existing.write_text(json.dumps({"device_props": {"mgmtVLANVID": 12}}))

    response = client.get("/api/config-assets?device_type=cambium")
    assert response.status_code == 200
    assets = response.json()
    assert assets[0]["family"] == "ePMP-3K"
    assert assets[0]["role"] == "SM"
    assert assets[0]["mode"] == "sm"
    assert assets[0]["editable"] is True

    response = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "cambium",
            "family": "ePMP-3K",
            "firmware": "5.11.1",
            "role": "SM",
            "mode": "sm",
        },
        files={"file": ("uploaded.json", '{"ok": true}', "application/json")},
    )
    assert response.status_code == 200
    assert (data_path / "configs/templates/cambium/ePMP-3K/5.11.1/SM/uploaded.json").is_file()

    traversal = client.get(
        "/api/config-assets/content",
        params={"path": "configs/templates/cambium/../../outside.json"},
    )
    assert traversal.status_code == 400


def test_config_asset_api_rejects_secret_and_unsupported_family_role(tmp_path):
    client, _data_path = make_client(tmp_path)

    secret = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "cambium",
            "family": "ePMP-3K",
            "firmware": "5.11.1",
            "role": "SM",
            "mode": "sm",
        },
        files={"file": ("secret.json", '{"device_password": "redacted"}', "application/json")},
    )
    assert secret.status_code == 400

    unsupported_role = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "tachyon",
            "family": "TNA-303L-65",
            "role": "AP",
            "mode": "ap",
        },
        files={"file": ("config.tar", b"not a tar", "application/x-tar")},
    )
    assert unsupported_role.status_code == 400


def test_config_asset_api_redacts_ptp_content(tmp_path):
    client, data_path = make_client(tmp_path)
    ptp = data_path / "configs/templates/tachyon/TNA-303X/PTP/twXX-twXX/Main/default.tar"
    ptp.parent.mkdir(parents=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        content = b'{"wireless": {"security": {"passphrase": "not returned"}}}'
        info = tarfile.TarInfo("config.json")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    ptp.write_bytes(buffer.getvalue())

    assets = client.get("/api/config-assets?device_type=tachyon").json()
    assert assets[0]["protected"] is True
    assert assets[0]["editable"] is False
    response = client.get("/api/config-assets/content", params={"path": assets[0]["path"]})
    assert response.status_code == 403
    assert "passphrase" not in response.text


def test_repository_assets_have_no_tracked_ptp_files():
    assets = ConfigAssetCatalog(Path.cwd()).list_assets()
    assert assets
    assert not any(asset.protected for asset in assets)
