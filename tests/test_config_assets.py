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
from provisioner.mode_config import ModeConfigManager, make_ptp_link_id
from provisioner.vendor_registry import (
    config_family_for_model,
    ptp_families_compatible,
)
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
    assert config_family_for_model("cambium", "ePMP 4616").directory == "ePMP-4K"
    assert config_family_for_model("cambium", "Cambium ePMP 4616").directory == "ePMP-4K"
    assert config_family_for_model("tachyon", "TNA-301").directory == "TNA-301-302"
    assert config_family_for_model("tachyon", "TNA-303X").directory == "TNA-303X"
    assert config_family_for_model("tachyon", "TNA-303L-65").directory == "TNA-303L-65"
    assert config_family_for_model("tachyon", "TNS-100") is None


def test_model_upload_fields_keep_tna_roles_distinct(tmp_path):
    catalog = ConfigAssetCatalog(tmp_path)

    family, role = catalog.infer_structured_fields_for_model("tachyon", "TNA-301")
    assert (family, role) == ("TNA-301-302", "AP")

    family, role = catalog.infer_structured_fields_for_model("tachyon", "TNA-302")
    assert (family, role) == ("TNA-301-302", "SM")

    with pytest.raises(ValueError, match="belongs to config family"):
        catalog.infer_structured_fields_for_model(
            "tachyon", "TNA-302", family="TNA-303X"
        )


def test_model_upload_destination_uses_handler_role_hint(tmp_path):
    catalog = ConfigAssetCatalog(tmp_path)

    ap_path = catalog.destination_for_model(
        "template",
        "tachyon",
        "TNA-301",
        family=None,
        firmware=None,
        role=None,
        mode=None,
        profile="West",
        link_profile=None,
        filename="captured.json",
    )
    assert ap_path.relative_to(tmp_path).as_posix() == (
        "configs/templates/tachyon/TNA-301-302/AP/West/captured.json"
    )

    sm_path = catalog.destination_for_model(
        "template",
        "tachyon",
        "TNA-302",
        family=None,
        firmware=None,
        role=None,
        mode=None,
        profile=None,
        link_profile=None,
        filename="captured.json",
    )
    assert sm_path.relative_to(tmp_path).as_posix() == (
        "configs/templates/tachyon/TNA-301-302/SM/captured.json"
    )


def test_cambium_sm_baselines_carry_the_handler_role_table_and_no_device_defaults():
    from provisioner.handlers.cambium import CambiumHandler

    for family in ("ePMP-4K", "ePMP-3K"):
        path = Path("configs/templates/cambium/%s/5.11.1/SM/default.json" % family)
        props = json.loads(path.read_text())["device_props"]
        for key, value in CambiumHandler.SM_ROLE_VALUES.items():
            assert props[key] == value, (family, key)
        # Device defaults are never written by a baseline.
        for key in (
            "wirelessInterface2PTPMode",
            "wirelessInterfaceTDDAntennaGain",
            "cambiumGPSConfigPrioritizeUSB",
            "systemConfigMinAntGain",
        ):
            assert key not in props, (family, key)


def test_registry_certifies_cross_family_ptp_pairs():
    assert ptp_families_compatible(
        "cambium", "ePMP 3000", "cambium", "ePMP 4616"
    )
    assert ptp_families_compatible(
        "cambium", "ePMP 4616", "cambium", "ePMP 4625"
    )
    assert ptp_families_compatible(
        "tachyon", "TNA-301", "tachyon", "TNA-303X"
    )
    assert ptp_families_compatible(
        "tachyon", "TNA-303L-65", "tachyon", "TNA-303X"
    )
    assert not ptp_families_compatible(
        "cambium", "ePMP 4616", "tachyon", "TNA-303X"
    )
    assert not ptp_families_compatible(
        "tachyon", "TNA-303X", "tachyon", "TNS-100"
    )


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


def test_family_sm_baseline_is_selected_per_model_and_never_shared(tmp_path):
    family = tmp_path / "configs/templates/cambium/ePMP-4K/5.11.1/SM/default.json"
    family.parent.mkdir(parents=True)
    family.write_text(json.dumps({"device_props": {"mgmtVLANVID": "12"}}))
    shared = tmp_path / "configs/templates/cambium/shared/5.11.1/SM/default.json"
    shared.parent.mkdir(parents=True)
    shared.write_text(json.dumps({"device_props": {"mgmtVLANVID": "99"}}))
    store = ConfigStore(str(tmp_path))

    for model in ("ePMP 4518", "ePMP 4616", "ePMP 4600C"):
        assert store.get_config_template("cambium", model) == family
    # A retired shared profile never wins, and other families fail closed.
    assert store.get_config_template("cambium", "ePMP 3000") is None

    assets = ConfigAssetCatalog(tmp_path).list_assets(device_type="cambium")
    assert any(asset.family == "ePMP-4K" and asset.role == "SM" for asset in assets)


def test_cambium_field_export_upload_preserves_original_and_protects_active(tmp_path):
    client, data_path = make_client(tmp_path)
    original = json.dumps(
        {
            "device_props": {
                "networkBridgeIPAddr": "192.0.2.10",
                "systemConfigDeviceName": "captured-name",
                "wirelessInterfaceSSID": "captured-ssid",
                "wirelessInterfaceScanFrequencyBandwidth": "19",
                "wirelessInterfaceTDDAntennaGain": "25",
                "snmpReadOnlyCommunity": "private-community",
                "cambiumCNSDeviceAgentPassword": "private-password",
                "wirelessInterfaceMode": "2",
                "wirelessInterfacePTPMode": "1",
                "wirelessInterfaceProtocolMode": "1",
            },
            "template_props": {"version": "5.11.1"},
        }
    ).encode()
    response = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "cambium",
            "firmware": "5.11.1",
            "role": "SM",
            "mode": "sm",
            "family": "ePMP-4K",
            "asset_kind": "field_export",
        },
        files={"file": ("bench-export.json", original, "application/json")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["metadata"]["export_type"] == "cambium_native_field_export"
    assert body["metadata"]["firmware_version"] == "5.11.1"
    assert body["metadata"]["secret_present"] is True
    assert "private-password" not in response.text

    active = data_path / "configs/templates/cambium/ePMP-4K/5.11.1/SM/default.json"
    active_props = json.loads(active.read_text())["device_props"]
    assert active_props["mgmtVLANVID"] == "12"
    assert active_props["wirelessInterfaceMode"] == "2"
    assert active_props["wirelessInterfaceScanFrequencyBandwidth"] == "19"
    assert "wirelessInterfaceTDDAntennaGain" not in active_props
    assert "snmpReadOnlyCommunity" not in active_props
    assert "cambiumCNSDeviceAgentPassword" not in active_props
    assert "networkBridgeIPAddr" not in active_props
    assert "systemConfigDeviceName" not in active_props
    assert "wirelessInterfaceSSID" not in active_props

    source = (
        data_path / "config-uploads" / "cambium" / body["metadata"]["source_id"]
        / "bench-export.json"
    )
    assert source.read_bytes() == original
    assert oct(source.parent.stat().st_mode & 0o777) == "0o700"
    assert oct(active.stat().st_mode & 0o777) == "0o600"
    assert client.get(
        "/api/config-assets/content", params={"path": body["asset"]["path"]}
    ).status_code == 403


def test_cambium_field_export_ap_keeps_role_rf_and_ssid(tmp_path):
    client, data_path = make_client(tmp_path)
    original = json.dumps(
        {
            "device_props": {
                "wirelessInterfaceSSID": "ORG-AP",
                "centerFrequency": "5790",
                "networkBridgeIPAddr": "192.0.2.11",
            },
            "template_props": {"version": "5.11.1"},
        }
    )
    response = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "cambium",
            "family": "ePMP-3K",
            "firmware": "5.11.1",
            "role": "AP",
            "mode": "ap",
            "scope": "family",
            "profile": "East",
            "asset_kind": "field_export",
        },
        files={"file": ("ap-export.json", original, "application/json")},
    )
    assert response.status_code == 200
    active = data_path / "configs/templates/cambium/ePMP-3K/5.11.1/AP/East/default.json"
    props = json.loads(active.read_text())["device_props"]
    assert props["wirelessInterfaceSSID"] == "ORG-AP"
    assert props["centerFrequency"] == "5790"
    assert "networkBridgeIPAddr" not in props


def test_cambium_field_export_rejects_firmware_metadata_mismatch(tmp_path):
    client, data_path = make_client(tmp_path)
    original = json.dumps(
        {
            "device_props": {"wirelessInterfaceSSID": "ORG-AP"},
            "template_props": {"version": "5.10.3"},
        }
    )
    response = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "cambium",
            "family": "ePMP-3K",
            "firmware": "5.11.1",
            "role": "AP",
            "mode": "ap",
            "scope": "family",
            "profile": "East",
            "asset_kind": "field_export",
        },
        files={"file": ("ap-export.json", original, "application/json")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Selected firmware must match the native export firmware version"
    )
    assert not list(data_path.glob("config-uploads/cambium/*"))


def test_cambium_field_export_ptp_uses_separate_side_path(tmp_path):
    client, data_path = make_client(tmp_path)
    original = json.dumps(
        {
            "device_props": {
                "wirelessInterfaceSSID": "PTP-LINK",
                "centerFrequency": "6835",
            },
            "template_props": {"version": "5.11.1"},
        }
    )
    response = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "cambium",
            "family": "ePMP-4K",
            "firmware": "5.11.1",
            "role": "PTP",
            "mode": "ptp-a",
            "scope": "family",
            "link_profile": "tw32-tw18",
            "profile": "Main",
            "asset_kind": "field_export",
        },
        files={"file": ("ptp-a.json", original, "application/json")},
    )
    assert response.status_code == 200
    assert response.json()["asset"]["path"] == (
        "configs/templates/cambium/ePMP-4K/5.11.1/PTP/tw32-tw18/Main/default.json"
    )
    assert (data_path / response.json()["asset"]["path"]).is_file()


def test_cambium_field_export_ptp_mode_matches_side_profile(tmp_path):
    client, _ = make_client(tmp_path)
    original = json.dumps(
        {
            "device_props": {"wirelessInterfaceSSID": "PTP-LINK"},
            "template_props": {"version": "5.11.1"},
        }
    )
    response = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "cambium",
            "family": "ePMP-4K",
            "firmware": "5.11.1",
            "role": "PTP",
            "mode": "ptp-b",
            "scope": "family",
            "link_profile": "tw32-tw18",
            "profile": "Main",
            "asset_kind": "field_export",
        },
        files={"file": ("ptp-b.json", original, "application/json")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "ptp-b exports require the SM side profile"
    )


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
    (root / "PTP/tw13-tw06/Main").mkdir(parents=True)
    (root / "PTP/tw13-tw06/Main/default.tar").write_bytes(b"reverse-exact")

    manager = ModeConfigManager(str(tmp_path / "configs/templates"))
    assert manager.get_template_path("tachyon", "ap", "TNA-303X", profile="North").name == "default.tar"
    assert manager.get_template_path(
        "tachyon", "ptp-a", "TNA-303X", link_profile="tw05-tw12"
    ).read_bytes() == b"exact"
    assert manager.get_template_path(
        "tachyon", "ptp-a", "TNA-303X", link_profile="tw07-tw14"
    ).parts[-3:] == ("twXX-twXX", "Main", "default.tar")
    assert manager.get_template_path(
        "tachyon", "ptp-a", "TNA-303X", link_profile="tw06-tw13"
    ).read_bytes() == b"reverse-exact"
    assert manager.get_template_path("tachyon", "ptp-a", "TNA-303X").parts[-2] == "Main"
    assert manager.get_template_path("tachyon", "ptp-b", "TNA-303X").parts[-2] == "SM"


def test_ptp_33_35_naming_keeps_shared_link_identity():
    manager = ModeConfigManager("unused")

    assert make_ptp_link_id(33, 35) == "tw33-tw35"
    assert manager.generate_ptp_naming(33, 35, "a", "cambium") == {
        "hostname": "tw33a-tw35",
        "systemname": "tw33a-tw35",
        "ssid": "tw33-tw35",
        "my_tower": "33",
        "my_tower_padded": "33",
        "remote_tower": "35",
        "remote_tower_padded": "35",
        "side": "a",
        "ptp_ssid": "tw33-tw35",
    }
    assert manager.generate_ptp_naming(33, 35, "b", "cambium")["hostname"] == (
        "tw33-tw35b"
    )
    assert manager.generate_ptp_naming(33, 35, "b", "cambium")["ssid"] == (
        "tw33-tw35"
    )
    assert manager.generate_ptp_naming(35, 33, "a", "cambium")["ssid"] == (
        "tw33-tw35"
    )


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


def test_legacy_cambium_ptp_templates_select_eptp_driver():
    """Cambium's writable ePTP selector is protocol mode, not effective status."""
    templates = Path(__file__).parents[1] / "configs/templates"
    manager = ModeConfigManager(str(templates))

    assert manager.load_template("cambium", "ptp-a")[
        "wirelessInterfaceProtocolMode"
    ] == "3"
    assert manager.load_template("cambium", "ptp-b")[
        "wirelessInterfaceProtocolMode"
    ] == "3"
    assert "cambiumSubModeType" not in manager.load_template("cambium", "ptp-a")
def test_ptp_settings_generation_requires_vendor_radio_settings():
    manager = ModeConfigManager("unused")
    naming = manager.generate_ptp_naming(32, 18, "a", "cambium")

    with pytest.raises(ValueError, match="Cambium PTP settings profile"):
        manager.generate_ptp_settings(
            {"device_props": {"wirelessInterfaceSSID": "profile"}},
            naming,
            "cambium",
            "a",
            "ePMP 4616",
        )

    config = {
        "device_props": {
            "wirelessInterfaceMode": "profile",
            "wirelessInterfacePTPMode": "profile",
            "wirelessInterfaceProtocolMode": "profile",
            "wirelessInterfaceTDDFrameSize": "profile",
            "wirelessInterfaceTDDRatio": "profile",
            "centerFrequency": "profile",
        }
    }
    with pytest.raises(ValueError, match="wirelessInterfaceMode"):
        manager.generate_ptp_settings(
            config, naming, "cambium", "a", "ePMP 4616"
        )

    config["device_props"].update(
        {
            "wirelessInterfaceMode": "1",
            "wirelessInterfacePTPMode": "1",
            "wirelessInterfaceProtocolMode": "3",
            "wirelessInterfaceTDDFrameSize": "5000",
            "wirelessInterfaceTDDRatio": "4",
            "centerFrequency": "6835",
        }
    )
    generated = manager.generate_ptp_settings(
        config, naming, "cambium", "a", "ePMP 4616"
    )
    assert generated["device_props"]["wirelessInterfaceSSID"] == naming["ssid"]

    with pytest.raises(ValueError, match="Tachyon PTP settings profile"):
        manager.generate_ptp_settings(
            {"system": {"hostname": "profile"}},
            naming,
            "tachyon",
            "a",
            "TNA-303X",
        )


def test_cambium_ptp_sm_settings_use_generated_preferred_ap_ssid():
    manager = ModeConfigManager("unused")
    naming = manager.generate_ptp_naming(32, 18, "b", "cambium")
    config = {
        "device_props": {
            "wirelessInterfaceSSID": "captured-ssid",
            "wirelessInterfaceMode": "2",
            "wirelessInterfacePTPMode": "1",
            "wirelessInterfaceProtocolMode": "3",
            "wirelessInterfaceTDDFrameSize": "5000",
            "wirelessInterfaceTDDRatio": "2",
            "centerFrequency": "6565",
            "prefferedAPTable": [
                {
                    "prefferedListTableEntrySSID": "captured-ssid",
                    "prefferedListTableEntryKEY": "kept-private",
                }
            ],
        }
    }

    generated = manager.generate_ptp_settings(
        config, naming, "cambium", "b", "ePMP 4616"
    )

    props = generated["device_props"]
    assert props["wirelessInterfaceSSID"] == naming["ssid"]
    assert props["prefferedAPTable"][0]["prefferedListTableEntrySSID"] == naming["ssid"]
    assert props["prefferedAPTable"][0]["prefferedListTableEntryKEY"] == "kept-private"


def test_cambium_ptp_sm_settings_require_preferred_ap_entry():
    manager = ModeConfigManager("unused")
    naming = manager.generate_ptp_naming(32, 18, "b", "cambium")
    config = {
        "device_props": {
            "wirelessInterfaceSSID": "captured-ssid",
            "wirelessInterfaceMode": "2",
            "wirelessInterfacePTPMode": "1",
            "wirelessInterfaceProtocolMode": "3",
            "wirelessInterfaceTDDFrameSize": "5000",
            "wirelessInterfaceTDDRatio": "2",
            "centerFrequency": "6565",
        }
    }

    with pytest.raises(ValueError, match="preferred AP entry"):
        manager.generate_ptp_settings(
            config, naming, "cambium", "b", "ePMP 4616"
        )


def test_mode_loader_matches_requested_firmware_version(tmp_path):
    root = tmp_path / "configs/templates/cambium/ePMP-4K"
    for version, marker in (("5.9.0", "old"), ("5.11.1", "current")):
        path = root / version / "PTP" / "tw18-tw32" / "Main"
        path.mkdir(parents=True)
        (path / "default.json").write_text(json.dumps({"marker": marker}))

    manager = ModeConfigManager(str(tmp_path / "configs/templates"))
    selected = manager.load_template(
        "cambium",
        "ptp-a",
        "ePMP 4616",
        link_profile="tw18-tw32",
        firmware="5.11.1",
    )

    assert selected == {"marker": "current"}


def _cambium_sm_doc():
    from provisioner.handlers.cambium import CambiumHandler

    props = dict(CambiumHandler.SM_FLEET_POLICY)
    props.update(CambiumHandler.SM_ROLE_VALUES)
    return json.dumps({"device_props": props})


def _tachyon_doc(mode):
    return json.dumps({"wireless": {"radios": {"wlan0": {"vaps": [{"mode": mode}]}}}})


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
        files={"file": ("uploaded.json", _cambium_sm_doc(), "application/json")},
    )
    assert response.status_code == 200, response.text
    assert (data_path / "configs/templates/cambium/ePMP-3K/5.11.1/SM/uploaded.json").is_file()

    refused = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "cambium",
            "family": "ePMP-3K",
            "firmware": "5.11.1",
            "role": "SM",
            "mode": "sm",
        },
        files={"file": ("bad.json", '{"device_props": {"wirelessInterfaceSSID": "site"}}', "application/json")},
    )
    assert refused.status_code == 400
    assert "wirelessInterfaceSSID (mode_action)" in refused.json()["detail"]
    assert "wirelessInterfaceMode (missing_role_field)" in refused.json()["detail"]

    traversal = client.get(
        "/api/config-assets/content",
        params={"path": "configs/templates/cambium/../../outside.json"},
    )
    assert traversal.status_code == 400


def test_config_asset_api_infers_family_and_role_from_model(tmp_path):
    client, data_path = make_client(tmp_path)

    ap_response = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "tachyon",
            "model": "TNA-301",
            "profile": "West",
        },
        files={"file": ("captured.json", _tachyon_doc("ap"), "application/json")},
    )
    assert ap_response.status_code == 200
    assert ap_response.json()["asset"]["family"] == "TNA-301-302"
    assert ap_response.json()["asset"]["role"] == "AP"
    assert (
        data_path / "configs/templates/tachyon/TNA-301-302/AP/West/captured.json"
    ).is_file()

    sm_response = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "tachyon",
            "model": "TNA-302",
        },
        files={"file": ("captured.json", _tachyon_doc("sta"), "application/json")},
    )
    assert sm_response.status_code == 200, sm_response.text
    assert sm_response.json()["asset"]["role"] == "SM"
    assert (
        data_path / "configs/templates/tachyon/TNA-301-302/SM/captured.json"
    ).is_file()

    mismatch = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "tachyon",
            "model": "TNA-302",
            "family": "TNA-303X",
            "role": "SM",
        },
        files={"file": ("captured.json", '{"ok": true}', "application/json")},
    )
    assert mismatch.status_code == 400
    assert "belongs to config family" in mismatch.json()["detail"]

    unsupported = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "tachyon",
            "model": "TNS-100",
        },
        files={"file": ("captured.json", '{"ok": true}', "application/json")},
    )
    assert unsupported.status_code == 400


def test_config_asset_api_rejects_secret_and_unsupported_family_role(tmp_path):
    client, data_path = make_client(tmp_path)

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

    legacy_secret = client.post(
        "/api/config-assets/upload",
        data={
            "config_type": "template",
            "device_type": "cambium",
        },
        files={"file": ("legacy-secret.json", '{"password": "redacted"}', "application/json")},
    )
    assert legacy_secret.status_code == 400

    legacy_path = data_path / "configs/templates/cambium/legacy.json"
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_text('{"snmpReadOnlyCommunity": "redacted"}')
    legacy_asset = next(
        item for item in client.get("/api/config-assets?device_type=cambium").json()
        if item["path"].endswith("legacy.json")
    )
    assert legacy_asset["protected"] is True
    legacy_content = client.get("/api/configs/template/cambium/legacy.json")
    assert legacy_content.status_code == 403
    assert "redacted" not in legacy_content.text

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
    assert not any(
        asset.role and asset.role.lower() == "ptp" for asset in assets
    )
