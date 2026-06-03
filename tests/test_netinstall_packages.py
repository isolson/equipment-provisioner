"""Tests for MikroTik Netinstall package selection."""

from pathlib import Path

from provisioner.handlers.mikrotik import MikrotikHandler
from provisioner.web.api import (
    _select_latest_npk_per_arch,
    _select_wifi_extra,
    _split_routeros_and_extras,
)


def test_select_latest_npk_per_package_and_arch(tmp_path: Path):
    for name in [
        "routeros-arm-7.21.4.npk",
        "routeros-arm-7.22.2.npk",
        "routeros-7.20.8-arm64.npk",
        "routeros-7.22.2-arm64.npk",
        "wifi-qcom-7.21.4-arm.npk",
        "wifi-qcom-7.22.2-arm.npk",
        "wifi-qcom-7.22.2-arm64.npk",
        "custom-prerelease.npk",
    ]:
        (tmp_path / name).write_text("npk")

    selected = [Path(path).name for path in _select_latest_npk_per_arch(tmp_path)]

    assert selected[:5] == [
        "routeros-arm-7.22.2.npk",
        "routeros-7.22.2-arm64.npk",
        "wifi-qcom-7.22.2-arm.npk",
        "wifi-qcom-7.22.2-arm64.npk",
        "custom-prerelease.npk",
    ]
    assert "routeros-arm-7.21.4.npk" not in selected
    assert "routeros-7.20.8-arm64.npk" not in selected
    assert "wifi-qcom-7.21.4-arm.npk" not in selected


def test_split_routeros_and_extras_classifies_wifi_drivers():
    """routeros packages ship via netinstall; wifi drivers (qcom AND mediatek)
    are held back as post-boot extras, keyed by (package, arch)."""
    npks = [
        "/fw/routeros-arm-7.23.1.npk",
        "/fw/routeros-arm64-7.23.1.npk",
        "/fw/wifi-qcom-7.23.1-arm.npk",
        "/fw/wifi-qcom-7.23.1-arm64.npk",
        "/fw/wifi-mediatek-7.23.1-arm.npk",
        "/fw/custom-prerelease.npk",  # unconventional → treated as routeros
    ]

    routeros, extras = _split_routeros_and_extras(npks)

    assert sorted(Path(p).name for p in routeros) == [
        "custom-prerelease.npk",
        "routeros-arm-7.23.1.npk",
        "routeros-arm64-7.23.1.npk",
    ]
    assert extras[("wifi-qcom", "arm")].endswith("wifi-qcom-7.23.1-arm.npk")
    assert extras[("wifi-qcom", "arm64")].endswith("wifi-qcom-7.23.1-arm64.npk")
    assert extras[("wifi-mediatek", "arm")].endswith("wifi-mediatek-7.23.1-arm.npk")
    # A wifi driver must never be shipped during netinstall.
    assert not any("wifi-" in Path(p).name for p in routeros)


def test_select_wifi_extra_picks_family_for_arch():
    extras = {
        ("wifi-qcom", "arm"): "/fw/wifi-qcom-7.23.1-arm.npk",
        ("wifi-qcom", "arm64"): "/fw/wifi-qcom-7.23.1-arm64.npk",
        ("wifi-mediatek", "arm"): "/fw/wifi-mediatek-7.23.1-arm.npk",
    }
    # MediaTek hAP ax S (arm) gets mediatek even though wifi-qcom-arm exists.
    assert _select_wifi_extra(extras, "wifi-mediatek", "arm").endswith(
        "wifi-mediatek-7.23.1-arm.npk"
    )
    # Qualcomm models get qcom.
    assert _select_wifi_extra(extras, "wifi-qcom", "arm64").endswith(
        "wifi-qcom-7.23.1-arm64.npk"
    )
    # No package for the family/arch → None.
    assert _select_wifi_extra(extras, "wifi-mediatek", "arm64") is None


def test_wifi_driver_for_model_maps_chipset():
    # hAP ax S is MediaTek/arm.
    assert MikrotikHandler.wifi_driver_for_model("hAP ax S", "arm") == "wifi-mediatek"
    # hAP ax² / ax³ are Qualcomm/arm64 (and unknown wifi models default qcom).
    assert MikrotikHandler.wifi_driver_for_model("hAP ax2", "arm64") == "wifi-qcom"
    assert MikrotikHandler.wifi_driver_for_model("hAP ax3", "arm64") == "wifi-qcom"
    # Wired-only architectures take no driver.
    assert MikrotikHandler.wifi_driver_for_model("hEX", "mipsbe") is None
    assert MikrotikHandler.wifi_driver_for_model("CRS310", "arm") == "wifi-qcom"
