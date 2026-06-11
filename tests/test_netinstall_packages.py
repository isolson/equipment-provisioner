"""Tests for MikroTik Netinstall package selection."""

from pathlib import Path

from provisioner.handlers.mikrotik import MikrotikHandler
from provisioner.web.api import (
    _select_latest_npk_per_arch,
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


def test_select_latest_npk_per_arch_keeps_wifi_drivers_for_netinstall(tmp_path: Path):
    """Netinstall now ships the selected WiFi driver packages with RouterOS."""
    for name in [
        "routeros-arm-7.23.1.npk",
        "wifi-qcom-7.23.1-arm.npk",
        "wifi-mediatek-7.23.1-arm.npk",
        "routeros-7.23.1-arm64.npk",
        "wifi-qcom-7.23.1-arm64.npk",
    ]:
        (tmp_path / name).write_text("npk")

    selected = [Path(path).name for path in _select_latest_npk_per_arch(tmp_path)]

    assert "routeros-arm-7.23.1.npk" in selected
    assert "wifi-qcom-7.23.1-arm.npk" in selected
    assert "wifi-mediatek-7.23.1-arm.npk" in selected
    assert "routeros-7.23.1-arm64.npk" in selected
    assert "wifi-qcom-7.23.1-arm64.npk" in selected


def test_wifi_driver_for_model_maps_chipset():
    # hAP ax S is MediaTek/arm.
    assert MikrotikHandler.wifi_driver_for_model("hAP ax S", "arm") == "wifi-mediatek"
    # hAP ax² / ax³ are Qualcomm/arm64 (and unknown wifi models default qcom).
    assert MikrotikHandler.wifi_driver_for_model("hAP ax2", "arm64") == "wifi-qcom"
    assert MikrotikHandler.wifi_driver_for_model("hAP ax3", "arm64") == "wifi-qcom"
    # Wired-only architectures take no driver.
    assert MikrotikHandler.wifi_driver_for_model("hEX", "mipsbe") is None
    assert MikrotikHandler.wifi_driver_for_model("CRS310", "arm") == "wifi-qcom"
