"""Tests for MikroTik Netinstall package selection."""

from pathlib import Path

from provisioner.web.api import _select_latest_npk_per_arch, _split_routeros_and_extras


def test_select_latest_npk_per_package_and_arch(tmp_path: Path):
    for name in [
        "routeros-arm-7.21.4.npk",
        "routeros-arm-7.22.2.npk",
        "routeros-7.20.8-arm64.npk",
        "routeros-7.22.2-arm64.npk",
        "wifi-qcom-7.21.4-arm.npk",
        "wifi-qcom-7.22.2-arm.npk",
        "wifi-qcom-7.22.2-arm64.npk",
        "wifi-mediatek-7.22.2-arm.npk",
        "wifi-mediatek-7.22.2-arm64.npk",
        "custom-prerelease.npk",
    ]:
        (tmp_path / name).write_text("npk")

    selected = [Path(path).name for path in _select_latest_npk_per_arch(tmp_path)]

    # routeros first (order 0), then wifi-qcom (10), wifi-mediatek (12)
    assert "routeros-arm-7.22.2.npk" in selected
    assert "routeros-7.22.2-arm64.npk" in selected
    assert "wifi-qcom-7.22.2-arm.npk" in selected
    assert "wifi-qcom-7.22.2-arm64.npk" in selected
    assert "wifi-mediatek-7.22.2-arm.npk" in selected
    assert "wifi-mediatek-7.22.2-arm64.npk" in selected
    assert "custom-prerelease.npk" in selected
    assert "routeros-arm-7.21.4.npk" not in selected
    assert "routeros-7.20.8-arm64.npk" not in selected
    assert "wifi-qcom-7.21.4-arm.npk" not in selected


def test_split_routeros_and_extras_groups_multiple_drivers_per_arch(tmp_path: Path):
    """hAP ax² uses Qualcomm; hAP ax S uses MediaTek; both are arm/arm64.
    We need to ship both drivers and let the device bind whichever matches.
    """
    npks = [
        str(tmp_path / "routeros-arm-7.22.2.npk"),
        str(tmp_path / "routeros-arm64-7.22.2.npk"),
        str(tmp_path / "wifi-qcom-7.22.2-arm.npk"),
        str(tmp_path / "wifi-qcom-7.22.2-arm64.npk"),
        str(tmp_path / "wifi-mediatek-7.22.2-arm.npk"),
        str(tmp_path / "wifi-mediatek-7.22.2-arm64.npk"),
    ]

    routeros, extras_by_arch = _split_routeros_and_extras(npks)

    assert sorted(Path(p).name for p in routeros) == [
        "routeros-arm-7.22.2.npk",
        "routeros-arm64-7.22.2.npk",
    ]
    assert sorted(Path(p).name for p in extras_by_arch["arm"]) == [
        "wifi-mediatek-7.22.2-arm.npk",
        "wifi-qcom-7.22.2-arm.npk",
    ]
    assert sorted(Path(p).name for p in extras_by_arch["arm64"]) == [
        "wifi-mediatek-7.22.2-arm64.npk",
        "wifi-qcom-7.22.2-arm64.npk",
    ]
