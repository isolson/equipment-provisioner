"""Tests for MikroTik Netinstall package selection."""

from pathlib import Path

from provisioner.web.api import _select_latest_npk_per_arch


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
