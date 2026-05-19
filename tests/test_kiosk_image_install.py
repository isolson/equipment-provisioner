"""Regression tests for kiosk image install artifacts."""

from pathlib import Path


def test_kiosk_watchdog_keeps_display_awake():
    script = Path("image/chroot-install.sh").read_text()

    assert "wake_display()" in script
    assert "xset dpms force on" in script
    assert "xset s off" in script
    assert "xset -dpms" in script
    assert script.count("wake_display") >= 3
