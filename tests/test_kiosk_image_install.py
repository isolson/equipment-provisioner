"""Regression tests for kiosk image install artifacts."""

from pathlib import Path


def _chroot_script():
    return Path("image/chroot-install.sh").read_text()


def test_kiosk_autostart_enables_native_dpms():
    """openbox autostart must enable native X DPMS so the screen idles off
    on user-input idle and wakes naturally on touch via libinput."""
    script = _chroot_script()
    assert "xset s 120 120" in script
    assert "xset +dpms" in script
    assert "xset dpms 120 120 300" in script
    # The old "always on" behavior must NOT be present.
    assert "xset s off" not in script
    assert "xset -dpms" not in script


def test_restart_kiosk_wakes_only_on_browser_respawn():
    """The kiosk watchdog must wake the screen only when respawning the
    browser, not on every loop iteration — otherwise it defeats X DPMS."""
    script = _chroot_script()
    # The wake command is present (for browser respawn).
    assert "xset dpms force on" in script
    assert "xset s reset" in script
    # The old wake_display() helper that fired every 10s is gone.
    assert "wake_display()" not in script
    # And the heredoc no longer permanently disables blanking.
    assert "xset s off" not in script
    assert "xset -dpms" not in script


def test_kiosk_install_includes_xinput():
    """xinput is required for auto-rotate's Coordinate Transformation Matrix."""
    script = _chroot_script()
    assert "xinput" in script


def test_auto_rotate_installed_with_kiosk():
    """auto-rotate.py + service must be installed and enabled by the
    chroot install when --kiosk is set."""
    script = _chroot_script()
    assert "/usr/local/bin/auto-rotate.py" in script
    assert "/etc/systemd/system/auto-rotate.service" in script
    assert "systemctl enable auto-rotate.service" in script
