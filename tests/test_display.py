"""Regression tests for the display controller (provisioner/display.py).

Covers the contract that wake-on-device-connect must remain functional
after the switch to native X DPMS for idle handling (sleep_timeout=0).
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from provisioner.display import DisplayController


class _OK:
    """Stand-in for subprocess.CompletedProcess with rc=0."""
    returncode = 0
    stdout = b""
    stderr = b""


@pytest.fixture
def patch_subprocess():
    with patch("provisioner.display.subprocess.run") as mock:
        mock.return_value = _OK()
        yield mock


def test_xset_uses_sudo_as_kiosk(patch_subprocess):
    """_xset must hop to the kiosk user with DISPLAY=:0 so root can drive
    the kiosk's X server (which uses same-uid local auth, not XAUTHORITY)."""
    ctl = DisplayController(use_dpms=True, use_backlight=False)
    ctl._xset("dpms", "force", "on")

    patch_subprocess.assert_called_once()
    argv = patch_subprocess.call_args.args[0]
    assert argv == [
        "sudo", "-n", "-u", "kiosk", "env", "DISPLAY=:0",
        "xset", "dpms", "force", "on",
    ]


async def test_wake_runs_commands_even_when_not_marked_sleeping(patch_subprocess):
    """X DPMS can turn the screen off without our knowledge (e.g. native
    idle timer fires), so wake() must NOT short-circuit on _sleeping.

    This is the regression that breaks wake-on-device-connect after a
    native DPMS idle off.
    """
    ctl = DisplayController(use_dpms=True, use_backlight=False)
    assert ctl._sleeping is False  # never slept programmatically

    await ctl.wake()

    # Must have invoked xset dpms force on regardless of _sleeping.
    calls = [c.args[0] for c in patch_subprocess.call_args_list]
    assert any("xset" in c and "force" in c and "on" in c for c in calls), (
        f"wake() did not invoke xset dpms force on; calls={calls}"
    )


async def test_wake_backlight_skipped_if_not_slept_by_us():
    """If we never put the backlight to sleep ourselves, wake() must NOT
    restore brightness to max — the user's current setting (or X DPMS) is
    the source of truth.  Otherwise calling wake() at startup would jump
    the screen to 100% brightness."""
    ctl = DisplayController(use_dpms=False, use_backlight=True)
    # Simulate having a backlight device but no recorded sleep.
    ctl._backlight_path = MagicMock()
    ctl._saved_brightness = None

    assert ctl._wake_backlight() is False
    ctl._backlight_path.write_text.assert_not_called()


def test_web_server_always_inits_display_controller():
    """The startup path must call init_display() unconditionally — even
    when sleep_timeout=0 — so wake-on-device-connect still works while
    X DPMS handles idle natively."""
    src = Path("provisioner/web_server.py").read_text()
    # The old gate that skipped init when timeout was 0 must be gone.
    assert "sleep_timeout > 0" not in src, (
        "init_display() must not be gated on sleep_timeout — "
        "wake-on-connect needs the controller initialized even when "
        "X DPMS handles idle (sleep_timeout=0)."
    )
    assert "init_display(" in src


def test_provisioner_callbacks_do_not_gate_wake_on_is_sleeping():
    """The device-detect callbacks in main.py must not check
    display.is_sleeping() before calling wake() — X DPMS can turn off
    the screen without our knowing, and wake() is idempotent."""
    src = Path("provisioner/main.py").read_text()
    # The is_sleeping() gate is the regression we're guarding against.
    assert "and display.is_sleeping()" not in src, (
        "main.py callsites must not gate wake() on is_sleeping(); "
        "X DPMS state can drift from DisplayController state."
    )


def test_provisioner_web_unit_has_setuid_caps():
    """The systemd unit must include CAP_SETUID/CAP_SETGID in
    CapabilityBoundingSet so the sudo-as-kiosk pattern in display.py
    actually works at runtime."""
    unit = Path("systemd/provisioner-web.service").read_text()
    # Find the bounding set line.
    bounding = next(
        (line for line in unit.splitlines() if line.startswith("CapabilityBoundingSet=")),
        None,
    )
    assert bounding is not None, "no CapabilityBoundingSet line found"
    assert "CAP_SETUID" in bounding, (
        "CAP_SETUID missing from CapabilityBoundingSet — sudo -u kiosk "
        "will silently fail and wake-on-connect breaks."
    )
    assert "CAP_SETGID" in bounding, (
        "CAP_SETGID missing from CapabilityBoundingSet — sudo -u kiosk "
        "will silently fail and wake-on-connect breaks."
    )
