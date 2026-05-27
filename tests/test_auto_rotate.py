"""Regression tests for the auto-rotate daemon (image/auto-rotate.py).

The daemon is shipped to /usr/local/bin on the kiosk host; the file
in-repo is at image/auto-rotate.py (hyphen, not importable as a
package).  We load it dynamically here to test the pure-function
classification logic.

The sysfs reads and xrandr/xinput shells are integration-only — see
docs/KIOSK_ARCHITECTURE.md for the manual smoke test.
"""

import importlib.util
from pathlib import Path

import pytest


def _load_auto_rotate():
    path = Path(__file__).parent.parent / "image" / "auto-rotate.py"
    spec = importlib.util.spec_from_file_location("auto_rotate", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def ar():
    return _load_auto_rotate()


def test_classify_normal_upright(ar):
    # Laptop sitting on a desk normally — gravity pulls down (-y in aligned).
    assert ar.classify(0.0, -9.0, -3.0) == "normal"


def test_classify_inverted_upside_down(ar):
    # Laptop flipped — gravity now pulls toward the top of the screen.
    assert ar.classify(0.0, 9.0, -3.0) == "inverted"


def test_classify_left_when_right_edge_down(ar):
    # Tilted so the display's +x (right edge) points down — rotate "left".
    assert ar.classify(9.0, 0.0, -3.0) == "left"


def test_classify_right_when_left_edge_down(ar):
    # Tilted the other way — rotate "right".
    assert ar.classify(-9.0, 0.0, -3.0) == "right"


def test_classify_flat_returns_none(ar):
    # Laptop face-up on a table — |z| dominates, orientation is ambiguous.
    assert ar.classify(0.0, 0.0, -9.5) is None
    assert ar.classify(0.0, 0.0, 9.5) is None


def test_classify_ambiguous_diagonal_returns_none(ar):
    # Tilted between two orientations and no axis crosses the threshold.
    assert ar.classify(2.0, -2.0, -3.0) is None


def test_apply_mount_matrix_negates_x_for_yoga(ar):
    # The ThinkPad Yoga lid sensor uses mount_matrix [-1,0,0; 0,1,0; 0,0,1].
    mount = [[-1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]]
    aligned = ar.apply_mount(mount, [5.0, -3.0, 2.0])
    assert aligned == [-5.0, -3.0, 2.0]


def test_daemon_exits_zero_when_no_lid_sensor(ar, tmp_path, monkeypatch, capsys):
    """On non-Yoga hardware (no iio device labeled accel-display), the
    daemon must exit 0 cleanly so the systemd unit stays dormant rather
    than restart-looping."""
    # Point at an empty sysfs dir so find_lid_device returns None.
    empty = tmp_path / "iio"
    empty.mkdir()
    monkeypatch.setattr(ar, "SYSFS_ROOT", str(empty))

    with pytest.raises(SystemExit) as exc:
        ar.main()
    assert exc.value.code == 0
