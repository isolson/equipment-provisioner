#!/usr/bin/env python3
"""Auto-rotate display + Wacom touch from the lid accelerometer.

Polls /sys/bus/iio/devices/iio:device* for the sensor labeled
'accel-display' (kernel-assigned, present on ThinkPad Yoga and similar
convertibles), applies its mount matrix, and runs `xrandr --rotate`
plus `xinput set-prop "Coordinate Transformation Matrix"` on the
Wacom touch sub-devices when orientation changes.

On hardware without a labeled lid sensor, exits 0 so the systemd unit
stays dormant rather than restart-looping.
"""

import os
import subprocess
import sys
import time

SYSFS_ROOT = "/sys/bus/iio/devices"
LID_LABEL = "accel-display"
OUTPUT = "eDP-1"
# Wacom devices on Yoga 11e — sub-device suffixes are added by libinput.
# Setting nonexistent devices is a no-op (xinput just prints to stderr).
TOUCH_DEVICES = [
    "Wacom HID 515F Pen stylus",
    "Wacom HID 515F Finger touch",
    "Wacom HID 515F Pen eraser",
]
POLL_INTERVAL = 0.5
SETTLE_TIME = 1.0
TILT_THRESHOLD = 9.81 * 0.55
FLAT_THRESHOLD = 9.81 * 0.80  # if |z| above this, screen is face up/down — skip

TOUCH_MATRIX = {
    "normal":   "1 0 0 0 1 0 0 0 1",
    "left":     "0 -1 1 1 0 0 0 0 1",
    "inverted": "-1 0 1 0 -1 1 0 0 1",
    "right":    "0 1 0 -1 0 1 0 0 1",
}


def find_lid_device():
    if not os.path.isdir(SYSFS_ROOT):
        return None
    for entry in sorted(os.listdir(SYSFS_ROOT)):
        if not entry.startswith("iio:device"):
            continue
        path = os.path.join(SYSFS_ROOT, entry)
        try:
            with open(os.path.join(path, "label")) as f:
                if f.read().strip() == LID_LABEL:
                    return path
        except FileNotFoundError:
            continue
    return None


def read_mount_matrix(path):
    with open(os.path.join(path, "in_mount_matrix")) as f:
        raw = f.read().strip()
    return [[float(v) for v in row.split(",")] for row in raw.split(";")]


def read_accel(path, scale):
    out = []
    for axis in ("x", "y", "z"):
        with open(os.path.join(path, "in_accel_{}_raw".format(axis))) as f:
            out.append(int(f.read().strip()) * scale)
    return out


def apply_mount(matrix, vec):
    return [sum(matrix[i][j] * vec[j] for j in range(3)) for i in range(3)]


def classify(ax, ay, az):
    if abs(az) > FLAT_THRESHOLD:
        return None
    if ay < -TILT_THRESHOLD:
        return "normal"
    if ay > TILT_THRESHOLD:
        return "inverted"
    if ax > TILT_THRESHOLD:
        return "left"
    if ax < -TILT_THRESHOLD:
        return "right"
    return None


def apply_rotation(orient):
    """Apply orientation. Returns True on xrandr success.

    xinput failures are tolerated (touch device names vary by hardware)
    but xrandr failing means X isn't ready — caller should retry.
    """
    r = subprocess.run(
        ["xrandr", "--output", OUTPUT, "--rotate", orient],
        capture_output=True,
    )
    if r.returncode != 0:
        return False
    matrix = TOUCH_MATRIX[orient].split()
    for dev in TOUCH_DEVICES:
        subprocess.run(
            ["xinput", "set-prop", dev,
             "Coordinate Transformation Matrix", *matrix],
            check=False,
        )
    return True


def main():
    lid = find_lid_device()
    if not lid:
        print("no iio device labeled '{}' — exiting cleanly".format(LID_LABEL))
        sys.exit(0)
    with open(os.path.join(lid, "in_accel_scale")) as f:
        scale = float(f.read().strip())
    mount = read_mount_matrix(lid)
    print("lid={} scale={} mount={}".format(lid, scale, mount), flush=True)

    current = None
    candidate = None
    candidate_since = 0.0

    while True:
        try:
            raw = read_accel(lid, scale)
        except OSError as e:
            print("read error: {}".format(e), file=sys.stderr, flush=True)
            time.sleep(POLL_INTERVAL)
            continue
        ax, ay, az = apply_mount(mount, raw)
        orient = classify(ax, ay, az)
        now = time.monotonic()

        if orient is None or orient == current:
            candidate = None
        elif candidate != orient:
            candidate = orient
            candidate_since = now
        elif now - candidate_since >= SETTLE_TIME:
            print("rotate {} -> {} (ax={:.2f} ay={:.2f} az={:.2f})".format(
                current, orient, ax, ay, az), flush=True)
            if apply_rotation(orient):
                current = orient
                candidate = None
            else:
                # xrandr failed (likely X not ready at boot) — back off and
                # retry one settle window from now.
                print("xrandr failed; will retry", flush=True)
                candidate_since = now

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
