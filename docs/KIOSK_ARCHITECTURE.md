# Kiosk Architecture

When the provisioner image is built with `--kiosk` (see `image/chroot-install.sh`), the host boots into a full-screen Chromium pointing at the provisioner UI. This doc explains the moving parts.

## Boot chain

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. getty@tty1.service → autologin as `kiosk` user                │
│    /etc/systemd/system/getty@tty1.service.d/autologin.conf       │
└────────────────────┬─────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. /home/kiosk/.bash_profile → `exec startx -- -nocursor`        │
└────────────────────┬─────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────┐
│ 3. startx → reads .xinitrc → `exec openbox-session`              │
└────────────────────┬─────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────┐
│ 4. openbox autostart                                             │
│    /home/kiosk/.config/openbox/autostart                         │
│    - Configures X DPMS (2 min blank / 5 min off)                 │
│    - Hides cursor via unclutter                                  │
│    - Waits for http://localhost:8080/                            │
│    - Launches chromium --kiosk http://localhost:8080             │
└──────────────────────────────────────────────────────────────────┘
```

Notably: **there is no display manager** (no lightdm/gdm). The Xorg auth file is at `/tmp/serverauth.XXXXXX` — random per session, not stable across reboots. Don't hardcode `XAUTHORITY` anywhere.

### Same-uid X access

This X server accepts local connections from the same uid **without** `XAUTHORITY` set. That's why every helper just does:

```bash
sudo -u kiosk env DISPLAY=:0 <xclient>
```

…and it Just Works. No auth file needed. (`provisioner-web` runs as root, so it uses this sudo-hop too — see "Display sleep/wake" below.)

## Companion services

| Unit | What it does |
| ---- | ------------ |
| `kiosk-watchdog.service` | Runs `/opt/provisioner/restart-kiosk.sh` as root. Polls every 10s; if chromium isn't running, wakes the screen (`xset dpms force on`, `xset s reset`) and respawns the browser. Important: it only wakes on **respawn**, not in the poll loop — otherwise it would defeat X DPMS idle. |
| `auto-rotate.service` | Runs `/usr/local/bin/auto-rotate.py` as `kiosk` user. Polls the lid accelerometer; rotates display + Wacom touchscreen on orientation change. Exits 0 if there's no `accel-display` iio sensor — the unit stays dormant on non-Yoga hardware. |
| `provisioner-web.service` | The provisioner itself. Runs as root, serves port 8080, **and runs the full provisioner loop** — `web_server.run_standalone()` calls `Provisioner.run()`, so this single process owns port monitoring, BOOTP listeners, and provisioning. This is the only unit the kiosk image enables. |
| `provisioner.service` | Headless (no-UI) variant that runs `Provisioner.run()` directly. **Do not enable it alongside `provisioner-web.service`** — two full provisioners means duplicate BOOTP listeners, so one plugged-in device fires two concurrent netinstalls that race on the interface IP. Kept on disk for no-UI deployments only. |

## Display sleep/wake

The kiosk image uses **native X DPMS** for idle handling, set in the openbox autostart:

```
xset s 120 120          # screensaver blanks after 2 min
xset +dpms              # enable DPMS
xset dpms 120 120 300   # standby/suspend 2 min, full off 5 min
```

Touch / keyboard / mouse input wakes the screen naturally via libinput.

### Wake on device connect

When the provisioner detects a device plug event (`provisioner/main.py` callbacks), it calls `DisplayController.wake()` (`provisioner/display.py`), which shells:

```bash
sudo -n -u kiosk env DISPLAY=:0 xset dpms force on
sudo -n -u kiosk env DISPLAY=:0 xset s reset
```

This requires `CAP_SETUID` + `CAP_SETGID` in the systemd unit — see [HOST_SETUP.md](HOST_SETUP.md#systemd-capabilities).

### Keep awake while devices are present

X DPMS only counts touch/keyboard/mouse as activity — a plugged-in device on its own doesn't reset the idle timer. To prevent the screen from blanking on a busy bench, `provisioner/main.py` runs a 60-second heartbeat loop (`_keep_display_awake_while_active`) that inspects `port_manager.port_states` and calls `DisplayController.keep_awake()` whenever any port has `link_up` or `device_detected`. `keep_awake()` shells:

```bash
sudo -n -u kiosk env DISPLAY=:0 xset s reset
```

which resets the screensaver counter; DPMS shares that timer in modern X, so the standby/suspend/off countdown is pushed back too. Idempotent, silent at INFO. When all ports are empty, the loop is a no-op and native X DPMS handles idle normally.

### Why not the JS idle path?

The kiosk UI has a JS-based "no devices on any port for N seconds → POST /api/display/sleep" timer. It's disabled by default (`config.yaml` `display.sleep_timeout: 0`) because it doesn't track user input — staring at the dashboard for 5 minutes would still trigger sleep. Native X DPMS handles user activity correctly.

Set `sleep_timeout: 300` if you want both behaviors (e.g. an unattended cabinet where you want the screen off whenever no devices are present, independent of touch).

## Auto-rotate

`auto-rotate.py` reads the lid accelerometer (sysfs `/sys/bus/iio/devices/iio:device*` where `label` is `accel-display`), applies the kernel-reported mount matrix, classifies orientation from gravity direction with hysteresis (1 s settle), and runs:

```bash
xrandr --output eDP-1 --rotate {normal,left,right,inverted}
xinput set-prop "Wacom HID 515F Pen stylus" "Coordinate Transformation Matrix" <...>
xinput set-prop "Wacom HID 515F Finger touch" "Coordinate Transformation Matrix" <...>
xinput set-prop "Wacom HID 515F Pen eraser" "Coordinate Transformation Matrix" <...>
```

If `xrandr` fails at startup (X not yet ready), the daemon backs off and retries on the next poll.

### Manual smoke tests

Most of the kiosk stack is system-dependent and not unit-testable. After a kiosk image build:

- [ ] `systemctl status auto-rotate.service` — service active, log shows `lid=/sys/bus/iio/devices/iio:deviceN`
- [ ] Rotate the device through all four orientations. Display + touch follow the sensor (tap something to confirm touch is aligned, not 90° off).
- [ ] Idle the kiosk for 2 min — screen blanks. Wait 5 min — screen fully off. Touch — wakes.
- [ ] On a non-Yoga host (or with the lid sensor masked), `auto-rotate.service` exits 0 cleanly and stays inactive instead of restart-looping.
- [ ] With chromium running, kill it (`pkill chromium`). `kiosk-watchdog` should respawn it within ~10 s and wake the screen if it was off.
- [ ] Plug in a device while the screen is off (5+ min idle). The screen wakes and the device-detect card appears.
- [ ] Plug a device into a port. After ~10 min of no touch input, the screen is still on. Unplug — the screen blanks normally on the next DPMS cycle (≤7 min later).

## Related

- [HOST_SETUP.md](HOST_SETUP.md) — Recommended hardware, SSH access, systemd capabilities
- `image/chroot-install.sh` — Canonical install steps (run during image build)
- `image/auto-rotate.py`, `image/auto-rotate.service` — Auto-rotate source
- `provisioner/display.py` — DisplayController source
