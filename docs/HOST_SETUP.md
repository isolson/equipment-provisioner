# Host Setup

The provisioner runs on a Linux host that drives a MikroTik switch and (optionally) a touchscreen kiosk UI. This doc covers the recommended hardware, SSH access, and deployment workflow.

## Recommended hardware: Lenovo ThinkPad Yoga 11e

The ThinkPad Yoga 11e is the canonical kiosk host:

- **x86_64** — required for MikroTik Netinstall (no ARM Netinstall binary exists)
- **Touchscreen** — Wacom AES, recognized as `Wacom HID 515F Pen/Finger/eraser` by libinput
- **Convertible** — auto-rotation via the lid accelerometer (`accel-display` iio device), wired up by `auto-rotate.service`
- **Quiet** — fanless, fits on a network rack
- **Cheap** — used units are widely available

Other x86 hardware works too (Dell OptiPlex 3050, Wyse 5070, HP EliteDesk 800 G2), but you give up touchscreen and rotation. The auto-rotate daemon is inert on hardware without an `accel-display` sensor — it exits 0 cleanly and the systemd unit stays dormant.

## SSH access

The kiosk image creates a `serveradmin` user with sudo and an authorized key. From a dev workstation:

```bash
ssh -i ~/.ssh/id_conductor serveradmin@<host-ip>
```

### Gotcha: 1Password SSH agent

If your dev machine's `~/.ssh/config` sets `IdentityAgent` to the 1Password agent for `Host *`, the agent burns through auth attempts with its own keys before `id_conductor` is offered. The host then disconnects with "Too many authentication failures".

Workaround — explicitly bypass the agent and the host's `IdentitiesOnly`:

```bash
unset SSH_AUTH_SOCK
ssh -i ~/.ssh/id_conductor -o IdentitiesOnly=yes serveradmin@<host-ip>
```

Or add a per-host alias in `~/.ssh/config`:

```
Host provisioner
    HostName 192.168.10.50
    User serveradmin
    IdentityFile ~/.ssh/id_conductor
    IdentitiesOnly yes
    IdentityAgent none
```

## Deploying code

`scripts/deploy.sh` rsyncs the working tree to `/opt/provisioner/` on the host and restarts `provisioner-web`. Defaults to `serveradmin@192.168.10.50`; override with `PROVISIONER_HOST` / `PROVISIONER_USER`.

The script auto-detects `~/.ssh/id_conductor` and passes `-i KEY -o IdentitiesOnly=yes` to both rsync and the inline ssh calls, so the 1Password-agent issue above doesn't affect it. Override with `SSH_KEY=/path/to/other_key` or set `SSH_OPTS=` to use whatever your `~/.ssh/config` provides.

## Config files: `/etc` vs `/opt`

`provisioner-web.service` reads its config from `/etc/provisioner/config.yaml` (set in the unit's `ExecStart`). The deploy script rsyncs the repo to `/opt/provisioner/`, which means **`/opt/provisioner/config.yaml` is NOT read at runtime**.

When applying config changes:

```bash
unset SSH_AUTH_SOCK
scp -i ~/.ssh/id_conductor -o IdentitiesOnly=yes config.yaml \
    serveradmin@<host>:/tmp/cfg.new
ssh -i ~/.ssh/id_conductor -o IdentitiesOnly=yes serveradmin@<host> \
    'sudo -n install -o root -g root -m 0644 /tmp/cfg.new /etc/provisioner/config.yaml && \
     rm /tmp/cfg.new && sudo -n systemctl restart provisioner-web'
```

## systemd capabilities

`provisioner-web.service` runs as `root` but with a restrictive `CapabilityBoundingSet`. Two non-obvious capabilities are required:

| Capability | Why |
| ---------- | --- |
| `CAP_NET_BIND_SERVICE` | Spawned `netinstall-cli` binds UDP/67 (BOOTP). Without this, even root can't bind — the BOOTP path fails with "Permission denied", which is confusing under `User=root`. |
| `CAP_SETUID`, `CAP_SETGID` | Display wake uses `sudo -u kiosk env DISPLAY=:0 xset …` to drive the kiosk's X server. Without these in the bounding set, sudo's `setuid()` call fails silently and wake-on-device-connect falls back to backlight-only (which doesn't actually turn the panel back on). |

If you edit the unit, keep both lines:

```ini
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_RAWIO CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
```

(`CAP_SETUID`/`SETGID` go in the bounding set only — sudo gets them via its setuid bit, it just needs the bounding set to permit the elevation.)

## Related

- [docs/KIOSK_ARCHITECTURE.md](KIOSK_ARCHITECTURE.md) — how the kiosk session is constructed (startx, openbox, auto-rotate, display sleep/wake)
- [docs/mikrotik-netinstall.md](mikrotik-netinstall.md) — why x86 is required for Netinstall
