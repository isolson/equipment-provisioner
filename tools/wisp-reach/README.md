# WISP-Reach

A tiny macOS menu-bar utility that puts a set of IP aliases on your **USB
Ethernet dongles** so every common WISP device is reachable at its factory
default IP at once — no more manually re-IPing your laptop per vendor.

## What it does

When a USB Ethernet dongle links up, it auto-adds these aliases (all `/24`):

| Alias | Reaches | Device default |
|---|---|---|
| `169.254.1.2`   | Cambium ePMP, Tachyon             | 169.254.1.1 |
| `169.254.100.2` | Tarana                            | 169.254.100.1 |
| `192.168.1.2`   | Ubiquiti airMAX/Wave, Tachyon-alt | 192.168.1.20 / .1 |
| `192.168.88.10` | MikroTik                          | 192.168.88.1 |

The menu bar icon (a network glyph) gives you: live per-interface status, a
**Reach Everything** action, per-vendor presets, **Clear**, and an **Auto-apply
on plug-in** toggle. Aliases persist until you Clear them (or unplug).

It only ever touches **USB Ethernet** — never Wi-Fi, never built-in Ethernet.

## Install

```bash
./install.sh
```

One password prompt (to install the helper + sudoers rule); silent after that.
Requires Xcode command-line tools (`xcode-select --install`).

## How privilege works

Adding IP aliases needs root. Instead of prompting every time (which would break
silent auto-apply) or running a full root daemon, WISP-Reach installs one small,
locked-down root helper — `/usr/local/libexec/wisp-net` — plus a scoped
`NOPASSWD` sudoers rule limited to that one path.

The helper is the only privileged code. It:
- holds the authoritative IP list itself (the app can never inject an IP),
- accepts only `en<N>` interface names,
- refuses to touch the Wi-Fi interface, and
- refuses any interface that isn't a real Ethernet hardware port.

It's installed `root:wheel`, mode `0755` — not writable by your user, so it
can't be tampered with to widen its powers.

## Uninstall

```bash
./uninstall.sh
```

## Layout

- `Sources/WispReach/` — the menu-bar app (AppKit, Swift Package Manager)
- `helper/wisp-net` — the privileged root helper
- `packaging/` — Info.plist, LaunchAgent, sudoers template
- `install.sh` / `uninstall.sh`

The core-4 subnets were derived from the network-provisioner project's
`DeviceLinkLocalIP` registry so they match the real fleet. To change them, edit
**both** `helper/wisp-net` (authoritative) and `Sources/WispReach/Presets.swift`
(menu display), then re-run `install.sh`.
