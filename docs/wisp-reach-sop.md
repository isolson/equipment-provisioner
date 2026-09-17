# WISP-Reach setup and recovery

WISP-Reach gives a Mac fixed addresses for common factory-default WISP devices. Use it only with a USB Ethernet adapter. The tool never changes Wi-Fi or built-in Ethernet.

The source is in [`tools/wisp-reach`](../tools/wisp-reach/). The root helper contains the fixed address list and accepts only approved interface names and presets.

## Install

Before you start, use macOS 13 or later and install the Xcode command-line tools:

```bash
xcode-select --install
```

From a clean checkout of this repository, run:

```bash
cd tools/wisp-reach
./install.sh
```

The installer builds the menu-bar app, installs the root helper, validates the scoped sudoers rule, and loads the per-user LaunchAgent. It asks for the administrator password once.

## Verify

After installation, plug in a USB Ethernet adapter. Confirm the LaunchAgent, helper, and aliases:

```bash
launchctl print "gui/$(id -u)/com.isolson.wispreach"
ls -l /usr/local/libexec/wisp-net
ifconfig en0
```

Replace `en0` with the device name for the USB adapter. The interface must show the required aliases:

| Device family | Alias |
| --- | --- |
| Cambium ePMP or Tachyon | `169.254.1.2` |
| Tarana | `169.254.100.2` |
| Ubiquiti airMAX or Wave | `192.168.1.2` |
| MikroTik | `192.168.88.10` |

Open the menu-bar network icon to apply one vendor preset, apply all presets, or clear the aliases. Test one device at a time on a private bench connection.

## Recover or remove

If automatic application fails, use the menu-bar **Reach Everything** action. If the adapter is connected, check its device name and link state with `ifconfig en0`. Review the user log at `~/Library/Logs/wisp-reach.log`.

To clear aliases without removing the tool, use **Clear** in the menu. To remove the installation, run:

```bash
cd tools/wisp-reach
./uninstall.sh
```

Uninstalling does not remove aliases that already exist. Clear them first, or unplug the adapter and restart the Mac.

## Maintain safely

- Keep the helper at `/usr/local/libexec/wisp-net` owned by `root:wheel` with mode `0755`.
- Keep `/etc/sudoers.d/wisp-net` limited to that helper. Validate changes with `visudo` before installation.
- If the address list changes, update both `helper/wisp-net` and `Sources/WispReach/Presets.swift`.
- Build after changes:

  ```bash
  swift build -c release
  ```

- Do not store device passwords or other secrets in this repository.

## What not to do

- Do not run the helper on Wi-Fi or built-in Ethernet.
- Do not add user-supplied IP addresses to the privileged helper.
- Do not replace the scoped sudoers rule with unrestricted `sudo` access.
- Do not run installation on a customer network. Use a private bench connection.
