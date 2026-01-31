# Scripts

Setup and installation scripts for the provisioner system. All scripts require root.

## setup.sh (recommended)

Unified setup script that runs all steps in order: install, credentials, switch detection, switch config, and service startup.

```bash
# Run directly
sudo bash scripts/setup.sh

# Or one-liner from a fresh machine
curl -sSL https://raw.githubusercontent.com/isolson/equipment-provisioner/main/scripts/bootstrap.sh | sudo bash
```

**Steps:**
1. Installs system dependencies and provisioner (calls `install.sh`)
2. Prompts for device credentials (Cambium, Tarana, Tachyon passwords)
3. Adds temporary IP on `eth0` so the Pi can reach the switch at `192.168.88.1`
4. Waits for a MikroTik switch to be plugged in (polls with spinner, 5 min timeout)
5. Configures the switch (calls `setup_switch.sh` with auto-confirm)
6. Creates management VLAN (`eth0.1990`) and verifies connectivity
7. Starts `provisioner-web` service and prints a ready banner

Each step is idempotent and skips completed work on re-runs. Ctrl+C during the switch wait skips that step. Setup log is written to `/var/log/provisioner-setup.log`.

## bootstrap.sh

Curl one-liner target. Installs `git`, clones the repo to `/opt/provisioner`, and runs `setup.sh`.

## install.sh

Main installation script. Installs the provisioner on an OrangePi or similar ARM Linux device.

```bash
# Full install
sudo ./scripts/install.sh

# Enable kiosk mode (Chromium fullscreen on boot)
sudo ./scripts/install.sh kiosk

# Disable kiosk mode
sudo ./scripts/install.sh disable-kiosk

# Uninstall
sudo ./scripts/install.sh uninstall
```

**What it does:**
1. Installs system dependencies (python3, git, vlan, iproute2, etc.)
2. Creates directories: `/opt/provisioner`, `/etc/provisioner`, `/var/lib/provisioner`
3. Creates Python virtualenv and installs pip dependencies
4. Copies config files to `/etc/provisioner/`
5. Installs systemd services (`provisioner`, `provisioner-web`)
6. Generates SSH deploy key for GitHub config repo access
7. (Optional) Configures kiosk mode: X11, Openbox, Chromium auto-login, screen blanking disabled

**Supported distros:** Debian, Ubuntu, Raspberry Pi OS, Armbian (apt-based), RHEL/CentOS (yum-based), Arch (pacman).

## setup_network.sh

Creates VLAN subinterfaces on the OrangePi for isolated device provisioning.

```bash
# Full setup with persistence (/etc/network/interfaces or netplan)
sudo ./scripts/setup_network.sh setup

# Quick setup (no persistence, for testing)
sudo ./scripts/setup_network.sh quick

# Show current VLAN interface status
sudo ./scripts/setup_network.sh status

# Remove all VLAN interfaces
sudo ./scripts/setup_network.sh cleanup
```

**Environment variables:**
| Variable | Default | Description |
|----------|---------|-------------|
| `PROVISIONER_INTERFACE` | `eth0` | Physical interface connected to switch trunk |
| `PROVISIONER_VLAN_START` | `1991` | First VLAN ID |
| `PROVISIONER_NUM_VLANS` | `6` | Number of provisioning VLANs |
| `PROVISIONER_LOCAL_IP` | `169.254.1.2` | IP assigned to each VLAN interface |

**Creates interfaces:**
- `eth0.1991` through `eth0.1996` — provisioning ports (169.254.1.2/24 each)
- `eth0.1990` — management VLAN (192.168.88.10/24, for switch webhooks)

## setup_switch.sh

Detects and configures a MikroTik switch for the provisioner's VLAN setup.

```bash
# Auto-detect switch and configure
sudo ./scripts/setup_switch.sh

# Specify switch IP and credentials
sudo ./scripts/setup_switch.sh --ip 192.168.88.1 --password yourpassword

# Use a custom RouterOS script instead of the built-in one
sudo ./scripts/setup_switch.sh --rsc /path/to/custom.rsc

# Skip password change prompt
sudo ./scripts/setup_switch.sh --skip-password-change

# Non-interactive (auto-confirm)
sudo ./scripts/setup_switch.sh --yes
```

**What it does:**
1. Scans common IPs and ARP table for MikroTik devices (by MAC OUI)
2. Connects via SSH (default: admin with empty password)
3. Uploads and imports the RouterOS config script
4. Configures VLANs 1990-1996, bridge, trunk port, and webhook scripts

The RouterOS template is at `configs/templates/mikrotik_switch_provisioner.rsc`.

## update_switch_script.sh

Updates the port monitoring script on an already-configured MikroTik switch. Use this after modifying `configs/templates/port-monitor-update.rsc`.

```bash
sudo ./scripts/update_switch_script.sh
```

This is a smaller, targeted update — it does not reconfigure VLANs or bridge settings.
