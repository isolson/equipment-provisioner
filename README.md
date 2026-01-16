# Equipment Auto-Provisioner

Automated provisioning system for network equipment running on OrangePi (or similar ARM Linux). Detects devices when plugged in, identifies them, applies configuration, updates firmware, and notifies on completion.

## Supported Devices

- **Cambium ePMP** - PTP/PTMP radios
- **Mikrotik RouterOS** - Routers and switches
- **Tarana** - G1 wireless units
- **Tachyon** - 30x series radios

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/isolson/equipment-provisioner/main/scripts/install.sh | sudo bash
```

Or clone and install manually:

```bash
git clone https://github.com/isolson/equipment-provisioner.git
cd equipment-provisioner
sudo ./scripts/install.sh
```

## Hardware Setup

### Required Equipment

- OrangePi (or Raspberry Pi / similar SBC)
- 8-port managed switch (Mikrotik CRS/CSS recommended)
- Ethernet cables

### Port Layout

| Switch Port | Purpose | VLAN |
|-------------|---------|------|
| Port 1 (ether1) | Provisioning slot 1 | 1991 |
| Port 2 (ether2) | Provisioning slot 2 | 1992 |
| Port 3 (ether3) | Provisioning slot 3 | 1993 |
| Port 4 (ether4) | Provisioning slot 4 | 1994 |
| Port 5 (ether5) | Provisioning slot 5 | 1995 |
| Port 6 (ether6) | Provisioning slot 6 | 1996 |
| Port 7 (ether7) | WAN/Internet from router | Native |
| Port 8 (ether8) | Trunk to OrangePi | All VLANs |

### Switch Configuration

For Mikrotik switches, import the included configuration:

```
/import file-name=mikrotik_switch_provisioner.rsc
```

Or upload via Winbox: Files → Upload → Terminal → `/import mikrotik_switch_provisioner.rsc`

The config file is at `configs/templates/mikrotik_switch_provisioner.rsc`

## Configuration

### 1. Edit credentials

```bash
sudo nano /etc/provisioner/provisioner.env
```

Set your device passwords:
```
CAMBIUM_PASSWORD=your_password
MIKROTIK_PASSWORD=your_password
TARANA_PASSWORD=your_password
TACHYON_PASSWORD=your_password
```

### 2. Configure GitHub repo (for configs/firmware)

Edit `/etc/provisioner/config.yaml`:
```yaml
github:
  repo: git@github.com:your-org/your-network-configs.git
  branch: main
```

Add the deploy key to your GitHub repo (shown after install).

### 3. Start the service

```bash
sudo systemctl start provisioner-web
sudo systemctl status provisioner-web

# View logs
journalctl -u provisioner-web -f
```

## How It Works

1. **Detection** - Monitors switch ports for link-up events
2. **Identification** - Probes device to determine type, model, firmware version
3. **Configuration** - Applies template config (with optional per-device overrides)
4. **Firmware Update** - Updates firmware if newer version available (supports dual-bank)
5. **Notification** - Sends Slack/Discord message and blinks LED

## Device Link-Local Addresses

Devices are accessed via their default link-local IPs:

| Device Type | Default IP |
|-------------|------------|
| Cambium ePMP | 169.254.1.1 |
| Tachyon | 169.254.1.1 |
| Tarana | 169.254.100.1 |
| Mikrotik | 192.168.88.1 |

The OrangePi uses `169.254.1.2` on each VLAN interface to communicate with devices.

## Directory Structure

```
/opt/provisioner/          # Application files
/etc/provisioner/          # Configuration
  ├── config.yaml          # Main config
  ├── provisioner.env      # Credentials (secrets)
  └── deploy_key           # GitHub SSH key
/var/lib/provisioner/      # Data
  ├── repo/                # Synced GitHub configs
  └── history.db           # Provisioning history
/var/log/provisioner.log   # Log file
```

## Web Interface

The provisioner includes a touch-friendly web interface for monitoring and control. The `provisioner-web` service runs both the provisioner and web UI.

```bash
# Access at http://<orangepi-ip>:8080
```

### Features

- **Real-time port status** - See all 6 ports with live updates
- **Device detection** - View detected device type, model, and IP
- **Manual provisioning** - Click a port to provision with custom credentials
- **Custom passwords** - Enter non-default credentials for devices
- **History log** - View recent provisioning jobs and results
- **GitHub sync** - Manually trigger config repository sync

### Touchscreen Kiosk Mode

For a dedicated touchscreen display, the install script can configure automatic kiosk mode:

```bash
# After running the main install, setup kiosk mode
sudo ./scripts/install.sh kiosk

# Then reboot to start in kiosk mode
sudo reboot
```

This will:
- Install X11, Chromium, and Openbox window manager
- Create a dedicated `kiosk` user
- Configure auto-login on boot
- Launch Chromium fullscreen pointing to the web UI
- Disable screen blanking and cursor hiding
- Auto-restart browser if it crashes

To disable kiosk mode:
```bash
sudo ./scripts/install.sh disable-kiosk
sudo reboot
```

### Headless Mode (no web UI)

If you don't need the web interface:

```bash
sudo systemctl start provisioner
journalctl -u provisioner -f
```

### Development Mode

```bash
# Without provisioner (shows mock data)
provisioner-web --standalone --port 8080

# With provisioner
provisioner-web -c /etc/provisioner/config.yaml --port 8080
```

## Development Workflow

Since this project requires hardware (OrangePi, managed switch, network devices) for testing, use rsync to sync changes to your test device instead of committing for every test.

### Setup

1. Create a sync script (not tracked in git):

```bash
# sync-to-pi.sh
#!/bin/bash
REMOTE="user@your-pi-ip"
REMOTE_PATH="/home/user/network-provisioner"

rsync -avz --delete \
    --exclude='.git' \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='firmware/*.bin' \
    ./ "$REMOTE:$REMOTE_PATH/"
```

2. Make it executable:
```bash
chmod +x sync-to-pi.sh
```

### Development Cycle

```bash
# 1. Edit code locally (use your preferred IDE)

# 2. Sync to Pi
./sync-to-pi.sh

# 3. SSH to Pi and test
ssh user@your-pi-ip
cd network-provisioner
source .venv/bin/activate
python -m provisioner.cli test --type cambium

# 4. Repeat steps 1-3 until it works

# 5. Commit once with a meaningful message
git add -A && git commit -m "Add feature X"
```

### Tips

- Use `./sync-to-pi.sh --dry-run` to preview what will sync
- Add `sync-to-pi.sh` to `.gitignore` (it contains your Pi's IP)
- For rapid iteration, use `fswatch` or VS Code Remote SSH
- Keep commits atomic and meaningful - avoid "test", "fix", "wip" commits

## CLI Usage

```bash
# Activate the virtual environment
source /opt/provisioner/venv/bin/activate

# Scan for devices
provisioner-cli scan

# Identify a specific device
provisioner-cli identify 169.254.1.1

# Get device info
provisioner-cli info 169.254.1.1 --type cambium

# Test with mock device
provisioner-cli test --type mock
```

## Network Setup (Manual)

If you need to reconfigure the VLAN interfaces:

```bash
# Full setup with persistence
sudo /opt/provisioner/setup_network.sh setup

# Check current status
sudo /opt/provisioner/setup_network.sh status

# Quick setup (no persistence, for testing)
sudo /opt/provisioner/setup_network.sh quick

# Remove VLAN interfaces
sudo /opt/provisioner/setup_network.sh cleanup
```

## GPIO Indicators (OrangePi)

| LED | Meaning |
|-----|---------|
| Green | Provisioning complete |
| Yellow | Provisioning in progress |
| Red | Error/failure |
| Buzzer | Short beep = success, long beep = error |

Default GPIO pins (BOARD numbering): Green=7, Red=8, Yellow=9, Buzzer=10

## Notifications

Configure webhooks in `/etc/provisioner/config.yaml` or via environment variables:

```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
export DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

## Uninstall

```bash
sudo /opt/provisioner/scripts/install.sh uninstall
```

## License

MIT
