# Equipment Auto-Provisioner

Automated provisioning for network radios. Plug in a device, it gets detected, configured, firmware-updated, and marked ready — no manual interaction needed after setup.

Designed for a Raspberry Pi (or OrangePi) with a 7" touchscreen and an 8-port MikroTik switch as a dedicated bench provisioning station. Provisions up to six devices simultaneously.

Any Linux machine will work as the host — the touchscreen and Pi are just the intended form factor.

## What it does

1. Plug a factory-default radio into any open port
2. System detects it, identifies the vendor and model
3. Applies configuration from your templates, updates firmware if needed
4. Shows status in the web UI

## What you need

- **A Linux host** — Raspberry Pi, OrangePi, or any dedicated Linux machine. Designed for a Pi with a 7" touchscreen attached, but headless works fine too.
- **A MikroTik 8-port switch running RouterOS** — We use the [CRS112-8G-4S](https://mikrotik.com/product/CRS112-8G-4S-IN) but any 8+ port RouterOS switch works (e.g. CRS310-8G+2S+). Must be RouterOS, not SwOS.
- **Ethernet cables**

## Setup

```bash
curl -sSL https://raw.githubusercontent.com/isolson/equipment-provisioner/main/scripts/bootstrap.sh | sudo bash
```

The setup script walks you through everything:
- Installs dependencies
- Collects device passwords
- Waits for you to plug in the MikroTik switch, then auto-configures it
- Starts the web UI

Or clone and run manually:

```bash
git clone https://github.com/isolson/equipment-provisioner.git /opt/provisioner
cd /opt/provisioner
sudo bash scripts/setup.sh
```

## Supported devices

| Vendor | Models | What gets provisioned |
|--------|--------|----------------------|
| **Cambium ePMP** | Force 300, Force 400, etc. | Config, firmware, AP/PTP/SM modes |
| **Tarana** | G1 | Config, firmware |
| **Tachyon** | 30x series | Config, firmware, AP/PTP/SM modes |

## Web UI

Real-time dashboard at `http://<your-host>:8080` showing all six ports with live status updates. Works on a phone, laptop, or the attached touchscreen.

After provisioning, you can reconfigure devices as **AP** or **PTP** from the UI — enter a tower number and direction, and the system sets hostnames, SSIDs, and vendor-specific config.

## Port layout

```
Port 1-6    Provisioning (one device each, isolated VLANs)
Port 7      WAN / Internet from your router
Port 8      Trunk to Pi / host
```

## How it saves time

| Without provisioner | With provisioner |
|---------------------|-----------------|
| Open browser, find device IP, log in | Plug in cable |
| Find correct firmware, upload, wait, verify | Automatic |
| Type config values from a spreadsheet | Template-based, zero typing |
| Repeat for next device | Next port is already working on one |
| One device at a time | Six at once |

## TODO

- Slack/Discord webhook notifications (plumbed but not tested)
- MikroTik device provisioning (switch config works, device provisioning not yet)
- Persistent PTP link tracking across service restarts

## Documentation

- [API Reference](docs/API.md) — REST endpoints for automation and integration
- [Troubleshooting](docs/TROUBLESHOOTING.md) — Common issues and fixes
- [Scripts Reference](scripts/README.md) — Setup, install, and switch config scripts
- [Changelog](CHANGELOG.md) — Release history

## License

MIT
