# Network Equipment Auto-Provisioner

**Plug in a radio. Walk away. It provisions itself automatically.**

This system automatically detects, configures, and updates firmware on wireless radios. Works with Cambium, Tarana, and Tachyon radios. Provisions up to 6 devices at the same time.

---

## What It Does

![Dashboard Overview](docs/screenshots/dashboard-overview.png)
*Main dashboard showing 6 ports with real-time status*

1. **Detects**: Plug in a factory-default radio. The system figures out what it is automatically.
2. **Configures**: Applies your settings (management IPs, passwords, SSIDs, etc.)
3. **Updates**: Installs the correct firmware version if it’s out of date
4. **Marks ready**: Shows a green "Ready" indicator when the device is done

All status updates appear live on the web dashboard. No manual steps after initial setup.

---

## What You’ll Need

### Shopping List

| Item | Recommended Model | Est. Cost | Notes |
|------|-------------------|-----------|-------|
| **Host computer** | Lenovo ThinkPad Yoga 11e | ~$80 used | Best all-around: x86, touchscreen, auto-rotates. Find on eBay/Amazon. |
| **Switch** | MikroTik [CRS112-8P-4S-IN](https://mikrotik.com/product/CRS112-8P-4S-IN) | ~$200 | PoE-out on all 8 ports: powers devices through the cable. Script configures it automatically. |
| **Ethernet cables** | Cat5e or better, 1–3 ft | ~$10/pack | Short cables keep the bench tidy. |
| **Internet connection** | Any broadband | - | Needed for firmware downloads. Can preload offline if needed. |

**Other compatible host computers** (if you can’t find the ThinkPad): Dell OptiPlex 3050, Dell Wyse 5070, HP EliteDesk 800 G2. Any x86 Linux machine works. Raspberry Pi 4 also works but can’t run MikroTik Netinstall.

> **What does the switch do?** It gives each device plugged in its own isolated lane: so 6 devices can provision at once without interfering with each other. It also powers devices through the Ethernet cable if your switch model supports it (PoE). **You don’t need to configure the switch yourself: the setup script does it automatically.**

### Cable Layout

```
Your devices (up to 6)
  └─ Ports 1–6:   Plug your radios here (switch powers them via PoE)

Internet/router
  └─ Port 7:      Plug your internet connection here (for firmware downloads)

Host computer
  └─ Port 8:      One cable from switch to your laptop/PC
```

---

## Setup (Step-by-Step)

### Step 1: Install Linux on the host computer

If you’re using the recommended ThinkPad Yoga 11e, install **Ubuntu 22.04 LTS** (64-bit). The [Ubuntu installation guide](https://ubuntu.com/tutorials/install-ubuntu-desktop) walks through it. Any Debian/Ubuntu-based Linux works.

Once installed, open a terminal (Ctrl+Alt+T) and proceed to Step 2.

### Step 2: Connect the cables

1. Connect the MikroTik switch to power
2. Plug an Ethernet cable from **switch port 8** to the host computer’s Ethernet port
3. Plug your internet connection into **switch port 7**
4. Don’t plug any radios in yet: do that after setup is complete

### Step 3: Run the setup script

In the terminal on your host computer, run this single command:

```bash
curl -sSL https://raw.githubusercontent.com/isolson/equipment-provisioner/main/scripts/bootstrap.sh | sudo bash
```

This downloads and runs the setup script. It will:
1. Install the software and its dependencies
2. Ask you for your device passwords (the current admin password on your Cambium/Tarana/Tachyon devices: usually `admin` if they’re factory default)
3. Detect the MikroTik switch automatically when you plug it in
4. Configure the switch (VLANs, port assignments, PoE: all automatic)
5. Start the provisioner service

**Expected output when done:**
```
✓ Provisioner installed
✓ Switch configured
✓ Service started

Dashboard: http://192.168.88.10:8080
```

> If you prefer to review the code before running it: `git clone -b production https://github.com/isolson/equipment-provisioner.git /opt/provisioner && sudo bash /opt/provisioner/scripts/setup.sh`

### Step 4: Finish setup in the browser

1. Open `http://192.168.88.10:8080` in a browser on the host computer
   - You should see the dashboard with 6 empty port cards
2. Click the **Setup** tab (or follow the banner if it appears)
3. Work through the readiness checklist:
   - **Credentials**: Confirm your device passwords are entered
   - **Config templates**: Upload your configuration templates (or use the bundled defaults)
   - **Firmware**: Pre-download firmware for your device types (optional: it can download on demand if you have internet)
4. The Setup tab will also verify your switch is wired correctly

> If you’re migrating from an existing provisioning bench, you can export its setup bundle and import it here to skip most of this.

### Step 5: Provision your first device

1. Plug a factory-default radio into **port 1** of the switch
2. Watch the port card on the dashboard: it will progress through:
   - **Detecting** (identifying what device it is)
   - **Provisioning** (logging in, configuring, updating firmware)
   - **Ready** (done: green indicator)
3. The system handles everything automatically: watch the checklist fill in as it goes

**What success looks like:** The port card turns green with a checkmark and shows "Ready". The checklist on the right shows all steps complete (Login ✓, Config ✓, Firmware ✓, Verify ✓).

---

## When Something Goes Wrong

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Port card stays blank after plugging in | Cable or device power issue | Check cable is fully seated; check device has power |
| "Detecting" runs for more than 2 minutes | Device isn’t at factory defaults | Factory reset the device first |
| "Provisioning" fails with "connection timeout" | No internet for firmware download | Check port 7 has internet; or preload firmware in the Setup tab |
| Dashboard doesn’t load | Service not running | Run `sudo systemctl status provisioner-web` in the terminal |
| Switch not found during setup | Switch not yet booted | Wait 30 seconds and try again; switch takes ~20s to boot |

For more detailed troubleshooting, see [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

---

## How It Works

### Device Detection

When you plug a device into ports 1–6:

1. **Link detection**: The MikroTik switch sends a webhook when it sees Ethernet link-up
2. **ARP probing**: The system probes known factory-default IPs:
   - `169.254.1.1` (Cambium, Tachyon)
   - `192.168.1.20` (Ubiquiti Wave/AirMax)
   - `192.168.88.1` (MikroTik)
   - `169.254.100.1` (Tarana)
3. **Fingerprinting**: HTTP requests identify the vendor and model
4. **Provisioning**: The appropriate handler logs in, applies config, and updates firmware

![Device Detection Flow](docs/screenshots/device-detection.png)
*Port card showing live detection and fingerprinting progress*

### Port Isolation

Each of the 6 provisioning ports runs on its own isolated network segment. This means:

- Devices can't see each other, even though they share a switch
- Multiple devices with the same factory-default IP can provision simultaneously without conflict
- A failed or misbehaving device on one port can't affect others

This is handled automatically by the switch configuration: no manual network setup required.

<details>
<summary>Technical details (VLAN IDs and subnets)</summary>

| Port | VLAN | Subnet |
|------|------|--------|
| 1 | 1991 | `169.254.1.0/24` |
| 2 | 1992 | `169.254.1.0/24` |
| 3 | 1993 | `169.254.1.0/24` |
| ... | ... | ... |
| 6 | 1996 | `169.254.1.0/24` |

Management VLAN 1990 (`192.168.88.0/24`) is for switch-to-host communication only.

</details>

---

## Web Dashboard

### Real-Time Port Cards

![Port Cards](docs/screenshots/port-cards.png)
*Each port shows vendor, model, link speed, and provisioning progress*

The dashboard updates live via WebSocket. No page refresh needed. Each port card shows:

- **Vendor badge**: Color-coded by manufacturer
- **Model name**: Detected via fingerprint
- **Link speed**: 1Gbps, 100Mbps, or blank if no link
- **Status center**: Large icon + text showing current state:
  - 🔵 **Detecting**: Probing for device
  - 🟡 **Booting**: Waiting for device to finish boot
  - 🔵 **Provisioning**: Logging in, configuring, updating firmware
  - 🟢 **Ready**: Device is configured and accessible
  - 🔴 **Failed**: Provisioning error (hover for details)
- **Checklist**: Step-by-step progress (login ✓, config ✓, firmware ✓, etc.)

### Mode Configuration

![Mode Configuration](docs/screenshots/mode-config.png)
*Reconfigure devices as AP or PTP after initial provisioning*

After a device is provisioned, you can set its operational mode:

- **Subscriber Module (SM)**: Default, no extra config
- **Access Point (AP)**: Enter tower number, system sets hostname + SSID
- **Point-to-Point (PTP)**: Enter tower numbers for both ends, system names them `tw05-tw12-a` / `tw05-tw12-b`

The mode configuration applies immediately. No need to unplug and re-provision.

---

## Supported Devices

### Cambium ePMP

| Model | Config | Firmware | Modes |
|-------|--------|----------|-------|
| Force 300-25 | ✓ | ✓ | SM, AP, PTP |
| Force 400 | ✓ | ✓ | SM, AP, PTP |
| Force 425 | ✓ | ✓ | SM, AP, PTP |
| Force 4600 | ✓ | ✓ | AP only |

**What gets configured:**
- Management IP: `192.168.88.10` (static, VLAN 1990)
- Admin password from your config
- SNMP community string
- Hostname based on mode (e.g., `tw05-sm-abc123`, `tw05-tw12-a`)
- Firmware upgraded to latest stable version

### Tarana

| Model | Config | Firmware | Modes |
|-------|--------|----------|-------|
| G1 (BN, RN) | ✓ | ✓ | Auto-detected |

**What gets configured:**
- Management IP: `192.168.88.10`
- Admin password
- Firmware upgraded if needed

### Tachyon

| Model | Config | Firmware | Modes |
|-------|--------|----------|-------|
| 30x series | ✓ | ✓ | SM, AP, PTP |

**What gets configured:**
- Management IP: `192.168.88.10`
- Admin credentials
- Mode-specific hostnames and SSIDs
- Firmware upgraded to your target version

---

## Configuration Files

The system reads templates from `/opt/provisioner/config/`:

### `config.yaml`

Main configuration file:

```yaml
management:
  ip: 192.168.88.10        # Host IP on management VLAN
  netmask: 255.255.255.0
  vlan: 1990               # Management VLAN ID
  switch_ip: 192.168.88.1  # MikroTik switch IP

ports:
  count: 6                 # How many ports to use (1-6)

credentials:
  cambium:
    username: admin
    password: your-password-here
  tarana:
    username: admin
    password: your-password-here
  tachyon:
    username: admin
    password: your-password-here

firmware:
  auto_update: true        # Auto-update to latest firmware
  download_timeout: 300    # Seconds to wait for downloads

display:
  # 0 = let native X DPMS (configured in the kiosk autostart, 2 min blank /
  # 5 min off) handle idle. Touch wakes via libinput, device-connect wakes
  # via the controller below. Set >0 to enable the older JS "no-devices-
  # for-N-seconds" backlight sleep (it doesn't track user input, so most
  # kiosks should leave this at 0).
  sleep_timeout: 0
  wake_on_connect: true    # Wake the screen when a device is plugged in
  use_dpms: true           # X DPMS via `sudo -u kiosk env DISPLAY=:0 xset`
  use_backlight: true      # sysfs backlight fallback (and complement to DPMS)
```

### `firmware.yaml`

Firmware version mappings:

```yaml
cambium:
  force_300_25: "4.7.2"
  force_400c: "4.7.2"

tarana:
  g1: "8.0.1-2024-11"

tachyon:
  t307: "2.1.5"
```

The system automatically downloads firmware from vendor CDNs if needed.

---

## Firmware Management

![Firmware Page](docs/screenshots/firmware-page.png)
*Firmware library showing available versions and download status*

The management UI at `http://<host>:8080/files` lets you seed first-run assets without shell access:

- **Available firmware**: Files already stored under `/var/lib/provisioner/repo/firmware/`
- **Config templates**: Upload/edit templates under `/var/lib/provisioner/repo/configs/`
- **Custom credentials**: Add fallback usernames/passwords stored in `credentials.json`
- **Manual upload or URL download**: Seed the bench ahead of time to avoid delays during provisioning

Firmware files are cached locally. Tachyon and MikroTik can auto-download when WAN access is available; for offline benches or slower links, preload the firmware you expect to use before the first provisioning run.

---

## API Integration

The provisioner exposes a REST API for automation and integration with other tools.

### Get Port Status

```bash
curl http://192.168.88.10:8080/api/ports
```

Response:

```json
[
  {
    "port_number": 2,
    "vlan_id": 1992,
    "link_up": true,
    "link_speed": "1Gbps",
    "device_detected": true,
    "device_type": "cambium",
    "device_model": "Force 300-25",
    "provisioning": false,
    "last_activity": "2026-02-09T18:30:51Z"
  }
]
```

### Manual Provision

Force provisioning on a specific port:

```bash
curl -X POST http://192.168.88.10:8080/api/provision \
  -H "Content-Type: application/json" \
  -d '{"port_number": 2}'
```

### WebSocket for Live Updates

```javascript
const ws = new WebSocket('ws://192.168.88.10:8080/ws');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Port', data.port_number, 'status:', data);
};
```

See [API.md](docs/API.md) for complete endpoint documentation.

---

## Troubleshooting

### Device not detected

1. **Check link speed**: Should show "1Gbps" or "100Mbps" in the port card
   - If blank, check cable and device power
2. **Check factory defaults**: Device must be at factory default IP
   - Cambium/Tachyon: `169.254.1.1`
   - Tarana: `169.254.100.1`
   - MikroTik: `192.168.88.1`
3. **Check logs**: `journalctl -u provisioner-web -f`

### Provisioning fails with "connection timeout"

- Device might not have internet access for firmware downloads
- Check port 7 (WAN) has internet connectivity
- Run `ping 8.8.8.8` from the host

### Switch not responding

- Ensure switch IP is `192.168.88.1` on VLAN 1990
- Check `/opt/provisioner/config/config.yaml` for correct `switch_ip`
- Verify trunk port (port 8) is configured correctly:
  ```bash
  /interface/bridge/vlan print
  ```

### "ARP probe miss" spam in logs

- This is normal for empty ports
- After deploying the latest version, these are logged at DEBUG level (not visible by default)

See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for more issues and solutions.

---

## Architecture

### Components

- **Port Manager** (`provisioner/port_manager.py`): Core state machine, device detection, boot wait logic
- **Switch Listener** (`provisioner/switch_listener.py`): RouterOS API client, listens for link up/down webhooks
- **Device Handlers** (`provisioner/handlers/`): Vendor-specific provisioning logic (Cambium, Tarana, Tachyon)
- **Firmware Manager** (`provisioner/firmware.py`): Downloads and caches firmware files
- **Web API** (`provisioner/web/api.py`): FastAPI server, WebSocket broadcaster
- **Web UI** (`provisioner/web/templates/`): Tailwind CSS dashboard, vanilla JavaScript

### Network Flow

```
Device (port 1-6)
  ↓ Ethernet link-up
MikroTik Switch (RouterOS)
  ↓ HTTP POST webhook to 192.168.88.10:8080/api/switch/port-event
Provisioner (port_manager.py)
  ↓ ARP probe on eth0.199x (VLAN 1991-1996)
  ↓ HTTP fingerprint request
  ↓ Provision via device handler
  ↓ Firmware download from vendor CDN (if needed)
  ↓ SSH/HTTP commands to device
Device configured ✓
```

### State Machine

Each port goes through these states:

1. **Idle**: No device detected
2. **Boot Wait**: Link detected, waiting for device to finish booting (120s max)
3. **Detecting**: ARP probing and HTTP fingerprinting
4. **Provisioning**: Handler is running (login → config → firmware → verify)
5. **Ready**: Provisioning complete, device accessible
6. **Failed**: Error occurred, see `last_error` in port state

The state machine handles:
- Link flapping during autonegotiation
- Device reboots (firmware updates)
- Stale state cleanup (ping failure detection)
- Concurrent provisioning across ports

---

## Development

### Local Setup

```bash
git clone https://github.com/isolson/equipment-provisioner.git
cd equipment-provisioner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run Tests

```bash
pytest tests/ -v
```

Current test coverage:
- Port manager state transitions (boot wait, link flaps, ping disconnect)
- MikroTik ARP detection invariants
- API response completeness

### Deploy to Remote Host

```bash
bash scripts/deploy.sh
```

The deploy script:
1. Rsyncs code to the target host (defined in script)
2. Restarts the systemd service
3. Shows service status

### Add a New Device Type

1. Create a handler in `provisioner/handlers/new_vendor.py`:

```python
from .base import BaseDeviceHandler

class NewVendorHandler(BaseDeviceHandler):
    async def provision(self, device_info):
        # Your provisioning logic here
        pass
```

2. Register it in `provisioner/handler_manager.py`
3. Add default IP to `DeviceLinkLocalIP` in `port_manager.py`
4. Add firmware mappings to `firmware.yaml`

---

## Roadmap

### In Progress

- [ ] Persistent PTP link tracking across restarts
- [ ] Slack/Discord webhook notifications
- [ ] MikroTik device provisioning (switch config works, device provisioning not yet)

### Planned

- [ ] TFTP boot server for devices that support netboot
- [ ] CSV import for bulk device naming
- [ ] Historical provisioning stats (devices/hour, failure rate)
- [ ] Mobile app for scanning device labels

---

## Contributing

Contributions welcome. Open an issue first to discuss major changes.

### Testing Locally

If you don't have the hardware setup:
1. Mock the switch listener (see `tests/` for examples)
2. Use `curl` to POST fake webhook events:
   ```bash
   curl -X POST http://localhost:8080/api/switch/port-event \
     -H "Content-Type: application/json" \
     -d '{"port": "ether2", "link_up": true, "speed": "1Gbps"}'
   ```
3. The UI will show state changes as if a real device was plugged in

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Credits

Built by Isaac Olson for network operators who provision too many radios by hand.

Feedback and bug reports: [GitHub Issues](https://github.com/isolson/equipment-provisioner/issues)
