# Network Equipment Auto-Provisioner

**Zero-touch provisioning for wireless radios.** Plug in a factory-default device, walk away. The system detects it, configures it, updates firmware, and marks it ready—all automatically.

Built for network operators who provision dozens or hundreds of devices. Works with Cambium, Tarana, and Tachyon radios. Provisions up to 6 devices simultaneously.

---

## What It Does

![Dashboard Overview](docs/screenshots/dashboard-overview.png)
*Main dashboard showing 6 ports with real-time status*

1. **Detect** — Plug in a factory-default radio. The system identifies vendor and model via fingerprinting.
2. **Configure** — Applies your configuration templates (management IPs, passwords, SSIDs, etc.)
3. **Update** — Downloads and installs the correct firmware version if needed
4. **Verify** — Confirms the device is accessible and ready to deploy

All status updates appear in real-time on the web dashboard. No manual steps after initial setup.

---

## Hardware Requirements

### The Provisioning Station

This system is designed to run on a dedicated Linux machine with an attached MikroTik switch:

- **Host Computer** — Raspberry Pi 3B+ or better, OrangePi 3 LTS, or any Linux x86_64 machine
  - Optional: 7" touchscreen for bench-top use (designed for 1024×600 displays)
  - Minimum: 1GB RAM, 8GB storage

- **Network Switch** — MikroTik 8-port RouterOS switch
  - Tested: [CRS112-8G-4S-IN](https://mikrotik.com/product/CRS112-8G-4S-IN), [CRS310-8G+2S+IN](https://mikrotik.com/product/crs310_8g_2s_in)
  - Must run **RouterOS** (not SwOS) — the system auto-configures it via API

- **Cables** — Ethernet cables to connect devices

### Port Layout

```
Port 1–6    Device provisioning (isolated VLANs, PoE if supported)
Port 7      WAN / Internet (for firmware downloads)
Port 8      Trunk to host computer (all VLANs + management)
```

The switch provides PoE to devices on ports 1–6 if your switch model supports it. Each port is isolated in its own VLAN so devices can't interfere with each other during provisioning.

---

## Quick Start

### One-Command Setup

```bash
curl -sSL https://raw.githubusercontent.com/isolson/network-provisioner/main/scripts/bootstrap.sh | sudo bash
```

The bootstrap script:
1. Installs dependencies (Python 3.9+, `arping`, `RouterOS API`, etc.)
2. Collects device passwords from you interactively
3. Waits for you to plug in the MikroTik switch
4. Auto-configures the switch (VLANs, trunk, webhook callbacks)
5. Starts the provisioner web service
6. Opens the dashboard at `http://<your-host>:8080`

### Manual Installation

If you prefer to review the code first:

```bash
git clone https://github.com/isolson/network-provisioner.git /opt/provisioner
cd /opt/provisioner
sudo bash scripts/setup.sh
```

---

## How It Works

### Device Detection

When you plug a device into ports 1–6:

1. **Link detection** — The MikroTik switch sends a webhook when it sees Ethernet link-up
2. **ARP probing** — The system probes known factory-default IPs:
   - `169.254.1.1` (Cambium, Tachyon)
   - `192.168.1.20` (Ubiquiti Wave/AirMax)
   - `192.168.88.1` (MikroTik)
   - `169.254.100.1` (Tarana)
3. **Fingerprinting** — HTTP requests identify the vendor and model
4. **Provisioning** — The appropriate handler logs in, applies config, and updates firmware

![Device Detection Flow](docs/screenshots/device-detection.png)
*Port card showing live detection and fingerprinting progress*

### VLAN Isolation

Each port uses its own provisioning VLAN:

| Port | VLAN | Subnet |
|------|------|--------|
| 1 | 1991 | `169.254.1.0/24` |
| 2 | 1992 | `169.254.1.0/24` |
| 3 | 1993 | `169.254.1.0/24` |
| ... | ... | ... |
| 6 | 1996 | `169.254.1.0/24` |

Management VLAN 1990 (`192.168.88.0/24`) is for switch-to-host communication only.

This isolation prevents devices from seeing each other during provisioning, which matters for devices that broadcast DHCP requests or have default IPs that conflict.

---

## Web Dashboard

### Real-Time Port Cards

![Port Cards](docs/screenshots/port-cards.png)
*Each port shows vendor, model, link speed, and provisioning progress*

The dashboard updates live via WebSocket. No page refresh needed. Each port card shows:

- **Vendor badge** — Color-coded by manufacturer
- **Model name** — Detected via fingerprint
- **Link speed** — 1Gbps, 100Mbps, or blank if no link
- **Status center** — Large icon + text showing current state:
  - 🔵 **Detecting** — Probing for device
  - 🟡 **Booting** — Waiting for device to finish boot
  - 🔵 **Provisioning** — Logging in, configuring, updating firmware
  - 🟢 **Ready** — Device is configured and accessible
  - 🔴 **Failed** — Provisioning error (hover for details)
- **Checklist** — Step-by-step progress (login ✓, config ✓, firmware ✓, etc.)

### Mode Configuration

![Mode Configuration](docs/screenshots/mode-config.png)
*Reconfigure devices as AP or PTP after initial provisioning*

After a device is provisioned, you can set its operational mode:

- **Subscriber Module (SM)** — Default, no extra config
- **Access Point (AP)** — Enter tower number, system sets hostname + SSID
- **Point-to-Point (PTP)** — Enter tower numbers for both ends, system names them `tw05-tw12-a` / `tw05-tw12-b`

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

## Time Savings

**Traditional manual provisioning:**
1. Find device on network (DHCP lease or factory default IP)
2. Open web browser, navigate to device
3. Log in with default credentials
4. Change password
5. Set management IP
6. Find correct firmware on vendor's website
7. Upload firmware, wait 5–10 minutes
8. Verify device rebooted correctly
9. Log back in
10. Apply configuration template
11. Label device with hostname

**With auto-provisioner:**
1. Plug in device
2. Wait (system does steps 1–11 automatically)
3. Unplug when card shows "Ready"

**Throughput:**
- Manual: ~15–20 minutes per device (serial, one at a time)
- Auto: ~10 minutes per device, but 6 devices run in parallel → **6 devices in 10 minutes instead of 90–120 minutes**

---

## Firmware Management

![Firmware Page](docs/screenshots/firmware-page.png)
*Firmware library showing available versions and download status*

The firmware page at `http://<host>:8080/firmware` shows:

- **Available firmware** — All versions defined in `firmware.yaml`
- **Local cache** — Firmware files already downloaded to `/opt/provisioner/firmware/`
- **Download status** — In-progress downloads with progress bars
- **Manual download** — Download firmware ahead of time to avoid delays during provisioning

Firmware files are cached locally. The first device of each model will trigger a download (~50–200MB), but subsequent devices use the cached copy.

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

1. **Check link speed** — Should show "1Gbps" or "100Mbps" in the port card
   - If blank, check cable and device power
2. **Check factory defaults** — Device must be at factory default IP
   - Cambium/Tachyon: `169.254.1.1`
   - Tarana: `169.254.100.1`
   - MikroTik: `192.168.88.1`
3. **Check logs** — `journalctl -u provisioner-web -f`

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

- **Port Manager** (`provisioner/port_manager.py`) — Core state machine, device detection, boot wait logic
- **Switch Listener** (`provisioner/switch_listener.py`) — RouterOS API client, listens for link up/down webhooks
- **Device Handlers** (`provisioner/handlers/`) — Vendor-specific provisioning logic (Cambium, Tarana, Tachyon)
- **Firmware Manager** (`provisioner/firmware.py`) — Downloads and caches firmware files
- **Web API** (`provisioner/web/api.py`) — FastAPI server, WebSocket broadcaster
- **Web UI** (`provisioner/web/templates/`) — Tailwind CSS dashboard, vanilla JavaScript

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

1. **Idle** — No device detected
2. **Boot Wait** — Link detected, waiting for device to finish booting (120s max)
3. **Detecting** — ARP probing and HTTP fingerprinting
4. **Provisioning** — Handler is running (login → config → firmware → verify)
5. **Ready** — Provisioning complete, device accessible
6. **Failed** — Error occurred, see `last_error` in port state

The state machine handles:
- Link flapping during autonegotiation
- Device reboots (firmware updates)
- Stale state cleanup (ping failure detection)
- Concurrent provisioning across ports

---

## Development

### Local Setup

```bash
git clone https://github.com/isolson/network-provisioner.git
cd network-provisioner
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

Feedback and bug reports: [GitHub Issues](https://github.com/isolson/network-provisioner/issues)
