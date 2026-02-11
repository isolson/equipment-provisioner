# Screenshot Guide for README

This document specifies what screenshots are needed for the README and what they should show.

## Required Screenshots

### 1. `docs/screenshots/dashboard-overview.png`

**Location in README:** Top of "What It Does" section

**What to capture:**
- Full dashboard showing all 6 port cards
- At least 2–3 ports with devices in different states:
  - One "Ready" (green, checkmarks visible)
  - One "Provisioning" (blue, progress checklist)
  - One "Idle" (gray, no device)
- Browser window should be sized to ~1200×800
- Include the top navigation tabs (Ports / Firmware / Files)

**How to capture:**
1. Provision 2–3 devices so you have a mix of states
2. Open `http://192.168.88.10:8080/` in Chrome
3. Press F12, toggle device toolbar, select "Laptop with HiDPI screen"
4. Screenshot the full page

---

### 2. `docs/screenshots/device-detection.png`

**Location in README:** "How It Works > Device Detection" section

**What to capture:**
- Single port card showing detection in progress
- Should show:
  - Vendor badge (Cambium, Tarana, or Tachyon)
  - Model name
  - Link speed indicator (1Gbps or 100Mbps)
  - Status center showing "Detecting..." or "Booting..."
  - Partial checklist (some items checked, some in progress)

**How to capture:**
1. Plug in a device and immediately open the dashboard
2. Zoom in on one port card (crop to just that card)
3. Capture when status shows "Detecting" or "Provisioning"

---

### 3. `docs/screenshots/port-cards.png`

**Location in README:** "Web Dashboard > Real-Time Port Cards" section

**What to capture:**
- 2–3 port cards side-by-side showing variety:
  - One Cambium device (blue badge) in "Ready" state
  - One Tarana device (purple badge) in "Provisioning" state
  - One Tachyon device (green badge) in "Failed" state (if possible)
- Each card should clearly show:
  - Vendor-colored badge
  - Model text
  - Link speed
  - Status icon and text
  - Checklist items

**How to capture:**
1. Arrange 3 devices across ports 1–3
2. Screenshot just the top row of port cards (crop out empty ports)

---

### 4. `docs/screenshots/mode-config.png`

**Location in README:** "Web Dashboard > Mode Configuration" section

**What to capture:**
- Port card with the mode configuration dropdown open
- Should show:
  - "Configure Mode" button or dropdown expanded
  - Mode options: SM (default), AP, PTP-A, PTP-B
  - Tower number input fields (if modal/panel is open)
  - Example: setting a device to AP mode with tower "05"

**How to capture:**
1. Click "Configure Mode" on a provisioned device
2. Fill in tower number (e.g., "05")
3. Screenshot the card or modal before submitting

---

### 5. `docs/screenshots/firmware-page.png`

**Location in README:** "Firmware Management" section

**What to capture:**
- `/firmware` page showing:
  - List of available firmware versions per vendor
  - At least one cached firmware file (green checkmark or "Cached" badge)
  - One firmware file downloading (progress bar if available)
  - File sizes and dates
- Include the page navigation showing "Ports / **Firmware** / Files"

**How to capture:**
1. Navigate to `http://192.168.88.10:8080/firmware`
2. If no downloads in progress, manually trigger one via API:
   ```bash
   curl -X POST http://192.168.88.10:8080/api/firmware/download \
     -H "Content-Type: application/json" \
     -d '{"vendor": "cambium", "model": "force_300_25"}'
   ```
3. Screenshot the full page

---

## Screenshot Specifications

### Dimensions
- **Full dashboard:** 1200×800 minimum
- **Port card closeup:** 400×300 minimum
- **Firmware page:** 1200×800 minimum

### Format
- PNG format, 72 DPI
- No browser chrome (address bar, bookmarks, etc.) unless showing full context

### Editing
- Blur or redact any:
  - Device MAC addresses
  - Serial numbers
  - Internal IP addresses (except `192.168.88.x` which is example range)
  - Passwords or credentials in console output

### Naming
- Use kebab-case: `dashboard-overview.png`, not `Dashboard_Overview.PNG`
- Store in `docs/screenshots/`

---

## Optional Screenshots (Nice to Have)

### 6. `docs/screenshots/checklist-detail.png`

**What to capture:**
- Zoomed-in view of a port card's checklist showing:
  - ✓ Login successful
  - ✓ Model confirmed: Force 300-25
  - ✓ Config applied
  - 🔄 Firmware downloading (50%)
  - ⏳ Firmware installing...

### 7. `docs/screenshots/failed-state.png`

**What to capture:**
- Port card showing "Failed" state with error message
- Hover tooltip or error detail visible

### 8. `docs/screenshots/touchscreen-view.png`

**What to capture:**
- Photo (not screenshot) of the provisioner running on a 7" Pi touchscreen
- Shows the physical hardware setup (Pi + touchscreen + switch)

### 9. `docs/screenshots/websocket-live-update.gif`

**What to capture:**
- Animated GIF showing:
  1. Port card in "Idle" state
  2. Device plugged in (card updates to "Booting")
  3. Detection phase (card updates to "Provisioning")
  4. Completion (card updates to "Ready")
- 5–10 seconds total, 800×600 resolution

---

## How to Take Screenshots

### macOS
- **Full screen:** `Cmd + Shift + 3`
- **Selection:** `Cmd + Shift + 4`
- **Window:** `Cmd + Shift + 4`, then press `Space`, click window

### Linux
- **Full screen:** `gnome-screenshot` or `scrot`
- **Selection:** `gnome-screenshot -a` or `scrot -s`

### Windows
- **Full screen:** `Win + PrtScn`
- **Selection:** `Win + Shift + S` (Snipping Tool)

### Browser DevTools
1. Open Chrome DevTools (F12)
2. Press `Cmd/Ctrl + Shift + P`
3. Type "screenshot"
4. Select "Capture full size screenshot"

---

## Mockups (If Real Screenshots Not Available)

If you don't have the hardware setup yet, you can create mockups:

1. Use Figma or Sketch to design the UI based on `provisioner/web/templates/index.html`
2. Match the Tailwind CSS styling (colors, fonts, spacing)
3. Show realistic data:
   - Vendor: Cambium, Tarana, Tachyon (not "Generic Vendor")
   - Models: Force 300-25, G1, T307 (not "Model XYZ")
   - Status: Use actual state names from code (Provisioning, Ready, Failed)

Mark mockups with a small "Mockup" watermark in the corner to avoid confusion.
