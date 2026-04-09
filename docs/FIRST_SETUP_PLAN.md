# First-Setup Plan

This plan is for the "brand new bench, brand new host" case. The installer should touch the CLI once at most, then finish everything else from the first-boot wizard and web UI.

## Goal

Target setup experience:

1. Flash a prebuilt image, or run one bootstrap command on an existing Linux host.
2. Answer a short first-boot/setup wizard for interface selection, switch setup, and fleet passwords.
3. Open the web UI and finish firmware/config seeding from `/files`.
4. Plug in one known-good device and verify the station is ready.

If a step still requires shell access after that, it should be treated as a gap to close.

## Current Setup Surfaces

The repo already has the main pieces for a low-CLI install:

- `scripts/setup.sh`: unified host install, credential prompts, switch detection, and service startup.
- `image/build.sh` + `image/first-boot.sh`: prebuilt-image path with a first-boot wizard.
- `/files` UI: upload and edit firmware, config templates, overrides, and custom credentials backed by `/var/lib/provisioner/repo`.

The main issue is not missing infrastructure. It is that the day-0 workflow is split across scripts, docs, and UI, so the installer still has to infer what is actually required before the first device can be provisioned cleanly.

## What Must Exist Before First Real Use

These are the concrete inputs a new install needs.

### 1. Host and switch baseline

- Host connected to the MikroTik trunk port.
- WAN connected if firmware should auto-download.
- Management VLAN reachable at `192.168.88.0/24`.
- Provisioning VLAN interfaces created for ports 1-6.

Current path:

- Host bootstrap: `scripts/setup.sh`
- Image path: `image/first-boot.sh`

### 2. Fleet credentials

Required for hands-off login to devices that are not using factory defaults.

- `/etc/provisioner/provisioner.env`: primary fleet passwords used by `config.yaml`.
- `/var/lib/provisioner/repo/credentials.json`: alternate credentials stored through the `/files` page.

Minimum first-setup expectation:

- Capture the common Cambium, Tarana, Tachyon, Ubiquiti, and MikroTik passwords during setup.
- Let the installer add extra fallback credentials from the UI without editing files by hand.

### 3. Config templates

Required if the station should do more than login and firmware-manage devices.

Store layout:

- `/var/lib/provisioner/repo/configs/templates/<device_type>/default.*`
- `/var/lib/provisioner/repo/configs/templates/<device_type>/ap.*`
- `/var/lib/provisioner/repo/configs/templates/<device_type>/ptp-a.*`
- `/var/lib/provisioner/repo/configs/templates/<device_type>/ptp-b.*`
- `/var/lib/provisioner/repo/configs/overrides/<device_type>/<MAC>.*`

Current repo state:

- Mode templates exist in `configs/templates/cambium/` and `configs/templates/tachyon/`.
- Those templates are not seeded automatically into `/var/lib/provisioner/repo`.
- The repo does not currently ship seeded `default.*` templates for base auto-provisioning.

Implication:

- The installer needs a clear "upload your default template now" step before expecting full zero-touch config application.

### 4. Firmware inventory

Required level depends on internet access and device vendor.

Always useful:

- Local firmware files in `/var/lib/provisioner/repo/firmware/<device_type>/`

Especially important:

- MikroTik Netinstall requires a local RouterOS package in `firmware/mikrotik/`.
- Offline or bandwidth-constrained installs should preload Cambium, Tarana, and any Ubiquiti firmware they expect to use.

Current behavior:

- Tachyon and MikroTik can auto-check and auto-download when WAN is available.
- Cambium and Ubiquiti auto-download are disabled by default.
- Filename-based discovery works even without a manifest for many cases.
- `manifest.yaml` is optional but still useful for pinning exact versions and checksums.

### 5. Optional but high-value runtime settings

- `device_settings.tarana.operator_id`
- `device_settings.mikrotik.ztp_api_url`
- `equipment_registry.url` and API key
- notification webhooks
- analytics endpoint
- GPIO disablement for non-OrangePi installs

These should not block first setup, but they should be grouped into a single "advanced settings" path instead of scattered YAML edits.

## Minimal-CLI Day-0 Workflow

This should be the recommended operator path.

### Preferred path: prebuilt image

1. Flash the image.
2. Boot the host.
3. First-boot wizard detects the interface, collects passwords, configures VLANs, and optionally configures the MikroTik switch.
4. Web UI starts automatically.
5. Installer opens `/files` and adds:
   - default config templates
   - AP/PTP templates if used
   - firmware files that should exist locally before first device plug-in
   - any extra fallback credentials
6. Installer plugs in one known-good device on port 1 and validates the full flow.

### Fallback path: existing Linux host

1. Run `sudo bash scripts/setup.sh`
2. Open the web UI
3. Finish the same `/files` seeding steps as the image path

## Work Required To Make This Smooth

### P0: make the current flow coherent

- Document the image-first workflow as the default recommendation.
- Surface `/files` as the primary first-time asset entry point.
- Stop describing the old "GitHub config repo" model as the main setup path.
- Seed bundled example templates from `configs/templates/` into `/var/lib/provisioner/repo/configs/templates/` during install or first boot.
- Add a first-run checklist in the UI that explicitly reports:
  - missing fleet passwords
  - missing default template per enabled vendor
  - missing MikroTik firmware for Netinstall
  - switch unreachable
  - WAN unavailable for auto-download workflows

### P1: reduce repeated operator work

- Add a single "setup bundle" import to `/files`:
  - credentials
  - config templates
  - overrides
  - firmware manifest
  - optional config overrides
- Add the matching export path so one known-good bench can seed the next one.
- Add readiness status to the dashboard so the station can say "not ready, missing assets" before a device is plugged in.

### P2: eliminate the last shell edits

- Add a UI page for editing the small subset of `config.yaml` values that installers commonly change.
- Add a guided advanced-settings page for registry, notifications, analytics, and vendor-specific options.
- Ship an offline firmware pack workflow for benches without reliable WAN.

## Definition Of Done

A new installer should be able to:

1. flash an image or run one bootstrap command,
2. answer a short guided setup,
3. use the web UI to load templates, firmware, and credentials,
4. provision a validation device successfully,
5. never open a shell again unless they are debugging.
