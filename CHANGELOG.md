# Changelog

All notable changes to the Equipment Auto-Provisioner are documented here. Entries are ordered newest-first.

## 2026-01-28

**Cambium model/firmware improvements, reboot notifications, AP config, UI credentials**
- Improved Cambium model detection and firmware version parsing
- Added reboot progress notifications to the UI
- AP config support for Cambium devices
- UI credentials management page for setting per-vendor passwords

## 2026-01-27

**Fix Tarana SetPackage proto fields, add protocol reference doc**
- Fixed incorrect protobuf field definitions in Tarana `SetPackage` RPC
- Added `docs/tarana-protocol.md` documenting gRPC-Web and gNOI protocol details

**Cambium reboot cookie fix, SKU 49 mapping, boot-up check, UI contrast**
- Fixed Cambium session cookie loss during reboot wait cycle
- Added SKU 49 model mapping for ePMP devices
- Added boot-up readiness check before post-reboot login
- Improved UI contrast for outdoor readability

## 2026-01-26

**Fix COMPLETE state reverting to READY after provisioning**
- Fixed race condition where completed port state was overwritten by detection loop

**Verify config read-back, fix verify_config delay, improve activity log**
- Added config verification by reading back applied values from the device
- Fixed timing issue in verify_config that caused false failures
- Improved activity log formatting in the UI modal

## 2026-01-25

**Redesign port card UI: status-focused cards, activity log modal**
- Replaced table-based UI with card-based port status display
- Added activity log modal with step-by-step provisioning detail
- Device summary grid showing MAC, serial, firmware banks

**Remove GitHub sync, add light mode UI, fix Tachyon password hash bug**
- Removed automatic GitHub repo sync (configs managed locally or via upload)
- Added light mode UI theme
- Fixed Tachyon handler sending hashed password instead of plaintext

## 2026-01-24

**Fix provisioning: Cambium config_import, Tachyon auth, verify flow**
- Fixed Cambium config apply to use `config_import` multipart upload instead of `set_param`
- Fixed Tachyon authentication cookie handling
- Fixed post-provisioning verify flow to reconnect before checking

**Tarana gRPC-web rewrite, firmware fixes, Tachyon config API fix**
- Rewrote Tarana handler to use gRPC-Web protocol directly (no grpclib dependency)
- Fixed firmware upload streaming for Tarana devices
- Fixed Tachyon config API endpoint path

## 2026-01-23

**Skip firmware upload when version matches after re-lookup**
- Added firmware version re-check after login to avoid unnecessary uploads

**Fix firmware verification for Tachyon auto-reboot devices**
- Handle Tachyon devices that reboot automatically after firmware flash

**Increase firmware upgrade wait time to 10 minutes**
- Extended reboot timeout for devices with slow firmware flash cycles

**Fix Cambium reconnect during firmware upgrade and add firmware re-lookup**
- Fixed session loss when Cambium device drops connection during firmware write
- Added firmware bank re-lookup after reconnect

**Fix Cambium firmware upload and add Tachyon model validation**
- Fixed Cambium firmware multipart upload format
- Added model string validation for Tachyon to reject unknown SKUs

## 2026-01-22

**Add display sleep/wake functionality for kiosk mode**
- Display auto-sleep after idle timeout
- Wake on touch or device connect event
- DPMS and sysfs backlight support

## 2026-01-21

**Network Device Auto-Provisioner**
- Initial commit with full provisioning system
- Handlers: Cambium ePMP, Tarana G1, Tachyon 30x, MikroTik RouterOS
- Web UI with real-time WebSocket updates
- VLAN-based multi-port isolation
- Firmware dual-bank update support
- GPIO LED/buzzer indicators
- CLI tools for manual provisioning and diagnostics
- Installation and network setup scripts
- Systemd service files
