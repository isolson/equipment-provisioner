# MikroTik Netinstall + Auto-Provisioning

Bottom line: a tech only needs to put the router into Netinstall mode on a
provisioner port. The provisioner flashes RouterOS with both the Netinstall
Mode script and the served Netinstall Configure script, verifies the router can
phone home after it is moved to internet, then registers it with WiFi.

How the provisioner detects a MikroTik device entering BOOTP/Netinstall mode,
flashes it via `netinstall-cli`, applies the served Configure script, and hands
the device off ready for customer config.

## Field-tech workflow

1. Plug the MikroTik into any of the six numbered ports on the provisioner
   switch.
2. Press and hold the device's reset button while applying power. Continue
   holding for ~20 seconds, until the power LED goes off (model-dependent
   indicator that the device has entered BOOTP listening mode).
3. Release the reset button.
4. Walk away. The provisioner detects the BOOTP request, runs the full
   Netinstall + Configure-script pipeline, and reports completion on the
   touchscreen.

The orange "Netinstall" button in the touchscreen UI remains as a manual
override / debug control but is not part of the normal happy path.

## End-to-end pipeline

```
                       ┌─────────────────────────────────────────────────┐
                       │  per-port BOOTP listener (always running)       │
                       │  fingerprint.sniff_for_bootp_request            │
                       └──────────────────────┬──────────────────────────┘
                                              │ chaddr MAC
                                              ▼
                       ┌─────────────────────────────────────────────────┐
                       │  port_manager._bootp_listener_loop              │
                       │  Idempotency gate:                              │
                       │    not provisioning AND                         │
                       │    not provision_attempted-for-this-MAC AND     │
                       │    not within REPROVISION_COOLDOWN (30 min)     │
                       └──────────────────────┬──────────────────────────┘
                                              │ fire _on_device_in_bootp
                                              ▼
                       ┌─────────────────────────────────────────────────┐
                       │  main._on_port_device_in_bootp                  │
                       │  Spawns asyncio task: _run_netinstall(self, n)  │
                       └──────────────────────┬──────────────────────────┘
                                              │
                                              ▼
                       ┌─────────────────────────────────────────────────┐
                       │  api._run_netinstall (also called by manual     │
                       │  POST /api/netinstall):                         │
                       │    1. Add transient 10.255.<vlan%256>.11/24     │
                       │       to port VLAN (cleanup in finally)         │
                       │    2. GET <ztp_api_url>/ztp/mikrotik/           │
                       │       netinstall-bootstrap.rsc with X-API-Key   │
                       │    3. netinstall-cli -i <vlan> -a <client-ip>   │
                       │       -r -c -sm <modescript> -s <userscript>    │
                       │       <npks>                                    │
                       │    4. Wait up to 240s for SSH                   │
                       │    5. SSH in as fleet-bootstrap                 │
                       │    6. Read RouterBOARD serial; abort if missing │
                       │    7. Verify /system/note contains              │
                       │       base_flash_version=universal-v1           │
                       │    8. Verify ZTP-ready state: device-mode,      │
                       │       phone-home, schedulers, WAN probes        │
                       │    9. POST <ztp_api_url>/ztp/mikrotik/register  │
                       │       with X-API-Key (contract payload)         │
                       └─────────────────────────────────────────────────┘
```

## Contract compliance

This pipeline implements the equipment-provisioner contract. The provisioner's
job is *only* fetch served Netinstall Configure script → flash with Mode +
Configure scripts → verify → register. Everything else (phone-home, role
detection, customer config delivery, factory-reset recovery) is **device-side**
logic baked into the served Configure script; the provisioner is forbidden from
authoring its own.

| Contract step | Code path |
|---|---|
| 1. `GET /ztp/mikrotik/netinstall-bootstrap.rsc` with `X-API-Key` | `MikrotikHandler.fetch_netinstall_bootstrap()` |
| 2. Flash RouterOS + required WiFi packages | `MikrotikHandler.netinstall()` in `provisioner/handlers/mikrotik.py` |
| 3. `device-mode=advanced` | `MODE_SCRIPT_BODY` (`/system/device-mode update mode=advanced`) written to a temp file, passed as `-sm <path>` to `netinstall-cli` (requires 7.22+) |
| 4. Serve the backend-owned Configure script via `-s` | `api._run_netinstall()` passes the fetched body into `MikrotikHandler.netinstall()` |
| 5. Verify `base_flash_version=universal-v1` | `MikrotikHandler.verify_base_flash_applied()` |
| 6. Verify phone-home readiness | `MikrotikHandler.verify_ztp_ready()` |
| 7. `POST /ztp/mikrotik/register` | `equipment_registry.register_mikrotik()` |

## Critical RouterOS 7.20+ quirks

The pipeline took several iterations to get right on RouterOS 7.20.8. The
non-obvious blockers:

| Layer | Quirk | Fix |
|---|---|---|
| `netinstall-cli` arch selection | Device is in BOOTP, model not yet known | Pass the latest RouterOS `.npk` plus required extra packages per arch; cli picks the matching arch from BOOTP |
| `netinstall-cli` interface check | Port-VLAN interfaces only have `192.168.88.11/32` (port isolation), no subnet | Add transient `10.255.<vlan%256>.11/24` around the call, cleaned up in `finally` |
| `netinstall-cli` concurrent runs | Default disallows simultaneous instances | Pass `-c` flag |
| Capability bounding set | Default systemd unit blocks `CAP_NET_BIND_SERVICE` → can't bind UDP/67 even as root | Added to `provisioner-web.service` |
| `-s` replaces default-config | The Configure script IS the entire first-boot script; default RouterOS config does NOT run on top | Fetch the served `netinstall-bootstrap.rsc` from the target backend and hand it to `netinstall-cli -s` unchanged |
| `device-mode = home` (default) | Blocks scheduler + `/tool/fetch`, so phone-home cannot reach the backend | `netinstall-cli -sm` runs `MODE_SCRIPT_BODY` (`/system/device-mode update mode=advanced`) before the Configure script |

## What ends up on the device

Defined by the served Netinstall Configure script on the wifi-api, not by the
provisioner. The provisioner verifies the post-conditions needed for uptime
before registration: `base_flash_version=universal-v1`, RouterOS `fetch` and
scheduler enabled, `phone-home` script and schedulers present, fleet identity
set, and WAN DHCP probe clients installed. Per the contract, the served
Configure script produces:

- Identity `fleet-init-<serial>` (device renames itself to `fleet-gw-<serial>`
  or `fleet-ext-<serial>` on first successful phone-home)
- `fleet-bootstrap` user with `$bootstrapPass`; no `admin` user
- `phone-home` script with `dont-require-permissions=yes` + two schedulers
  (boot + 5-min adaptive)
- DHCP clients on `ether1`, `sfp-sfpplus1`, `ether2`–`ether5` (option 60 =
  `Treehouse-CPE`)
- Factory-reset recovery via the custom default Configure script installed by
  Netinstall
- Services trimmed: telnet/ftp/www/api/api-ssl disabled; ssh + winbox enabled
- `wifi2` configured for `th-ext-join` (disabled until role-detection enables)

## Idempotency / safety

The auto-trigger BOOTP listener reuses the same state machine the IP-probe
detection path uses:

- `port_state.provisioning` short-circuits while a Netinstall is in flight.
- `port_state.provision_attempted` short-circuits subsequent BOOTP frames
  from the *same* MAC after we've fired once. Different MAC clears the
  flag so a replaced device can still be netinstalled.
- `REPROVISION_COOLDOWN = 1800s` (30 minutes) prevents reflash if the same
  device cycles in and out of BOOTP repeatedly. Cooldown is bypassed when
  the BOOTP chaddr differs from `last_provisioned_mac`.

## Concurrent provisioning

Each port VLAN runs an independent BOOTP listener task, with its own raw
socket and `PortState`. Multiple ports can netinstall simultaneously:

- Each port-VLAN is its own L2 broadcast domain, so BOOTP traffic doesn't
  cross between ports.
- Transient IPs use distinct /24s per VLAN (`10.255.<vlan%256>.0/24`) so
  there's no kernel-route ambiguity.
- `netinstall-cli` is invoked with `-c` to allow parallel server instances.
- `netinstall-cli` is bound to a specific VLAN interface with `-i`, so its
  packets always go out the correct port regardless of the routing table.

## Planned reboots vs. the link-loss watchdog

The netinstall pipeline performs a **planned reboot** for the first post-flash
boot, plus a slow Configure-script settle window (`wait_for_base_flash_applied`,
up to 360s) during which the device is reachable but the note marker may lag.
Those transitions can still drop or stall the switch-port link.

The port-level link-loss watchdog (`_delayed_provision_cancel`, 10s grace →
cancel the in-flight task) would otherwise read those transitions as an unplug
and kill the pipeline.

`_run_netinstall` therefore calls `set_expecting_reboot(port, True)` right after
`netinstall-cli` returns and clears it in the `finish()` cleanup, suppressing
the watchdog for the whole pipeline — mirroring how the detection-based flow
brackets reboots with `reboot_started`/`reboot_ended` (`main.py`). A genuine
unplug still terminates the pipeline, because every wait inside the suppressed
region is bounded by its own timeout (`netinstall` 300s, `wait_for_reboot`
240s, `wait_for_base_flash_applied` 360s).

## Host requirements

The provisioner host must:

- Run x86_64 — `netinstall-cli` is a 32-bit i386 binary; ARM hosts won't
  work even under QEMU (raw packet socket emulation fails).
- Have `netinstall-cli` **7.22 or newer** installed at
  `/opt/provisioner/tools/netinstall-cli`. The `-sm advanced` flag was added
  in 7.22; older binaries will reject the flag and abort. The .npk RouterOS
  packages in `/var/lib/provisioner/repo/firmware/mikrotik/` should also be
  7.22+ so the `advanced`-mode constructs in the served Configure script
  (scheduler, `/tool/fetch`, `dont-require-permissions=yes`) actually run.
  Note: 7.22.x is on the **stable** channel, not the **long-term** channel
  (latest LTS at the time of writing is 7.21.4). The contract requires this
  trade-off — the LTS path lacks the `-sm` flag.
- Include the required WiFi driver `.npk` files (`wifi-qcom`, `wifi-qcom-ac`,
  `wifi-mediatek`, or `wireless` as appropriate for the fleet hardware). The
  Netinstall path now ships those packages alongside RouterOS.
- Run `provisioner-web.service` with `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`
  in both `CapabilityBoundingSet` and `AmbientCapabilities`.
- Set the following in `/etc/provisioner/provisioner.env`:
  - `MIKROTIK_BOOTSTRAP_PASS` — operator-controlled fleet password used by the
    served Netinstall Configure script and by the canonical base-flash's
    `$bootstrapPass`. Must match the wifi-side stored value. Avoid `$`,
    backtick, `;`, `{`, `}`, and newline (RouterScript misinterprets them).
  - `MIKROTIK_ONBOARDING_PASS` — *(optional)* fleet-wide `th-ext-join` WPA2 PSK
    baked into every device as the canonical base-flash's `$onboardingPass`.
    Wireless extenders use it to join gateways, so it **must be identical for
    every device the fleet ever flashes** — store it durably (a secrets
    manager / password vault), not just in this env file, and never rotate it
    without re-flashing the whole fleet. If unset, it defaults to
    `MIKROTIK_BOOTSTRAP_PASS`. Same RouterScript-unsafe characters apply.
  - `MIKROTIK_ZTP_API_KEY` — `X-API-Key` for both
    `GET /ztp/mikrotik/netinstall-bootstrap.rsc` and
    `POST /ztp/mikrotik/register`.
- Have `device_settings.mikrotik.ztp_api_url` set in `config.yaml` to the
  wifi-api base URL (e.g. `https://ztp.example.com`). The provisioner
  hard-fails registration if this is unset rather than guessing a default.
