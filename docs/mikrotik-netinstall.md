# MikroTik Netinstall + Auto-Provisioning

How the provisioner detects a MikroTik device entering BOOTP/Netinstall mode,
flashes it via `netinstall-cli`, applies a base configuration, and hands the
device off ready for customer config.

## Field-tech workflow

1. Plug the MikroTik into any of the six numbered ports on the provisioner
   switch.
2. Press and hold the device's reset button while applying power. Continue
   holding for ~20 seconds, until the power LED goes off (model-dependent
   indicator that the device has entered BOOTP listening mode).
3. Release the reset button.
4. Walk away. The provisioner detects the BOOTP request, runs the full
   Netinstall + base-flash pipeline, and reports completion on the
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
                       │    2. netinstall-cli -i <vlan> -a <client-ip>   │
                       │       -r -c -sm advanced -s <userscript> <npks> │
                       │    3. Wait up to 240s for SSH                   │
                       │    4. SSH in as fleet-bootstrap                 │
                       │    5. Read RouterBOARD serial; abort if missing │
                       │    6. GET <ztp_api_url>/ztp/mikrotik/           │
                       │       base-flash.rsc (canonical, no auth)       │
                       │    7. Prepend :local serial / bootstrapPass /   │
                       │       onboardingPass; /import combined script   │
                       │    8. Verify /system/note contains              │
                       │       base_flash_version=universal-v1           │
                       │    9. POST <ztp_api_url>/ztp/mikrotik/register  │
                       │       with X-API-Key (contract payload)         │
                       └─────────────────────────────────────────────────┘
```

## Contract compliance

This pipeline implements the equipment-provisioner contract. The provisioner's
job is *only* flash → fetch canonical base-flash → /import → verify → register.
Everything else (phone-home, role detection, customer config delivery,
factory-reset recovery) is **device-side** logic baked in by the canonical
base-flash; the provisioner is forbidden from authoring its own.

| Contract step | Code path |
|---|---|
| 1. Flash RouterOS | `MikrotikHandler.netinstall()` in `provisioner/handlers/mikrotik.py` |
| 2. `device-mode=advanced` | `-sm advanced` flag in `netinstall()` cmd (requires `netinstall-cli` 7.22+) |
| 3. `GET /ztp/mikrotik/base-flash.rsc` | `MikrotikHandler.fetch_base_flash()` |
| 4. Prepend `:local` parameters | `MikrotikHandler.build_import_script()` |
| 5. `/import` over SSH | `MikrotikHandler.apply_config_file()` |
| 6. Verify `base_flash_version=universal-v1` | `MikrotikHandler.verify_base_flash_applied()` |
| 7. `POST /ztp/mikrotik/register` | `equipment_registry.register_mikrotik()` |

## Critical RouterOS 7.20+ quirks

The pipeline took several iterations to get right on RouterOS 7.20.8. The
non-obvious blockers:

| Layer | Quirk | Fix |
|---|---|---|
| `netinstall-cli` arch selection | Device is in BOOTP, model not yet known | Pass *all* arch `.npk`s; cli picks correct one from BOOTP request |
| `netinstall-cli` interface check | Port-VLAN interfaces only have `192.168.88.11/32` (port isolation), no subnet | Add transient `10.255.<vlan%256>.11/24` around the call, cleaned up in `finally` |
| `netinstall-cli` concurrent runs | Default disallows simultaneous instances | Pass `-c` flag |
| Capability bounding set | Default systemd unit blocks `CAP_NET_BIND_SERVICE` → can't bind UDP/67 even as root | Added to `provisioner-web.service` |
| Default `admin` post-reset | RouterOS 7.20+ keeps `admin` in "must change password on first login" — `/user/set` doesn't lift it | `-s` user-script creates a non-admin `fleet-bootstrap` user with a known password |
| `-s` replaces default-config | The user-script IS the entire first-boot script; default RouterOS config does NOT run on top | `-s` script also builds `bridge-bootstrap` + assigns `192.168.88.1/24` so post-flash SSH is reachable |
| `device-mode = home` (default) | Blocks `/system/scheduler/add`, `/tool/fetch`, `dont-require-permissions=yes` scripts that the canonical base-flash requires | `netinstall-cli -sm advanced` sets `device-mode=advanced` non-interactively at install time (requires `netinstall-cli` 7.22+) |

## What ends up on the device

Defined by the canonical base-flash on the wifi-api, not by the provisioner.
The provisioner only verifies the post-condition `/system/note` contains
`base_flash_version=universal-v1`. Per the contract, the canonical script
produces:

- Identity `fleet-init-<serial>` (device renames itself to `fleet-gw-<serial>`
  or `fleet-ext-<serial>` on first successful phone-home)
- `fleet-bootstrap` user with `$bootstrapPass`; no `admin` user
- `phone-home` script with `dont-require-permissions=yes` + two schedulers
  (boot + 5-min adaptive)
- DHCP clients on `ether1`, `sfp-sfpplus1`, `ether2`–`ether5` (option 60 =
  `Treehouse-CPE`)
- `/system/default-configuration/set` populated for factory-reset recovery
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

## Host requirements

The provisioner host must:

- Run x86_64 — `netinstall-cli` is a 32-bit i386 binary; ARM hosts won't
  work even under QEMU (raw packet socket emulation fails).
- Have `netinstall-cli` **7.22 or newer** installed at
  `/opt/provisioner/tools/netinstall-cli`. The `-sm advanced` flag was added
  in 7.22; older binaries will reject the flag and abort. The .npk RouterOS
  packages in `/var/lib/provisioner/repo/firmware/mikrotik/` should also be
  7.22+ so the `advanced`-mode constructs in the canonical base-flash
  (scheduler, `/tool/fetch`, `dont-require-permissions=yes`) actually run.
  Note: 7.22.x is on the **stable** channel, not the **long-term** channel
  (latest LTS at the time of writing is 7.21.4). The contract requires this
  trade-off — the LTS path lacks the `-sm` flag.
- Run `provisioner-web.service` with `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`
  in both `CapabilityBoundingSet` and `AmbientCapabilities`.
- Set the following in `/etc/provisioner/provisioner.env`:
  - `MIKROTIK_BOOTSTRAP_PASS` — operator-controlled fleet password used both
    by netinstall's `-s` user-script and by the canonical base-flash's
    `$bootstrapPass`. Must match the wifi-side stored value. Avoid `$`,
    backtick, `;`, `{`, `}`, and newline (RouterScript misinterprets them).
  - `MIKROTIK_ZTP_API_KEY` — `X-API-Key` for `POST /ztp/mikrotik/register`.
- Have `device_settings.mikrotik.ztp_api_url` set in `config.yaml` to the
  wifi-api base URL (e.g. `https://api.infra.treehouse.mn`). The provisioner
  hard-fails registration if this is unset rather than guessing a default.
