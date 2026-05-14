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
                       │       -r -c -s <userscript> <all .npks>         │
                       │    3. Wait up to 240s for SSH                   │
                       │    4. SSH in as fleet-bootstrap                 │
                       │    5. /import base-flash.rsc                    │
                       │    6. Mark provisioning complete                │
                       └─────────────────────────────────────────────────┘
```

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
| `device-mode = home` (default) | Blocks `/system/scheduler/add`, `/tool/fetch`, `dont-require-permissions=yes` scripts | Base-flash uses only `home`-allowed operations; phone-home/ZTP fetch deferred until `advanced` mode is feasible (see "Future work") |

## What ends up on the device

After a successful Netinstall + base-flash:

- Identity: `fleet-gw-<serial>` (or `fleet-ext-<serial>` for extenders)
- User `fleet-bootstrap` with password from `MIKROTIK_BOOTSTRAP_PASS`
  (and *no* `admin` user)
- Services trimmed: telnet/ftp/www/api/api-ssl disabled, ssh + winbox enabled
- DHCP client on ether1 (WAN)
- DNS: 1.1.1.1, 1.0.0.1
- WiFi disabled
- All physical ether ports bridged into `bridge-bootstrap` (a transient
  topology; the eventual customer config is responsible for splitting
  into WAN + LAN bridges)

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
- Have `netinstall-cli` installed at `/opt/provisioner/tools/netinstall-cli`,
  matching the RouterOS version of the `.npk` files in
  `/var/lib/provisioner/repo/firmware/mikrotik/`.
- Run `provisioner-web.service` with `CAP_NET_BIND_SERVICE` and `CAP_NET_RAW`
  in both `CapabilityBoundingSet` and `AmbientCapabilities`.
- Set `MIKROTIK_BOOTSTRAP_PASS` in `/etc/provisioner/provisioner.env`.

## Future work

Two follow-ups deliberately deferred to keep the auto-trigger flow simple:

1. **Phone-home / ZTP checkin.** Originally the device was supposed to
   periodically `tool/fetch` a customer config from the ZTP API. This needs
   `device-mode=advanced` (RouterOS 7.x default `home` blocks scheduler and
   fetch). Switching to `advanced` currently requires either physical
   reset-button confirmation within 5 min, or RouterOS 7.22+ + the
   `netinstall-cli -sm` flag to set mode at install time. Until either is
   available, the provisioner pushes customer config over SSH itself using
   the `fleet-bootstrap` credentials.

2. **Factory-reset recovery hook.** `/system/default-configuration/set` was a
   RouterOS 6 feature and was removed in 7.x. A device hard-reset in the
   field now falls back to MikroTik factory default-config and needs a
   fresh Netinstall to rejoin the fleet.
