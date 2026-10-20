# Business router and switch bench SOP

**BLUF:** Set up a MikroTik business router or switch on one bench port with
`scripts/mikrotik_business_bench.py`:

1. Identify the unit.
2. Clear the first-login flag.
3. Update the firmware.
4. Apply the role profile.
5. Confirm that every read-back check passes.

The profile and checks come from the handler, so this procedure adds no second
copy of the business policy. This is the interim path until epic #206 (routers)
and epic #207 (switches) deliver the kiosk flow.

Policy, port maps and provenance are in [Business wired profiles](business-wired-profiles.md).
Teltonika TSW202 business switches use the separate bench tool from #202
(epic #207), not this procedure.

## Scope

| Board | Roles run on the bench | Notes |
|---|---|---|
| hEX S (E60iUGS, `arm`) | `router`, `router-sfp`, `switch` | The qualified board. PoE out on ether5 only. |
| hEX PoE (RB960PGS, `mipsbe`) | `router` with `--pin-poe ether5` | PoE out on ether2–ether5. LAN switching is in software (see Known limits). |

Other boards need their own profile and bench evidence first (epic #206, slice 5).
The tool refuses an unlisted board unless you pass `--allow-unqualified-board`.

## Roles

| Role | WAN | Trunks (VLAN 10 untagged; 20/40/70 tagged) | Internal access | Management |
|---|---|---|---|---|
| `router` | ether1 | ether2, ether4, ether5 | ether3, sfp1 | 192.168.10.1 |
| `router-sfp` | sfp1 | ether2, ether4, ether5 | ether1, ether3 | 192.168.10.1 |
| `switch` | ether1 is the trusted uplink trunk | ether1, ether2, ether4, ether5 | ether3, sfp1 | 192.168.10.2 |

- `router-sfp` also sets ether5 `poe-out=auto-on`.
- For other boards, pin a PoE port with `--pin-poe`.
- Both router roles carry the interim WAN SSH exception (see Management access).

## Before you start

- Plug in **one business unit at a time.** Every router answers at
  192.168.10.1 after its profile is applied. If two are on the bench, the
  read-back could reach the wrong unit. The tool checks the serial number before
  every write and every read-back, so this fails instead of passing falsely.
- Connect the unit's **ether2** to the bench port. The bench host reaches it
  untagged, as Internal.
- On the bench host, map the bench port to its interface: port N is
  `enp3s0.199N`.
- Put the firmware for the target version in `/var/lib/provisioner/repo/firmware/mikrotik/`
  as `routeros-<arch>-<version>.npk`. The fleet channel is set in
  `/etc/provisioner/config.yaml` (`firmware.checker.sources.mikrotik.channel`).
  Business routers use the `stable` channel (operator decision, 2026-10-20).
- Read the label password into the environment. Do not type it into a command
  line or chat, and do not paste a photo of the label into a shared channel.

```bash
read -rs MIKROTIK_PASS; export MIKROTIK_PASS
TOOL=/opt/provisioner/scripts/mikrotik_business_bench.py   # or a checkout of the branch under test
```

## Procedure

### 1. Identify the unit (no login)

```bash
python3 $TOOL probe --iface enp3s0.1995
```

A factory unit announces identity `MikroTik`, its RouterOS version, board, and
the `bridge/ether2` interface. The MAC is one above the label's E01 MAC.
`bridge-bootstrap` instead of `bridge` means that the unit was Netinstalled
with the WiFi-gateway base. Stop and use that pipeline's procedure.

`probe` is for factory units. A unit that already has a business profile
ignores discovery requests from outside 192.168.10.0/24.

**Do not trust 192.168.88.1 alone.** The bench switch also answers at
192.168.88.1 on the management VLAN (enp3s0.1990). The tool binds every
connection to the port interface. Hand-run commands must do the same: use
`ssh -B` or an interface-bound socket.

### 2. Clear the first-login flag

```bash
python3 $TOOL clear-first-login --iface enp3s0.1995
```

RouterOS 7.20+ marks `admin` as `expired` until the first password change.
While the flag is set, REST accepts the label password but SSH rejects it. This
step sets admin's password to the **same** label value, so the login does not
change. Confirm it with the operator before you run it.

If REST returns 401, the label password does not match this unit, even though
the unit otherwise looks factory-fresh. Do not guess passwords. Reset the
configuration with the reset button: hold it at power-on until the LED
flashes, about 5 s. Then start again at step 1.

### 3. Update firmware

```bash
python3 $TOOL update --iface enp3s0.1995 --serial <SN> --target 7.24.5
```

The tool uploads the package for the device's architecture and reboots to
install it. It then upgrades RouterBOOT and reboots again, and it verifies both
versions. The 16 MB hEX PoE reports less free flash than the package size, but
the upload still succeeded. If the upload fails, the tool removes the partial
file and stops before it reboots.

### 4. Apply the role

```bash
python3 $TOOL apply --iface enp3s0.1995 --serial <SN> --mode router [--pin-poe ether5]
```

The tool:

1. Uploads the profile.
2. Runs a RouterOS syntax dry-run.
3. Starts the import on the device.
4. Reconnects at the management address.
5. Checks the serial number.
6. Reads back every check.
7. Removes the uploaded file.

Success is `RESULT: N/N checks pass`. An import exit code alone never means
success.

The tool never prints device replies on failure, because RouterOS can echo
credential-bearing lines. Diagnose a rejected import in the protected bench
evidence workflow ([BENCH_EVIDENCE.md](BENCH_EVIDENCE.md)).

### 5. Re-verify (read-only) and hand off

```bash
python3 $TOOL verify --iface enp3s0.1995 --serial <SN> --mode router [--pin-poe ether5]
```

Record the unit in the run log below. Then hand it off with:

- The label password still in place. The operator rotates it (epic #206,
  slice 3).
- RoMON unchanged. The operator enables it.
- No customer, site or inventory claim. The identity stays
  `subscriber-unassigned-<serial>`.

## Management access

- Internal (192.168.10.0/24) can use SSH, HTTPS and Winbox.
- **Interim exception:** both router roles accept SSH from server VLAN 15
  (`100.126.15.0/24`) on the WAN.
  - The input rule is placed before the final drop.
  - Winbox and HTTPS stay Internal-only.
  - This rule replaces the business standard's "no management from WAN" until
    the wghub01 WireGuard aggregator exists (treehouse-architecture #666).
    Remove the exception when that aggregator is live.
  - The rule is not rate-limited: this profile has no `mgmt-login` chain.
- The upstream path must still route server VLAN 15 to the router's WAN address.
  A double-NAT WAN needs an upstream forward.

## RouterOS 7.24 read-back notes

- `/ip service` lists every live session as an additional dynamic row, such as
  `ssh`. Use `find where name="ssh" and dynamic=no` or the read-back fails.
- An address list with more than one entry never matches
  `address="a,b"`. Match it with an anchored regex:
  `address~"^a;b\$"`.
- `get … address` returns empty; the property is printed as `available-from`.

## Known limits

- **hEX PoE LAN switching is in software.**
  - The QCA-8337 chip cannot offload bridge VLAN filtering, and bridge DHCP
    snooping also prevents hardware offload. Bridge ports show `hw=yes` but have
    no `H` flag.
  - Internet traffic is handled by the CPU anyway because of NAT. This limit
    affects only LAN-to-LAN throughput, and the operator accepted it on
    2026-10-20.
  - A hardware-switched hEX PoE profile would use the switch-chip VLAN table.
    Bench-check WAN egress before you use it (epic #206).
- **Hardware offload on the hEX S is unverified.** Check the bridge-port `H`
  flag on the next unit.
- **Not verified on the bench:** WAN Internet/NAT traffic, PoE delivery to a
  load, syslog receipt at 100.126.15.28, NTP synchronization, and a power
  cycle. These remain deployment acceptance checks.
- **WireGuard:** the `wg-mgmt` tunnel waits for the wghub01 hub. Do not use the
  handler's "Prepare and store a WireGuard key" option. It stores the router's
  private key on the bench, which treehouse-architecture
  `58-business-router-access.md` forbids.

## Run log

| Date | Serial | Board | Role | Firmware | Result |
|---|---|---|---|---|---|
| 2026-10-18 | HMG0BE209PD | hEX S | `router-sfp` | 7.24.5 | 68/68. Applied before the WAN SSH exception. |
| 2026-10-19 | HMN0B81ATRT | hEX S | — | 7.20.8 | Label password and blank password rejected. Not configured. |
| 2026-10-20 | HMG0B8X4XQ5 | hEX S | `router` + WAN SSH | 7.24.5 | All `router` checks pass, including the WAN SSH checks (read-only re-check). |
| 2026-10-20 | HMS0BQFM19K | hEX PoE | `router` + WAN SSH, `--pin-poe ether5` | 7.24.5 | 69/69. Software LAN switching accepted. |

These runs used one-off scripts with the same steps. The tool consolidates
those scripts, and its first hardware run is still pending.
