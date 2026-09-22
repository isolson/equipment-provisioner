# Business wired profiles — hEX S bench release

The Business router and Business switch profiles implement the business VLAN
policy on the E60iUGS ARM hEX S running RouterOS 7.23.5. Other boards remain
unqualified in this provisioner. Select **Wired modes**, inspect the device,
choose its role, and apply. The executor reads the configuration back before
reporting success.

## Policy and port map

| Network | VLAN | Router gateway | Switch behavior |
| --- | --- | --- | --- |
| Internal / management | 10, native untagged | 192.168.10.1/24 | Management 192.168.10.2/24; gateway 192.168.10.1 |
| IoT | 20, tagged | 192.168.20.1/24 | Bridged on trunks |
| Guest | 40, tagged | 192.168.40.1/22 | Bridged on trunks |
| OpenRoam | 70, tagged | 192.168.70.1/23 | Bridged on trunks |

- Router: ether1 is WAN. Switch: ether1 is the trusted uplink trunk.
- ether2, ether4 and ether5 are trunks: native 10, tagged 20/40/70.
- ether3 and SFP are Internal access ports. No forced PoE changes are made.
- Router supplies DHCP on all four networks, WAN NAT and the standard
  inter-network firewall. Switch has no DHCP server, NAT or IP forwarding.
- SSH, HTTPS and Winbox are restricted to Internal. HTTP, FTP, Telnet and API
  services are disabled. IPv6 forwarding and input are blocked until a
  business IPv6 policy is defined.
- Syslog and NTP target **100.126.15.28**. DNS uses 100.126.15.20 and 9.9.9.9.
  The router includes the standard UniFi DHCP option 43 and inform-port remap.
- Current device credentials are retained. Identity is serial-bound and
  unassigned; no customer, site slot or inventory claim is created.

The switch address is the first-switch default. Do not install two units at
192.168.10.2 on one business LAN. Additional switch addressing needs an explicit
profile before deployment.

## Advanced management

**RoMON** is opt-in, limited to ether3. The wildcard entry forbids all other
ports. The provisioner creates and stores a per-device secret before enabling
it. A peer needs that same secret; it is not the fleet-wide RoMON domain secret.
RoMON is off at the end of the bench tests.

**Prepare and store a WireGuard key** creates the disabled `wg-management`
interface and stores its key pair. Repeating the operation retains the same
key. The UI displays only the public key. The private key and RoMON secret
live in `/var/lib/provisioner/device-secrets/mikrotik/`, in mode-0600 files under
a mode-0700 directory, named by a hash of device serial. Back up that private
store using the host's secret-handling process; never commit or include it in
HAR exports.

No tunnel peer, tunnel address, route or default-route change is created.
Ops [issue #666](https://github.com/sixtyops/treehouse-architecture/issues/666)
tracks the management concentrator separately from the existing exit VPN.
An endpoint, public peer key, assigned tunnel address and allowed management
prefixes are required before enabling a tunnel. Reachability to syslog/NTP must
be verified over the actual deployment path.

## Bench transport and execution

The business subnet overlaps the host LAN. Device connections bind both the
isolated interface and a 192.168.10.254/32 source. No host LAN route is replaced.
The MikroTik handler selects ARP discovery using the existing bench source;
the shared detection flow consumes that capability. Previous vendor probe
ordering is retained; the two business addresses are appended to MikroTik's
registered address list.

For tagged traffic, bench switch port 1 uses PVID 1991, `tag-stacking=yes` and
`frame-types=admit-all`. This carries inner customer VLANs inside that port's
outer isolation VLAN. The other bench ports were not changed. Configure and
verify equivalent isolation before testing tagged traffic on another port.

The executor imports a complete bench profile over SFTP/SSH. It runs RouterOS
syntax dry-run first, applies on-device across the management-address change,
reconnects, checks identity and policy, then removes the uploaded file. Dynamic
firewall counter rules survive cleanup; old static bridge VLAN rows are removed
before rebuilding the profile. An import exit code alone never means success.

MikroTik SSH login, command, and config-import errors omit device replies and
command text from reported failures. RouterOS can echo a password-bearing line
when it rejects an import. Successful read-back output remains available to
the handler; callers must still keep secret reads out of job results and logs.
Diagnose rejected imports in the protected bench evidence workflow described in
[BENCH_EVIDENCE.md](BENCH_EVIDENCE.md), not by enabling raw response logging.

This is an interim credentialed bench reconfiguration flow. It does not perform
Netinstall, install the fleet reset-default state, derive KDF credentials, or
implement the Ops claim/enrollment contract. A factory reset still uses the
unit's existing reset configuration. Those lifecycle features belong to the
Ops epic and [configuration handoff](ops-config-handoff.md).

## Provenance and validation

The router asset is adapted from the [canonical business router configuration](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/docs/operations/business-router-canonical.rsc)
and [business router standard](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/docs/operations/business-router-standard.md).
The switch applies the VLAN, addressing and L2 policy from the [business switch standard](https://github.com/sixtyops/treehouse-architecture/blob/0121b9ccc7a13fc2627a8f5deaa091b241465552/architecture/48-business-switch.md),
adapted to the verified E60iUGS ports. These code-owned mode assets are under
`configs/templates/mikrotik/modes/`; they are not standard deep-merge templates
or site renderers. Their deployment includes these assets under `/opt/provisioner`.

The [evidence record](../bench-evidence/mikrotik/hEX_S/7.23.5/capture-summary.md)
contains the initial flat-profile history and subsequent business-profile checks.
Router passed 66 configuration checks; switch passed 48. All four router VLANs
returned DHCP offers from their correct scopes. Only Internal replied to gateway
ICMP; IoT, Guest and OpenRoam did not. RoMON enable/disable, private key storage,
and router/key persistence across a software reboot passed.

Browser-driven role changes and advanced controls passed without page errors.
Synthetic UDP probes verified Internal → IoT forwarding and blocked IoT →
Internal, Guest → Internal/IoT, and OpenRoam → Internal/IoT. These probes do
not qualify every client protocol or same-VLAN isolation. The full automated
suite passed 983 tests, with 5 skipped (host Python 3.13).

Login acceptance remains pending: the label login is retained, and the target
standard credential source must be selected and verified with a fresh session.
Do not mark this unit ready for deployment on the strength of role checks alone.

WAN Internet/NAT traffic (deferred by the operator), upstream switch forwarding, syslog receipt, NTP synchronization and a physical power cycle
remain deployment acceptance checks. These are not inferred from configured
settings or the gateway tests.
