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

The provisioner keeps **no persistent per-device secret store**. There is no
`/var/lib/provisioner/device-secrets/` directory, no 1Password token, and no KDF
seed on the bench; any legacy copy is removed automatically when the business
flow runs (see [issue #167](https://github.com/isolson/network-provisioner/issues/167)).

**RoMON** is opt-in, limited to ether3. The wildcard entry forbids all other
ports. The per-device RoMON secret is supplied transiently by the management
contract; the provisioner never generates, substitutes a fleet secret for, or
stores one. Enabling RoMON without a supplied secret fails closed. A peer needs
that same secret; it is not the fleet-wide RoMON domain secret. RoMON is off at
the end of the bench tests.

**Prepare on-device management access** creates the disabled `wg-management`
interface on the device. The key pair is generated on-device and only the
**public** half is ever read back — the private key never leaves the router and
is never stored, logged, or exported. Repeating the operation keeps the same key
(idempotent). A one-time rotation regenerates the key on the device for units
whose private half was exported by the earlier interim flow; the new public half
must then be re-published to any peer that held the old one.

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

This is an interim credentialed bench reconfiguration flow. It does not perform
Netinstall, install the fleet reset-default state, or derive KDF credentials —
the provisioner is a pure consumer of the Ops render-credential contract and
never holds a seed. A factory reset still uses the unit's existing reset
configuration. Those lifecycle features belong to the Ops epic and
[configuration handoff](ops-config-handoff.md).

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
ICMP; IoT, Guest and OpenRoam did not. RoMON enable/disable and on-device
WireGuard key persistence across a software reboot passed. That capture predates
issue #167; the removal of the bench secret store, transient RoMON secret, and
`localadmin` credential acceptance still need a fresh hEX S round trip before
deployment sign-off.

Browser-driven role changes and advanced controls passed without page errors.
Synthetic UDP probes verified Internal → IoT forwarding and blocked IoT →
Internal, Guest → Internal/IoT, and OpenRoam → Internal/IoT. These probes do
not qualify every client protocol or same-VLAN isolation. The full automated
suite passed 983 tests, with 5 skipped (host Python 3.13).

Network-policy verification and credential/deployment acceptance are separate
steps. Applying and verifying a role proves the network policy only; it does not
accept the login. Credential acceptance runs through the trusted Ops
render-credential contract (see
[`ops-render-credentials.md`](https://github.com/sixtyops/treehouse-architecture/blob/master/docs/api-reference/ops-render-credentials.md)):
the provisioner receives the per-device `localadmin` password transiently,
replaces the consumed label login, verifies a fresh `localadmin` login works and
the old login fails, then reports verified completion. It stores nothing and
fails safe — the previous login is disabled only after the new one is proven, so
a failure never strands the device. This step is dormant until
`render_credentials_url` and `render_credentials_token` are configured and the
Ops endpoint is deployed. Do not mark a unit ready for deployment on the strength
of role checks alone.

WAN Internet/NAT traffic (deferred by the operator), upstream switch forwarding, syslog receipt, NTP synchronization and a physical power cycle
remain deployment acceptance checks. These are not inferred from configured
settings or the gateway tests.
