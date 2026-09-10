# hEX S package update and wired modes — 2026-09-10

The E60iUGS ARM unit is on provisioner port 1, connected through its ether2 LAN
port. Its label credentials are stored privately on the bench host. Initial
login/readback used interface-bound IPv6 SSH; IPv4 SSH also succeeded with a
source address explicitly selected from the device's management subnet.

RouterOS was updated from 7.20.7 long-term to 7.23.5 long-term using the official
ARM NPK. RouterBOOT was subsequently updated to 7.23.5. Separate reboot/readback
checks verified both versions. No Wi-Fi packages or Netinstall were involved,
and the device was not given an Internet route through the provisioner.

The host was missing `arping`, which its MikroTik detection path requires.
Installing Debian's `iputils-arping` made the interface/source-bound ARP probe
succeed. The Debian installer now includes that dependency. Fingerprint probe
ordering and vendor registries were not changed.

## Mode workflow

The dashboard's **Wired modes** link opens `/network-modes`. Select the port,
inspect it, then choose and apply a role. The API authenticates, checks physical
identity and firmware, verifies the supported layout, applies through the
vendor handler, and reads the state back. An unknown layout, changed device,
busy port, unqualified model/firmware, or failed readback is refused.

- **Router:** ether1 WAN; ether2–ether5 and SFP bridged as LAN; IPv4/IPv6
  forwarding, the existing NAT rule, and DHCP client/server enabled.
- **Switch:** all six Ethernet/SFP interfaces bridged; forwarding, NAT, and
  DHCP client/server disabled. The existing management address and credentials
  are retained, so the management address must suit the deployment network.

The initial layout had NAT disabled. The bench normalized Router mode, then
verified Router → Switch → Router, ending in Router mode. The handler rejects
other hardware architectures, altered bridge/address/service layouts, and
backend-managed `phone-home` configurations. This is a wired role workflow,
not a replacement for the existing fleet Netinstall/ZTP pipeline.

Role descriptions and commands live in the handler. The web workflow consumes
those capabilities and the exact model/firmware evidence. Existing AP/PTP
qualification requirements and transition reports retain their prior behavior.
The wired workflow and its integration were deployed as scoped changes to the
existing application, with private file backups and before/after hashes.

An automated Chromium browser check exercised the deployed page through
Inspect → Switch → Router. Both applications returned verified device readbacks,
and the page had no JavaScript errors. The device was left in Router mode.
A successful explicit mode application clears an earlier login failure without
marking a full provisioning run successful. The unique label login is a
temporary per-port override; after a service restart, use **Device login** on
this page to enter it again. It was not added to fleet-wide credentials.

The final regression suite passed 970 tests, with 5 skipped, on Python 3.13.
Python 3.9 syntax compatibility was checked separately; no Python 3.9 runtime
test is claimed.

## Evidence and limits

[The evidence record](../bench-evidence/mikrotik/hEX_S/7.23.5/capture-summary.md)
contains sanitized role counts and both successful transitions. Original
exports, package provenance, and version readbacks are under
`/var/lib/provisioner/bench-evidence/mikrotik/E60iUGS/live-2026-09-10/`.

This validates package installation and role configuration/readback. WAN/LAN
traffic, DHCP service delivery to a client, and role persistence across a power
cycle are separate acceptance checks. No fresh-factory baseline, fleet
registration, or deployment qualification is claimed by the mode check.
