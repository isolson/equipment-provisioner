# hEX S (E60iUGS ARM): package update and wired modes

## What the capture did

The device was identified on provisioner port 1 with its ether2 connected.
Label login succeeded over interface-bound IPv6 SSH. Explicit source binding
also allowed IPv4 SSH. Missing `arping` on the host prevented its normal
ARP-based discovery; installing `iputils-arping` restored the ARP probe.

RouterOS and RouterBOOT were independently verified at 7.23.5 after their
respective reboots. Only the RouterOS ARM package was installed. The official
package SHA-256 was
`1a16dbb14e8d6c540ba980274b69be7f3fb350d9b85fc1849b93b791ac081511`.

The initial layout matched the six-port factory topology but had NAT disabled.
The handler normalized Router mode, then verified Router → Switch → Router.
In Switch mode all six Ethernet/SFP ports were bridged, IPv4/IPv6 forwarding
was off, and NAT and DHCP client/server functions were disabled. Router mode
restored ether1 WAN, five bridged LAN ports, forwarding, NAT, and DHCP.
The management address and login were retained. No Internet path was provided
to the device by the provisioner.

The committed fixture contains role flags and counts from authenticated
readbacks. It contains no identity, credential, or full export. Raw exports
and update provenance remain in the private evidence directory named by the
manifest. WAN/LAN traffic and role persistence across a power cycle remain
acceptance checks; this record qualifies the configuration transition only.

## Request sequence

The device update and initial transition capture used SSH/SFTP:

1. Read resource/package/RouterBOARD information and export the configuration.
2. Upload the ARM NPK with SFTP and verify its remote size.
3. Reboot; reconnect and read RouterOS 7.23.5.
4. Stage `/system routerboard upgrade`; reboot and read RouterBOOT 7.23.5.
5. Read the wired layout, apply Router mode, and read back its role flags.
6. Apply Switch mode and read back bridge membership, forwarding, NAT and DHCP.
7. Restore Router mode, verify the same fields, and export the configuration.

The deployed `/network-modes` page was subsequently exercised with Chromium:
Inspect → Switch → Router. Both applications returned successful authenticated
readbacks with no page JavaScript errors. The private
`wired-modes-ui.private.har` and screenshot record that provisioner UI sequence;
`ui-verification.json` records its results. The device was left in Router mode.

## Business VLAN profiles and advanced management

The later business release supersedes the initial flat role profiles. See
[the profile runbook](../../../../docs/business-wired-profiles.md) for source
provenance, role policy, exact ports, credentials and remaining acceptance work.

- Complete imports passed 66 router and 48 switch readback checks, including
  VLAN filtering, DHCP/scope settings, management services, firewall, syslog and
  NTP configuration. Router → Switch → Router completed.
- DHCP probes received correct-scope offers on router VLANs 10, 20, 40 and 70.
  Switch probes received no offers.
- ARP reached each router VLAN gateway. Internal ICMP received replies; IoT,
  Guest and OpenRoam gateway ICMP received none, as required by the standard.
- Router configuration and the prepared WireGuard key survived a software reboot.
- RoMON enable/disable on ether3 passed containment readback. The wildcard
  remains forbidden. A per-device secret is stored privately.
- WireGuard key preparation was repeatable and the private store permissions
  were verified. The interface remains disabled; no peer or tunnel is claimed.

The first tagged DHCP checks exposed the bench switch's untagged-only port
setting. Port 1 was changed to tag stacking with PVID 1991 and admit-all,
then the packet checks passed. Other bench ports were not changed.

Two execution findings are retained: dry-run is a flag on this RouterOS
version; syntax success does not detect built-in dynamic firewall rules that
cannot be removed. Cleanup now preserves dynamic rules and removes static
bridge VLAN rows before replacing the bridge. RouterOS readback stringifies
lists with semicolons; unset default firewall flags must be handled as enabled.

Sanitized business role readbacks are in `business-router.structure.json` and
`business-switch.structure.json`. Private operational evidence includes
`business-router-readback.json`, `business-switch-readback.json`,
`business-router-dhcp.json`, `business-switch-dhcp.json`,
`business-management-isolation.json`, `business-advanced.json`,
`business-reboot.json` and `business-after-reboot.private.rsc`.

Browser role changes and advanced controls passed without page errors. Synthetic
UDP probes allowed Internal → IoT and blocked IoT → Internal, Guest →
Internal/IoT, and OpenRoam → Internal/IoT. The full suite passed 983 tests,
with 5 skipped on host Python 3.13. Login standardization remains pending;
the unit retains its label login.

WAN traffic (operator deferred), other client protocols, upstream switch forwarding,
collector receipt, NTP synchronization and physical power-cycle acceptance
remain unverified. The installed fleet reset/enrollment lifecycle is not part
of this interim credentialed reconfiguration flow.
