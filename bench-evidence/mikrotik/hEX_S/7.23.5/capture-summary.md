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
