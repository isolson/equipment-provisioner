# Tachyon configuration

Native Tachyon exports are full device configurations. The provisioner applies
them as authoritative documents. Older reduced TAR profiles use patch
semantics so they do not remove working device settings.

## Required network layout

Firmware 1.12 and 1.15 live exports use these top-level sections:

```text
ethernet
network
services
system
version
wireless
```

Ethernet ports are under `ethernet.ports`. Management is carried by the WAN
zone with management VLAN `12`, management protocol `802.1q`, WAN DHCP, and
`use_zone_ip` enabled. These values are the same for all Tachyon families.
The working exports also contain the `lan` and `local` DHCP scopes. These
fields must remain in a native full export.

The WAN DHCP object must keep custom DNS disabled. The device then gets DNS
from DHCP. The profile also disables custom MAC use so one device MAC cannot
be copied to another device.

The standard service profile enables remote syslog on UDP port `514`, SNMP,
NTP, discovery, and SSH. It disables Telnet and cloud management. The SNMP
credential is a protected operational setting. Do not use an empty or default
community for field monitoring.

The provisioner accepts the older reduced runtime layout where Ethernet is
under `network.ethernet`. Before it sends the request, the Tachyon handler
moves that section to the top level and removes the malformed nested copy.
The handler merges this reduced layout with the live configuration. This keeps
the live DHCP scopes, interface list, and local fallback account.

## Apply behavior

- Native full TAR files and full JSON exports use replace semantics.
- Reduced TAR files and partial JSON files use a live-config deep merge.
- The handler adds only API-required defaults that are missing from older
  exports.
- A successful HTTP response is not enough. The handler reads the config back
  and fails closed when verification cannot confirm the applied fields.

Firmware 1.12 and 1.15 use the same management path. The export difference is
limited to optional fields. There is no known DHCP interface-MAC migration.

Keep RADIUS as a separate post-management step. Tachyon RADIUS covers web
login only. Keep one local admin account as a fallback.

Do not commit customer exports. They can contain device identity, passwords,
SNMP communities, and wireless passphrases. Keep those files in protected
runtime storage or an ignored local path.
