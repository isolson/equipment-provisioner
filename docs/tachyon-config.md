# Tachyon configuration

Tachyon TNA exports are full device configurations. The provisioner applies
them as authoritative documents. It does not merge a TAR export with the live
device configuration.

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
zone with management VLAN `12`, WAN DHCP, and `use_zone_ip` enabled. The
working exports also contain the `lan` and `local` DHCP scopes. These fields
must remain in the full export.

The provisioner accepts the older promoted runtime layout where Ethernet is
under `network.ethernet`. Before it sends the request, the Tachyon handler
moves that section to the top level and removes the malformed nested copy.

## Apply behavior

- TAR files and full JSON exports use replace semantics.
- Partial JSON files use a live-config deep merge.
- The handler adds only API-required defaults that are missing from older
  exports.
- A successful HTTP response is not enough. The handler reads the config back
  and fails closed when verification cannot confirm the applied fields.

Do not commit customer exports. They can contain device identity, passwords,
SNMP communities, and wireless passphrases. Keep those files in protected
runtime storage or an ignored local path.
