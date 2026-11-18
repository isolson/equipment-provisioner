# MikroTik GPEN21 SwOS Lite bench notes

## Device and API

The GPEN21 runs SwOS Lite, not RouterOS. The provisioner's MikroTik handler
cannot log in and times out. Configure it through the SwOS Lite HTTP API.
There is no GPEN21 handler or committed bench tool yet; the one-off script and
raw evidence remain on the bench host in `~/bench-evidence`.

Factory settings on the tested unit were `192.168.88.1`, user `admin`, blank
password and HTTP Digest authentication. The unit ran SwOS Lite 2.17. Ports
are Port1 (PoE in), Port2 (PoE out) and SFP1.

`GET /<page>.b` returns a JavaScript-like object. Strings use hex-encoded ASCII
in single quotes, numbers use `0x` hex, and IPv4 addresses are little-endian
uint32 (`192.168.10.4` is `0x040aa8c0`). POST editable page fields as
`text/plain` in the same format. Field IDs come from the device's own
gzip-compressed `engine.js`.

The field map used was:

- `sys.b`: `i05` identity; `i0a` address mode (0 DHCP with fallback, 1 static,
  2 DHCP only); `i09` static IP; `i1b` allow-from-VLAN; `i1c` PoE out mode
  (0 auto on, 1 force on, 2 off); `i1d` PoE out status (read-only); `i06`
  version (hex ASCII); `i0c` upgrade staged flag.
- `fwd.b`: `i1f` set-as-uplink port bitmask (SFP1 is `0x4`); `i15` VLAN mode
  per port (0 disabled, 1 optional, 2 strict); `i17` VLAN receive (0 any);
  `i18` default VLAN ID per port.
- `vlan.b`: rows with `i01` VLAN ID and `i02` member-port bitmask.
- `snmp.b`: `i01` enabled.

## Business-switch profile

The bench profile created VLANs 10, 20, 40 and 70 on all three ports (member
bitmask `0x7`), strict VLAN mode, default VLAN 10 untagged, SFP1 as uplink,
SNMP off, and management static at `192.168.10.{1+unit}`, reachable only on
VLAN 10. Write order was `vlan.b`, `fwd.b`, `snmp.b`, then `sys.b`; the
management address change drops the connection.

Identity is limited to 15 characters. `th.echoshores.sw03` was truncated, so
the tested identity was `echoshores.sw03`. SwOS Lite has no default gateway
setting; the switch answers only hosts on its `192.168.10.0/24` LAN. Reach it
from the site LAN or router. PoE out “auto on” powers 802.3af/at devices;
“force on” is for passive-PoE devices only and can damage other devices.

## Firmware update

The web UI obtains the latest version from
`http://upgrade.mikrotik.com/swoslite/gpen21/LATEST` and the image from
`http://upgrade.mikrotik.com/swoslite/gpen21/swos-gpen21-<major.minor>.bin`.
POST `/pboot` with body `*` (303 redirect to `/index.html` is normal), then
POST `/upgrade` as multipart field `blob` (200). `sys.b` field `i0c` becomes
1 when the image is staged. The version changes only after POST `/reboot` with
body `*`; the first three attempts appeared to fail because they skipped the
reboot.

For bench access, the host has factory addresses on each port VLAN. Use a
temporary network namespace with a macvlan on the port's VLAN interface, as
the TSW202 tool does.

## Bench run — 2026-11-18

Echo Shores “house on the hill” fiber-to-AP unit, serial `HM60B1Z8SJN`, used
identity `echoshores.sw03` at `192.168.10.4`. SwOS Lite upgraded from 2.17 to
2.21; PoE out was set to force on for the passive-PoE AP. Read-back passed
9/9 before and after reboot. The admin password remains factory blank.
Production login is a separate step in issue #207, slice 4.
