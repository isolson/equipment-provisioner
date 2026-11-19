# GPEN21 business-switch apply and upgrade (2026-11-18)

SwOS Lite used HTTP API requests with digest authentication. Factory page
captures are from firmware 2.17. The business-switch profile passed read-back
9/9 on 2.17. The upgrade to 2.21 staged the image and rebooted. Two read-backs
then passed 9/9. PoE out was set to force on for a passive AP and passed
read-back.

## Request sequence

Page endpoints: `GET` and `POST` for `/sys.b`, `/fwd.b`, `/vlan.b`,
`/snmp.b`, and `/link.b`. Writes were sent in this order: `vlan.b`,
`fwd.b`, `snmp.b`, `sys.b`.

Upgrade sequence:

- `POST /pboot` with `*`; status 303 is normal.
- `POST /upgrade` with multipart field `blob`; status 200.
- Set `sys.b` field `i0c=1` to stage the image.
- `POST /reboot` with `*`.

## What the capture did

Values use hex strings and `0x` numbers. IPv4 values use little-endian
encoding. See [`docs/gpen21-swos-lite.md`](../../../../docs/gpen21-swos-lite.md)
for the field map. Request bodies are omitted. The known-good page captures
are empty because the unit was off the bench at export time. Production login,
SFP link testing, PoE load testing, and a physical power cycle are not
claimed.
