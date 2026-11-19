# TSW202 business-switch apply and read-back (2026-11-18)

The bench tool upgraded factory firmware TSW2_R_00.01.10.1 to
TSW2_R_00.01.10.4 with `keep_settings=1`, applied the business-switch
profile, moved management to static VLAN 10, and passed two read-backs 30
seconds apart. The first apply run disconnected at the NTP step. An
idempotent re-run passed.

## Request sequence

Write endpoints seen in the logs:

- `POST` and `PUT /api/port_based_vlan/config`
- `PUT /api/dot1x/ports/config/<port>`
- `POST /api/interfaces/config`
- `DELETE /api/interfaces/config/<id>`
- `POST /api/bulk`
- The hardening `PUT` endpoints named in `scripts/tsw202_business_switch.py`

## What the capture did

The logs record stages from that tool. Request bodies are omitted. This
record does not claim production login, RADIUS, SNMP polling, PoE load
testing, or a physical power cycle.
