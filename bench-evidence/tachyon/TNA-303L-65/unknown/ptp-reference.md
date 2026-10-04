# TNA-303L-65 customer-network PTP reference (2026-09-27)

This is the target config for customer-network PTP setup on a TNA-303L-65. It comes from one export of a working link radio. `known-good.structure.json` holds the redacted values. This page lists the settings that make the radio a PTP link, and it names where each secret must come from. No secret or site identity value is in this record.

The export covers one side of the link: the radio that runs the access point (side A). Side B has no export. Its target is in "Side B" below.

## Link

| Setting | Path | Value |
|---|---|---|
| Role | `wireless.radios.wlan0.vaps[0].mode` | `ap` |
| PTP mode | `wireless.radios.wlan0.vaps[0].ptp` | `true` |
| Channel | `wireless.radios.wlan0.channel.number` | `3` |
| Automatic channel | `wireless.radios.wlan0.channel.auto` | `false` |
| Channel width | `wireless.radios.wlan0.channel.width` | `2160` (MHz) |
| Data rate | `wireless.radios.wlan0.datarate` | automatic |
| Transmit power | `wireless.radios.wlan0.txpower` | `14` |
| Sensitivity | `wireless.radios.wlan0.sensitivity` | `high` |
| Link security | `wireless.radios.wlan0.vaps[0].security.mode` | `wpapsk` |
| SM profile list | `wireless.radios.wlan0.vaps[0].sta_profiles.enabled` | `false` |
| Country | `wireless.country` | `US` |

The channel is per link, not fleet policy. Two links in sight of each other need different channels.

The export still holds the 4 fleet SM profiles, with profile use turned off.

## Side A apply

Two bench findings from 2026-09-28 (two TNA-303L-65 units, firmware 1.15.1 rev 8541) apply to side A:

- Rogue-DHCP blocking must be off. The radio rejects `network.zones.wan.dhcp_snooping.block_rogue_servers_enabled: true` while wlan0 runs as an AP (HTTP 400). The export also has `false`. The provisioner sets `false` for side A.
- The radio needs a reboot after the PTP apply. Without a reboot, the saved config had PTP on, but the radio ran without PTP and had no peer for 4 minutes. The provisioner reboots the radio after the apply and then reads the config back again.

## Side B

Isaac approved this target on 2026-09-29. No side B export exists.

| Setting | Target value |
|---|---|
| wlan0 VAP mode (`wireless.radios.wlan0.vaps[0].mode`) | `sta` |
| PTP mode (`wireless.radios.wlan0.vaps[0].ptp`) | `true` |
| SSID | the same as side A |
| Link key | the same as side A |
| VLAN | none |
| Management address | DHCP |

All other settings are the same as side A.

## Second radio (wlan1)

wlan1 is the 2.4 GHz radio. It is for management access only, and only when a USB interface is plugged in. It never carries customer traffic. In the export and on both bench units, the wlan1 VAP is in zone `lan` with management on. Zone `wan` is the customer bridge.

A PTP profile changes wlan0 only. The provisioner refuses a config that puts a wlan1 VAP in a zone other than `lan`, or that gives it no zone.

## Network

Customer-outbuilding and business PTP links use no VLAN. Isaac decided this on 2026-09-28. The link is untagged. Each radio gets its management address by DHCP on that untagged network.

| Setting | Target value | Value in the export |
|---|---|---|
| Network mode | `bridge` | `bridge` |
| WAN zone address | DHCP, untagged: the management address | DHCP |
| Management VLAN 12 (`network.zones.wan.management.enabled`) | off | off |
| Data VLAN (`dataVlan`) | off | off |
| Port VLANs | none | VLAN 101 on every port |
| WLAN VAP | zone `wan`, MTU 1500 | zone `wan`, MTU 1500 |

The export carries VLAN 101 on every port. A PTP profile for these links does not copy it.

The local LAN address (`network.zones.wan.alt_local_ip.ipaddr`) is the same on each radio. It does not pass across the PTP link, so it is not a field management address. Use the DHCP address.

The export lists six Ethernet ports (`eth0` to `eth5`). A TNA-303L-65 has one physical port, `eth0`. Two bench units with the same model, board (`tam-110-prs`), and firmware (1.15.1 rev 8541) both show one port in the live status (`/cgi.lua/status?type=ethernet`). One of them had the six ports in its saved config only. The extra ports are config state, not hardware. A profile sets `eth0` only.

## Secrets and identity

A template never holds these values. The placeholder names the source that must supply the value.

| Path | Placeholder |
|---|---|
| `wireless.radios.wlan0.vaps[0].security.wpapsk.passphrase` | `<secret: per-link PTP key, HMAC of link data with the KDF seed (#184)>` |
| `wireless.radios.wlan0.vaps[0].sta_profiles.profiles[].security.wpapsk.passphrase` | `<secret: host credentials.tachyon.wpa_key>` |
| `wireless.radios.wlan1.vaps[0].security.wpapsk.passphrase` | `<secret: wlan1 management-access key>` |
| `system.users[].password` (2 accounts) | `<secret: device login from the Ops render-credential contract (sixtyops/treehouse-architecture docs/api-reference/ops-render-credentials.md)>` |
| `services.snmp.v2.ro.community` | `<secret: host credentials.tachyon.snmp_community>` |
| `services.snmp.v2.rw.community` | `<secret: host credentials.tachyon.snmp_write_community>` |
| `services.snmp.v3.*.password` (off) | `<secret: not used, v3 off>` |
| `services.snmp_traps.community`, `.password` (off) | `<secret: not used, traps off>` |
| `system.auth.radius.auth_secret` (auth method `local`) | `<secret: not used, RADIUS off>` |
| `wireless.radios.wlan0.vaps[0].ssid` | `<identity: link SSID from the PTP workflow>` |
| `system.hostname`, `system.name`, `system.description`, `system.location`, `system.latitude`, `system.longitude` | `<identity: site values from the PTP workflow>` |
| `network.zones.wan.custom_mac.address`, `wireless.radios.wlan0.vaps[0].bssid.mac` | `<identity: unit value, never copied>` |
| `network.zones.wan.ip.ipaddr`, `.gateway`, `.alt_local_ip.ipaddr`, `.dataBridgeStaticIp.ipaddr`, `services.ping_watchdog.addresses[0]`, `services.remote_syslog.server` | `<address: masked>`. The DHCP address and the site network supply these. |

## Open questions

- Which firmware did the unit run? The export does not say.
