# Single-port (no-switch) ThinkPad setup

A no-managed-switch variant of the provisioner. The ThinkPad's wifi handles
internet/management (equipment-registry webhooks, firmware downloads); a single
ethernet port handles the device under provisioning. One device at a time.

This is the lower-friction SKU — no rackmount switch, no per-port VLAN
configuration. Same codebase as the multi-port deployment; the only switch
is `network.mode: simple` in config.

## Hardware

- ThinkPad Yoga (or similar x86 laptop running Linux).
- Wifi connected to an internet-routable network for the host's default route.
- Ethernet port (built-in NIC or USB-C dock) connected directly to the device
  under provisioning. No switch in between.

## Software prerequisites

- Same provisioner package as the multi-port deployment (`/opt/provisioner`).
- Same systemd units (`provisioner.service`, `provisioner-web.service`).
- `netinstall-cli` at `/opt/provisioner/tools/netinstall-cli` for MikroTik
  flashing (already required by the multi-port deployment; same binary).

## Install

1. Deploy the provisioner code as usual (`./scripts/deploy.sh`).
2. Copy `configs/thinkpad-single-port.yaml` to `/etc/provisioner/config.yaml`
   on the laptop.
3. Edit `network.interface` to match the wired interface name on this host
   (check with `ip -br link` — typically `enp0s31f6`, `enxXXXXXX`, or similar).
4. Restart: `sudo systemctl restart provisioner provisioner-web`.

## NetworkManager / routing

The wired interface must NOT carry the host's default route — devices answer
ARP from link-local addresses (169.254.x.x) that would conflict with regular
internet routing.

For a NetworkManager-managed laptop:

```
nmcli connection modify "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses 169.254.1.2/16 \
  ipv4.gateway "" \
  ipv4.never-default yes \
  connection.autoconnect yes
nmcli connection up "Wired connection 1"
```

The provisioner adds additional source-IP aliases (192.168.1.2/24,
192.168.88.11/32) on top of this at startup via `_configure_single_port_interface`
in `port_manager.py`. You don't need to add them manually.

Wifi: any DHCP-managed network with internet works. Confirm the default route
goes via wifi after both connections are up:

```
ip route | grep '^default'
# should show: default via <gateway> dev wlp<...>
```

## Detection coverage

Single-port mode discovers devices via three mechanisms on each detection
cycle:

1. **Passive MAC sniff** — for vendors with no management IP (Evolution
   Digital). Driven by carrier-state polling: when the wired interface goes
   from no-link to link, the same boot-wait + sniff flow runs that the
   managed-switch webhook normally triggers.
2. **Vendor link-local probes** — pings each address in `DeviceLinkLocalIP.ALL`
   (169.254.1.1, 192.168.1.1, 192.168.1.20, 169.254.100.1, 192.168.88.1) and
   identifies the responder. Covers factory-default devices.
3. **Subnet ARP sweep** — scans `simple_mode.subnet` for already-DHCP'd
   devices that aren't at any of the link-local addresses. Set the subnet to
   match your operational network if you re-provision devices in place.

## Verify

1. With the laptop running and nothing on ethernet, open `http://localhost:8080`
   in a browser. UI should show a single centered port card.
2. Plug a factory Tachyon directly into the ethernet port. Within ~30 seconds:
   - Port card shows link-up
   - Device discovered at 169.254.1.1
   - Fingerprint → firmware → config flow runs end-to-end
   - Equipment-registry POST fires via wifi (check the registry endpoint).
3. Plug a factory MikroTik. Auto-Netinstall should trigger from the BOOTP
   listener on the ethernet interface (same as multi-port mode).
4. Plug a Ubiquiti device. The 192.168.1.2/24 alias on the wired interface
   answers ARP for 192.168.1.20.
5. Plug a device that's already DHCP'd (e.g. previously provisioned router on
   192.168.1.50). Confirm the subnet sweep discovers it on the next cycle.

## Troubleshooting

**BOOTP/Netinstall fails immediately**: the MikroTik flash path binds UDP/67.
On Ubuntu desktop, systemd-resolved or NetworkManager's dnsmasq may already
hold this port. Check with `sudo ss -ulnp | grep ':67 '` and stop the
conflicting service before retrying.

**Device detected but provisioning fails at "login"**: confirm the wired
interface has the right source IP for that vendor. `ip -br addr show <iface>`
should list `169.254.1.2/16`, `169.254.100.2/24`, `192.168.1.2/24`,
`192.168.88.11/32`. If they're missing, the provisioner's startup setup
silently failed — check the service log (`journalctl -u provisioner`) and
confirm the service has `CAP_NET_ADMIN`.

**Wifi captive portal**: at customer sites, the wifi may require captive-portal
sign-in before internet works. Equipment-registry POST will fail silently
until the portal is dismissed. Watch the provisioner log for HTTP errors on
the registry URL.

**Two devices on the same port at once**: only one device at a time. Plug,
provision, unplug, repeat. The UI shows "READY FOR NEXT DEVICE" after a
completed provision; that's the cue to swap.
