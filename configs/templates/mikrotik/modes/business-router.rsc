# E60iUGS ARM bench profile; see docs/business-wired-profiles.md for provenance.
# ---- Bridge + VLAN interfaces (Internal is untagged on access/trunk ports) ----
/interface bridge
# dhcp-snooping blocks rogue DHCP server replies from LAN ports (the router is the only
# legit DHCP server). VLAN filtering keeps Guest and OpenRoam off the untagged LAN.
add name=bridge auto-mac=yes dhcp-snooping=yes vlan-filtering=yes comment="LAN bridge (untagged = Internal VLAN 10)"
/interface vlan
add interface=bridge name=vlan10-internal vlan-id=10
add interface=bridge name=vlan20-iot      vlan-id=20
add interface=bridge name=vlan40-guest    vlan-id=40
add interface=bridge name=vlan70-openroam vlan-id=70

# ---- Ports ----
# Exact E60iUGS port map. PoE settings are retained; no forced power.
/interface bridge port
add bridge=bridge interface=ether2 pvid=10 ingress-filtering=yes frame-types=admit-all comment="UniFi switch uplink (trunk)"
add bridge=bridge interface=ether3 pvid=10 ingress-filtering=yes frame-types=admit-only-untagged-and-priority-tagged comment="Internal access"
add bridge=bridge interface=ether4 pvid=10 ingress-filtering=yes frame-types=admit-all comment="AP trunk"
add bridge=bridge interface=ether5 pvid=10 ingress-filtering=yes frame-types=admit-all comment="AP trunk"
add bridge=bridge interface=sfp1  pvid=10 ingress-filtering=yes frame-types=admit-only-untagged-and-priority-tagged comment="Internal access"
/interface bridge vlan
add bridge=bridge vlan-ids=10 tagged=bridge untagged=ether2,ether3,ether4,ether5,sfp1
add bridge=bridge vlan-ids=20 tagged=bridge,ether2,ether4,ether5
add bridge=bridge vlan-ids=40 tagged=bridge,ether2,ether4,ether5
add bridge=bridge vlan-ids=70 tagged=bridge,ether2,ether4,ether5
/interface list
add name=WAN
add name=LAN
add name=MGMT
/interface list member
add interface=ether1      list=WAN
add interface=vlan10-internal list=LAN
add interface=vlan20-iot      list=LAN
add interface=vlan40-guest   list=LAN
add interface=vlan70-openroam list=LAN
add interface=vlan10-internal list=MGMT

# ---- Addressing ----
/ip address
add address=192.168.10.1/24 interface=vlan10-internal comment="Internal (untagged on LAN ports)"
add address=192.168.20.1/24 interface=vlan20-iot      comment="IoT"
add address=192.168.40.1/22 interface=vlan40-guest    comment="Guest VLAN 40"
add address=192.168.70.1/23 interface=vlan70-openroam comment="OpenRoam"
/ip dhcp-client
add interface=ether1 disabled=no comment="WAN"

# ---- DHCP option 43 so UniFi APs (on Internal) find the controller ----
/ip dhcp-server option
add code=43 name=unifi value=0x0104ACE9D0AE
# value = sub-opt 1, len 4, controller IP 172.233.208.174 (AC E9 D0 AE). Update if the controller IP changes.
/ip dhcp-server option sets
add name=unifi options=unifi

# ---- DHCP pools / servers / scopes ----
/ip pool
add name=pool-guest    ranges=192.168.40.20-192.168.43.254
add name=pool-internal ranges=192.168.10.10-192.168.10.254
add name=pool-iot      ranges=192.168.20.20-192.168.20.254
add name=pool-openroam ranges=192.168.70.20-192.168.71.254
/ip dhcp-server
add name=dhcp-internal interface=vlan10-internal address-pool=pool-internal lease-time=12h authoritative=yes disabled=no dhcp-option-set=unifi
add name=dhcp-iot      interface=vlan20-iot      address-pool=pool-iot      lease-time=12h authoritative=yes disabled=no
add name=dhcp-guest    interface=vlan40-guest    address-pool=pool-guest    lease-time=2h  authoritative=yes disabled=no
add name=dhcp-openroam interface=vlan70-openroam address-pool=pool-openroam lease-time=2h  authoritative=yes disabled=no
/ip dhcp-server network
add address=192.168.40.0/22 gateway=192.168.40.1 dns-server=1.1.1.1,8.8.8.8
add address=192.168.10.0/24 gateway=192.168.10.1 dns-server=192.168.10.1 dhcp-option-set=unifi
add address=192.168.20.0/24 gateway=192.168.20.1 dns-server=192.168.20.1
add address=192.168.70.0/23 gateway=192.168.70.1 dns-server=1.1.1.1,8.8.8.8

# ---- DNS (numeric resolver addresses support RouterOS field limitations) ----
/ip dns
set allow-remote-requests=yes servers=100.126.15.20,9.9.9.9 max-concurrent-queries=120
/ip dns static
add address=192.168.10.1 name=router.lan

# ---- Firewall: input (only Internal manages the router) ----
/ip firewall filter
add chain=input action=accept connection-state=established,related,untracked comment="accept est/rel/untracked"
add chain=input action=drop   connection-state=invalid comment="drop invalid"
# ICMP to the router is allowed only from Internal (covered by the Internal mgmt rule below);
# Guest/IoT/OpenRoam cannot ping the router. For WAN/tower-side ping monitoring, uncomment:
# add chain=input action=accept protocol=icmp in-interface-list=WAN src-address=<monitoring-net> comment="monitoring ping"
add chain=input action=accept dst-address=127.0.0.1 comment="loopback"
add chain=input action=accept in-interface=vlan10-internal src-address=192.168.10.0/24 comment="Internal: full router mgmt"
add chain=input action=accept protocol=udp dst-port=67 in-interface-list=LAN comment="DHCP from all LAN VLANs"
add chain=input action=accept protocol=udp dst-port=53 in-interface=vlan20-iot comment="IoT DNS via router"
add chain=input action=accept protocol=tcp dst-port=53 in-interface=vlan20-iot
add chain=input action=drop comment="drop everything else (WAN + untrusted VLANs)"

# ---- Firewall: forward (segmentation) ----
/ip firewall filter
add chain=forward action=accept ipsec-policy=in,ipsec comment="ipsec in"
add chain=forward action=accept ipsec-policy=out,ipsec comment="ipsec out"
add chain=forward action=fasttrack-connection connection-state=established,related comment="fasttrack"
add chain=forward action=accept connection-state=established,related,untracked comment="accept est/rel/untracked"
add chain=forward action=drop connection-state=invalid comment="drop invalid"
# Guest + OpenRoam: internet only (no LAN-to-LAN)
add chain=forward action=drop in-interface=vlan40-guest    out-interface-list=!WAN comment="Guest: internet only"
add chain=forward action=drop in-interface=vlan70-openroam out-interface-list=!WAN comment="OpenRoam: internet only"
# IoT: internet allowed, but no access to other LANs (Internal can still reach IoT cameras)
add chain=forward action=drop in-interface=vlan20-iot out-interface=vlan10-internal comment="IoT !-> Internal"
add chain=forward action=drop in-interface=vlan20-iot out-interface=vlan40-guest    comment="IoT !-> Guest"
add chain=forward action=drop in-interface=vlan20-iot out-interface=vlan70-openroam comment="IoT !-> OpenRoam"
# (Optional) cut IoT off the internet if cameras are local-only:
# add chain=forward action=drop in-interface=vlan20-iot out-interface-list=WAN comment="IoT no internet"
add chain=forward action=drop connection-state=new connection-nat-state=!dstnat in-interface-list=WAN comment="drop unsolicited WAN"

# ---- NAT ----
/ip firewall nat
# UniFi AP inform remap: APs inform to the controller on :8080, but it listens on :8089.
add chain=dstnat action=dst-nat dst-address=172.233.208.174 dst-port=8080 protocol=tcp to-ports=8089 comment="UniFi controller inform 8080->8089"
add chain=srcnat action=masquerade out-interface-list=WAN ipsec-policy=out,none comment="LAN -> WAN"

# ---- WebFig HTTPS certificate ----
# RouterOS does not start www-ssl without a certificate. RouterOS cannot sign a
# server certificate without a certificate authority (CA), and this router has
# none after a no-defaults reset. So make a local CA first, sign it (a sign
# command with no ca= parameter makes the certificate self-signed), then sign
# the server certificate with that CA.
# Management is LAN-only, so a local CA is sufficient.
# Each key and each sign operation needs a few seconds on a hEX, thus the delays.
# After import, confirm that both certificates show the "K" (private key) and
# "T" (trusted) flags in /certificate print. If they do not, run the two sign
# commands again by hand and then set the www-ssl certificate.
:if ([:len [/certificate find where name="webfig-local"]] = 0) do={
 /certificate add name=webfig-ca common-name=webfig-ca key-size=2048 days-valid=3650 key-usage=key-cert-sign,crl-sign
 /certificate sign webfig-ca
 :delay 15s
 /certificate add name=webfig-local common-name=webfig-local key-size=2048 days-valid=3650 key-usage=digital-signature,key-encipherment,tls-server
 /certificate sign webfig-local ca=webfig-ca
 :delay 15s
}

# ---- Services: management on Internal only; no Winbox/SSH from WAN ----
/ip service
set telnet  disabled=yes
set ftp     disabled=yes
set api     disabled=yes
set api-ssl disabled=yes
set www     disabled=yes
set www-ssl disabled=no certificate=webfig-local address=192.168.10.0/24
set ssh     disabled=no address=192.168.10.0/24
set winbox  disabled=no address=192.168.10.0/24
/ip neighbor discovery-settings
set discover-interface-list=MGMT
/tool mac-server
set allowed-interface-list=MGMT
/tool mac-server mac-winbox
set allowed-interface-list=MGMT
/tool romon
set enabled=no

# ---- System ----
/system clock
set time-zone-name=America/Chicago
/system logging action
set remote remote=100.126.15.28 remote-log-format=syslog syslog-severity=auto
/system logging
add action=remote topics=system,info
add action=remote topics=interface,info
add action=remote topics=firewall,info
add action=remote topics=dhcp,info
/system ntp client set enabled=yes
# NTP server-list syntax differs by RouterOS line (v6: server-dns-names; v7+: servers).
# Use numeric addresses. Some RouterOS versions do not resolve FQDN in this field.
:if ([:pick [/system resource get version] 0 1]="6") do={ /system ntp client set server-dns-names=100.126.15.28 } else={ /system ntp client set servers=100.126.15.28 }


# IPv6 has no business allocation/policy yet; do not bypass IPv4 isolation.
/ipv6 settings set forward=no
/ipv6 firewall filter add chain=input action=drop comment="business: IPv6 management disabled"
/ipv6 firewall filter add chain=forward action=drop comment="business: IPv6 forwarding disabled"
/ip settings set ip-forward=yes
/system identity set name=("subscriber-unassigned-" . [/system routerboard get serial-number])
/system note set note="treehouse-business-v1:router"
