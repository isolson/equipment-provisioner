# E60iUGS ARM bench profile; see docs/business-wired-profiles.md for provenance.
# ---- Bridge + VLAN interfaces (Internal is untagged on access/trunk ports) ----
/interface bridge
# dhcp-snooping blocks rogue DHCP server replies from LAN ports (the router is the only
# legit DHCP server). VLAN filtering keeps Guest and OpenRoam off the untagged LAN.
add name=bridge auto-mac=yes dhcp-snooping=yes vlan-filtering=yes comment="LAN bridge (untagged = Internal VLAN 10)"
/interface vlan
add interface=bridge name=vlan10-internal vlan-id=10

# ---- Ports ----
# Exact E60iUGS port map. PoE settings are retained; no forced power.
/interface bridge port
add bridge=bridge interface=ether1 pvid=10 ingress-filtering=yes frame-types=admit-all trusted=yes comment="Business switch uplink"
add bridge=bridge interface=ether2 pvid=10 ingress-filtering=yes frame-types=admit-all comment="UniFi switch uplink (trunk)"
add bridge=bridge interface=ether3 pvid=10 ingress-filtering=yes frame-types=admit-only-untagged-and-priority-tagged comment="Internal access"
add bridge=bridge interface=ether4 pvid=10 ingress-filtering=yes frame-types=admit-all comment="AP trunk"
add bridge=bridge interface=ether5 pvid=10 ingress-filtering=yes frame-types=admit-all comment="AP trunk"
add bridge=bridge interface=sfp1  pvid=10 ingress-filtering=yes frame-types=admit-only-untagged-and-priority-tagged comment="Internal access"
/interface bridge vlan
add bridge=bridge vlan-ids=10 tagged=bridge untagged=ether1,ether2,ether3,ether4,ether5,sfp1
add bridge=bridge vlan-ids=20 tagged=ether1,ether2,ether4,ether5
add bridge=bridge vlan-ids=40 tagged=ether1,ether2,ether4,ether5
add bridge=bridge vlan-ids=70 tagged=ether1,ether2,ether4,ether5
/interface list
add name=WAN
add name=LAN
add name=MGMT
/interface list member
add interface=ether1      list=WAN
add interface=vlan10-internal list=LAN
add interface=vlan10-internal list=MGMT

# ---- Switch management: first switch on the business LAN ----
/ip address add address=192.168.10.2/24 interface=vlan10-internal
/ip route add dst-address=0.0.0.0/0 gateway=192.168.10.1 comment="business management gateway"

# ---- DNS (numeric resolver addresses support RouterOS field limitations) ----
/ip dns
set allow-remote-requests=no servers=100.126.15.20,9.9.9.9 max-concurrent-queries=120
/ip dns static


# ---- Management firewall; no routed data plane ----
/ip firewall filter
add chain=input action=accept connection-state=established,related,untracked
add chain=input action=drop connection-state=invalid
add chain=input action=accept in-interface=vlan10-internal src-address=192.168.10.0/24
add chain=input action=drop
add chain=forward action=drop

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
/ip settings set ip-forward=no
/system identity set name=("switch-unassigned-" . [/system routerboard get serial-number])
/system note set note="treehouse-business-v1:switch"
