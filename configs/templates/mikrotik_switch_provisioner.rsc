# Mikrotik CRS/CSS 8-Port Switch Configuration for Network Provisioner
# Compatible with: CRS305, CRS309, CRS310, CRS312, CRS326, CSS106, CSS610, etc.
#
# Port Layout:
#   Ports 1-6 (ether1-ether6): Provisioning ports for network devices
#   Port 7 (ether7): WAN/Internet uplink - connects to your router
#   Port 8 (ether8): Trunk port to OrangePi provisioner
#
# VLAN Layout:
#   VLAN 1: Management/Internet (native on trunk, for OrangePi internet access)
#   VLAN 1991-1996: Provisioning VLANs (one per port, tagged on trunk)
#
# To apply: System > Reset Configuration, then paste in terminal
# Or: /import file-name=mikrotik_switch_provisioner.rsc

# Reset to defaults (uncomment if needed)
# /system reset-configuration no-defaults=yes skip-backup=yes

#---------------------------------------
# Bridge Configuration
#---------------------------------------
/interface bridge
add name=bridge1 vlan-filtering=no comment="Main bridge - enable VLAN filtering after config"

#---------------------------------------
# VLAN Configuration
#---------------------------------------
/interface bridge vlan
# Internet VLAN (untagged on WAN port, for router connection)
add bridge=bridge1 tagged="" untagged=ether7 vlan-ids=1
# Management VLAN 1990 (tagged on bridge and trunk, for switch-to-Pi communication)
# Bridge must be tagged for switch CPU to send/receive on this VLAN
add bridge=bridge1 tagged=bridge1,ether8 vlan-ids=1990
# Provisioning VLANs (untagged on device port, tagged on trunk)
add bridge=bridge1 tagged=ether8 untagged=ether1 vlan-ids=1991
add bridge=bridge1 tagged=ether8 untagged=ether2 vlan-ids=1992
add bridge=bridge1 tagged=ether8 untagged=ether3 vlan-ids=1993
add bridge=bridge1 tagged=ether8 untagged=ether4 vlan-ids=1994
add bridge=bridge1 tagged=ether8 untagged=ether5 vlan-ids=1995
add bridge=bridge1 tagged=ether8 untagged=ether6 vlan-ids=1996

#---------------------------------------
# Bridge Ports Configuration
#---------------------------------------
/interface bridge port
# Provisioning ports - each in its own VLAN
add bridge=bridge1 interface=ether1 pvid=1991 frame-types=admit-only-untagged-and-priority-tagged
add bridge=bridge1 interface=ether2 pvid=1992 frame-types=admit-only-untagged-and-priority-tagged
add bridge=bridge1 interface=ether3 pvid=1993 frame-types=admit-only-untagged-and-priority-tagged
add bridge=bridge1 interface=ether4 pvid=1994 frame-types=admit-only-untagged-and-priority-tagged
add bridge=bridge1 interface=ether5 pvid=1995 frame-types=admit-only-untagged-and-priority-tagged
add bridge=bridge1 interface=ether6 pvid=1996 frame-types=admit-only-untagged-and-priority-tagged
# WAN port - PVID 1 for internet access
add bridge=bridge1 interface=ether7 pvid=1 frame-types=admit-only-untagged-and-priority-tagged
# Trunk port to OrangePi - accepts all frame types, PVID 1 for native/management
add bridge=bridge1 interface=ether8 pvid=1 frame-types=admit-all

#---------------------------------------
# Switch IP Configuration (VLAN 1990 for Pi communication)
#---------------------------------------
/interface vlan
add interface=bridge1 name=vlan1990-mgmt vlan-id=1990

/ip address
add address=192.168.88.1/24 interface=vlan1990-mgmt comment="Switch management IP on VLAN 1990"

# Note: No default route here - switch doesn't need internet access
# The Pi gets its internet via a separate path or can NAT through the router

/ip dns
set servers=8.8.8.8,8.8.4.4

#---------------------------------------
# Enable VLAN Filtering (DO THIS LAST)
#---------------------------------------
# WARNING: Enabling VLAN filtering will apply all VLAN rules
# Make sure your configuration is correct before enabling
/interface bridge set bridge1 vlan-filtering=yes

#---------------------------------------
# System Settings
#---------------------------------------
/system identity
set name="provisioner-switch"

/system clock
set time-zone-name=America/Chicago

# Disable unused services for security
/ip service
set telnet disabled=yes
set ftp disabled=yes
set api disabled=no
set api-ssl disabled=no
set ssh disabled=no
set www disabled=no
set www-ssl disabled=no

#---------------------------------------
# Port Descriptions (for reference)
#---------------------------------------
/interface ethernet
set ether1 comment="Provisioning Port 1 - VLAN 1991"
set ether2 comment="Provisioning Port 2 - VLAN 1992"
set ether3 comment="Provisioning Port 3 - VLAN 1993"
set ether4 comment="Provisioning Port 4 - VLAN 1994"
set ether5 comment="Provisioning Port 5 - VLAN 1995"
set ether6 comment="Provisioning Port 6 - VLAN 1996"
set ether7 comment="WAN - Internet Uplink"
set ether8 comment="Trunk - OrangePi Provisioner"

#---------------------------------------
# LED Configuration (optional, for CRS switches)
#---------------------------------------
# /system leds
# Uncomment and adjust for your switch model

#---------------------------------------
# Port Event Webhooks to Provisioner
#---------------------------------------
# Sends HTTP POST to provisioner when port link status changes
# This enables instant device detection without polling

# Set the provisioner IP address (OrangePi address on VLAN 1990)
:global provisionerIp "192.168.88.10"
:global provisionerPort "8080"

# Initialize port state tracking variables
:global port1LastState false
:global port2LastState false
:global port3LastState false
:global port4LastState false
:global port5LastState false
:global port6LastState false

# Create init script that sets globals on boot (globals don't survive reboot)
/system script add name="port-monitor-init" dont-require-permissions=yes source={
    :global provisionerIp "192.168.88.10"
    :global provisionerPort "8080"
    :global port1LastState false
    :global port2LastState false
    :global port3LastState false
    :global port4LastState false
    :global port5LastState false
    :global port6LastState false
    :log info "Port monitor globals initialized"
}

# Schedule init script to run at startup
/system scheduler add name="port-monitor-init-scheduler" on-event="/system script run port-monitor-init" start-time=startup

# Script to check port status and send webhooks on change
/system script
add name="port-monitor" dont-require-permissions=yes source={
    :global provisionerIp
    :global provisionerPort
    :global port1LastState
    :global port2LastState
    :global port3LastState
    :global port4LastState
    :global port5LastState
    :global port6LastState

    # Function to send port event
    :local sendEvent do={
        :global provisionerIp
        :global provisionerPort
        :local port $1
        :local linkUp $2
        :local speed $3
        :local url "http://$provisionerIp:$provisionerPort/api/switch/port-event"
        :local json "{\"port\":\"$port\",\"link_up\":$linkUp,\"speed\":\"$speed\"}"
        :do {
            /tool fetch url=$url http-method=post http-header-field="Content-Type:application/json" http-data=$json keep-result=no
        } on-error={
            :log warning "Failed to send port event to provisioner"
        }
    }

    # Check each provisioning port
    :local port1Running [/interface ethernet get ether1 running]
    :if ($port1Running != $port1LastState) do={
        :set port1LastState $port1Running
        :local linkStr "false"
        :local speed ""
        :if ($port1Running) do={
            :set linkStr "true"
            :do {
                :local mon [/interface ethernet monitor ether1 once as-value]
                :set speed ($mon->"rate")
            } on-error={ :set speed "" }
        }
        :log info "Port ether1 link changed: $linkStr speed: $speed"
        $sendEvent "ether1" $linkStr $speed
    }

    :local port2Running [/interface ethernet get ether2 running]
    :if ($port2Running != $port2LastState) do={
        :set port2LastState $port2Running
        :local linkStr "false"
        :local speed ""
        :if ($port2Running) do={
            :set linkStr "true"
            :do {
                :local mon [/interface ethernet monitor ether2 once as-value]
                :set speed ($mon->"rate")
            } on-error={ :set speed "" }
        }
        :log info "Port ether2 link changed: $linkStr speed: $speed"
        $sendEvent "ether2" $linkStr $speed
    }

    :local port3Running [/interface ethernet get ether3 running]
    :if ($port3Running != $port3LastState) do={
        :set port3LastState $port3Running
        :local linkStr "false"
        :local speed ""
        :if ($port3Running) do={
            :set linkStr "true"
            :do {
                :local mon [/interface ethernet monitor ether3 once as-value]
                :set speed ($mon->"rate")
            } on-error={ :set speed "" }
        }
        :log info "Port ether3 link changed: $linkStr speed: $speed"
        $sendEvent "ether3" $linkStr $speed
    }

    :local port4Running [/interface ethernet get ether4 running]
    :if ($port4Running != $port4LastState) do={
        :set port4LastState $port4Running
        :local linkStr "false"
        :local speed ""
        :if ($port4Running) do={
            :set linkStr "true"
            :do {
                :local mon [/interface ethernet monitor ether4 once as-value]
                :set speed ($mon->"rate")
            } on-error={ :set speed "" }
        }
        :log info "Port ether4 link changed: $linkStr speed: $speed"
        $sendEvent "ether4" $linkStr $speed
    }

    :local port5Running [/interface ethernet get ether5 running]
    :if ($port5Running != $port5LastState) do={
        :set port5LastState $port5Running
        :local linkStr "false"
        :local speed ""
        :if ($port5Running) do={
            :set linkStr "true"
            :do {
                :local mon [/interface ethernet monitor ether5 once as-value]
                :set speed ($mon->"rate")
            } on-error={ :set speed "" }
        }
        :log info "Port ether5 link changed: $linkStr speed: $speed"
        $sendEvent "ether5" $linkStr $speed
    }

    :local port6Running [/interface ethernet get ether6 running]
    :if ($port6Running != $port6LastState) do={
        :set port6LastState $port6Running
        :local linkStr "false"
        :local speed ""
        :if ($port6Running) do={
            :set linkStr "true"
            :do {
                :local mon [/interface ethernet monitor ether6 once as-value]
                :set speed ($mon->"rate")
            } on-error={ :set speed "" }
        }
        :log info "Port ether6 link changed: $linkStr speed: $speed"
        $sendEvent "ether6" $linkStr $speed
    }
}

# Schedule to run port monitor every 2 seconds
/system scheduler
add name="port-monitor-scheduler" interval=2s on-event="/system script run port-monitor" start-time=startup

# Send initial port states after boot (with delay for network init)
/system scheduler
add name="port-init-report" on-event={
    :delay 30s
    :log info "Sending initial port states to provisioner"
    /system script run port-monitor
    # Run twice to catch any that changed during startup
    :delay 2s
    /system script run port-monitor
    # Disable this one-shot scheduler
    /system scheduler disable port-init-report
} start-time=startup

:log info "Provisioner switch configuration applied successfully"
:put "Configuration complete. Port layout:"
:put "  ether1-ether6: Provisioning ports (VLANs 1991-1996)"
:put "  ether7: WAN/Internet uplink"
:put "  ether8: Trunk to OrangePi"
:put ""
:put "Port event webhooks configured to: http://$provisionerIp:$provisionerPort/api/switch/port-event"
:put "Edit provisionerIp variable if OrangePi has a different IP"
