# Update port-monitor script - fixes speed detection
# Run: /import file-name=port-monitor-update.rsc

# Set global variables (these persist until reboot)
:global provisionerIp "192.168.88.10"
:global provisionerPort "8080"

# Remove old script and scheduler
/system script remove [find name=port-monitor]
/system script remove [find name=port-monitor-init]
/system scheduler remove [find name=port-monitor-init-scheduler]

# Create init script that sets globals on boot
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

# Run init now
/system script run port-monitor-init

/system script add name="port-monitor" dont-require-permissions=yes source={
    :global provisionerIp
    :global provisionerPort
    :global port1LastState
    :global port2LastState
    :global port3LastState
    :global port4LastState
    :global port5LastState
    :global port6LastState

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

:log info "port-monitor script updated - speed detection fixed, globals persist on reboot"
