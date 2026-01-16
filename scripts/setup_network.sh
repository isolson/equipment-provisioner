#!/bin/bash
#
# OrangePi Network Setup Script for Provisioner
#
# Sets up VLAN interfaces for the provisioning system.
# Run this after connecting to the Mikrotik switch trunk port.
#
# Interface Layout:
#   eth0: Main interface (connected to switch trunk port 8)
#   eth0 (untagged): Gets DHCP from router via VLAN 1 (management/internet)
#   eth0.101-106: VLAN interfaces for provisioning ports
#
# Each VLAN interface gets 169.254.1.2/24 to communicate with devices
# at their link-local addresses (169.254.1.1 for Cambium/Tachyon, etc.)

set -e

# Configuration - adjust these to match your setup
INTERFACE="${PROVISIONER_INTERFACE:-eth0}"
VLAN_START="${PROVISIONER_VLAN_START:-1991}"
NUM_VLANS="${PROVISIONER_NUM_VLANS:-6}"
LOCAL_IP="${PROVISIONER_LOCAL_IP:-169.254.1.2}"
NETMASK="24"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."

    # Check for required commands
    for cmd in ip vconfig modprobe; do
        if ! command -v $cmd &> /dev/null; then
            case $cmd in
                vconfig)
                    log_warn "vconfig not found, will use ip command for VLAN creation"
                    ;;
                *)
                    log_error "Required command not found: $cmd"
                    exit 1
                    ;;
            esac
        fi
    done

    # Check if interface exists
    if ! ip link show "$INTERFACE" &> /dev/null; then
        log_error "Interface $INTERFACE not found"
        echo "Available interfaces:"
        ip -br link show
        exit 1
    fi

    log_info "Prerequisites OK"
}

# Load VLAN kernel module
load_vlan_module() {
    log_step "Loading 8021q VLAN module..."

    if ! lsmod | grep -q 8021q; then
        modprobe 8021q
        log_info "Loaded 8021q module"
    else
        log_info "8021q module already loaded"
    fi

    # Ensure it loads on boot
    if ! grep -q "^8021q" /etc/modules 2>/dev/null; then
        echo "8021q" >> /etc/modules
        log_info "Added 8021q to /etc/modules for boot persistence"
    fi
}

# Create VLAN interfaces
create_vlan_interfaces() {
    log_step "Creating VLAN interfaces..."

    for i in $(seq 0 $((NUM_VLANS - 1))); do
        vlan_id=$((VLAN_START + i))
        vlan_iface="${INTERFACE}.${vlan_id}"
        port_num=$((i + 1))

        # Check if interface already exists
        if ip link show "$vlan_iface" &> /dev/null; then
            log_warn "Interface $vlan_iface already exists, reconfiguring..."
            ip link set "$vlan_iface" down 2>/dev/null || true
            ip addr flush dev "$vlan_iface" 2>/dev/null || true
        else
            # Create VLAN interface
            ip link add link "$INTERFACE" name "$vlan_iface" type vlan id "$vlan_id"
            log_info "Created $vlan_iface (VLAN $vlan_id) for provisioning port $port_num"
        fi

        # Bring interface up
        ip link set "$vlan_iface" up

        # Assign link-local IP
        # Using the same IP on each VLAN is fine since they're isolated
        ip addr add "${LOCAL_IP}/${NETMASK}" dev "$vlan_iface" 2>/dev/null || true

        log_info "Configured $vlan_iface with ${LOCAL_IP}/${NETMASK}"
    done
}

# Setup persistent network configuration (systemd-networkd)
setup_systemd_networkd() {
    log_step "Setting up persistent configuration with systemd-networkd..."

    NETWORKD_DIR="/etc/systemd/network"
    mkdir -p "$NETWORKD_DIR"

    # Main interface config (DHCP for management/internet)
    # Generate VLAN lines dynamically based on VLAN_START and NUM_VLANS
    local vlan_lines=""
    for i in $(seq 0 $((NUM_VLANS - 1))); do
        vlan_lines="${vlan_lines}VLAN=${INTERFACE}.$((VLAN_START + i))\n"
    done

    cat > "${NETWORKD_DIR}/10-${INTERFACE}.network" << EOF
[Match]
Name=${INTERFACE}

[Network]
DHCP=yes
# Enable VLAN interfaces
$(echo -e "$vlan_lines")
[DHCP]
UseDNS=yes
UseNTP=yes
EOF

    # Create VLAN netdev and network files
    for i in $(seq 0 $((NUM_VLANS - 1))); do
        vlan_id=$((VLAN_START + i))
        vlan_iface="${INTERFACE}.${vlan_id}"

        # VLAN netdev definition
        cat > "${NETWORKD_DIR}/20-${vlan_iface}.netdev" << EOF
[NetDev]
Name=${vlan_iface}
Kind=vlan

[VLAN]
Id=${vlan_id}
EOF

        # VLAN network configuration
        cat > "${NETWORKD_DIR}/20-${vlan_iface}.network" << EOF
[Match]
Name=${vlan_iface}

[Network]
Address=${LOCAL_IP}/${NETMASK}
# No gateway - these are isolated provisioning networks
ConfigureWithoutCarrier=yes

[Link]
RequiredForOnline=no
EOF
    done

    log_info "Created systemd-networkd configuration files"

    # Enable and restart networkd
    systemctl enable systemd-networkd
    systemctl restart systemd-networkd

    log_info "systemd-networkd restarted with new configuration"
}

# Alternative: Setup with /etc/network/interfaces (Debian/Armbian)
setup_interfaces_file() {
    log_step "Setting up persistent configuration with /etc/network/interfaces..."

    INTERFACES_FILE="/etc/network/interfaces"
    INTERFACES_DIR="/etc/network/interfaces.d"

    mkdir -p "$INTERFACES_DIR"

    # Create provisioner interfaces file
    cat > "${INTERFACES_DIR}/provisioner-vlans" << EOF
# Provisioner VLAN interfaces
# Generated by setup_network.sh

# Main interface (DHCP for management/internet)
auto ${INTERFACE}
iface ${INTERFACE} inet dhcp

EOF

    # Add VLAN interfaces
    for i in $(seq 0 $((NUM_VLANS - 1))); do
        vlan_id=$((VLAN_START + i))
        vlan_iface="${INTERFACE}.${vlan_id}"

        cat >> "${INTERFACES_DIR}/provisioner-vlans" << EOF
# VLAN ${vlan_id} - Provisioning port $((i + 1))
auto ${vlan_iface}
iface ${vlan_iface} inet static
    address ${LOCAL_IP}
    netmask 255.255.255.0
    vlan-raw-device ${INTERFACE}

EOF
    done

    # Check if interfaces.d is sourced
    if ! grep -q "source.*interfaces.d" "$INTERFACES_FILE" 2>/dev/null; then
        echo "source /etc/network/interfaces.d/*" >> "$INTERFACES_FILE"
        log_info "Added interfaces.d source to $INTERFACES_FILE"
    fi

    log_info "Created $INTERFACES_DIR/provisioner-vlans"
}

# Setup with netplan (Ubuntu)
setup_netplan() {
    log_step "Setting up persistent configuration with netplan..."

    NETPLAN_DIR="/etc/netplan"
    NETPLAN_FILE="${NETPLAN_DIR}/60-provisioner.yaml"

    mkdir -p "$NETPLAN_DIR"

    cat > "$NETPLAN_FILE" << EOF
# Provisioner Network Configuration
# Generated by setup_network.sh

network:
  version: 2
  renderer: networkd

  ethernets:
    ${INTERFACE}:
      dhcp4: true
      dhcp6: false

  vlans:
EOF

    # Add VLAN interfaces
    for i in $(seq 0 $((NUM_VLANS - 1))); do
        vlan_id=$((VLAN_START + i))
        vlan_iface="${INTERFACE}.${vlan_id}"

        cat >> "$NETPLAN_FILE" << EOF
    ${vlan_iface}:
      id: ${vlan_id}
      link: ${INTERFACE}
      addresses:
        - ${LOCAL_IP}/${NETMASK}
EOF
    done

    # Fix permissions
    chmod 600 "$NETPLAN_FILE"

    log_info "Created $NETPLAN_FILE"

    # Apply netplan
    netplan apply

    log_info "Netplan configuration applied"
}

# Detect network configuration system and setup persistence
setup_persistence() {
    log_step "Setting up persistent network configuration..."

    if command -v netplan &> /dev/null && [[ -d /etc/netplan ]]; then
        log_info "Detected netplan (Ubuntu)"
        setup_netplan
    elif systemctl is-active systemd-networkd &> /dev/null || [[ -d /etc/systemd/network ]]; then
        log_info "Detected systemd-networkd"
        setup_systemd_networkd
    elif [[ -f /etc/network/interfaces ]]; then
        log_info "Detected /etc/network/interfaces (Debian/Armbian)"
        setup_interfaces_file
    else
        log_warn "Could not detect network configuration system"
        log_warn "VLAN interfaces created but may not persist after reboot"
        log_warn "Please configure persistence manually for your distribution"
    fi
}

# Remove VLAN interfaces (cleanup)
cleanup_vlans() {
    log_step "Removing VLAN interfaces..."

    for i in $(seq 0 $((NUM_VLANS - 1))); do
        vlan_id=$((VLAN_START + i))
        vlan_iface="${INTERFACE}.${vlan_id}"

        if ip link show "$vlan_iface" &> /dev/null; then
            ip link set "$vlan_iface" down
            ip link delete "$vlan_iface"
            log_info "Removed $vlan_iface"
        fi
    done

    # Remove persistent configs
    rm -f /etc/systemd/network/20-${INTERFACE}.*.netdev
    rm -f /etc/systemd/network/20-${INTERFACE}.*.network
    rm -f /etc/network/interfaces.d/provisioner-vlans
    rm -f /etc/netplan/60-provisioner.yaml

    log_info "Cleanup complete"
}

# Show current status
show_status() {
    echo ""
    echo "========================================"
    echo "Provisioner Network Status"
    echo "========================================"
    echo ""

    echo "Main Interface (${INTERFACE}):"
    ip -br addr show "$INTERFACE" 2>/dev/null || echo "  Not found"
    echo ""

    echo "VLAN Interfaces:"
    for i in $(seq 0 $((NUM_VLANS - 1))); do
        vlan_id=$((VLAN_START + i))
        vlan_iface="${INTERFACE}.${vlan_id}"
        port_num=$((i + 1))

        if ip link show "$vlan_iface" &> /dev/null; then
            state=$(ip -br link show "$vlan_iface" | awk '{print $2}')
            addr=$(ip -br addr show "$vlan_iface" | awk '{print $3}')
            echo "  Port $port_num: $vlan_iface (VLAN $vlan_id) - $state - $addr"
        else
            echo "  Port $port_num: $vlan_iface (VLAN $vlan_id) - NOT CONFIGURED"
        fi
    done
    echo ""

    echo "Device Link-Local Addresses:"
    echo "  Cambium/Tachyon: 169.254.1.1 (ports respond on this IP)"
    echo "  Tarana: 169.254.100.1"
    echo "  Mikrotik: 192.168.88.1 (default, may vary)"
    echo ""
}

# Print usage
usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  setup     Create VLAN interfaces and configure persistence (default)"
    echo "  cleanup   Remove VLAN interfaces and persistent configuration"
    echo "  status    Show current network status"
    echo "  quick     Quick setup without persistence (for testing)"
    echo ""
    echo "Environment Variables:"
    echo "  PROVISIONER_INTERFACE   Base interface (default: eth0)"
    echo "  PROVISIONER_VLAN_START  Starting VLAN ID (default: 101)"
    echo "  PROVISIONER_NUM_VLANS   Number of VLANs (default: 6)"
    echo "  PROVISIONER_LOCAL_IP    Local IP on each VLAN (default: 169.254.1.2)"
    echo ""
    echo "Example:"
    echo "  $0 setup                    # Full setup with persistence"
    echo "  PROVISIONER_INTERFACE=enp1s0 $0 setup  # Use different interface"
    echo ""
}

# Main
main() {
    echo "========================================"
    echo "OrangePi Network Setup for Provisioner"
    echo "========================================"
    echo ""
    echo "Configuration:"
    echo "  Interface: $INTERFACE"
    echo "  VLANs: $VLAN_START - $((VLAN_START + NUM_VLANS - 1)) ($NUM_VLANS total)"
    echo "  Local IP: $LOCAL_IP/$NETMASK"
    echo ""

    case "${1:-setup}" in
        setup)
            check_root
            check_prerequisites
            load_vlan_module
            create_vlan_interfaces
            setup_persistence
            show_status
            log_info "Network setup complete!"
            log_warn "DHCP lease may have renewed - your IP address may have changed!"
            log_warn "New IP: $(ip -br addr show "$INTERFACE" | awk '{print $3}' | cut -d/ -f1)"
            ;;
        quick)
            check_root
            check_prerequisites
            load_vlan_module
            create_vlan_interfaces
            show_status
            log_warn "Quick setup complete (not persistent across reboots)"
            ;;
        cleanup)
            check_root
            cleanup_vlans
            ;;
        status)
            show_status
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
