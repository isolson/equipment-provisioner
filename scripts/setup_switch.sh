#!/bin/bash
#
# MikroTik Provisioner Switch Setup Script
# Detects, connects to, and configures a MikroTik switch for the provisioner
#

set -e

# Configuration
CONFIG_DIR="/etc/provisioner"
ENV_FILE="${CONFIG_DIR}/provisioner.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RSC_TEMPLATE="${SCRIPT_DIR}/../configs/templates/mikrotik_switch_provisioner.rsc"

# Known MikroTik MAC prefixes (OUI)
MIKROTIK_MAC_PREFIXES="E4:8D:8C|2C:C8:1B|48:8F:5A|64:D1:54|74:4D:28|B8:69:F4|CC:2D:E0|D4:01:C3|C4:AD:34|DC:2C:6E|6C:3B:6B"

# Default IPs to scan
DEFAULT_IPS="192.168.88.1 192.168.1.1 10.0.0.1 192.168.0.1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Default values
USERNAME="admin"
PASSWORD=""
IP_ADDRESS=""
SKIP_PASSWORD_CHANGE=false
AUTO_CONFIRM=false
CUSTOM_RSC=""

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[*]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check for required tools
check_dependencies() {
    local missing=()

    if ! command -v sshpass &> /dev/null; then
        missing+=("sshpass")
    fi

    if ! command -v ssh &> /dev/null; then
        missing+=("openssh-client")
    fi

    if ! command -v scp &> /dev/null; then
        missing+=("openssh-client")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  apt-get install -y sshpass openssh-client"
        echo ""
        exit 1
    fi
}

# Print usage information
usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Detect and configure a MikroTik switch as the provisioner switch.

Options:
  --ip ADDRESS           IP address of the MikroTik switch (skip auto-detection)
  --username USER        Username for SSH (default: admin)
  --password PASS        Password for SSH (default: empty)
  --config FILE          Path to custom RSC configuration file
  --skip-password-change Don't generate/set a new admin password
  --yes, -y              Auto-confirm all prompts (non-interactive mode)
  --help, -h             Show this help message

Examples:
  # Interactive mode (recommended for first setup)
  sudo ./setup_switch.sh

  # Non-interactive with factory defaults
  sudo ./setup_switch.sh --ip 192.168.88.1 --username admin --password "" --yes

  # Keep existing password
  sudo ./setup_switch.sh --skip-password-change

EOF
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --ip)
                IP_ADDRESS="$2"
                shift 2
                ;;
            --username)
                USERNAME="$2"
                shift 2
                ;;
            --password)
                PASSWORD="$2"
                shift 2
                ;;
            --config)
                CUSTOM_RSC="$2"
                shift 2
                ;;
            --skip-password-change)
                SKIP_PASSWORD_CHANGE=true
                shift
                ;;
            --yes|-y)
                AUTO_CONFIRM=true
                shift
                ;;
            --help|-h)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# Check if a port is open
check_port() {
    local host=$1
    local port=$2
    local timeout=${3:-2}

    if command -v nc &> /dev/null; then
        nc -z -w"${timeout}" "$host" "$port" 2>/dev/null
    elif command -v timeout &> /dev/null; then
        timeout "${timeout}" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
    else
        # Fallback using bash
        (echo >/dev/tcp/"$host"/"$port") 2>/dev/null
    fi
}

# Check if host responds to SSH
check_ssh() {
    local host=$1
    check_port "$host" 22 2
}

# Check if host has MikroTik API port
check_mikrotik_api() {
    local host=$1
    check_port "$host" 8728 2 || check_port "$host" 8729 2
}

# Scan for MikroTik devices using ARP
scan_arp_for_mikrotik() {
    log_step "Scanning network for MikroTik devices (ARP)..."

    local found_ips=()

    if command -v arp-scan &> /dev/null; then
        # Get all network interfaces
        for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -5); do
            local result
            result=$(arp-scan --interface="$iface" --localnet 2>/dev/null | \
                     grep -iE "$MIKROTIK_MAC_PREFIXES" | \
                     awk '{print $1}' || true)
            if [[ -n "$result" ]]; then
                while IFS= read -r ip; do
                    found_ips+=("$ip")
                done <<< "$result"
            fi
        done
    fi

    # Also check ARP cache
    local arp_cache
    arp_cache=$(arp -an 2>/dev/null | grep -iE "$MIKROTIK_MAC_PREFIXES" | \
                awk -F'[()]' '{print $2}' || true)
    if [[ -n "$arp_cache" ]]; then
        while IFS= read -r ip; do
            [[ -n "$ip" ]] && found_ips+=("$ip")
        done <<< "$arp_cache"
    fi

    # Remove duplicates
    printf '%s\n' "${found_ips[@]}" | sort -u
}

# Scan default IPs for MikroTik
scan_default_ips() {
    log_step "Checking default MikroTik IPs..."

    for ip in $DEFAULT_IPS; do
        if check_ssh "$ip" || check_mikrotik_api "$ip"; then
            echo "$ip"
            return 0
        fi
    done

    return 1
}

# Detect MikroTik switches on the network
detect_mikrotik() {
    echo ""
    echo -e "${BOLD}Scanning for MikroTik devices...${NC}"
    echo ""

    local found_ips=()

    # First check default IPs (fastest)
    for ip in $DEFAULT_IPS; do
        echo -n "  Checking $ip... "
        if check_ssh "$ip"; then
            echo -e "${GREEN}found${NC}"
            found_ips+=("$ip")
        else
            echo "no response"
        fi
    done

    # Then scan ARP for MikroTik MACs
    local arp_results
    arp_results=$(scan_arp_for_mikrotik)
    if [[ -n "$arp_results" ]]; then
        while IFS= read -r ip; do
            # Don't add duplicates
            if [[ ! " ${found_ips[*]} " =~ " ${ip} " ]]; then
                echo -n "  Found via ARP: $ip... "
                if check_ssh "$ip"; then
                    echo -e "${GREEN}SSH available${NC}"
                    found_ips+=("$ip")
                else
                    echo "no SSH"
                fi
            fi
        done <<< "$arp_results"
    fi

    echo ""

    if [[ ${#found_ips[@]} -eq 0 ]]; then
        return 1
    elif [[ ${#found_ips[@]} -eq 1 ]]; then
        echo "${found_ips[0]}"
    else
        # Multiple devices found - let user choose
        echo "Multiple MikroTik devices found:"
        local i=1
        for ip in "${found_ips[@]}"; do
            echo "  $i) $ip"
            ((i++))
        done
        echo ""
        read -rp "Select device [1]: " choice
        choice=${choice:-1}

        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#found_ips[@]} ]]; then
            echo "${found_ips[$((choice-1))]}"
        else
            log_error "Invalid selection"
            return 1
        fi
    fi
}

# Prompt for credentials
prompt_credentials() {
    echo ""
    echo -e "${BOLD}Enter credentials (press Enter for defaults):${NC}"

    read -rp "  Username [$USERNAME]: " input_user
    USERNAME=${input_user:-$USERNAME}

    read -rsp "  Password [${PASSWORD:-(empty)}]: " input_pass
    echo ""
    # Only update if something was entered
    if [[ -n "$input_pass" ]]; then
        PASSWORD="$input_pass"
    fi
}

# Test SSH connection and get device info
test_credentials() {
    local ip=$1
    local user=$2
    local pass=$3

    log_step "Testing connection to $ip..."

    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

    # Test connection and get system info
    local result
    if [[ -z "$pass" ]]; then
        # Empty password - try without sshpass
        result=$(ssh $ssh_opts "${user}@${ip}" "/system resource print; /system identity print; /system routerboard print" 2>/dev/null) || return 1
    else
        result=$(sshpass -p "$pass" ssh $ssh_opts "${user}@${ip}" "/system resource print; /system identity print; /system routerboard print" 2>/dev/null) || return 1
    fi

    echo "$result"
}

# Parse device info from RouterOS output
parse_device_info() {
    local info=$1

    local model board_name identity serial version

    # Extract model/board name
    board_name=$(echo "$info" | grep -E "^\s*board-name:" | awk -F': ' '{print $2}' | tr -d '\r')

    # Extract identity
    identity=$(echo "$info" | grep -E "^\s*name:" | head -1 | awk -F': ' '{print $2}' | tr -d '\r')

    # Extract serial
    serial=$(echo "$info" | grep -E "^\s*serial-number:" | awk -F': ' '{print $2}' | tr -d '\r')

    # Extract version
    version=$(echo "$info" | grep -E "^\s*version:" | awk -F': ' '{print $2}' | tr -d '\r')

    echo "board_name=${board_name:-Unknown}"
    echo "identity=${identity:-MikroTik}"
    echo "serial=${serial:-Unknown}"
    echo "version=${version:-Unknown}"
}

# Upload RSC file to switch
upload_config() {
    local ip=$1
    local user=$2
    local pass=$3
    local rsc_file=$4

    log_step "Uploading configuration file..."

    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"
    local scp_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

    if [[ -z "$pass" ]]; then
        scp $scp_opts "$rsc_file" "${user}@${ip}:provisioner_config.rsc"
    else
        sshpass -p "$pass" scp $scp_opts "$rsc_file" "${user}@${ip}:provisioner_config.rsc"
    fi
}

# Apply configuration on the switch
apply_config() {
    local ip=$1
    local user=$2
    local pass=$3

    log_step "Applying configuration (this may take a moment)..."

    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30 -o LogLevel=ERROR"

    # Import the RSC file
    if [[ -z "$pass" ]]; then
        ssh $ssh_opts "${user}@${ip}" "/import file-name=provisioner_config.rsc" 2>&1
    else
        sshpass -p "$pass" ssh $ssh_opts "${user}@${ip}" "/import file-name=provisioner_config.rsc" 2>&1
    fi
}

# Generate a secure random password
generate_password() {
    # 16 characters, alphanumeric
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16
}

# Set new admin password on the switch
set_switch_password() {
    local ip=$1
    local user=$2
    local old_pass=$3
    local new_pass=$4

    log_step "Setting new admin password..."

    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

    if [[ -z "$old_pass" ]]; then
        ssh $ssh_opts "${user}@${ip}" "/user set [find name=$user] password=\"$new_pass\"" 2>/dev/null
    else
        sshpass -p "$old_pass" ssh $ssh_opts "${user}@${ip}" "/user set [find name=$user] password=\"$new_pass\"" 2>/dev/null
    fi
}

# Save password to environment file
save_password_to_env() {
    local new_pass=$1

    # Create config directory if needed
    mkdir -p "$CONFIG_DIR"

    if [[ -f "$ENV_FILE" ]]; then
        # Update existing MIKROTIK_PASSWORD line or add it
        if grep -q "^MIKROTIK_PASSWORD=" "$ENV_FILE"; then
            sed -i "s/^MIKROTIK_PASSWORD=.*/MIKROTIK_PASSWORD=${new_pass}/" "$ENV_FILE"
        else
            echo "MIKROTIK_PASSWORD=${new_pass}" >> "$ENV_FILE"
        fi
    else
        # Create new env file
        cat > "$ENV_FILE" << EOF
# Network Device Provisioner Environment Variables

# MikroTik switch password (auto-generated)
MIKROTIK_PASSWORD=${new_pass}

# Other device passwords
CAMBIUM_PASSWORD=your_cambium_password
TARANA_PASSWORD=your_tarana_password
TACHYON_PASSWORD=your_tachyon_password

# Notification webhooks (optional)
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=
EOF
    fi

    chmod 600 "$ENV_FILE"
    log_info "Password saved to $ENV_FILE"
}

# Verify configuration was applied
verify_config() {
    local ip=$1
    local user=$2
    local pass=$3

    log_step "Verifying configuration..."

    local ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

    local cmd="/system identity print; /interface bridge vlan print"

    local result
    if [[ -z "$pass" ]]; then
        result=$(ssh $ssh_opts "${user}@${ip}" "$cmd" 2>/dev/null)
    else
        result=$(sshpass -p "$pass" ssh $ssh_opts "${user}@${ip}" "$cmd" 2>/dev/null)
    fi

    # Check for provisioner-switch identity
    if echo "$result" | grep -q "provisioner-switch"; then
        log_info "Identity set to 'provisioner-switch'"
    else
        log_warn "Identity may not have been set correctly"
    fi

    # Check for VLANs
    if echo "$result" | grep -q "1991"; then
        log_info "Provisioning VLANs configured"
    else
        log_warn "VLANs may not have been configured correctly"
    fi

    return 0
}

# Main function
main() {
    echo ""
    echo -e "${BOLD}=== MikroTik Provisioner Switch Setup ===${NC}"
    echo ""

    parse_args "$@"
    check_root
    check_dependencies

    # Determine RSC file to use
    local rsc_file
    if [[ -n "$CUSTOM_RSC" ]]; then
        rsc_file="$CUSTOM_RSC"
    else
        rsc_file="$RSC_TEMPLATE"
    fi

    if [[ ! -f "$rsc_file" ]]; then
        log_error "Configuration template not found: $rsc_file"
        exit 1
    fi

    # Detect or use provided IP
    local switch_ip
    if [[ -n "$IP_ADDRESS" ]]; then
        switch_ip="$IP_ADDRESS"
        log_info "Using provided IP: $switch_ip"
    else
        switch_ip=$(detect_mikrotik) || {
            echo ""
            log_error "No MikroTik device found on the network."
            echo ""
            echo "Make sure:"
            echo "  - The switch is powered on and connected"
            echo "  - Your computer is connected to the switch"
            echo "  - The switch has a default IP (192.168.88.1)"
            echo ""
            echo "You can also specify the IP manually:"
            echo "  $0 --ip <switch-ip>"
            echo ""
            exit 1
        }
    fi

    # Prompt for credentials in interactive mode
    if [[ "$AUTO_CONFIRM" != true ]] && [[ -z "$IP_ADDRESS" ]]; then
        prompt_credentials
    fi

    # Test connection
    local device_info
    device_info=$(test_credentials "$switch_ip" "$USERNAME" "$PASSWORD") || {
        echo ""
        log_error "Failed to connect to $switch_ip"
        echo ""
        echo "Check that:"
        echo "  - The IP address is correct"
        echo "  - Username and password are correct"
        echo "  - SSH is enabled on the switch"
        echo ""
        exit 1
    }

    # Parse and display device info
    echo ""
    log_info "Connected to MikroTik device:"

    eval "$(parse_device_info "$device_info")"
    echo "  Model:    $board_name"
    echo "  Identity: $identity"
    echo "  Serial:   $serial"
    echo "  Version:  $version"
    echo ""

    # Confirm before proceeding
    if [[ "$AUTO_CONFIRM" != true ]]; then
        echo -e "${YELLOW}WARNING: This will overwrite the switch configuration!${NC}"
        echo ""
        echo "The switch will be configured as the provisioning switch with:"
        echo "  - Ports 1-6 (ether1-ether6): Provisioning ports (VLANs 1991-1996)"
        echo "  - Port 7 (ether7): WAN/Internet uplink"
        echo "  - Port 8 (ether8): Trunk to OrangePi"
        echo ""
        read -rp "Configure this switch? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            log_info "Aborted by user"
            exit 0
        fi
    fi

    # Upload configuration
    upload_config "$switch_ip" "$USERNAME" "$PASSWORD" "$rsc_file" || {
        log_error "Failed to upload configuration file"
        exit 1
    }

    # Apply configuration
    local apply_output
    apply_output=$(apply_config "$switch_ip" "$USERNAME" "$PASSWORD" 2>&1) || true

    echo "$apply_output" | grep -v "^$" | head -20

    # Wait for switch to process
    sleep 2

    # Handle password change
    local current_pass="$PASSWORD"
    if [[ "$SKIP_PASSWORD_CHANGE" != true ]]; then
        echo ""

        if [[ "$AUTO_CONFIRM" != true ]]; then
            read -rp "Generate and set a new secure password? [Y/n]: " set_pass
            set_pass=${set_pass:-Y}
        else
            set_pass="Y"
        fi

        if [[ "$set_pass" =~ ^[Yy]$ ]]; then
            local new_pass
            new_pass=$(generate_password)

            if set_switch_password "$switch_ip" "$USERNAME" "$PASSWORD" "$new_pass"; then
                log_info "New password set on switch"
                save_password_to_env "$new_pass"
                current_pass="$new_pass"
            else
                log_warn "Failed to set new password on switch"
            fi
        fi
    fi

    # Verify configuration
    echo ""
    verify_config "$switch_ip" "$USERNAME" "$current_pass" || true

    # Print success message
    echo ""
    echo -e "${GREEN}${BOLD}Setup complete!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Connect OrangePi to port 8 (trunk)"
    echo "  2. Connect router/internet to port 1 (WAN)"
    echo "  3. Run: sudo ./scripts/install.sh install"
    echo ""

    if [[ -f "$ENV_FILE" ]] && grep -q "MIKROTIK_PASSWORD=" "$ENV_FILE"; then
        echo "The switch password has been saved to:"
        echo "  $ENV_FILE"
        echo ""
    fi

    echo "Port mapping:"
    echo "  Port 1 (ether1):  Provisioning - VLAN 1991"
    echo "  Port 2 (ether2):  Provisioning - VLAN 1992"
    echo "  Port 3 (ether3):  Provisioning - VLAN 1993"
    echo "  Port 4 (ether4):  Provisioning - VLAN 1994"
    echo "  Port 5 (ether5):  Provisioning - VLAN 1995"
    echo "  Port 6 (ether6):  Provisioning - VLAN 1996"
    echo "  Port 7 (ether7):  WAN/Internet uplink"
    echo "  Port 8 (ether8):  Trunk to OrangePi"
    echo ""
}

main "$@"
