#!/bin/bash
#
# Update MikroTik switch port-monitor script
# Connects to the switch and updates the webhook script with speed detection fix
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RSC_FILE="${SCRIPT_DIR}/../configs/templates/port-monitor-update.rsc"
CONFIG_DIR="/etc/provisioner"
ENV_FILE="${CONFIG_DIR}/provisioner.env"

# Default values
SWITCH_IP="192.168.88.1"
USERNAME="admin"
PASSWORD=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Load password from env file if it exists
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
    if [[ -n "$MIKROTIK_PASSWORD" ]]; then
        PASSWORD="$MIKROTIK_PASSWORD"
    fi
fi

# Parse arguments first (may override env file)
while [[ $# -gt 0 ]]; do
    case $1 in
        --ip) SWITCH_IP="$2"; shift 2 ;;
        --user) USERNAME="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--ip SWITCH_IP] [--user USERNAME] [--password PASSWORD]"
            echo ""
            echo "Updates the port-monitor script on the MikroTik switch."
            echo "Password is loaded from $ENV_FILE if available."
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Prompt for password if not set
if [[ -z "$PASSWORD" ]]; then
    echo -n "Enter MikroTik switch password for ${USERNAME}@${SWITCH_IP}: "
    read -s PASSWORD
    echo ""
    if [[ -z "$PASSWORD" ]]; then
        log_error "Password is required"
        exit 1
    fi
fi

# Check for RSC file
if [[ ! -f "$RSC_FILE" ]]; then
    log_error "RSC file not found: $RSC_FILE"
    exit 1
fi

# Check for sshpass
if ! command -v sshpass &> /dev/null; then
    log_error "sshpass is required. Install with: apt-get install sshpass"
    exit 1
fi

log_info "Updating port-monitor script on MikroTik switch at $SWITCH_IP"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"
SCP_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

# Test connection
log_info "Testing connection..."
if [[ -z "$PASSWORD" ]]; then
    ssh $SSH_OPTS "${USERNAME}@${SWITCH_IP}" "/system identity print" > /dev/null 2>&1 || {
        log_error "Failed to connect to switch (no password)"
        exit 1
    }
else
    sshpass -p "$PASSWORD" ssh $SSH_OPTS "${USERNAME}@${SWITCH_IP}" "/system identity print" > /dev/null 2>&1 || {
        log_error "Failed to connect to switch"
        exit 1
    }
fi
log_info "Connected to switch"

# Upload RSC file
log_info "Uploading script file..."
if [[ -z "$PASSWORD" ]]; then
    scp $SCP_OPTS "$RSC_FILE" "${USERNAME}@${SWITCH_IP}:port-monitor-update.rsc"
else
    sshpass -p "$PASSWORD" scp $SCP_OPTS "$RSC_FILE" "${USERNAME}@${SWITCH_IP}:port-monitor-update.rsc"
fi

# Import the script
log_info "Importing script (this removes old and installs new)..."
if [[ -z "$PASSWORD" ]]; then
    ssh $SSH_OPTS "${USERNAME}@${SWITCH_IP}" "/import file-name=port-monitor-update.rsc" 2>&1
else
    sshpass -p "$PASSWORD" ssh $SSH_OPTS "${USERNAME}@${SWITCH_IP}" "/import file-name=port-monitor-update.rsc" 2>&1
fi

# Verify
log_info "Verifying script installation..."
if [[ -z "$PASSWORD" ]]; then
    ssh $SSH_OPTS "${USERNAME}@${SWITCH_IP}" "/system script print where name=port-monitor"
else
    sshpass -p "$PASSWORD" ssh $SSH_OPTS "${USERNAME}@${SWITCH_IP}" "/system script print where name=port-monitor"
fi

log_info "Done! Port-monitor script updated with speed detection fix."
log_info "Test by cycling PoE on a port:"
log_info "  /interface ethernet poe set ether2 poe-out=off"
log_info "  :delay 3s"
log_info "  /interface ethernet poe set ether2 poe-out=auto-on"
