#!/bin/bash
#
# Provisioner First-Boot Wizard
#
# Runs once on first power-on via firstboot.service.
# Detects the ethernet interface, collects credentials,
# configures VLANs, optionally sets up the MikroTik switch,
# and starts provisioner services.
#
# Gated by sentinel file: /opt/provisioner/.first-boot
# This script removes the sentinel when done.
#

set -e

INSTALL_DIR="/opt/provisioner"
CONFIG_DIR="/etc/provisioner"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
ENV_FILE="${CONFIG_DIR}/provisioner.env"
LOG_FILE="/var/log/provisioner-firstboot.log"
SWITCH_DEFAULT_IP="192.168.88.1"
PI_MGMT_IP="192.168.88.10"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

log_step()   { echo -e "\n${CYAN}${BOLD}$1${NC}"; echo "[$(date)] STEP: $1" >> "$LOG_FILE"; }
log_info()   { echo -e "  ${GREEN}✓${NC} $1"; echo "[$(date)] INFO: $1" >> "$LOG_FILE"; }
log_warn()   { echo -e "  ${YELLOW}!${NC} $1"; echo "[$(date)] WARN: $1" >> "$LOG_FILE"; }
log_error()  { echo -e "  ${RED}✗${NC} $1"; echo "[$(date)] ERROR: $1" >> "$LOG_FILE"; }
log_detail() { echo -e "  ${DIM}$1${NC}"; }

# Initialize log
mkdir -p "$(dirname "$LOG_FILE")"
echo "=== First boot started $(date) ===" >> "$LOG_FILE"

# ============================================================
# Banner
# ============================================================
clear
echo ""
echo -e "${BOLD}  ╔══════════════════════════════════════════╗${NC}"
echo -e "${BOLD}  ║     Network Device Provisioner           ║${NC}"
echo -e "${BOLD}  ║     First-Boot Setup                     ║${NC}"
echo -e "${BOLD}  ╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${DIM}Log: ${LOG_FILE}${NC}"
echo ""

# ============================================================
# Step 1: Detect ethernet interface
# ============================================================
log_step "[1/6] Detecting ethernet interface"

IFACE=""
for dev in /sys/class/net/*; do
    devname=$(basename "$dev")

    # Skip loopback and wireless
    [[ "$devname" == "lo" ]] && continue
    [[ -d "$dev/wireless" ]] && continue

    # Check it's a physical ethernet device (type 1 = Ethernet)
    if [[ -f "$dev/type" ]] && [[ "$(cat "$dev/type")" == "1" ]]; then
        # Prefer devices that look like ethernet (not docker/veth/br)
        case "$devname" in
            eth*|end*|enp*|eno*|ens*)
                IFACE="$devname"
                break
                ;;
        esac
        # Fallback: use first non-virtual device
        if [[ -z "$IFACE" ]]; then
            IFACE="$devname"
        fi
    fi
done

if [[ -z "$IFACE" ]]; then
    log_error "No ethernet interface found!"
    echo ""
    echo "  Available interfaces:"
    ip -br link show
    echo ""
    echo "  Please set the interface manually in ${CONFIG_FILE}"
    echo "  then run: /opt/provisioner/scripts/setup_network.sh setup"
    # Don't block boot — continue with defaults
    IFACE="eth0"
    log_warn "Falling back to eth0"
else
    log_info "Detected ethernet interface: $IFACE"
fi

# Update config.yaml with detected interface
if [[ -f "$CONFIG_FILE" ]]; then
    # Replace the interface line in config
    sed -i "s/^  interface:.*/  interface: ${IFACE}/" "$CONFIG_FILE" 2>/dev/null || true
    log_info "Updated config.yaml with interface: $IFACE"
fi

# ============================================================
# Step 2: Collect credentials
# ============================================================
log_step "[2/6] Configure device credentials"

echo ""
echo -e "  These passwords are used to log into devices during provisioning."
echo -e "  Press Enter to skip a field."
echo ""

# Write or update a key in the .env file
set_env_value() {
    local key=$1
    local value=$2
    if [[ -f "$ENV_FILE" ]] && grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
    elif [[ -f "$ENV_FILE" ]]; then
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}

read -rsp "  Cambium password: " pw; echo ""
[[ -n "$pw" ]] && set_env_value "CAMBIUM_PASSWORD" "$pw"

read -rsp "  Tarana password: " pw; echo ""
[[ -n "$pw" ]] && set_env_value "TARANA_PASSWORD" "$pw"

read -rsp "  Tachyon password: " pw; echo ""
[[ -n "$pw" ]] && set_env_value "TACHYON_PASSWORD" "$pw"

read -rsp "  Ubiquiti password: " pw; echo ""
[[ -n "$pw" ]] && set_env_value "UBIQUITI_PASSWORD" "$pw"

echo ""
read -rp "  Slack webhook URL (optional, Enter to skip): " slack_url
[[ -n "$slack_url" ]] && set_env_value "SLACK_WEBHOOK_URL" "$slack_url"

chmod 600 "$ENV_FILE"
log_info "Credentials saved to ${ENV_FILE}"

# ============================================================
# Step 3: Configure VLAN network
# ============================================================
log_step "[3/6] Configuring VLAN network"

export PROVISIONER_INTERFACE="$IFACE"

if [[ -f "${INSTALL_DIR}/scripts/setup_network.sh" ]]; then
    bash "${INSTALL_DIR}/scripts/setup_network.sh" setup
    log_info "VLAN interfaces configured"
else
    log_error "setup_network.sh not found — VLANs need manual configuration"
fi

# ============================================================
# Step 4: MikroTik switch setup (optional)
# ============================================================
log_step "[4/6] MikroTik switch configuration"

echo ""
read -rp "  Is a MikroTik switch connected? [y/N]: " setup_switch

if [[ "$setup_switch" =~ ^[Yy]$ ]]; then
    # Prepare network for switch detection
    ip link set "$IFACE" up 2>/dev/null || true

    # Add temporary IP to reach switch at factory default
    MGMT_VLAN_IFACE="${IFACE}.1990"
    if ip link show "$MGMT_VLAN_IFACE" &>/dev/null; then
        if ! ip addr show "$MGMT_VLAN_IFACE" | grep -q "${PI_MGMT_IP}"; then
            ip addr add "${PI_MGMT_IP}/24" dev "$MGMT_VLAN_IFACE" 2>/dev/null || true
        fi
    else
        if ! ip addr show "$IFACE" | grep -q "${PI_MGMT_IP}"; then
            ip addr add "${PI_MGMT_IP}/24" dev "$IFACE" 2>/dev/null || true
        fi
    fi

    # Wait for switch
    echo ""
    echo -e "  Scanning for switch at ${SWITCH_DEFAULT_IP}..."

    local_timeout=120
    elapsed=0
    found=false
    while [[ $elapsed -lt $local_timeout ]]; do
        if ping -c1 -W1 "$SWITCH_DEFAULT_IP" &>/dev/null; then
            found=true
            break
        fi
        printf "\r  Waiting... [%3ds]" "$elapsed"
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo ""

    if [[ "$found" == true ]]; then
        log_info "Switch detected at ${SWITCH_DEFAULT_IP}"

        # Get switch credentials
        read -rp "  Switch username [admin]: " switch_user
        switch_user=${switch_user:-admin}
        read -rsp "  Switch password (Enter for none): " switch_pass
        echo ""

        # Run switch setup
        switch_args=(--ip "$SWITCH_DEFAULT_IP" --username "$switch_user" --yes)
        if [[ -n "$switch_pass" ]]; then
            switch_args+=(--password "$switch_pass")
        else
            switch_args+=(--password "")
        fi

        if [[ -f "${INSTALL_DIR}/scripts/setup_switch.sh" ]]; then
            bash "${INSTALL_DIR}/scripts/setup_switch.sh" "${switch_args[@]}"
            log_info "Switch configured"

            log_detail "Waiting 15s for switch to apply VLAN configuration..."
            sleep 15
        else
            log_warn "setup_switch.sh not found"
        fi
    else
        log_warn "Switch not detected within ${local_timeout}s"
        echo "  Run this later: ${INSTALL_DIR}/scripts/setup_switch.sh"
    fi

    # Clean up temporary IP from raw interface
    ip addr del "${PI_MGMT_IP}/24" dev "$IFACE" 2>/dev/null || true
else
    log_info "Skipped switch setup"
    echo ""
    echo "  To configure the switch later, run:"
    echo "    sudo ${INSTALL_DIR}/scripts/setup_switch.sh"
    echo ""
fi

# ============================================================
# Step 5: Start services
# ============================================================
log_step "[5/6] Starting provisioner services"

systemctl daemon-reload
systemctl restart provisioner-web

# Wait for service to start
started=false
for i in $(seq 1 15); do
    if systemctl is-active --quiet provisioner-web; then
        started=true
        break
    fi
    sleep 1
done

if [[ "$started" == true ]]; then
    log_info "provisioner-web service is running"
else
    log_warn "Service may not have started — check: journalctl -u provisioner-web -f"
fi

# ============================================================
# Step 6: Finalize
# ============================================================
log_step "[6/6] Finalizing"

# Remove sentinel file so this doesn't run again
rm -f "${INSTALL_DIR}/.first-boot"

# Disable the first-boot service
systemctl disable firstboot.service 2>/dev/null || true

log_info "First-boot setup complete"

# --- Ready banner ---
PI_IP=$(ip -br addr show "$IFACE" 2>/dev/null | awk '{print $3}' | cut -d/ -f1 | head -1)
PI_IP=${PI_IP:-"<device-ip>"}

echo ""
echo -e "  ${GREEN}${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "  ${GREEN}${BOLD}║         PROVISIONER READY                ║${NC}"
echo -e "  ${GREEN}${BOLD}╠══════════════════════════════════════════╣${NC}"
echo -e "  ${GREEN}${BOLD}║${NC}                                          ${GREEN}${BOLD}║${NC}"
echo -e "  ${GREEN}${BOLD}║${NC}  Web UI:  ${CYAN}http://${PI_IP}:8080${NC}$(printf '%*s' $((18 - ${#PI_IP})) '')${GREEN}${BOLD}║${NC}"
echo -e "  ${GREEN}${BOLD}║${NC}                                          ${GREEN}${BOLD}║${NC}"
echo -e "  ${GREEN}${BOLD}║${NC}  Port 1-6   Provisioning devices         ${GREEN}${BOLD}║${NC}"
echo -e "  ${GREEN}${BOLD}║${NC}  Port 7     WAN / Internet               ${GREEN}${BOLD}║${NC}"
echo -e "  ${GREEN}${BOLD}║${NC}  Port 8     OrangePi (trunk)             ${GREEN}${BOLD}║${NC}"
echo -e "  ${GREEN}${BOLD}║${NC}                                          ${GREEN}${BOLD}║${NC}"
echo -e "  ${GREEN}${BOLD}║${NC}  Plug devices into ports 1-6 to start.   ${GREEN}${BOLD}║${NC}"
echo -e "  ${GREEN}${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Logs:  ${DIM}journalctl -u provisioner-web -f${NC}"
echo ""

echo "[$(date)] First boot complete" >> "$LOG_FILE"
