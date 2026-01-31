#!/bin/bash
#
# Network Device Auto-Provisioner Installation Script
# For OrangePi and similar ARM Linux devices
#

set -e

# Configuration
# All paths use consistent "provisioner" naming
INSTALL_DIR="/opt/provisioner"          # Git repo clone location - code runs from here
CONFIG_DIR="/etc/provisioner"           # Configuration files
DATA_DIR="/var/lib/provisioner"         # Runtime data (firmware, configs, database)
LOG_DIR="/var/log"
VENV_DIR="${INSTALL_DIR}/venv"
SERVICE_NAME="provisioner"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect OS and install system dependencies
install_system_deps() {
    log_info "Installing system dependencies..."

    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y \
            python3 \
            python3-pip \
            python3-venv \
            python3-dev \
            git \
            libffi-dev \
            libssl-dev \
            build-essential \
            net-tools \
            iproute2 \
            vlan \
            arp-scan \
            sshpass

    elif command -v yum &> /dev/null; then
        yum install -y \
            python3 \
            python3-pip \
            python3-devel \
            git \
            libffi-devel \
            openssl-devel \
            gcc \
            net-tools \
            iproute \
            arp-scan \
            sshpass

    elif command -v pacman &> /dev/null; then
        pacman -Sy --noconfirm \
            python \
            python-pip \
            git \
            libffi \
            openssl \
            base-devel \
            net-tools \
            iproute2 \
            arp-scan \
            sshpass
    else
        log_error "Unsupported package manager. Please install dependencies manually."
        exit 1
    fi
}

# Create directories
create_directories() {
    log_info "Creating directories..."

    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${DATA_DIR}"
    mkdir -p "${DATA_DIR}/repo"
    mkdir -p "${LOG_DIR}"

    # Set permissions
    chmod 755 "${INSTALL_DIR}"
    chmod 700 "${CONFIG_DIR}"
    chmod 755 "${DATA_DIR}"
}

# Setup application files (run directly from repo, just copy configs)
copy_files() {
    log_info "Setting up application..."

    # Get the directory where this script is located (robust method)
    SOURCE="${BASH_SOURCE[0]}"
    while [ -L "$SOURCE" ]; do
        DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
        SOURCE="$(readlink "$SOURCE")"
        [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
    done
    REPO_DIR="$(cd -P "$(dirname "$SOURCE")/.." && pwd)"

    # Verify we're in the repo
    if [[ ! -d "${REPO_DIR}/provisioner" ]]; then
        log_error "Cannot find source files at ${REPO_DIR}/provisioner"
        log_error "Please clone the repo first: git clone https://github.com/isolson/equipment-provisioner ${INSTALL_DIR}"
        exit 1
    fi

    # Check if repo is in the right location
    if [[ "${REPO_DIR}" != "${INSTALL_DIR}" ]]; then
        log_warn "Repo is at ${REPO_DIR} but should be at ${INSTALL_DIR}"
        log_warn "For easiest updates, clone directly to ${INSTALL_DIR}:"
        log_warn "  git clone https://github.com/isolson/equipment-provisioner ${INSTALL_DIR}"
        echo ""
        read -rp "Continue anyway from ${REPO_DIR}? [y/N]: " continue_anyway
        if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
            exit 1
        fi
        # Update INSTALL_DIR to actual repo location
        INSTALL_DIR="${REPO_DIR}"
        VENV_DIR="${INSTALL_DIR}/venv"
    fi

    log_info "Running from ${INSTALL_DIR}"

    # Copy config template if config doesn't exist
    if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
        cp "${INSTALL_DIR}/config.yaml" "${CONFIG_DIR}/config.yaml"
        log_info "Created config file at ${CONFIG_DIR}/config.yaml"
    else
        log_warn "Config file already exists, not overwriting"
    fi

    # Copy systemd services
    cp "${INSTALL_DIR}/systemd/provisioner.service" "/etc/systemd/system/${SERVICE_NAME}.service"
    cp "${INSTALL_DIR}/systemd/provisioner-web.service" "/etc/systemd/system/${SERVICE_NAME}-web.service"
}

# Create Python virtual environment and install dependencies
setup_python() {
    log_info "Setting up Python virtual environment..."

    python3 -m venv "${VENV_DIR}"
    source "${VENV_DIR}/bin/activate"

    pip install --upgrade pip wheel
    pip install -r "${INSTALL_DIR}/requirements.txt"

    deactivate
}

# Create environment file template
create_env_file() {
    ENV_FILE="${CONFIG_DIR}/provisioner.env"

    if [[ ! -f "${ENV_FILE}" ]]; then
        log_info "Creating environment file..."
        cat > "${ENV_FILE}" << 'EOF'
# Network Device Provisioner Environment Variables
# Edit this file with your actual credentials

# Device passwords
CAMBIUM_PASSWORD=your_cambium_password
MIKROTIK_PASSWORD=your_mikrotik_password
TARANA_PASSWORD=your_tarana_password
TACHYON_PASSWORD=your_tachyon_password
UBIQUITI_PASSWORD=your_ubiquiti_password

# Notification webhooks (optional)
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=

# Analytics (optional)
ANALYTICS_API_KEY=
EOF
        chmod 600 "${ENV_FILE}"
        log_info "Created environment file at ${ENV_FILE}"
        log_warn "Please edit ${ENV_FILE} with your credentials"
    else
        log_warn "Environment file already exists, not overwriting"
    fi
}

# Setup GitHub deploy key
setup_deploy_key() {
    DEPLOY_KEY="${CONFIG_DIR}/deploy_key"

    if [[ ! -f "${DEPLOY_KEY}" ]]; then
        log_info "Generating SSH deploy key..."
        ssh-keygen -t ed25519 -f "${DEPLOY_KEY}" -N "" -C "provisioner@$(hostname)"
        chmod 600 "${DEPLOY_KEY}"

        log_info "Deploy key generated at ${DEPLOY_KEY}"
        log_info "Add this public key to your GitHub repository as a deploy key:"
        echo ""
        cat "${DEPLOY_KEY}.pub"
        echo ""
    else
        log_warn "Deploy key already exists, not regenerating"
    fi
}

# Enable and start service
setup_service() {
    log_info "Setting up systemd services..."

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    systemctl enable "${SERVICE_NAME}-web"

    log_info "Services enabled."

    # Start the web service immediately
    log_info "Starting web service..."
    systemctl start "${SERVICE_NAME}-web"

    if systemctl is-active --quiet "${SERVICE_NAME}-web"; then
        log_info "Web service started successfully"
    else
        log_warn "Web service may not have started - check: journalctl -u ${SERVICE_NAME}-web"
    fi
}

# Post-install interactive setup
post_install_setup() {
    echo ""
    echo "=================================="
    echo "Optional Setup"
    echo "=================================="
    echo ""

    # Ask about kiosk mode
    read -rp "Setup HDMI kiosk mode for touchscreen display? [y/N]: " setup_kiosk_mode
    if [[ "$setup_kiosk_mode" =~ ^[Yy]$ ]]; then
        echo ""
        setup_kiosk
        echo ""
        log_info "Kiosk mode configured. It will activate on next reboot."
    fi
}

# Setup network interface permissions
setup_network() {
    log_info "Setting up network permissions..."

    # Allow Python to use raw sockets for ARP scanning
    PYTHON_BIN="${VENV_DIR}/bin/python3"
    if [[ -f "${PYTHON_BIN}" ]]; then
        setcap cap_net_raw,cap_net_admin+eip "${PYTHON_BIN}" || true
    fi

    # Network setup script is already in the repo at scripts/setup_network.sh
    # Make sure it's executable
    chmod +x "${INSTALL_DIR}/scripts/setup_network.sh"
    log_info "Network setup script: ${INSTALL_DIR}/scripts/setup_network.sh"
}

# Setup VLAN interfaces for provisioning
setup_vlans() {
    log_info "Setting up VLAN interfaces..."

    if [[ -f "${INSTALL_DIR}/scripts/setup_network.sh" ]]; then
        # Run the network setup script
        "${INSTALL_DIR}/scripts/setup_network.sh" setup
    else
        log_warn "Network setup script not found, skipping VLAN configuration"
        log_warn "Run scripts/setup_network.sh manually after installation"
    fi
}

# Print summary
print_summary() {
    echo ""
    log_info "Installation complete!"
    echo ""
    # Show current IP since DHCP may have renewed
    CURRENT_IP=$(ip -br addr show eth0 2>/dev/null | awk '{print $3}' | cut -d/ -f1)
    if [[ -n "$CURRENT_IP" ]]; then
        log_warn "NOTE: DHCP lease may have renewed during network setup"
        log_warn "Current IP address: ${CURRENT_IP}"
        echo ""
    fi
    echo "Directory structure:"
    echo "  ${INSTALL_DIR}/     - Application code (git repo)"
    echo "  ${CONFIG_DIR}/      - Configuration files"
    echo "  ${DATA_DIR}/        - Runtime data (firmware, configs, db)"
    echo ""
    echo "To update the application:"
    echo "  cd ${INSTALL_DIR} && git pull && sudo systemctl restart ${SERVICE_NAME}-web"
    echo ""
    echo "Next steps:"
    echo "  1. Configure your Mikrotik switch:"
    echo "     - Import configs/templates/mikrotik_switch_provisioner.rsc"
    echo "     - Or manually configure VLANs 1991-1996 on ports 1-6, WAN on port 7, trunk on port 8"
    echo "  2. Connect OrangePi to switch port 8 (trunk port)"
    echo "  3. Connect router/internet to switch port 7 (WAN port)"
    echo "  4. Edit ${CONFIG_DIR}/config.yaml with your settings"
    echo "  5. Edit ${CONFIG_DIR}/provisioner.env with your credentials"
    echo "  6. Access web UI at http://${CURRENT_IP:-<device-ip>}:8080"
    echo "  7. Check logs: journalctl -u ${SERVICE_NAME}-web -f"
    echo ""
    echo "Port mapping (with default Mikrotik config):"
    echo "  Port 1 (ether1): Provisioning - VLAN 1991"
    echo "  Port 2 (ether2): Provisioning - VLAN 1992"
    echo "  Port 3 (ether3): Provisioning - VLAN 1993"
    echo "  Port 4 (ether4): Provisioning - VLAN 1994"
    echo "  Port 5 (ether5): Provisioning - VLAN 1995"
    echo "  Port 6 (ether6): Provisioning - VLAN 1996"
    echo "  Port 7 (ether7): WAN/Internet uplink"
    echo "  Port 8 (ether8): Trunk to OrangePi"
    echo ""
}

# Setup touchscreen kiosk mode
setup_kiosk() {
    log_info "Setting up touchscreen kiosk mode..."

    # Install X11 and Chromium
    log_info "Installing display packages..."
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y \
            xserver-xorg \
            x11-xserver-utils \
            xinit \
            openbox \
            unclutter \
            xdotool \
            libinput-tools

        # Chromium package name varies by distro - try to actually install
        if apt-get install -y chromium 2>/dev/null; then
            CHROMIUM_BIN="chromium"
        elif apt-get install -y chromium-browser 2>/dev/null; then
            CHROMIUM_BIN="chromium-browser"
        else
            log_error "Could not find chromium package. Try: apt-get install chromium"
            return 1
        fi
    elif command -v pacman &> /dev/null; then
        pacman -Sy --noconfirm \
            xorg-server \
            xorg-xinit \
            xorg-xset \
            openbox \
            chromium \
            unclutter \
            xdotool \
            libinput
        CHROMIUM_BIN="chromium"
    else
        log_error "Unsupported package manager for kiosk setup"
        return 1
    fi

    log_info "Using browser: ${CHROMIUM_BIN}"

    # Create kiosk user if it doesn't exist
    if ! id "kiosk" &>/dev/null; then
        log_info "Creating kiosk user..."
        useradd -m -s /bin/bash kiosk
        usermod -aG video,input,tty kiosk
    fi

    KIOSK_HOME="/home/kiosk"

    # Create openbox autostart
    mkdir -p "${KIOSK_HOME}/.config/openbox"
    cat > "${KIOSK_HOME}/.config/openbox/autostart" << AUTOSTART
# Disable screen blanking and power management
xset s off
xset s noblank
xset -dpms

# Hide cursor after 3 seconds of inactivity
unclutter -idle 3 -root &

# Wait for network and web server
sleep 5

# Start Chromium in kiosk mode
${CHROMIUM_BIN} \\
    --kiosk \\
    --noerrdialogs \\
    --disable-infobars \\
    --disable-session-crashed-bubble \\
    --disable-restore-session-state \\
    --no-first-run \\
    --start-fullscreen \\
    --disable-translate \\
    --disable-features=TranslateUI \\
    --check-for-update-interval=31536000 \\
    --disable-pinch \\
    --overscroll-history-navigation=0 \\
    http://localhost:8080
AUTOSTART

    # Create .xinitrc
    cat > "${KIOSK_HOME}/.xinitrc" << 'XINITRC'
#!/bin/bash
exec openbox-session
XINITRC
    chmod +x "${KIOSK_HOME}/.xinitrc"

    # Create .bash_profile for auto-startx
    cat > "${KIOSK_HOME}/.bash_profile" << 'BASHPROFILE'
# Auto-start X on tty1
if [[ -z $DISPLAY ]] && [[ $(tty) = /dev/tty1 ]]; then
    exec startx -- -nocursor
fi
BASHPROFILE

    # Fix ownership
    chown -R kiosk:kiosk "${KIOSK_HOME}/.config" "${KIOSK_HOME}/.xinitrc" "${KIOSK_HOME}/.bash_profile"

    # Setup autologin on tty1
    mkdir -p /etc/systemd/system/getty@tty1.service.d
    cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf << 'AUTOLOGIN'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin kiosk --noclear %I $TERM
AUTOLOGIN

    # Create a script to restart kiosk if it crashes
    cat > "${INSTALL_DIR}/restart-kiosk.sh" << RESTART
#!/bin/bash
# Restart kiosk browser if it exits
BROWSER="${CHROMIUM_BIN}"
while true; do
    if ! pgrep -x "\${BROWSER}" > /dev/null && ! pgrep -x "chromium" > /dev/null; then
        sudo -u kiosk DISPLAY=:0 \${BROWSER} \\
            --kiosk \\
            --noerrdialogs \\
            --disable-infobars \\
            http://localhost:8080 &
    fi
    sleep 10
done
RESTART
    chmod +x "${INSTALL_DIR}/restart-kiosk.sh"

    # Create systemd service for kiosk watchdog
    cat > /etc/systemd/system/kiosk-watchdog.service << SERVICE
[Unit]
Description=Kiosk Browser Watchdog
After=provisioner-web.service
Requires=provisioner-web.service

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/restart-kiosk.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    systemctl enable kiosk-watchdog.service

    log_info "Kiosk mode configured!"
    echo ""
    echo "Kiosk setup complete. To activate:"
    echo "  1. Start the web service: systemctl start ${SERVICE_NAME}-web"
    echo "  2. Reboot to start kiosk: sudo reboot"
    echo ""
    echo "The system will auto-login as 'kiosk' user and launch Chromium"
    echo "pointing to http://localhost:8080"
    echo ""
    echo "To disable kiosk mode later:"
    echo "  rm /etc/systemd/system/getty@tty1.service.d/autologin.conf"
    echo "  systemctl daemon-reload"
    echo ""
}

# Disable kiosk mode
disable_kiosk() {
    log_info "Disabling kiosk mode..."

    # Remove autologin
    rm -f /etc/systemd/system/getty@tty1.service.d/autologin.conf
    rmdir /etc/systemd/system/getty@tty1.service.d 2>/dev/null || true

    # Disable watchdog
    systemctl disable kiosk-watchdog.service 2>/dev/null || true
    systemctl stop kiosk-watchdog.service 2>/dev/null || true

    systemctl daemon-reload

    log_info "Kiosk mode disabled. Reboot to apply changes."
}

# Uninstall function
uninstall() {
    log_info "Uninstalling provisioner..."

    # Stop and disable services
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl stop "${SERVICE_NAME}-web" 2>/dev/null || true
    systemctl stop kiosk-watchdog 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}-web" 2>/dev/null || true
    systemctl disable kiosk-watchdog 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    rm -f "/etc/systemd/system/${SERVICE_NAME}-web.service"
    rm -f "/etc/systemd/system/kiosk-watchdog.service"
    systemctl daemon-reload

    # Remove installation directory
    rm -rf "${INSTALL_DIR}"

    # Optionally remove config and data
    read -p "Remove configuration and data? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "${CONFIG_DIR}"
        rm -rf "${DATA_DIR}"
        rm -f "${LOG_DIR}/provisioner.log"
    fi

    # Optionally remove kiosk user
    if id "kiosk" &>/dev/null; then
        read -p "Remove kiosk user? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            userdel -r kiosk 2>/dev/null || true
            disable_kiosk
        fi
    fi

    log_info "Uninstall complete"
}

# Main
main() {
    echo "=================================="
    echo "Network Device Auto-Provisioner"
    echo "Installation Script"
    echo "=================================="
    echo ""

    case "${1:-install}" in
        install)
            check_root
            install_system_deps
            create_directories
            copy_files
            setup_python
            create_env_file
            setup_deploy_key
            setup_network
            setup_vlans
            setup_service
            post_install_setup
            print_summary
            ;;
        kiosk)
            check_root
            setup_kiosk
            ;;
        disable-kiosk)
            check_root
            disable_kiosk
            ;;
        setup-switch)
            check_root
            SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
            "${SCRIPT_DIR}/setup_switch.sh" "${@:2}"
            ;;
        uninstall)
            check_root
            uninstall
            ;;
        help|--help|-h)
            echo "Usage: $0 {install|setup-switch|kiosk|disable-kiosk|uninstall}"
            echo ""
            echo "Commands:"
            echo "  install        Install the provisioner and web interface"
            echo "  setup-switch   Detect and configure MikroTik provisioning switch"
            echo "  kiosk          Setup touchscreen kiosk mode (run after install)"
            echo "  disable-kiosk  Disable kiosk mode auto-login"
            echo "  uninstall      Remove the provisioner"
            echo ""
            echo "Setup-switch options:"
            echo "  --ip ADDRESS   IP address of MikroTik switch (skip auto-detection)"
            echo "  --username     SSH username (default: admin)"
            echo "  --password     SSH password (default: empty)"
            echo "  --yes          Auto-confirm prompts (non-interactive mode)"
            echo ""
            ;;
        *)
            echo "Usage: $0 {install|setup-switch|kiosk|disable-kiosk|uninstall}"
            echo "Run '$0 help' for more information"
            exit 1
            ;;
    esac
}

main "$@"
