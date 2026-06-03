#!/bin/bash
#
# Provisioner Chroot Installation Script
#
# Runs inside an ARM chroot during image build.
# Installs system packages, Python venv, pip dependencies,
# copies configs, and enables systemd services.
#
# Does NOT: start services, configure network, collect credentials.
# Those happen at first boot on real hardware.
#

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

INSTALL_DIR="/opt/provisioner"
CONFIG_DIR="/etc/provisioner"
DATA_DIR="/var/lib/provisioner"
VENV_DIR="${INSTALL_DIR}/venv"
KIOSK=false

# --- Colors ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[CHROOT]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[CHROOT]${NC} $1"; }
log_error() { echo -e "${RED}[CHROOT]${NC} $1"; }
log_step()  { echo -e "\n${CYAN}${BOLD}[CHROOT] $1${NC}"; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kiosk) KIOSK=true; shift ;;
        *) shift ;;
    esac
done

# --- Step 1: Install system packages ---
log_step "Installing system packages"

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
    sshpass \
    openssh-client \
    openssh-server \
    curl

log_info "System packages installed"

# --- Step 2: Install kiosk packages (optional) ---
if [[ "$KIOSK" == true ]]; then
    log_step "Installing kiosk mode packages"

    apt-get install -y \
        xserver-xorg \
        x11-xserver-utils \
        xinit \
        openbox \
        unclutter \
        xdotool \
        xinput \
        libinput-tools

    # Try chromium (package name varies)
    CHROMIUM_BIN=""
    if apt-get install -y chromium 2>/dev/null; then
        CHROMIUM_BIN="chromium"
    elif apt-get install -y chromium-browser 2>/dev/null; then
        CHROMIUM_BIN="chromium-browser"
    else
        log_warn "Could not install Chromium — kiosk browser will need manual install"
    fi

    log_info "Kiosk packages installed"
fi

# --- Step 3: Create directories ---
log_step "Creating directories"

mkdir -p "${CONFIG_DIR}"
mkdir -p "${DATA_DIR}"
mkdir -p "${DATA_DIR}/repo"

chmod 755 "${INSTALL_DIR}"
chmod 700 "${CONFIG_DIR}"
chmod 755 "${DATA_DIR}"

log_info "Directories created"

# --- Step 4: Create Python venv and install dependencies ---
log_step "Setting up Python virtual environment"

python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --upgrade pip wheel
"${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

log_info "Python venv created and dependencies installed"

# --- Step 5: Copy config template ---
log_step "Setting up configuration files"

if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
    cp "${INSTALL_DIR}/config.yaml" "${CONFIG_DIR}/config.yaml"
    log_info "Copied config.yaml to ${CONFIG_DIR}/"
fi

# Create placeholder env file (credentials populated at first boot)
cat > "${CONFIG_DIR}/provisioner.env" << 'EOF'
# Network Device Provisioner Environment Variables
# Populated during first-boot setup

# Device passwords
CAMBIUM_PASSWORD=
MIKROTIK_PASSWORD=
TARANA_PASSWORD=
TACHYON_PASSWORD=
UBIQUITI_PASSWORD=

# Notification webhooks (optional)
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=

# Analytics (optional)
ANALYTICS_API_KEY=
EOF
chmod 600 "${CONFIG_DIR}/provisioner.env"

log_info "Configuration files set up"

# --- Step 6: Install and enable systemd services ---
log_step "Installing systemd services"

cp "${INSTALL_DIR}/systemd/provisioner.service" /etc/systemd/system/provisioner.service
cp "${INSTALL_DIR}/systemd/provisioner-web.service" /etc/systemd/system/provisioner-web.service

# Enable ONLY provisioner-web — it runs the full provisioner *and* the web UI
# in one process (web_server.run_standalone() calls Provisioner.run()).
# Enabling provisioner.service as well would start a SECOND full provisioner:
# duplicate BOOTP listeners and port monitoring, so a single plugged-in device
# triggers two concurrent netinstalls that race on the interface IP
# ("Address already assigned"). The provisioner.service unit is kept on disk
# for headless (no-UI) deployments, but must not run alongside provisioner-web.
# systemctl enable just creates symlinks — works in chroot.
systemctl enable provisioner-web.service

log_info "Systemd services installed (provisioner-web enabled; runs provisioner + UI)"

# --- Step 7: Set Python capabilities ---
log_step "Setting network capabilities"

PYTHON_BIN="${VENV_DIR}/bin/python3"
if [[ -f "${PYTHON_BIN}" ]]; then
    setcap cap_net_raw,cap_net_admin+eip "${PYTHON_BIN}" 2>/dev/null || \
        log_warn "setcap failed (will retry at first boot)"
fi

log_info "Capabilities set"

# --- Step 8: Configure 8021q module for boot ---
log_step "Configuring VLAN kernel module"

if ! grep -q "^8021q" /etc/modules 2>/dev/null; then
    echo "8021q" >> /etc/modules
fi

log_info "8021q will load on boot"

# --- Step 9: Make scripts executable ---
chmod +x "${INSTALL_DIR}/scripts/"*.sh 2>/dev/null || true
chmod +x "${INSTALL_DIR}/image/"*.sh 2>/dev/null || true

# --- Step 10: Configure kiosk mode (optional) ---
if [[ "$KIOSK" == true && -n "${CHROMIUM_BIN:-}" ]]; then
    log_step "Configuring kiosk mode"

    # Create kiosk user
    if ! id "kiosk" &>/dev/null; then
        useradd -m -s /bin/bash kiosk
        usermod -aG video,input,tty kiosk
    fi

    KIOSK_HOME="/home/kiosk"

    # Openbox autostart
    mkdir -p "${KIOSK_HOME}/.config/openbox"
    cat > "${KIOSK_HOME}/.config/openbox/autostart" << AUTOSTART
# Idle screen handling — touch/keyboard/mouse wake naturally via libinput.
# 120s: screensaver blank.  300s: full DPMS off.
xset s 120 120
xset +dpms
xset dpms 120 120 300

# Hide cursor after 3 seconds of inactivity
unclutter -idle 3 -root &

# Wait for the web service to be ready before launching the browser.
# Otherwise on a slow boot Chromium hits its default error page and
# the kiosk can't escape from it.
for i in \$(seq 1 60); do
    if curl -fsS -o /dev/null --max-time 2 http://localhost:8080/; then
        break
    fi
    sleep 1
done

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

    # .xinitrc
    cat > "${KIOSK_HOME}/.xinitrc" << 'XINITRC'
#!/bin/bash
exec openbox-session
XINITRC
    chmod +x "${KIOSK_HOME}/.xinitrc"

    # Auto-start X on tty1
    cat > "${KIOSK_HOME}/.bash_profile" << 'BASHPROFILE'
if [[ -z $DISPLAY ]] && [[ $(tty) = /dev/tty1 ]]; then
    exec startx -- -nocursor
fi
BASHPROFILE

    chown -R kiosk:kiosk "${KIOSK_HOME}/.config" "${KIOSK_HOME}/.xinitrc" "${KIOSK_HOME}/.bash_profile"

    # Autologin on tty1
    mkdir -p /etc/systemd/system/getty@tty1.service.d
    cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf << 'AUTOLOGIN'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin kiosk --noclear %I $TERM
AUTOLOGIN

    # Kiosk watchdog service
    cat > "${INSTALL_DIR}/restart-kiosk.sh" << RESTART
#!/bin/bash
BROWSER="${CHROMIUM_BIN}"
while true; do
    if ! pgrep -x "\${BROWSER}" > /dev/null && ! pgrep -x "chromium" > /dev/null; then
        # Browser died — wake the screen so the relaunched browser is visible,
        # then wait for the web service before respawning.
        sudo -u kiosk DISPLAY=:0 xset dpms force on 2>/dev/null || true
        sudo -u kiosk DISPLAY=:0 xset s reset 2>/dev/null || true
        for i in \$(seq 1 30); do
            curl -fsS -o /dev/null --max-time 2 http://localhost:8080/ && break
            sleep 1
        done
        sudo -u kiosk DISPLAY=:0 \${BROWSER} \\
            --kiosk --noerrdialogs --disable-infobars \\
            http://localhost:8080 &
    fi
    sleep 10
done
RESTART
    chmod +x "${INSTALL_DIR}/restart-kiosk.sh"

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

    systemctl enable kiosk-watchdog.service

    # Auto-rotate daemon for convertible laptops (ThinkPad Yoga etc.)
    # Inert on hardware without an 'accel-display' iio sensor.
    install -m 0755 "${INSTALL_DIR}/image/auto-rotate.py" /usr/local/bin/auto-rotate.py
    install -m 0644 "${INSTALL_DIR}/image/auto-rotate.service" /etc/systemd/system/auto-rotate.service
    systemctl enable auto-rotate.service

    log_info "Kiosk mode configured"
fi

# --- Step 11: Clean up ---
log_step "Cleaning up"

apt-get clean
rm -rf /var/cache/apt/archives/*.deb
rm -rf /tmp/* /var/tmp/*

log_info "Chroot installation complete"
