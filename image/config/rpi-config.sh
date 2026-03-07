#!/bin/bash
#
# Raspberry Pi platform-specific configuration
#
# Sourced by build.sh after chroot installation.
# Expects: $ROOTFS, $BOOT_DIR, $KIOSK, $PLATFORM
#

log_info "Applying Raspberry Pi configuration"

# Enable SSH on first boot
touch "${BOOT_DIR}/ssh"
log_info "SSH enabled"

# Set hostname
echo "provisioner" > "${ROOTFS}/etc/hostname"
sed -i 's/raspberrypi/provisioner/g' "${ROOTFS}/etc/hosts" 2>/dev/null || true
log_info "Hostname set to 'provisioner'"

# Create default user (pi:provisioner)
# RPi OS bookworm requires userconf.txt for the initial user
# Hash generated with: echo 'provisioner' | openssl passwd -6 -stdin
USER_HASH='$6$rounds=656000$pPNOq5x3kVfGbKBv$wFQ.YfNMqEyKlVX8G/JBqo5jLXXxVpqNEjFM6OPC8HcVZBSqWfCJP5YL0MjXm5RB8tTU/47fV.1bM3P0mJKPi/'
echo "pi:${USER_HASH}" > "${BOOT_DIR}/userconf.txt"
log_info "Default user created (pi:provisioner)"

# HDMI display settings for 7" touchscreen (kiosk mode)
if [[ "$KIOSK" == true ]]; then
    CONFIG_TXT="${BOOT_DIR}/config.txt"
    if [[ -f "$CONFIG_TXT" ]]; then
        cat >> "$CONFIG_TXT" << 'EOF'

# Provisioner display settings (7" touchscreen)
hdmi_force_hotplug=1
hdmi_group=2
hdmi_mode=87
hdmi_cvt=1024 600 60 6 0 0 0
max_usb_current=1
EOF
        log_info "HDMI display configured for 7\" touchscreen"
    fi
fi

# Ensure SSH service is enabled
chroot "$ROOTFS" systemctl enable ssh 2>/dev/null || true

log_info "Raspberry Pi configuration complete"
