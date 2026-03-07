#!/bin/bash
#
# Orange Pi platform-specific configuration
#
# Sourced by build.sh after chroot installation.
# Expects: $ROOTFS, $BOOT_DIR, $KIOSK, $PLATFORM
#

log_info "Applying Orange Pi / Armbian configuration"

# Disable Armbian's first-run wizard (conflicts with ours)
rm -f "${ROOTFS}/root/.not_logged_in_yet"
log_info "Disabled Armbian first-run wizard"

# Set root password to 'provisioner'
chroot "$ROOTFS" bash -c 'echo "root:provisioner" | chpasswd'
log_info "Root password set (root:provisioner)"

# Set hostname
echo "provisioner" > "${ROOTFS}/etc/hostname"
sed -i 's/orangepi[^ ]*/provisioner/g' "${ROOTFS}/etc/hosts" 2>/dev/null || true
# Also handle generic armbian hostname
sed -i 's/armbian/provisioner/g' "${ROOTFS}/etc/hosts" 2>/dev/null || true
log_info "Hostname set to 'provisioner'"

# Ensure SSH is enabled
chroot "$ROOTFS" systemctl enable ssh 2>/dev/null || \
    chroot "$ROOTFS" systemctl enable sshd 2>/dev/null || true
log_info "SSH enabled"

# Disable Armbian MOTD generation on first login (optional, keeps console clean)
rm -f "${ROOTFS}/etc/update-motd.d/10-armbian-header" 2>/dev/null || true

log_info "Orange Pi configuration complete"
