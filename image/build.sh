#!/bin/bash
#
# Provisioner Image Builder
#
# Builds a flashable SD card image for Raspberry Pi or Orange Pi
# with the provisioner pre-installed and a first-boot wizard.
#
# Usage:
#   sudo ./image/build.sh --platform rpi [--kiosk] [--base-image PATH] [--output PATH]
#   sudo ./image/build.sh --platform opi [--kiosk] [--base-image PATH] [--output PATH]
#
# Requirements (Linux):
#   apt-get install qemu-user-static binfmt-support kpartx parted e2fsprogs rsync xz-utils wget
#
# On macOS, use the Docker wrapper instead:
#   ./image/build-in-docker.sh --platform rpi
#

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CACHE_DIR="${SCRIPT_DIR}/.cache"
WORK_DIR="${SCRIPT_DIR}/work"
IMAGE_SIZE="4G"
COMPRESS=true
PLATFORM=""
KIOSK=false
BASE_IMAGE=""
OUTPUT=""

# Base image URLs
RPI_IMAGE_URL="https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2024-11-19/2024-11-19-raspios-bookworm-arm64-lite.img.xz"
OPI_IMAGE_URL="https://dl.armbian.com/orangepi3-lts/Bookworm_current_minimal"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "\n${CYAN}${BOLD}==> $1${NC}"; }

# --- Cleanup trap ---
LOOP_DEV=""
ROOTFS=""
cleanup() {
    log_step "Cleaning up..."

    # Unmount in reverse order, ignore errors
    if [[ -n "$ROOTFS" ]]; then
        umount "${ROOTFS}/sys"      2>/dev/null || true
        umount "${ROOTFS}/proc"     2>/dev/null || true
        umount "${ROOTFS}/dev/pts"  2>/dev/null || true
        umount "${ROOTFS}/dev"      2>/dev/null || true
        umount "${ROOTFS}/tmp"      2>/dev/null || true
        # Boot partition (RPi only)
        umount "${ROOTFS}/boot/firmware" 2>/dev/null || true
        umount "${ROOTFS}/boot"     2>/dev/null || true
        # Rootfs
        umount "${ROOTFS}"          2>/dev/null || true
    fi

    # Detach loop device
    if [[ -n "$LOOP_DEV" ]]; then
        losetup -d "$LOOP_DEV" 2>/dev/null || true
    fi

    # Remove QEMU binary if left behind
    if [[ -n "$ROOTFS" && -f "${ROOTFS}/usr/bin/qemu-aarch64-static" ]]; then
        rm -f "${ROOTFS}/usr/bin/qemu-aarch64-static" 2>/dev/null || true
    fi

    log_info "Cleanup complete"
}
trap cleanup EXIT

# --- Parse arguments ---
usage() {
    echo "Usage: $0 --platform rpi|opi [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --platform rpi|opi    Target platform (required)"
    echo "  --base-image PATH     Path to stock .img or .img.xz (auto-downloads if omitted)"
    echo "  --output PATH         Output image path (default: provisioner-<platform>-<date>.img.xz)"
    echo "  --kiosk               Pre-install kiosk mode (Chromium fullscreen)"
    echo "  --image-size SIZE     Final image size (default: 4G)"
    echo "  --no-compress         Output raw .img instead of .img.xz"
    echo "  -h, --help            Show this help"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform)     PLATFORM="$2"; shift 2 ;;
        --base-image)   BASE_IMAGE="$2"; shift 2 ;;
        --output)       OUTPUT="$2"; shift 2 ;;
        --kiosk)        KIOSK=true; shift ;;
        --image-size)   IMAGE_SIZE="$2"; shift 2 ;;
        --no-compress)  COMPRESS=false; shift ;;
        -h|--help)      usage ;;
        *)              log_error "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$PLATFORM" ]]; then
    log_error "--platform is required (rpi or opi)"
    usage
fi

if [[ "$PLATFORM" != "rpi" && "$PLATFORM" != "opi" ]]; then
    log_error "Platform must be 'rpi' or 'opi', got: $PLATFORM"
    usage
fi

DATE=$(date +%Y-%m-%d)
if [[ -z "$OUTPUT" ]]; then
    OUTPUT="${SCRIPT_DIR}/provisioner-${PLATFORM}-${DATE}.img"
    if [[ "$COMPRESS" == true ]]; then
        OUTPUT="${OUTPUT}.xz"
    fi
fi

# --- Step 1: Validate prerequisites ---
log_step "Checking build host prerequisites"

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        log_error "Required command not found: $1"
        echo "  Install with: $2"
        return 1
    fi
}

MISSING=false
check_cmd losetup  "apt-get install mount"           || MISSING=true
check_cmd parted   "apt-get install parted"           || MISSING=true
check_cmd e2fsck   "apt-get install e2fsprogs"        || MISSING=true
check_cmd resize2fs "apt-get install e2fsprogs"       || MISSING=true
check_cmd rsync    "apt-get install rsync"            || MISSING=true
check_cmd xz       "apt-get install xz-utils"        || MISSING=true
check_cmd wget     "apt-get install wget"             || MISSING=true

# Check for QEMU
QEMU_BIN=""
if command -v qemu-aarch64-static &>/dev/null; then
    QEMU_BIN="qemu-aarch64-static"
elif command -v qemu-arm-static &>/dev/null; then
    QEMU_BIN="qemu-arm-static"
else
    log_error "qemu-aarch64-static not found"
    echo "  Install with: apt-get install qemu-user-static binfmt-support"
    MISSING=true
fi

if [[ "$MISSING" == true ]]; then
    echo ""
    log_error "Missing prerequisites. Install them and try again."
    echo "  Full install: apt-get install -y qemu-user-static binfmt-support kpartx parted e2fsprogs rsync xz-utils wget"
    exit 1
fi

# Check binfmt_misc is set up for ARM
if [[ ! -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ]] && [[ ! -f /proc/sys/fs/binfmt_misc/qemu-arm ]]; then
    log_warn "binfmt_misc may not be configured for ARM emulation"
    log_warn "If chroot fails, run: systemctl restart binfmt-support"
fi

if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (for loop mount and chroot)"
    exit 1
fi

log_info "All prerequisites OK"

# --- Step 2: Obtain base image ---
log_step "Obtaining base image"

mkdir -p "$CACHE_DIR" "$WORK_DIR"

if [[ -n "$BASE_IMAGE" ]]; then
    log_info "Using provided base image: $BASE_IMAGE"
    if [[ ! -f "$BASE_IMAGE" ]]; then
        log_error "Base image not found: $BASE_IMAGE"
        exit 1
    fi
    CACHED_IMAGE="$BASE_IMAGE"
else
    if [[ "$PLATFORM" == "rpi" ]]; then
        IMAGE_URL="$RPI_IMAGE_URL"
        CACHED_IMAGE="${CACHE_DIR}/rpi-base.img.xz"
    else
        IMAGE_URL="$OPI_IMAGE_URL"
        CACHED_IMAGE="${CACHE_DIR}/opi-base.img.xz"
    fi

    if [[ -f "$CACHED_IMAGE" ]]; then
        log_info "Using cached base image: $CACHED_IMAGE"
    else
        log_info "Downloading base image..."
        log_info "URL: $IMAGE_URL"
        wget -q --show-progress -O "$CACHED_IMAGE" "$IMAGE_URL"
        log_info "Download complete"
    fi
fi

# --- Step 3: Prepare working copy ---
log_step "Preparing working image"

WORK_IMG="${WORK_DIR}/provisioner-${PLATFORM}.img"

# Decompress if needed
if [[ "$CACHED_IMAGE" == *.xz ]]; then
    log_info "Decompressing base image..."
    xz -dkf "$CACHED_IMAGE" -c > "$WORK_IMG"
elif [[ "$CACHED_IMAGE" == *.zip ]]; then
    log_info "Unzipping base image..."
    unzip -o -p "$CACHED_IMAGE" '*.img' > "$WORK_IMG"
elif [[ "$CACHED_IMAGE" == *.gz ]]; then
    log_info "Decompressing base image..."
    gzip -dkf "$CACHED_IMAGE" -c > "$WORK_IMG"
else
    log_info "Copying base image..."
    cp "$CACHED_IMAGE" "$WORK_IMG"
fi

# Expand image
log_info "Expanding image to ${IMAGE_SIZE}..."
truncate -s "$IMAGE_SIZE" "$WORK_IMG"

# Grow the last partition to fill the image
log_info "Growing partition..."
PART_NUM=$(parted -ms "$WORK_IMG" print 2>/dev/null | tail -1 | cut -d: -f1)
parted -s "$WORK_IMG" resizepart "$PART_NUM" 100%

log_info "Working image prepared: $WORK_IMG"

# --- Step 4: Mount the image ---
log_step "Mounting image"

LOOP_DEV=$(losetup --find --show --partscan "$WORK_IMG")
log_info "Loop device: $LOOP_DEV"

# Wait for partition devices to appear
sleep 1

# Detect partition layout
# RPi OS: p1=boot(FAT32), p2=rootfs(ext4)
# Armbian: p1=rootfs(ext4) — boot is inside rootfs
ROOTFS="${WORK_DIR}/rootfs"
mkdir -p "$ROOTFS"

if [[ "$PLATFORM" == "rpi" ]]; then
    ROOTFS_PART="${LOOP_DEV}p2"
    BOOT_PART="${LOOP_DEV}p1"

    # Check and resize rootfs
    e2fsck -fy "$ROOTFS_PART" || true
    resize2fs "$ROOTFS_PART"

    mount "$ROOTFS_PART" "$ROOTFS"

    # RPi OS bookworm uses /boot/firmware
    if [[ -d "${ROOTFS}/boot/firmware" ]]; then
        mount "$BOOT_PART" "${ROOTFS}/boot/firmware"
        BOOT_DIR="${ROOTFS}/boot/firmware"
    else
        mount "$BOOT_PART" "${ROOTFS}/boot"
        BOOT_DIR="${ROOTFS}/boot"
    fi
    log_info "Mounted rootfs and boot partition"
else
    ROOTFS_PART="${LOOP_DEV}p1"

    e2fsck -fy "$ROOTFS_PART" || true
    resize2fs "$ROOTFS_PART"

    mount "$ROOTFS_PART" "$ROOTFS"
    BOOT_DIR="${ROOTFS}/boot"
    log_info "Mounted rootfs (boot inside rootfs)"
fi

# --- Step 5: Prepare chroot ---
log_step "Preparing chroot environment"

# Copy QEMU binary
QEMU_PATH=$(which "$QEMU_BIN")
cp "$QEMU_PATH" "${ROOTFS}/usr/bin/"
log_info "Copied $QEMU_BIN into image"

# Mount special filesystems
mount --bind /dev     "${ROOTFS}/dev"
mount --bind /dev/pts "${ROOTFS}/dev/pts"
mount -t proc proc    "${ROOTFS}/proc"
mount -t sysfs sysfs  "${ROOTFS}/sys"
mount -t tmpfs tmpfs  "${ROOTFS}/tmp"

# DNS resolution
cp /etc/resolv.conf "${ROOTFS}/etc/resolv.conf"

log_info "Chroot environment ready"

# --- Step 6: Copy provisioner source ---
log_step "Copying provisioner source into image"

rsync -a \
    --exclude='.git' \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='image/.cache' \
    --exclude='image/work' \
    --exclude='image/*.img*' \
    --exclude='.context' \
    "${REPO_DIR}/" "${ROOTFS}/opt/provisioner/"

log_info "Source copied to /opt/provisioner"

# --- Step 7: Run chroot installation ---
log_step "Installing provisioner in chroot (this may take a while)"

CHROOT_ARGS=""
if [[ "$KIOSK" == true ]]; then
    CHROOT_ARGS="--kiosk"
fi

chmod +x "${ROOTFS}/opt/provisioner/image/chroot-install.sh"
chroot "$ROOTFS" /opt/provisioner/image/chroot-install.sh $CHROOT_ARGS

log_info "Chroot installation complete"

# --- Step 8: Install first-boot service ---
log_step "Installing first-boot service"

# Copy first-boot script
chmod +x "${ROOTFS}/opt/provisioner/image/first-boot.sh"

# Install systemd service
cp "${ROOTFS}/opt/provisioner/image/firstboot.service" \
   "${ROOTFS}/etc/systemd/system/firstboot.service"

# Enable the service (creates symlink, works in chroot)
chroot "$ROOTFS" systemctl enable firstboot.service

# Create sentinel file — first-boot.sh removes this when done
touch "${ROOTFS}/opt/provisioner/.first-boot"

log_info "First-boot service installed and enabled"

# --- Step 9: Platform-specific configuration ---
log_step "Applying platform-specific configuration"

# Export variables for platform config scripts
export ROOTFS BOOT_DIR KIOSK PLATFORM

if [[ "$PLATFORM" == "rpi" ]]; then
    source "${SCRIPT_DIR}/config/rpi-config.sh"
else
    source "${SCRIPT_DIR}/config/opi-config.sh"
fi

log_info "Platform configuration applied"

# --- Step 10: Clean up chroot ---
log_step "Cleaning up chroot"

# Clean apt caches
chroot "$ROOTFS" apt-get clean
chroot "$ROOTFS" rm -rf /var/cache/apt/archives/*.deb /tmp/* /var/tmp/*

# Remove QEMU binary
rm -f "${ROOTFS}/usr/bin/${QEMU_BIN}"

# Restore resolv.conf (some images use a symlink)
rm -f "${ROOTFS}/etc/resolv.conf"
chroot "$ROOTFS" bash -c 'ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || true'

# Unmount special filesystems
umount "${ROOTFS}/sys"
umount "${ROOTFS}/proc"
umount "${ROOTFS}/dev/pts"
umount "${ROOTFS}/dev"
umount "${ROOTFS}/tmp"

# Unmount boot and rootfs
if [[ "$PLATFORM" == "rpi" ]]; then
    umount "$BOOT_DIR"
fi
umount "$ROOTFS"

# Detach loop device
losetup -d "$LOOP_DEV"
LOOP_DEV=""  # Prevent cleanup trap from trying again
ROOTFS=""

log_info "Chroot cleaned up, image unmounted"

# --- Step 11: Shrink and compress ---
log_step "Finalizing image"

# Try PiShrink if available
if command -v pishrink.sh &>/dev/null; then
    log_info "Shrinking image with PiShrink..."
    pishrink.sh -s "$WORK_IMG"
fi

if [[ "$COMPRESS" == true ]]; then
    log_info "Compressing image (this may take a while)..."
    FINAL_OUTPUT="${OUTPUT}"
    xz -T0 -9 -f "$WORK_IMG"
    mv "${WORK_IMG}.xz" "$FINAL_OUTPUT"
    FINAL_SIZE=$(du -h "$FINAL_OUTPUT" | cut -f1)
    log_info "Compressed image: $FINAL_OUTPUT ($FINAL_SIZE)"
else
    FINAL_OUTPUT="${OUTPUT%.xz}"
    mv "$WORK_IMG" "$FINAL_OUTPUT"
    FINAL_SIZE=$(du -h "$FINAL_OUTPUT" | cut -f1)
    log_info "Raw image: $FINAL_OUTPUT ($FINAL_SIZE)"
fi

# --- Done ---
echo ""
echo -e "${GREEN}${BOLD}Build complete!${NC}"
echo ""
echo "Output: $FINAL_OUTPUT"
echo ""
echo "To flash:"
if [[ "$COMPRESS" == true ]]; then
    echo "  xz -dc $FINAL_OUTPUT | sudo dd of=/dev/sdX bs=4M status=progress"
else
    echo "  sudo dd if=$FINAL_OUTPUT of=/dev/sdX bs=4M status=progress"
fi
echo ""
echo "  Or use Balena Etcher (handles .img.xz natively)"
echo ""
echo "On first boot, a setup wizard will guide you through configuration."
echo ""
