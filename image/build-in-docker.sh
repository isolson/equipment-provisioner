#!/bin/bash
#
# Docker wrapper for building provisioner images on macOS (or any host)
#
# Usage:
#   ./image/build-in-docker.sh --platform rpi [--kiosk]
#   ./image/build-in-docker.sh --platform opi
#
# This builds a Docker container with all the required tools,
# then runs the image build inside it with --privileged (needed for
# loop devices and chroot).
#
# Output images are written to the image/ directory.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE_NAME="provisioner-image-builder"

# Check Docker is available
if ! command -v docker &>/dev/null; then
    echo "Error: Docker is not installed or not in PATH"
    echo "Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
    exit 1
fi

# Check Docker is running
if ! docker info &>/dev/null 2>&1; then
    echo "Error: Docker daemon is not running"
    echo "Start Docker Desktop and try again"
    exit 1
fi

# Build the builder image (cached after first run)
echo "Building Docker image for image builder..."
docker build -t "$IMAGE_NAME" -f "${SCRIPT_DIR}/Dockerfile.builder" "${REPO_DIR}"

# Run the build inside Docker
# --privileged is required for loop devices and chroot
echo ""
echo "Starting image build inside Docker..."
echo ""

docker run --rm \
    --privileged \
    -v "${REPO_DIR}:/build" \
    "$IMAGE_NAME" \
    "$@"

echo ""
echo "Done. Output image is in the image/ directory."
