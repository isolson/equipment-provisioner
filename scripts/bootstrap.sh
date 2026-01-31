#!/bin/bash
#
# Provisioner Bootstrap Script
# Downloads the repo and runs the unified setup.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/isolson/equipment-provisioner/main/scripts/bootstrap.sh | sudo bash
#

set -e

REPO_URL="https://github.com/isolson/equipment-provisioner.git"
INSTALL_DIR="/opt/provisioner"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Install git if missing
if ! command -v git &>/dev/null; then
    echo -e "${GREEN}Installing git...${NC}"
    apt-get update -qq && apt-get install -y -qq git
fi

# Clone or update the repo
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    echo -e "${GREEN}Updating existing installation...${NC}"
    cd "$INSTALL_DIR" && git pull --ff-only
else
    echo -e "${GREEN}Cloning provisioner to ${INSTALL_DIR}...${NC}"
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

# Hand off to the unified setup script
exec bash "${INSTALL_DIR}/scripts/setup.sh"
