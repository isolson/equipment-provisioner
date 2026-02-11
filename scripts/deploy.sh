#!/bin/bash
# Deploy provisioner to the Pi at 192.168.1.120
# Usage: ./scripts/deploy.sh

set -e

TARGET_HOST="192.168.10.120"
TARGET_USER="orangepi"
TARGET_PATH="/opt/provisioner"

echo "Deploying to ${TARGET_USER}@${TARGET_HOST}:${TARGET_PATH}..."

rsync -avz --delete \
  --exclude='.git' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.venv' \
  --exclude='venv' \
  --exclude='.env' \
  --exclude='*.har' \
  --exclude='.context' \
  --exclude='firmware/' \
  ./ "${TARGET_USER}@${TARGET_HOST}:${TARGET_PATH}/"

echo "Restarting provisioner-web service..."
ssh "${TARGET_USER}@${TARGET_HOST}" 'sudo -n systemctl restart provisioner-web'

echo "Done. Checking service status..."
ssh "${TARGET_USER}@${TARGET_HOST}" 'SYSTEMD_PAGER= sudo -n systemctl status provisioner-web' 2>&1 | head -20
