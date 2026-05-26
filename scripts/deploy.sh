#!/bin/bash
# Deploy provisioner code to the running provisioner host.
# Usage: ./scripts/deploy.sh

set -e

TARGET_HOST="${PROVISIONER_HOST:-192.168.10.50}"
TARGET_USER="${PROVISIONER_USER:-serveradmin}"
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
  --exclude='tools/' \
  --exclude='restart-kiosk.sh' \
  ./ "${TARGET_USER}@${TARGET_HOST}:${TARGET_PATH}/"

echo "Restarting provisioner-web service..."
ssh "${TARGET_USER}@${TARGET_HOST}" 'sudo -n systemctl restart provisioner-web'

echo "Done. Checking service status..."
ssh "${TARGET_USER}@${TARGET_HOST}" 'SYSTEMD_PAGER= sudo -n systemctl status provisioner-web' 2>&1 | head -20
