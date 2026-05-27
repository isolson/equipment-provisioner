#!/bin/bash
# Deploy provisioner code to the running provisioner host.
# Usage: ./scripts/deploy.sh

set -e

TARGET_HOST="${PROVISIONER_HOST:-192.168.10.50}"
TARGET_USER="${PROVISIONER_USER:-serveradmin}"
TARGET_PATH="/opt/provisioner"

# Pick the SSH identity explicitly.  Without this, a 1Password (or other)
# SSH agent will offer its own keys first and burn through MaxAuthTries
# before our key is tried, causing "Too many authentication failures".
# IdentitiesOnly=yes tells ssh to ignore the agent and only use this key.
# Override either with SSH_KEY=... or SSH_OPTS=... (set empty to disable).
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_conductor}"
if [[ -z "${SSH_OPTS+x}" ]]; then
  if [[ -f "$SSH_KEY" ]]; then
    SSH_OPTS="-i $SSH_KEY -o IdentitiesOnly=yes"
  else
    SSH_OPTS=""
  fi
fi
SSH_CMD="ssh $SSH_OPTS"

echo "Deploying to ${TARGET_USER}@${TARGET_HOST}:${TARGET_PATH}..."

rsync -avz --delete \
  -e "$SSH_CMD" \
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
$SSH_CMD "${TARGET_USER}@${TARGET_HOST}" 'sudo -n systemctl restart provisioner-web'

echo "Done. Checking service status..."
$SSH_CMD "${TARGET_USER}@${TARGET_HOST}" 'SYSTEMD_PAGER= sudo -n systemctl status provisioner-web' 2>&1 | head -20
