#!/bin/bash
# Deploy provisioner code to the running provisioner host.
# Usage: ./scripts/deploy.sh [--allow-branch]
#
# Production deploys run from a checkout of the 'production' branch (the
# deploy pin — see docs/BRANCHING.md). Use --allow-branch to deploy a
# feature branch for hardware testing.

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

# Guard: production deploys come from the 'production' branch only.
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DIRTY=""
if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
  DIRTY="-dirty"
fi

if [[ "$BRANCH" != "production" && "$1" != "--allow-branch" ]]; then
  echo "REFUSING: on branch '$BRANCH', not 'production'."
  echo "Production deploys: run from a 'production' checkout (see docs/BRANCHING.md)."
  echo "Hardware-testing a feature branch: ./scripts/deploy.sh --allow-branch"
  exit 1
fi
if [[ -n "$DIRTY" ]]; then
  echo "WARNING: working tree is dirty; deploying uncommitted changes."
fi

echo "Deploying ${BRANCH}@${SHA}${DIRTY} to ${TARGET_USER}@${TARGET_HOST}:${TARGET_PATH}..."

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
  --exclude='.deployed-rev' \
  ./ "${TARGET_USER}@${TARGET_HOST}:${TARGET_PATH}/"

# Branch names may contain shell metacharacters; pass via stdin, not argv.
printf '%s %s %s\n' "${SHA}${DIRTY}" "$BRANCH" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | \
  $SSH_CMD "${TARGET_USER}@${TARGET_HOST}" "cat > ${TARGET_PATH}/.deployed-rev"

echo "Restarting provisioner-web service..."
$SSH_CMD "${TARGET_USER}@${TARGET_HOST}" 'sudo -n systemctl restart provisioner-web'

echo "Done. Checking service status..."
$SSH_CMD "${TARGET_USER}@${TARGET_HOST}" 'SYSTEMD_PAGER= sudo -n systemctl status provisioner-web' 2>&1 | head -20
