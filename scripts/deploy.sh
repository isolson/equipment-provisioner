#!/bin/bash
# Deploy provisioner code to the running provisioner host.
# Usage: ./scripts/deploy.sh [--allow-branch] [--skip-tests] [--rollback]
#
# Production deploys run from a checkout of the 'production' branch (the
# deploy pin — see docs/BRANCHING.md). Use --allow-branch to deploy a
# feature branch for hardware testing.
#
# Guardrails (see docs/BRANCHING.md "Deploy guardrails"):
#   1. Pre-deploy test gate — the full pytest suite must pass before anything
#      is pushed. Bypass only with --skip-tests (discouraged; prints a warning).
#   2. Branch guard — refuses off-'production' unless --allow-branch, which
#      prints a prominent warning so a stray feature deploy is never silent.
#   3. Rollback snapshot — the current on-host tree is copied to
#      /opt/provisioner.prev before every deploy; `--rollback` restores it.
#   4. Post-deploy health check — verifies the service is active, boots without
#      a traceback, and serves /ports; a failure exits non-zero and prints the
#      rollback command.

set -euo pipefail

TARGET_HOST="${PROVISIONER_HOST:-192.168.10.50}"
TARGET_USER="${PROVISIONER_USER:-serveradmin}"
TARGET_PATH="/opt/provisioner"
PREV_PATH="/opt/provisioner.prev"

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
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- argument parsing ------------------------------------------------------
ALLOW_BRANCH=0
SKIP_TESTS=0
ROLLBACK=0
for arg in "$@"; do
  case "$arg" in
    --allow-branch) ALLOW_BRANCH=1 ;;
    --skip-tests)   SKIP_TESTS=1 ;;
    --rollback)     ROLLBACK=1 ;;
    *) echo "Unknown argument: $arg"; echo "Usage: $0 [--allow-branch] [--skip-tests] [--rollback]"; exit 2 ;;
  esac
done

health_check() {
  # Returns 0 if the freshly-restarted service is healthy, 1 otherwise.
  echo "Running post-deploy health check..."
  local ok=1

  # /health is the root-level liveness endpoint. The service does heavy async
  # startup (BOOTP listeners, per-port detection scans), so poll rather than
  # sleeping a fixed amount.
  local code="000"
  local i
  for i in $(seq 1 15); do
    code="$($SSH_CMD "${TARGET_USER}@${TARGET_HOST}" \
      'curl -s -m 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/health' 2>/dev/null || echo 000)"
    [[ "$code" == "200" ]] && break
    sleep 2
  done
  if [[ "$code" == "200" ]]; then
    echo "  ✓ /health responds 200"
  else
    echo "  ✗ /health returned '$code' after ~30s"; ok=0
  fi

  if $SSH_CMD "${TARGET_USER}@${TARGET_HOST}" 'systemctl is-active --quiet provisioner-web'; then
    echo "  ✓ provisioner-web active"
  else
    echo "  ✗ provisioner-web is not active"; ok=0
  fi

  # Boot-crash signatures from a missed registry site (see CLAUDE.md S1 list).
  # Match the specific fatal exception types, NOT a bare "Traceback" — the
  # service logs a benign asyncio CancelledError traceback on every startup.
  if $SSH_CMD "${TARGET_USER}@${TARGET_HOST}" \
       'SYSTEMD_PAGER= sudo -n journalctl -u provisioner-web --since "90 sec ago" --no-pager -o cat 2>/dev/null | grep -qE "ImportError|ModuleNotFoundError|AttributeError|NameError|SyntaxError"'; then
    echo "  ✗ import/attribute error in recent logs (boot-crash signature)"; ok=0
  else
    echo "  ✓ no import/attribute error in recent logs"
  fi
  [[ "$ok" == "1" ]]
}

# --- rollback --------------------------------------------------------------
if [[ "$ROLLBACK" == "1" ]]; then
  echo "ROLLBACK: restoring ${PREV_PATH} → ${TARGET_PATH} on ${TARGET_USER}@${TARGET_HOST}..."
  if ! $SSH_CMD "${TARGET_USER}@${TARGET_HOST}" "test -d ${PREV_PATH}"; then
    echo "REFUSING: no ${PREV_PATH} snapshot on the host — nothing to roll back to."
    exit 1
  fi
  $SSH_CMD "${TARGET_USER}@${TARGET_HOST}" \
    "sudo -n rsync -a --delete --exclude venv --exclude .git ${PREV_PATH}/ ${TARGET_PATH}/ && \
     ([ -f ${PREV_PATH}/.deployed-rev ] && sudo -n cp ${PREV_PATH}/.deployed-rev ${TARGET_PATH}/.deployed-rev || true)"
  echo "Restarting provisioner-web service..."
  $SSH_CMD "${TARGET_USER}@${TARGET_HOST}" 'sudo -n systemctl restart provisioner-web'
  if health_check; then
    echo "Rollback complete and healthy. Deployed rev:"
    $SSH_CMD "${TARGET_USER}@${TARGET_HOST}" "cat ${TARGET_PATH}/.deployed-rev" || true
  else
    echo "WARNING: rollback restored but health check FAILED — investigate on the host."
    exit 1
  fi
  exit 0
fi

# --- branch + dirty state --------------------------------------------------
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DIRTY=""
if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
  DIRTY="-dirty"
fi

if [[ "$BRANCH" != "production" && "$ALLOW_BRANCH" != "1" ]]; then
  echo "REFUSING: on branch '$BRANCH', not 'production'."
  echo "Production deploys: run from a 'production' checkout (see docs/BRANCHING.md)."
  echo "Hardware-testing a feature branch: ./scripts/deploy.sh --allow-branch"
  exit 1
fi
if [[ "$BRANCH" != "production" && "$ALLOW_BRANCH" == "1" ]]; then
  echo "############################################################"
  echo "# WARNING: deploying NON-PRODUCTION branch '$BRANCH'"
  echo "# This is for hardware testing only. Re-deploy from"
  echo "# 'production' when done (see docs/BRANCHING.md)."
  echo "############################################################"
fi
if [[ -n "$DIRTY" ]]; then
  echo "WARNING: working tree is dirty; deploying uncommitted changes."
fi

# --- pre-deploy test gate --------------------------------------------------
if [[ "$SKIP_TESTS" == "1" ]]; then
  echo "WARNING: --skip-tests set; deploying WITHOUT running the test suite."
else
  echo "Running pre-deploy test gate (pytest)..."
  if ! command -v python3 >/dev/null 2>&1; then
    echo "REFUSING: python3 not found to run the test gate. Use --skip-tests to override."
    exit 1
  fi
  if ! python3 -m pytest --version >/dev/null 2>&1; then
    echo "REFUSING: pytest not installed to run the test gate. Use --skip-tests to override."
    exit 1
  fi
  if ! ( cd "$REPO_ROOT" && python3 -m pytest -q -o addopts="" ); then
    echo "REFUSING: test suite failed — fix it or deploy with --skip-tests (discouraged)."
    exit 1
  fi
  echo "Test gate passed."
fi

echo "Deploying ${BRANCH}@${SHA}${DIRTY} to ${TARGET_USER}@${TARGET_HOST}:${TARGET_PATH}..."

# Snapshot the current on-host tree for one-command rollback (excludes venv/.git
# so it stays small; venv is host-built and unchanged by deploys).
echo "Snapshotting current deploy to ${PREV_PATH} (for --rollback)..."
$SSH_CMD "${TARGET_USER}@${TARGET_HOST}" \
  "test -d ${TARGET_PATH} && sudo -n rsync -a --delete --exclude venv --exclude .git ${TARGET_PATH}/ ${PREV_PATH}/ || echo '(no existing deploy to snapshot)'"

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

if health_check; then
  echo "Done. Deploy healthy."
else
  echo "############################################################"
  echo "# DEPLOY UNHEALTHY — the new code is live but failing checks."
  echo "# Roll back with:  ./scripts/deploy.sh --rollback"
  echo "############################################################"
  # Redacted log tail — never dump `systemctl status` (its process list
  # exposes device passwords passed as curl/sshpass argv).
  echo "Recent log tail (secrets filtered):"
  $SSH_CMD "${TARGET_USER}@${TARGET_HOST}" \
    'SYSTEMD_PAGER= sudo -n journalctl -u provisioner-web --since "90 sec ago" --no-pager -o cat 2>/dev/null | grep -ivE "password|username|sshpass|curl .*-d |cgi-bin" | tail -20'
  exit 1
fi
