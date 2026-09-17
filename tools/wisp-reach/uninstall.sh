#!/bin/bash
# Remove everything install.sh put in place.
set -euo pipefail
LABEL="com.isolson.wispreach"
AGENT="$HOME/Library/LaunchAgents/com.isolson.wispreach.plist"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$AGENT"
rm -rf "$HOME/Applications/WispReach.app"

echo "Removing privileged bits (needs sudo)…"
sudo rm -f /usr/local/libexec/wisp-net /etc/sudoers.d/wisp-net
echo "Done. (Any live aliases remain until you unplug/reboot or clear them with ifconfig.)"
