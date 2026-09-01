#!/bin/bash
#
# WISP-Reach installer.
#   - builds the menu-bar app (Swift Package Manager, release)
#   - assembles WispReach.app into ~/Applications
#   - installs the root helper to /usr/local/libexec (root:wheel, 0755)
#   - installs a scoped NOPASSWD sudoers drop-in (validated with visudo)
#   - installs + loads a per-user LaunchAgent (start at login)
#
# One password prompt up front (primed via `sudo -v`), silent thereafter.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_NAME="$(id -un)"
APP_DIR="$HOME/Applications/WispReach.app"
HELPER_DST="/usr/local/libexec/wisp-net"
SUDOERS_DST="/etc/sudoers.d/wisp-net"
AGENT_DST="$HOME/Library/LaunchAgents/com.isolson.wispreach.plist"
LOG_PATH="$HOME/Library/Logs/wisp-reach.log"
LABEL="com.isolson.wispreach"

echo "==> Checking toolchain"
command -v swift >/dev/null || { echo "swift not found — install Xcode command line tools (xcode-select --install)"; exit 1; }

echo "==> Building (release)"
( cd "$HERE" && swift build -c release )
BIN="$(cd "$HERE" && swift build -c release --show-bin-path)/WispReach"
[ -x "$BIN" ] || { echo "build did not produce $BIN"; exit 1; }

echo "==> Assembling app bundle at $APP_DIR"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS"
cp "$BIN" "$APP_DIR/Contents/MacOS/WispReach"
cp "$HERE/packaging/WispReach.app.template/Info.plist" "$APP_DIR/Contents/Info.plist"
APP_BINARY="$APP_DIR/Contents/MacOS/WispReach"

echo "==> Elevating (single prompt)"
sudo -v

echo "==> Installing helper to $HELPER_DST"
sudo mkdir -p /usr/local/libexec
sudo install -o root -g wheel -m 0755 "$HERE/helper/wisp-net" "$HELPER_DST"

echo "==> Installing sudoers drop-in"
TMP_SUDO="$(mktemp)"
sed "s/__USER__/$USER_NAME/" "$HERE/packaging/wisp-net.sudoers" > "$TMP_SUDO"
if sudo visudo -cf "$TMP_SUDO" >/dev/null; then
  sudo install -o root -g wheel -m 0440 "$TMP_SUDO" "$SUDOERS_DST"
  rm -f "$TMP_SUDO"
else
  rm -f "$TMP_SUDO"
  echo "sudoers validation failed — aborting"; exit 1
fi

echo "==> Installing LaunchAgent"
mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
sed -e "s#__APP_BINARY__#$APP_BINARY#" -e "s#__LOG_PATH__#$LOG_PATH#" \
  "$HERE/packaging/com.isolson.wispreach.plist" > "$AGENT_DST"

# (Re)load the agent.
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$AGENT_DST"
launchctl enable "gui/$(id -u)/$LABEL" 2>/dev/null || true

echo
echo "==> Done."
echo "    App:      $APP_DIR"
echo "    Helper:   $HELPER_DST"
echo "    Sudoers:  $SUDOERS_DST"
echo "    Agent:    $AGENT_DST  (running now, starts at login)"
echo "    Log:      $LOG_PATH"
echo
echo "Plug in a USB Ethernet dongle — aliases apply automatically."
echo "Click the network icon in the menu bar for presets / Clear."
