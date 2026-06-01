#!/usr/bin/env bash
# install.sh — build and install ward-os binaries + launchd agent
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
LAUNCHD_DIR="$HOME/Library/LaunchAgents"
PLIST_NAME="com.skerve.ward-guard.plist"
CONFIG_DIR="$HOME/.config/ward-os"

echo "╔══════════════════════════════════════╗"
echo "║  ward-os installer                   ║"
echo "╚══════════════════════════════════════╝"
echo

# ── 1. Build ────────────────────────────────────────────────────────────────
echo "▶ Building binaries..."
cd "$REPO_DIR"

# go-sqlite3 requires CGO
CGO_ENABLED=1 go build -o "$INSTALL_DIR/ward"       ./cmd/ward
CGO_ENABLED=1 go build -o "$INSTALL_DIR/ward-guard" ./cmd/ward-guard
CGO_ENABLED=1 go build -o "$INSTALL_DIR/ward-shell" ./cmd/ward-shell

echo "  Installed: $INSTALL_DIR/ward"
echo "  Installed: $INSTALL_DIR/ward-guard"
echo "  Installed: $INSTALL_DIR/ward-shell"

# ── 2. Config ───────────────────────────────────────────────────────────────
echo
echo "▶ Installing default config..."
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/ward.yaml" ]; then
  cp "$REPO_DIR/config/ward.yaml" "$CONFIG_DIR/ward.yaml"
  echo "  Written: $CONFIG_DIR/ward.yaml"
else
  echo "  Skipped (already exists): $CONFIG_DIR/ward.yaml"
fi

# ── 3. launchd plist ────────────────────────────────────────────────────────
echo
echo "▶ Installing launchd user agent (ward-guard auto-start on login)..."
mkdir -p "$LAUNCHD_DIR"

cat > "$LAUNCHD_DIR/$PLIST_NAME" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.skerve.ward-guard</string>

    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/ward-guard</string>
        <string>--config</string>
        <string>$CONFIG_DIR/ward.yaml</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>$HOME/.local/share/ward-os/ward-guard.log</string>

    <key>StandardErrorPath</key>
    <string>$HOME/.local/share/ward-os/ward-guard.error.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
EOF

echo "  Written: $LAUNCHD_DIR/$PLIST_NAME"

# ── 4. Load launchd agent ───────────────────────────────────────────────────
echo
echo "▶ Loading launchd agent..."
mkdir -p "$HOME/.local/share/ward-os"
launchctl unload "$LAUNCHD_DIR/$PLIST_NAME" 2>/dev/null || true
launchctl load  "$LAUNCHD_DIR/$PLIST_NAME"
echo "  ward-guard started as a user agent."

# ── 5. .cursorignore ────────────────────────────────────────────────────────
echo
echo "▶ Installing ~/.cursorignore..."
ward ignore install

# ── 6. Shell hook ────────────────────────────────────────────────────────────
echo
echo "▶ Installing vault auto-check shell hook..."
ward shell-init --install

# ── 7. Done ─────────────────────────────────────────────────────────────────
echo
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Installation complete!                                  ║"
echo "║                                                          ║"
echo "║  Next steps:                                             ║"
echo "║    ward vault create   — create the encrypted vault      ║"
echo "║    ward status         — check protection status         ║"
echo "║                                                          ║"
echo "║  To use ward-shell as your agent shell, set:            ║"
echo "║    terminal.integrated.shell.osx = /usr/local/bin/ward-shell ║"
echo "║  in Cursor / VS Code settings.                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
