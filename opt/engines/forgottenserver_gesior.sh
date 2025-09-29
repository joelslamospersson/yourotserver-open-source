#!/usr/bin/env bash
set -euo pipefail

# ────────────────────────── Config ──────────────────────────
GITHUB_REPO="https://github.com/gesior/forgottenserver-gesior"
ZIP_NAME="forgottenserver-gesior-compilation.zip"
SRC_DIR_NAME="forgottenserver-gesior-source"   # temporary directory name, rename to tfs for web-engine scripts

log(){ echo -e "\n>>> $*"; }
die(){ echo -e "\nERROR: $*" >&2; exit 1; }

# Pick the real user even if running via sudo
APP_USER="${SUDO_USER:-$USER}"
APP_HOME="$(getent passwd "$APP_USER" | cut -d: -f6)"
TFS_DIR="$APP_HOME/tfs"

# ────────────────────────── Pre-flight ──────────────────────
log "Updating apt and installing required packages…"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ufw git cmake build-essential unzip \
  libluajit-5.1-dev libmysqlclient-dev \
  libboost-system-dev libboost-iostreams-dev libboost-filesystem-dev libboost-date-time-dev libboost-locale-dev \
  libpugixml-dev libcrypto++-dev libfmt-dev

# ────────────────────────── UFW ─────────────────────────────
log "Configuring UFW (allow 7171/tcp, 7172/tcp) and enabling firewall…"
ufw allow 7171/tcp || true
ufw allow 7172/tcp || true
# Enable UFW if not already enabled
if ! ufw status | grep -q "Status: active"; then
  echo "y" | ufw enable
fi

# ────────────────────────── Get sources ─────────────────────
log "Ensuring working dir exists for $APP_USER…"
install -d -o "$APP_USER" -g "$APP_USER" "$APP_HOME"

cd "$APP_HOME"

if [[ ! -f "$ZIP_NAME" ]]; then
  log "Downloading latest source from GitHub: $GITHUB_REPO"
  # Download the latest compilation branch as zip
  DOWNLOAD_URL="${GITHUB_REPO}/archive/refs/heads/compilation.zip"
  # Prefer curl, fall back to wget
  if command -v curl >/dev/null 2>&1; then
    curl -fL "$DOWNLOAD_URL" -o "$ZIP_NAME"
  else
    wget -O "$ZIP_NAME" "$DOWNLOAD_URL"
  fi
fi

log "Unzipping sources…"
# Clean previous extracted directory if present
rm -rf "$SRC_DIR_NAME"
unzip -q -o "$ZIP_NAME"

# GitHub archives extract with format: forgottenserver-gesior-compilation
# Rename to expected directory name
if [[ -d "forgottenserver-gesior-compilation" ]]; then
  mv "forgottenserver-gesior-compilation" "$SRC_DIR_NAME"
fi

# ────────────────────────── Prepare tree ────────────────────
# Move/rename to ~/tfs
log "Preparing source directory at: $TFS_DIR"
rm -rf "$TFS_DIR"
mv "$SRC_DIR_NAME" "$TFS_DIR"

# Ensure ownership to the actual user (not root)
chown -R "$APP_USER:$APP_USER" "$TFS_DIR"

# ────────────────────────── Build TFS ───────────────────────
log "Building TFS (Release) with all CPU cores…"
cd "$TFS_DIR"
# Out-of-source build
rm -rf build
install -d -o "$APP_USER" -g "$APP_USER" build
cd build
# Configure
cmake -DCMAKE_BUILD_TYPE=Release ..
# Compile
make -j"$(nproc)"

# ────────────────────────── Place binary ────────────────────
# Handle different CMake layouts (bin/tfs, tfs in build root, src/tfs)
BIN_PATH=""

for p in "$TFS_DIR/build/bin/tfs" "$TFS_DIR/build/tfs" "$TFS_DIR/build/src/tfs"; do
  if [[ -x "$p" ]]; then BIN_PATH="$p"; break; fi
done

if [[ -z "$BIN_PATH" ]]; then
  # Last resort: search for an executable named 'tfs' within build/*
  BIN_PATH="$(find "$TFS_DIR/build" -maxdepth 3 -type f -name tfs -perm -111 | head -n1 || true)"
fi

if [[ -n "$BIN_PATH" && -x "$BIN_PATH" ]]; then
  log "Placing compiled binary into $TFS_DIR/tfs (from ${BIN_PATH#$TFS_DIR/})"
  cp "$BIN_PATH" "$TFS_DIR/tfs"
  chown "$APP_USER:$APP_USER" "$TFS_DIR/tfs"
else
  echo "ERROR: Compiled binary 'tfs' not found under $TFS_DIR/build" >&2
  find "$TFS_DIR/build" -maxdepth 3 -type f -name tfs 2>/dev/null || true
  exit 1
fi

# ────────────────────────── Config file ─────────────────────
log "Setting up config.lua…"
cd "$TFS_DIR"

# ─────────────── Patch (or create) config.lua ───────────────────────────────
CONFIG_DIST="$TFS_DIR/config.lua.dist"
CONFIG_FILE="$TFS_DIR/config.lua"

if [[ -f "$CONFIG_FILE" ]]; then
  log "Found existing config.lua – patching IP in place"
elif [[ -f "$CONFIG_DIST" ]]; then
  log "No config.lua, copying from config.lua.dist"; cp "$CONFIG_DIST" "$CONFIG_FILE"
else
  die "Neither $CONFIG_FILE nor $CONFIG_DIST found!"
fi

IPV4="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)"
[[ -z "$IPV4" ]] && IPV4="$(hostname -I | awk '{print $1}')"
IPV4="${IPV4:-127.0.0.1}"
sed -i -E "s|^([[:space:]]*ip[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\")|\1${IPV4}\2|" "$CONFIG_FILE"
chown "$APP_USER:$APP_USER" "$CONFIG_FILE"
log "Patched $CONFIG_FILE with ip = \"$IPV4\""

# ────────────────────────── Summary ─────────────────────────
log "Done!"
echo "TFS directory:     $TFS_DIR"
echo "Binary:            $TFS_DIR/tfs"
echo "Config:            $TFS_DIR/config.lua"
echo "Ports opened:      7171/tcp, 7172/tcp (UFW)"
echo "To run TFS:        cd \"$TFS_DIR\" && ./tfs"
