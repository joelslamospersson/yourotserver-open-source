#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

die(){ echo "ERROR: $*" >&2; exit 1; }
log(){ echo -e "\n>>> $*"; }

# ────────────────────────── Parse args ──────────────────────────────────────
# Current simplified pattern: l_canary.sh IPV4_ADDRESS APP_USER
# Legacy fallback: l_canary.sh APP_USER (auto-detect IP)
# Old code goes BRRRRRRRRRRRRRRRRRR
if [[ $# -eq 2 ]]; then
    # New simplified pattern: IPV4_ADDRESS APP_USER
    IPV4="${1}"
    APP_USER="${2}"
    log "Using simplified argument pattern: APP_USER=${APP_USER}, IPV4=${IPV4}"
elif [[ $# -eq 1 ]]; then
    # Legacy pattern: APP_USER (auto-detect IP)
    APP_USER="${1}"
    IPV4=$(curl -s -4 ifconfig.me || curl -s -4 ipinfo.io/ip || echo "127.0.0.1")
    log "Using legacy argument pattern: APP_USER=${APP_USER}, detected IP=${IPV4}"
else
    # Fallback
    # Fuck is this shit?
    APP_USER="${1:-${SUDO_USER:-}}"
    IPV4=$(curl -s -4 ifconfig.me || curl -s -4 ipinfo.io/ip || echo "127.0.0.1")
    log "Using fallback: APP_USER=${APP_USER}, detected IP=${IPV4}"
fi
[[ -n "$APP_USER" ]] || die "APP_USER must be specified as argument"
[[ -n "$IPV4" ]] || die "IPV4 address must be available"
[[ $EUID -eq 0 ]] || die "Must run as root"

# ───────────────────────── USER / HOME ──────────────────────────────────────
USER_HOME="/home/${APP_USER}"
export HOME="$USER_HOME"

log "Using server IP for config.lua: $IPV4"

log "Latest Canary setup starting..."

# ────────────────────────── System Updates & Dependencies ──────────────────────
log "Updating system and installing dependencies..."
# Single apt update and batch install for speed
apt update && apt install -y \
  git build-essential autoconf libtool ca-certificates curl zip unzip tar \
  pkg-config ninja-build ccache linux-headers-$(uname -r) \
  snapd gcc-14 g++-14 \
  software-properties-common

# Remove old cmake and install via snap (parallel with other operations)
apt remove --purge cmake -y || true
hash -r || true

log "Installing latest CMake via snap..."
snap install cmake --classic
cmake --version || die "CMake installation failed"

# ────────────────────────── Setup GCC-14 ──────────────────────────────────
log "Setting up GCC-14..."
update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 --slave /usr/bin/g++ g++ /usr/bin/g++-14 --slave /usr/bin/gcov gcov /usr/bin/gcov-14
  update-alternatives --set gcc /usr/bin/gcc-14
gcc-14 --version
g++-14 --version

# ────────────────────────── Setup vcpkg ──────────────────────────────────
log "Setting up vcpkg..."
cd "$USER_HOME"
if [[ -d "vcpkg" ]]; then
    log "Removing existing vcpkg directory..."
    rm -rf vcpkg
fi

# vcpkg needs full git history for baseline version management
log "Cloning vcpkg (full clone required for baselines)..."
git clone https://github.com/microsoft/vcpkg
cd vcpkg

# Bootstrap vcpkg with retry logic
log "Bootstrapping vcpkg (with retry logic)..."
attempt=1
max_attempts=4
wait_times=(0 5 10 15)  # Wait times for each attempt (0 for first attempt)

while [[ $attempt -le $max_attempts ]]; do
    if [[ $attempt -gt 1 ]]; then
        wait_time=${wait_times[$((attempt-1))]}
        log "Attempt $attempt failed, waiting ${wait_time} seconds before retry..."
        sleep $wait_time
    fi
    
    log "Bootstrap attempt $attempt of $max_attempts..."
    if ./bootstrap-vcpkg.sh; then
        log "✅ vcpkg bootstrap successful on attempt $attempt"
        break
    else
        if [[ $attempt -eq $max_attempts ]]; then
            die "vcpkg bootstrap failed after $max_attempts attempts"
        fi
        log "⚠️ Bootstrap attempt $attempt failed"
        ((attempt++))
    fi
done

chown -R "$APP_USER:$APP_USER" "$USER_HOME/vcpkg"
cd "$USER_HOME"

# ────────────────────────── Clone and Build Canary ──────────────────────────
log "Cloning Canary repository..."
if [[ -d "canary" ]]; then
    log "Removing existing canary directory..."
    rm -rf canary
fi

git clone --depth 1 https://github.com/opentibiabr/canary.git
cd canary
chown -R "$APP_USER:$APP_USER" "$USER_HOME/canary"

log "Building Canary..."
# Create build directory as the app user to ensure correct permissions
sudo -u "$APP_USER" mkdir -p "$USER_HOME/canary/build"
chown -R "$APP_USER:$APP_USER" "$USER_HOME/canary"

# Build as the app user to avoid permission issues
sudo -u "$APP_USER" bash -c "
    cd '$USER_HOME/canary/build'
    # Use Release build with optimizations
    cmake -DCMAKE_TOOLCHAIN_FILE='$USER_HOME/vcpkg/scripts/buildsystems/vcpkg.cmake' \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_CXX_FLAGS_RELEASE='-O2 -DNDEBUG' \
          ..
    # Use all available cores + ccache if available
    export CCACHE_DIR='$USER_HOME/.ccache'
    cmake --build . -j\$(nproc) --config Release
"

log "Build completed successfully!"

# ────────────────────────── Move Binary and Set Permissions ──────────────────────────────
log "Moving canary binary to main directory and setting permissions..."
chown -R "$APP_USER:$APP_USER" "$USER_HOME/canary"

# Find and move the canary binary to the main canary directory
# Failed to detect the binary location, so we're going to move the binary to the main canary directory
BINARY_MOVED=false
if [[ -f "$USER_HOME/canary/build/bin/canary" ]]; then
    log "Moving canary binary from build/bin/ to main canary directory..."
    cp "$USER_HOME/canary/build/bin/canary" "$USER_HOME/canary/canary"
    chmod +x "$USER_HOME/canary/canary"
    chown "$APP_USER:$APP_USER" "$USER_HOME/canary/canary"
    BINARY_MOVED=true
elif [[ -f "$USER_HOME/canary/build/canary" ]]; then
    log "Moving canary binary from build/ to main canary directory..."
    cp "$USER_HOME/canary/build/canary" "$USER_HOME/canary/canary"
    chmod +x "$USER_HOME/canary/canary"
    chown "$APP_USER:$APP_USER" "$USER_HOME/canary/canary"
    BINARY_MOVED=true
elif [[ -f "$USER_HOME/canary/build/linux-release/bin/canary" ]]; then
    log "Moving canary binary from build/linux-release/bin/ to main canary directory..."
    cp "$USER_HOME/canary/build/linux-release/bin/canary" "$USER_HOME/canary/canary"
    chmod +x "$USER_HOME/canary/canary"
    chown "$APP_USER:$APP_USER" "$USER_HOME/canary/canary"
    BINARY_MOVED=true
else
    log "Warning: Could not find canary binary in expected locations"
fi

# Set executable permissions on start.sh if it exists
if [[ -f "$USER_HOME/canary/start.sh" ]]; then
    log "Setting executable permissions on start.sh..."
    chmod +x "$USER_HOME/canary/start.sh"
    chown "$APP_USER:$APP_USER" "$USER_HOME/canary/start.sh"
    log "✓ start.sh is now executable"
else
    log "start.sh not found in canary directory (this is normal)"
fi

# ────────────────────────── Configure config.lua ──────────────────────────
log "Configuring config.lua with server IP..."
CONFIG_FILE="$USER_HOME/canary/config.lua.dist"
if [[ -f "$CONFIG_FILE" ]]; then
    # Copy dist to actual config
    cp "$CONFIG_FILE" "$USER_HOME/canary/config.lua"
    CONFIG_FILE="$USER_HOME/canary/config.lua"
    
    # Update IP address in config.lua
    sed -i -E "s|^([[:space:]]*ip[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\")|\1${IPV4}\2|" "$CONFIG_FILE"
    
    chown "$APP_USER:$APP_USER" "$CONFIG_FILE"
    log "Updated config.lua with IP = \"$IPV4\""
else
    log "Warning: config.lua.dist not found, skipping IP configuration"
fi

# ────────────────────────── Summary ──────────────────────────────────
log "=== Canary Installation Complete ==="
log "✓ System updated and dependencies installed"
log "✓ Latest CMake installed via snap"
log "✓ GCC-14 installed and configured"
log "✓ vcpkg set up in $USER_HOME/vcpkg"
log "✓ Canary cloned and built successfully"
log "✓ Permissions configured for user: $APP_USER"
log "✓ config.lua configured with IP: $IPV4"
log ""
log "Canary binary location:"
if [[ "$BINARY_MOVED" == "true" ]] && [[ -f "$USER_HOME/canary/canary" ]]; then
    log "  → $USER_HOME/canary/canary"
else
    log "  → Binary location may vary, check $USER_HOME/canary/build/"
fi
log ""
log "Configuration file: $USER_HOME/canary/config.lua"
if [[ -f "$USER_HOME/canary/start.sh" ]]; then
    log "Start script: $USER_HOME/canary/start.sh (executable)"
fi
log "To start the server: cd $USER_HOME/canary && ./canary"
