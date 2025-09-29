#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

die(){ echo "ERROR: $*" >&2; exit 1; }
log(){ echo -e "\n>>> $*"; }

# ────────────────────────── Parse args ──────────────────────────────────────
# Current simplified pattern: l_tfs.sh IPV4_ADDRESS APP_USER
# Legacy fallback: l_tfs.sh APP_USER (auto-detect IP)
# Copy from new canary code
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

log "The Forgotten Server setup starting..."

# ────────────────────────── System Updates & Dependencies ──────────────────────
log "Updating system and installing dependencies..."
# Single apt update and batch install for speed
apt update && apt install -y \
  git build-essential cmake ninja-build \
  pkg-config ccache ca-certificates curl zip unzip tar \
  linux-headers-$(uname -r) \
  gcc-14 g++-14 \
  software-properties-common

# Remove old cmake and install via snap (parallel with other operations)
# Secureing that no old cmake is installed
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

# ────────────────────────── vcpkg Setup ──────────────────────────────────
log "Setting up vcpkg..."
cd "$USER_HOME"
if [[ -d "vcpkg" ]]; then
    log "Removing existing vcpkg directory..."
    rm -rf vcpkg
fi

# Clone vcpkg (full clone required for baselines)
log "Cloning vcpkg..."
git clone https://github.com/microsoft/vcpkg.git "$USER_HOME/vcpkg"
cd "$USER_HOME/vcpkg"

# Bootstrap vcpkg with retry logic
log "Bootstrapping vcpkg (with retry logic)..."
attempt=1
max_attempts=4
wait_times=(0 5 10 15)  # Wait times for each attempt (0 for first attempt, 4 max)

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

# Integrate vcpkg
log "Integrating vcpkg..."
./vcpkg integrate install

# Export vcpkg root
# Required for the build process
export VCPKG_ROOT="$USER_HOME/vcpkg"

chown -R "$APP_USER:$APP_USER" "$USER_HOME/vcpkg"
cd "$USER_HOME"

# ────────────────────────── Clone and Build TFS ──────────────────────────
log "Cloning The Forgotten Server repository..."
if [[ -d "forgottenserver" ]]; then
    log "Removing existing forgottenserver directory..."
    rm -rf forgottenserver
fi
if [[ -d "tfs" ]]; then
    log "Removing existing tfs directory..."
    rm -rf tfs
fi

git clone https://github.com/otland/forgottenserver.git "$USER_HOME/forgottenserver"

# Rename forgottenserver to tfs for consistency, keeping all Forgotten Server related files using the same folder name
# Requires less changes and checks for the web server scripts
log "Renaming forgottenserver directory to tfs..."
mv "$USER_HOME/forgottenserver" "$USER_HOME/tfs"
cd "$USER_HOME/tfs"

chown -R "$APP_USER:$APP_USER" "$USER_HOME/tfs"

log "Building The Forgotten Server..."
# Build as the app user to avoid permission issues
sudo -u "$APP_USER" bash -c "
    cd '$USER_HOME/tfs'
    export VCPKG_ROOT='$USER_HOME/vcpkg'
    export HOME='$USER_HOME'
    
    # Use vcpkg preset as per TFS wiki
    cmake --preset vcpkg
    
    # Build with RelWithDebInfo as per TFS wiki
    cmake --build --preset vcpkg --config RelWithDebInfo
"

log "Build completed successfully!"

# ────────────────────────── Move Binary ──────────────────────────────────
log "Moving TFS binary to main directory..."
chown -R "$APP_USER:$APP_USER" "$USER_HOME/tfs"

# Find and move the tfs binary to the main tfs directory
BINARY_MOVED=false
if [[ -f "$USER_HOME/tfs/build/RelWithDebInfo/tfs" ]]; then
    log "Moving tfs binary from build/RelWithDebInfo/ to main tfs directory..."
    cp "$USER_HOME/tfs/build/RelWithDebInfo/tfs" "$USER_HOME/tfs/tfs"
    chmod +x "$USER_HOME/tfs/tfs"
    chown "$APP_USER:$APP_USER" "$USER_HOME/tfs/tfs"
    BINARY_MOVED=true
elif [[ -f "$USER_HOME/tfs/build/Release/tfs" ]]; then
    log "Moving tfs binary from build/Release/ to main tfs directory..."
    cp "$USER_HOME/tfs/build/Release/tfs" "$USER_HOME/tfs/tfs"
    chmod +x "$USER_HOME/tfs/tfs"
    chown "$APP_USER:$APP_USER" "$USER_HOME/tfs/tfs"
    BINARY_MOVED=true
elif [[ -f "$USER_HOME/tfs/build/tfs" ]]; then
    log "Moving tfs binary from build/ to main tfs directory..."
    cp "$USER_HOME/tfs/build/tfs" "$USER_HOME/tfs/tfs"
    chmod +x "$USER_HOME/tfs/tfs"
    chown "$APP_USER:$APP_USER" "$USER_HOME/tfs/tfs"
    BINARY_MOVED=true
elif [[ -f "$USER_HOME/tfs/build/bin/tfs" ]]; then
    log "Moving tfs binary from build/bin/ to main tfs directory..."
    cp "$USER_HOME/tfs/build/bin/tfs" "$USER_HOME/tfs/tfs"
    chmod +x "$USER_HOME/tfs/tfs"
    chown "$APP_USER:$APP_USER" "$USER_HOME/tfs/tfs"
    BINARY_MOVED=true
elif [[ -f "$USER_HOME/tfs/build/linux-release/bin/tfs" ]]; then
    log "Moving tfs binary from build/linux-release/bin/ to main tfs directory..."
    cp "$USER_HOME/tfs/build/linux-release/bin/tfs" "$USER_HOME/tfs/tfs"
    chmod +x "$USER_HOME/tfs/tfs"
    chown "$APP_USER:$APP_USER" "$USER_HOME/tfs/tfs"
    BINARY_MOVED=true
else
    log "Warning: Could not find tfs binary in expected locations"
    log "Checking available files in build directory:"
    if [[ -d "$USER_HOME/tfs/build" ]]; then
        find "$USER_HOME/tfs/build" -name "tfs" -type f 2>/dev/null || log "No tfs binary found in build directory"
    fi
fi

# Set executable permissions on start.sh if it exists
if [[ -f "$USER_HOME/tfs/start.sh" ]]; then
    log "Setting executable permissions on start.sh..."
    chmod +x "$USER_HOME/tfs/start.sh"
    chown "$APP_USER:$APP_USER" "$USER_HOME/tfs/start.sh"
    log "✓ start.sh is now executable"
else
    log "start.sh not found in tfs directory (this is normal)"
fi

# ────────────────────────── Configure config.lua ──────────────────────────
log "Configuring config.lua with server IP..."
CONFIG_FILE="$USER_HOME/tfs/config.lua.dist"
if [[ -f "$CONFIG_FILE" ]]; then
    # Copy dist to actual config
    cp "$CONFIG_FILE" "$USER_HOME/tfs/config.lua"
    CONFIG_FILE="$USER_HOME/tfs/config.lua"
    
    # Update IP address in config.lua
    # Setting machine ipv4 as ip
    sed -i -E "s|^([[:space:]]*ip[[:space:]]*=[[:space:]]*\")[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\")|\1${IPV4}\2|" "$CONFIG_FILE"
    
    chown "$APP_USER:$APP_USER" "$CONFIG_FILE"
    log "Updated config.lua with IP = \"$IPV4\""
else
    log "Warning: config.lua.dist not found, skipping IP configuration"
fi

# ────────────────────────── Summary ──────────────────────────────────
log "=== The Forgotten Server Installation Complete ==="
log "✓ System updated and dependencies installed"
log "✓ Latest CMake installed via snap"
log "✓ GCC-14 installed and configured"
log "✓ vcpkg set up in $USER_HOME/vcpkg"
log "✓ TFS cloned and built successfully"
log "✓ Directory renamed from forgottenserver to tfs"
log "✓ Permissions configured for user: $APP_USER"
log "✓ config.lua configured with IP: $IPV4"
log ""
log "TFS binary location:"
if [[ "$BINARY_MOVED" == "true" ]] && [[ -f "$USER_HOME/tfs/tfs" ]]; then
    log "  → $USER_HOME/tfs/tfs"
else
    log "  → Binary location may vary, check $USER_HOME/tfs/build/"
fi
log ""
log "Configuration file: $USER_HOME/tfs/config.lua"
if [[ -f "$USER_HOME/tfs/start.sh" ]]; then
    log "Start script: $USER_HOME/tfs/start.sh (executable)"
fi
log "To start the server: cd $USER_HOME/tfs && ./tfs"
log "✅ The Forgotten Server setup complete!"
exit 0
