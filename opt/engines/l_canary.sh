#!/usr/bin/env bash
set -euo pipefail
die() { echo "ERROR: $*" >&2; exit 1; }

APP_USER="${1:-$SUDO_USER}"
USER_HOME="/home/${APP_USER}"
VCPKG_DIR="${USER_HOME}/vcpkg"
CANARY_DIR="${USER_HOME}/canary"
BUILD_DIR="${CANARY_DIR}/build"

log(){ echo -e "\n>>> $*"; }

[[ $EUID -eq 0 ]] || die "Must run as root"

log "Starting L Canary setup for user ${APP_USER}"

# [1/7] System update
if [[ ! -f "${USER_HOME}/.l_canary.1.done" ]]; then
  log "[1/7] apt update && dist-upgrade"
  apt update && apt dist-upgrade -y
  touch "${USER_HOME}/.l_canary.1.done"
else
  log "[1/7] skipped"
fi

# [1.1] UFW setup
if [[ ! -f "${USER_HOME}/.l_canary.1.1.done" ]]; then
  log "[1.1/7] installing and enabling ufw"
  apt install -y ufw
  ufw allow ssh
  ufw allow 7171/tcp
  ufw allow 7172/tcp
  ufw --force enable
  touch "${USER_HOME}/.l_canary.1.1.done"
else
  log "[1.1/7] skipped"
fi

# [SWAP] Ensure swap
SWAPFILE=/swapfile
if ! grep -q "^/swapfile" /etc/fstab; then
  log "Creating 1GB swapfile"
  fallocate -l 1G $SWAPFILE
  chmod 600 $SWAPFILE
  mkswap $SWAPFILE
  swapon $SWAPFILE
  echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
else
  log "Swapfile already present"
fi

# [2/7] Dependencies
if [[ ! -f "${USER_HOME}/.l_canary.2.done" ]]; then
  log "[2/7] installing system packages"
  apt install -y \
    git cmake build-essential autoconf libtool ca-certificates \
    curl zip unzip tar pkg-config ninja-build ccache \
    gcc-14 g++-14 \
    linux-headers-$(uname -r) \
    snapd

  log "[2/7] removing apt cmake, installing snap cmake"
  apt remove --purge -y cmake
  hash -r
  snap install cmake --classic
  cmake --version

  touch "${USER_HOME}/.l_canary.2.done"
else
  log "[2/7] skipped"
fi

# [3/7] Configure GCC-14
if ! command -v gcc-14 &>/dev/null; then
  log "[3/7] installing gcc-14"
  apt install -y gcc-14 g++-14
fi

update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 \
  --slave /usr/bin/g++ g++ /usr/bin/g++-14 \
  --slave /usr/bin/gcov gcov /usr/bin/gcov-14
update-alternatives --set gcc /usr/bin/gcc-14
gcc-14 --version
g++-14 --version

# [4/7] Clone & bootstrap vcpkg
if [[ -d "$VCPKG_DIR" && ! -d "$VCPKG_DIR/.git" ]]; then
  log "Removing invalid vcpkg folder"
  rm -rf "$VCPKG_DIR"
fi

if [[ ! -d "$VCPKG_DIR" ]]; then
  log "[4/7] cloning vcpkg"
  sudo -u "$APP_USER" git clone https://github.com/microsoft/vcpkg "$VCPKG_DIR" --quiet
  cd "$VCPKG_DIR"

  log "[4/7] detecting latest stable tag"
  LATEST_TAG=$(git ls-remote --tags --refs https://github.com/microsoft/vcpkg.git | \
    awk -F/ '{print $3}' | grep -E '^[0-9]+\.[0-9]+(\.[0-9]+)?$' | sort -V | tail -n1)
  log "Using vcpkg tag: $LATEST_TAG"

  sudo -u "$APP_USER" git fetch --tags --quiet
  sudo -u "$APP_USER" git checkout --quiet "tags/$LATEST_TAG"

  # Patch to avoid unreachable crash
  sed -i 's/unreachable("Unreachable code");//g' src/vcpkg/metrics.cpp || true

  log "[4/7] bootstrapping vcpkg"
  sudo -u "$APP_USER" env VCPKG_DISABLE_METRICS=1 ./bootstrap-vcpkg.sh
else
  log "[4/7] skipped (already exists)"
fi

# [5/7] Clone Canary
if [[ ! -d "${CANARY_DIR}" ]]; then
  log "[5/7] cloning canary"
  sudo -u "${APP_USER}" git clone --depth 1 https://github.com/opentibiabr/canary.git "${CANARY_DIR}"
else
  log "[5/7] skipped"
fi

# Optional version patch (if needed)
VCPKG_JSON="${CANARY_DIR}/vcpkg.json"
if [[ -f "$VCPKG_JSON" ]]; then
  log "[5.1] optional patch of vcpkg.json"
  sed -i 's/"nlohmann-json": *"[^"]*"/"nlohmann-json": "3.11.3"/' "$VCPKG_JSON" || true
  sed -i 's/"openssl": *"[^"]*"/"openssl": "3.5.0"/' "$VCPKG_JSON" || true
fi
chown -R "${APP_USER}:${APP_USER}" "${CANARY_DIR}"

# [6/9] Build Canary
log "[6/9] building canary"
build_canary() {
  rm -rf "$BUILD_DIR" "${CANARY_DIR}/canary"
  mkdir -p "$BUILD_DIR"
  cd "$BUILD_DIR" || return 1

  cmake -DCMAKE_TOOLCHAIN_FILE="${VCPKG_DIR}/scripts/buildsystems/vcpkg.cmake" .. --preset linux-release || return 1
  cmake --build linux-release --parallel || return 1
}

if build_canary; then
  log "✅ Canary built successfully"
else
  log "Initial build failed — retrying with vcpkg reset"
  cd /tmp
  rm -rf "$VCPKG_DIR" "$BUILD_DIR" "${CANARY_DIR}/vcpkg_installed"

  git clone https://github.com/microsoft/vcpkg "$VCPKG_DIR"
  chown -R "$APP_USER:$APP_USER" "$VCPKG_DIR"
  cd "$VCPKG_DIR"
  git checkout "tags/$LATEST_TAG"
  sed -i 's/unreachable("Unreachable code");//g' src/vcpkg/metrics.cpp || true
  env VCPKG_DISABLE_METRICS=1 ./bootstrap-vcpkg.sh

  if build_canary; then
    log "✅ Canary rebuilt successfully"
  else
    die "❌ Final build failed even after vcpkg reset"
  fi
fi

# [7/7] Install binary
log "[7/7] installing binary"
cp -f "${BUILD_DIR}/linux-release/bin/canary" "${CANARY_DIR}/canary"
chown "${APP_USER}:${APP_USER}" "${CANARY_DIR}/canary"

# [8/9] Patch config.lua
MACHINE_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
CONFIG_DIST="$CANARY_DIR/config.lua.dist"
CONFIG="$CANARY_DIR/config.lua"

[[ -f "$CONFIG" ]] || cp "$CONFIG_DIST" "$CONFIG"

CURRENT_IP="$(grep -E '^ip\s*=' "$CONFIG" | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ "$CURRENT_IP" != "$MACHINE_IP" ]]; then
  log "[8/9] patching config.lua IP to $MACHINE_IP"
  sed -i 's|^ip\s*=.*|ip = "'"$MACHINE_IP"'"|' "$CONFIG"
fi

# [9/9] Permissions
log "[9/9] fixing permissions"
chmod +x "$USER_HOME"
chmod +x "$CANARY_DIR"
chmod 775 "${CANARY_DIR}/canary"
chmod 775 "${CANARY_DIR}/start.sh"

log "✅ L Canary setup complete!"
exit 0
