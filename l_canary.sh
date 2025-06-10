#!/usr/bin/env bash
set -euo pipefail

# l_canary.sh — non-interactive Latest Canary installer & builder
# Usage: sudo ./l_canary.sh <app_user>

APP_USER="${1:-$SUDO_USER}"
USER_HOME="/home/${APP_USER}"
VCPKG_DIR="${USER_HOME}/vcpkg"
CANARY_DIR="${USER_HOME}/canary"
BUILD_DIR="${CANARY_DIR}/build"

log(){ echo -e "\n>>> $*"; }

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root"; exit 1
fi

log "Starting L Canary setup for user ${APP_USER}"

# 1) update & upgrade
if [[ ! -f "${USER_HOME}/.l_canary.1.done" ]]; then
  log "[1/7] apt update && dist-upgrade"
  apt update && apt dist-upgrade -y
  touch "${USER_HOME}/.l_canary.1.done"
else
  log "[1/7] skipped (already done)"
fi

# 1.1) Make sure ufw is installed
if [[ ! -f "${USER_HOME}/.l_canary.1.1.done" ]]; then
  log "[1.1/7] installing ufw"
  apt install -y ufw
  touch "${USER_HOME}/.l_canary.1.1.done"
else
  log "[1.1/7] skipped (already done)"
fi

# 1.1.1) Make sure ufw is enabled
if [[ ! -f "${USER_HOME}/.l_canary.1.1.1.done" ]]; then
  log "[1.1.1/7] enabling ufw"
  ufw --force enable
  touch "${USER_HOME}/.l_canary.1.1.1.done"
else
  log "[1.1.1/7] skipped (already done)"
fi

# 1.2) Setup UFW and allow OpenTibia ports
if [[ ! -f "${USER_HOME}/.l_canary.1.2.done" ]]; then
  log "[1.1/7] setting up UFW"
  ufw allow ssh
  ufw allow 7171/tcp
  ufw allow 7172/tcp
  ufw --force enable
  touch "${USER_HOME}/.l_canary.1.2.done"
else
  log "[1.1/7] skipped (already done)"
fi

# 2) install build tools & snap‐cmake
if [[ ! -f "${USER_HOME}/.l_canary.2.done" ]]; then
  log "[2/7] installing build tools"
  apt install -y \
    git cmake build-essential autoconf libtool ca-certificates \
    curl zip unzip tar pkg-config ninja-build ccache \
    linux-headers-$(uname -r)
  log "[2/7] replacing cmake via snap"
  apt remove --purge -y cmake
  hash -r
  apt install -y snapd
  snap install cmake --classic
  cmake --version
  touch "${USER_HOME}/.l_canary.2.done"
else
  log "[2/7] skipped"
fi

# 3) install gcc-14/g++-14
if ! command -v gcc-14 &>/dev/null; then
  log "[3/7] installing GCC-14/G++-14"
  apt update
  apt install -y gcc-14 g++-14
  update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 \
    --slave /usr/bin/g++ g++ /usr/bin/g++-14 \
    --slave /usr/bin/gcov gcov /usr/bin/gcov-14
  update-alternatives --set gcc /usr/bin/gcc-14
  gcc-14 --version
  g++-14 --version
else
  log "[3/7] skipped (gcc-14 present)"
fi

# 4) clone & checkout a stable vcpkg release
if [[ ! -d "${VCPKG_DIR}" ]]; then
  log "[4/7] cloning vcpkg"
  sudo -u "${APP_USER}" git clone https://github.com/microsoft/vcpkg "${VCPKG_DIR}" --quiet
  cd "${VCPKG_DIR}"
  log "[4/7] checking out stable tag 2024.10"
  sudo -u "${APP_USER}" git checkout 2024.10
  log "[4/7] bootstrapping vcpkg"
  sudo -u "${APP_USER}" env VCPKG_DISABLE_METRICS=1 ./bootstrap-vcpkg.sh
else
  log "[4/7] skipped (vcpkg exists)"
fi

# 5) clone canary repo
if [[ ! -d "${CANARY_DIR}" ]]; then
  log "[5/7] cloning canary repository"
  sudo -u "${APP_USER}" git clone --depth 1 https://github.com/opentibiabr/canary.git "${CANARY_DIR}"
else
  log "[5/7] skipped (canary exists)"
fi
chown -R "${APP_USER}":"${APP_USER}" "${CANARY_DIR}"

# 6) Build canary
log "[6/9] Building canary…"

# if build dir already exists, wipe it out + remove old binary
if [[ -d "${BUILD_DIR}" ]]; then
  log "  → Existing build directory found, removing…"
  rm -rf "${BUILD_DIR}"
  if [[ -f "${CANARY_DIR}/canary" ]]; then
    log "  → Removing old canary binary…"
    rm -f "${CANARY_DIR}/canary"
  fi
fi

# re-create & enter
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# run cmake & build
cmake \
  -DCMAKE_TOOLCHAIN_FILE="${VCPKG_DIR}/scripts/buildsystems/vcpkg.cmake" \
  .. --preset linux-release

cmake --build linux-release

# 7) install binary
log "[7/7] installing canary binary"
# the real binary path is under bin/
cp -f "${BUILD_DIR}/linux-release/bin/canary" "${CANARY_DIR}/canary"
chown "${APP_USER}":"${APP_USER}" "${CANARY_DIR}/canary"

# 8) Clone & patch config.lua
# detect machine IP (needed for config.lua patch)
MACHINE_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"

CONFIG_DIST="$CANARY_DIR/config.lua.dist"
CONFIG="$CANARY_DIR/config.lua"
if [[ ! -f "$CONFIG" ]]; then
  echo "[8/9] creating config.lua from config.lua.dist…"
  cp "$CONFIG_DIST" "$CONFIG"
else
  echo "[8/9] config.lua already exists"
fi
# ensure IP is correct
CURRENT_IP="$(grep -E '^ip\s*=' "$CONFIG" | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ "$CURRENT_IP" != "$MACHINE_IP" ]]; then
  echo "[8/9] updating ip in config.lua → $MACHINE_IP"
  sed -i 's|^ip\s*=.*|ip = "'"$MACHINE_IP"'"|' "$CONFIG"
else
  echo "[8/9] config.lua ip already set to $MACHINE_IP"
fi

# 9) Fix permissions
echo "[9/9] setting execute permissions…"
sudo chmod +x /home
sudo chmod +x "$USER_HOME"
sudo chmod +x "$CANARY_DIR"
sudo chmod 775 "${USER_HOME}/canary/canary"
sudo chmod 775 "${USER_HOME}/canary/start.sh"

log "✅ L Canary setup complete!"
exit 0
