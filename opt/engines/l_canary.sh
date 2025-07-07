#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
die() { echo "ERROR: $*" >&2; exit 1; }

APP_USER="${1:-$SUDO_USER}"
BUILD_MODE="${2:-release}"   # release / debug / both
RAW_CACHE="${3:-no}"         # yes / no / disabled

# normalize inputs
BUILD_MODE="${BUILD_MODE,,}"
RAW_CACHE="${RAW_CACHE,,}"

case "$RAW_CACHE" in
  yes|y|true|1) ENABLE_BINARY_CACHE="yes" ;;
  no|n|false|0|disabled) ENABLE_BINARY_CACHE="no" ;;
  *) die "Invalid binary-cache: $RAW_CACHE" ;;
esac

case "$BUILD_MODE" in
  release|debug|both) ;;
  *) die "Invalid build-mode: $BUILD_MODE" ;;
esac

# map build-mode → vcpkg triplet
case "$BUILD_MODE" in
  release) VCPKG_TRIPLET="x64-linux-release" ;;
  debug)   VCPKG_TRIPLET="x64-linux-dbg"     ;;
  both)    VCPKG_TRIPLET="x64-linux"         ;;
esac
export VCPKG_DEFAULT_TRIPLET="$VCPKG_TRIPLET"

log(){ echo -e "\n>>> $*"; }
if [[ $EUID -ne 0 ]]; then die "Must run as root"; fi

USER_HOME="/home/${APP_USER}"
CANARY_DIR="${USER_HOME}/canary"
VCPKG_DIR="${USER_HOME}/vcpkg"
BUILD_DIR="${CANARY_DIR}/build"

log "Starting L Canary setup for user $APP_USER"

# ——————————————————————————————
# [1/7] System update & core tool install
if [[ ! -f "${USER_HOME}/.l_canary.1.done" ]]; then
  log "[1/7] Updating system and installing core packages"
  apt update && apt dist-upgrade -y
  apt install -y \
    git \
    build-essential \
    autoconf \
    libtool \
    ca-certificates \
    curl \
    zip unzip tar pkg-config \
    ninja-build \
    ccache \
    linux-headers-$(uname -r)
  touch "${USER_HOME}/.l_canary.1.done"
else
  log "[1/7] skipped"
fi

# ——————————————————————————————
# [2/7] CMake via snap
if [[ ! -f "${USER_HOME}/.l_canary.2.done" ]]; then
  log "[2/7] Upgrading CMake via snap"
  apt remove --purge -y cmake || true
  hash -r
  apt install -y snapd
  snap install cmake --classic
  cmake --version
  touch "${USER_HOME}/.l_canary.2.done"
else
  log "[2/7] skipped"
fi

# ——————————————————————————————
# [3/7] Install GCC-14 and select
if [[ ! -f "${USER_HOME}/.l_canary.3.done" ]]; then
  log "[3/7] Installing and configuring GCC-14"
  apt update
  apt install -y gcc-14 g++-14
  update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 \
    --slave /usr/bin/g++ g++ /usr/bin/g++-14 \
    --slave /usr/bin/gcov gcov /usr/bin/gcov-14
  update-alternatives --set gcc /usr/bin/gcc-14
  gcc --version
  g++ --version
  touch "${USER_HOME}/.l_canary.3.done"
else
  log "[3/7] skipped"
fi

# ——————————————————————————————
# [4/7] Install vcpkg
if [[ ! -f "${USER_HOME}/.l_canary.4.done" ]]; then
  log "[4/7] Cloning and bootstrapping vcpkg"
  cd "${USER_HOME}"
  rm -rf "$VCPKG_DIR"
  git clone https://github.com/microsoft/vcpkg "$VCPKG_DIR"
  cd "$VCPKG_DIR"
  export VCPKG_METRICS_OPT_OUT=1
  ./bootstrap-vcpkg.sh --disableMetrics
  log "✅ vcpkg ready at $VCPKG_DIR/vcpkg"

  # Ensure permanent metrics disable
  log "[4/7] Ensuring vcpkg metrics disabled permanently"
  for f in .bashrc .profile; do
    if ! grep -q "VCPKG_METRICS_OPT_OUT=1" "${USER_HOME}/$f"; then
      echo "export VCPKG_METRICS_OPT_OUT=1" >> "${USER_HOME}/$f"
    fi
  done

  mkdir -p "${USER_HOME}/.vcpkg"
  cat > "${USER_HOME}/.vcpkg/vcpkg-configuration.json" <<EOF
{
  "user": {
    "sendMetrics": false
  }
}
EOF
  chown -R "$APP_USER:$APP_USER" "${USER_HOME}/.vcpkg"

  touch "${USER_HOME}/.l_canary.4.done"
else
  log "[4/7] skipped"
fi

# ——————————————————————————————
# [5/7] Clone Canary
if [[ ! -f "${USER_HOME}/.l_canary.5.done" ]]; then
  log "[5/7] Cloning Canary source"
  cd "${USER_HOME}"
  git clone --depth 1 https://github.com/opentibiabr/canary.git "$CANARY_DIR"
  touch "${USER_HOME}/.l_canary.5.done"
else
  log "[5/7] skipped"
fi
chown -R "$APP_USER:$APP_USER" "$CANARY_DIR"

# ——————————————————————————————
# [6/7] Configure & build Canary
if [[ ! -f "${USER_HOME}/.l_canary.6.done" ]]; then
  log "[6/7] Configuring and building Canary"
  mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"
  cmake --preset linux-release \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_DIR/scripts/buildsystems/vcpkg.cmake" ..
  cmake --build linux-release --parallel "$(nproc)"
  touch "${USER_HOME}/.l_canary.6.done"
else
  log "[6/7] skipped"
fi

# ——————————————————————————————
# [7/7] Install binary
log "[7/7] Installing Canary binary"
if [[ -x "$BUILD_DIR/linux-release/canary" ]]; then
  SRC="$BUILD_DIR/linux-release/canary"
elif [[ -x "$BUILD_DIR/linux-release/bin/canary" ]]; then
  SRC="$BUILD_DIR/linux-release/bin/canary"
else
  die "❌ built binary not found"
fi
cp "$SRC" "$CANARY_DIR/canary"
chown "$APP_USER:$APP_USER" "$CANARY_DIR/canary"

log "✅ L Canary setup complete!"
exit 0
