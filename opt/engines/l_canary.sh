#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

die(){ echo "ERROR: $*" >&2; exit 1; }
log(){ echo -e "\n>>> $*"; }

# ────────────────────────── Parse args ──────────────────────────────────────
APP_USER="${1:-$SUDO_USER}"
BUILD_MODE="${2:-release}"
BUILD_MODE="${BUILD_MODE,,}"

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

[[ $EUID -eq 0 ]] || die "Must run as root"
log "L Canary setup (mode=$BUILD_MODE)"

USER_HOME="/home/${APP_USER}"
CANARY_DIR="${USER_HOME}/canary"
VCPKG_DIR="${USER_HOME}/vcpkg"
BUILD_DIR="${CANARY_DIR}/build"

# ──────────────────────── 1/7: System & core tools ─────────────────────────
if [[ ! -f "$USER_HOME/.l_canary.1" ]]; then
  log "1/7: Update & install core packages"
  apt update && apt dist-upgrade -y
  apt install -y \
    git build-essential autoconf libtool ca-certificates curl \
    zip unzip tar pkg-config ninja-build ccache \
    linux-headers-$(uname -r)
  touch "$USER_HOME/.l_canary.1"
else log "1/7 skipped"; fi

# ───────────────────────── 2/7: CMake via snap ───────────────────────────────
if [[ ! -f "$USER_HOME/.l_canary.2" ]]; then
  log "2/7: Install snapd + CMake"
  apt remove --purge -y cmake || true
  apt install -y snapd
  snap install cmake --classic
  cmake --version
  touch "$USER_HOME/.l_canary.2"
else log "2/7 skipped"; fi

# ─────────────────────────── 3/7: GCC-14 ─────────────────────────────────────
if [[ ! -f "$USER_HOME/.l_canary.3" ]]; then
  log "3/7: Install & select GCC-14"
  apt update && apt install -y gcc-14 g++-14
  update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-14 100 \
    --slave /usr/bin/g++ g++ /usr/bin/g++-14 \
    --slave /usr/bin/gcov gcov /usr/bin/gcov-14
  update-alternatives --set gcc /usr/bin/gcc-14
  touch "$USER_HOME/.l_canary.3"
else log "3/7 skipped"; fi

# ────────────────────────── 4/7: Populate vcpkg ─────────────────────────────
if [[ ! -f "$USER_HOME/.l_canary.4" ]]; then
  log "4/7: Populate vcpkg (bundle or bootstrap)"

  # first try binary bundle
  if curl -fsSL https://yourotserver.com/cache/vcpkg_bundle.tar.gz -o /tmp/vcpkg_bundle.tar.gz; then
    log "-> bundle downloaded, extracting to /"
    tar -xzf /tmp/vcpkg_bundle.tar.gz -C /
    chown -R "$APP_USER:$APP_USER" "$USER_HOME/vcpkg"
    log "✅ bundle extraction complete, skipping bootstrap"
  else
    log "⚠ bundle download failed – falling back to clone+bootstrap"

    # clone
    cd "$USER_HOME"
    rm -rf "$VCPKG_DIR"
    git clone https://github.com/microsoft/vcpkg "$VCPKG_DIR"
    cd "$VCPKG_DIR"
    export VCPKG_METRICS_OPT_OUT=1

    # try up to 3 bootstraps
    for attempt in 1 2 3; do
      log "-> bootstrap attempt #$attempt"
      if ./bootstrap-vcpkg.sh --disableMetrics; then
        log "✅ bootstrap succeeded"
        break
      else
        log "⚠ bootstrap failed"
        sleep 2
      fi
    done

    # final fallback: download prebuilt
    if [[ ! -x "$VCPKG_DIR/vcpkg" ]]; then
      log "⚠ bootstrap never produced vcpkg – downloading prebuilt"
      VCPKG_TAG=2025-06-20
      curl -fsSL \
        "https://github.com/microsoft/vcpkg/releases/download/${VCPKG_TAG}/vcpkg-linux.tar.gz" \
        | tar -xz -C "$VCPKG_DIR"
      chmod +x "$VCPKG_DIR/vcpkg"
    fi
  fi

  # disable metrics permanently
  for f in .bashrc .profile; do
    grep -q VCPKG_METRICS_OPT_OUT=1 "$USER_HOME/$f" || \
      echo "export VCPKG_METRICS_OPT_OUT=1" >>"$USER_HOME/$f"
  done

  # manifest-mode config
  mkdir -p "$USER_HOME/.vcpkg"
  cat >"$USER_HOME/.vcpkg/vcpkg-configuration.json" <<EOF
{
  "user": { "sendMetrics": false }
}
EOF
  chown -R "$APP_USER:$APP_USER" "$USER_HOME/.vcpkg"
  touch "$USER_HOME/.l_canary.4"
else log "4/7 skipped"; fi

# ─────────────────────────── 5/7: Clone Canary ──────────────────────────────
if [[ ! -f "$USER_HOME/.l_canary.5" ]]; then
  log "5/7: Clone Canary source"
  cd "$USER_HOME"
  git clone --depth 1 https://github.com/opentibiabr/canary.git "$CANARY_DIR"
  touch "$USER_HOME/.l_canary.5"
else log "5/7 skipped"; fi
chown -R "$APP_USER:$APP_USER" "$CANARY_DIR"

# ──────────────────── 6/7: Configure & build Canary ─────────────────────────
if [[ ! -f "$USER_HOME/.l_canary.6" ]]; then
  for m in ${BUILD_MODE}; do
    log "6/7: Configure & build Canary (${m^})"
    SUBDIR="$BUILD_DIR/$m"
    mkdir -p "$SUBDIR"
    cmake -S "$CANARY_DIR" -B "$SUBDIR" \
      -DCMAKE_BUILD_TYPE=${m^} \
      -DVCPKG_TARGET_TRIPLET="$VCPKG_DEFAULT_TRIPLET" \
      -DVCPKG_FEATURE_FLAGS=manifests \
      -DVCPKG_MANIFEST_INSTALL=ON \
      -DCMAKE_TOOLCHAIN_FILE="$VCPKG_DIR/scripts/buildsystems/vcpkg.cmake"
    cmake --build "$SUBDIR" --parallel "$(nproc)"
  done
  touch "$USER_HOME/.l_canary.6"
else log "6/7 skipped"; fi

# ─────────────────────────── 7/7: Install binary ─────────────────────────────
log "7/7: Install Canary binary"
for m in ${BUILD_MODE}; do
  B="$BUILD_DIR/$m"
  [[ -x "$B/canary"     ]] && SRC="$B/canary"
  [[ -x "$B/bin/canary" ]] && SRC="$B/bin/canary"
done
[[ -n "${SRC:-}" ]] || die "❌ built binary not found"
cp "$SRC" "$CANARY_DIR/canary"
chown "$APP_USER:$APP_USER" "$CANARY_DIR/canary"

log "✅ L Canary setup complete!"
exit 0
