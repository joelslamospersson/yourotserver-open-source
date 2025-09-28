#!/usr/bin/env bash
set -euo pipefail
set -o errtrace

# ────────────────────────── Config ──────────────────────────
# Build TFS 7.72 using vcpkg-based workflow
# Keep cached source zip (for Nekiro downgrades)
CACHE_URL="http://cache.yourotserver.com/cache/TFS-1.5-Downgrades-7.72.zip"
ZIP_NAME="TFS-1.5-Downgrades-7.72.zip"
SRC_DIR_NAME="TFS-1.5-Downgrades-7.72"   # how the zip extracts

log(){ echo -e "\n>>> $*"; }
die(){ echo -e "\nERROR: $*" >&2; exit 1; }

# Error trap to print failing command, line and useful build logs
on_error(){
  local exit_code=$?
  echo -e "\n✖ Failure (exit ${exit_code}) at line ${BASH_LINENO[0]}: ${BASH_COMMAND}"
  if [[ -n "${TFS_DIR:-}" ]] && [[ -d "$TFS_DIR/build" ]]; then
    [[ -f "$TFS_DIR/build/CMakeFiles/CMakeError.log"  ]] && { echo "--- tail CMakeError.log ---";  tail -n 80 "$TFS_DIR/build/CMakeFiles/CMakeError.log"; }
    [[ -f "$TFS_DIR/build/CMakeFiles/CMakeOutput.log" ]] && { echo "--- tail CMakeOutput.log ---"; tail -n 40 "$TFS_DIR/build/CMakeFiles/CMakeOutput.log"; }
    # Any other logs under build
    find "$TFS_DIR/build" -maxdepth 2 -type f -name '*.log' -print -exec tail -n 50 {} \; 2>/dev/null || true
  fi
}
trap on_error ERR

# Pick the real user even if running via sudo
APP_USER="${SUDO_USER:-$USER}"
APP_HOME="$(getent passwd "$APP_USER" | cut -d: -f6)"
TFS_DIR="$APP_HOME/tfs"

# Mirror all output to a logfile while keeping console output
LOG_FILE="${APP_HOME:-${HOME:-/root}}/nekiro_setup_772.log"
{ : >"$LOG_FILE"; } 2>/dev/null || true
exec > >(tee -a "$LOG_FILE") 2>&1

# ────────────────────────── Pre-flight ──────────────────────
log "Updating apt and installing required packages…"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ufw git cmake build-essential curl unzip zip tar pkg-config ninja-build \
  libmysqlclient-dev libpugixml-dev libluajit-5.1-dev libcrypto++-dev libfmt-dev

# ────────────────────────── UFW ─────────────────────────────
log "Configuring UFW (OpenSSH + 7171/7172) and enabling firewall…"
ufw allow OpenSSH || ufw allow 22/tcp || true
ufw allow 7171/tcp || true
ufw allow 7172/tcp || true
# Enable UFW if not already enabled
if ! ufw status | grep -q "Status: active"; then
  echo "y" | ufw enable
fi

# ────────────────────────── vcpkg setup ─────────────────────
log "Ensuring working dir exists for $APP_USER…"
install -d -o "$APP_USER" -g "$APP_USER" "$APP_HOME"

cd "$APP_HOME"

if [[ ! -d "$APP_HOME/vcpkg" ]]; then
  log "Cloning vcpkg…"
  git clone https://github.com/microsoft/vcpkg.git "$APP_HOME/vcpkg"
fi

log "Bootstrapping vcpkg…"
cd "$APP_HOME/vcpkg"
./bootstrap-vcpkg.sh
./vcpkg integrate install || true
export VCPKG_ROOT="$APP_HOME/vcpkg"
chown -R "$APP_USER:$APP_USER" "$APP_HOME/vcpkg"

# ────────────────────────── Get sources (from cache zip) ─────────────────────
cd "$APP_HOME"
log "Fetching cached source zip if missing…"
if [[ ! -f "$ZIP_NAME" ]]; then
  if command -v curl >/dev/null 2>&1; then
    curl -fL "$CACHE_URL" -o "$ZIP_NAME"
  else
    wget -O "$ZIP_NAME" "$CACHE_URL"
  fi
fi
log "Unzipping sources…"
rm -rf "$SRC_DIR_NAME"
unzip -q -o "$ZIP_NAME"

# Prepare tree at ~/tfs for consistency with other scripts
log "Preparing source directory at: $TFS_DIR"
rm -rf "$TFS_DIR"
mv "$SRC_DIR_NAME" "$TFS_DIR"
chown -R "$APP_USER:$APP_USER" "$TFS_DIR"

# ────────────────────────── Source compatibility (Boost.Asio) ────────────────
# Adapt older Nekiro 7.72 sources to newer Boost.Asio APIs
# Old code goes BRRRRRRRRRRRRRRRRRR
# I love ai, this is a mess of code but works ty
log "Patching sources for Boost.Asio compatibility…"
(
  cd "$TFS_DIR"
  # 1) io_service → io_context
  find . -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' \) \
    -not -path '*/.git/*' -exec sed -i 's/boost::asio::io_service/boost::asio::io_context/g' {} +
  
  # 2) io_context::work → executor_work_guard<io_context::executor_type>
  find . -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' \) \
    -not -path '*/.git/*' -exec sed -i -E \
    's#boost::asio::io_context::work#boost::asio::executor_work_guard<boost::asio::io_context::executor_type>#g' {} +
  
  # 3) Replace work-guard constructions with make_work_guard(io_context)
  #    - handles both {...} and (...) initializations (escape braces/parens)
  find . -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' \) \
    -not -path '*/.git/*' -exec sed -i -E \
    -e 's#boost::asio::executor_work_guard<[^>]+>[[:space:]]+work[[:space:]]*\{[[:space:]]*io_context[[:space:]]*\}#auto work = boost::asio::make_work_guard(io_context)#g' \
    -e 's#boost::asio::executor_work_guard<[^>]+>[[:space:]]+work[[:space:]]*\([[:space:]]*io_context[^\)]*\)#auto work = boost::asio::make_work_guard(io_context)#g' {} +
  
  # 4) Also convert any remaining io_context::work lines directly to make_work_guard (just in case)
  find . -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' \) \
    -not -path '*/.git/*' -exec sed -i -E \
    -e 's#boost::asio::io_context::work[[:space:]]+work[[:space:]]*[\{\(][[:space:]]*io_context[[:space:]]*[\)\}]#auto work = boost::asio::make_work_guard(io_context)#g' {} +
  
  # 5) If any auto work remains in member context, replace with explicit guard type using get_executor()
  find . -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' \) \
    -not -path '*/.git/*' -exec sed -i -E \
    -e 's#(^|[[:space:]])auto[[:space:]]+work[[:space:]]*=[[:space:]]*boost::asio::make_work_guard\([[:space:]]*io_context[[:space:]]*\);#\1boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};#g' {} +

  # 6) More robust fallback: replace any variant of 'auto work = make_work_guard(io_context);'
  find . -type f -not -path '*/.git/*' -exec sed -i -E \
    -e 's#(^|[[:space:]])auto[[:space:]]+work[[:space:]]*=[[:space:]]*boost::asio::make_work_guard\([[:space:]]*io_context[[:space:]]*\);#boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};#g' {} +

  # Replace timer/address API across all sources (robust pass)
  find . -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' \) \
    -not -path '*/.git/*' -exec sed -i -E \
    -e 's/\bexpires_from_now\b/expires_after/g' \
    -e 's/\.to_v4\(\)\.to_ulong\(\)/.to_v4().to_uint()/g' {} +

  # 11) Convert X.post(handler) -> boost::asio::post(X, handler) (for io_context variables)
  find . -type f \( -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.hpp' -o -name '*.hh' -o -name '*.h' \) \
    -not -path '*/.git/*' -exec sed -i -E \
    -e 's#\b([[:alnum:]_]+)[[:space:]]*\.[[:space:]]*post[[:space:]]*\(#boost::asio::post(\1, #g' {} +

  # 12) Replace address_v4::from_string(...) -> boost::asio::ip::make_address_v4(...)
  find . -type f \( -name '*.cpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.hpp' -o -name '*.hh' -o -name '*.h' \) \
    -not -path '*/.git/*' -exec sed -i -E \
    -e 's#\bboost::asio::ip::address_v4::from_string\(#boost::asio::ip::make_address_v4(#g' \
    -e 's#\baddress_v4::from_string\(#boost::asio::ip::make_address_v4(#g' {} +

  # 10) Provide fmt formatter for all enum types so fmt::format works
  FMTCOMPAT="$TFS_DIR/src/compat_fmt.h"
  if [[ ! -f "$FMTCOMPAT" ]]; then
    cat >"$FMTCOMPAT" <<'EOF'
#pragma once
#include <type_traits>
#include <fmt/format.h>

// Generic formatter for any enum: print as underlying integer
template <typename E>
struct fmt::formatter<E, char, std::enable_if_t<std::is_enum<E>::value, void>>
    : fmt::formatter<std::underlying_type_t<E>> {
  template <typename FormatContext>
  auto format(E e, FormatContext& ctx) const {
    return fmt::formatter<std::underlying_type_t<E>>::format(
        static_cast<std::underlying_type_t<E>>(e), ctx);
  }
};
EOF
  fi

  # Ensure compat header is included early via otpch.h if present
  if [[ -f "$TFS_DIR/src/otpch.h" ]] && ! grep -q 'compat_fmt.h' "$TFS_DIR/src/otpch.h"; then
    sed -i '1i #include "compat_fmt.h"' "$TFS_DIR/src/otpch.h"
  fi

  # 11) Replace non-conforming allocator usage with make_shared for OutputMessage
  find . -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' \) \
    -not -path '*/.git/*' -exec sed -i -E \
    -e 's#std::allocate_shared<[[:space:]]*OutputMessage[[:space:]]*>[[:space:]]*\([^\)]*\)#std::make_shared<OutputMessage>()#g' {} +
  # remove accidental extra ')'
  grep -RIl -E --exclude-dir=.git -e 'make_shared<OutputMessage>\(\)\)[[:space:]]*;' . | xargs -r sed -i \
    's/std::make_shared<OutputMessage>()\)[[:space:]]*;/std::make_shared<OutputMessage>();/g'
  # tighten any leftover ') ;' on the same line as make_shared<OutputMessage>()
  grep -RIl -E --exclude-dir=.git -e 'make_shared<OutputMessage>\(' . | xargs -r sed -i -E \
    's#(std::make_shared<OutputMessage>\(\))[[:space:]]*\)[[:space:]]*;#\1;#g'
) || true

# ────────────────────────── Build TFS ───────────────────────
log "Building TFS via vcpkg…"
cd "$TFS_DIR"
export VCPKG_ROOT="$APP_HOME/vcpkg"
if [[ -f "CMakePresets.json" ]] && grep -q '"name"\s*:\s*"vcpkg"' CMakePresets.json; then
  # Ensure missing deps are available in case preset doesn't declare them
  "$VCPKG_ROOT/vcpkg" install cryptopp fmt pugixml luajit boost || true
  export CMAKE_PREFIX_PATH="$VCPKG_ROOT/installed/x64-linux/share:$VCPKG_ROOT/installed/x64-linux:${CMAKE_PREFIX_PATH:-}"
  cmake -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" --preset vcpkg \
        -Dfmt_DIR="$VCPKG_ROOT/installed/x64-linux/share/fmt" -DFMT_DIR="$VCPKG_ROOT/installed/x64-linux/share/fmt"
  cmake --build --preset vcpkg --config RelWithDebInfo
else
  log "CMake preset 'vcpkg' not found; using toolchain file instead"
  rm -rf build
  # Ensure required deps via vcpkg
  "$VCPKG_ROOT/vcpkg" install cryptopp fmt pugixml luajit boost || true
  cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -DMySQL_INCLUDE_DIR="/usr/include/mysql" \
    -Dfmt_DIR="$VCPKG_ROOT/installed/x64-linux/share/fmt" \
    -DFMT_DIR="$VCPKG_ROOT/installed/x64-linux/share/fmt"
  cmake --build build --config RelWithDebInfo -j"$(nproc)"
fi

# ────────────────────────── Place binary ────────────────────
# Handle different CMake/vcpkg layouts
BIN_PATH=""

for p in \
  "$TFS_DIR/build/bin/tfs" \
  "$TFS_DIR/build/tfs" \
  "$TFS_DIR/build/src/tfs" \
  "$TFS_DIR/bin/RelWithDebInfo/tfs" \
  "$TFS_DIR/bin/Release/tfs" \
  "$TFS_DIR/build/vcpkg/RelWithDebInfo/tfs" \
  "$TFS_DIR/build/vcpkg/Release/tfs"; do
  if [[ -x "$p" ]]; then BIN_PATH="$p"; break; fi
done

if [[ -z "$BIN_PATH" ]]; then
  # Last resort: search for an executable named 'tfs' within build/*
  BIN_PATH="$(find "$TFS_DIR" -maxdepth 5 -type f -name tfs -perm -111 | head -n1 || true)"
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
# Database credentials are left out for myacc setup
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
