#!/usr/bin/env bash
# Version: 1
# Check if machine applied kernel settings
set -euo pipefail

# ── 0) Must be root ─────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

# ── Color markers ───────────────────────────────────────────────────────────
OK=$'\e[32m✔\e[0m'
FAIL=$'\e[31m✖\e[0m'

# ── Helpers ─────────────────────────────────────────────────────────────────
check_cmdline() {
  local flag=$1
  if grep -qw "$flag" /proc/cmdline; then
    printf "  %b %s in /proc/cmdline\n" "$OK" "$flag"
  else
    printf "  %b %s missing from /proc/cmdline\n" "$FAIL" "$flag"
  fi
}

check_sysctl() {
  local key=$1 want=$2
  local got
  got=$(sysctl -n "$key" 2>/dev/null || echo "n/a")
  if [[ "$got" == "$want" ]]; then
    printf "  %b %s = %s\n" "$OK" "$key" "$got"
  else
    printf "  %b %s = %s (expected %s)\n" "$FAIL" "$key" "$got" "$want"
  fi
}

check_mount() {
  local dir=$1 want=$2
  local opts
  opts=$(findmnt -n -o OPTIONS "$dir" 2>/dev/null)
  if echo "$opts" | grep -qw "$want"; then
    printf "  %b %s mounted with %s\n" "$OK" "$dir" "$want"
  else
    printf "  %b %s missing %s (opts: %s)\n" "$FAIL" "$dir" "$want" "$opts"
  fi
}

check_apparmor() {
  if ! command -v aa-status &>/dev/null; then
    printf "  %b aa-status not found\n" "$FAIL"
    return
  fi
  local enforced
  enforced=$(aa-status --enforced | grep -E '^ ' | wc -l)
  if (( enforced > 0 )); then
    printf "  %b %d profiles enforced\n" "$OK" "$enforced"
  else
    printf "  %b no profiles enforced\n" "$FAIL"
  fi
}

echo
echo "=== 1) Kernel boot-flags ==="
check_cmdline lockdown=integrity
check_cmdline module.sig_enforce=1
check_cmdline kaslr
check_cmdline kptr_restrict=2

echo
echo "=== 2) Sysctl settings ==="
# make sure we reload any new settings first
sysctl --system >/dev/null 2>&1 || true
declare -A want=(
  [kernel.yama.ptrace_scope]=1
  [kernel.dmesg_restrict]=1
  [fs.suid_dumpable]=0
  [kernel.randomize_va_space]=2
  [vm.mmap_min_addr]=65536
  [net.ipv4.conf.all.rp_filter]=1
  [net.ipv4.conf.default.rp_filter]=1
  [net.ipv4.conf.all.accept_source_route]=0
  [net.ipv4.conf.default.accept_source_route]=0
  [net.ipv4.conf.all.log_martians]=1
  [net.ipv4.icmp_echo_ignore_broadcasts]=1
  [net.ipv4.tcp_syncookies]=1
)
for k in "${!want[@]}"; do
  check_sysctl "$k" "${want[$k]}"
done

echo
echo "=== 3) /tmp & /var/tmp mount options ==="
for d in /tmp /var/tmp; do
  check_mount "$d" noexec
  check_mount "$d" nosuid
  check_mount "$d" nodev
done

echo
echo "=== 4) AppArmor enforcement ==="
check_apparmor

echo
echo "=== Verification complete ==="
