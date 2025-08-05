#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Ubuntu 24.04 kernel & LSM hardening
# -----------------------------------------------------------------------------

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo $0"
  exit 1
fi

echo "=== 1) GRUB bootflags ==="
GRUB_FILE=/etc/default/grub
BACKUP="$GRUB_FILE.bak.$(date +%F-%T)"
cp "$GRUB_FILE" "$BACKUP"
echo "  backed up $GRUB_FILE → $BACKUP"

# add lockdown=integrity module.sig_enforce=1 kaslr kptr_restrict=2 inside GRUB_CMDLINE_LINUX=""
sed -i '/^GRUB_CMDLINE_LINUX=/ {
  s/^\(GRUB_CMDLINE_LINUX="\)\(.*\)\(".*\)$/\1\2 lockdown=integrity module.sig_enforce=1 kaslr kptr_restrict=2\3/
}' "$GRUB_FILE"

echo "  patched GRUB_CMDLINE_LINUX. now running update-grub..."
update-grub

echo
echo "=== 2) sysctl hardening ==="
SYSCTL_CONF=/etc/sysctl.d/99-hardening.conf
cat > "$SYSCTL_CONF" <<'EOF'
# Prevent userspace ptrace (Yama LSM)
kernel.yama.ptrace_scope = 1

# Hide kernel logs from unprivileged
kernel.dmesg_restrict    = 1

# Disable core-dumps of SUID binaries
fs.suid_dumpable         = 0

# ASLR / exec-shield
kernel.randomize_va_space= 2

# Prevent mmap of very low addresses
vm.mmap_min_addr         = 65536

# Network stack hardening
net.ipv4.conf.all.rp_filter            = 1
net.ipv4.conf.default.rp_filter        = 1
net.ipv4.conf.all.accept_source_route  = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians         = 1
net.ipv4.icmp_echo_ignore_broadcasts   = 1
net.ipv4.tcp_syncookies                = 1
EOF
echo "  wrote $SYSCTL_CONF"
sysctl --system

echo
echo "=== 3) /tmp & /var/tmp mount hardening ==="
FSTAB=/etc/fstab
FSTAB_BAK="$FSTAB.bak.$(date +%F-%T)"
cp "$FSTAB" "$FSTAB_BAK"
echo "  backed up $FSTAB → $FSTAB_BAK"

# if there's already a /tmp line, append noexec,nosuid,nodev
if grep -qE '^\s*tmpfs\s+/tmp\s+' "$FSTAB"; then
  sed -i '/^\s*tmpfs\s\+\/tmp\s\+/ {
    s/\(defaults\([^,]*\)\)/\1,noexec,nosuid,nodev/
  }' "$FSTAB"
else
  echo "tmpfs   /tmp    tmpfs   defaults,noexec,nosuid,nodev   0 0" >> "$FSTAB"
fi

if grep -qE '^\s*tmpfs\s+/var/tmp\s+' "$FSTAB"; then
  sed -i '/^\s*tmpfs\s\+\/var\/tmp\s\+/ {
    s/\(defaults\([^,]*\)\)/\1,noexec,nosuid,nodev/
  }' "$FSTAB"
else
  echo "tmpfs   /var/tmp tmpfs   defaults,noexec,nosuid,nodev   0 0" >> "$FSTAB"
fi

echo "  reloading systemd and remounting /tmp and /var/tmp..."
systemctl daemon-reload

for d in /tmp /var/tmp; do
  if mountpoint -q "$d"; then
    mount -o remount,noexec,nosuid,nodev "$d" || echo "WARN: could not remount $d, will apply on next reboot."
  else
    echo "INFO: $d is not mounted, mounting tmpfs now…"
    mount -t tmpfs -o defaults,noexec,nosuid,nodev tmpfs "$d" || \
      echo "WARN: could not mount tmpfs on $d, will apply on next reboot."
  fi
done

echo
echo "=== 4) AppArmor enforcement ==="
if command -v aa-enforce &>/dev/null; then
  aa-enforce /etc/apparmor.d/* || true
  echo "  all AppArmor profiles set to enforce"
else
  echo "  WARNING: AppArmor tools not found (is it installed?)"
fi

echo
echo "=== Done! ==="
echo "→ Reboot now to activate your new GRUB flags."
