#!/usr/bin/env bash
set -euo pipefail

SSHD_CONF="/etc/ssh/sshd_config"

# If it’s already “no”, nothing to do
if grep -qE '^[[:space:]]*PermitRootLogin[[:space:]]+no' "$SSHD_CONF"; then
  echo "OK: root login already disabled"
  exit 0
fi

# Otherwise back it up and flip/append
BACKUP="${SSHD_CONF}.bak.$(date +%s)"
cp "$SSHD_CONF" "$BACKUP" \
  || { echo "ERR: could not back up $SSHD_CONF"; exit 1; }

if grep -qE '^[[:space:]]*PermitRootLogin' "$SSHD_CONF"; then
  sed -i 's/^[[:space:]]*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONF" \
    || { echo "ERR: sed failed"; exit 1; }
else
  echo "" >> "$SSHD_CONF"
  echo "PermitRootLogin no" >> "$SSHD_CONF" \
    || { echo "ERR: append failed"; exit 1; }
fi

# Reload the service
# Try systemctl on both common unit names, then fall back to service(8)
if systemctl reload sshd 2>/dev/null; then
  :
elif systemctl reload ssh 2>/dev/null; then
  :
elif service ssh reload >/dev/null 2>&1; then
  :
elif service sshd reload >/dev/null 2>&1; then
  :
else
  echo "WARN: could not reload SSH daemon; config is updated but service may need manual reload"
fi

echo "OK: root login disabled"
exit 0
