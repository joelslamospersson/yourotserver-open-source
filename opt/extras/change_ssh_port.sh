#!/usr/bin/env bash
set -euo pipefail

# If executed directly, ensure the script is executable
if [[ ! -x "$0" ]]; then
  chmod +x "$0" || {
    echo "✖ Could not make $0 executable" >&2
    exit 1
  }
fi

# ─── Setup variables ────────────────────────────────────────────────────────
APP_USER="${SUDO_USER:-$(id -un)}"
USER_HOME="$(eval echo "~${APP_USER}")"
PORT_FILE="${USER_HOME}/port.txt"

SSHD_CONF=/etc/ssh/sshd_config
RATE_CHAIN=RATE_LIMIT
IPTABLES_SAVE=/etc/iptables/rules.v4

log(){ echo "[$(date +'%Y-%m-%d %H:%M:%S')] ChangeSSH: $*"; }
err(){ echo "[$(date +'%Y-%m-%d %H:%M:%S')] ChangeSSH ERROR: $*" >&2; }

log "Starting Change SSH Port script"

# ─── 1) Detect current SSH port ───────────────────────────────────────────
# try to read the first "Port" line, otherwise default to 22
CURRENT_PORT=$(
  awk '
    BEGIN {port="22"} 
    /^\s*Port[[:space:]]+[0-9]+/ { port=$2; exit } 
    END { print port }
  ' "$SSHD_CONF"
)
log "Current SSH port: $CURRENT_PORT"

# ─── 2) Pick or keep SSH port ─────────────────────────────────────────────
if [[ "$CURRENT_PORT" =~ ^(22|2222|2200|2022)$ ]]; then
  NEW_PORT=$(shuf -i 57500-57532 -n1)
  log "Rotating SSH port to $NEW_PORT"
  if grep -q '^\s*#\?Port[[:space:]]' "$SSHD_CONF"; then
    sed -i "s|^\s*#\?Port[[:space:]].*|Port $NEW_PORT|" "$SSHD_CONF" \
      && log "Updated Port line in $SSHD_CONF"
  else
    echo -e "\nPort $NEW_PORT" >> "$SSHD_CONF" \
      && log "Appended Port $NEW_PORT to $SSHD_CONF"
  fi
else
  NEW_PORT="$CURRENT_PORT"
  log "Keeping existing custom SSH port: $NEW_PORT"
fi

# ─── 3) Record the chosen port in ~/port.txt ──────────────────────────────
if echo "$NEW_PORT" > "$PORT_FILE"; then
  chown "$APP_USER:$APP_USER" "$PORT_FILE"
  log "Wrote SSH port ($NEW_PORT) to $PORT_FILE"
else
  err "Failed to write SSH port to $PORT_FILE"
fi

# ─── 3a) Emit the marker that worker.py is expecting ──────────────────────
if [[ "$NEW_PORT" == "$CURRENT_PORT" ]]; then
  echo "KEEPING_SSH_PORT:$NEW_PORT"
else
  echo "CHANGED_SSH_PORT:$NEW_PORT"
fi

# ─── 4) Ensure RATE_LIMIT chain exists ────────────────────────────────────
log "Ensuring iptables chain $RATE_CHAIN exists"
if ! iptables -L "$RATE_CHAIN" &>/dev/null; then
  iptables -N "$RATE_CHAIN" \
    && iptables -A "$RATE_CHAIN" \
         -m conntrack --ctstate NEW \
         -m limit --limit 60/min --limit-burst 120 \
         -j ACCEPT \
    && iptables -A "$RATE_CHAIN" -j DROP \
    && log "Created chain $RATE_CHAIN with rate-limit and DROP rules" \
    || err "Failed to create/configure chain $RATE_CHAIN"
else
  log "Chain $RATE_CHAIN already exists"
fi

# ─── 5) Apply rate-limit for the SSH port ─────────────────────────────────
log "Adding RELATED,ESTABLISHED accept rule"
iptables -C INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT \
  || (iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT \
      && log "Inserted RELATED,ESTABLISHED rule")

log "Rate-limiting NEW SSH on port $NEW_PORT"
iptables -C INPUT -p tcp --dport "$NEW_PORT" -j "$RATE_CHAIN" \
  || (iptables -A INPUT -p tcp --dport "$NEW_PORT" -j "$RATE_CHAIN" \
      && log "Inserted RATE_LIMIT → port $NEW_PORT")

# ─── 6) Clean up old port rule if we rotated ─────────────────────────────
if [[ "$CURRENT_PORT" =~ ^(22|2222|2200|2022)$ ]] && [[ "$NEW_PORT" != "$CURRENT_PORT" ]]; then
  log "Removing old rate-limit rule for port $CURRENT_PORT"
  # only attempt deletion if the rule actually exists
  if iptables -C INPUT -p tcp --dport "$CURRENT_PORT" -j "$RATE_CHAIN" &>/dev/null; then
    iptables -D INPUT -p tcp --dport "$CURRENT_PORT" -j "$RATE_CHAIN" \
      && log "Removed old port rule for $CURRENT_PORT" \
      || err "Failed to remove old port rule for $CURRENT_PORT"
  else
    log "No existing rate-limit rule found for port $CURRENT_PORT, skipping delete"
  fi
fi

# ─── 7) Persist iptables rules ────────────────────────────────────────────
log "Saving iptables rules to $IPTABLES_SAVE"
mkdir -p "$(dirname "$IPTABLES_SAVE")" \
  && iptables-save > "$IPTABLES_SAVE" \
  && log "iptables rules saved" \
  || err "Failed to save iptables rules"

exit 0
