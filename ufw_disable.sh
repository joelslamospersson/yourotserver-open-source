#!/usr/bin/env bash
set -euo pipefail

# ——— helpers ————————————————————————————————————————————————
# timestamped logger; all stdout goes to run_and_log’s buffer
log(){ echo "[$(date +'%Y-%m-%d %H:%M:%S')] [UFW] $*"; }

# on error, log and exit
err(){ log "ERROR: $*"; exit 1; }

# ---- ensure noninteractive install of iptables-persistent ----
export DEBIAN_FRONTEND=noninteractive
cat <<EOF | debconf-set-selections
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF

# ---- vars ----
PORTS=(22 80 443 7171 7172)
IPTABLES_SAVE="/etc/iptables/rules.v4"

# ---- 0) install iptables + persistence ----
if ! command -v iptables >/dev/null; then
  apt-get update -qq || err "apt-get update failed"
  apt-get install -y -qq iptables iptables-persistent \
    || err "install iptables/iptables-persistent failed"
fi

# ---- 1) create a rate‑limit chain if missing ----
# this chain will limit NEW connections to 60/minute with a burst of 120
if ! iptables -L RATE_LIMIT 2>/dev/null; then
  iptables -N RATE_LIMIT
  iptables -A RATE_LIMIT -m conntrack --ctstate NEW \
          -m limit --limit 60/min --limit-burst 120 -j ACCEPT
  iptables -A RATE_LIMIT -j DROP
fi

# ─── 2) cleanup old direct ACCEPTs & reapply RATE_LIMIT ──────────────────
PORTS=(22 80 443 7171 7172)
for p in "${PORTS[@]}"; do
  # 1) Remove any unsafe bare ACCEPT for this port
  while iptables -C INPUT -p tcp --dport "$p" -j ACCEPT &>/dev/null; do
    log "Removing old direct ACCEPT on port $p"
    iptables -D INPUT -p tcp --dport "$p" -j ACCEPT \
      || log "  ⚠ could not delete direct ACCEPT on port $p, continuing"
  done

  # 2) Ensure RELATED/ESTABLISHED comes first
  if ! iptables -C INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &>/dev/null; then
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  fi

  # 3) Now rate-limit NEW on this port
  if ! iptables -C INPUT -p tcp --dport "$p" -j RATE_LIMIT &>/dev/null; then
    log "Adding RATE_LIMIT rule for port $p"
    iptables -A INPUT -p tcp --dport "$p" -j RATE_LIMIT
  fi
done

# ---- accept loopback and drop invalid ----
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -A INPUT -i lo -j ACCEPT
iptables -C INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null \
  || iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# ---- default policy: drop everything else ----
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# ---- 3) save rules for reboot ----
# ensure the persistence directory & file exist
IPTABLES_DIR=$(dirname "$IPTABLES_SAVE")
echo "INFO: making sure $IPTABLES_DIR exists…" 
mkdir -p "$IPTABLES_DIR"   || err "could not create $IPTABLES_DIR"
: > "$IPTABLES_SAVE"        || err "could not create $IPTABLES_SAVE"
echo "INFO: saving current rules to $IPTABLES_SAVE"
iptables-save > "$IPTABLES_SAVE" || err "could not save iptables rules to $IPTABLES_SAVE"

# ─── UFW DISABLE WITH VERBOSE LOGGING ──────────────────────────────────────
log "Checking for ufw…"

if ! command -v ufw &>/dev/null; then
  log "ufw not installed — nothing to do"
elif ufw status 2>&1 | grep -qi '^Status: active'; then
  log "ufw is active — attempting to disable…"
  if output=$(ufw --force disable 2>&1); then
    log "✔ ufw disabled successfully: $output"
  else
    log "⚠ ufw disable failed (exit $?): $output"
  fi
else
  log "ufw is not active — skipping disable"
fi

echo "OK: iptables rules set and ufw disable attempted"
exit 0
