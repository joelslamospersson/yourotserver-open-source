#!/usr/bin/env bash
# Ubuntu 24.04 LTS
# Fail2Ban + iptables hashlimit ( bucket per IP ) with persistence + safer logging

set -euo pipefail
trap 'die "Error on or near line ${LINENO}. See ${LOG_FILE}."' ERR

# Setup variables
APP_USER="${1:-${SUDO_USER:-$(id -un)}}"
USER_HOME="$(eval echo "~${APP_USER}")"
LOG_FILE="${USER_HOME}/fail2ban_setup.log"
JAIL_LOCAL="/etc/fail2ban/jail.local"
FILTER_DIR="/etc/fail2ban/filter.d"
MARKER="# managed by fail2ban_setup.sh"
ACCESS_LOG=""

log(){ echo -e "\n>>> $*" | tee -a "$LOG_FILE"; }
die(){
  echo -e "\n✖ $*" | tee -a "$LOG_FILE"
  echo -e "\n---- Begin fail2ban_setup.log ----"
  cat "$LOG_FILE" || true
  echo    "----  End fail2ban_setup.log  ----"
  exit 1
}

# require root
[[ $EUID -eq 0 ]] || die "Must run as root"

# init log
: >"$LOG_FILE"
chmod 600 "$LOG_FILE"
log "Starting Fail2Ban setup (user=${APP_USER})"

# 0) Install dependencies
log "[0/10] Installing dependencies (fail2ban, iptables-persistent)"
export DEBIAN_FRONTEND=noninteractive

# Check if we can reach package repositories
if ! apt-get update -qq; then
  log "Warning: apt-get update failed, continuing with existing package lists"
fi

# Install packages with better error handling
if ! apt-get install -y fail2ban iptables-persistent netfilter-persistent >/dev/null 2>&1; then
  log "Warning: Some packages failed to install, continuing with available packages"
  # Try to install fail2ban separately
  apt-get install -y fail2ban >/dev/null 2>&1 || log "Warning: fail2ban installation failed"
fi

# Helpers: add/delete/check iptables rules idempotent
ipt_has() {
  iptables -C "$@" >/dev/null 2>&1
}
ipt_add() {
  if ! ipt_has "$@"; then
    iptables -A "$@" || log "Warning: iptables -A $* failed, continuing..."
  fi
}
ipt_del_if_present() {
  iptables -D "$@" >/dev/null 2>&1 || true
}

# 1) Setup iptables hashlimit DDoS protection (bucket per IP)
log "[1/10] Setting up iptables hashlimit (7171/7172, 80/443, 22)"

# Check if conntrack module is available
if ! modprobe -n conntrack >/dev/null 2>&1; then
  log "Warning: conntrack module not available, using state instead"
  CONNTRACK_MODULE="state"
else
  CONNTRACK_MODULE="conntrack --ctstate"
fi

# Clear old variants
ipt_del_if_present INPUT -p tcp --dport 7171 -m hashlimit --hashlimit-name otsrv7171 -j DROP
ipt_del_if_present INPUT -p tcp --dport 7172 -m hashlimit --hashlimit-name otsrv7172 -j DROP
ipt_del_if_present INPUT -p tcp --dport 80   -m hashlimit --hashlimit-name http80  -j DROP
ipt_del_if_present INPUT -p tcp --dport 443  -m hashlimit --hashlimit-name https443 -j DROP
ipt_del_if_present INPUT -p tcp --dport 22   -m hashlimit --hashlimit-name ssh22   -j DROP

# New rules (use conntrack NEW or state NEW)
ipt_add INPUT -p tcp --dport 7171 -m $CONNTRACK_MODULE NEW -m hashlimit \
  --hashlimit-name otsrv7171 --hashlimit-above 15/10s --hashlimit-burst 20 \
  --hashlimit-mode srcip --hashlimit-htable-expire 300000 -j DROP

ipt_add INPUT -p tcp --dport 7172 -m $CONNTRACK_MODULE NEW -m hashlimit \
  --hashlimit-name otsrv7172 --hashlimit-above 15/10s --hashlimit-burst 20 \
  --hashlimit-mode srcip --hashlimit-htable-expire 300000 -j DROP

ipt_add INPUT -p tcp --dport 80 -m $CONNTRACK_MODULE NEW -m hashlimit \
  --hashlimit-name http80 --hashlimit-above 120/10s --hashlimit-burst 200 \
  --hashlimit-mode srcip --hashlimit-htable-expire 300000 -j DROP

ipt_add INPUT -p tcp --dport 443 -m $CONNTRACK_MODULE NEW -m hashlimit \
  --hashlimit-name https443 --hashlimit-above 120/10s --hashlimit-burst 200 \
  --hashlimit-mode srcip --hashlimit-htable-expire 300000 -j DROP

ipt_add INPUT -p tcp --dport 22 -m $CONNTRACK_MODULE NEW -m hashlimit \
  --hashlimit-name ssh22 --hashlimit-above 5/10s --hashlimit-burst 10 \
  --hashlimit-mode srcip --hashlimit-htable-expire 300000 -j DROP

# Save persistent rules
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || log "Warning: netfilter-persistent save failed"
  log "→ iptables hashlimit configured & saved (netfilter-persistent)"
else
  log "→ iptables hashlimit configured (netfilter-persistent not available)"
fi

# 1b) Ensure loopback always allowed + SSH/HTTP reachable (handles custom ports)
# Always allow loopback early
if ! iptables -C INPUT -i lo -j ACCEPT >/dev/null 2>&1; then
  iptables -I INPUT 1 -i lo -j ACCEPT || true
fi

# 1c) Ensure SSH port is always reachable (handles custom ports)
# Detect active SSH port from config; default to 22
SSH_PORT="$(awk '/^\s*Port\s+/ {print $2}' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -n1)"
[[ -z "$SSH_PORT" ]] && SSH_PORT=22

# Add global ESTABLISHED/RELATED fast-path at top of INPUT
if ! iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; then
  iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
fi

# Insert an early ACCEPT for the SSH port before any UFW chains (position 2 is typically safe)
if ! iptables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT >/dev/null 2>&1; then
  iptables -I INPUT 2 -p tcp --dport "$SSH_PORT" -j ACCEPT || true
fi

# Do the same for IPv6 if available
if command -v ip6tables >/dev/null 2>&1; then
  if ! ip6tables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1; then
    ip6tables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || true
  fi
  if ! ip6tables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT >/dev/null 2>&1; then
    ip6tables -I INPUT 2 -p tcp --dport "$SSH_PORT" -j ACCEPT || true
  fi
fi

# Persist again if possible so rules survive reboot
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
fi

# 1d) Early ACCEPT for HTTP/HTTPS to avoid legacy UFW chains blocking
for PORT in 80 443; do
  if ! iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT >/dev/null 2>&1; then
    iptables -I INPUT 2 -p tcp --dport "$PORT" -j ACCEPT || true
  fi
  if command -v ip6tables >/dev/null 2>&1; then
    if ! ip6tables -C INPUT -p tcp --dport "$PORT" -j ACCEPT >/dev/null 2>&1; then
      ip6tables -I INPUT 2 -p tcp --dport "$PORT" -j ACCEPT || true
    fi
  fi
done

# 2) Detect access log (nginx/apache)
if [[ -f /var/log/nginx/access.log ]]; then
  ACCESS_LOG="/var/log/nginx/access.log"
elif [[ -f /var/log/apache2/access.log ]]; then
  ACCESS_LOG="/var/log/apache2/access.log"
else
  ACCESS_LOG=""
fi
[[ -n "$ACCESS_LOG" ]] && log "→ Using ACCESS_LOG=$ACCESS_LOG" || log "→ No web access log detected (HTTP jails will be skipped)"

# 3) Backup & reset managed jail.local
if [[ -f "$JAIL_LOCAL" ]] && grep -qF "$MARKER" "$JAIL_LOCAL"; then
  cp -a "$JAIL_LOCAL" "${JAIL_LOCAL}.bak"
  log "[3/10] Backed up ${JAIL_LOCAL} -> ${JAIL_LOCAL}.bak"
fi

# 4) Write jail.local
log "[4/10] Writing ${JAIL_LOCAL}"
cat >"$JAIL_LOCAL" <<EOF
$MARKER
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = auto
ignoreip = 127.0.0.1/8 ::1
# Add your IP here if needed:
# ignoreip = 127.0.0.1/8 ::1 1.2.3.4

# Fail2ban log
fail2ban_socket = /run/fail2ban/fail2ban.sock

# iptables action
banaction = iptables-multiport

# SSH
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 4
bantime  = 12h
findtime = 10m

# Extra (if available)
[ssh-ddos]
enabled  = true
filter   = sshd-ddos
port     = ssh
logpath  = /var/log/auth.log
maxretry = 10
findtime = 1m
bantime  = 1h
EOF

# 4b) OT server jail only if log exists
if [[ -f /var/log/otserver.log ]]; then
  cat >>"$JAIL_LOCAL" <<'EOF'

[otserver]
enabled  = true
port     = 7171,7172
protocol = tcp
filter   = otserver
logpath  = /var/log/otserver.log
maxretry = 10
bantime  = 6h
findtime = 5m
EOF
  log "→ otserver jail enabled"
else
  log "→ Skipping otserver jail (no /var/log/otserver.log)"
fi

# 5) HTTP jails (if access log found)
if [[ -n "$ACCESS_LOG" ]]; then
  cat >>"$JAIL_LOCAL" <<EOF

[apache-login]
enabled  = true
port     = http,https
filter   = apache-auth
logpath  = $ACCESS_LOG
maxretry = 6
bantime  = 2h
findtime = 10m

[phpmyadmin]
enabled  = true
port     = http,https
filter   = phpmyadmin
logpath  = $ACCESS_LOG
maxretry = 5
bantime  = 24h
findtime = 10m

[nginx-4xx-5xx]
enabled  = true
filter   = nginx-4xx-5xx
port     = http,https
logpath  = $ACCESS_LOG
maxretry = 60
findtime = 60
bantime  = 5m

[login-php-dos]
enabled  = true
filter   = login-php-dos
port     = http,https
logpath  = $ACCESS_LOG
maxretry = 100
findtime = 60
bantime  = 5m

[login-bruteforce]
enabled  = true
filter   = login-bruteforce
port     = http,https
logpath  = $ACCESS_LOG
maxretry = 10
findtime = 5m
bantime  = 30m

[php-adm-bruteforce]
enabled  = true
filter   = php-adm-bruteforce
port     = http,https
logpath  = $ACCESS_LOG
maxretry = 25
findtime = 5m
bantime  = 1h

[bad-bots]
enabled  = true
filter   = bad-bots
port     = http,https
logpath  = $ACCESS_LOG
bantime  = 1h

[sql-injection]
enabled  = true
filter   = sql-injection
port     = http,https
logpath  = $ACCESS_LOG
bantime  = 1h

[shell-upload]
enabled  = true
filter   = shell-upload
port     = http,https
logpath  = $ACCESS_LOG
bantime  = 1h

[directory-traversal]
enabled  = true
filter   = directory-traversal
port     = http,https
logpath  = $ACCESS_LOG
bantime  = 1h

[suspicious-file-upload]
enabled  = true
filter   = suspicious-file-upload
port     = http,https
logpath  = $ACCESS_LOG
findtime = 5m
maxretry = 15
bantime  = 10m

[api-abuse]
enabled  = true
filter   = api-abuse
port     = http,https
logpath  = $ACCESS_LOG
bantime  = 1h

[xmlrpc-abuse]
enabled  = true
filter   = xmlrpc-abuse
port     = http,https
logpath  = $ACCESS_LOG
maxretry = 10
findtime = 5m
bantime  = 1h

[suspicious-params]
enabled  = true
filter   = suspicious-params
port     = http,https
logpath  = $ACCESS_LOG
bantime  = 1h

[web-admin-bruteforce]
enabled  = true
filter   = web-admin-bruteforce
port     = http,https
logpath  = $ACCESS_LOG
bantime  = 1h

[gm-login]
enabled  = true
filter   = gm-login
port     = http,https
logpath  = $ACCESS_LOG
findtime = 5m
maxretry = 3
bantime  = 1h

[register-abuse]
enabled  = true
filter   = register-abuse
port     = http,https
logpath  = $ACCESS_LOG
bantime  = 1h
EOF
else
  log "→ Skipping HTTP-based jails (no access log)"
fi

# 6) game-login (if otland log exists)
if [[ -f /var/log/otland/login.log ]]; then
  cat >>"$JAIL_LOCAL" <<'EOF'

[game-login]
enabled  = true
filter   = game-login
port     = 7171,7172
logpath  = /var/log/otland/login.log
bantime  = 1h
EOF
  log "→ game-login jail enabled"
fi

# 7) Recidive
cat >>"$JAIL_LOCAL" <<'EOF'

[recidive]
enabled   = true
filter    = recidive
logpath   = /var/log/fail2ban.log
action    = iptables-multiport[name=recidive, port="ssh,80,443,7171,7172"]
bantime   = 3h
findtime  = 1h
maxretry  = 10

[http-get-dos]
enabled   = true
filter    = http-get-dos
port      = http,https
# Note: changes automatically if ACCESS_LOG was nginx
logpath   = /var/log/nginx/access.log
maxretry  = 200
findtime  = 60
bantime   = 5m
action    = iptables-allports[name=ddos]
EOF
log "→ recidive + http-get-dos configured"

# 8) Copy/Write filters
log "[8/10] Installing filters"

# Copy standard filters if they exist
for f in sshd-ddos modsecurity http-get-dos recidive; do
  if [[ -f "/etc/fail2ban/filter.d/${f}.conf" ]]; then
    cp "/etc/fail2ban/filter.d/${f}.conf" "$FILTER_DIR/" || true
  fi
done

# Fallback filters if distro doesn't ship them
if [[ ! -f "$FILTER_DIR/sshd-ddos.conf" ]]; then
  cat >"$FILTER_DIR/sshd-ddos.conf" <<'EOF'
[Definition]
# Simple SSH abuse patterns without Fail2ban macros
failregex = ^.*sshd(?:\[\d+\])?: Invalid user .* from <HOST> port .*$
            ^.*sshd(?:\[\d+\])?: Failed (?:password|publickey) for .* from <HOST> port .*$
            ^.*sshd(?:\[\d+\])?: Received disconnect from <HOST> port .*$
            ^.*sshd(?:\[\d+\])?: error: maximum authentication attempts exceeded for .* from <HOST> port .*$
ignoreregex =
EOF
fi

if [[ ! -f "$FILTER_DIR/http-get-dos.conf" ]]; then
  cat >"$FILTER_DIR/http-get-dos.conf" <<'EOF'
[Definition]
# Match any request line; rate limiting is handled by maxretry/findtime
failregex = ^<HOST> - - \[.*\] "(GET|POST|HEAD|PUT|DELETE|OPTIONS) .+ HTTP/.*" [0-9]{3} .*$
ignoreregex =
EOF
fi

# OT server (adapt to your actual log lines)
cat >"$FILTER_DIR/otserver.conf" <<'EOF'
[Definition]
failregex = ^.*Connection attempt failed for .* \[IP: <HOST>\].*$
            ^.*Too many connections from <HOST>.*$
ignoreregex =
EOF

# game-login (example)
cat >"$FILTER_DIR/game-login.conf" <<'EOF'
[Definition]
failregex = ^.*Login failed for account.*<HOST>.*$
ignoreregex =
EOF

# HTTP generics (matches Combined log where IP comes first)
declare -A filters=(
  [nginx-4xx-5xx]='.*"(GET|POST) /(?!login\.php$|upload/).*" (4|5)[0-9][0-9]'
  [login-php-dos]='.*"POST /login\.php"'
  [login-bruteforce]='.*"POST /(login|user/login|admin/login).*" (401|403)'
  [php-adm-bruteforce]='.*"(GET|POST) /php_adm.*" (401|403)'
  [bad-bots]='.*"(curl|sqlmap|nikto|acunetix|fuzzer|nmap|python-requests|ZmEu|netsparker)".*'
  [sql-injection]='.*(union.*select| or 1=1|--|select.*from).*'
  [shell-upload]='.*(\.php|\.jsp|\.exe|\.asp|\.py|cmd=|php\?eval|shell\.php).*'
  [directory-traversal]='.*(\.\./|%%2e%%2e/).*'
  [suspicious-file-upload]='.*POST .*(/(uploads|tmp)/.*\.(php|jsp|exe|asp|py)).*'
  [api-abuse]='.*"(GET|POST) /(api/token|auth).*" (401|403)'
  [suspicious-params]='.*(;--|\?q=\.\.|eval\(|exec=).*'
  [web-admin-bruteforce]='.*"POST .*(install|config\.php|admin|setup).*" (401|403)'
  [gm-login]='.*"POST /admin.*" (401|403)'
  [register-abuse]='.*"POST /(register|api/register).*"'
  [xmlrpc-abuse]='.*"POST /xmlrpc\.php" (4|5)[0-9][0-9]'
  [phpmyadmin]='.*"(GET|POST).*phpmyadmin.*" 40[34] .*'
)

for name in "${!filters[@]}"; do
  cat >"$FILTER_DIR/${name}.conf" <<EOF
[Definition]
failregex = ^<HOST> ${filters[$name]}
ignoreregex =
EOF
done

# If ACCESS_LOG is Apache, change http-get-dos logpath
if [[ "$ACCESS_LOG" == "/var/log/apache2/access.log" ]]; then
  sed -i 's|^logpath\s*=\s*/var/log/nginx/access\.log|logpath = /var/log/apache2/access.log|' "$JAIL_LOCAL"
fi

# 9) Enable & reload
log "[9/10] Enabling & reloading fail2ban"

# Check if fail2ban service exists
if ! systemctl list-unit-files | grep -q fail2ban; then
  log "Warning: fail2ban service not found, trying to start anyway"
fi

# Try to enable and start fail2ban
if systemctl enable fail2ban >/dev/null 2>&1; then
  log "→ fail2ban service enabled"
else
  log "Warning: Failed to enable fail2ban service"
fi

# Try to start the service
if systemctl start fail2ban >/dev/null 2>&1; then
  log "→ fail2ban service started"
else
  log "Warning: Failed to start fail2ban service"
fi

# Try to reload configuration
if command -v fail2ban-client >/dev/null 2>&1; then
  if fail2ban-client reload >/dev/null 2>&1; then
    log "→ fail2ban-client reload OK"
  else
    log "→ reload failed; trying to restart service"
    systemctl restart fail2ban >/dev/null 2>&1 || log "Warning: Service restart failed"
  fi
else
  log "Warning: fail2ban-client not found"
fi

# Check if service is active
if systemctl is-active --quiet fail2ban; then
  log "→ fail2ban service is active"
else
  log "Warning: fail2ban service is not active, but continuing..."
fi

# 10) Show status
log "[10/10] Active jails:"
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client status | tee -a "$LOG_FILE" || log "Warning: Could not get fail2ban status"
else
  log "Warning: fail2ban-client not available for status check"
fi

# Change log ownership to appuser
chown "${APP_USER}:${APP_USER}" "$LOG_FILE" 2>/dev/null || log "Warning: Could not change log ownership"

log "Setup complete. Log saved to: $LOG_FILE"
exit 0
