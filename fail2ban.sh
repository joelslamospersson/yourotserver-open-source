#!/usr/bin/env bash
# Ubuntu 24.04 LTS ( Current only )
set -euo pipefail
trap 'die "Error on or near line ${LINENO}. See ${LOG_FILE}."' ERR

# ─── Setup variables ───────────────────────────────────────────────────────
APP_USER="${1:-${SUDO_USER:-$(id -un)}}"
USER_HOME="$(eval echo "~${APP_USER}")"
LOG_FILE="${USER_HOME}/fail2ban_setup.log"
JAIL_LOCAL="/etc/fail2ban/jail.local"
FILTER_DIR="/etc/fail2ban/filter.d"
MARKER="# managed by fail2ban_setup.sh"

log(){ echo -e "\n>>> $*" | tee -a "$LOG_FILE"; }
die(){
  echo -e "\n✖ $*" | tee -a "$LOG_FILE"
  echo -e "\n---- Begin fail2ban_setup.log ----" | tee -a "$LOG_FILE"
  cat "$LOG_FILE"           | tee -a "$LOG_FILE"
  echo    "----  End fail2ban_setup.log  ----" | tee -a "$LOG_FILE"
  exit 1
}

# ─── require root ─────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Must run as root"

# ─── init log ─────────────────────────────────────────────────────────────
: >"$LOG_FILE"
chmod 600 "$LOG_FILE"
log "Starting Fail2Ban setup (user=${APP_USER})"

# ─── 1) Install fail2ban if missing ────────────────────────────────────────
if ! dpkg -s fail2ban &>/dev/null; then
  log "[1/9] Installing fail2ban"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban
else
  log "[1/9] fail2ban already installed"
fi

# ─── declare your custom filters ───────────────────────────────────────────
declare -A filters=(
  [nginx-4xx-5xx]='"(GET|POST) /(?!login\\.php$|upload/).*" (4|5)[0-9][0-9]'
  [login-php-dos]='"POST /login\\.php"'
  [login-bruteforce]='"POST /(login|user/login|admin/login).*" (401|403)'
  [php-adm-bruteforce]='"(GET|POST) /php_adm.*" (401|403)'
  [bad-bots]='"(curl|sqlmap|nikto|acunetix|fuzzer|nmap|python-requests|ZmEu|netsparker)"'
  [sql-injection]='(union.*select| or 1=1|--|select.*from)'
  [shell-upload]='"(\.php|\.jsp|\.exe|\.asp|\.py|cmd=|php\?eval|shell\.php)"'
  [directory-traversal]='(\.\.\/|%%2e%%2e\/)'
  # Suspicious file uploads ─────────────────────────────────────────────
  [suspicious-file-upload]='POST .*(/(uploads|tmp)/.*\.(php|jsp|exe|asp|py))'
  [api-abuse]='"(GET|POST) /(api/token|auth).*" (401|403)'
  [suspicious-params]='(;--|\?q=\.\.|eval\(|exec=)'
  [game-login]='Login failed for account'
  [http-get-dos]='"GET /(?!assets|images|css|js|favicon).*"'
  # Extra secure net, not needed and should not exist?
  [web-admin-bruteforce]='"POST (?!.*(/php_adm|/admin)).*(install|config\.php|admin|setup).*" (401|403)'
  [gm-login]='"POST /admin.*" (401|403)'
  [register-abuse]='"POST /(register|api/register).*"'

  # Wordpress/API protection filters ───────────────────────────────
  [xmlrpc-abuse]='"POST /xmlrpc\.php" (4|5)[0-9][0-9]'
)

# ─── 2) Backup & reset any prior run ───────────────────────────────────────
if grep -qF "$MARKER" "$JAIL_LOCAL" 2>/dev/null; then
  log "[2/9] jail.local already managed; backing up & resetting"
  cp "$JAIL_LOCAL" "${JAIL_LOCAL}.bak"
  for f in "${!filters[@]}"; do
    rm -f "${FILTER_DIR}/${f}.conf"
  done
fi

# ─── 2) Start fresh jail.local ─────────────────────────────────────────────
log "[2/9] Writing managed jail.local"
cat >"$JAIL_LOCAL" <<EOF
$MARKER
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 30m
findtime = 10m
maxretry = 5
backend  = auto

[sshd]
enabled  = true
filter   = sshd
port     = ssh,57500-57532
logpath  = /var/log/auth.log
EOF

# ─── 2a) sshd-ddos ────────────────────────────────────────────────────────
if [[ -f /etc/fail2ban/filter.d/sshd-ddos.conf ]]; then
  cat >>"$JAIL_LOCAL" <<EOF

[ssh-ddos]
enabled  = true
filter   = sshd-ddos
port     = ssh,57500-57532
logpath  = /var/log/auth.log
maxretry = 10
findtime = 1m
bantime  = 1h
EOF
  log "→ sshd-ddos jail enabled"
fi

# ─── 2b) Mail services ────────────────────────────────────────────────────
if [[ -f /var/log/mail.log ]]; then
  cat >>"$JAIL_LOCAL" <<EOF

[postfix]
enabled = true
filter  = postfix
port    = smtp,ssmtp
logpath = /var/log/mail.log

[dovecot]
enabled = true
filter  = dovecot
port    = pop3,pop3s,imap,imaps
logpath = /var/log/mail.log
EOF
  log "→ postfix & dovecot jails enabled"
fi

# ─── 2c) FTP services ─────────────────────────────────────────────────────
if [[ -f /etc/fail2ban/filter.d/vsftpd.conf && -f /var/log/vsftpd.log ]]; then
  cat >>"$JAIL_LOCAL" <<EOF

[vsftpd]
enabled = true
filter  = vsftpd
port    = ftp,ftp-data,ftps
logpath = /var/log/vsftpd.log
EOF
  log "→ vsftpd jail enabled"
fi

# ─── 2d) HTTP-based jails ─────────────────────────────────────────────────
ACCESS_LOG=""
if [[ -f /var/log/nginx/access.log ]]; then
  ACCESS_LOG="/var/log/nginx/access.log"
elif [[ -f /var/log/apache2/access.log ]]; then
  ACCESS_LOG="/var/log/apache2/access.log"
fi

# nginx-4xx-5xx, login-bruteforce, common-scan, bad-bots,
# sql-injection, shell-upload, directory-traversal, suspicious-file-upload,
# api-abuse, exploit-scanner, suspicious-params, web-admin-bruteforce,
# HTTP-based jails, ( nginx-4xx-5xx ), not needed if exchanged for bad-bots, common-scan,
# bot brute-forcing invalid URLs (like /admin, /phpmyadmin, etc.).

#nginx-4xx-5xx -> skips login.php, php_adm, upload directories.
# For login.php, we instead use login-php-dos jail.

if [[ -n "$ACCESS_LOG" ]]; then
  cat >>"$JAIL_LOCAL" <<EOF
[nginx-4xx-5xx]
enabled = true
filter  = nginx-4xx-5xx
port    = http,https
logpath = $ACCESS_LOG
maxretry = 60
findtime = 1m
bantime  = 5m

[login-php-dos]
enabled = true
filter  = login-php-dos
port    = http,https
logpath = /var/log/nginx/access.log
maxretry = 100
findtime = 1m
bantime  = 5m

[login-bruteforce]
enabled = true
filter  = login-bruteforce
port    = http,https
logpath = $ACCESS_LOG
maxretry = 10
findtime = 5m
bantime = 30m

[php-adm-bruteforce]
enabled  = true
filter   = php-adm-bruteforce
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 25
findtime = 5m
bantime  = 1h

[bad-bots]
enabled = true
filter  = bad-bots
port    = http,https
logpath = $ACCESS_LOG
bantime = 1h

[sql-injection]
enabled = true
filter  = sql-injection
port    = http,https
logpath = $ACCESS_LOG
bantime = 1h

[shell-upload]
enabled = true
filter  = shell-upload
port    = http,https
logpath = $ACCESS_LOG
bantime = 1h

[directory-traversal]
enabled = true
filter  = directory-traversal
port    = http,https
logpath = $ACCESS_LOG
bantime = 1h

[suspicious-file-upload]
enabled = true
filter  = suspicious-file-upload
port    = http,https
logpath = $ACCESS_LOG
findtime = 5m
maxretry = 15
bantime  = 10m

[api-abuse]
enabled = true
filter  = api-abuse
port    = http,https
logpath = $ACCESS_LOG
bantime = 1h

[xmlrpc-abuse]
enabled  = true
filter   = xmlrpc-abuse
port     = http,https
logpath  = /var/log/nginx/access.log
maxretry = 10
findtime = 5m
bantime  = 1h

[suspicious-params]
enabled = true
filter  = suspicious-params
port    = http,https
logpath = $ACCESS_LOG
bantime = 1h

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
  log "→ HTTP-based jails enabled"
else
  log "→ Skipping HTTP-based jails (no access log)"
fi

# ─── 2e) OT-server game-login failures ────────────────────────────────────
if [[ -f /var/log/otland/login.log ]]; then
  cat >>"$JAIL_LOCAL" <<EOF

[game-login]
enabled  = true
filter   = game-login
port     = 7171,7172
logpath  = /var/log/otland/login.log
bantime  = 1h
EOF
  log "→ game-login jail enabled"
fi

# ─── 2f) Recidive (always-on) ────────────────────────────────────────────
cat >>"$JAIL_LOCAL" <<EOF

[recidive]
enabled  = true
filter   = recidive
# only yank your “public” ports
action   = iptables-multiport[name=recidive, port="ssh,80,443,7171,7172"]
bantime  = 3h
findtime = 1h
maxretry = 10

[http-get-dos]
enabled   = true
filter    = http-get-dos
port      = http,https
logpath   = /var/log/nginx/access.log
maxretry  = 600
findtime  = 60
bantime   =  5m
action    = iptables-allports[name=ddos]
EOF

log "→ recidive jail enabled"

# ─── 3) Copy distro filters ───────────────────────────────────────────────
log "[3/9] Copying distro filters"
for f in sshd-ddos modsecurity http-get-dos; do
  src="/etc/fail2ban/filter.d/${f}.conf"
  dst="${FILTER_DIR}/${f}.conf"
  if [[ -f "$src" ]]; then
    cp "$src" "$dst"
    log "→ copied ${f}.conf"
  else
    log "→ distro filter ${f}.conf not found, skipping"
  fi
done

# ─── 3a) Deploy custom filters ────────────────────────────────────────────
log "[3/9] Writing custom filters"
for name in "${!filters[@]}"; do
  file="$FILTER_DIR/${name}.conf"
  log "→ ${name}"
  cat >"$file" <<EOF
[Definition]
failregex = ^<HOST> .*${filters[$name]}
ignoreregex =
EOF
done

# ─── 4) pure-ftpd filter ─────────────────────────────────────────────────
if [[ ! -f "$FILTER_DIR/pure-ftpd.conf" ]]; then
  log "[4/9] Deploying pure-ftpd filter"
  cat >"$FILTER_DIR/pure-ftpd.conf" <<EOF
[Definition]
failregex = ^<HOST> .*Login authentication failed
ignoreregex =
EOF
else
  log "[4/9] pure-ftpd filter already present"
fi

# ─── 5) recidive.conf ─────────────────────────────────────────────────────
if [[ ! -f "$FILTER_DIR/recidive.conf" ]]; then
  log "[5/9] Installing recidive filter"
  cp /etc/fail2ban/filter.d/recidive.conf "$FILTER_DIR/"
else
  log "[5/9] recidive filter already present"
fi

# ─── 6) Enable & reload/restart ───────────────────────────────────────────
log "[6/9] Enabling & reloading fail2ban"
systemctl enable fail2ban
if systemctl show fail2ban --property=CanReload | grep -q 'yes$'; then
  log "→ systemctl reload"
  if systemctl reload fail2ban; then
    log "→ reload succeeded"
  else
    log "→ reload failed; trying fail2ban-client"
    if fail2ban-client reload; then
      log "→ client reload succeeded"
    else
      log "→ client reload failed; restarting"
      systemctl restart fail2ban
    fi
  fi
else
  log "→ reload not supported; using fail2ban-client"
  if fail2ban-client reload; then
    log "→ client reload succeeded"
  else
    log "→ client reload failed; restarting"
    systemctl restart fail2ban
  fi
fi

# ─── 7) Final check ───────────────────────────────────────────────────────
if systemctl is-active --quiet fail2ban; then
  log "[7/9] fail2ban is running"
else
  die "fail2ban service is not active"
fi

# ─── 8) List active jails ─────────────────────────────────────────────────
log "[8/9] Active jails:"
if fail2ban-client status | tee -a "$LOG_FILE"; then
  log "→ listed jails successfully"
else
  log "→ Warning: could not list active jails"
fi

# ─── 9) Done & dump log ───────────────────────────────────────────────────
log "[9/9] Setup complete!"

# make the log readable by the app user
chown "${APP_USER}:${APP_USER}" "$LOG_FILE"

log "[10/9] Full fail2ban_setup.log:"
cat "$LOG_FILE"

exit 0
