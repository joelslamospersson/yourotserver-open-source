#!/usr/bin/env bash
set -euo pipefail

# Get basic variables first
APP_USER="${1:-${SUDO_USER:-$(id -un)}}"
USER_HOME="/home/${APP_USER}"
LOG_FILE="${USER_HOME}/myacc_setup.log"
PMA_CRED_FILE="${USER_HOME}/phpmyadmin.txt"

# Define functions immediately after variables
log(){ echo -e "\n>>> $*" | tee -a "${LOG_FILE}"; }
die(){ echo -e "\n✖ $*" | tee -a "${LOG_FILE}"; exit 1; }

# Set up error trap now that die function is defined
trap 'die "Error on or near line ${LINENO}. See ${LOG_FILE}."' ERR

# Generate secure 32-character MySQL root password
MYSQL_ROOT_PASS="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9!#' | head -c 32 | tr -d ' ')"
# Engine autodetect: support ~/tfs or /root/tfs, and ~/canary or /root/canary
# TFS requires passwordType = "sha1" in config.lua for proper password hashing
TFS_DIR_USER="${USER_HOME}/tfs"
CANARY_DIR_USER="${USER_HOME}/canary"
TFS_DIR_ROOT="/root/tfs"
CANARY_DIR_ROOT="/root/canary"

if [[ -d "$TFS_DIR_USER" ]]; then
  ENGINE_DIR="$TFS_DIR_USER"
elif [[ -d "$TFS_DIR_ROOT" ]]; then
  ENGINE_DIR="$TFS_DIR_ROOT"
elif [[ -d "$CANARY_DIR_USER" ]]; then
  ENGINE_DIR="$CANARY_DIR_USER"
elif [[ -d "$CANARY_DIR_ROOT" ]]; then
  ENGINE_DIR="$CANARY_DIR_ROOT"
else
  # default to user-canary path if neither exists yet (first-time run)
  ENGINE_DIR="$CANARY_DIR_USER"
fi
ENGINE_NAME="$(basename "$ENGINE_DIR")"   # "tfs" or "canary"
DB_NAME="$ENGINE_NAME"

# Set executable permissions for MyAcc to access engine directories
log "Setting executable permissions for MyAcc access to engine directories..."
chmod +x /home
if [[ -d "$USER_HOME" ]]; then
  chmod +x "$USER_HOME"
  log "Set executable permission on $USER_HOME"
fi
if [[ -d "$ENGINE_DIR" ]]; then
  chmod +x "$ENGINE_DIR"
  log "Set executable permission on $ENGINE_DIR"
fi
# Also set permissions on /root if engine is there
if [[ "$ENGINE_DIR" == "/root/"* ]]; then
  chmod +x /root
  log "Set executable permission on /root"
fi

# Handle special case for Nostalrius (uses nostalrius.sql instead of schema.sql)
# Too lazy to rename the file, req unzip and zip
if [[ "$ENGINE_NAME" == "tfs" ]] && [[ -f "${ENGINE_DIR}/nostalrius.sql" ]]; then
  SCHEMA_FILE="${ENGINE_DIR}/nostalrius.sql"
  log "Using nostalrius.sql for TFS database schema"
else
  SCHEMA_FILE="${ENGINE_DIR}/schema.sql"
fi
DEF_NGINX="/etc/nginx/sites-available/default"

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export COMPOSER_ALLOW_SUPERUSER=1
export COMPOSER_HOME=/root/.config/composer

# acceleration with eatmydata (fallback to no-op if missing)
if command -v eatmydata >/dev/null 2>&1; then
  EAT="eatmydata"
else
  EAT=""
fi

find_blockers() {
    ps -eo pid,ppid,comm,args | grep -E 'apt(-get)?|dpkg|unattended-upgrade|mandb|update-mandb|update-mime' | grep -vE "grep|$$" | awk '{print $1}'
}

kill_blockers_safe() {
    log "Scanning for dpkg/apt blockers (safe, skip our install process)..."
    local pids
    pids=$(find_blockers)
    for pid in $pids; do
        if ! pstree -ps $$ | grep -qw $pid; then
            log "Killing blocker process $pid"
            kill -9 $pid || true
        fi
    done
    rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* || true
}

kill_blockers() {
    log "Killing dpkg/apt-get/apt/lock blockers (and any stuck composer, php, npm, node, unattended-upgrade, mandb)"
    for proc in apt-get apt dpkg mandb update-mandb update-mime composer php npm node unattended-upgrade; do
        pkill -9 "$proc" 2>/dev/null || true
    done
    rm -f /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* || true
}

trycmd() {
    local _cmd="$1"; local _retries="${2:-2}"; local _delay="${3:-10}"; local _rc
    for _try in $(seq 1 $_retries); do
        log "trycmd: ($_try/$_retries) $_cmd"
        eval $_cmd && return 0
        _rc=$?
        log "[WARN] trycmd failed ($_try): rc=$_rc, will retry after $_delay sec"
        kill_blockers
        sleep $_delay
    done
    log "❌ trycmd: failed after $_retries tries: $_cmd"
    return 1
}

run_apt_fast_aggressive(){
  local tmo=1800
  local cmd="$*"
  local start_time=$(date +%s)
  local rc
  local main_pid

  wait_for_dpkg_lock
  kill_blockers_safe
  log "→ $cmd (timeout ${tmo}s, aggressive lock killer)"

  timeout $tmo bash -c "$EAT $cmd" &
  main_pid=$!

  while kill -0 $main_pid 2>/dev/null; do
    sleep 5
    if (( $(date +%s) - start_time > tmo )); then
      log "[WARN] Install process timed out, killing..."
      kill -9 $main_pid 2>/dev/null || true
      wait $main_pid 2>/dev/null
      return 124
    fi
  done

  wait $main_pid
  rc=$?
  if (( rc == 0 )); then
    log "[OK] $cmd"
    return 0
  else
    log "[WARN] $cmd failed with rc=$rc"
    return $rc
  fi
}

# Lock to avoid conflicts with other processes
# Fucking hell, this is the most annoying thing ever
wait_for_dpkg_lock(){
  local sec=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
    ((sec++))
    log "⚠ dpkg locked (${sec}s)…"
    [ $sec -ge 10 ] && { kill_blockers; sec=0; }
    sleep 1
  done
}

# Speedy boy
run_apt_fast(){
  local tmo=600
  local cmd
  if [[ "$1" =~ ^[0-9]+$ ]]; then
    tmo="$1"
    shift
  fi
  cmd="$*"
  local rc attempt=1
  while (( attempt <= 2 )); do
    wait_for_dpkg_lock
    kill_blockers
    log "→ $cmd (timeout ${tmo}s, try #$attempt)"
    timeout $tmo bash -c "$EAT $cmd"
    rc=$?
    if (( rc == 0 )); then
      log "[OK] $cmd"
      return 0
    elif (( rc == 124 )); then
      log "[WARN] $cmd timed out, killing blockers and retrying"
      kill_blockers
      (( attempt++ ))
      continue
    else
      log "[WARN] $cmd failed with rc=$rc, retrying"
      kill_blockers
      (( attempt++ ))
      continue
    fi
  done
  log "❌ $cmd failed after 2 tries"
  return 1
}

APT_FAST="-o Dpkg::Options::=--no-triggers -o Dpkg::Options::=--force-unsafe-io --no-install-recommends"

cat > /usr/sbin/policy-rc.d <<'EOF'
#!/bin/sh
exit 101
EOF
chmod +x /usr/sbin/policy-rc.d

[[ $EUID -eq 0 ]] || die "Must run as root"

: >"${LOG_FILE}"
chmod 600 "${LOG_FILE}"
log "Starting full MyAcc+Canary setup (user=${APP_USER})"

log "Neutering man-db triggers and binaries (mandb, update-mandb, update-mime)"
if [ ! -L /usr/bin/mandb ]; then
    dpkg-divert --local --rename --add /usr/bin/mandb
    ln -sf /bin/true /usr/bin/mandb
fi
if [ ! -L /usr/bin/update-mime ]; then
    dpkg-divert --local --rename --add /usr/bin/update-mime
    ln -sf /bin/true /usr/bin/update-mime
fi
if [ ! -L /usr/share/man-db/update-mandb ]; then
    dpkg-divert --local --rename --add /usr/share/man-db/update-mandb
    echo -e '#!/bin/sh\nexit 0' > /usr/share/man-db/update-mandb
    chmod +x /usr/share/man-db/update-mandb
fi
echo "man-db hold" | dpkg --set-selections

cat > /etc/dpkg/dpkg.cfg.d/01_nodocs <<EOF
path-exclude=/usr/share/doc/*
path-exclude=/usr/share/groff/*
path-exclude=/usr/share/info/*
path-exclude=/usr/share/lintian/*
path-exclude=/usr/share/man/*
EOF
cat > /etc/apt/apt.conf.d/99locale <<EOF
Acquire::Languages "none";
EOF
cat > /etc/apt/apt.conf.d/90parallel <<EOF
Acquire::Queue-Mode "access";
Acquire::http { Pipeline-Depth "10"; };
EOF

if [ ! -L /usr/sbin/locale-gen ]; then
    dpkg-divert --local --rename --add /usr/sbin/locale-gen
    ln -sf /bin/true /usr/sbin/locale-gen
fi

set +e
for attempt in 1 2; do
  log "---- Provision attempt #$attempt ----"
  kill_blockers
  run_apt_fast "dpkg --configure -a"
  kill_blockers
  run_apt_fast "apt-get install -f -y $APT_FAST"

  # ------- PHP SECTION, FASTEST INSTALL ---------
  kill_blockers
  # Install all web stack components in one command for speed
  run_apt_fast_aggressive "apt-get install -y $APT_FAST nginx ufw php-fpm php-mysql php-cli php-common php-gd php-zip mysql-server mysql-client-core-8.0 libmysqlclient-dev composer nodejs npm"

  ufw --force enable || true; ufw allow 80; ufw allow 443

  rm -f /usr/sbin/policy-rc.d
  kill_blockers
  pkill -9 mysqld mysqld_safe || true
  rm -f /var/run/mysqld/*.pid /var/run/mysqld/*.sock || true
  sleep 1

  kill_blockers
  systemctl enable mysql
  systemctl restart mysql
  mysql_ok=0
  for try in {1..4}; do
    sleep 2
    if mysqladmin ping -uroot --silent; then
      log "[OK] mysql running"
      mysql_ok=1; break
    else
      pkill -9 mysqld mysqld_safe || true
      sleep 3
    fi
  done

  if ((mysql_ok==1)); then
    log "[MySQL] Securing root and privileges"
    mysql -uroot <<SQL
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
UPDATE mysql.user SET Host='localhost' WHERE User='root';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db LIKE 'test%';
FLUSH PRIVILEGES;
SQL
  fi

# Place holder for SSL setup, will be replaced by letsencrypt.sh
# If not, user can do this manually after the install
cat > "$DEF_NGINX" <<EOF
# Change yourdomain.com to your actual domain name, in case of SSL setup
# 1) Redirect all HTTP requests (any host) → HTTPS on yourdomain.com
#server {
#    listen 80 default_server;
#    listen [::]:80 default_server;
#    return 301 https://yourdomain.com\$request_uri;
#}

# 2) Catch‑all for HTTPS on 443 that doesn’t match our cert host → redirect
#server {
#    listen 443 ssl http2 default_server;
#    listen [::]:443 ssl http2 default_server;
#    server_name _;
#
#    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
#    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
#    include             /etc/letsencrypt/options-ssl-nginx.conf;
#    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;
#
#    return 301 https://yourdomain.com\$request_uri;
#}

# 3) Main site block for yourdomain.com & www.yourdomain.com (HTTP on port 80)
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /var/www/html;
    index index.php index.html;

    # SSL configuration (managed by Certbot)
    # ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    # include             /etc/letsencrypt/options-ssl-nginx.conf;
    # ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    # Allow larger uploads
    client_max_body_size 10M;

    # Serve static assets directly with long cache
    location ~* \.(?:ico|css|js|gif|jpe?g|png|woff2?|eot|ttf|svg|otf|webp|map)$ {
        access_log off;
        expires    30d;
        add_header Cache-Control "public";
        try_files  \$uri =404;
    }

    # “Pretty URL” front controller
    location / {
        try_files \$uri \$uri/ @rewrite;
    }
    location @rewrite {
        rewrite ^/(.*)$ /index.php/\$1 last;
    }

    # PHP execution (with PATH_INFO)
    location ~ ^(.+\.php)(/.*)?\$ {
        fastcgi_split_path_info ^(.+\.php)(/.*)\$;
        include             snippets/fastcgi-php.conf;
        fastcgi_pass        unix:/run/php/php8.3-fpm.sock;
        fastcgi_param       SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param       PATH_INFO       \$fastcgi_path_info;
        include             fastcgi_params;
        fastcgi_read_timeout 240;
    }

    # Deny access to internal/system folders
    location ~ ^/(system|vendor|storage|tests|\.env) {
        deny all;
    }

    # Deny dotfiles and version control
    location ~* /\.(?:ht|git|svn|env)\$ {
        deny all;
    }

    # Deny backups, docs, dumps, etc.
    location ~* \.(?:md|json|dist|sql|bak|old|backup|tpl|twig|log)\$ {
        deny all;
    }

    # Additional security headers
    add_header X-Frame-Options        "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection       "1; mode=block";
}
EOF

  kill_blockers
  systemctl enable nginx
  systemctl restart nginx
  nginx -t && systemctl reload nginx

  debconf-set-selections <<EOL
phpmyadmin phpmyadmin/dbconfig-install boolean true
phpmyadmin phpmyadmin/app-password-confirm password ${MYSQL_ROOT_PASS}
phpmyadmin phpmyadmin/mysql/admin-pass password ${MYSQL_ROOT_PASS}
phpmyadmin phpmyadmin/mysql/app-pass password ${MYSQL_ROOT_PASS}
phpmyadmin phpmyadmin/reconfigure-webserver multiselect none
EOL
  kill_blockers
  run_apt_fast "apt-get install -y $APT_FAST phpmyadmin"
  ln -snf /usr/share/phpmyadmin /var/www/html/php_adm

# ─── phpMyAdmin super-user + reuse for canary/myacc ─────────────────────────

# 1) Generate a phpMyAdmin super-user with a random 32-char password (!, #, letters, digits)
PHS_USER="pmauser$(shuf -i1-9999 -n1)"
PHS_PASS="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9!#' | head -c 32 | tr -d ' ')"

# 2) Recreate the credentials file and lock it down
: > "$PMA_CRED_FILE"
chmod 600 "$PMA_CRED_FILE"
chown "${APP_USER}:${APP_USER}" "$PMA_CRED_FILE"

# Add MySQL root credentials with description
printf 'MySQL Root User (Full Database Access):\n  User: root\n  Pass: %s\n  Description: Main MySQL administrator account with full privileges\n\n' "${MYSQL_ROOT_PASS// /}" >> "$PMA_CRED_FILE"

# Add phpMyAdmin application credentials with description
printf 'phpMyAdmin Application User:\n  User: pmaapp\n  Pass: %s\n  Description: phpMyAdmin internal application user for database management\n\n' "${MYSQL_ROOT_PASS// /}" >> "$PMA_CRED_FILE"

# Add phpMyAdmin super-user credentials with description
printf 'phpMyAdmin Super-User (Web Interface Access):\n  User: %s\n  Pass: %s\n  Description: phpMyAdmin web interface super-user with global database privileges\n\n' \
  "$PHS_USER" "${PHS_PASS// /}" >> "$PMA_CRED_FILE"

# 3) Create the user and grant global rights ( so phpMyAdmin can manage anything )
mysql -uroot -p${MYSQL_ROOT_PASS} <<SQL
CREATE USER IF NOT EXISTS '${PHS_USER}'@'localhost' IDENTIFIED BY '${PHS_PASS}';
GRANT ALL PRIVILEGES ON *.* TO '${PHS_USER}'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQL
log "[phpMyAdmin super-user ready: ${PHS_USER}]"

# 4) Now restrict that same account to only your canary & myacc schemas
mysql -uroot -p${MYSQL_ROOT_PASS} <<SQL
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${PHS_USER}'@'localhost';
GRANT ALL PRIVILEGES ON myacc.*    TO '${PHS_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
log "[${DB_NAME} & myacc privileges granted to ${PHS_USER}]"

# 5) Append a note about those schema-specific grants for easy reference
printf 'Special Database User (Canary/MyAcc Security):\n  User: %s\n  Pass: %s\n  Description: Special user with restricted access to %s and myacc databases only for enhanced security\n  Note: This user has been granted specific privileges to tighten database security\n' \
  "$PHS_USER" "${PHS_PASS// /}" "$DB_NAME" >> "$PMA_CRED_FILE"

  nginx -t && systemctl reload nginx

  if [[ -f "$SCHEMA_FILE" ]]; then
    mysql -uroot -p${MYSQL_ROOT_PASS} -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mysql -uroot -p${MYSQL_ROOT_PASS} ${DB_NAME} < "$SCHEMA_FILE"
    log "[${DB_NAME} DB schema imported]"
  elif [[ "${ENGINE_NAME}" == "tfs" ]]; then
    # For TFS engines, check if database already exists (created by engine script)
    if mysql -uroot -p${MYSQL_ROOT_PASS} -e "USE ${DB_NAME};" 2>/dev/null; then
      log "[${DB_NAME} DB already exists, skipping schema import]"
    else
      log "[${DB_NAME} DB not found, creating empty database]"
      mysql -uroot -p${MYSQL_ROOT_PASS} -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    fi
  fi

  if [[ ! -d /var/www/html ]] || [[ ! -f /var/www/html/composer.json ]]; then
    rm -rf /var/www/html 
    kill_blockers
    trycmd "timeout 500 git clone https://github.com/otsoft/myaac.git /var/www/html" 3 30 || die "MyAAC clone failed"
    chown -R www-data:www-data /var/www/html
  fi
  ln -snf /usr/share/phpmyadmin /var/www/html/php_adm

  # --------- COMPOSER INSTALL (FASTER!) ---------
  # Composer already installed above in batch
  if [[ -f /var/www/html/composer.json ]] && [[ ! -f /var/www/html/vendor/autoload.php ]]; then
    cd /var/www/html
    kill_blockers
    # Use parallel downloads and disable dev dependencies for speed
    trycmd "timeout 1200 $EAT composer install --no-dev --optimize-autoloader --no-interaction --no-plugins --no-scripts --prefer-dist --no-suggest" 3 60 || die "Composer install failed"
  fi

  chown -R www-data:www-data /var/www/html
  [[ -d /var/www/html/images       ]] && find /var/www/html/images        -type f -exec chmod 660 {} \;
  [[ -d /var/www/html/system/cache ]] && find /var/www/html/system/cache -type f -exec chmod 760 {} \;

  # Composer already installed above in batch
  cd /var/www/html
  if [[ -f composer.json ]]; then
    kill_blockers
    trycmd "timeout 1200 $EAT composer install --no-dev --optimize-autoloader --no-interaction --no-plugins --no-scripts --prefer-dist --no-suggest" 3 60 || die "Composer install failed"
  fi

  # ─────────────────────────── 4/7: Node.js & npm (already installed above) ──────────────────────────────
  # Node.js and npm already installed above in batch
  cd /var/www/html
  if [[ -f package.json ]]; then
    kill_blockers
    trycmd "timeout 500 $EAT npm install --production --no-optional" 3 30 || die "npm install failed"
  fi

  chown -R www-data:www-data /var/www/html
  find /var/www/html -type d -exec chmod 755 {} \;
  find /var/www/html -type f -exec chmod 644 {} \;

  # Find the first php*-fpm.sock ( e.g. php8.3-fpm.sock )
  phpfpm_sock=$(ls /run/php/php*-fpm.sock 2>/dev/null | head -n1)
  if [ -n "$phpfpm_sock" ]; then
    # Strip “.sock” to get “php8.3-fpm” ( or whatever version is installed- )
    phpfpm_service=$(basename "$phpfpm_sock" .sock)
    log "Re-starting $phpfpm_service service"
    systemctl enable "$phpfpm_service"
    systemctl start  "$phpfpm_service"
  else
    log "⚠️  No php-fpm socket found under /run/php/, skipping PHP-FPM restart"
  fi

  log "✅ All steps complete on attempt #${attempt}!"
  success=1

  # ─────── install GD & ZIP extensions, required for MyAcc plugins ───────
  # PHP GD & ZIP extensions already installed above in batch
  log "PHP GD & ZIP extensions already installed"

  # reload FPM so it picks up the new modules
  php_fpm_svc=$(basename "$(ls /run/php/php*-fpm.sock 2>/dev/null | head -n1)" .sock)
  if systemctl is-enabled "$php_fpm_svc" &>/dev/null; then
    log "Restarting $php_fpm_svc to load new PHP extensions"
    systemctl restart "$php_fpm_svc"
  fi

  # ─────── Ensure install/ip.txt is owned by the app user ───────
  IP_FILE="/var/www/html/install/ip.txt"
  if [[ -f "$IP_FILE" ]]; then
    chown "${APP_USER}:${APP_USER}" "$IP_FILE"
    log "✅ Ownership of $IP_FILE set to ${APP_USER}:${APP_USER}"
  else
    log "⚠️  $IP_FILE not found, skipping ownership change"
  fi

  log "Patching MyAAC ${ENGINE_NAME} config.lua with phpMyAdmin credentials..."
  CONFIG_DIR="${ENGINE_DIR}"
  CONFIG_FILE="${CONFIG_DIR}/config.lua"
  CONFIG_DIST="${CONFIG_FILE}.dist"

  if [[ -f "${PMA_CRED_FILE}" ]]; then
    PMA_USER=$(awk '/phpMyAdmin Super-User/ {getline; print $2}' "${PMA_CRED_FILE}")
    PMA_PASS=$(awk '/phpMyAdmin Super-User/ {getline; getline; print $2}' "${PMA_CRED_FILE}")
    log "Extracted PMA_USER: '${PMA_USER}', PMA_PASS: '${PMA_PASS}' from ${PMA_CRED_FILE}"
  else
    log "⚠️ Could not find PMA_CRED_FILE (${PMA_CRED_FILE}), skipping config.lua patch."
    PMA_USER=""
    PMA_PASS=""
  fi

  if [[ -d "${CONFIG_DIR}" ]]; then
    if [[ ! -f "${CONFIG_FILE}" && -f "${CONFIG_DIST}" ]]; then
      cp -a "${CONFIG_DIST}" "${CONFIG_FILE}"
      log "Copied ${CONFIG_DIST} to ${CONFIG_FILE}"
    fi

    if [[ -f "${CONFIG_FILE}" ]]; then
      log "Patching MyAAC ${ENGINE_NAME} config.lua MySQL settings..."
      log "Before patch - mysqlUser: $(grep '^mysqlUser' "${CONFIG_FILE}" || echo 'not found')"
      log "Before patch - mysqlPass: $(grep '^mysqlPass' "${CONFIG_FILE}" || echo 'not found')"
      
      sed -i \
        -e "s/^mysqlUser = \".*\"/mysqlUser = \"${PMA_USER}\"/" \
        -e "s/^mysqlPass = \".*\"/mysqlPass = \"${PMA_PASS}\"/" \
        -e "s/^mysqlPass = \"PLACEHOLDER_PASSWORD\"/mysqlPass = \"${PMA_PASS}\"/" \
        -e "s/^mysqlDatabase = \".*\"/mysqlDatabase = \"${DB_NAME}\"/" \
        "${CONFIG_FILE}"
      
      log "After patch - mysqlUser: $(grep '^mysqlUser' "${CONFIG_FILE}" || echo 'not found')"
      log "After patch - mysqlPass: $(grep '^mysqlPass' "${CONFIG_FILE}" || echo 'not found')"
      
      # Add passwordType = "sha1" for TFS
      # Why is it even missing in the first place?
      if [[ "${ENGINE_NAME}" == "tfs" ]]; then
        # Check if passwordType already exists
        if ! grep -q "^passwordType" "${CONFIG_FILE}"; then
          # Add passwordType after mysqlSock line
          sed -i '/^mysqlSock = ".*"/a passwordType = "sha1"' "${CONFIG_FILE}"
          log "Added passwordType = \"sha1\" to TFS config.lua"
        else
          log "passwordType already exists in TFS config.lua"
        fi
      fi
      
      log "Patched ${CONFIG_FILE} with phpmyadmin MySQL credentials"
    else
      log "No ${CONFIG_FILE} found, skipping config patch."
    fi
  else
    log "No ${ENGINE_NAME} dir (${CONFIG_DIR}), skipping config.lua patch."
  fi
  break
done

set -e
[[ -n "${success-}" ]] || die "Provisioning failed after 2 attempts."
chown "${APP_USER}:${APP_USER}" "${LOG_FILE}"
exit 0
