#!/usr/bin/env bash
set -euo pipefail
trap 'die "Error on or near line ${LINENO}. See ${LOG_FILE}."' ERR

#
# myacc_nginx.sh — fully idempotent MyAcc + phpMyAdmin + Canary setup
# Usage: sudo ./myacc_nginx.sh <app_user>
#

APP_USER="${1:-${SUDO_USER:-$(id -un)}}"
USER_HOME="/home/${APP_USER}"
LOG_FILE="${USER_HOME}/myacc_setup.log"
PMA_CRED_FILE="${USER_HOME}/phpmyadmin.txt"
CANARY_DIR="${USER_HOME}/canary"
SCHEMA_FILE="${CANARY_DIR}/schema.sql"
DEF_NGINX="/etc/nginx/sites-available/default"

# allow Composer to run as root without complaining
export COMPOSER_ALLOW_SUPERUSER=1
export COMPOSER_HOME=/root/.config/composer
mkdir -p "$COMPOSER_HOME"
echo '{}' > "$COMPOSER_HOME/composer.json"

log(){ echo -e "\n>>> $*" | tee -a "$LOG_FILE"; }
die(){ echo -e "\n✖ $*" | tee -a "$LOG_FILE"; exit 1; }

# require root
[[ $EUID -eq 0 ]] || die "Must run as root"

# initialize and lock down log
: >"$LOG_FILE"
chmod 600 "$LOG_FILE"

log "Starting full MyAcc+Canary setup (user=${APP_USER})"

# ─── helper: read an existing "Label:\n  User: X\n  Pass: Y" block ────────
_read_cred(){
  local label="$1"
  # find the first occurrence
  local block
  block="$(awk "/^${label}/ {flag=1; print; next} flag && /^  User:/ { print; next } flag && /^  Pass:/ { print; exit }" "$PMA_CRED_FILE" || true)"
  R_USER="$(echo "$block" | awk '/^  User:/ {print $2}')"
  R_PASS="$(echo "$block" | awk '/^  Pass:/ {print $2}')"
}

# ─── helper: append a new credential block ─────────────────────────────────
_append_cred(){
  local label="$1" user="$2" pass="$3"
  {
    echo -e "${label}:"
    echo -e "  User: ${user}"
    echo -e "  Pass: ${pass}"
  } >> "$PMA_CRED_FILE"
}

# ─── 1) nginx ─────────────────────────────────────────────────────────────
if ! dpkg -l nginx &>/dev/null; then
  log "[1/14] apt install nginx"
  apt update && apt install -y nginx
else
  log "[1/14] nginx already installed"
fi

# ─── 2a) Make sure ufw is installed ──────────────────────────────────────────
if ! dpkg -l ufw &>/dev/null; then
  log "[2/14] installing ufw"
  apt update && apt install -y ufw
else
  log "[2/14] ufw already installed"
fi

# ─── 2b) make sure ufw is enabled  ───────────────────────────────────────────────────────
if ! ufw status | grep -q 'Status: active' &>/dev/null; then
  log "[2/14] enabling ufw"
  ufw --force enable
else
  log "[2/14] ufw already enabled"
fi

# ─── 2c) allow 80/443 ports ufw ───────────────────────────────────────
# Allow port 80/443 for HTTP/HTTPS
if ! ufw status | grep -q '80/tcp' &>/dev/null; then
  log "[2/14] allowing HTTP/HTTPS in ufw"
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 'Nginx Full'
else
  log "[2/14] HTTP/HTTPS, Nginx Full already allowed in ufw"
fi

# ─── 3) mysql-server ─────────────────────────────────────────────────────
if ! dpkg -l mysql-server &>/dev/null; then
  log "[3/14] apt install mysql-server"
  DEBIAN_FRONTEND=noninteractive apt update
  DEBIAN_FRONTEND=noninteractive apt install -y mysql-server
else
  log "[3/14] mysql-server already present"
fi

# ─── 4) mysql_secure_installation ─────────────────────────────────────────
SEC_MARK="/root/.mysql_secure_done"
if [[ ! -f $SEC_MARK ]]; then
  log "[4/14] hardening MySQL"
  mysql -u root <<SQL
DELETE FROM mysql.user WHERE User='';
UPDATE mysql.user SET Host='localhost' WHERE User='root';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db LIKE 'test%';
FLUSH PRIVILEGES;
SQL
  touch "$SEC_MARK"
else
  log "[4/14] MySQL already secured"
fi

# ─── 5) PHP-FPM & extension ────────────────────────────────────────────────
if ! dpkg -l php-fpm &>/dev/null; then
  log "[5/14] apt install php-fpm php-mysql"
  apt update && apt install -y php-fpm php-mysql
else
  log "[5/14] php-fpm already installed"
fi

# detect PHP socket & machine IP
MACHINE_IP="$(hostname -I | awk '{print $1}')"; log "Machine IP: ${MACHINE_IP}"
shopt -s nullglob
php_socks=(/run/php/php*-fpm.sock /var/run/php/php*-fpm.sock)
shopt -u nullglob
(( ${#php_socks[@]} )) || die "Could not locate PHP-FPM socket"
PHP_SOCK="${php_socks[0]}"; log "PHP-FPM socket: ${PHP_SOCK}"

# ─── 6) Replace default nginx vhost with template ─────────────────────────

# 1) Create backup once
if [[ ! -f "${DEF_NGINX}.bak" ]]; then
  cp "$DEF_NGINX" "${DEF_NGINX}.bak"
  log "[6/14] Backed up $DEF_NGINX to ${DEF_NGINX}.bak"
fi

# 2) Detect PHP version + socket path
MACHINE_IP="$(hostname -I | awk '{print $1}')"
shopt -s nullglob
php_socks=(/run/php/php*-fpm.sock /var/run/php/php*-fpm.sock)
shopt -u nullglob
(( ${#php_socks[@]} )) || die "Could not locate PHP-FPM socket"
PHP_SOCK="${php_socks[0]}"
log "[6/14] PHP-FPM socket: ${PHP_SOCK}"

# 3) Replace default nginx config with full template
cat > "$DEF_NGINX" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;

    # Add index.php to the list if you are using PHP
    index index.php;

    server_name _;

    location /php_adm {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }

    # fixed issue with nginx not serving index.php
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    # pass PHP scripts to FastCGI server
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${PHP_SOCK};
        fastcgi_read_timeout 240;
    }

    # Max upload size
    client_max_body_size 10M;

    # ─── SECURITY HARDENING ───────────────────────────────
    location ~ /system {
        deny all;
    }

    location ~ /\.(git|ht|md|json|dist)\$ {
        deny all;
    }

    location ~* (file://|\.%00) {
        return 444;
    }

    location ~* /\.env.* {
        return 403;
    }
}
EOF

# 4) Validate and reload Nginx
nginx -t && systemctl reload nginx && log "[6/14] Default site replaced and reloaded"

# ─── 7) install & record phpMyAdmin app password ──────────────────────────
if ! dpkg -l phpmyadmin &>/dev/null; then
  log "[7/14] installing phpMyAdmin"
  apt update && apt install -y debconf-utils dbconfig-common software-properties-common
  PMA_APP_PASS="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 64)"
  PRESEED=$(cat <<EOF
phpmyadmin phpmyadmin/reconfigure-webserver multiselect none
phpmyadmin phpmyadmin/dbconfig-install boolean true
phpmyadmin phpmyadmin/mysql/app-pass password $PMA_APP_PASS
phpmyadmin phpmyadmin/app-password-confirm password $PMA_APP_PASS
EOF
)
  echo "$PRESEED" | debconf-set-selections
  DEBIAN_FRONTEND=noninteractive apt install -y phpmyadmin
  echo -e "phpMyAdmin application password:\n  User: pmaapp\n  Pass: $PMA_APP_PASS" > "$PMA_CRED_FILE"
  log "[7/14] recorded phpMyAdmin app password"
  chown "${APP_USER}:${APP_USER}" "$PMA_CRED_FILE"
  chmod 600 "$PMA_CRED_FILE"
else
  log "[7/14] phpMyAdmin already installed"
fi

# ─── 8) expose it under /php_adm ──────────────────────────────────────────
if [[ ! -L /var/www/html/php_adm ]]; then
  log "[8/14] linking phpMyAdmin → /var/www/html/php_adm"
  ln -snf /usr/share/phpmyadmin /var/www/html/php_adm
else
  log "[8/14] /php_adm link already exists"
fi

# ─── 9) phpMyAdmin super-user ─────────────────────────────────────────────
if grep -q "^phpMyAdmin super-user:" "$PMA_CRED_FILE"; then
  _read_cred "phpMyAdmin super-user"
else
  PHS_USER="pmauser$(shuf -i1-9999 -n1)"
  PHS_PASS="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 64)"
  _append_cred "phpMyAdmin super-user" "$PHS_USER" "$PHS_PASS"
  _read_cred "phpMyAdmin super-user"
fi
mysql -u root --execute="
  CREATE USER IF NOT EXISTS '${R_USER}'@'localhost' IDENTIFIED BY '${R_PASS}';
  GRANT ALL PRIVILEGES ON *.* TO '${R_USER}'@'localhost' WITH GRANT OPTION;
  FLUSH PRIVILEGES;
"
log "[9/14] phpMyAdmin super-user ready: ${R_USER}"

# ─── 10) HTTP basic-auth on /php_adm ──────────────────────────────────────
if ! dpkg -l apache2-utils &>/dev/null; then
  log "[10/14] installing apache2-utils"
  apt install -y apache2-utils
fi
if grep -q "^HTpasswd for /php_adm:" "$PMA_CRED_FILE"; then
  _read_cred "HTpasswd for /php_adm"
else
  HT_USER="${APP_USER}$(shuf -i1-999 -n1)"
  HT_PASS="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 64)"
  htpasswd -bc /etc/nginx/.htpasswd "$HT_USER" "$HT_PASS"
  _append_cred "HTpasswd for /php_adm" "$HT_USER" "$HT_PASS"
  _read_cred "HTpasswd for /php_adm"
fi
sed -i '/location \/php_adm/!b;:a;N;/\}/!ba' "$DEF_NGINX" || true
if ! grep -q 'auth_basic_user_file /etc/nginx/.htpasswd' "$DEF_NGINX"; then
  log "[10/14] inserting auth_basic block"
  sed -i '/server_name/a \
    location /php_adm { auth_basic "Restricted"; auth_basic_user_file /etc/nginx/.htpasswd; }' \
    "$DEF_NGINX"
  nginx -t && systemctl reload nginx
fi
log "[10/14] HTTP auth ready: ${R_USER}"

# ─── 11) create & import canary DB ───────────────────────────────────────
if mysql -u root -e "USE canary" &>/dev/null; then
  log "[11/14] canary DB exists"
else
  [[ -s "$SCHEMA_FILE" ]] || die "Schema file missing: $SCHEMA_FILE"
  log "[11/14] creating canary DB + importing schema"
  mysql -u root <<SQL
CREATE DATABASE canary CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
SQL
  mysql -u root canary < "$SCHEMA_FILE"
fi

# ─── 12) deploy MyAcc to /var/www/html ──────────────────────────────────
if ! dpkg -l git &>/dev/null; then
  log "[12/14] installing git"
  apt update && apt install -y git
fi
if [[ ! -d /var/www/myacc ]]; then
  log "[12/14] cloning MyAcc"
  rm -rf /var/www/html /var/www/myacc
  git clone https://github.com/otsoft/myaac.git /var/www/myacc
fi
if [[ ! -d /var/www/html ]]; then
  log "[12/14] moving MyAcc → /var/www/html"
  mv /var/www/myacc /var/www/html
fi
ln -snf /usr/share/phpmyadmin /var/www/html/php_adm
chown -R www-data:www-data /var/www/*
chmod 660 /var/www/html/images/{guilds,houses,gallery}
chmod -R 760 /var/www/html/system/cache

# Set permissions for canary folder
chmod +x /home
chmod +x /home/$APP_USER
if [[ -d "${CANARY_DIR}" ]]; then
  log "[12/14] setting execute bit on ${CANARY_DIR}"
  chmod +x "${CANARY_DIR}"
else
  log "[12/14] no ${CANARY_DIR} directory — skipping chmod"
fi

# ─── 12.1) Install git ──────────────────────────────────────────────
if ! dpkg -l git &>/dev/null; then
  log "[12.1/14] installing git"
  apt update && apt install -y git
else
  log "[12.1/14] git already installed"
fi
# ─── 12.2) Install composer ──────────────────────────────────────────────
# install composer /var/www/html
if ! dpkg -l composer &>/dev/null; then
  log "[12.2/14] installing composer"
  apt update && apt install -y composer
else
  log "[12.2/14] composer already installed"
fi

# ─── Install required PHP extensions ──────────────────────────────
log "[12.2/14] ensuring PHP extensions are present"
apt install -y php-mbstring php-xml php-curl php-zip php-bcmath php-tokenizer php-cli php-common php-mysql

# ─── Fix permissions before composer install ──────────────────────────────
log "[12.2/14] fixing permissions on /var/www/html"
chown -R www-data:www-data /var/www/html
find /var/www/html -type d -exec chmod 755 {} \;
find /var/www/html -type f -exec chmod 644 {} \;

# ─── Install composer dependencies ──────────────────────────────
if [[ ! -d /var/www/html/vendor ]]; then
  log "[12.2/14] running composer install (this may take a moment...)"
  cd /var/www/html || die "Failed to enter /var/www/html"

  # Increase PHP memory limit and run composer with timeout
  # Ensure /vendor exists and is owned by web user
  # Fix ownership and directory structure
  mkdir -p /var/www/html/vendor || die "Failed to create /var/www/html/vendor"
  mkdir -p /var/www/html/vendor/composer || die "Failed to create /var/www/html/vendor/composer"

  chown -R www-data:www-data /var/www/html
  chmod -R 755 /var/www/html
  chmod -R 775 /var/www/html/vendor
  chmod -R 775 /var/www/html/vendor/composer
  if [[ -e /var/www/html/install/ip.txt ]]; then
    chown "$APP_USER":"$APP_USER" /var/www/html/install/ip.txt
  else
    log "[12.2/14] no install/ip.txt to chown, skipping"
  fi

  # Confirm permissions (again)
  find /var/www/html -type d -exec chmod 755 {} \;
  find /var/www/html -type f -exec chmod 644 {} \;

  # Use PHP with memory bump and force timeout (no plugins/scripts)
  timeout 300 php -d memory_limit=1G /usr/bin/composer install \
    --no-dev --optimize-autoloader --no-interaction --no-plugins --no-scripts -vvv \
  2>&1 | tee -a "$LOG_FILE" || true
  if [[ $? -ne 0 ]]; then
    log "[12.2/14] composer install failed"
    exit 1
  fi

  log "[12.2/14] composer install completed"
else
  log "[12.2/14] composer dependencies already installed"
fi

# ─── 12.3) Install Node.js (from NodeSource) ────────────────────────────────
if ! command -v node &>/dev/null; then
  log "[12.3/14] installing Node.js"
  curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
  apt install -y nodejs
else
  log "[12.3/14] Node.js already installed"
fi

# ─── 12.4) Install Node.js dependencies ─────────────────────────────────────
cd /var/www/html || die "Failed to enter /var/www/html"
if [[ -f package.json ]]; then
  log "[12.4/14] installing Node.js dependencies"
  apt install -y build-essential
  npm install 2>&1 | tee -a "$LOG_FILE" || true
else
  log "[12.4/14] no package.json found—skipping npm install"
fi

# ─── 13) OTServer & Webhost DB users ──────────────────────────────────────
if grep -q "^OTServer host:" "$PMA_CRED_FILE"; then
  _read_cred "OTServer host"
else
  OTSU="otservhost$(shuf -i1-9999 -n1)"
  OTSPASS="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 64)"
  mysql -u root <<SQL
CREATE USER IF NOT EXISTS '${OTSU}'@'localhost' IDENTIFIED BY '${OTSPASS}';
GRANT
  SELECT, INSERT, ALTER, UPDATE, DELETE, CREATE, EVENT,
  EXECUTE, INDEX, DROP, LOCK TABLES
ON canary.* TO '${OTSU}'@'localhost';
FLUSH PRIVILEGES;
SQL
  _append_cred "OTServer host" "$OTSU" "$OTSPASS"
  _read_cred "OTServer host"
fi
log "[13/14] OTServer host ready: ${R_USER}"

if grep -q "^Webhost user:" "$PMA_CRED_FILE"; then
  _read_cred "Webhost user"
else
  WEBU="webhost$(shuf -i1-9999 -n1)"
  WEBP="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 64)"
  mysql -u root <<SQL
CREATE USER IF NOT EXISTS '${WEBU}'@'localhost' IDENTIFIED BY '${WEBP}';
GRANT
  SELECT, INSERT, ALTER, UPDATE, DELETE, CREATE, EVENT,
  EXECUTE, INDEX, DROP, LOCK TABLES
ON canary.* TO '${WEBU}'@'localhost';
FLUSH PRIVILEGES;
SQL
  _append_cred "Webhost user" "$WEBU" "$WEBP"
  _read_cred "Webhost user"
fi
log "[13/14] Webhost user ready: ${R_USER}"

# ensure creds file remains secure
chown "${APP_USER}:${APP_USER}" "$PMA_CRED_FILE"
chmod 600 "$PMA_CRED_FILE"

# ─── 14) patch canary/config.lua ─────────────────────────────────────────
CFG="${CANARY_DIR}/config.lua"
if [[ -f "$CFG" ]]; then
  if grep -q "^mysqlUser = \"${R_USER}\"" "$CFG"; then
    log "[14/14] config.lua already patched"
  else
    log "[14/14] patching config.lua"
    sed -i \
      -e 's|^mysqlHost =.*|mysqlHost = "127.0.0.1"|' \
      -e 's|^mysqlUser =.*|mysqlUser = "'"$R_USER"'"|' \
      -e 's|^mysqlPass =.*|mysqlPass = "'"$R_PASS"'"|' \
      -e 's|^mysqlDatabase =.*|mysqlDatabase = "canary"|' \
      -e 's|^mysqlDatabaseBackup =.*|mysqlDatabaseBackup = true|' \
      -e 's|^serverName =.*|serverName = "Canary"|' \
      "$CFG"
  fi
else
  log "[14/14] config.lua not found; skipping"
fi

log "✅ All 14 steps complete!"
# make myacc_setup.log readable to the app user
chown "${APP_USER}:${APP_USER}" "${LOG_FILE}"
exit 0
