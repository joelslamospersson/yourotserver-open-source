#!/usr/bin/env bash
set -euo pipefail
trap 'die "Error on or near line ${LINENO}. See ${LOG_FILE}."' ERR

#
# znoteacc_setup.sh — fully idempotent ZnoteAAC 1.6 + phpMyAdmin + Canary setup
#

APP_USER="${1:-${SUDO_USER:-$(id -un)}}"
USER_HOME="/home/${APP_USER}"
LOG_FILE="${USER_HOME}/znoteacc_setup.log"
PMA_CRED_FILE="${USER_HOME}/phpmyadmin.txt"
CANARY_DIR="${USER_HOME}/canary"
SCHEMA_FILE="${CANARY_DIR}/schema.sql"
DEF_NGINX="/etc/nginx/sites-available/default"

log(){ echo -e "\n>>> $*" | tee -a "$LOG_FILE"; }
die(){ echo -e "\n✖ $*" | tee -a "$LOG_FILE"; exit 1; }

# require root
[[ $EUID -eq 0 ]] || die "Must run as root"

# initialize and lock down log
: >"$LOG_FILE"
chmod 600 "$LOG_FILE"

log "Starting full ZnoteAAC+Canary setup (user=${APP_USER})"

# ─── helper: read an existing "Label:\n  User: X\n  Pass: Y" block ─────────────────
_read_cred(){
  local label="$1"
  local block
  block="$(awk "/^${label}/ {flag=1; print; next} flag && /^  User:/ {print; next} flag && /^  Pass:/ {print; exit}" "$PMA_CRED_FILE" || true)"
  R_USER="$(echo "$block" | awk '/^  User:/ {print $2}')"
  R_PASS="$(echo "$block" | awk '/^  Pass:/ {print $2}')"
}

# ─── helper: append a new credential block ──────────────────────────────────────
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

# ─── 2a) ufw install ────────────────────────────────────────────────────────
if ! dpkg -l ufw &>/dev/null; then
  log "[2/14] installing ufw"
  apt update && apt install -y ufw
else
  log "[2/14] ufw already installed"
fi

# ─── 2b) ufw enable ─────────────────────────────────────────────────────────
if ! ufw status | grep -q 'Status: active'; then
  log "[2/14] enabling ufw"
  ufw --force enable
else
  log "[2/14] ufw already enabled"
fi

# ─── 2c) allow 80/443 ───────────────────────────────────────────────────────
if ! ufw status | grep -q '80/tcp'; then
  log "[2/14] allowing HTTP/HTTPS in ufw"
  ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 'Nginx Full'
else
  log "[2/14] HTTP/HTTPS already allowed"
fi

# ─── 3) mysql-server ──────────────────────────────────────────────────────
if ! dpkg -l mysql-server &>/dev/null; then
  log "[3/14] apt install mysql-server"
  DEBIAN_FRONTEND=noninteractive apt update
  DEBIAN_FRONTEND=noninteractive apt install -y mysql-server
else
  log "[3/14] mysql-server already present"
fi

# ─── 4) mysql_secure_installation ────────────────────────────────────────
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

# ─── 5) PHP-FPM & extension ───────────────────────────────────────────────
if ! dpkg -l php-fpm &>/dev/null; then
  log "[5/14] apt install php-fpm php-mysql"
  apt update && apt install -y php-fpm php-mysql
else
  log "[5/14] php-fpm already installed"
fi

# detect PHP socket
shopt -s nullglob
php_socks=(/run/php/php*-fpm.sock /var/run/php/php*-fpm.sock)
shopt -u nullglob
(( ${#php_socks[@]} )) || die "Could not locate PHP-FPM socket"
PHP_SOCK="${php_socks[0]}"; log "[5/14] PHP-FPM socket: ${PHP_SOCK}"

# ─── 6) Replace default nginx vhost ───────────────────────────────────────
if [[ ! -f "${DEF_NGINX}.bak" ]]; then
  cp "$DEF_NGINX" "${DEF_NGINX}.bak"
  log "[6/14] backed up $DEF_NGINX"
fi

cat >"$DEF_NGINX" <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    index index.php;
    server_name _;
    location /php_adm {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
    location / { try_files \$uri \$uri/ =404; }
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${PHP_SOCK};
        fastcgi_read_timeout 240;
    }
    client_max_body_size 10M;
    location ~ /system { deny all; }
    location ~ /\.(git|ht|md|json|dist)\$ { deny all; }
    location ~* (file://|\.%00) { return 444; }
    location ~* /\.env.* { return 403; }
}
EOF

nginx -t && systemctl reload nginx && log "[6/14] nginx reloaded"

# ─── 7) install & record phpMyAdmin app password ─────────────────────────
if ! dpkg -l phpmyadmin &>/dev/null; then
  log "[7/14] installing phpMyAdmin"
  apt update && apt install -y debconf-utils dbconfig-common software-properties-common
  PMA_APP_PASS="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 64)"
  PRESEED=$(cat <<DEB
phpmyadmin phpmyadmin/reconfigure-webserver multiselect none
phpmyadmin phpmyadmin/dbconfig-install boolean true
phpmyadmin phpmyadmin/mysql/app-pass password $PMA_APP_PASS
phpmyadmin phpmyadmin/app-password-confirm password $PMA_APP_PASS
DEB
)
  echo "$PRESEED" | debconf-set-selections
  DEBIAN_FRONTEND=noninteractive apt install -y phpmyadmin
  echo -e "phpMyAdmin application password:\n  User: pmaapp\n  Pass: $PMA_APP_PASS" >"$PMA_CRED_FILE"
  log "[7/14] recorded phpMyAdmin app pass"
  chown "${APP_USER}:${APP_USER}" "$PMA_CRED_FILE"
  chmod 600 "$PMA_CRED_FILE"
else
  log "[7/14] phpMyAdmin already installed"
fi

# ─── 8) expose under /php_adm ────────────────────────────────────────────
if [[ ! -L /var/www/html/php_adm ]]; then
  log "[8/14] linking phpMyAdmin → /var/www/html/php_adm"
  ln -snf /usr/share/phpmyadmin /var/www/html/php_adm
else
  log "[8/14] /php_adm link exists"
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
mysql -u root <<SQL
CREATE USER IF NOT EXISTS '${R_USER}'@'localhost' IDENTIFIED BY '${R_PASS}';
GRANT ALL PRIVILEGES ON *.* TO '${R_USER}'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQL
log "[9/14] phpMyAdmin super-user ready: ${R_USER}"

# ─── 10) HTTP basic-auth on /php_adm ─────────────────────────────────────
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
nginx -t && systemctl reload nginx
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

# ─── 12) deploy ZnoteAAC 1.6 ───────────────────────────────────────────────
if ! dpkg -l git &>/dev/null; then
  log "[12/14] installing git"
  apt update && apt install -y git
else
  log "[12/14] git already installed"
fi

if [[ ! -d /var/www/html ]]; then
  log "[12/14] cloning ZnoteAAC"
  rm -rf /var/www/html
  git clone https://github.com/Znote/ZnoteAAC.git /var/www/html
  chown -R www-data:www-data /var/www/html
else
  log "[12/14] /var/www/html exists"
fi

# ─── 12.1) import ZnoteAAC DB (if provided) ──────────────────────────────
if [[ -f /var/www/html/database.sql ]]; then
  if mysql -u root -e "USE znoteaac" &>/dev/null; then
    log "[12.1/14] ZnoteAAC DB exists"
  else
    log "[12.1/14] creating znoteaac DB + importing schema"
    mysql -u root <<SQL
CREATE DATABASE znoteaac CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
SQL
    mysql -u root znoteaac < /var/www/html/database.sql
  fi
else
  log "[12.1/14] no database.sql found, skipping ZnoteAAC DB import"
fi

# ─── 13) OTServer & Webhost DB users ─────────────────────────────────────
if grep -q "^OTServer host:" "$PMA_CRED_FILE"; then
  _read_cred "OTServer host"
else
  OTSU="otservhost$(shuf -i1-9999 -n1)"
  OTSPASS="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 64)"
  mysql -u root <<SQL
CREATE USER IF NOT EXISTS '${OTSU}'@'localhost' IDENTIFIED BY '${OTSPASS}';
GRANT SELECT,INSERT,UPDATE,DELETE ON canary.* TO '${OTSU}'@'localhost';
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
GRANT SELECT,INSERT,UPDATE,DELETE ON canary.* TO '${WEBU}'@'localhost';
FLUSH PRIVILEGES;
SQL
  _append_cred "Webhost user" "$WEBU" "$WEBP"
  _read_cred "Webhost user"
fi
log "[13/14] Webhost user ready: ${R_USER}"

# ─── 14) patch canary/config.lua ──────────────────────────────────────────
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
chown "${APP_USER}:${APP_USER}" "${LOG_FILE}"
exit 0
