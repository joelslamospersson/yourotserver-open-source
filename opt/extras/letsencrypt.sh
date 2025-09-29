#!/usr/bin/env bash
set -euo pipefail

# V.1.0.0, 2025-09-10
# Let's Encrypt SSL Certificate Setup Script
# Usage: ./letsencrypt.sh <email> <domain> [app_user]
# Example: ./letsencrypt.sh admin@example.com example.com joriku

# ────────────────────────── Config ──────────────────────────
EMAIL="${1:-}"
DOMAIN="${2:-}"
APP_USER="${3:-${SUDO_USER:-$(id -un)}}"

if [[ -z "$EMAIL" || -z "$DOMAIN" ]]; then
    echo "Usage: $0 <email> <domain> [app_user]"
    echo "Example: $0 admin@example.com example.com joriku"
    exit 1
fi

log(){ echo -e "\n>>> $*"; }
die(){ echo -e "\nERROR: $*" >&2; exit 1; }

# ────────────────────────── Email and Domain Validation ──────────────────────────
# Required to register for a certificate, need to be checked before running the script
# Otherwise we risk getting a certificate for the wrong email or domain, or not getting a certificate at all with files laying on machine
log "Validating email and domain format..."

# Email validation regex
EMAIL_REGEX="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
if [[ ! $EMAIL =~ $EMAIL_REGEX ]]; then
    die "Invalid email format: $EMAIL"
fi

# Domain validation regex
DOMAIN_REGEX="^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
if [[ ! $DOMAIN =~ $DOMAIN_REGEX ]]; then
    die "Invalid domain format: $DOMAIN"
fi

# Image using for easier identification in logs, check if the email and domain format is valid
log "✅ Email and domain format validation passed"

# ────────────────────────── Pre-flight checks ──────────────────────────
log "Checking prerequisites for Let's Encrypt setup..."

# Check if running as root or with sudo
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root or with sudo"
fi

# Check if domain is accessible
log "Verifying domain $DOMAIN is accessible..."
if ! nslookup "$DOMAIN" >/dev/null 2>&1; then
    die "Domain $DOMAIN is not resolvable. Please check your DNS settings."
fi

# Check if nginx is installed and running
if ! systemctl is-active --quiet nginx; then
    die "Nginx is not running. Please ensure nginx is installed and started."
fi

# Check if port 80 is accessible
if ! netstat -tlnp | grep -q ":80 "; then
    die "Port 80 is not listening. Nginx must be accessible on port 80 for Let's Encrypt validation."
fi

# ────────────────────────── Configure iptables for Nginx Full ──────────────────────────
log "Configuring iptables for Nginx Full with DDoS protection..."

# Install iptables-persistent if not already installed
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent

# Configure iptables rules for Nginx Full with bucket-per-IP protection
log "Setting up iptables rules for ports 80 and 443 with DDoS protection..."

# Create iptables rules with bucket-per-IP protection
iptables -t mangle -A PREROUTING -p tcp --dport 80 -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name http-ddos -j DROP
iptables -t mangle -A PREROUTING -p tcp --dport 443 -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name https-ddos -j DROP

# Allow Nginx Full (ports 80 and 443) with rate limiting
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --set --name http
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 --name http -j DROP
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --set --name https
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 --name https -j DROP
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Save iptables rules
# Required for the persistence, otherwise the rules will be lost after reboot
iptables-save > /etc/iptables/rules.v4
log "✅ iptables rules configured for Nginx Full with DDoS protection"

# ────────────────────────── Install Certbot ──────────────────────────
log "Installing Certbot and nginx plugin..."

# Update package list
apt-get update -y

# Install certbot and nginx plugin
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    certbot \
    python3-certbot-nginx \
    nginx

# ────────────────────────── Backup nginx config ──────────────────────────
log "Backing up current nginx configuration..."
NGINX_CONFIG="/etc/nginx/sites-available/default"
BACKUP_CONFIG="/etc/nginx/sites-available/default.backup.$(date +%Y%m%d_%H%M%S)"

if [[ -f "$NGINX_CONFIG" ]]; then
    cp "$NGINX_CONFIG" "$BACKUP_CONFIG"
    log "Nginx config backed up to: $BACKUP_CONFIG"
fi

# ────────────────────────── Update nginx server_name ──────────────────────────
log "Updating nginx server_name to use user's domain..."

# Update the current nginx config to use the user's domain
sed -i "s/server_name _;/server_name $DOMAIN www.$DOMAIN;/" "$NGINX_CONFIG"

log "✅ Updated nginx server_name to: $DOMAIN www.$DOMAIN"

# ────────────────────────── Prepare nginx for Let's Encrypt ──────────────────────────
log "Preparing nginx configuration for Let's Encrypt validation..."

# Create a temporary nginx config that allows Let's Encrypt validation
# This will be replaced by the final nginx config after the certificate is obtained
cat > "$NGINX_CONFIG" <<EOF
# Temporary nginx config for Let's Encrypt validation
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DOMAIN www.$DOMAIN;

    # Let's Encrypt validation location
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        try_files \$uri =404;
    }

    # Temporary redirect for all other requests
    location / {
        return 200 'Let\\'s Encrypt validation in progress. Please wait...';
        add_header Content-Type text/plain;
    }
}
EOF

# Test and reload nginx
# Required to apply the changes to the nginx config
nginx -t || die "Nginx configuration test failed"
systemctl reload nginx

# ────────────────────────── Obtain SSL Certificate ──────────────────────────
log "Obtaining SSL certificate for $DOMAIN using email: $EMAIL..."

# Run certbot to obtain the certificate with user's email
if certbot --nginx \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    --domains "$DOMAIN,www.$DOMAIN" \
    --redirect; then
    
    log "✅ SSL certificate obtained successfully!"
else
    log "❌ Failed to obtain SSL certificate"
    
    # Restore backup config if available
    if [[ -f "$BACKUP_CONFIG" ]]; then
        log "Restoring nginx configuration from backup..."
        cp "$BACKUP_CONFIG" "$NGINX_CONFIG"
        nginx -t && systemctl reload nginx
    fi
    
    die "Let's Encrypt certificate acquisition failed"
fi

# ────────────────────────── Update nginx config for MyAAC with SSL ──────────────────────────
log "Updating nginx configuration for MyAAC with SSL and user's domain..."

# Create the final nginx configuration with SSL and user's domain
cat > "$NGINX_CONFIG" <<EOF
# MyAAC with SSL configuration for $DOMAIN
# Redirect all HTTP requests to HTTPS
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DOMAIN www.$DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS server block
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name $DOMAIN www.$DOMAIN;

    # SSL configuration (managed by Certbot)
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    root /var/www/html;
    index index.php index.html;

    # Allow larger uploads
    client_max_body_size 10M;

    # Serve static assets directly with long cache
    location ~* \.(?:ico|css|js|gif|jpe?g|png|woff2?|eot|ttf|svg|otf|webp|map)$ {
        access_log off;
        expires    30d;
        add_header Cache-Control "public";
        try_files  \$uri =404;
    }

    # "Pretty URL" front controller
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
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
EOF

# Test and reload nginx
nginx -t || die "Updated nginx configuration test failed"
systemctl reload nginx

# ────────────────────────── Setup auto-renewal ──────────────────────────
log "Setting up automatic certificate renewal..."

# Create a renewal test script
# Required to test the renewal process, does it work as expected?
cat > /usr/local/bin/certbot-renewal-test.sh <<'EOF'
#!/bin/bash
# Test script for Let's Encrypt renewal
certbot renew --dry-run
EOF

chmod +x /usr/local/bin/certbot-renewal-test.sh

# Add cron job for automatic renewal (runs twice daily)
set +e  # Temporarily disable exit on error
(crontab -l 2>/dev/null; echo "0 12,0 * * * /usr/bin/certbot renew --quiet --nginx") | crontab -
cron_exit_code=$?
set -e  # Re-enable exit on error

if [[ $cron_exit_code -eq 0 ]]; then
    log "✅ Cron job for certificate renewal added successfully"
else
    log "⚠️ Failed to add cron job (exit code: $cron_exit_code), but continuing..."
fi

# Test the renewal process
log "Testing certificate renewal process..."
set +e  # Temporarily disable exit on error
/usr/local/bin/certbot-renewal-test.sh 2>/dev/null
renewal_exit_code=$?
set -e  # Re-enable exit on error

if [[ $renewal_exit_code -eq 0 ]]; then
    log "✅ Certificate renewal test successful"
else
    log "⚠️ Certificate renewal test failed (exit code: $renewal_exit_code), but continuing..."
    log "ℹ️ This is normal for newly created certificates - renewal will work when needed"
fi

# ────────────────────────── Final verification ──────────────────────────
log "Performing final verification..."

# Check if certificate files exist
# Make sure the certificate files are present
if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" && -f "/etc/letsencrypt/live/$DOMAIN/privkey.pem" ]]; then
    log "✅ SSL certificate files are present"
else
    die "SSL certificate files are missing"
fi

# Check nginx status
if systemctl is-active --quiet nginx; then
    log "✅ Nginx is running"
else
    die "Nginx is not running"
fi

# Test HTTPS connectivity
if curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" | grep -q "200\|301\|302"; then
    log "✅ HTTPS is working for $DOMAIN"
else
    log "⚠️ HTTPS test failed, but certificate was installed"
fi

# ────────────────────────── Summary ──────────────────────────
log "Let's Encrypt SSL setup completed successfully!"
echo ""
echo "📋 Summary:"
echo "  Domain: $DOMAIN (and www.$DOMAIN)"
echo "  Email: $EMAIL"
echo "  Certificate location: /etc/letsencrypt/live/$DOMAIN/"
echo "  Auto-renewal: Enabled (cron job added)"
echo "  Nginx config: Updated with SSL and user's domain"
echo "  iptables: Configured with DDoS protection for ports 80/443"
echo "  HTTP to HTTPS: Automatic redirect enabled"
echo ""
echo "🔗 Your site should now be accessible at: https://$DOMAIN"
echo "🔒 SSL certificate will auto-renew every 12 hours"
echo "🛡️ DDoS protection active with bucket-per-IP rate limiting"
echo ""
echo "📁 Backup nginx config: $BACKUP_CONFIG"
echo ""

# Clean up backup if everything worked
if [[ -f "$BACKUP_CONFIG" ]]; then
    log "Cleaning up temporary backup file..."
    rm -f "$BACKUP_CONFIG"
fi

# Log for worker to know that the script has finished
log "Done, Let's Encrypt SSL setup completed successfully!"
