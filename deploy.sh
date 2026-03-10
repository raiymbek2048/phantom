#!/bin/bash
# PHANTOM VPS Deploy Script
# Usage: ssh root@your-vps 'bash -s' < deploy.sh
# Or: copy repo to VPS and run: bash deploy.sh

set -e

DOMAIN="${1:-phantom.yourdomain.com}"
EMAIL="${2:-admin@yourdomain.com}"

echo "=== PHANTOM VPS Deploy ==="
echo "Domain: $DOMAIN"
echo ""

# 1. Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "[1/7] Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    echo "[1/7] Docker already installed"
fi

# 2. Generate secrets
echo "[2/7] Generating secrets..."
DB_PASS=$(openssl rand -hex 16)
SECRET_KEY=$(openssl rand -hex 32)
REDIS_PASS=$(openssl rand -hex 16)

# Update .env.prod with real secrets
sed -i "s/CHANGE_ME_STRONG_PASSWORD_HERE/$DB_PASS/g" .env.prod
sed -i "s/CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32/$SECRET_KEY/g" .env.prod
sed -i "s/phantomredis/$REDIS_PASS/g" .env.prod

echo "  DB password: $DB_PASS"
echo "  Secret key: ${SECRET_KEY:0:8}..."

# 3. Update nginx domain
echo "[3/7] Configuring nginx for $DOMAIN..."
sed -i "s/server_name _;/server_name $DOMAIN;/g" nginx/nginx.prod.conf
sed -i "s|/etc/nginx/certs/live/phantom/|/etc/nginx/certs/live/$DOMAIN/|g" nginx/nginx.prod.conf

# 4. Get SSL certificate (first run without SSL)
echo "[4/7] Getting SSL certificate..."
# Temporary nginx for certbot challenge
docker run -d --name certbot-nginx \
    -p 80:80 \
    -v $(pwd)/nginx/certs:/etc/letsencrypt \
    -v /tmp/certbot:/var/www/certbot \
    nginx:alpine sh -c "echo 'server { listen 80; location /.well-known/acme-challenge/ { root /var/www/certbot; } }' > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'" \
    2>/dev/null || true

sleep 2

docker run --rm \
    -v $(pwd)/nginx/certs:/etc/letsencrypt \
    -v /tmp/certbot:/var/www/certbot \
    certbot/certbot certonly \
    --webroot --webroot-path=/var/www/certbot \
    --email "$EMAIL" --agree-tos --no-eff-email \
    -d "$DOMAIN" \
    2>/dev/null || echo "  SSL cert skipped (get it manually or check domain DNS)"

docker rm -f certbot-nginx 2>/dev/null || true

# 5. Build and start
echo "[5/7] Building containers (this takes 5-10 min)..."
docker compose -f docker-compose.prod.yml build

echo "[6/7] Starting PHANTOM..."
docker compose -f docker-compose.prod.yml up -d

# 7. Download Ollama model
echo "[7/7] Downloading AI model (qwen2.5-coder:3b)..."
sleep 10  # Wait for ollama to start
docker compose -f docker-compose.prod.yml exec -T ollama ollama pull qwen2.5-coder:3b

echo ""
echo "========================================="
echo "  PHANTOM deployed successfully!"
echo "========================================="
echo ""
echo "  URL:  https://$DOMAIN"
echo "  API:  https://$DOMAIN/api/health"
echo ""
echo "  Create admin account:"
echo "    curl -X POST https://$DOMAIN/api/auth/register \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"username\":\"admin\",\"email\":\"$EMAIL\",\"password\":\"YourStrongPassword\"}'"
echo ""
echo "  DB Password: $DB_PASS"
echo "  (saved in .env.prod)"
echo "========================================="
