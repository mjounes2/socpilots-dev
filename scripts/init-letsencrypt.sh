#!/bin/bash
# One-time Let's Encrypt certificate issuance for SOCPilots.
# Run AFTER "docker compose up -d" (nginx must be healthy first).
# Usage: bash scripts/init-letsencrypt.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

DOMAIN="${DOMAIN:?ERROR: DOMAIN is not set. Add DOMAIN=your.domain.com to .env}"
EMAIL="${CERTBOT_EMAIL:?ERROR: CERTBOT_EMAIL is not set. Add CERTBOT_EMAIL=you@example.com to .env}"

echo "=================================================="
echo " SOCPilots — Let's Encrypt certificate request"
echo " Domain : ${DOMAIN}"
echo " Email  : ${EMAIL}"
echo "=================================================="
echo ""
echo "IMPORTANT — Cloudflare users:"
echo "  If ${DOMAIN} is behind Cloudflare (orange cloud / proxied),"
echo "  temporarily set SSL/TLS mode to 'Flexible' and disable"
echo "  'Always Use HTTPS' in Cloudflare before continuing."
echo "  Re-enable both after the certificate is issued."
echo ""
read -rp "Press ENTER to continue or Ctrl-C to abort..."

echo ""
echo "==> Waiting for nginx to be ready..."
until docker compose exec -T nginx nginx -t >/dev/null 2>&1; do
  echo "    nginx not ready, retrying in 5s..."
  sleep 5
done

echo "==> Requesting certificate..."
docker compose run --rm certbot \
  certonly \
  --webroot \
  --webroot-path /var/www/certbot \
  --email "${EMAIL}" \
  --agree-tos \
  --no-eff-email \
  -d "${DOMAIN}"

echo ""
echo "==> Certificate issued. Reloading nginx to activate HTTPS..."
docker compose exec nginx nginx -s reload

echo ""
echo "==> Done! SOCPilots is now available at https://${DOMAIN}"
