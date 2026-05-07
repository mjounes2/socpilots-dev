#!/bin/sh
set -e

DOMAIN="${DOMAIN:-localhost}"
LE_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
SELF_SIGNED_DIR="/etc/nginx/ssl"

if [ -f "$LE_CERT" ]; then
    echo "[nginx] Let's Encrypt cert found for ${DOMAIN}"
    CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
else
    echo "[nginx] No LE cert for ${DOMAIN} — generating self-signed bootstrap cert"
    mkdir -p "$SELF_SIGNED_DIR"
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "${SELF_SIGNED_DIR}/privkey.pem" \
        -out    "${SELF_SIGNED_DIR}/fullchain.pem" \
        -days 3650 \
        -subj "/CN=${DOMAIN}" 2>/dev/null
    CERT_DIR="$SELF_SIGNED_DIR"
fi

export DOMAIN CERT_DIR
envsubst '${DOMAIN} ${CERT_DIR}' \
    < /etc/nginx/nginx.conf.template \
    > /etc/nginx/nginx.conf

echo "[nginx] Config generated — domain: ${DOMAIN}, cert: ${CERT_DIR}"

# Background watcher: reload nginx when LE cert is renewed
(
    while true; do
        sleep 12h
        if [ -f "$LE_CERT" ]; then
            echo "[nginx] Reloading for cert renewal"
            nginx -s reload 2>/dev/null || true
            CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
            export CERT_DIR
            envsubst '${DOMAIN} ${CERT_DIR}' \
                < /etc/nginx/nginx.conf.template \
                > /etc/nginx/nginx.conf
        fi
    done
) &

exec nginx -g "daemon off;"
