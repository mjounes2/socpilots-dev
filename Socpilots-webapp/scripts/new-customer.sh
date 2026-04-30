#!/bin/bash
# ================================================================
# SOC PILOTS — New Customer Setup Script
# Usage: ./new-customer.sh
# ================================================================

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║   SOC PILOTS — New Customer Setup            ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Collect customer info ──────────────────────────────────────
echo -e "${BOLD}Enter customer details:${NC}"
echo ""

read -p "Customer name (e.g. acme-corp): " CUSTOMER_NAME
CUSTOMER_NAME=$(echo "$CUSTOMER_NAME" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')

echo ""
echo -e "${CYAN}[Wazuh / OpenSearch]${NC}"
read -p "  OpenSearch URL (e.g. https://192.168.1.100:9200): " OS_URL
read -p "  OpenSearch username [admin]: " OS_USER
OS_USER=${OS_USER:-admin}
read -sp "  OpenSearch password: " OS_PASS
echo ""

echo ""
echo -e "${CYAN}[TheHive]${NC}"
read -p "  TheHive URL (e.g. https://thehive.company.com): " HIVE_URL
read -sp "  TheHive API Key: " HIVE_KEY
echo ""

echo ""
echo -e "${CYAN}[n8n Webhook]${NC}"
read -p "  n8n webhook URL (e.g. http://n8n-server:5678/webhook/socpilots): " N8N_URL

echo ""
echo -e "${CYAN}[Users]${NC}"
read -p "  Admin username [admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -sp "  Admin password: " ADMIN_PASS
echo ""
read -p "  Analyst username [analyst]: " ANALYST_USER
ANALYST_USER=${ANALYST_USER:-analyst}
read -sp "  Analyst password: " ANALYST_PASS
echo ""

echo ""
echo -e "${CYAN}[Server]${NC}"
read -p "  Webapp server IP or domain: " SERVER_IP

# ── Create customer directory ──────────────────────────────────
DEPLOY_DIR="./customers/${CUSTOMER_NAME}"
mkdir -p "$DEPLOY_DIR"

# ── Write .env ─────────────────────────────────────────────────
cat > "${DEPLOY_DIR}/.env" << ENVEOF
# ================================================================
# SOC PILOTS — ${CUSTOMER_NAME}
# Created: $(date '+%Y-%m-%d')
# ================================================================

PORT=3000
NODE_ENV=production

# Wazuh OpenSearch
OPENSEARCH_URL=${OS_URL}
OPENSEARCH_USER=${OS_USER}
OPENSEARCH_PASS=${OS_PASS}
WAZUH_INDEX=wazuh-alerts-*

# TheHive
THEHIVE_URL=${HIVE_URL}
THEHIVE_API_KEY=${HIVE_KEY}

# n8n AI Webhook
N8N_WEBHOOK_URL=${N8N_URL}

# Users
SOC_USERS=${ADMIN_USER}:${ADMIN_PASS}:admin,${ANALYST_USER}:${ANALYST_PASS}:analyst

# CORS
ALLOWED_ORIGINS=http://${SERVER_IP},https://${SERVER_IP},http://localhost
ENVEOF

# ── Write deploy instructions ──────────────────────────────────
cat > "${DEPLOY_DIR}/DEPLOY.md" << DOCEOF
# SOC Pilots — ${CUSTOMER_NAME} Deployment

## Server
- IP / URL: ${SERVER_IP}
- Created: $(date '+%Y-%m-%d')

## Connections
- Wazuh OpenSearch: ${OS_URL}
- TheHive: ${HIVE_URL}
- n8n: ${N8N_URL}

## Users
| Username | Role |
|----------|------|
| ${ADMIN_USER} | Admin |
| ${ANALYST_USER} | Analyst |

## Deploy Steps

1. SSH into ${SERVER_IP}
2. Upload socpilots-final/ folder
3. Copy this .env file to: socpilots-final/.env
4. Run:
   \`\`\`bash
   cd socpilots-final
   docker compose build --no-cache
   docker compose up -d
   \`\`\`
5. Open: http://${SERVER_IP}

## Firewall Requirements
Run on ${SERVER_IP}:
\`\`\`bash
ufw allow 80
ufw allow 3000
ufw reload
\`\`\`

Run on Wazuh server to allow this webapp:
\`\`\`bash
ufw allow from ${SERVER_IP} to any port 9200
\`\`\`

Run on n8n server to allow webhook calls:
\`\`\`bash
ufw allow from ${SERVER_IP} to any port 5678
\`\`\`
DOCEOF

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✅ Customer setup complete!                ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Customer:  ${BOLD}${CUSTOMER_NAME}${NC}"
echo -e "  Config:    ${CYAN}${DEPLOY_DIR}/.env${NC}"
echo -e "  Guide:     ${CYAN}${DEPLOY_DIR}/DEPLOY.md${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Copy ${DEPLOY_DIR}/.env → your server's socpilots-final/.env"
echo "  2. docker compose build --no-cache"
echo "  3. docker compose up -d"
echo "  4. Open http://${SERVER_IP}"
echo ""
