# SOC Pilots — Deployment Guide

## Overview

SOC Pilots is an AI-powered Security Operations Center web application.
It connects to Wazuh (via OpenSearch), TheHive, and n8n (AI automation).

```
Browser
   │
Nginx (port 80)
   │
Express Backend (port 3000)
   ├── OpenSearch :9200  → Wazuh alerts, agents, rules
   ├── TheHive API       → Cases, alerts
   └── n8n Webhook       → AI Copilot, reports, hunt
```

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker | ≥ 24.x | `docker --version` |
| Docker Compose | ≥ 2.x | `docker compose version` |
| Linux server | Ubuntu 20+ / Debian | 2GB RAM minimum |
| Open ports | 80, 3000 | On your firewall |

---

## Step 1 — Get the Files

Upload the `socpilots-final/` folder to your server:

```bash
# On your local machine:
scp -r socpilots-final/ root@YOUR_SERVER_IP:/opt/socpilots/

# Or use SFTP / FileZilla to upload the folder
```

On the server:
```bash
cd /opt/socpilots/socpilots-final
ls
# You should see: backend/ frontend/ nginx/ Dockerfile docker-compose.yml .env
```

---

## Step 2 — Configure the Environment

```bash
# Copy the template
cp /path/to/configs/.env.template .env

# Edit with your customer's details
nano .env
```

Fill in:

### Wazuh (OpenSearch)
```env
OPENSEARCH_URL=https://YOUR_WAZUH_SERVER:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASS=YOUR_WAZUH_PASSWORD
```

**How to find Wazuh OpenSearch password:**
```bash
# On the Wazuh server:
cat /etc/wazuh-indexer/opensearch.yml
# or
docker exec wazuh-indexer cat /usr/share/wazuh-indexer/opensearch-security/internal_users.yml
```

### TheHive
```env
THEHIVE_URL=https://YOUR_THEHIVE_URL
THEHIVE_API_KEY=YOUR_API_KEY
```

**How to get TheHive API key:**
1. Login to TheHive
2. Go to: Settings → API Keys
3. Click "Create API Key"
4. Copy the key

### n8n Webhook
```env
N8N_WEBHOOK_URL=http://YOUR_N8N_SERVER:5678/webhook/YOUR_WEBHOOK_PATH
```

**How to get the n8n webhook URL:**
1. Open your n8n workflow
2. Click on the Webhook node
3. Copy the "Production URL"

### Users
```env
SOC_USERS=admin:STRONG_PASSWORD:admin,analyst:ANALYST_PASSWORD:analyst
```

---

## Step 3 — Open Firewall Ports

On your webapp server:
```bash
ufw allow 80
ufw allow 3000
ufw reload
```

On your Wazuh/OpenSearch server (to allow webapp to connect):
```bash
ufw allow from YOUR_WEBAPP_SERVER_IP to any port 9200
ufw reload
```

On your n8n server (to allow webhook calls):
```bash
ufw allow from YOUR_WEBAPP_SERVER_IP to any port 5678
# or open publicly:
ufw allow 5678
ufw reload
```

---

## Step 4 — Deploy

```bash
cd /opt/socpilots/socpilots-final

# Build Docker image
docker compose build --no-cache

# Start containers
docker compose up -d

# Check status
docker ps
```

Expected output:
```
CONTAINER ID   IMAGE                    STATUS          PORTS
xxxxx          socpilots-final-webapp   Up (healthy)    0.0.0.0:3000->3000/tcp
xxxxx          nginx:alpine             Up              0.0.0.0:80->80/tcp
```

---

## Step 5 — Verify

```bash
# Health check
curl http://localhost:3000/health

# Expected:
# {"status":"ok","time":"...","config":{"opensearch":"...","thehive":"...","n8n":"..."}}

# Test login page
curl -s http://localhost/login | grep "<title>"
# Expected: <title>SOC Pilots — Login</title>

# Test login API
curl -s -X POST http://localhost/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_ADMIN_PASSWORD"}'
# Expected: {"token":"...","username":"admin","role":"admin"}
```

---

## Step 6 — Access

Open browser: `http://YOUR_SERVER_IP`

Login with the credentials you set in `SOC_USERS`.

---

## Management Commands

```bash
# View logs
docker compose logs -f

# View webapp logs only
docker compose logs -f webapp

# Restart
docker compose restart

# Stop
docker compose down

# Update and rebuild
docker compose down
docker compose build --no-cache
docker compose up -d

# Check connection diagnostics
# In the webapp: Settings → Run Tests
```

---

## Troubleshooting

### Cannot access the website
```bash
# Check containers are running
docker ps

# Check nginx is healthy
docker compose logs nginx

# Check webapp is healthy
docker compose logs webapp
curl http://localhost:3000/health
```

### OpenSearch / Wazuh data not loading
```bash
# Test OpenSearch from the server
curl -k -u admin:YOUR_PASSWORD https://YOUR_WAZUH_IP:9200/_cluster/health

# If timeout → open firewall port 9200 on Wazuh server
ufw allow 9200
```

### TheHive data not loading
```bash
# Test TheHive API from the server
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://YOUR_THEHIVE_URL/api/v1/status
```

### AI Copilot not responding
```bash
# Test n8n webhook from the server
curl -X POST http://YOUR_N8N_SERVER:5678/webhook/YOUR_PATH \
  -H "Content-Type: application/json" \
  -d '{"action":"chat","message":"ping","session_id":"test"}'

# If no response → open port 5678 on n8n server
ufw allow 5678
```

### Login page shows file error
```bash
# Fix path bug (if upgrading from older version)
python3 -c "
c=open('backend/src/server.js').read()
c=c.replace(\"'../frontend'\",\"'../../frontend'\")
c=c.replace(\"'../.env'\",\"'../../.env'\")
open('backend/src/server.js','w').write(c)
print('Fixed!')
"
docker compose build --no-cache && docker compose up -d
```

---

## File Structure

```
socpilots-final/
├── .env                    ← Customer credentials (KEEP SECRET)
├── Dockerfile              ← Docker build config
├── docker-compose.yml      ← Container orchestration
├── backend/
│   ├── package.json
│   └── src/
│       └── server.js       ← Express API server
├── frontend/
│   ├── index.html          ← Main SPA dashboard
│   └── login.html          ← Login page
└── nginx/
    └── nginx.conf          ← Reverse proxy config
```

---

## Default Credentials

| User | Password | Role |
|------|----------|------|
| admin | socpilots2024 | Admin |
| analyst | younes123 | Analyst |

⚠️ **Always change default passwords for each customer!**

---

## Feature Map

| Feature | Data Source |
|---------|------------|
| Dashboard KPIs | OpenSearch aggregations |
| Agents | OpenSearch (agent.name field) |
| Alerts | OpenSearch wazuh-alerts-* |
| Detection Rules | OpenSearch (rule.id deduplicated) |
| Cases | TheHive API |
| Hive Alerts | TheHive API |
| Threat Hunt | OpenSearch + n8n AI |
| Correlation | OpenSearch + TheHive + n8n AI |
| AI Copilot | n8n → Mistral → MCP |
| Vulnerabilities | n8n → Wazuh MCP |
| Reports | n8n → Mistral AI |

---

*SOC Pilots — Built by Younes | CyberTalents*
