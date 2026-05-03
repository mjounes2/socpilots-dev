# SOC PILOTS — AI Security Operations Center
### Version 3.0 | April 2026
> Built by Younes | CyberTalents

---

```
██████╗  ██████╗  ██████╗    ██████╗ ██╗██╗      ██████╗ ████████╗███████╗
██╔════╝ ██╔═══██╗██╔════╝    ██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝██╔════╝
███████╗ ██║   ██║██║         ██████╔╝██║██║     ██║   ██║   ██║   ███████╗
╚════██║ ██║   ██║██║         ██╔═══╝ ██║██║     ██║   ██║   ██║   ╚════██║
███████║ ╚██████╔╝╚██████╗    ██║     ██║███████╗╚██████╔╝   ██║   ███████║
╚══════╝  ╚═════╝  ╚═════╝    ╚═╝     ╚═╝╚══════╝ ╚═════╝   ╚═╝   ╚══════╝
```

---

## What is SOC Pilots?

SOC Pilots is a production-grade AI-powered Security Operations Center web application.
It connects directly to your SIEM (Wazuh/OpenSearch), Case Management (TheHive),
and AI automation (n8n) to provide a unified security command center.

**No vendor names are exposed to end users.** Everything is branded as:
- `SIEM` — Wazuh via OpenSearch
- `SP-CM` — SOCPilots Case Management (TheHive)
- `SOCPilots AI` — n8n + LLM automation

---

## Architecture

```
Browser
   │
Nginx :80
   │
Express Backend :3000
   ├── OpenSearch :9200  ──→  Wazuh Alerts, Agents, Rules, MITRE
   ├── TheHive API       ──→  Cases, Alerts
   └── n8n Webhook       ──→  AI Copilot, IOC Enrichment, Reports, Hunt AI
```

---

## Features

| Page | Data Source | Description |
|------|------------|-------------|
| **Dashboard** | SIEM + SP-CM | Live KPIs, stacked timeline, severity donut, world attack map |
| **Agents** | SIEM | Wazuh monitored endpoints with status (6h activity window) |
| **Alerts** | SIEM | Live feed with filters: severity, time, agent, src IP |
| **Detection Rules** | SIEM | Deduplicated active rules with MITRE mapping |
| **Vulnerabilities** | SOCPilots AI | CVE data with severity/status/search filters |
| **SP-CM Cases** | SP-CM | 4-column Kanban (New / In Progress / Resolved / Closed) |
| **SP-CM Alerts** | SP-CM | TheHive alert inbox |
| **Threat Hunt** | SIEM + SOCPilots AI | Direct SIEM search + AI analysis |
| **IOC Enrichment** | SOCPilots AI | IP/Domain/URL/Hash — geo + threat intel + map |
| **Correlation** | SIEM + SP-CM + AI | Interactive node graph + AI report |
| **Live Threat Map** | SIEM | Full-page attack map with real IP geolocation |
| **SOCPilots AI** | n8n → LLM → MCP | AI chat connected to SIEM + SP-CM |
| **Reports** | SOCPilots AI | Executive AI summary reports |
| **Settings** | All | Connection diagnostics |

---

## Project Structure

```
SOCPilots-Project/
├── README.md                      ← This file
├── CHANGELOG.md                   ← Version history
├── .env                           ← Active credentials (KEEP SECRET)
├── Dockerfile                     ← Docker build
├── docker-compose.yml             ← Container orchestration
│
├── backend/
│   ├── package.json               ← Node dependencies
│   └── src/
│       └── server.js              ← Express API (689 lines)
│
├── frontend/
│   ├── index.html                 ← Main SPA dashboard (1225 lines)
│   └── login.html                 ← Login page
│
├── nginx/
│   └── nginx.conf                 ← Reverse proxy (HTTP, no SSL)
│
├── configs/
│   ├── .env.template              ← Template for new customers
│   ├── .env.socpilots             ← Younes production config
│   └── .env.customer-a            ← Example customer config
│
├── scripts/
│   ├── new-customer.sh            ← Interactive new customer wizard
│   └── test-connections.sh        ← Pre-deploy connection tester
│
└── docs/
    ├── DEPLOYMENT_GUIDE.md        ← Full deployment steps
    └── N8N_SETUP.md               ← n8n workflow configuration
```

---

## Quick Deploy

```bash
# 1. SSH into your server
ssh root@YOUR_SERVER_IP

# 2. Upload this folder
# Use SFTP / scp / FileZilla

# 3. Configure credentials
cp configs/.env.template .env
nano .env  # Fill in your SIEM, SP-CM, AI details

# 4. Test connections (optional but recommended)
chmod +x scripts/test-connections.sh
./scripts/test-connections.sh

# 5. Build and start
docker compose build --no-cache
docker compose up -d

# 6. Verify
curl http://localhost:3000/health
# Open: http://YOUR_SERVER_IP
```

---

## Default Login

| Username | Password | Role |
|----------|----------|------|
| `admin` | `socpilots2024` | Admin |
| `younes` | `younes123` | Analyst |

> ⚠️ Change passwords in `.env` before deploying for customers!

---

## Configuration (.env)

```env
PORT=3000

# SIEM (Wazuh OpenSearch)
OPENSEARCH_URL=https://YOUR_WAZUH_IP:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASS=YOUR_PASSWORD
WAZUH_INDEX=wazuh-alerts-*

# SP-CM (TheHive)
THEHIVE_URL=https://YOUR_THEHIVE_URL
THEHIVE_API_KEY=YOUR_API_KEY

# SOCPilots AI (n8n)
N8N_WEBHOOK_URL=http://YOUR_N8N_IP:5678/webhook/YOUR_PATH

# Users (username:password:role)
SOC_USERS=admin:YOUR_PASS:admin,analyst:YOUR_PASS:analyst
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | Authenticate |
| GET | `/api/dashboard` | Dashboard KPIs + timeline |
| GET | `/api/agents` | SIEM agents (OpenSearch agg) |
| GET | `/api/alerts` | Alerts with filters |
| GET | `/api/rules` | Detection rules (deduplicated) |
| GET | `/api/vulnerabilities` | CVEs via SOCPilots AI |
| GET | `/api/cases` | SP-CM cases |
| GET | `/api/hive-alerts` | SP-CM alerts |
| POST | `/api/cases/create` | Create SP-CM case |
| POST | `/api/hunt` | Threat hunt: SIEM + AI |
| POST | `/api/correlate` | Correlation: SIEM + SP-CM + AI |
| POST | `/api/ai/chat` | SOCPilots AI chat |
| GET | `/api/stats/top-agents` | Top agents by alert count |
| GET | `/api/stats/top-ips` | Top source IPs |
| GET | `/api/stats/top-rules` | Top triggered rules |
| GET | `/api/stats/mitre` | MITRE ATT&CK breakdown |
| GET | `/api/reports/summary` | AI executive report |
| GET | `/api/status` | System health check |

---

## New Customer Setup

```bash
# Interactive wizard — generates .env + deploy guide
./scripts/new-customer.sh
```

---

## Production Server (Younes)

- **Webapp**: http://vmi3254460.contaboserver.net / http://79.143.190.97
- **SIEM**: vmi3247591.contaboserver.net:9200
- **SP-CM**: https://app.socpilots.com
- **SOCPilots AI**: vmi3254460.contaboserver.net:5678

---

*SOC Pilots — AI Security Operations Center | CyberTalents 2026*
