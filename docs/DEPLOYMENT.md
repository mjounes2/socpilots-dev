# DEPLOYMENT.md — SOCPilots Deployment Guide

## Prerequisites

- Docker Engine ≥ 24.x and Docker Compose v2 plugin
- Running Wazuh (manager + indexer/OpenSearch) — can be separate server
- Running TheHive instance — can be separate server
- OpenAI API key
- Domain name (for TLS) — optional for dev

---

## First-Time Deployment

```bash
# 1. Clone repository
git clone https://github.com/mjounes2/socpilots.git
cd socpilots

# 2. Configure environment
cp .env.example .env
nano .env   # Fill ALL required values

# 3. (Production) Issue TLS certificate
bash scripts/init-letsencrypt.sh

# 4. Start full stack
docker compose up -d --build

# 5. Verify all services healthy
docker compose ps
# All should show "healthy" or "running"

# 6. Import n8n automation workflows
bash automation/deploy-workflows.sh

# 7. Initial knowledge base ingest (MITRE + rules)
docker compose exec knowledge-ingestion \
  curl -s -X POST http://localhost:5004/ingest \
  -H "X-API-Key: $RAG_API_KEY" | jq .

# 8. Access SOCPilots
# http://YOUR_SERVER_IP (or https://your.domain.com)
# Default credentials: admin/admin  (change immediately!)
```

---

## Service Rebuild (After Code Changes)

```bash
# Rebuild single service (most common)
docker compose up -d --build webapp

# Rebuild all services
docker compose up -d --build

# Rebuild specific set
docker compose up -d --build webapp langchain-agent
```

---

## Log Monitoring

```bash
# Stream all logs
docker compose logs -f

# Stream specific service
docker compose logs -f webapp
docker compose logs -f langchain-agent
docker compose logs -f knowledge-ingestion
docker compose logs -f mcp-wazuh

# View last N lines
docker compose logs --tail=100 webapp
```

---

## Environment Variables

See `.env.example` for full list with comments. Required variables:

| Variable | Description | Example |
|---|---|---|
| `DOMAIN` | Production domain | `soc.company.com` |
| `SERVER_IP` | Server IP address | `1.2.3.4` |
| `PG_PASSWORD` | PostgreSQL password | Strong random string |
| `SOC_USERS` | Login accounts | `admin:pass:admin,user:pass:analyst` |
| `WAZUH_HOST` | Wazuh manager IP | `10.0.0.10` |
| `WAZUH_INDEXER_HOST` | OpenSearch IP | `10.0.0.11` |
| `OPENSEARCH_URL` | Full OpenSearch URL | `https://10.0.0.11:9200` |
| `THEHIVE_URL` | TheHive URL | `https://thehive.company.com` |
| `THEHIVE_API_KEY` | TheHive API key | From TheHive user settings |
| `OPENAI_API_KEY` | OpenAI key | `sk-proj-...` |
| `AUTH_SECRET_KEY` | Session secret | `openssl rand -hex 32` |
| `MCP_API_KEY` | MCP auth key | `wazuh_$(openssl rand -hex 20)` |
| `OTX_API_KEY` | OTX AlienVault key | From otx.alienvault.com |
| `VIRUSTOTAL_API_KEY` | VirusTotal key | From virustotal.com |
| `ABUSEIPDB_API_KEY` | AbuseIPDB key | From abuseipdb.com |

---

## Storage Volumes

```bash
# List all volumes
docker volume ls | grep socpilots

# Backup PostgreSQL
docker compose exec postgres pg_dump -U socpilots socpilots > backup_$(date +%Y%m%d).sql

# Restore PostgreSQL
docker compose exec -T postgres psql -U socpilots socpilots < backup.sql

# Backup Qdrant (copy volume)
docker run --rm -v socpilots_qdrant_data:/src -v $(pwd):/backup alpine \
  tar czf /backup/qdrant_backup_$(date +%Y%m%d).tar.gz -C /src .
```

---

## TLS / HTTPS

- Certificate: Let's Encrypt via certbot (auto-renewal cronjob)
- nginx handles TLS termination on port 443
- Port 80 redirects to HTTPS
- Run `bash scripts/init-letsencrypt.sh` for initial certificate

For development (no domain): nginx runs on port 80 only with self-signed cert.

---

## External Ports

| Port | Service | Exposed To |
|---|---|---|
| 80 | nginx (HTTP→HTTPS redirect) | Internet |
| 443 | nginx (SOCPilots webapp) | Internet |
| 5678 | n8n admin interface | Internet (restrict in firewall) |

**Firewall recommendations:** Restrict port 5678 to specific analyst IPs. Ports 3000, 3001, 5432, 6333, 7687, 8001, 8080 must remain internal-only.

---

## Health Checks

```bash
# Quick health check
curl http://localhost/health

# Service connectivity (requires auth)
curl -H "Authorization: Bearer $TOKEN" http://localhost/api/status

# Individual service health
docker compose exec webapp curl -s http://langchain-agent:8001/health
docker compose exec webapp curl -s http://rag-retrieval:5005/health
docker compose exec qdrant curl -s http://localhost:6333/healthz
```

---

## Updating SOCPilots

```bash
# Pull latest code
git pull origin main

# Rebuild changed services
docker compose up -d --build

# Verify no regressions
docker compose ps
docker compose logs --tail=20 webapp
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| 502 on API calls | Upstream service down | `docker compose ps`; check failing service logs |
| Black screen after login | JS error in index.html | Check browser console; check nginx logs |
| SIEM data empty | OpenSearch auth/URL wrong | Verify `OPENSEARCH_*` env vars |
| RAG returns no results | Qdrant empty / not ingested | Re-run knowledge ingest command |
| Investigation hangs | LangChain timeout | Check `docker compose logs langchain-agent` |
| Notifications not live | Socket.IO issue | Refresh page; check nginx WebSocket config |

---

*See also: `Socpilots/docs/DEPLOYMENT_GUIDE.md` for original detailed guide*
