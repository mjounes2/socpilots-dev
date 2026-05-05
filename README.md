# SOCPilots

An open-source Security Operations Center (SOC) platform integrating Wazuh SIEM, TheHive case management, n8n automation, and AI-powered threat investigation.

## Architecture

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│  SOCPilots UI   │───▶│  n8n         │───▶│  Wazuh MCP      │
│  (Node.js)      │    │  (Workflows) │    │  (AI Bridge)    │
└────────┬────────┘    └──────────────┘    └─────────────────┘
         │                                          │
         ▼                                          ▼
┌─────────────────┐                       ┌─────────────────┐
│  TheHive        │                       │  Wazuh/OpenSearch│
│  (Case Mgmt)    │                       │  (SIEM + Indexer)│
└─────────────────┘                       └─────────────────┘
```

## Prerequisites

- Docker & Docker Compose
- A running Wazuh instance (manager + indexer)
- A running TheHive instance
- OpenAI API key (for AI features)
- VirusTotal & AbuseIPDB API keys (for threat intel enrichment)

## Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/mjounes2/socpilots.git
cd socpilots
```

### 2. Configure environment

```bash
cp .env.example .env
nano .env   # fill in ALL values — see comments in the file
```

Required values to set:

| Variable | Description |
|---|---|
| `SERVER_IP` | IP of this server |
| `PG_PASSWORD` | Choose a strong PostgreSQL password |
| `SOC_USERS` | Login accounts — format: `user:pass:role,...` |
| `WAZUH_HOST` | IP/hostname of your Wazuh manager |
| `WAZUH_PASS` | Wazuh wui password |
| `WAZUH_INDEXER_HOST` | IP/hostname of your Wazuh indexer |
| `WAZUH_INDEXER_PASS` | OpenSearch admin password |
| `OPENSEARCH_URL` | Full URL of OpenSearch, e.g. `https://1.2.3.4:9200` |
| `OPENSEARCH_PASS` | Same as `WAZUH_INDEXER_PASS` |
| `THEHIVE_URL` | Full URL of your TheHive instance |
| `THEHIVE_API_KEY` | TheHive API key |
| `N8N_PASSWORD` | Choose a strong n8n admin password |
| `AUTH_SECRET_KEY` | Run: `openssl rand -hex 32` |
| `MCP_API_KEY` | Run: `echo "wazuh_$(openssl rand -hex 20)"` |
| `OPENAI_API_KEY` | From https://platform.openai.com/api-keys |
| `VIRUSTOTAL_API_KEY` | From https://www.virustotal.com/gui/my-apikey |
| `ABUSEIPDB_API_KEY` | From https://www.abuseipdb.com/account/api |

### 3. Deploy

```bash
docker compose up -d
```

### 4. Import n8n workflows

```bash
bash automation/deploy-workflows.sh
```

Access the UI at `http://YOUR_SERVER_IP:3000`

## Components

| Directory | Description |
|---|---|
| `Socpilots/` | Main web UI (Node.js + Vue) |
| `automation/` | n8n automation engine |
| `MCP-WAZUH/` | Wazuh AI bridge (MCP server) |
| `thehive-mcp-new/` | TheHive MCP server |

## Security Notes

- Never commit your `.env` file — it is excluded by `.gitignore`
- All secrets must be set via environment variables
- The `WAZUH_VERIFY_SSL=false` setting is intentional for self-signed certs; enable in production if you have valid certs

## License

MIT
