# SOCPilots

> **Enterprise-grade, open-source Security Operations Center platform** — integrating Wazuh SIEM, TheHive case management, n8n automation, LangChain AI investigation, MITRE ATT&CK coverage mapping, UEBA graph analytics, and automated Dark SOC response.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](docker-compose.yml)
[![Node.js](https://img.shields.io/badge/Node.js-Express-339933?logo=nodedotjs)](Socpilots/backend/src/server.js)
[![Python](https://img.shields.io/badge/Python-FastAPI%20%2F%20Flask-3776AB?logo=python)](langchain-agent/main.py)
[![Go](https://img.shields.io/badge/Go-MCP%20Bridge-00ADD8?logo=go)](thehive-mcp-new/thehive-mcp-new/main.go)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [AI Engine](#ai-engine)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Integrations](#integrations)
- [Installation](#installation)
- [Deployment](#deployment)
- [Security](#security)
- [Screenshots](#screenshots)
- [Repository Structure](#repository-structure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

SOCPilots is a single-server, Docker Compose-based SOC platform designed for security operations teams that need deep SIEM integration, AI-powered investigation, automated playbook response, and comprehensive threat intelligence — without the complexity of a multi-cluster deployment.

**Key capabilities:**

- Real-time alert ingestion and investigation from Wazuh / OpenSearch
- AI-powered multi-step threat investigation via LangChain ReAct agent (GPT-4)
- Automated case management and escalation to TheHive
- Interactive MITRE ATT&CK Enterprise coverage heatmap with Navigator export
- UEBA (User and Entity Behavior Analytics) graph powered by Neo4j
- Dark SOC automated playbook engine with consensus gates for destructive actions
- Semantic knowledge search (RAG) over MITRE techniques, detection rules, and evidence files
- IOC enrichment via VirusTotal, AbuseIPDB, OTX AlienVault, and Shodan
- n8n workflow automation for triage, enrichment, and investigation pipelines

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      External Access                            │
│  Browser  ──→  nginx:443  (HTTPS + TLS termination)            │
│  Analyst  ──→  n8n:5678   (automation admin)                   │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────── Docker Network: soc ────────────────────────┐
│                              │                                  │
│                     ┌────────▼────────┐                         │
│                     │   webapp:3000   │  Node.js / Express SPA  │
│                     └──┬──┬──┬──┬──┬──┘                         │
│                        │  │  │  │  │                            │
│   ┌────────────────────┘  │  │  │  └─────────────────────┐     │
│   │ langchain-agent:8001  │  │  │  asset-scan:5003        │     │
│   │ (FastAPI / ReAct)     │  │  │  (Flask / nmap)         │     │
│   └────────┬──────────────┘  │  └─────────────────────────┘     │
│            │     ┌───────────┘                                  │
│   ┌────────▼─┐  ┌▼────────────────┐  ┌───────────────────┐     │
│   │ rag-     │  │ knowledge-      │  │  scanner:7777     │     │
│   │ retrieval│  │ ingestion:5004  │  │  (Node / nmap)    │     │
│   │ :5005    │  └────────┬────────┘  └───────────────────┘     │
│   └────┬─────┘           │                                      │
│        │                 ▼                                       │
│        └──────→  qdrant:6333  (vector DB)                       │
│                                                                  │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────┐             │
│   │ mcp-wazuh    │  │ thehive-mcp  │  │  neo4j   │             │
│   │ :3001 (MCP)  │  │ :8080 (Go)   │  │7687/7474 │             │
│   └──────────────┘  └──────────────┘  └──────────┘             │
│                                                                  │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐                     │
│   │ postgres │  │  redis   │  │   n8n    │                     │
│   │  :5432   │  │  :6379   │  │  :5678   │                     │
│   └──────────┘  └──────────┘  └──────────┘                     │
└─────────────────────────────────────────────────────────────────┘
                    │                 │
             Wazuh Manager     TheHive Instance
             + OpenSearch       (external)
              (external)
```

### Request Path

```
Browser → nginx:443 → webapp:3000 (Express)
                           │
                           ├─ /api/langchain/*   → langchain-agent:8001 (FastAPI / ReAct)
                           ├─ /api/rag/*         → rag-retrieval:5005   (Flask / Qdrant)
                           ├─ /api/evidence/*    → knowledge-ingestion:5004
                           ├─ /api/assets/*      → asset-scan:5003      (Flask / nmap)
                           ├─ /api/scan/*        → scanner:7777         (Node.js / nmap)
                           └─ /api/darksoc/*     → mcp-wazuh:3001       (Python MCP)

n8n:5678 → mcp-wazuh:3001    (Wazuh active response)
n8n:5678 → thehive-mcp:8080  (case management)
```

For full architecture detail see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Features

### SOC Dashboard

- Real-time KPI cards: total alerts, open investigations, active threats, MITRE coverage %
- Severity distribution charts and alert timeline
- Top triggered rules, top source IPs, active Wazuh agents
- MITRE coverage mini-heatmap widget
- Live Socket.IO notifications for new investigations, Dark SOC actions, and correlations

### Alert Management

- Full-text search, severity/time/agent/rule filters with pagination
- Expandable alert rows with raw log view
- One-click AI investigation from any alert
- Alert grouping by rule with aggregate counts

### Investigations

- AI-generated investigation reports with structured threat narratives
- Artifact tracking (IPs, hashes, domains) per investigation
- Severity status lifecycle (open → in-progress → closed)
- TheHive case escalation with one click
- MITRE technique tagging on investigations
- Evidence file attachments (PDF, Excel, CSV, TXT, images — with OCR)

### UEBA (User & Entity Behavior Analytics)

- Neo4j graph: Users, Hosts, Processes, Network, Files with typed relationships
- Risk scoring engine with 7 anomaly categories:
  - Impossible travel (weight 95), lateral movement (85), privilege escalation (80)
  - New host access (75), new process execution (70)
  - After-hours access (55), high-frequency login (50)
- Entity risk leaderboard with score history
- Attack-path highlighting via Neo4j `shortestPath`
- Weekly AI threat digest
- D3.js interactive force graph with curved edges and hover labels

### SP-CM / TheHive Alerts

- Native TheHive alert queue with status management
- Bulk triage operations
- Case creation and task management from within SOCPilots

### Dark SOC (Automated Response Engine)

- Rule-based playbook evaluation triggered on new investigations
- Six automated response actions:

| Action | Mechanism | Consensus Required |
|---|---|---|
| `block_ip` | Wazuh active-response | No |
| `isolate_host` | Wazuh active-response | **Yes** |
| `kill_process` | Wazuh active-response | No |
| `disable_user` | Wazuh active-response | **Yes** |
| `create_case` | TheHive REST API | No |
| `close_case` | DB only | No |

- FP probability gate: skips destructive actions if false-positive likelihood exceeds threshold
- Consensus validation: second LLM must agree for irreversible actions
- Protected assets list: prevents auto-isolation of critical infrastructure
- Full audit log in `playbook_executions` table
- Disabled by default; enabled in Settings → Dark SOC

### Correlation Engine

- Cross-alert correlation with configurable time windows
- AI-generated correlation reports
- Persistent correlation results with MITRE tagging

### Threat Hunting

- Scheduled hunt jobs with cron-based execution
- Hunt results stored and linked to investigations
- AI-assisted hunt analysis

### Asset Inventory

- nmap-based network discovery across configured subnets
- Asset status tracking (online/offline/unknown)
- Wazuh agent coverage gap detection
- Criticality tiers with isolation protection

### Threat Intelligence

- OTX AlienVault feed sync (every 6h, incremental after first full sync, ~5,000 IOCs)
- IOC cross-reference on artifact save: automatic threat score boost for OTX-known indicators
- Manual IOC lookup from the UI

### Knowledge Base & RAG

- MITRE ATT&CK technique embeddings (55+ hardcoded + OpenSearch-derived)
- Wazuh detection rule embeddings
- Evidence file upload and semantic search (PDF, Excel, CSV, TXT, images with OCR)
- BGE asymmetric retrieval (`BAAI/bge-small-en-v1.5`, 384 dimensions)

### Detection Rules

- Rule analytics from OpenSearch: count, severity, first/last seen, MITRE mapping
- Searchable/filterable rule table
- Decoder distribution and group tags

---

## AI Engine

SOCPilots uses three AI layers working in concert:

### 1. LangChain ReAct Agent

File: [`langchain-agent/main.py`](langchain-agent/main.py)

The primary investigation engine. Uses the ReAct (Reason + Act) pattern with GPT-4 as the primary LLM and Mistral as a cost-efficient triage fallback.

**Available tools:**

| Tool | Purpose |
|---|---|
| `search_alerts` | Query OpenSearch for SIEM alerts by keyword, IP, or agent |
| `enrich_ip` | VirusTotal + AbuseIPDB + OTX enrichment with Redis cache (1h TTL) |
| `check_cases` | Search TheHive for related cases |
| `query_ueba` | Neo4j entity behavior profile and risk score |
| `query_assets` | Asset inventory lookup by IP or hostname |
| `query_shodan` | Shodan port/service/vulnerability data |

**Endpoints:**

| Endpoint | Purpose | LLM |
|---|---|---|
| `POST /investigate` | Deep multi-step investigation | GPT-4 |
| `POST /triage` | Fast single-step alert triage | Mistral |
| `POST /enrich` | IOC enrichment with OTX context | GPT-4 |

### 2. RAG / Qdrant Knowledge Search

Files: [`services/rag-retrieval/`](services/rag-retrieval/), [`services/knowledge-ingestion/`](services/knowledge-ingestion/)

Semantic search over two Qdrant collections:

| Collection | Content | Dimensions |
|---|---|---|
| `socpilots_knowledge` | MITRE ATT&CK, Wazuh rules, TheHive incidents | 384 |
| `socpilots_evidence` | Uploaded investigation evidence files | 384 |

Embedding model: `BAAI/bge-small-en-v1.5`. BGE requires the query prefix `"Represent this sentence for searching relevant passages: "` for asymmetric retrieval.

### 3. n8n Automation Workflows

Three primary workflows in [`Socpilots/workflows/`](Socpilots/workflows/):

| Workflow | Purpose |
|---|---|
| `SOCPilots_Main` | Wazuh alert ingestion → AI triage → investigation trigger |
| `SOCPilots_Enrichment` | IOC enrichment via VirusTotal + AbuseIPDB (MCP tools) |
| `SOCPilots_Investigation` | Full ReAct investigation → TheHive case creation |

n8n connects to internal services via Docker DNS: `mcp-wazuh:3001`, `thehive-mcp:8080`, `langchain-agent:8001`, `webapp:3000`.

For full AI architecture detail see [`docs/AI-ENGINE.md`](docs/AI-ENGINE.md).

---

## MITRE ATT&CK Coverage

SOCPilots generates a real-time ATT&CK Enterprise coverage heatmap derived directly from Wazuh alert data.

- **14 Enterprise tactics** (TA0043 → TA0040)
- **~190 parent techniques** mapped across all tactics
- Coverage levels: High (≥10 alerts), Medium (3–9), Low (1–2), None (0)
- Timeframe filter: 24h / 7d / 30d / 90d
- Drill-down modal: per-technique alert count, agent list, daily timeline histogram
- **Navigator export**: MITRE ATT&CK Navigator 4.9 JSON for offline use

Backend endpoint: `GET /api/mitre/coverage?timeframe=7d` (30s in-memory cache)

For framework details see [`docs/MITRE-COVERAGE.md`](docs/MITRE-COVERAGE.md).

---

## Integrations

| System | Protocol | Purpose |
|---|---|---|
| **Wazuh Manager** | HTTPS REST (port 55000) | Agent management, active response, rule deployment |
| **OpenSearch / Wazuh Indexer** | HTTPS REST (port 9200) | Alert queries, MITRE coverage, rule analytics |
| **TheHive** | HTTPS REST + MCP (Go bridge) | Case management, SP-CM alert triage |
| **OpenAI GPT-4** | HTTPS REST | ReAct investigation agent (primary LLM) |
| **Mistral AI** | HTTPS REST | Cost-efficient triage fallback |
| **VirusTotal** | HTTPS REST | IP/domain/hash/URL threat scoring |
| **AbuseIPDB** | HTTPS REST | IP confidence score and reputation |
| **OTX AlienVault** | HTTPS REST | IOC feed sync, pulse/campaign enrichment |
| **Shodan** | HTTPS REST | Port scan, service fingerprint, CVE data |
| **Neo4j** | Bolt (port 7687) | UEBA entity graph, anomaly scoring |
| **Qdrant** | REST (port 6333) | Vector embeddings for RAG knowledge search |
| **Redis** | TCP (port 6379) | IOC enrichment cache (1h TTL) |
| **n8n** | HTTP webhooks | Triage, enrichment, and investigation automation |

For integration configuration details see [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

---

## Installation

### Prerequisites

| Requirement | Notes |
|---|---|
| Docker Engine 24+ | With Docker Compose v2 |
| 8 GB RAM minimum | 16 GB recommended for full stack |
| External Wazuh deployment | Manager + Indexer (OpenSearch) |
| External TheHive deployment | v5 recommended |
| OpenAI API key | GPT-4 access required |
| VirusTotal / AbuseIPDB keys | Free tiers sufficient for most deployments |

### 1. Clone

```bash
git clone https://github.com/mjounes2/socpilots.git
cd socpilots
```

### 2. Configure

```bash
cp .env.example .env
nano .env   # fill ALL values — comments explain each variable
```

**Required variables:**

| Variable | Description | Generate with |
|---|---|---|
| `SERVER_IP` | This server's public IP | — |
| `DOMAIN` | Public domain for TLS cert | — |
| `CERTBOT_EMAIL` | Let's Encrypt registration email | — |
| `PG_PASSWORD` | PostgreSQL password | `openssl rand -hex 16` |
| `SOC_USERS` | User accounts — `user:pass:role,...` | — |
| `WAZUH_HOST` | Wazuh manager IP/hostname | — |
| `WAZUH_PASS` | Wazuh `wazuh-wui` password | — |
| `WAZUH_INDEXER_HOST` | OpenSearch IP/hostname | — |
| `WAZUH_INDEXER_PASS` | OpenSearch admin password | — |
| `OPENSEARCH_URL` | Full OpenSearch URL | — |
| `THEHIVE_URL` | TheHive URL | — |
| `THEHIVE_API_KEY` | TheHive API key | TheHive → Settings → API Keys |
| `N8N_PASSWORD` | n8n admin password | `openssl rand -hex 16` |
| `AUTH_SECRET_KEY` | Session signing key | `openssl rand -hex 32` |
| `MCP_API_KEY` | Wazuh MCP auth token | `echo "wazuh_$(openssl rand -hex 20)"` |
| `OPENAI_API_KEY` | OpenAI key | platform.openai.com |
| `VIRUSTOTAL_API_KEY` | VirusTotal key | virustotal.com |
| `ABUSEIPDB_API_KEY` | AbuseIPDB key | abuseipdb.com |

Optional: `SHODAN_API_KEY`, `MISTRAL_API_KEY`, `OTX_API_KEY`, `RAG_API_KEY`

### 3. Deploy

```bash
docker compose up -d --build
```

### 4. Issue TLS Certificate (production)

```bash
bash scripts/init-letsencrypt.sh
```

### 5. Import n8n Automation Workflows

```bash
bash automation/deploy-workflows.sh
```

### 6. Force Initial RAG Knowledge Ingest

```bash
docker compose exec knowledge-ingestion \
  curl -s -X POST http://localhost:5004/ingest \
  -H "X-API-Key: $RAG_API_KEY" | jq .
```

### 7. Access

| Service | URL |
|---|---|
| SOCPilots UI | `https://YOUR_DOMAIN` or `http://YOUR_SERVER_IP` |
| n8n Automation | `http://YOUR_SERVER_IP:5678` |
| Neo4j Browser | `http://YOUR_SERVER_IP:7474` |

---

## Deployment

### Stack Overview

All services run on a single host in one Docker Compose stack on the `soc` bridge network.

| Container | Port (internal) | Language | Role |
|---|---|---|---|
| `nginx` | 80, 443 (host) | — | Reverse proxy; TLS termination; rate limiting |
| `webapp` | 3000 | Node.js | Express API + SPA |
| `postgres` | 5432 | — | Investigations, assets, playbooks, settings |
| `neo4j` | 7687 / 7474 | — | UEBA entity graph |
| `qdrant` | 6333 | — | Vector DB (two collections) |
| `redis` | 6379 | — | IOC cache (1h TTL) |
| `langchain-agent` | 8001 | Python (FastAPI) | ReAct investigation agent |
| `knowledge-ingestion` | 5004 | Python (Flask) | RAG ingest + evidence upload/OCR |
| `rag-retrieval` | 5005 | Python (Flask) | Semantic search over knowledge base |
| `scanner` | 7777 | Node.js | nmap XML parser |
| `asset-scan` | 5003 | Python (Flask) | Asset discovery + agent gap detection |
| `mcp-wazuh` | 3001 | Python (MCP) | Wazuh Manager + Indexer bridge |
| `thehive-mcp` | 8080 | Go (MCP) | TheHive case management bridge |
| `n8n` | 5678 (host) | — | Workflow automation |

### nginx Rate Limits

| Endpoint | Limit |
|---|---|
| Login (`/api/login`) | 10 req/min, burst 5 |
| API (`/api/*`) | 60 req/min |
| AI (`/api/ai/*`, `/api/langchain/*`) | 8 req/min, burst 4 |

### Useful Commands

```bash
# Rebuild after code changes
docker compose up -d --build webapp

# Stream logs
docker compose logs -f webapp
docker compose logs -f langchain-agent

# Health check
docker compose ps

# PostgreSQL inspection
docker compose exec postgres psql -U socpilots -d socpilots -c "\dt"

# Run RAG tests
docker compose exec rag-retrieval python -m pytest tests/ -v
```

For full deployment guide see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## Security

### Authentication

- All API routes protected by `authMW` (valid session token required)
- Role hierarchy: `admin(4) > l3(3) > l2(2) > l1(1)`
- Sessions stored in-memory with 8-hour TTL; no permanent sessions
- Tokens: `crypto.randomBytes(32)` hex, stored in browser `sessionStorage`
- Internal service-to-service: static Bearer token (`LANGCHAIN_INTERNAL_TOKEN`)

### Input Validation

- SQL: parameterized queries only — no string concatenation
- HTML output: `esc()` function applied to all user-supplied strings
- OpenSearch: structured DSL queries — no user input in raw query strings
- File uploads: MIME type + extension validation, size limits enforced
- Path traversal protection on all file operations

### Secrets Management

- All credentials exclusively via environment variables — never hardcoded
- `.env` excluded from git by `.gitignore`
- `.gitleaks.toml` configured for CI/CD secret scanning
- `scripts/clean-deploy.sh` validates no real values in template files before deploy

### Container Hardening

- `mcp-wazuh`: read-only filesystem, no Linux capabilities
- nginx: HTTP/2, HSTS, security headers
- `rejectUnauthorized: false` only for internal-to-internal HTTPS (self-signed Wazuh/TheHive certs)

For full security documentation see [`docs/SECURITY.md`](docs/SECURITY.md).

---

## Screenshots

> Screenshots will be added in an upcoming release. See the [Features](#features) section for a full description of each module.

Planned screenshots:
- SOC Dashboard (KPI cards, alert timeline, MITRE widget)
- MITRE ATT&CK Coverage Heatmap with drill-down
- LangChain AI Investigation Report
- UEBA Entity Risk Graph (D3.js force layout)
- Dark SOC Playbook Execution Log
- Asset Inventory with agent coverage gaps

---

## Repository Structure

```
socpilots/
├── Socpilots/                   # Main webapp
│   ├── backend/src/
│   │   ├── server.js            # Express API (~3500 lines)
│   │   ├── db.js                # PostgreSQL schema + CRUD (~1500 lines)
│   │   ├── playbook-engine.js   # Dark SOC response engine
│   │   ├── neo4j.js             # UEBA graph queries
│   │   └── email-service.js     # SMTP notifications
│   ├── frontend/
│   │   ├── index.html           # Entire SPA — vanilla JS, no build step (~7600 lines)
│   │   └── login.html
│   └── workflows/               # n8n workflow JSON exports
│
├── langchain-agent/             # ReAct investigation agent (Python / FastAPI)
├── services/
│   ├── knowledge-ingestion/     # RAG ingest + evidence file processing
│   └── rag-retrieval/           # Qdrant semantic search service
│
├── MCP-WAZUH/                   # Wazuh MCP server (Python)
├── thehive-mcp-new/             # TheHive MCP bridge (Go)
├── scanner/                     # nmap XML parser (Node.js)
├── services/asset-scan/         # Asset discovery (Python / Flask)
│
├── Socpilots-webapp/nginx/      # nginx config + TLS entrypoint
├── automation/                  # n8n workflow deployment scripts
├── scripts/                     # init-letsencrypt, clean-deploy
├── docs/                        # Extended documentation
│   ├── ARCHITECTURE.md
│   ├── AI-ENGINE.md
│   ├── MITRE-COVERAGE.md
│   ├── INTEGRATIONS.md
│   ├── DEPLOYMENT.md
│   ├── SECURITY.md
│   ├── API.md
│   └── UI-STANDARDS.md
│
├── docker-compose.yml           # Full unified stack definition
├── .env.example                 # Environment variable template
└── .gitleaks.toml               # Secret scanning config
```

---

## Roadmap

### Near-term

- [ ] Screenshot gallery and demo video
- [ ] Dark SOC: additional playbook action types (quarantine file, revoke token)
- [ ] Dark SOC: improved ML-based FP confidence scoring
- [ ] UEBA: additional anomaly detection patterns (DNS tunneling, data exfiltration volume)
- [ ] Compliance reporting: CIS, NIST, ISO 27001 coverage mapping

### Medium-term

- [ ] Multi-tenant support (per-customer isolation)
- [ ] Sigma rule import and conversion to Wazuh XML
- [ ] SOAR integrations: PagerDuty, Jira, Slack notifications
- [ ] API key management UI (rotate keys without .env edits)
- [ ] OpenTelemetry observability (traces, metrics, health dashboards)

### Long-term

- [ ] Kubernetes deployment manifest (Helm chart)
- [ ] Custom ML model for alert severity re-scoring
- [ ] Federated multi-site deployment
- [ ] Mobile analyst app

---

## Contributing

Contributions are welcome. Please open an issue first to discuss major changes.

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Follow the coding standards in [`CLAUDE.md`](CLAUDE.md)
4. Commit with conventional commit format: `feat(module): description`
5. Open a pull request against `main`

**Security issues:** Please do not open public issues for security vulnerabilities. Contact the maintainers directly.

---

## License

[MIT](LICENSE) — SOCPilots Engineering Team
