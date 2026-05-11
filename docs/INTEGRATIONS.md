# INTEGRATIONS.md — SOCPilots Third-Party Integrations

## Wazuh SIEM

**Purpose:** Primary SIEM — alert source, agent management, active response

### Connections

| Component | Protocol | URL Pattern | Auth |
|---|---|---|---|
| Wazuh Manager API | HTTPS | `https://WAZUH_HOST:55000` | Basic auth (wazuh-wui) |
| OpenSearch Indexer | HTTPS | `https://WAZUH_INDEXER_HOST:9200` | Basic auth (admin) |

### OpenSearch Index

- Index pattern: `wazuh-alerts-*` (configured via `WAZUH_INDEX` env var)
- Key fields used:
  - `@timestamp` — alert time (always filter by this for performance)
  - `rule.id`, `rule.level`, `rule.description` — detection rule info
  - `rule.groups` — rule categories (array of strings)
  - `rule.mitre.id`, `rule.mitre.tactic`, `rule.mitre.technique` — MITRE mapping
  - `rule.decoder.name` — log source/decoder
  - `agent.name`, `agent.id` — endpoint info
  - `data.srcip`, `data.dstip` — network IPs
  - `full_log` — complete raw log line

### Active Response via MCP

Automated actions routed through `mcp-wazuh:3001` using JSON-RPC 2.0:
- `wazuh_block_ip` — block source IP at firewall
- `wazuh_isolate_host` — network isolation
- `wazuh_kill_process` — terminate process by PID
- `wazuh_disable_user` — disable user account

---

## TheHive Case Management

**Purpose:** Incident tracking, case management, SP-CM alert triage

### Connection

```
Direct API: THEHIVE_URL (https)
Auth: Authorization: Bearer {THEHIVE_API_KEY}
MCP bridge: thehive-mcp:8080 (Go service, JSON-RPC 2.0)
```

### Integration Points

- **Case creation:** Escalate from alert or investigation → POST `/api/cases`
- **SP-CM alerts:** TheHive alert list → `go('hive-alerts')`
- **Dark SOC:** `create_case` playbook action creates TheHive cases automatically
- **n8n:** SOCPilots_Main + Investigation workflows create cases via thehive-mcp

### Case Status Mapping

Closed statuses: `TruePositive`, `FalsePositive`, `Duplicate`, `Other`, `Indeterminate`, `Resolved`

---

## OpenAI

**Purpose:** Primary LLM for ReAct investigation agent

### Usage

```python
ChatOpenAI(model="gpt-4", temperature=0, openai_api_key=OPENAI_API_KEY)
```

- Used in: `langchain-agent/main.py`
- Rate: Investigation queries only (not every alert)
- Cost control: Mistral fallback for cheap triage

---

## Mistral AI

**Purpose:** Fallback LLM for cost-efficient triage

### Usage

```python
ChatMistralAI(model="mistral-medium", mistral_api_key=MISTRAL_API_KEY)
```

- Used as fallback when OpenAI unavailable or for `/triage` endpoint
- Optional: system works without it if `MISTRAL_API_KEY` not set

---

## OTX AlienVault

**Purpose:** Threat intelligence IOC feed + enrichment

### Integration

- Feed sync: every 6h via `otxFeedSync()` in server.js
- Enrichment: through langchain-agent `/enrich` endpoint
- API: `https://otx.alienvault.com/api/v1/`
- Data: pulse count, campaign names, malware families, tags, indicator type

### Supported Indicator Types

IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, hostname, email

---

## VirusTotal

**Purpose:** Malware/IP reputation enrichment

### Integration

- Called by `enrich_ip` tool in langchain-agent
- Returns: malicious/suspicious vote counts, detection engines, categories
- Cache: Redis 1h TTL
- Rate: Free tier limited — cache is critical

---

## AbuseIPDB

**Purpose:** IP abuse history and confidence scoring

### Integration

- Called alongside VirusTotal in `enrich_ip` tool
- Returns: confidence score (0–100), country, ISP, usage type, last reported
- Cache: Redis 1h TTL (same key as VT)

---

## Shodan

**Purpose:** Internet-facing host intelligence

### Integration

- Called by `query_shodan` tool in langchain-agent (optional)
- Returns: open ports, services, OS fingerprint, CVEs, geographic info
- Optional: system works without it if `SHODAN_API_KEY` not set

---

## n8n Automation

**Purpose:** Low-code workflow orchestration

### Connection

- Admin UI: `http://SERVER_IP:5678` (restrict to analyst IPs)
- Internal webhooks: `http://n8n:5678/webhook/...`
- Credentials stored in n8n credential vault (not `.env`)

### Workflow Files

Located in `automation/` directory. Deploy with `bash automation/deploy-workflows.sh`.

### n8n → Internal Services

| Service | URL | Auth |
|---|---|---|
| webapp | `http://webapp:3000` | Bearer token |
| langchain-agent | `http://langchain-agent:8001` | Bearer token |
| mcp-wazuh | `http://mcp-wazuh:3001` | MCP_API_KEY |
| thehive-mcp | `http://thehive-mcp:8080` | MCP_API_KEY |

---

## Redis

**Purpose:** IOC enrichment result cache

### Cache Keys

```
ioc:{type}:{indicator} → JSON enrichment result (1h TTL)
```

### Configuration

```
maxmemory: 256mb
maxmemory-policy: allkeys-lru  (evict least recently used)
```

Optional: system degrades gracefully without Redis (no caching, more API calls).

---

## Neo4j

**Purpose:** UEBA entity behavior graph

### Connection

```
bolt://neo4j:7687
Username: neo4j (default)
Password: NEO4J_PASSWORD env var
Browser UI: http://neo4j:7474 (internal only)
```

Used exclusively by `Socpilots/backend/src/neo4j.js`. Not directly accessible from frontend.

---

*See also: `docs/AI-ENGINE.md` for LangChain tool details, `docs/ARCHITECTURE.md` for service topology*
