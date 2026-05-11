# AI-ENGINE.md — SOCPilots AI Architecture

## Overview

SOCPilots uses three AI layers:
1. **LangChain ReAct Agent** (`langchain-agent:8001`) — multi-step investigation orchestration
2. **RAG / Qdrant** (`rag-retrieval:5005` + `knowledge-ingestion:5004`) — semantic knowledge retrieval
3. **n8n Automation** (`n8n:5678`) — trigger-based workflow automation connecting all components

---

## LangChain ReAct Agent

### File: `langchain-agent/main.py` (~896 lines)

### Architecture Pattern

```
User triggers investigation
    │
    ▼
POST /investigate (FastAPI)
    │
    ▼
AgentExecutor (ReAct loop)
    │
    ├─ Thought: "I need to find related alerts"
    ├─ Action: search_alerts(query, hours=24)
    ├─ Observation: [list of alerts]
    │
    ├─ Thought: "The source IP needs enrichment"
    ├─ Action: enrich_ip(ip="1.2.3.4")
    ├─ Observation: { vt_score: 45, abuseipdb: 87, otx: {...} }
    │
    ├─ Thought: "Check for existing cases"
    ├─ Action: check_cases("1.2.3.4 brute force")
    ├─ Observation: []
    │
    ├─ Thought: "Check entity behavior"
    ├─ Action: query_ueba("user:john.doe")
    ├─ Observation: { risk_score: 78, anomalies: [...] }
    │
    └─ Final Answer: structured investigation report
```

### Available Tools

| Tool | Description | Parameters |
|---|---|---|
| `search_alerts` | Query OpenSearch for related SIEM alerts | `query: str`, `hours: int = 24` |
| `enrich_ip` | VirusTotal + AbuseIPDB + OTX + Shodan enrichment | `ip: str` |
| `check_cases` | Search TheHive for related cases | `query: str` |
| `query_ueba` | Neo4j entity behavior profile | `entity: str` (user: or host: prefix) |
| `query_assets` | Asset inventory lookup | `ip_or_host: str` |
| `query_shodan` | Shodan port/service/vuln data | `ip: str` |

### LLM Configuration

```python
# Primary: OpenAI GPT-4 (investigation accuracy)
primary_llm = ChatOpenAI(
    model="gpt-4",
    temperature=0,
    openai_api_key=OPENAI_API_KEY
)

# Fallback: Mistral (cost-efficient triage)
fallback_llm = ChatMistralAI(
    model="mistral-medium",
    mistral_api_key=MISTRAL_API_KEY
)
```

### Redis IOC Cache

```python
# Cache key format: "ioc:{indicator_type}:{indicator_value}"
# TTL: 3600 seconds (1 hour)
# Falls back gracefully if Redis unavailable
cache_key = f"ioc:{ioc_type}:{indicator}"
cached = _redis.get(cache_key)
if cached:
    return json.loads(cached)
```

### API Endpoints

| Method | Path | Purpose | Auth |
|---|---|---|---|
| `POST` | `/investigate` | Deep multi-step ReAct investigation | Internal token |
| `POST` | `/triage` | Fast single-step alert triage | Internal token |
| `POST` | `/enrich` | IOC enrichment (VT + IPDB + OTX + Shodan) | Internal token |
| `GET` | `/health` | Health check | None |

Internal token: `Authorization: Bearer {LANGCHAIN_INTERNAL_TOKEN}`

---

## RAG System

### Architecture

```
Document ingestion (knowledge-ingestion:5004):
  MITRE ATT&CK techniques → chunk → BGE embed → Qdrant upsert
  Wazuh detection rules   → chunk → BGE embed → Qdrant upsert
  TheHive incidents       → chunk → BGE embed → Qdrant upsert
  Uploaded evidence       → chunk → BGE embed → Qdrant upsert (evidence collection)

Query (rag-retrieval:5005):
  User query
    → prefix: "Represent this sentence for searching relevant passages: "
    → BGE embed (384d)
    → Qdrant cosine search (top-k)
    → return chunks + scores
```

### Qdrant Collections

| Collection | Dimensions | Model | Distance | Content |
|---|---|---|---|---|
| `socpilots_knowledge` | 384 | `BAAI/bge-small-en-v1.5` | Cosine | MITRE, rules, incidents |
| `socpilots_evidence` | 384 | `BAAI/bge-small-en-v1.5` | Cosine | Evidence files |

### Critical BGE Query Prefix

**ALWAYS prefix retrieval queries with:**
```
"Represent this sentence for searching relevant passages: "
```

This is a hard requirement for BGE asymmetric retrieval. Without it, retrieval quality degrades by ~40%.

Documents are stored WITHOUT this prefix.

### Knowledge Ingestion Sources

1. **MITRE ATT&CK** — 55 hardcoded Enterprise techniques in `knowledge_ingest.py`
2. **Wazuh rules** — fetched from Wazuh Manager API at ingest time
3. **TheHive incidents** — fetched from TheHive API at ingest time
4. **Evidence files** — uploaded via `/api/evidence/upload`; supports PDF, Excel, CSV, TXT, images (OCR)

### Re-ingest Command

```bash
docker compose exec knowledge-ingestion \
  curl -s -X POST http://localhost:5004/ingest \
  -H "X-API-Key: $RAG_API_KEY" | jq .
```

---

## n8n Automation Workflows

### Workflow Architecture

```
Wazuh alert webhook → SOCPilots_Main workflow:
  1. Parse alert metadata (severity, agent, rule, MITRE)
  2. Call mcp-wazuh for additional context
  3. POST /api/investigations (create in DB)
  4. If severity >= high: trigger Enrichment workflow
  5. If severity = critical: trigger Investigation workflow

Enrichment workflow:
  1. Extract IOCs from investigation
  2. Call langchain-agent /enrich for each IOC
  3. Update investigation with enrichment data
  4. Notify analyst via in-app notification

Investigation workflow:
  1. POST /investigate to langchain-agent
  2. Wait for ReAct completion (up to 180s)
  3. Parse investigation result
  4. Create TheHive case if warranted
  5. Update investigation status
```

### n8n Internal Service URLs

```
langchain-agent:  http://langchain-agent:8001
mcp-wazuh:        http://mcp-wazuh:3001
thehive-mcp:      http://thehive-mcp:8080
webapp:           http://webapp:3000
```

### Workflow Files

Stored in `automation/` directory. Deploy with:
```bash
bash automation/deploy-workflows.sh
```

---

## UEBA AI Engine

### File: `Socpilots/backend/src/neo4j.js` (~851 lines)

UEBA uses Neo4j to maintain a behavioral graph of all users and hosts. Risk scores are computed mathematically from weighted anomaly signals.

### Anomaly Detection Patterns

| Pattern | Weight | Detection Method |
|---|---|---|
| Impossible travel | 95 | Same user, different geolocations within 2h |
| Lateral movement | 85 | Sequential host access pattern across subnet |
| Privilege escalation | 80 | Process with elevated permissions not in baseline |
| New host access | 75 | User accessing host never accessed before |
| New process execution | 70 | Process not in established baseline for user |
| After-hours access | 55 | Activity outside established working hours |
| High-frequency login | 50 | Login rate > 3σ from baseline |

### Composite Risk Score

```javascript
// Risk score: weighted average of active anomalies, capped at 100
risk_score = Math.min(100, sum(active_anomalies.map(a => ANOMALY_WEIGHTS[a])) / active_count)
```

### Neo4j Graph Schema

```cypher
// Nodes
(:User {username, email, department, risk_score, last_updated})
(:Host {hostname, ip, os, department, criticality})
(:Process {name, hash, path})
(:Network {ip, port, protocol})

// Relationships
(:User)-[:LOGGED_IN {timestamp, location}]->(:Host)
(:User)-[:EXECUTED {timestamp, privileges}]->(:Process)
(:Host)-[:CONNECTED_TO {timestamp, bytes, direction}]->(:Network)
(:User)-[:TRANSFERRED {timestamp, bytes, method}]->(:Network)
```

---

## Dark SOC AI Gates

Dark SOC uses two AI validation layers before destructive actions:

### FP Confidence Check (Single LLM)
```javascript
// LangChain call to assess false positive probability
const fpScore = await assessFalsePositive(investigation);
if (fpScore > PLAYBOOK_FP_THRESHOLD) { skip(); audit('High FP confidence'); }
```

### Consensus Validation (Dual LLM)
```javascript
// For isolate_host / disable_user: two independent LLM assessments required
const [decision1, decision2] = await Promise.all([
  llm1.assess(investigation),
  llm2.assess(investigation)
]);
if (decision1.approved && decision2.approved) { execute(); }
else { createApprovalRecord(); notifyAnalysts(); }
```

---

*See also: `CLAUDE.md` sections 12–13, `docs/INTEGRATIONS.md`*
