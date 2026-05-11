# ARCHITECTURE.md — SOCPilots System Architecture

## Overview

SOCPilots is a containerized, microservice-adjacent SOC platform running on a single Docker Compose host. All services communicate over the internal `soc` bridge network. Only two ports are exposed externally: 443 (nginx→webapp) and 5678 (n8n admin).

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     External Network                            │
│  Browser → nginx:443 ──────────────────────────────────────┐   │
│  Analyst → n8n:5678  ──────────────────────────────────┐   │   │
└─────────────────────────────────────────────────────────│───│───┘
                                                          │   │
┌─── Docker Network: soc ──────────────────────────────────────────┐
│                                                          │   │   │
│  ┌──────────┐     ┌────────────────────────────────────────┐ │  │
│  │   n8n    │◄────│              nginx:80/443              │◄┘  │
│  │  :5678   │     └────────────────┬───────────────────────┘    │
│  └────┬─────┘                      │                            │
│       │                   ┌────────▼────────┐                   │
│       │                   │    webapp:3000   │                   │
│       │                   │  (Express SPA)  │                   │
│       │                   └──┬──┬──┬──┬──┬──┘                   │
│       │                      │  │  │  │  │                      │
│  ┌────▼──────┐    ┌──────────┘  │  │  │  └──────────┐          │
│  │mcp-wazuh  │    │langchain    │  │  │  asset-scan  │          │
│  │  :3001    │    │ agent:8001  │  │  │     :5003    │          │
│  └────┬──────┘    └──────┬──────┘  │  └──────────────┘          │
│       │                  │    ┌────┘                             │
│  ┌────▼──────┐    ┌───────────▼┐ ┌──────────┐  ┌─────────────┐ │
│  │thehive-mcp│    │rag-retrieval│ │knowledge │  │ scanner:7777│ │
│  │  :8080    │    │   :5005     │ │ingestion │  └─────────────┘ │
│  └───────────┘    └──────┬──────┘ │  :5004   │                  │
│                           │       └─────┬────┘                  │
│  ┌──────────┐  ┌──────────┘             │                       │
│  │postgres  │  │    ┌───────────────────┘                       │
│  │  :5432   │  │    │                                           │
│  └──────────┘  │  ┌─▼──────┐  ┌──────────┐  ┌──────────────┐  │
│                │  │qdrant  │  │  neo4j   │  │   redis      │  │
│                └──│ :6333  │  │7687/7474 │  │   :6379      │  │
│                   └────────┘  └──────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Data Flows

### 1. Alert Ingestion & Investigation

```
Wazuh Manager
    │ (Wazuh agent events)
    ▼
OpenSearch Indexer (wazuh-alerts-*)
    │
    ├─ n8n polls via mcp-wazuh → triggers SOCPilots_Main workflow
    │
    └─ webapp queries directly via /api/alerts (OpenSearch DSL)
           │
           └─ User clicks "Investigate" → POST /api/langchain/investigate
                  │
                  └─ langchain-agent ReAct loop:
                        search_alerts → enrich_ip → check_cases
                        → query_ueba → query_assets → synthesize
                        │
                        └─ result → POST to webapp → saved as investigation
                                        └─ optionally → TheHive case creation
```

### 2. RAG Knowledge Query

```
User query
    │
    ├─ Prefixed: "Represent this sentence for searching relevant passages: " + query
    │
    └─ POST /api/rag/search
           │
           └─ rag-retrieval:5005
                  │
                  └─ BGE embedding (384d) → Qdrant cosine search
                         │
                         └─ top-k chunks → returned to user
```

### 3. Dark SOC Automated Response

```
New investigation (severity critical/high)
    │
    ├─ playbook-engine.js evaluates against playbook rules
    │      (MITRE technique match, rule level threshold, FP confidence)
    │
    ├─ if require_consensus = true:
    │      └─ create isolation_approvals record (30-min TTL)
    │            └─ wait for L2+ sign-off via /api/darksoc/approve/:id
    │
    └─ execute action via mcp-wazuh JSON-RPC:
           wazuh_block_ip / wazuh_isolate_host / wazuh_kill_process
           wazuh_disable_user / create_case (TheHive) / close_case (DB)
```

### 4. OTX Threat Feed

```
Boot → 5min → otxFeedSync() in server.js
    │
    ├─ GET https://otx.alienvault.com/api/v1/pulses/subscribed
    │      (incremental: ?modified_since=otx_last_sync setting)
    │
    ├─ extract IOCs → upsert into otx_ioc_feed (cap 5000)
    │
    └─ every 6h → repeat
           │
           └─ saveArtifacts() auto-cross-references new IOCs
                  └─ boosts threat_score for matches
```

---

## Storage Architecture

| Store | Technology | Persistence | Purpose |
|---|---|---|---|
| Relational | PostgreSQL 16 | `postgres_data` volume | Investigations, assets, settings, users |
| Graph | Neo4j (latest) | `neo4j_data` volume | UEBA entity relationships + behavior baseline |
| Vector | Qdrant v1.9.3 | `qdrant_data` volume | Semantic embeddings for RAG |
| Cache | Redis 7 | `redis_data` volume | IOC enrichment results (1h TTL) |
| Sessions | In-memory Map | Lost on restart | Auth sessions (8h TTL) |
| Evidence files | Docker volume | `evidence_data` volume | Uploaded evidence raw files |

---

## Technology Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Frontend framework | None (vanilla JS) | Zero build complexity, single file, instant deploy |
| Backend framework | Express.js | Minimal overhead, mature ecosystem, easy proxy |
| SIEM | Wazuh + OpenSearch | Open source, enterprise-grade, MITRE-mapped rules |
| Vector DB | Qdrant | Native Docker, fast cosine search, simple REST API |
| Graph DB | Neo4j | Industry standard for entity relationship analysis |
| LLM orchestration | LangChain ReAct | Proven agent pattern, tool extensibility |
| Automation | n8n | Low-code, visual workflows, WebSocket triggers |
| Case management | TheHive | Open source DFIR-grade case management |
| MCP bridges | Python/Go | Lightweight, type-safe protocol adapters |

---

## Scalability Notes

Current architecture is single-server. Scaling paths:
- **Horizontal webapp scaling:** replace in-memory sessions with Redis-backed store
- **Multi-node OpenSearch:** already Wazuh cluster-compatible
- **Qdrant clustering:** native cluster mode supported
- **n8n:** can switch to queue mode with separate worker nodes

---

*See also: `docs/DEPLOYMENT.md`, `docs/INTEGRATIONS.md`*
