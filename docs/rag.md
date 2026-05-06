# SOCPilots RAG Architecture

## Overview

SOCPilots uses Retrieval-Augmented Generation (RAG) to enrich AI investigations with domain knowledge from MITRE ATT&CK, SOC detection rules, historical incidents, and response procedures.

```
Analyst query / Alert
        │
        ▼
 ┌─────────────────┐     embed with      ┌──────────────────────┐
 │  rag-retrieval  │◄── bge-small-en ───►│  Qdrant vector DB    │
 │   :5005         │    v1.5 (384-dim)   │  collection:         │
 └─────────────────┘                     │  socpilots_knowledge  │
        │                                └──────────────────────┘
        │  top-K semantic results
        ▼
 ┌─────────────────┐
 │  LangChain      │  ← injected into system prompt
 │  Agent :8001    │
 └─────────────────┘
        │
        ▼
 Investigation report + MITRE context
```

## Components

### 1. knowledge-ingestion (port 5004)

Indexes four types of knowledge into Qdrant:

| Type | Source | Count |
|------|--------|-------|
| `AttackPattern` | MITRE ATT&CK (hardcoded 55 key techniques) | ~55 |
| `DetectionRule` | Built-in SOC rules + Wazuh rules from OpenSearch | 15–200+ |
| `IncidentCase` | TheHive cases (last 200) | varies |
| `IncidentReport` | TheHive resolved cases tagged `post-incident` | varies |
| `ResponseProcedure` | Hardcoded 10 SOC response playbooks | 10 |

### 2. rag-retrieval (port 5005)

Provides semantic search over the Qdrant collection. Three specialized search modes:

| Endpoint | Use case | Returns |
|----------|----------|---------|
| `POST /retrieve` | Generic similarity search | top-K items of any type |
| `POST /search/investigation` | Alert triage | attack_patterns + similar_incidents + detection_rules |
| `POST /search/hunting` | Threat hunting | attack_patterns + detection_rules |

### 3. Embedding Model: BAAI/bge-small-en-v1.5

- **Dimensions:** 384
- **Similarity:** Cosine
- **Query prefix:** `"Represent this sentence for searching relevant passages: "` (prepended to search queries only, not to indexed documents)
- **Why bge over MiniLM:** ~30% better semantic accuracy on security-domain text (MTEB benchmark)

## Authentication

All retrieval endpoints require an API key in the `X-API-Key` header.

```bash
curl -X POST http://rag-retrieval:5005/retrieve \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $RAG_API_KEY" \
  -d '{"query": "lateral movement via RDP", "limit": 5}'
```

Set `RAG_API_KEY` in your `.env` file. Leave empty to disable auth (internal-only networks only).

## Querying Investigation Endpoints

### Search by alert description

```bash
curl -X POST http://rag-retrieval:5005/search/investigation \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $RAG_API_KEY" \
  -d '{
    "query": "PowerShell encoded command spawned by Word.exe",
    "limit": 5
  }'
```

Response:
```json
{
  "attack_patterns": [
    {
      "id": "mitre:T1059",
      "title": "T1059 — Command and Scripting Interpreter",
      "content": "Adversaries abuse command-line interfaces...",
      "type": "AttackPattern",
      "metadata": { "technique_id": "T1059", "tactic": "Execution" },
      "score": 0.9234
    }
  ],
  "similar_incidents": [...],
  "detection_rules": [...],
  "context_text": "[MITRE T1059] Command and Scripting..."
}
```

### Threat hunting search

```bash
curl -X POST http://rag-retrieval:5005/search/hunting \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $RAG_API_KEY" \
  -d '{"query": "Find lateral movement in the last 24 hours"}'
```

### Direct retrieval with type filter

```bash
curl -X POST http://rag-retrieval:5005/retrieve \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $RAG_API_KEY" \
  -d '{
    "query": "credential dumping LSASS",
    "type": "AttackPattern",
    "limit": 3
  }'
```

Valid `type` values: `AttackPattern`, `DetectionRule`, `IncidentCase`, `IncidentReport`, `ResponseProcedure`

## Ingesting New Data Sources

### Trigger ingestion via API

```bash
# Ingest all sources
curl -X POST http://knowledge-ingestion:5004/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $RAG_API_KEY" \
  -d '{"sources": ["mitre", "rules", "incidents", "incident_reports", "response_procedures"]}'

# Ingest only new TheHive cases
curl -X POST http://knowledge-ingestion:5004/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $RAG_API_KEY" \
  -d '{"sources": ["incidents"]}'
```

### Check knowledge base stats

```bash
curl http://knowledge-ingestion:5004/stats
```

```json
{
  "status": "ok",
  "stats": {
    "AttackPattern": 55,
    "DetectionRule": 127,
    "IncidentCase": 48,
    "IncidentReport": 3,
    "ResponseProcedure": 10,
    "total": 243
  }
}
```

### Adding custom data sources

To add a new data source, extend `KnowledgeIngestionService` in `knowledge_ingest.py`:

```python
def ingest_custom_source(self) -> int:
    count = 0
    for item in fetch_my_data():
        self._upsert_knowledge_item(
            item_id=f"custom:{item['id']}",
            title=item['name'],
            description=item['description'],
            item_type="CustomType",   # new type
            source="my_system",
            metadata={"key": "value"},
        )
        count += 1
    return count
```

Then add `"custom"` as a valid source in `run_ingestion()`.

## Performance Targets

| Operation | Target | Current (estimated) |
|-----------|--------|---------------------|
| `/retrieve` (top-5) | < 500ms | ~200ms |
| `/search/investigation` | < 2s | ~600ms |
| `/search/hunting` | < 2s | ~400ms |
| Full ingestion (all sources) | < 5 min | ~2 min |

Monitor latency via `GET /metrics`:

```bash
curl http://rag-retrieval:5005/metrics
```

```json
{
  "routes": {
    "POST /retrieve": { "p50_seconds": 0.18, "p95_seconds": 0.45, "samples": 142 },
    "POST /search/investigation": { "p50_seconds": 0.55, "p95_seconds": 1.2, "samples": 87 }
  }
}
```

## Running Tests

```bash
# Unit tests (no external dependencies)
cd /path/to/socpilots
pytest services/rag-retrieval/tests/test_rag.py -v -m unit
pytest services/knowledge-ingestion/tests/test_ingestion.py -v -m unit

# Integration tests (requires running stack)
QDRANT_URL=http://localhost:6333 RAG_API_KEY=your-key \
  pytest services/rag-retrieval/tests/test_rag.py -v -m integration
```
