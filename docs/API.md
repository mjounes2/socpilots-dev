# API.md — SOCPilots REST API Reference

## Authentication

All endpoints require `Authorization: Bearer <token>` header.

Obtain token: `POST /api/login`
```json
Request:  { "username": "admin", "password": "..." }
Response: { "token": "...", "user": { "username": "admin", "role": "admin" } }
```

Token TTL: 8 hours. Stored in browser `sessionStorage` as `soc_token`.

---

## Pagination Contract

All list endpoints use the unified pagination contract:

**Request:** `GET /api/endpoint?page=1&page_size=50&sort_by=created_at&sort_dir=desc&q=...`

**Response:**
```json
{
  "items": [...],  // or "alerts", "investigations", "assets", etc.
  "total": 1234,
  "page": 1,
  "page_size": 50,
  "has_more": true
}
```

---

## Core Endpoints

### Alerts

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/alerts` | any | Paginated SIEM alerts from OpenSearch |
| `GET` | `/api/alerts/:id` | any | Single alert detail |
| `GET` | `/api/alert-groups` | any | Deduplicated alert groups |

**Alert filters:** `severity`, `hours`, `from`, `to`, `agent`, `srcip`, `q`; capped at 10,000

### Investigations

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/investigations` | any | Paginated investigation history |
| `POST` | `/api/investigations` | l2 | Create investigation |
| `GET` | `/api/investigations/:id` | any | Single investigation |
| `PUT` | `/api/investigations/:id` | l2 | Update status/notes |
| `DELETE` | `/api/investigations/:id` | l3 | Delete investigation |

**Filters:** `severity`, `agent`, `ruleId`, `q`, `sort_by`, `sort_dir`, `time_from`, `time_to`

### Agents

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/agents` | any | Agent list with alert counts, status |
| `GET` | `/api/agents/:id` | any | Agent detail |

### Assets

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/assets` | any | Paginated asset inventory |
| `POST` | `/api/assets` | l2 | Add asset |
| `PUT` | `/api/assets/:id` | l2 | Update asset |
| `DELETE` | `/api/assets/:id` | l3 | Delete asset |

### Cases (TheHive)

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/cases` | any | TheHive cases (proxied) |
| `POST` | `/api/cases` | l2 | Create TheHive case |
| `GET` | `/api/hive-alerts` | any | TheHive SP-CM alerts |

### Detection Rules

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/rules` | any | Enriched rules from OpenSearch (60s cache) |
| `POST` | `/api/rules/create` | l2 | Push new detection rule to Wazuh |

### MITRE ATT&CK

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/mitre/coverage` | any | Coverage heatmap data (30s cache) |
| `GET` | `/api/mitre/technique/:id` | any | Technique drill-down detail |
| `GET` | `/api/stats/mitre` | any | Dashboard mini-widget stats (24h) |

### OTX Threat Feed

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/otx/stats` | any | Feed stats (total, last sync, breakdown by type) |
| `GET` | `/api/otx/feeds` | any | Paginated IOC feed search |
| `GET` | `/api/otx/check/:indicator` | any | Check if indicator is in feed |
| `POST` | `/api/otx/sync` | admin | Manual feed sync trigger |

### LangChain / AI

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/api/langchain/investigate` | l2 | Trigger deep investigation |
| `POST` | `/api/langchain/triage` | l2 | Fast triage |
| `GET` | `/api/langchain/enrich` | any | IOC enrichment (VT+IPDB+OTX) |
| `GET` | `/api/langchain/health` | any | Agent health check |

### UEBA

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/ueba/stats` | any | Summary stats |
| `GET` | `/api/ueba/leaderboard` | any | Top risky entities |
| `GET` | `/api/ueba/anomalies` | any | Recent anomaly list |
| `GET` | `/api/ueba/graph` | any | D3.js force graph data |
| `GET` | `/api/ueba/entity/:name` | any | Entity detail |

### Hunt

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/hunt/schedules` | any | Scheduled hunt jobs |
| `POST` | `/api/hunt/schedules` | l2 | Create hunt schedule |
| `DELETE` | `/api/hunt/schedules/:id` | l2 | Delete schedule |
| `POST` | `/api/hunt/run` | l2 | Run hunt immediately |

### Dark SOC

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/darksoc/status` | any | Dark SOC enable/disable status |
| `GET` | `/api/playbook-executions` | any | Execution history (paginated) |
| `POST` | `/api/darksoc/approve/:id` | l2 | Approve pending isolation |
| `POST` | `/api/darksoc/reject/:id` | l2 | Reject pending isolation |

### Notifications

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/notifications` | any | Paginated notifications |
| `POST` | `/api/notifications/:id/read` | any | Mark one read |
| `POST` | `/api/notifications/read-all` | any | Mark all read |

### RAG / Evidence

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/api/rag/search` | any | Semantic knowledge search |
| `POST` | `/api/evidence/upload` | l2 | Upload evidence file |
| `GET` | `/api/evidence/search` | any | Search evidence collection |
| `DELETE` | `/api/evidence/:id` | l2 | Delete evidence |

### Settings

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/settings` | any | All settings (excludes secrets) |
| `POST` | `/api/settings` | admin | Update setting |

### Status

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/api/status` | any | Service connectivity status |
| `GET` | `/health` | none | Simple health check (no auth) |

---

## Error Responses

All errors follow:
```json
{ "error": "Human-readable error message" }
```

HTTP status codes: `400` (bad request), `401` (unauthenticated), `403` (insufficient role), `404` (not found), `502` (upstream service error)

---

*Full OpenAPI spec: `docs/openapi.yaml`*
