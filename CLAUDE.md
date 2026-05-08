# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the stack

```bash
# First-time setup
cp .env.example .env && nano .env   # fill all required values (see .env.example comments)
docker compose up -d --build

# Rebuild and restart a single service (e.g. after editing server.js)
docker compose up -d --build webapp

# Stream logs
docker compose logs -f webapp
docker compose logs -f langchain-agent
docker compose logs -f knowledge-ingestion

# Health check all services
docker compose ps

# Force re-ingest MITRE/rules knowledge base into Qdrant
docker compose exec knowledge-ingestion \
  curl -s -X POST http://localhost:5004/ingest \
  -H "X-API-Key: $RAG_API_KEY" | jq .

# Run RAG unit tests
docker compose exec rag-retrieval python -m pytest tests/ -v

# Inspect the database
docker compose exec postgres psql -U socpilots -d socpilots -c "\dt"
docker compose exec postgres psql -U socpilots -d socpilots -c "SELECT * FROM settings;"

# Import n8n automation workflows
bash automation/deploy-workflows.sh
```

## Architecture

All services share one Docker network (`soc`) and one `.env` file at the repo root. There is no external ingress except port 80 (nginx) and port 5678 (n8n admin).

### Request path

```
Browser → nginx:80 → webapp:3000 (Express)
                         │
                         ├─ /api/langchain/* → langchain-agent:8001 (FastAPI / ReAct)
                         ├─ /api/rag/*       → rag-retrieval:5005  (Flask / Qdrant)
                         ├─ /api/evidence/*  → knowledge-ingestion:5004 (Flask / Qdrant)
                         ├─ /api/assets/*    → asset-scan:5003  (Flask / nmap)
                         ├─ /api/scan/*      → scanner:7777     (Node / nmap)
                         └─ /api/darksoc/*   → mcp-wazuh:3001   (Python MCP)
```

n8n (port 5678) reaches `mcp-wazuh:3001` and `thehive-mcp:8080` directly over the internal network.

### Service map

| Container | Port (internal) | Language | Purpose |
|---|---|---|---|
| `nginx` | 80 (host) | — | Reverse proxy; rate limits (login 10r/m, api 60r/m, ai 8r/m); 200s timeout for AI routes |
| `webapp` | 3000 | Node.js | Monolithic Express API + SPA serving |
| `postgres` | 5432 | — | Persistent state (investigations, assets, playbooks, evidence metadata) |
| `neo4j` | 7687 / 7474 | — | UEBA entity graph; browser UI at `:7474` |
| `qdrant` | 6333 | — | Vector DB; two collections: `socpilots_knowledge` and `socpilots_evidence` |
| `redis` | 6379 | — | IOC result cache (1h TTL) for LangChain agent |
| `langchain-agent` | 8001 | Python (FastAPI) | ReAct investigation agent; primary LLM = OpenAI, fallback = Mistral |
| `knowledge-ingestion` | 5004 | Python (Flask) | Embeds MITRE/rules/incidents + handles evidence file upload/OCR |
| `rag-retrieval` | 5005 | Python (Flask) | Semantic search over `socpilots_knowledge` |
| `scanner` | 7777 | Node.js | nmap XML parser (NET_RAW/NET_ADMIN caps) |
| `asset-scan` | 5003 | Python (Flask) | Asset discovery + Wazuh agent gap detection |
| `mcp-wazuh` | 3001 | Python (MCP) | Wazuh Manager + Indexer bridge; hardened (read-only FS, no caps) |
| `thehive-mcp` | 8080 | Go (MCP) | TheHive case management bridge |
| `n8n` | 5678 (host) | — | Automation (SOCPilots_Main / Enrichment / Investigation workflows) |

### Key source files

| File | What's in it |
|---|---|
| `Socpilots/backend/src/server.js` | Entire Express backend (~3276 lines): auth, all REST routes, hunt scheduler, OTX feed sync, evidence upload |
| `Socpilots/backend/src/db.js` | PostgreSQL pool + `initSchema()` + all CRUD functions (~1522 lines) |
| `Socpilots/backend/src/playbook-engine.js` | Dark SOC automated playbook execution logic |
| `Socpilots/backend/src/neo4j.js` | UEBA Neo4j Cypher queries (~818 lines) |
| `Socpilots/frontend/index.html` | Entire SPA (~6575 lines, vanilla JS, no build step) |
| `langchain-agent/main.py` | ReAct agent with tools: `search_alerts`, `enrich_ip`, `check_cases`, `query_ueba`, `query_assets`, `query_shodan`; `/enrich` endpoint includes OTX |
| `services/knowledge-ingestion/src/app.py` | Flask app: `/ingest`, `/upload`, `/evidence/search`, `/evidence/delete` |
| `services/knowledge-ingestion/src/file_processor.py` | PDF/Excel/CSV/OCR text extraction + chunking |
| `services/knowledge-ingestion/src/knowledge_ingest.py` | 55 hardcoded MITRE techniques + rule/incident ingestion into Qdrant |
| `services/rag-retrieval/src/rag_service.py` | Semantic search (BGE query prefix required for retrieval queries) |
| `Socpilots-webapp/nginx/nginx.conf` | nginx rate limits and proxy timeouts |

## Auth system

- Sessions stored in an **in-memory Map** in `server.js` (lost on restart — users must re-login).
- Tokens are `crypto.randomBytes(32)` hex strings, 8-hour TTL.
- Users come from two sources, merged at startup: `SOC_USERS` env var → seeded into Postgres `users` table.
- Role hierarchy (defined in `ROLE_HIERARCHY`): `admin(4) > l3(3) > l2(2) > l1(1)`.
- The string `analyst` in `SOC_USERS` env maps to `l2` at seed time.
- Internal service-to-service auth: `LANGCHAIN_INTERNAL_TOKEN` (static Bearer token, grants `l2` access).
- Route protection: `authMW` (any logged-in user) or `requireRole('l2')` / `requireRole('admin')`.

## Database schema

Schema lives entirely in `db.js:initSchema()`. It runs on every webapp startup. Rules:

- New **tables**: append a `CREATE TABLE IF NOT EXISTS` block to the `queries` array.
- New **columns on existing tables**: append `ALTER TABLE … ADD COLUMN IF NOT EXISTS` — never modify the original `CREATE TABLE` statement alone.
- There is no migration framework. All statements must be idempotent.
- Postgres tables: `investigations`, `artifacts`, `settings`, `subnets`, `assets`, `scan_jobs`, `playbooks`, `playbook_executions`, `protected_assets`, `isolation_approvals`, `users`, `hunt_schedules`, `chat_messages`, `evidence_files`, `otx_ioc_feed`.

## Qdrant collections

| Collection | Dimensions | Model | Content |
|---|---|---|---|
| `socpilots_knowledge` | 384 | `BAAI/bge-small-en-v1.5` | MITRE ATT&CK techniques, Wazuh detection rules, TheHive historical incidents |
| `socpilots_evidence` | 384 | `BAAI/bge-small-en-v1.5` | Uploaded evidence files (PDF, Excel, CSV, TXT, images) |

RAG retrieval queries **must** be prefixed with `"Represent this sentence for searching relevant passages: "` (BGE asymmetric retrieval requirement). Documents are stored without the prefix.

## Frontend

`Socpilots/frontend/index.html` is the entire SPA — vanilla JS, no framework, no build step. Pages are shown/hidden by `go(section)` toggling `<div>` visibility. Bearer tokens are stored in `sessionStorage` under the key `soc_token`. `login.html` sets the token then redirects to `index.html`.

To add a new page: add a `<div id="page-NAME">` section, add a nav item calling `go('NAME')`, and register `'NAME'` in the `LOAD_MAP` object (not just in the `go()` function's section list — `go()` uses `document.getElementById` dynamically).

## Notifications

In-app notification bell (top-right) + full notifications page (`go('notifications')`).

- **Bell dropdown** — shows last 20 notifications via `GET /api/notifications?page=1&page_size=20`; "View all notifications" closes the dropdown and navigates to `page-notifications`.
- **Full page** (`page-notifications`) — paginated list via `loadNotificationsPage()`; supports All/Unread filter, Mark all read, Refresh.
- **API** — `GET /api/notifications?page=N&page_size=N&unread=true|false` → `{ notifications, total, page, page_size, has_more }`. Mark one read: `POST /api/notifications/:id/read`. Mark all: `POST /api/notifications/read-all`.
- **db.js** — `listNotifications(username, limit, offset, unreadOnly)` uses `COUNT(*) OVER()` and returns `{ rows, total }`.
- **Creating notifications** — call `db.createNotification(type, title, message, severity, username, metadata)`. Types used: `investigation`, `case_created`, `true_positive`, `correlation`, `playbook`.
- **Socket.IO** — `_notifCount` is also incremented on `investigation:new`, `correlation:found`, `darksoc:action` socket events so the badge stays live without polling.

## Adding a new API route

1. Add the route handler in `server.js` **before** the static file handler block (the `app.use(express.static(...))` line near the end).
2. If it needs new DB operations, add functions to `db.js` and export them.
3. Protect with `authMW` (all authenticated users) or `authMW, requireRole('l2')` (analyst+) or `authMW, requireRole('admin')`.
4. If the route proxies to an internal service, define the upstream URL as a `const` from `process.env` at the top of `server.js` with a sensible Docker DNS default.

## Adding a new environment variable

1. Add to `.env.example` with a comment and placeholder value.
2. Add to the relevant service's `environment:` block in `docker-compose.yml`.
3. Read in code via `process.env.VAR_NAME` (Node) or `os.environ.get("VAR_NAME", "")` (Python).
4. Update `README.md` Required Variables table if it's operator-facing.

## Dark SOC (automated response)

Dark SOC is the playbook automation engine. It is **disabled by default** (`darksoc_enabled = false` in `settings`). When enabled:

- `playbook-engine.js` evaluates incoming investigations against playbook rules (MITRE techniques, rule level, FP confidence).
- Playbooks with `require_consensus = true` create an `isolation_approvals` record (30-min TTL) that requires L2+ analyst sign-off before execution.
- The `protected_assets` table prevents auto-isolation of critical hosts; `critical` tier assets block isolation entirely and escalate instead.
- Execution history is logged to `playbook_executions`.

## OTX AlienVault IOC Feed

OTX is integrated for both real-time IOC enrichment and a periodic threat feed:

- **Enrichment**: `GET /api/langchain/enrich` (proxied to langchain-agent `/enrich`) now returns an `otx` field with pulse count, matching campaign names, tags, and malware families. Supports all indicator types: IP, domain, URL, hash.
- **Feed sync**: `otxFeedSync()` in `server.js` runs every 6h (first run 5min after boot). Fetches subscribed OTX pulses, stores IOCs in `otx_ioc_feed` table (capped at 20 pages / 5000 IOCs per run; incremental after first sync using `otx_last_sync` setting).
- **Cross-reference**: `saveArtifacts()` in `db.js` automatically cross-references new investigation artifacts against `otx_ioc_feed` and boosts the threat score for known-bad indicators.
- **API routes** (all require auth):
  - `GET /api/otx/stats` — total IOC count, last sync time, breakdown by type
  - `GET /api/otx/feeds?page=1&page_size=100&type=IPv4&search=...` — paginated list/search feed IOCs
  - `GET /api/otx/check/:indicator` — check if a specific indicator is in the feed
  - `POST /api/otx/sync` — manual sync trigger (admin only)
- **Env var**: `OTX_API_KEY` — required in `.env`, set in both `webapp` and `langchain-agent` environments in `docker-compose.yml`.

## Pagination

All list endpoints use a unified contract. Always use `page` + `page_size` — never raw `limit`/`offset` in new code.

**Request:** `?page=1&page_size=50&sort_by=created_at&sort_dir=desc&time_from=ISO&time_to=ISO&q=...`
**Response:** `{ items (or alerts/groups/etc), total, page, page_size, has_more }`

### Paginated endpoints

| Endpoint | Backend | Default page_size | Extra filters |
|---|---|---|---|
| `GET /api/investigations` | PostgreSQL | 50 | `severity`, `agent`, `ruleId`, `q`, `sort_by`, `sort_dir`, `time_from`, `time_to` |
| `GET /api/alerts` | OpenSearch | 50 | `severity`, `hours`, `from`, `to`, `agent`, `srcip`, `q`; capped at 10 000 from+size |
| `GET /api/alert-groups` | PostgreSQL | 50 | — |
| `GET /api/assets` | PostgreSQL | 50 | `status`, `q` |
| `GET /api/hunt/schedules` | PostgreSQL | 50 | — |
| `GET /api/playbook-executions` | PostgreSQL | 50 | — |
| `GET /api/otx/feeds` | PostgreSQL | 100 | `type`, `search` |
| `GET /api/ueba/leaderboard` | Neo4j | 20 | — |

### db.js pattern (PostgreSQL)

All paginated functions use `COUNT(*) OVER() AS total_count` (window function — one query, no race). Sort column is whitelisted against an `ALLOWED_SORT` map before interpolation. Return shape: `{ rows, total }`.

### Frontend pagination

Shared helper: `buildPaginator(page, pageSize, total, prevFn, nextFn, sizeFn)` — returns HTML with Prev/Next buttons and 20/50/100 page-size selector.

Page state variables (top-level JS): `_alertPage`, `_invPage`, `_assetPage`, `_agPage`, `_lbPage`, `_rulesPage`, `_pbExecPage`, `_otxPage`.

Investigation History gained date-range (`hist-from` / `hist-to`) and sort-by (`hist-sort`) filter inputs in addition to pagination controls.
