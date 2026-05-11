# CLAUDE.md — SOCPilots Engineering Context

> Persistent AI engineering context for Claude Code sessions.
> Read this file before writing any code. It is the single source of truth for conventions, patterns, and architecture decisions.

---

## 1. Project Overview

**SOCPilots** is an enterprise-grade, open-source Security Operations Center (SOC) platform that integrates:
- **Wazuh SIEM** (alerts, rules, agents, OpenSearch indexer)
- **TheHive** (case management, SP-CM alert triage)
- **n8n** (workflow automation — triage, enrichment, investigation)
- **LangChain ReAct Agent** (AI-powered multi-step investigation)
- **RAG/Qdrant** (semantic search over MITRE ATT&CK, rules, evidence)
- **Neo4j UEBA** (user and entity behavior analytics graph)
- **Dark SOC** (automated playbook response engine)
- **OTX / VirusTotal / AbuseIPDB / Shodan** (threat intelligence enrichment)
- **MITRE ATT&CK Coverage** (enterprise heatmap + Navigator export)

**Stack:** Node.js (Express) + PostgreSQL + Neo4j + Qdrant + Redis + Python (FastAPI/Flask) + Go (MCP) + vanilla JS SPA (no build step) + Docker Compose.

**Supporting docs:** `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/UI-STANDARDS.md`, `docs/AI-ENGINE.md`, `docs/MITRE-COVERAGE.md`, `docs/API.md`, `docs/DEPLOYMENT.md`, `docs/INTEGRATIONS.md`

---

## 2. Quick Reference Commands

```bash
# First-time setup
cp .env.example .env && nano .env
docker compose up -d --build

# Rebuild a single service (most common — after editing server.js or index.html)
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

# Inspect PostgreSQL
docker compose exec postgres psql -U socpilots -d socpilots -c "\dt"
docker compose exec postgres psql -U socpilots -d socpilots -c "SELECT * FROM settings;"

# Import n8n automation workflows
bash automation/deploy-workflows.sh
```

---

## 3. System Architecture

All services share one Docker network (`soc`) and one `.env` file at the repo root. No external ingress except port 80/443 (nginx) and port 5678 (n8n admin).

### Request Path

```
Browser → nginx:80/443 → webapp:3000 (Express)
                              │
                              ├─ /api/langchain/*  → langchain-agent:8001 (FastAPI / ReAct)
                              ├─ /api/rag/*        → rag-retrieval:5005   (Flask / Qdrant)
                              ├─ /api/evidence/*   → knowledge-ingestion:5004 (Flask / Qdrant)
                              ├─ /api/assets/*     → asset-scan:5003      (Flask / nmap)
                              ├─ /api/scan/*       → scanner:7777         (Node.js / nmap)
                              └─ /api/darksoc/*    → mcp-wazuh:3001       (Python MCP)

n8n:5678 → mcp-wazuh:3001 (Wazuh automation)
n8n:5678 → thehive-mcp:8080 (case management automation)
```

### Service Map

| Container | Internal Port | Language | Purpose |
|---|---|---|---|
| `nginx` | 80, 443 (host) | — | Reverse proxy; rate limits (login 10r/m, api 60r/m, ai 8r/m); 200s AI timeout |
| `webapp` | 3000 | Node.js | Monolithic Express API + SPA serving |
| `postgres` | 5432 | — | Persistent state: investigations, assets, playbooks, evidence metadata |
| `neo4j` | 7687 / 7474 | — | UEBA entity graph; browser UI at `:7474` |
| `qdrant` | 6333 | — | Vector DB; collections: `socpilots_knowledge`, `socpilots_evidence` |
| `redis` | 6379 | — | IOC result cache (1h TTL) for LangChain agent |
| `langchain-agent` | 8001 | Python (FastAPI) | ReAct investigation agent; primary=OpenAI, fallback=Mistral |
| `knowledge-ingestion` | 5004 | Python (Flask) | Embeds MITRE/rules/incidents + evidence file upload/OCR |
| `rag-retrieval` | 5005 | Python (Flask) | Semantic search over `socpilots_knowledge` |
| `scanner` | 7777 | Node.js | nmap XML parser (NET_RAW/NET_ADMIN caps) |
| `asset-scan` | 5003 | Python (Flask) | Asset discovery + Wazuh agent gap detection |
| `mcp-wazuh` | 3001 | Python (MCP) | Wazuh Manager + Indexer bridge; hardened (read-only FS, no caps) |
| `thehive-mcp` | 8080 | Go (MCP) | TheHive case management MCP bridge |
| `n8n` | 5678 (host) | — | Automation: SOCPilots_Main / Enrichment / Investigation workflows |

---

## 4. Key Source Files

| File | Lines | What's in it |
|---|---|---|
| `Socpilots/backend/src/server.js` | ~3517 | Entire Express backend: auth, all REST routes, hunt scheduler, OTX feed sync |
| `Socpilots/backend/src/db.js` | ~1523 | PostgreSQL pool + `initSchema()` + all CRUD functions |
| `Socpilots/backend/src/playbook-engine.js` | ~504 | Dark SOC automated playbook execution (6 response actions) |
| `Socpilots/backend/src/neo4j.js` | ~851 | UEBA Neo4j Cypher queries + anomaly scoring |
| `Socpilots/backend/src/email-service.js` | ~373 | SMTP email notifications |
| `Socpilots/frontend/index.html` | ~7605 | Entire SPA — vanilla JS, no build step |
| `langchain-agent/main.py` | ~896 | ReAct agent with 6 tools + `/investigate`, `/triage`, `/enrich` endpoints |
| `services/knowledge-ingestion/src/app.py` | — | Flask: `/ingest`, `/upload`, `/evidence/search`, `/evidence/delete` |
| `services/knowledge-ingestion/src/file_processor.py` | — | PDF/Excel/CSV/OCR text extraction + chunking |
| `services/knowledge-ingestion/src/knowledge_ingest.py` | — | 55 hardcoded MITRE techniques + rule/incident ingestion |
| `services/rag-retrieval/src/rag_service.py` | — | BGE semantic search over `socpilots_knowledge` |
| `Socpilots-webapp/nginx/nginx.conf` | — | nginx rate limits and proxy timeouts |
| `docker-compose.yml` | — | Full unified stack definition |

---

## 5. Frontend Architecture

`Socpilots/frontend/index.html` is the **entire SPA** — vanilla JS, zero framework, zero build step. Every UI component, style, page, and function lives in this single file (~7600 lines).

### Page Navigation Pattern

Pages are `<div class="page" id="page-NAME">` elements. Only one is `active` at a time.

```javascript
// Navigate to a page
go('alerts');

// LOAD_MAP — maps page name to load function
const LOAD_MAP = {
  dashboard: loadDashboard,
  alerts: loadAlerts,
  rules: loadRules,
  mitre: loadMitre,
  // ... all pages registered here
};
```

**Adding a new page:**
1. Add `<div class="page" id="page-NAME">` (before `</main>`)
2. Add nav item: `<div class="sbi" onclick="go('NAME')">...</div>`
3. Register in `LOAD_MAP`: `NAME: loadNAME`
4. Define `async function loadNAME() {...}`

### Key Utility Functions

```javascript
G(url)             // GET with auth header → parsed JSON or null on error
P(url, body)       // POST with auth header + JSON body
D(url)             // DELETE with auth header
esc(str)           // XSS-safe HTML escaping — ALWAYS use for user data
fmtDate(ts)        // Format ISO timestamp to human-readable
spin(text)         // Loading spinner HTML
empty(text)        // Empty state HTML
errBnr(text)       // Error banner HTML
sbadge(severity)   // CSS class for severity badge (critical/high/medium/low/ok)
sevFromLevel(n)    // Convert numeric rule level → severity string
openModal(id)      // Open a modal overlay by ID
closeModal(id)     // Close a modal overlay by ID
buildPaginator(page, pageSize, total, prevFn, nextFn, sizeFn)  // Pagination HTML
```

### CSS Design System

All CSS lives in the `<style>` block at the top of `index.html`. CSS custom properties:

```css
:root {
  /* Colors */
  --c: #00e5ff;           /* Primary accent (cyan) */
  --c2: #00b8d4;          /* Secondary accent */
  --cdim: rgba(0,229,255,.1);
  --g: #00e676;           /* Green / success */
  --r: #ff1744;           /* Red / critical */
  --o: #ff9800;           /* Orange / high */
  --y: #ffc107;           /* Yellow / medium */
  /* Backgrounds */
  --bg: #0a1628;          /* Main background */
  --bg2: #0f1e35;         /* Secondary background */
  --b1: #1a2f4a;          /* Border 1 */
  --b2: #244060;          /* Border 2 */
  --b3: #2e5070;          /* Border 3 */
  /* Text */
  --txt: #e8f4fd;
  --txt2: #8ab0d0;
  --txt3: #4a6f8a;
  /* Fonts */
  --fw: 'Exo 2', ...;     /* Display / headings */
  --fm: 'Share Tech Mono', monospace;  /* Data / IDs / numbers */
  --r3: 6px;              /* Border radius */
}
```

**KPI card classes:** `.kpi.cl` (cyan), `.kpi.cg` (green), `.kpi.cr` (red), `.kpi.co` (orange), `.kpi.cp` (purple)
**Badge classes:** `.badge.critical`, `.badge.high`, `.badge.medium`, `.badge.low`, `.badge.ok`
**Common layout:** `.card` (panel), `.card-hd` (header), `.tbl` (scrollable table wrapper), `.loading` (spinner), `.empty` (empty state)

### Pagination Frontend

```javascript
// Page state variables (top-level)
let _alertPage=1, _alertPageSize=50;
let _invPage=1,   _invPageSize=50;
let _rulesPage=1, _rulesPageSize=50;
// ... one pair per paginated module

// Build paginator HTML
const pgn = buildPaginator(page, pageSize, total, 'prevFn()', 'nextFn()', 'setSizeFn(this)');
```

---

## 6. Backend Architecture

### Route Organization in server.js

Routes are grouped by feature with comment headers. Insert new routes **before** the `app.use(express.static(...))` static file handler (near end of file).

```javascript
// ── FEATURE NAME ──
app.get('/api/feature', authMW, async (req, res) => { ... });
app.post('/api/feature', authMW, requireRole('l2'), async (req, res) => { ... });
```

### Authentication Middleware

```javascript
authMW               // Any authenticated user (valid session token)
requireRole('l2')    // Analyst+ (l2, l3, admin)
requireRole('l3')    // Senior analyst+ (l3, admin)
requireRole('admin') // Admin only
```

Role hierarchy: `admin(4) > l3(3) > l2(2) > l1(1)`

### Session Management

- Sessions stored in **in-memory `Map`** — lost on restart, users must re-login
- Token: `crypto.randomBytes(32)` hex string, 8-hour TTL
- Internal service auth: `LANGCHAIN_INTERNAL_TOKEN` (static Bearer, grants `l2` access)
- Token stored in browser `sessionStorage` under key `soc_token`

### OpenSearch Helper

```javascript
// All OpenSearch queries go through osSearch()
const r = await osSearch({ size: 0, query: {...}, aggs: {...} });
```

### In-Memory Cache Pattern

```javascript
let _fooCache = null, _fooCacheTime = 0;
app.get('/api/foo', authMW, async (req, res) => {
  const now = Date.now();
  if (_fooCache && now - _fooCacheTime < 60000) return res.json(_fooCache);
  // ... fetch data ...
  _fooCache = result; _fooCacheTime = now;
  res.json(result);
});
```

Use 60s for most endpoints, 30s for MITRE coverage.

### Adding a New API Route

1. Add handler in `server.js` **before** the static file handler block
2. Add DB functions to `db.js` and export them if needed
3. Protect with appropriate `authMW` + `requireRole()` chain
4. Define upstream URL as `const` from `process.env` with Docker DNS default
5. Add to `.env.example` if new env var needed

---

## 7. Database Schema

### PostgreSQL (db.js)

Schema lives entirely in `db.js:initSchema()` — runs idempotently on every webapp startup.

**Rules:**
- New tables: append `CREATE TABLE IF NOT EXISTS` to `queries` array
- New columns: append `ALTER TABLE … ADD COLUMN IF NOT EXISTS` — **never** modify the original `CREATE TABLE`
- No migration framework — all statements must be idempotent
- Sort columns whitelisted via `ALLOWED_SORT` map before interpolation

**Tables:**

| Table | Purpose |
|---|---|
| `investigations` | SIEM alert investigations with severity, status, MITRE tags |
| `artifacts` | IOC artifacts per investigation (IPs, hashes, domains) |
| `settings` | Key-value config store (darksoc_enabled, smtp_*, otx_last_sync, etc.) |
| `subnets` | Network subnets for asset scanning |
| `assets` | Discovered assets with status, criticality, agent_id |
| `scan_jobs` | nmap/asset scan job history |
| `playbooks` | Dark SOC response playbook definitions |
| `playbook_executions` | Execution audit log (action, result, agent, timestamp) |
| `protected_assets` | Assets excluded from automated isolation |
| `isolation_approvals` | Pending consensus approvals (30-min TTL) |
| `users` | Auth users seeded from `SOC_USERS` env |
| `hunt_schedules` | Scheduled threat hunt jobs |
| `chat_messages` | AI copilot conversation history |
| `evidence_files` | Uploaded evidence file metadata |
| `otx_ioc_feed` | OTX AlienVault IOC feed (capped ~5000 IOCs) |
| `notifications` | In-app notification records |

### PostgreSQL Pagination Pattern

```javascript
// Always use window function — one query, no race condition
SELECT *, COUNT(*) OVER() AS total_count FROM investigations
ORDER BY created_at DESC LIMIT $1 OFFSET $2;
// Returns: { rows, total }
```

### Qdrant Vector Collections

| Collection | Dimensions | Model | Content |
|---|---|---|---|
| `socpilots_knowledge` | 384 | `BAAI/bge-small-en-v1.5` | MITRE ATT&CK, Wazuh rules, TheHive incidents |
| `socpilots_evidence` | 384 | `BAAI/bge-small-en-v1.5` | Uploaded evidence files (PDF/Excel/CSV/TXT/images) |

**Critical:** RAG retrieval queries MUST be prefixed: `"Represent this sentence for searching relevant passages: "` (BGE asymmetric retrieval). Documents stored WITHOUT this prefix.

### Neo4j Graph (UEBA)

Bolt: `bolt://neo4j:7687` | Browser: `http://neo4j:7474`

Node types: `User`, `Host`, `Process`, `Network`, `File`
Relationship types: `LOGGED_IN`, `ACCESSED`, `EXECUTED`, `CONNECTED_TO`, `TRANSFERRED`

Anomaly scoring weights (0–100): impossible_travel(95), lateral_movement(85), privilege_escalation(80), new_host_access(75), new_process(70), after_hours_access(55), high_frequency_login(50)

---

## 8. Auth System

```javascript
// Session creation (login)
sessions.set(token, { username, role, exp: Date.now() + 8*3600*1000 });

// Route protection
app.get('/api/protected', authMW, handler);             // Any user
app.post('/api/l2', authMW, requireRole('l2'), handler); // Analyst+
app.post('/api/admin', authMW, requireRole('admin'), handler); // Admin only
```

**Role map:** `admin=4`, `l3=3`, `l2=2`, `l1=1`. The string `analyst` in `SOC_USERS` env seeds as `l2`.

---

## 9. Notifications System

- Bell dropdown: `GET /api/notifications?page=1&page_size=20` → last 20
- Full page (`go('notifications')`): paginated via `loadNotificationsPage()`
- API: `GET /api/notifications?page=N&page_size=N&unread=true|false`
- Mark one: `POST /api/notifications/:id/read`
- Mark all: `POST /api/notifications/read-all`
- Create: `db.createNotification(type, title, message, severity, username, metadata)`
- Types: `investigation`, `case_created`, `true_positive`, `correlation`, `playbook`
- Socket.IO increments `_notifCount` badge live on `investigation:new`, `correlation:found`, `darksoc:action`

---

## 10. API Contract

### Pagination (MANDATORY for all list endpoints)

```
Request:  GET /api/endpoint?page=1&page_size=50&sort_by=created_at&sort_dir=desc&q=...
Response: { items, total, page, page_size, has_more }
```

**Never use raw `limit`/`offset` in new code.** Always `page` + `page_size`.

### Paginated Endpoints

| Endpoint | Backend | Default page_size | Extra filters |
|---|---|---|---|
| `GET /api/investigations` | PostgreSQL | 50 | `severity`, `agent`, `ruleId`, `q`, `sort_by`, `sort_dir`, `time_from`, `time_to` |
| `GET /api/alerts` | OpenSearch | 50 | `severity`, `hours`, `from`, `to`, `agent`, `srcip`, `q`; capped at 10 000 |
| `GET /api/alert-groups` | PostgreSQL | 50 | — |
| `GET /api/assets` | PostgreSQL | 50 | `status`, `q` |
| `GET /api/hunt/schedules` | PostgreSQL | 50 | — |
| `GET /api/playbook-executions` | PostgreSQL | 50 | — |
| `GET /api/otx/feeds` | PostgreSQL | 100 | `type`, `search` |
| `GET /api/ueba/leaderboard` | Neo4j | 20 | — |
| `GET /api/notifications` | PostgreSQL | 20 | `unread` |

---

## 11. MITRE ATT&CK Coverage Module

Page: `go('mitre')` → `page-mitre` → `loadMitre()`

### Backend Endpoints

- `GET /api/mitre/coverage?timeframe=24h|7d|30d|90d` — OpenSearch aggregation on `rule.mitre.id`; 30s cache keyed by timeframe. Returns `{ coverage: {techId: {count, max_level, rules[], agents[], tactics[], last_seen}}, timeframe }`
- `GET /api/mitre/technique/:id?timeframe=...` — Full drill-down: 20 recent alerts, rule list, agent list, decoder list, daily timeline histogram

### Frontend Data

- `MITRE_TACTICS` — 14 Enterprise ATT&CK tactics (TA0043→TA0040)
- `MITRE_TECHS` — ~190 parent techniques as `[id, name, [tactic_ids...]]`
- `MITRE_DATA` (variable): `_mitreCovData = {techId: {...}}` — loaded from API
- Coverage levels: High(≥10 alerts), Medium(3–9), Low(1–2), None(0)

### Key Functions

```javascript
loadMitre()              // Load coverage data + render matrix
applyMitreFilters()      // Re-render after filter change
renderMitreMatrix()      // Build 14-column HTML heatmap
mitreShowTech(id, name)  // Open drill-down modal with full detail
mitreExportNav()         // Export MITRE Navigator 4.9 JSON
mitreGetCovLevel(techId) // Returns 'high'|'medium'|'low'|'none'
```

**Dashboard widget**: `loadMitreDash()` (renamed — NOT `loadMitre()`) calls `/api/stats/mitre` for the dashboard MITRE card.

### OpenSearch MITRE Fields

- `rule.mitre.id` — technique IDs (e.g., `T1059`)
- `rule.mitre.tactic` — tactic names (e.g., `execution`)
- `rule.mitre.technique` — technique names

---

## 12. Detection Rules Module

Page: `go('rules')` → `page-rules` → `loadRules()`

### Backend `/api/rules`

OpenSearch aggregation on `rule.id`, 60s cache. Returns per-rule:
```json
{ "id": "100200", "level": 12, "severity": "critical", "description": "...",
  "groups": ["authentication_failed", "pam"], "mitre": ["T1110"],
  "decoder": "pam", "first_seen": 1234567890, "last_seen": 1234567890, "count": 450 }
```

Groups and MITRE are **arrays** (not comma-joined strings).

### Backward Compatibility

When consuming `r.groups` or `r.mitre`, always guard:
```javascript
(Array.isArray(r.groups) ? r.groups.join(', ') : r.groups || '')
(Array.isArray(r.mitre) ? r.mitre : [r.mitre]).filter(Boolean)
```

### Key Functions

```javascript
loadRules()          // Fetch all rules, update stats, populate filter dropdowns
applyRulesFilters()  // Client-side filter+sort from _rules[]
renderRules(filtered) // Render paginated table
rlSearchDebounce()   // 250ms debounced search input
rulesGoPage(p)       // Navigate to page p
rulesSetPageSize(sel) // Update page size from dropdown
```

---

## 13. AI Architecture

### LangChain ReAct Agent (`langchain-agent/main.py`)

ReAct pattern: Reason → Act → Observe → loop until answer.

**Tools available:**
- `search_alerts(query, hours)` — OpenSearch alert search
- `enrich_ip(ip)` — VirusTotal + AbuseIPDB + OTX lookup (Redis-cached 1h)
- `check_cases(query)` — TheHive case search
- `query_ueba(entity)` — Neo4j entity behavior profile
- `query_assets(ip_or_host)` — asset inventory lookup
- `query_shodan(ip)` — Shodan port/service lookup

**Endpoints:**
- `POST /investigate` — deep multi-step investigation (primary LLM: GPT-4)
- `POST /triage` — fast single-step triage (fallback: Mistral)
- `POST /enrich` — IOC enrichment with OTX integration
- `GET /health`

**Redis IOC Cache:** 1h TTL, keyed by indicator+type. Falls back gracefully if Redis unavailable.

**LLM Config:** Primary = `ChatOpenAI(model="gpt-4", temperature=0)`, Fallback = `ChatMistralAI`.

### RAG System

- **Embedding model:** `BAAI/bge-small-en-v1.5` (384 dims)
- **CRITICAL query prefix:** `"Represent this sentence for searching relevant passages: "` — required for BGE asymmetric retrieval
- **Retrieval:** Qdrant cosine similarity search, top-k results
- **Collections:** `socpilots_knowledge` (MITRE + rules + incidents), `socpilots_evidence` (uploaded files)

### n8n Automation Workflows

Three primary workflows:
1. **SOCPilots_Main** — Wazuh alert ingestion → triage → investigation trigger
2. **Enrichment** — IOC enrichment pipeline (VT + IPDB + OTX)
3. **Investigation** — Full ReAct investigation → TheHive case creation

n8n reaches internal services via Docker DNS: `mcp-wazuh:3001`, `thehive-mcp:8080`, `langchain-agent:8001`, `webapp:3000`.

---

## 14. Dark SOC (Playbook Engine)

File: `Socpilots/backend/src/playbook-engine.js`

**Disabled by default** (`darksoc_enabled = false` in settings).

### Response Actions

| Action | MCP Tool | Consensus Required |
|---|---|---|
| `block_ip` | `wazuh_block_ip` | No |
| `isolate_host` | `wazuh_isolate_host` | Yes |
| `kill_process` | `wazuh_kill_process` | No |
| `disable_user` | `wazuh_disable_user` | Yes |
| `create_case` | TheHive API | No |
| `close_case` | DB only | No |

### Security Gates

1. **FP probability check** — skip destructive action if FP likelihood > threshold
2. **Consensus validation** — second LLM must agree for `isolate_host` / `disable_user`
3. **Protected assets** — `protected_assets` table blocks auto-isolation; `critical` tier escalates instead
4. **Audit log** — every action stored in `playbook_executions`
5. **Consensus TTL** — `isolation_approvals` records expire after 30 minutes

---

## 15. Threat Intelligence

### OTX AlienVault

- **Feed sync:** `otxFeedSync()` in server.js — runs every 6h (first run 5min after boot)
- **Incremental:** Uses `otx_last_sync` setting for delta fetches after first full sync
- **Cap:** 20 pages / ~5000 IOCs per run; stored in `otx_ioc_feed` table
- **Cross-reference:** `saveArtifacts()` in db.js auto-boosts threat score for OTX-known indicators
- **Routes:** `GET /api/otx/stats`, `GET /api/otx/feeds`, `GET /api/otx/check/:indicator`, `POST /api/otx/sync` (admin only)

### Enrichment APIs (via LangChain agent)

- **VirusTotal:** `GET /api/langchain/enrich?ip=...` → malicious vote count, categories, engine detections
- **AbuseIPDB:** confidence score (0–100), country, ISP, usage type
- **Shodan:** open ports, services, OS, vulnerabilities, geographic info
- **OTX:** pulse count, campaign names, malware families, tags

---

## 16. UEBA Engine

File: `Socpilots/backend/src/neo4j.js` (~851 lines)

Key Neo4j queries:
- **Risk score backfill** — updates all users with composite score from relationship data
- **Leaderboard** — top risky entities ranked by score
- **Anomaly detection** — impossible travel, lateral movement, privilege escalation
- **Entity correlation** — links alerts to user/host graph context
- **Force graph data** — D3.js visualization with nodes + weighted edges

Risk backfill runs on every webapp startup to ensure scores are current.

---

## 17. Coding Standards

### Node.js / Express (server.js)

```javascript
// Route handler pattern
app.get('/api/endpoint', authMW, async (req, res) => {
  try {
    const { param } = req.query;
    // ... logic ...
    res.json(result);
  } catch (e) {
    console.error('[endpoint]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// Always validate/whitelist sort columns before string interpolation
const ALLOWED_SORT = { created_at: 'created_at', severity: 'severity' };
const col = ALLOWED_SORT[req.query.sort_by] || 'created_at';
```

- No raw SQL string interpolation for user input — use `$1, $2` parameterized queries
- Always use `console.error('[label]', e.message)` for error logging
- Define upstream URLs as `const` from `process.env` at file top with Docker DNS fallbacks
- Cache patterns use `let _cache = null, _cacheTime = 0` with TTL check

### Python (FastAPI/Flask services)

```python
# Use type annotations
# Structured logging: logging.getLogger(__name__)
# Always wrap external calls in try/except with meaningful fallbacks
# Redis cache: check _redis is not None before operations
# httpx for async HTTP, requests for sync
```

### Vanilla JS (index.html)

```javascript
// ALWAYS escape user data before HTML insertion
el.innerHTML = `<div>${esc(userInput)}</div>`;

// NEVER use innerHTML without esc() for user-supplied strings
// Use G(), P(), D() wrappers — never raw fetch() calls
// Debounce search inputs: clearTimeout(timer); timer = setTimeout(fn, 250)
// Module pattern: keep _privateState as top-level let variables
```

### CSS (index.html style block)

- Use CSS variables exclusively — never hardcode colors
- Dark theme glassmorphism: `background: rgba(N,N,N,.N)` + `backdrop-filter: blur`
- Glow effects via `box-shadow: 0 0 Npx rgba(0,229,255,.N)`
- Responsive via CSS Grid and Flexbox — no external CSS frameworks

---

## 18. Git / GitHub Workflow (MANDATORY)

### Commit Standards

Every completed task — fix, feature, refactor, UI update, docs — **must** result in a commit and push. No uncommitted changes after task completion.

**Commit type prefixes:**

| Prefix | Use for |
|---|---|
| `feat:` | New feature or page |
| `fix:` | Bug fix |
| `perf:` | Performance improvement |
| `refactor:` | Code restructuring without behavior change |
| `docs:` | Documentation updates |
| `security:` | Security hardening |
| `style:` | UI/CSS changes |
| `chore:` | Dependency/config/tooling updates |

**Commit message format:**
```
feat(module): short imperative summary (max 72 chars)

Optional body explaining WHY (not what the diff already shows).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
```

### Workflow After Every Task

```bash
# 1. Stage only relevant files (never git add -A)
git add Socpilots/backend/src/server.js Socpilots/frontend/index.html

# 2. Verify nothing sensitive staged
git diff --staged | grep -E "(API_KEY|password|secret|token)" | head -5

# 3. Commit with descriptive message
git commit -m "$(cat <<'EOF'
feat(mitre): add ATT&CK coverage heatmap with Navigator export

190 Enterprise techniques across 14 tactics. Backend: /api/mitre/coverage
and /api/mitre/technique/:id with 30s cache. Frontend: interactive matrix,
drill-down modal, coverage stats, JSON export.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"

# 4. Push to GitHub
git push origin main
```

### Security Rules for Git

- **NEVER** commit `.env` files, API keys, tokens, passwords, or credentials
- **NEVER** use `git add .` or `git add -A` without reviewing `git diff --staged` first
- **NEVER** commit `node_modules/`, `__pycache__/`, `*.pyc`, log files, or editor config
- **NEVER** force push to `main`
- Always rebuild and test (`docker compose up -d --build webapp`) before committing

### Branch Hygiene

- Main branch: `main`
- Feature branches (if needed): `feat/module-name` or `fix/description`
- Keep `main` always deployable — no broken builds

---

## 19. Security Standards

### Input Validation

- All API inputs validated and sanitized before use
- SQL: parameterized queries only — `$1, $2` params, never string concatenation
- OpenSearch: use structured query DSL — never user input in raw query strings
- HTML: always `esc()` user data in innerHTML — never skip this
- File uploads: validate MIME type + extension, size limit enforced
- Path traversal: validate file paths are within allowed directories

### Authentication Requirements

- All API routes require `authMW` at minimum
- Destructive operations (`DELETE`, automated actions) require `requireRole('l2')` or higher
- Admin operations require `requireRole('admin')`
- Internal service calls use `LANGCHAIN_INTERNAL_TOKEN` static Bearer token
- Tokens expire after 8 hours — no permanent sessions

### Sensitive Data

- API keys, secrets, passwords exclusively from `process.env` / `os.environ.get()`
- Never log full request bodies that may contain credentials
- `rejectUnauthorized: false` only for internal-to-internal HTTPS (Wazuh/TheHive)
- `mcp-wazuh` container: read-only FS, no Linux capabilities

### nginx Rate Limits

- Login: 10 req/min with burst=5
- API: 60 req/min
- AI endpoints (`/api/ai/`, `/api/langchain/`): 8 req/min with burst=4

---

## 20. Performance Optimization Rules

- **Never** query OpenSearch without a time range filter in production
- **In-memory cache** all expensive OpenSearch aggregations (60s TTL standard)
- **Client-side filtering** for rules/techniques (loaded once, filtered in JS)
- Paginate all list endpoints — default 50, never return unbounded lists
- OpenSearch: cap `from + size ≤ 10,000`; use `search_after` for deep pagination
- Redis: cache IOC enrichment results for 1h (keyed by indicator+type)
- Avoid N+1 queries: use aggregations or batch queries
- Neo4j: use parameterized Cypher, create indexes on frequently queried properties
- Static assets served directly by nginx — never through Express in production

---

## 21. Environment Variables

All variables defined in `.env` (root). Template in `.env.example`.

**Required:**
- `SERVER_IP`, `DOMAIN`, `CERTBOT_EMAIL`
- `PG_DATABASE`, `PG_USER`, `PG_PASSWORD`
- `SOC_USERS` (format: `user:pass:role,...`)
- `WAZUH_HOST`, `WAZUH_PORT`, `WAZUH_USER`, `WAZUH_PASS`
- `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_PORT`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS`
- `OPENSEARCH_URL`, `OPENSEARCH_USER`, `OPENSEARCH_PASS`, `WAZUH_INDEX`
- `THEHIVE_URL`, `THEHIVE_API_KEY`
- `N8N_USER`, `N8N_PASSWORD`
- `AUTH_SECRET_KEY` (generate: `openssl rand -hex 32`)
- `MCP_API_KEY` (generate: `echo "wazuh_$(openssl rand -hex 20)"`)
- `OPENAI_API_KEY`
- `OTX_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`

**Optional:** `SHODAN_API_KEY`, `MISTRAL_API_KEY`, `REDIS_URL`, `RAG_API_KEY`, `LANGCHAIN_INTERNAL_TOKEN`

**Adding a new env var:**
1. Add to `.env.example` with comment and placeholder
2. Add to service's `environment:` block in `docker-compose.yml`
3. Read via `process.env.VAR_NAME` (Node) or `os.environ.get("VAR_NAME", "")` (Python)
4. Update `README.md` Required Variables table if operator-facing

---

## 22. Adding New Features — Patterns

### New Frontend Page

```javascript
// 1. HTML (before </main>)
// <div class="page" id="page-NAME">
//   <div class="ph"><h1>PAGE TITLE</h1><p>subtitle</p></div>
//   ... content ...
// </div>

// 2. Nav item (in sidebar)
// <div class="sbi" onclick="go('NAME')">SVG + label</div>

// 3. LOAD_MAP registration
const LOAD_MAP = { ..., NAME: loadNAME, ... };

// 4. Load function
async function loadNAME() {
  const d = await G('/api/name');
  if (!d || d.error) { el.innerHTML = errBnr(d?.error || 'Error'); return; }
  // render...
}
```

### New Backend API + Database

```javascript
// server.js — new route
app.get('/api/feature', authMW, async (req, res) => { ... });

// db.js — new function
async function getFeatureItems(page, pageSize) {
  const offset = (page - 1) * pageSize;
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count FROM feature_table ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
    [pageSize, offset]
  );
  return { rows: r.rows, total: r.rows[0]?.total_count || 0 };
}
module.exports = { ..., getFeatureItems };
```

### New Database Table

```javascript
// In db.js initSchema() queries array — APPEND, never modify existing CREATE TABLE
`CREATE TABLE IF NOT EXISTS new_table (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
)`,
// New column on existing table:
`ALTER TABLE existing_table ADD COLUMN IF NOT EXISTS new_col TEXT`,
```

---

## 23. Deployment

Managed by Docker Compose. Single server deployment.

**Production checklist:**
1. `cp .env.example .env && nano .env` — fill ALL values
2. `bash scripts/init-letsencrypt.sh` — issue Let's Encrypt TLS cert
3. `docker compose up -d --build` — start full stack
4. `bash automation/deploy-workflows.sh` — import n8n workflows
5. Force initial RAG ingest (see Quick Reference)
6. Verify: `docker compose ps` — all services healthy

**TLS:** nginx terminates TLS on port 443. Let's Encrypt via certbot (auto-renewal). Port 80 redirects to 443.

**External ports:** 80 (HTTP→HTTPS redirect), 443 (webapp), 5678 (n8n admin)

---

## 24. Project Priorities (Current)

1. **Security hardening** — auth, input validation, rate limiting
2. **Detection coverage** — MITRE ATT&CK gap closure, rule enrichment
3. **AI accuracy** — LangChain agent tool precision, false positive reduction
4. **Performance** — OpenSearch query optimization, caching
5. **UEBA depth** — more anomaly detection patterns, ML scoring
6. **Dark SOC maturity** — more playbook actions, better consensus logic
7. **Observability** — better logging, metrics, health dashboards

---

*Last updated: 2026-05-11 | SOCPilots Engineering Team*
