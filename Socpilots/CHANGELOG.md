# SOC Pilots — Changelog

---

## v3.0 — April 26, 2026 (Current)

### Major Redesign
- **New fonts**: Rajdhani (display) + JetBrains Mono (data) + Space Grotesk (body)
- **Live UTC clock** in topbar — updates every second
- **Complete rebranding** — zero vendor exposure:
  - OpenSearch → **SIEM**
  - TheHive → **SP-CM**
  - n8n AI → **SOCPilots AI**
  - Mistral model → **LLM (ENGINE)**
  - All loading messages → "Loading from SOCPilots AI..."

### New Pages
- **Live Threat Map** — full-page attack map with real IP geolocation dots, top attackers panel, attack stats, MITRE tactics, timeline chart
- **IOC Enrichment** — fully working: IP/Domain/URL/Hash lookup via SOCPilots AI, geo-map visualization, quick-fill from top SIEM IPs

### Dashboard Improvements
- Stacked bar chart for alert timeline (color-coded by severity)
- World attack map with pulsing IP dots and hover tooltips
- Severity breakdown bar charts
- Live refresh every 90 seconds
- Threat level indicator in topbar

### Correlation Graph
- Interactive node graph with draggable nodes
- Central indicator node → SIEM alerts → SP-CM cases → MITRE → Timeline
- SVG edges with color coding by node type

### Vulnerability Page
- Added 3 filters: Severity + Search (CVE/package) + Status (Open/Fixed)

### Cases Kanban
- Fixed 4-column kanban: New / In Progress / Resolved / Closed
- Correct TheHive status mapping (TruePositive, FalsePositive → Closed column)
- Resolution badge displayed on closed cards

---

## v2.5 — April 26, 2026

### Bug Fixes
- **Agent status**: Fixed 6-hour window (was 5 minutes — caused active agents to show as inactive)
- **Cases**: Fixed `resolutionStatus` — TheHive uses `c.status` directly (not a separate field)
- **Case routing**: Added `isClosed` and `isInProgress` server-side flags
- **4th kanban column**: Added "CLOSED" column for TruePositive/FalsePositive/Duplicate
- **IOC page**: Added IOC Enrichment page with AI integration

### Branding (partial)
- Status pills: OpenSearch → SIEM, TheHive → SP-CM, n8n AI → SOCPilots AI

---

## v2.0 — April 26, 2026

### New Architecture — Direct API Calls
- Dashboard: 5 parallel OpenSearch aggregation queries
- Agents: OpenSearch agg on `agent.name` with timestamp-based status
- Alerts: Direct `wazuh-alerts-*` with multi-field filters
- Rules: OpenSearch `rule.id` deduplication
- Cases: TheHive `/api/v1/query` listCase
- Alerts: TheHive `/api/v1/query` listAlert
- n8n used ONLY for: AI Copilot, Vulns, Hunt AI, Correlation AI, Reports

### OpenSearch Functions Implemented (20)
1. Alert Retrieval
2. Advanced Filtering (severity, IP, agent, rule ID)
3. Full-Text Search
4. Time-Based Queries
5. Aggregation & Statistics
6. Threat Hunting
7. Event Correlation
8. MITRE ATT&CK Mapping
9. Field-Based Analysis
10. Sorting & Pagination
11. Index Pattern Querying (`wazuh-alerts-*`)
12. Data Exploration
13. Severity Analysis
14. Source/Destination Analysis
15. Keyword Matching
16. Range Queries
17. Existence Checks
18. Nested Field Queries
19. Anomaly Identification
20. Historical Analysis

### SIEM Alert Severity Mapping
- Critical: `rule.level` ≥ 12
- High: `rule.level` 8–11
- Medium: `rule.level` 5–7
- Low: `rule.level` < 5

---

## v1.5 — April 26, 2026

### Path Bug Fix
- Fixed: `ENOENT: no such file or directory, stat '/app/backend/frontend/index.html'`
- Cause: `__dirname = /app/backend/src`, so `../frontend` resolved to `/app/backend/frontend`
- Fix: Changed all paths from `'../frontend'` to `'../../frontend'`

---

## v1.1 — April 26, 2026

### Nginx Fix
- Fixed: nginx container restarting due to missing SSL certificates
- Removed SSL server block (no certificates available)
- HTTP-only on port 80

### Health Check Fix
- Changed from `wget` to `node -e require('http').get(...)` (wget not available in node:alpine)

---

## v1.0 — April 26, 2026

### Initial Release
- Express backend with JWT-like session tokens
- Nginx reverse proxy
- Docker + Docker Compose deployment
- Login page with cyber theme
- Dashboard with OpenSearch + TheHive data
- Alert feed, agents, cases, AI copilot
- Deployment package with customer configs

---

## Known Architecture Decisions

| Decision | Reason |
|----------|--------|
| No SSL in nginx.conf | No certificates on webapp server; use HTTP |
| n8n port 5678 must be open | n8n is on separate server — needs firewall rule |
| 6h agent activity window | Low-traffic agents may have gaps > 5 minutes |
| OpenSearch ignores SSL cert | Wazuh uses self-signed cert; `rejectUnauthorized: false` |
| `wazuh-alerts-*` wildcard | Covers all date-sharded indices |
| `@timestamp` for time filters | Index name dates are unreliable; use field |
