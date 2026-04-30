# AI Investigation Module — Setup Guide

## Overview

Dedicated AI investigation feature for HIGH and CRITICAL alerts.
Uses a **separate n8n webhook** (`socpilots-investigation`) to avoid 
load on the main SOCPilots AI workflow.

## Architecture

```
Webapp Tab "AI Investigation"
        │
        ▼
GET /api/alerts (level >= 8)  ──→  Display H+C alerts
        │
        ▼
User clicks alert
        │
        ▼
POST /api/ai/investigate  ──→  http://n8n:5678/webhook/socpilots-investigation
                                       │
                                       ▼
                               GPT-4o-mini Agent
                                       │
                            ┌──────────┼──────────┐
                            ▼          ▼          ▼
                       MCP Wazuh  MCP TheHive  MCP Enrichment
                            │          │          │
                            └──────────┴──────────┘
                                       │
                                       ▼
                            Comprehensive Investigation Report
```

## Deployment Steps

### 1. Update Backend (server.js)
Already includes `/api/ai/investigate` endpoint and `N8N_INVESTIGATION_URL` env var.

### 2. Update .env
```env
N8N_INVESTIGATION_URL=http://vmi3254460.contaboserver.net:5678/webhook/socpilots-investigation
```

### 3. Restart Webapp
```bash
docker compose restart webapp
```

### 4. Import Investigation Workflow
1. Open n8n: `http://vmi3254460.contaboserver.net:5678`
2. Workflows → Import from File
3. Select: `workflows/SOCPilots_Investigation.json`
4. **Activate the workflow** (toggle top-right)
5. Verify webhook is registered:
   ```bash
   curl -s http://localhost:5678/webhook/socpilots-investigation \
     -X POST -H "Content-Type: application/json" \
     -d '{"prompt":"test"}'
   ```

## Investigation Workflow Details

| Component | Configuration |
|-----------|--------------|
| **Webhook** | `POST /webhook/socpilots-investigation` |
| **LLM** | GPT-4o-mini, temp=0.4, maxTokens=2000 |
| **Memory** | Per-investigation session (4 messages) |
| **Tools** | MCP Wazuh + TheHive + Enrichment |
| **Max Iterations** | 8 (focused, fast investigation) |
| **Timeout** | 180 seconds |

## Investigation Report Sections

The AI generates structured reports with:

1. **Executive Summary** — Brief overview for management
2. **Technical Analysis** — Attack vector, IOCs, timeline
3. **Risk Assessment** — Severity, confidence, business impact
4. **MITRE ATT&CK Mapping** — Tactics + techniques with IDs
5. **Recommended Actions** — Immediate, short-term, hunt
6. **IOC Enrichment** — VirusTotal + AbuseIPDB results
7. **Related Events** — Other alerts from same source/agent

## Frontend Features

- **4 KPI cards**: Critical / High / Investigated / Auto-Triaged
- **Alert list** with severity color bars (left panel)
- **Filters**: severity (all/high/critical), time range (6h/24h/3d/7d)
- **Click alert** → triggers investigation with elapsed timer
- **Copy Report** button → copies to clipboard
- **Escalate to SP-CM** → pre-fills new TheHive case with full report

## Troubleshooting

**Investigation webhook not responding:**
- Check workflow is active in n8n (toggle top-right)
- Verify `.env` has `N8N_INVESTIGATION_URL` set correctly
- Test webhook: `curl -X POST http://localhost:5678/webhook/socpilots-investigation -d '{"prompt":"test"}'`

**Rate limit errors:**
- Backend limits to 8 investigations/minute per user
- Wait 60 seconds and retry

**Empty response:**
- GPT-4o-mini may have failed — check n8n executions log
- Verify OpenAI credentials in n8n
- Check MCP tools are reachable from n8n container
