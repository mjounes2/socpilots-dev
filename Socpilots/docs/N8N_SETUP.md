# SOC Pilots — n8n Workflow Setup Guide

## What is n8n Used For?

SOC Pilots uses n8n **ONLY** for AI features:

| Feature | Uses n8n |
|---------|----------|
| Dashboard | ❌ No (direct OpenSearch) |
| Alerts | ❌ No (direct OpenSearch) |
| Agents | ❌ No (direct OpenSearch) |
| Cases | ❌ No (direct TheHive API) |
| **AI Copilot** | ✅ Yes |
| **Threat Hunt** | ✅ Yes (AI analysis part) |
| **Correlation** | ✅ Yes (AI report part) |
| **Vulnerabilities** | ✅ Yes |
| **Reports** | ✅ Yes |

---

## Required n8n Workflow Structure

```
[Webhook] → [AI Agent] → [Respond to Webhook]
                ↓
        [Mistral AI Model]
        [Simple Memory]
        [MCP Client → Wazuh]
        [MCP Client → TheHive]
```

---

## Setup Steps in n8n

### Step 1 — Create the Workflow

1. Open your n8n dashboard
2. Click **New Workflow**
3. Name it: `SOC Pilots - AI Assistant`

### Step 2 — Add Webhook Node

- Type: **Webhook**
- HTTP Method: `POST`
- Path: `socpilots` (or any name — update N8N_WEBHOOK_URL accordingly)
- Response Mode: `Response Node`

Your webhook URL will be:
```
http://YOUR_N8N_SERVER:5678/webhook/socpilots
```

### Step 3 — Add AI Agent Node

- Type: **AI Agent**
- Connect from: Webhook node

**Prompt (Text field):**
```
={{ $('Webhook').item.json.body.message }}
```

**System Message:**
```
You are the SOC Pilots AI Security Operations Analyst.
You are connected to Wazuh SIEM and TheHive via MCP tools.

Your capabilities:
- Query Wazuh agents, alerts, rules, and vulnerabilities via MCP
- List and create TheHive cases via MCP
- Analyze security events and suggest response actions
- Map alerts to MITRE ATT&CK techniques
- Provide SOC metrics and security summaries

Always use MCP tools to fetch real data.
When asked to return JSON data, return ONLY the JSON with no extra text.
Be technically precise and concise.

Operator: {{ $('Webhook').item.json.body._user || 'SOC Analyst' }}
```

### Step 4 — Connect AI Model

- Add: **Mistral Cloud Chat Model**
- Model: `devstral-medium-latest` (or `mistral-large-latest`)
- Connect to AI Agent's "Model" input

### Step 5 — Add Memory (Optional but recommended)

- Add: **Simple Memory**
- Session Key: `soc-copilot-session` (static key)
- Context Window: `10`
- Connect to AI Agent's "Memory" input

### Step 6 — Add MCP Clients

**MCP Wazuh:**
- Add: **MCP Client Tool**
- Endpoint URL: `http://YOUR_WAZUH_MCP_SERVER:3000/mcp`
- Connect to AI Agent's "Tool" input

**MCP TheHive:**
- Add: **MCP Client Tool**
- Endpoint URL: `http://YOUR_THEHIVE_MCP_SERVER:8080/mcp`
- Connect to AI Agent's "Tool" input

### Step 7 — Add Respond to Webhook Node

- Type: **Respond to Webhook**
- Response Body:
```javascript
={{ JSON.stringify({ "response": $('AI Agent').item.json.output }) }}
```
- Headers:
  - `Content-Type: application/json`
  - `Access-Control-Allow-Origin: *`

### Step 8 — Activate the Workflow

1. Click **Save**
2. Toggle **Active** (top right)
3. Copy the Production URL from the Webhook node

---

## Test the Webhook

```bash
curl -X POST http://YOUR_N8N_SERVER:5678/webhook/socpilots \
  -H "Content-Type: application/json" \
  -d '{
    "action": "chat",
    "message": "How many Wazuh agents do we have?",
    "session_id": "test-session",
    "_user": "admin"
  }'

# Expected response:
# {"response": "You have X active Wazuh agents..."}
```

---

## Troubleshooting n8n

| Problem | Solution |
|---------|----------|
| Webhook timeout | Open port 5678: `ufw allow 5678` |
| "No prompt specified" | Check prompt field: `={{ $('Webhook').item.json.body.message }}` |
| Empty response | Check AI Agent has Chat Model connected |
| MCP tools not working | Check MCP server URLs and authentication |
| Memory error | Change session key from expression to static text: `soc-copilot-session` |

---

## Your n8n Webhook URL Format

```
http://<N8N_SERVER_IP>:<PORT>/webhook/<WEBHOOK_PATH>
```

Set in `.env`:
```env
N8N_WEBHOOK_URL=http://YOUR_N8N_SERVER:5678/webhook/socpilots
```
