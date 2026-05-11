# SECURITY.md — SOCPilots Security Standards

## Authentication & Authorization

### Session Security
- Tokens: `crypto.randomBytes(32)` hex strings (256-bit entropy)
- TTL: 8 hours; stored in server-side in-memory Map
- Transport: `Authorization: Bearer <token>` header on all API requests
- Client storage: `sessionStorage` (cleared on browser close)
- Internal service auth: static `LANGCHAIN_INTERNAL_TOKEN` Bearer token (grants `l2` role)

### Role Hierarchy
```
admin (4) — full access, user management, force-push settings
l3    (3) — senior analyst: all l2 + advanced hunt, manual playbook trigger
l2    (2) — analyst: investigate, create cases, approve isolation
l1    (1) — read-only: view alerts, investigations, assets
```

### Route Protection Requirements
| Operation | Minimum Role |
|---|---|
| View alerts, investigations, assets | Any authenticated (authMW) |
| Create investigation, escalate case | l2 |
| Execute playbook, approve isolation | l2 |
| Manage hunt schedules | l2 |
| Manage playbooks | l3 |
| Admin settings, user management | admin |
| OTX manual sync | admin |
| Dark SOC enable/disable | admin |

---

## Input Validation & Injection Prevention

### SQL Injection — MANDATORY
```javascript
// CORRECT — parameterized query
pool.query('SELECT * FROM table WHERE id=$1 AND user=$2', [id, username]);

// WRONG — never do this
pool.query(`SELECT * FROM table WHERE id=${id}`); // SQL INJECTION RISK
```

### Sort Column Whitelisting — MANDATORY
```javascript
const ALLOWED_SORT = { created_at: 'created_at', severity: 'severity', name: 'name' };
const col = ALLOWED_SORT[req.query.sort_by] || 'created_at'; // safe to interpolate
```

### XSS Prevention — MANDATORY
```javascript
// CORRECT — always escape user data in innerHTML
el.innerHTML = `<div>${esc(userInput)}</div>`;

// WRONG — never skip esc() for user-supplied data
el.innerHTML = `<div>${userInput}</div>`; // XSS RISK
```

### OpenSearch Query Safety
- Always use structured query DSL objects — never string-interpolate user input into query JSON
- Always include time range filter: `{ range: { '@timestamp': { gte: 'now-Xh' } } }`
- Cap `from + size` at 10,000 to prevent deep pagination abuse

### File Upload Security
- Validate MIME type via file content (not extension only)
- Enforce size limits (handled by multer in knowledge-ingestion service)
- Files stored in isolated Docker volume, not directly web-accessible
- OCR processed server-side — no file execution

---

## Network Security

### nginx Rate Limits
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;  # Login
limit_req_zone $binary_remote_addr zone=api:10m   rate=60r/m;  # API
limit_req_zone $binary_remote_addr zone=ai:10m    rate=8r/m;   # AI endpoints
```

### Security Headers (nginx)
- `server_tokens off` — hide nginx version
- All external traffic HTTPS only (port 80 redirects to 443)
- Internal service-to-service over Docker network (never external)

### TLS
- Let's Encrypt certificates via certbot (auto-renewal)
- `rejectUnauthorized: false` ONLY for internal Wazuh/TheHive HTTPS (self-signed certs)
- External-facing nginx always uses valid TLS

### Container Hardening
- `mcp-wazuh`: read-only filesystem, no Linux capabilities
- No containers run as root where possible
- `scanner`: NET_RAW + NET_ADMIN caps for nmap only, no others

---

## Secrets Management

### Rules
1. ALL secrets in `.env` file — never hardcoded anywhere in source code
2. `.env` is gitignored — **never commit it**
3. Access via `process.env.VAR_NAME` (Node) or `os.environ.get("VAR_NAME", default)` (Python)
4. `.env.example` contains placeholders only — never real values

### Git Secret Prevention
```bash
# Before staging, always check for accidental secrets
git diff --staged | grep -iE "(api_key|password|secret|token|bearer)" | head -10

# Files that must NEVER be committed
.env
*.pem *.key *.crt (except publicly-known CA certs)
node_modules/
__pycache__/
```

### Rotation
- `AUTH_SECRET_KEY`: rotate by regenerating (`openssl rand -hex 32`) and restarting webapp
- `MCP_API_KEY`: rotate in `.env` and restart mcp-wazuh
- `LANGCHAIN_INTERNAL_TOKEN`: rotate in `.env`, restart webapp + langchain-agent
- Session tokens: invalidated automatically on webapp restart

---

## Dark SOC Security Gates

The automated response engine has multiple safety layers to prevent accidents:

1. **FP confidence gate**: if investigation FP probability > threshold, skip destructive actions
2. **Consensus requirement**: `isolate_host` and `disable_user` require two independent LLM approvals
3. **Human approval gate**: `require_consensus = true` playbooks create a 30-min approval window
4. **Protected assets table**: critical assets can never be auto-isolated — only escalate
5. **Audit trail**: every executed action (including failures) logged to `playbook_executions`
6. **Global kill switch**: `darksoc_enabled = false` in settings immediately halts all automation

---

## Threat Intelligence Security

- API keys for VT, AbuseIPDB, OTX, Shodan in `.env` only
- Redis-cached results prevent leaking enrichment patterns via timing attacks
- OTX IOC feed stored in DB — no raw API credentials exposed to frontend
- Shodan queries go through langchain-agent backend — never direct from browser

---

## Incident Response for Platform Security

If SOCPilots itself is compromised:
1. Immediately disable Dark SOC: `POST /api/settings {darksoc_enabled: false}`
2. Rotate all API keys and secrets
3. `docker compose down` to stop all automation
4. Review `playbook_executions` for unauthorized automated actions
5. Review `investigation` table for abnormal activity
6. Regenerate `AUTH_SECRET_KEY` and `MCP_API_KEY` before restarting

---

*See also: `CLAUDE.md` Section 19, `docs/DEPLOYMENT.md`*
