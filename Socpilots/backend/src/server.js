// ============================================================
// SOC PILOTS — Production Backend
// OpenSearch (Wazuh) + SP-CM (direct) + n8n (AI/Hunt/Rules)
// ============================================================
const express   = require('express');
const http      = require('http');
const axios     = require('axios');
const https     = require('https');
const crypto    = require('crypto');
const path      = require('path');
const fs        = require('fs');
const bcrypt    = require('bcryptjs');
const multer    = require('multer');
const FormData  = require('form-data');
const { Server: IOServer } = require('socket.io');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });
const db       = require('./db');
const ueba     = require('./neo4j');
const playbook = require('./playbook-engine');
const email    = require('./email-service');

const app        = express();
const httpServer = http.createServer(app);
const io         = new IOServer(httpServer, { cors: { origin: false } });
const PORT       = process.env.PORT || 3000;
app.use(express.json({ limit: '10mb' }));

// ─── EVIDENCE FILE UPLOAD (multer) ─────────────────────────
const EVIDENCE_DIR = process.env.EVIDENCE_DIR || '/app/evidence';
if (!fs.existsSync(EVIDENCE_DIR)) {
  try { fs.mkdirSync(EVIDENCE_DIR, { recursive: true }); } catch(e) { /* volume may already exist */ }
}
const _evidenceStorage = multer.diskStorage({
  destination: EVIDENCE_DIR,
  filename: (req, file, cb) => {
    const uid = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase() || '';
    cb(null, `${Date.now()}_${uid}${ext}`);
  },
});
const _evidenceUpload = multer({
  storage: _evidenceStorage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.pdf','.xlsx','.xls','.csv','.txt','.log','.jpg','.jpeg','.png'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(Object.assign(new Error(`Unsupported file type: ${ext}`), { code: 'INVALID_FILE_TYPE' }));
  },
});

// ─── PERFORMANCE TRACKING ──────────────────────────────────
const routeLatencies = new Map();
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const key = `${req.method} ${req.route?.path || req.path}`;
    if (!routeLatencies.has(key)) routeLatencies.set(key, []);
    const arr = routeLatencies.get(key);
    arr.push(Date.now() - start);
    if (arr.length > 1000) arr.shift();
  });
  next();
});

// ─── CONFIG ────────────────────────────────────────────────
const OS_URL   = (process.env.OPENSEARCH_URL  || '').replace(/\/$/,'');
const OS_USER  = process.env.OPENSEARCH_USER  || 'admin';
const OS_PASS  = process.env.OPENSEARCH_PASS  || '';
const HIVE_URL = (process.env.THEHIVE_URL     || '').replace(/\/$/,'');
const HIVE_KEY = process.env.THEHIVE_API_KEY  || '';
const N8N_URL  = process.env.N8N_WEBHOOK_URL  || 'http://n8n:5678/webhook/socpilots';
const N8N_INV  = process.env.N8N_INVESTIGATION_URL || 'http://n8n:5678/webhook/socpilots-investigation';
const IDX          = process.env.WAZUH_INDEX      || 'wazuh-alerts-*';
const SCANNER_URL       = process.env.SCANNER_URL      || 'http://scanner:7777';
const LANGCHAIN_URL     = process.env.LANGCHAIN_URL    || 'http://langchain-agent:8001';
const RAG_URL           = process.env.RAG_URL          || 'http://rag-retrieval:5005';
const KNOWLEDGE_URL     = process.env.KNOWLEDGE_URL    || 'http://knowledge-ingestion:5004';
const LANGCHAIN_TOKEN   = process.env.LANGCHAIN_INTERNAL_TOKEN || '';
const MCP_WAZUH_URL     = process.env.MCP_WAZUH_URL    || 'http://mcp-wazuh:3001';
const OTX_API_KEY       = process.env.OTX_API_KEY      || '';

// Skip SSL verify (Wazuh self-signed cert)
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// ─── AUTH ──────────────────────────────────────────────────
// In-memory env users (backward compat): admin→admin, analyst→l2
const ENV_USERS = (process.env.SOC_USERS || '')
  .split(',').map(u => {
    const [username, password, role = 'analyst'] = u.trim().split(':');
    // Map legacy env roles to the new hierarchy
    const mappedRole = role === 'analyst' ? 'l2' : role;
    return { username, password, role: mappedRole };
  }).filter(u => u.username && u.password);

// Role hierarchy: admin > l3 > l2 > l1
const ROLE_HIERARCHY = { admin: 4, l3: 3, l2: 2, l1: 1 };

const sessions = new Map();
function mkToken(username, role, displayName) {
  const t = crypto.randomBytes(32).toString('hex');
  sessions.set(t, { username, role, displayName: displayName || username, exp: Date.now() + 8 * 3600 * 1000 });
  return t;
}
function authMW(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '').trim();
  // Static service-account token for internal services (LangChain agent, etc.)
  if (t && t === LANGCHAIN_TOKEN) {
    req.user = { username: 'langchain-service', role: 'l2', displayName: 'LangChain Agent', service: true };
    return next();
  }
  const s = sessions.get(t);
  if (!s || s.exp < Date.now()) { sessions.delete(t); return res.status(401).json({ error: 'Unauthorized' }); }
  req.user = s; next();
}

// Role-aware middleware factory
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const userLevel = ROLE_HIERARCHY[req.user.role] || 0;
    const required  = Math.max(...roles.map(r => ROLE_HIERARCHY[r] || 0));
    if (userLevel < required) return res.status(403).json({ error: 'Insufficient permissions' });
    next();
  };
}

// ── Socket.IO auth: require valid session token in handshake ──
io.use((socket, next) => {
  const token = (socket.handshake.auth?.token || '').trim();
  if (!token) return next(new Error('Authentication required'));
  const s = sessions.get(token);
  if (!s || s.exp < Date.now()) { sessions.delete(token); return next(new Error('Session expired')); }
  socket.user = s;
  next();
});

io.on('connection', socket => {
  console.log(`[WS] ${socket.user?.username} connected`);
  socket.on('disconnect', () => console.log(`[WS] ${socket.user?.username} disconnected`));
});

// ── Composite risk score: TI(40%) + UEBA(30%) + SIEM(20%) + Freq(10%) ──
async function computeCompositeRisk({ level = 0, severity = 'low', srcIp, agent, groupCount = 1 }) {
  const siemScore = Math.min(100, (level / 15) * 100);
  const freqScore = Math.min(100, (Math.log1p(groupCount) / Math.log1p(50)) * 100);
  const TI_MAP    = { critical: 100, high: 75, medium: 50, low: 25, unknown: 0 };
  const tiScore   = TI_MAP[severity] || 0;

  let uebaScore = 0;
  try {
    const candidates = [srcIp, agent].filter(e => e && e !== 'N/A' && e !== 'unknown');
    for (const entity of candidates) {
      const profile = await ueba.getUserProfile(entity).catch(() => null);
      if (profile?.risk_score > uebaScore) uebaScore = profile.risk_score;
    }
  } catch(e) { /* UEBA unavailable */ }

  return Math.round(Math.min(100, tiScore * 0.4 + uebaScore * 0.3 + siemScore * 0.2 + freqScore * 0.1));
}

// ── UEBA ↔ SIEM cross-correlation (runs async after investigation saved) ──
function _correlationType(alert, profile) {
  const flags = (profile.recent_logins || []).flatMap(l => l.flags || []);
  const groups = (alert.groups || '').toLowerCase();
  if (flags.includes('impossible_travel') && (groups.includes('vpn') || groups.includes('pam')))
    return 'compromised_credentials';
  if (flags.includes('lateral_movement') && (groups.includes('sshd') || groups.includes('authentication')))
    return 'lateral_movement_brute_force';
  if (flags.includes('privilege_escalation'))
    return 'privilege_escalation';
  if (flags.includes('after_hours'))
    return 'after_hours_activity';
  if (flags.includes('shared_credentials'))
    return 'shared_credentials';
  return 'behavioral_anomaly';
}

async function runUebaCorrelation(invId, alert) {
  try {
    const candidates = [alert.srcIp, alert.agent].filter(e => e && e !== 'N/A' && e !== 'unknown');
    for (const entity of candidates) {
      const profile = await ueba.getUserProfile(entity).catch(() => null);
      if (!profile) continue;
      const uebaRisk = profile.risk_score || 0;
      const uebaAnomalies = profile.anomaly_count || 0;
      if (uebaAnomalies === 0 && uebaRisk < 30) continue;

      const correlation = {
        investigation_id: invId,
        entity,
        entity_type:      profile.entity_type,
        ueba_risk:        uebaRisk,
        ueba_anomalies:   uebaAnomalies,
        siem_rule:        alert.ruleId,
        siem_severity:    alert.severity,
        mitre:            alert.mitre || [],
        mitre_tactic:     alert.mitreTactic || [],
        correlation_type: _correlationType(alert, profile),
        timestamp:        new Date().toISOString(),
      };

      io.emit('correlation:found', correlation);
      db.createNotification(
        'correlation',
        `UEBA Correlation: ${entity}`,
        `${entity} (risk ${uebaRisk}, ${uebaAnomalies} anomalies) matches ${alert.severity} SIEM alert — ${correlation.correlation_type.replace(/_/g,' ')}`,
        uebaRisk >= 70 ? 'critical' : 'warning',
        null,
        { investigation_id: invId, entity, ueba_risk: uebaRisk, correlation_type: correlation.correlation_type }
      ).catch(() => {});
    }
  } catch(e) { console.warn('[Correlation]', e.message); }
}

// Restrict to admin role (used for protected-asset management)
function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin role required' });
  next();
}

// ─── SEED DB USERS FROM SOC_USERS ENV ─────────────────────
async function seedUsersFromEnv() {
  try {
    for (const u of ENV_USERS) {
      const hash = bcrypt.hashSync(u.password, 10);
      await db.createUser(u.username, hash, u.role, u.username, null);
    }
    if (ENV_USERS.length > 0) {
      console.log(`[AUTH] Seeded ${ENV_USERS.length} user(s) from SOC_USERS env into DB`);
    }
  } catch(e) {
    console.warn('[AUTH] seedUsersFromEnv error:', e.message);
  }
}

// ─── OPENSEARCH HELPER ─────────────────────────────────────
async function osSearch(body, index = IDX, size = 200) {
  const r = await axios.post(`${OS_URL}/${index}/_search`, body, {
    auth: { username: OS_USER, password: OS_PASS },
    httpsAgent, timeout: 15000,
    headers: { 'Content-Type': 'application/json' },
  });
  return r.data;
}

async function osCount(body, index = IDX) {
  const r = await axios.post(`${OS_URL}/${index}/_count`, body, {
    auth: { username: OS_USER, password: OS_PASS },
    httpsAgent, timeout: 10000,
    headers: { 'Content-Type': 'application/json' },
  });
  return r.data.count || 0;
}

// ─── THEHIVE HELPER ────────────────────────────────────────
async function hiveQuery(queryArr, extra = {}) {
  const r = await axios.post(`${HIVE_URL}/api/v1/query`,
    { query: queryArr, ...extra },
    {
      headers: { Authorization: `Bearer ${HIVE_KEY}`, 'Content-Type': 'application/json' },
      httpsAgent, timeout: 15000,
    }
  );
  return r.data;
}

// ─── n8n HELPER — retry on 429 rate limit ──────────────────
async function n8nAsk(message, sessionId, user, extra = {}, _retry = 0) {
  const MAX_RETRIES = 2;
  try {
    const r = await axios.post(N8N_URL, {
      action: 'chat', message,
      session_id: sessionId || 'soc-session',
      _user: user?.username || 'system',
      _role: user?.role || 'analyst',
      ...extra,
    }, { timeout: 150000, headers: { 'Content-Type': 'application/json' }, validateStatus: () => true }); // 150s — n8n AI agent can take 2min+

    const d = r.data;
    const bodyStr = JSON.stringify(d || '');

    // 429 from n8n itself
    if (r.status === 429 && _retry < MAX_RETRIES) {
      const wait = (2 ** _retry) * 3000;
      console.warn(`[n8n] HTTP 429. Retry ${_retry+1}/${MAX_RETRIES} in ${wait}ms`);
      await new Promise(res => setTimeout(res, wait));
      return n8nAsk(message, sessionId, user, extra, _retry + 1);
    }

    // Mistral 429 in response body
    if ((bodyStr.includes('Rate limit') || bodyStr.includes('rate_limited') || bodyStr.includes('"code":"1300"')) && _retry < MAX_RETRIES) {
      const wait = (2 ** _retry) * 5000; // 5s, 10s for Mistral
      console.warn(`[n8n] Mistral rate limit in body. Retry ${_retry+1}/${MAX_RETRIES} in ${wait}ms`);
      await new Promise(res => setTimeout(res, wait));
      return n8nAsk(message, sessionId, user, extra, _retry + 1);
    }

    // After retries exhausted — return specific error
    if (bodyStr.includes('Rate limit') || bodyStr.includes('rate_limited')) {
      return { ok: false, error: 'Rate limit exceeded (429) — AI engine quota reached. Wait 60s and retry.', raw: d };
    }

    const text = d?.response || d?.output || d?.text || d?.message ||
      (Array.isArray(d) ? (d[0]?.response || d[0]?.output || '') : '') || '';
    return { ok: r.status < 500, text, raw: d };

  } catch(e) {
    const isTimeout = e.code === 'ECONNABORTED' || e.message.includes('timeout');
    const isRefused = e.code === 'ECONNREFUSED';
    const isNoHost  = e.code === 'ENOTFOUND' || e.code === 'EAI_AGAIN';
    let msg = e.message;
    if (isTimeout) msg = 'n8n_timeout'; // special code — handled by frontend
    if (isRefused) msg = 'n8n refused — check: docker ps, ensure n8n container is running';
    if (isNoHost)  msg = 'Cannot resolve n8n host — check N8N_WEBHOOK_URL in .env';
    return { ok: false, error: msg };
  }
}

// ─── SEVERITY HELPER ───────────────────────────────────────
function sevFromLevel(lvl) {
  const n = parseInt(lvl || 0);
  if (n >= 12) return 'critical';
  if (n >= 8)  return 'high';
  if (n >= 5)  return 'medium';
  return 'low';
}
function hiveSevLabel(n) {
  return { 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' }[n] || 'medium';
}
function hiveSevNum(s) {
  return { low: 1, medium: 2, high: 3, critical: 4 }[s] || 2;
}

// ─── ROUTES ────────────────────────────────────────────────

// STATIC — login served first, then SPA
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, '../../frontend/login.html')));

app.get('/health', (req, res) => res.json({
  status: 'ok',
  time: new Date().toISOString(),
  config: { opensearch: OS_URL, thehive: HIVE_URL, n8n: N8N_URL }
}));

// ── AUTH ──
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  const uname = (username || '').toLowerCase().trim();

  // 1. Try DB user first
  try {
    const dbUser = await db.getUserByUsername(uname);
    if (dbUser) {
      const valid = bcrypt.compareSync(password, dbUser.password_hash);
      if (!valid) {
        db.createSystemEvent('auth', uname, `Failed login attempt for user ${uname}`, 'fail', { ip: req.ip }).catch(() => {});
        return res.status(401).json({ error: 'Invalid username or password' });
      }
      await db.updateLastLogin(uname);
      const token = mkToken(dbUser.username, dbUser.role, dbUser.display_name);
      console.log(`[LOGIN] ${dbUser.username} (db, role=${dbUser.role})`);
      db.createSystemEvent('auth', dbUser.username, `User ${dbUser.username} logged in (role: ${dbUser.role})`, 'ok', { ip: req.ip }).catch(() => {});
      return res.json({ token, username: dbUser.username, role: dbUser.role, display_name: dbUser.display_name });
    }
  } catch(e) {
    console.warn('[LOGIN] DB lookup error:', e.message);
  }

  // 2. Fall back to env users (backward compat)
  const u = ENV_USERS.find(u =>
    u.username.toLowerCase() === uname && u.password === password
  );
  if (!u) {
    db.createSystemEvent('auth', uname, `Failed login attempt for user ${uname}`, 'fail', { ip: req.ip }).catch(() => {});
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const token = mkToken(u.username, u.role, u.username);
  console.log(`[LOGIN] ${u.username} (env, role=${u.role})`);
  db.createSystemEvent('auth', u.username, `User ${u.username} logged in (role: ${u.role})`, 'ok', { ip: req.ip }).catch(() => {});
  res.json({ token, username: u.username, role: u.role, display_name: u.username });
});

app.post('/api/logout', authMW, (req, res) => {
  sessions.delete((req.headers.authorization || '').replace('Bearer ', '').trim());
  db.createSystemEvent('auth', req.user.username, `User ${req.user.username} logged out`, 'ok').catch(() => {});
  res.json({ success: true });
});

app.get('/api/me', authMW, (req, res) => res.json({
  username: req.user.username,
  role: req.user.role,
  display_name: req.user.displayName || req.user.username,
}));

// ── STATUS / DIAGNOSTICS ──
app.get('/api/status', authMW, async (req, res) => {
  const results = {};

  // Test OpenSearch
  try {
    const start = Date.now();
    const r = await axios.get(`${OS_URL}/_cluster/health`, {
      auth: { username: OS_USER, password: OS_PASS },
      httpsAgent, timeout: 6000,
    });
    results.opensearch = { ok: true, latency: Date.now() - start, status: r.data.status };
  } catch (e) {
    results.opensearch = { ok: false, error: e.code || e.message };
  }

  // Test SP-CM
  try {
    const start = Date.now();
    await hiveQuery([{ _name: 'listCase' }, { _name: 'page', from: 0, to: 1 }]);
    results.thehive = { ok: true, latency: Date.now() - start };
  } catch (e) {
    results.thehive = { ok: false, error: e.message };
  }

  // Test n8n
  try {
    const start = Date.now();
    const r = await axios.post(N8N_URL,
      { action: 'chat', message: 'ping', session_id: 'health' },
      { timeout: 8000, validateStatus: () => true }
    );
    results.n8n = { ok: r.status < 500, latency: Date.now() - start };
  } catch (e) {
    results.n8n = { ok: false, error: e.code === 'ECONNABORTED' ? 'Timeout — open port 5678 on n8n server' : e.message };
  }

  results.config = {
    opensearch_url: OS_URL || '(not configured)',
    thehive_url:    HIVE_URL || '(not configured)',
    n8n_url:        N8N_URL,
  };
  res.json(results);
});

// ── DASHBOARD ─── OpenSearch aggregations ──
app.get('/api/dashboard', authMW, async (req, res) => {
  try {
    // Time range: hours preset OR absolute from/to
    const hours   = parseInt(req.query.hours) || 24;
    const fromTs  = req.query.from || null;
    const toTs    = req.query.to   || null;

    const tsRange = fromTs
      ? { gte: fromTs, ...(toTs ? { lte: toTs } : {}) }
      : { gte: `now-${hours}h` };

    // Pick histogram interval based on window size
    let calInterval = 'hour';
    if (fromTs && toTs) {
      const diffH = (new Date(toTs) - new Date(fromTs)) / 3600000;
      calInterval = diffH <= 48 ? 'hour' : diffH <= 336 ? '6h' : 'day';
    } else {
      calInterval = hours <= 48 ? 'hour' : hours <= 336 ? '6h' : 'day';
    }
    const boundsMin = fromTs || `now-${hours}h`;
    const boundsMax = toTs   || 'now';

    // Run 5 queries in parallel
    const [totalAlerts, critAlerts, periodAlerts, agentAgg, hiveCases] = await Promise.allSettled([
      // All-time total
      osCount({ query: { match_all: {} } }),
      // Critical in selected period
      osCount({ query: { bool: { must: [
        { range: { 'rule.level': { gte: 12 } } },
        { range: { '@timestamp': tsRange } },
      ]}}}),
      // Total in selected period
      osCount({ query: { range: { '@timestamp': tsRange } } }),
      // Unique agents + severity breakdown + timeline — all scoped to period
      osSearch({
        size: 0,
        aggs: {
          agents: { terms: { field: 'agent.name', size: 100 } },
          by_sev: { range: { field: 'rule.level',
            ranges: [
              { key: 'critical', from: 12 },
              { key: 'high',     from: 8,  to: 12 },
              { key: 'medium',   from: 5,  to: 8  },
              { key: 'low',      to: 5 },
            ]
          }},
          over_time: {
            date_histogram: { field: '@timestamp', calendar_interval: calInterval, min_doc_count: 0,
              extended_bounds: { min: boundsMin, max: boundsMax }
            },
            aggs: {
              critical: { filter: { range: { 'rule.level': { gte: 12 } } } },
              high:     { filter: { range: { 'rule.level': { gte: 8, lt: 12 } } } },
              medium:   { filter: { range: { 'rule.level': { gte: 5, lt: 8  } } } },
              low:      { filter: { range: { 'rule.level': { lt: 5 } } } },
            }
          }
        },
        query: { range: { '@timestamp': tsRange } }
      }),
      // SP-CM open cases
      hiveQuery([
        { _name: 'listCase' },
        { _name: 'filter', _field: 'status', _value: 'New' }
      ]).catch(() => null),
    ]);

    const aggs    = agentAgg.value?.aggregations;
    const sevBkts = aggs?.by_sev?.buckets || [];
    const getSev  = key => sevBkts.find(b => b.key === key)?.doc_count || 0;
    const timeline = (aggs?.over_time?.buckets || []).map(b => ({
      time:     b.key_as_string || new Date(b.key).toISOString(),
      count:    b.doc_count,
      critical: b.critical?.doc_count || 0,
      high:     b.high?.doc_count     || 0,
      medium:   b.medium?.doc_count   || 0,
      low:      b.low?.doc_count      || 0,
    }));
    const agentCount = aggs?.agents?.buckets?.length || 0;

    res.json({
      totalAlerts:    totalAlerts.value   || 0,
      alerts24h:      periodAlerts.value  || 0,   // "period" alerts — label updated on frontend
      criticalAlerts: critAlerts.value    || 0,
      highAlerts:     getSev('high'),
      mediumAlerts:   getSev('medium'),
      lowAlerts:      getSev('low'),
      totalAgents:    agentCount,
      openCases:      Array.isArray(hiveCases.value) ? hiveCases.value.length : 0,
      timeline,
      sevBreakdown: {
        critical: critAlerts.value || 0,
        high:     getSev('high'),
        medium:   getSev('medium'),
        low:      getSev('low'),
      },
      periodLabel: fromTs
        ? `${new Date(fromTs).toLocaleDateString()} – ${toTs ? new Date(toTs).toLocaleDateString() : 'now'}`
        : `Last ${hours >= 720 ? Math.round(hours/720)+'mo' : hours >= 168 ? Math.round(hours/168)+'w' : hours >= 24 ? Math.round(hours/24)+'d' : hours+'h'}`,
    });
  } catch (e) {
    console.error('[dashboard]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── ALERTS ── OpenSearch ──
app.get('/api/alerts', authMW, async (req, res) => {
  try {
    const page      = Math.max(parseInt(req.query.page) || 1, 1);
    const page_size = Math.min(parseInt(req.query.page_size) || parseInt(req.query.limit) || 50, 500);
    const sev    = req.query.severity;
    const search = req.query.q;
    const hours  = parseInt(req.query.hours) || 0;
    const fromTs = req.query.from || null;
    const toTs   = req.query.to   || null;
    const agent  = req.query.agent;
    const srcip  = req.query.srcip;

    const from = (page - 1) * page_size;
    // OpenSearch hard limit is 10000 hits; cap gracefully
    const cappedFrom = Math.min(from, 9500);
    const cappedSize = Math.min(page_size, 10000 - cappedFrom);

    const must = [];
    if (fromTs || toTs) {
      const r = {};
      if (fromTs) r.gte = fromTs;
      if (toTs)   r.lte = toTs;
      must.push({ range: { '@timestamp': r } });
    } else if (hours) {
      must.push({ range: { '@timestamp': { gte: `now-${hours}h` } } });
    }
    if (agent)  must.push({ term: { 'agent.name': agent } });
    if (srcip)  must.push({ term: { 'data.srcip': srcip } });
    if (sev) {
      const ranges = { critical: { gte: 12 }, high: { gte: 8, lt: 12 }, medium: { gte: 5, lt: 8 }, low: { lt: 5 } };
      if (ranges[sev]) must.push({ range: { 'rule.level': ranges[sev] } });
    }
    if (search) must.push({ multi_match: { query: search, fields: ['rule.description', 'full_log', 'agent.name', 'data.srcip'] } });

    const body = {
      from: cappedFrom,
      size: cappedSize,
      track_total_hits: true,
      sort: [{ '@timestamp': 'desc' }],
      query: must.length ? { bool: { must } } : { match_all: {} },
      _source: ['@timestamp', 'rule', 'agent', 'data', 'srcip', 'full_log', 'location', 'manager'],
    };

    const r = await osSearch(body);
    const total = typeof r.hits.total === 'object' ? r.hits.total.value : (r.hits.total || 0);
    const alerts = r.hits.hits.map(h => {
      const s = h._source;
      return {
        id:          h._id,
        timestamp:   s['@timestamp'],
        ruleId:      s.rule?.id || 'N/A',
        level:       s.rule?.level || 0,
        severity:    sevFromLevel(s.rule?.level),
        description: s.rule?.description || 'N/A',
        agent:       s.agent?.name || s.agent?.id || 'unknown',
        agentId:     s.agent?.id || '',
        agentIp:     s.agent?.ip || 'N/A',
        srcIp:       s.data?.srcip || s.srcip || 'N/A',
        dstUser:     s.data?.dstuser || '',
        groups:      (s.rule?.groups || []).join(', '),
        mitre:       s.rule?.mitre?.id || [],
        mitreTactic: s.rule?.mitre?.tactic || [],
        technique:   s.rule?.mitre?.technique || [],
        fullLog:     s.full_log || '',
        location:    s.location || '',
      };
    });
    res.json({ alerts, total, page, page_size, has_more: page * page_size < total });
  } catch (e) {
    console.error('[alerts]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── AGENTS ── from OpenSearch unique agents ──
app.get('/api/agents', authMW, async (req, res) => {
  try {
    const r = await osSearch({
      size: 0,
      aggs: {
        agents: {
          terms: { field: 'agent.name', size: 500 },
          aggs: {
            id:       { terms: { field: 'agent.id', size: 1 } },
            ip:       { terms: { field: 'agent.ip', size: 1 } },
            last:     { max: { field: '@timestamp' } },
            count:    { value_count: { field: '_id' } },
            // Active = seen in last 2 hours (covers agents with less frequent alerts)
            recent2h: { filter: { range: { '@timestamp': { gte: 'now-2h' } } } },
            // Truly active = seen in last 15 min
            recent15m: { filter: { range: { '@timestamp': { gte: 'now-15m' } } } },
          },
        },
      },
    });

    const now = Date.now();
    // Exclude the wazuh manager itself from agent list
    const EXCLUDE = new Set(['wazuh.manager','wazuh-manager','manager']);
    const agents = r.aggregations.agents.buckets
      .filter(b => !EXCLUDE.has((b.key||'').toLowerCase()))
      .map(b => {
        const lastMs   = b.last?.value || 0;
        const diffMs   = lastMs > 0 ? now - lastMs : Infinity;
        const diffHrs  = diffMs / 3600000;
        // Active   = seen in last 24h (matches Wazuh's own definition)
        // Inactive = seen but > 24h ago
        // Disconnected = never seen (no alerts at all)
        const status = lastMs === 0 ? 'disconnected'
                     : diffHrs < 24 ? 'active'
                     : 'inactive';
        return {
          name:       b.key,
          id:         b.id?.buckets?.[0]?.key || 'N/A',
          ip:         b.ip?.buckets?.[0]?.key || 'N/A',
          status,
          lastSeen:   lastMs > 0 ? new Date(lastMs).toISOString() : 'N/A',
          alertCount: b.doc_count,
          diffHrs:    Math.round(diffHrs * 10) / 10,
        };
      }).sort((a, b) => b.alertCount - a.alertCount);

    res.json({ agents, total: agents.length });
  } catch (e) {
    console.error('[agents]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── RULES ── unique rules from OpenSearch ──
let _rulesCache = null, _rulesCacheTime = 0;
app.get('/api/rules', authMW, async (req, res) => {
  try {
    const now = Date.now();
    if (_rulesCache && now - _rulesCacheTime < 60000) return res.json(_rulesCache);
    const r = await osSearch({
      size: 0,
      aggs: {
        rules: {
          terms: { field: 'rule.id', size: 2000, order: { _count: 'desc' } },
          aggs: {
            desc:       { terms: { field: 'rule.description', size: 1 } },
            max_level:  { max: { field: 'rule.level' } },
            groups:     { terms: { field: 'rule.groups', size: 10 } },
            mitre:      { terms: { field: 'rule.mitre.id', size: 5 } },
            decoder:    { terms: { field: 'rule.decoder.name', size: 1 } },
            first_seen: { min: { field: '@timestamp' } },
            last_seen:  { max: { field: '@timestamp' } },
          },
        },
      },
    });

    const rules = r.aggregations.rules.buckets.map(b => ({
      id:          b.key,
      level:       Math.round(b.max_level?.value || 0),
      description: b.desc?.buckets?.[0]?.key || 'N/A',
      severity:    sevFromLevel(b.max_level?.value),
      groups:      b.groups?.buckets?.map(g => g.key) || [],
      mitre:       b.mitre?.buckets?.map(m => m.key) || [],
      decoder:     b.decoder?.buckets?.[0]?.key || '',
      first_seen:  b.first_seen?.value || null,
      last_seen:   b.last_seen?.value || null,
      count:       b.doc_count,
    }));

    const result = { rules, total: rules.length };
    _rulesCache = result;
    _rulesCacheTime = now;
    res.json(result);
  } catch (e) {
    console.error('[rules]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── VULNERABILITIES ── via n8n (Wazuh MCP) ──
// ── STATS for dashboard charts ──

// ── DIRECT RULE DEPLOYMENT (bypasses AI) ─────────────────
// Deploys custom rule directly via Wazuh API to local_rules.xml
app.post('/api/rules/deploy-custom', authMW, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'analyst') {
    return res.status(403).json({ error: 'analyst or admin role required' });
  }

  const { name, level, group, description, pattern, mitre, freq, action, context } = req.body;
  if (!name || !description || !pattern) {
    return res.status(400).json({ error: 'name, description, pattern required' });
  }

  // Generate next available custom rule ID (200000-298999)
  const ruleId = 200000 + Math.floor(Math.random() * 99000);

  // Build rule XML
  const safeDesc = String(description).replace(/[<>&]/g, '');
  const safePattern = String(pattern).replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
  const safeName = String(name).replace(/[<>&]/g, '');
  const grp = group || 'custom';

  const ruleXml = `<group name="${grp},custom,">
  <rule id="${ruleId}" level="${level || 5}">
    <description>${safeDesc}</description>
    <match>${safePattern}</match>
    ${mitre ? `<mitre><id>${mitre}</id></mitre>` : ''}
  </rule>
</group>`;

  // Use n8n MCP-Wazuh tool via the AI agent
  const deployPrompt = `Deploy this custom Wazuh rule using the Wazuh MCP tool add_wazuh_rule.

Call add_wazuh_rule with exactly these parameters:
- rule_content: the XML below (complete, do not modify)
- rule_filename: "custom_rules.xml"
- overwrite: true

RULE XML:
\`\`\`xml
${ruleXml}
\`\`\`

Return ONLY a JSON object:
{"success": true/false, "ruleId": ${ruleId}, "message": "...", "verified": true/false}`;

  try {
    const r = await n8nAsk(deployPrompt, `rule-deploy-${ruleId}`, req.user);
    if (!r.ok) {
      return res.status(502).json({ error: r.error || 'AI agent unavailable', ruleId });
    }

    // Try to extract JSON from response
    let result = { success: false, ruleId, message: r.text };
    try {
      const jsonMatch = r.text.match(/\{[\s\S]*?\}/);
      if (jsonMatch) {
        result = { ...result, ...JSON.parse(jsonMatch[0]) };
      }
    } catch(e) {}

    res.json({ ...result, ruleXml, fullResponse: r.text });
  } catch(e) {
    res.status(502).json({ error: e.message, ruleId });
  }
});


app.get('/api/stats/top-agents', authMW, async (req, res) => {
  try {
    const r = await osSearch({
      size: 0,
      query: { range: { '@timestamp': { gte: 'now-24h' } } },
      aggs: { top: { terms: { field: 'agent.name', size: 10 } } },
    });
    const data = r.aggregations.top.buckets.map(b => ({ name: b.key, count: b.doc_count }));
    res.json(data);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.get('/api/stats/top-rules', authMW, async (req, res) => {
  try {
    const r = await osSearch({
      size: 0,
      query: { range: { '@timestamp': { gte: 'now-24h' } } },
      aggs: { top: { terms: { field: 'rule.id', size: 10 }, aggs: { desc: { terms: { field: 'rule.description', size: 1 } }, level: { max: { field: 'rule.level' } } } } },
    });
    const data = r.aggregations.top.buckets.map(b => ({
      id: b.key, count: b.doc_count,
      desc: b.desc?.buckets?.[0]?.key || b.key,
      level: Math.round(b.level?.value || 0),
      severity: sevFromLevel(b.level?.value),
    }));
    res.json(data);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.get('/api/stats/top-ips', authMW, async (req, res) => {
  try {
    const r = await osSearch({
      size: 0,
      query: { range: { '@timestamp': { gte: 'now-24h' } } },
      aggs: { top: { terms: { field: 'data.srcip', size: 10 } } },
    });
    const data = r.aggregations.top.buckets
      .filter(b => b.key && b.key !== 'N/A' && !b.key.startsWith('127.') && !b.key.startsWith('::'))
      .map(b => ({ ip: b.key, count: b.doc_count }));
    res.json(data);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.get('/api/stats/mitre', authMW, async (req, res) => {
  try {
    const r = await osSearch({
      size: 0,
      query: { bool: { must: [{ range: { '@timestamp': { gte: 'now-24h' } } }, { exists: { field: 'rule.mitre.id' } }] } },
      aggs: {
        tactics:    { terms: { field: 'rule.mitre.tactic', size: 10 } },
        techniques: { terms: { field: 'rule.mitre.id', size: 15 } },
      },
    });
    res.json({
      tactics:    r.aggregations.tactics?.buckets?.map(b => ({ name: b.key, count: b.doc_count })) || [],
      techniques: r.aggregations.techniques?.buckets?.map(b => ({ id: b.key, count: b.doc_count })) || [],
    });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// ── MITRE ATT&CK COVERAGE ──
let _mitreCovCache = null, _mitreCovCacheTime = 0, _mitreCovCacheTf = '';
let _mitreAutoAnalysis = null;

// KEEP IN SYNC WITH Socpilots/frontend/index.html MITRE_TACTICS and MITRE_TECHS
const _MITRE_TACTICS_MAP = {
  TA0043:'reconnaissance',TA0042:'resource_development',TA0001:'initial_access',
  TA0002:'execution',TA0003:'persistence',TA0004:'privilege_escalation',
  TA0005:'defense_evasion',TA0006:'credential_access',TA0007:'discovery',
  TA0008:'lateral_movement',TA0009:'collection',TA0010:'exfiltration',
  TA0011:'command_and_control',TA0040:'impact',
};
const _MITRE_TECHS_LIST = [
  ['T1595','Active Scanning',['TA0043']],['T1592','Gather Victim Host Info',['TA0043']],
  ['T1589','Gather Victim Identity Info',['TA0043']],['T1590','Gather Victim Network Info',['TA0043']],
  ['T1591','Gather Victim Org Info',['TA0043']],['T1598','Phishing for Info',['TA0043']],
  ['T1597','Search Closed Sources',['TA0043']],['T1596','Search Open Tech Databases',['TA0043']],
  ['T1593','Search Open Websites',['TA0043']],['T1594','Search Victim Website',['TA0043']],
  ['T1583','Acquire Infrastructure',['TA0042']],['T1584','Compromise Infrastructure',['TA0042']],
  ['T1586','Compromise Accounts',['TA0042']],['T1587','Develop Capabilities',['TA0042']],
  ['T1588','Obtain Capabilities',['TA0042']],['T1585','Establish Accounts',['TA0042']],
  ['T1608','Stage Capabilities',['TA0042']],
  ['T1189','Drive-by Compromise',['TA0001']],['T1190','Exploit Public-Facing App',['TA0001']],
  ['T1133','External Remote Services',['TA0001','TA0003']],['T1200','Hardware Additions',['TA0001']],
  ['T1566','Phishing',['TA0001']],['T1091','Replication via Removable Media',['TA0001','TA0008']],
  ['T1195','Supply Chain Compromise',['TA0001']],['T1199','Trusted Relationship',['TA0001']],
  ['T1078','Valid Accounts',['TA0001','TA0003','TA0004','TA0005']],['T1659','Content Injection',['TA0001']],
  ['T1059','Command and Scripting Interpreter',['TA0002']],['T1203','Exploitation for Client Execution',['TA0002']],
  ['T1559','Inter-Process Communication',['TA0002']],['T1106','Native API',['TA0002']],
  ['T1053','Scheduled Task/Job',['TA0002','TA0003','TA0004']],['T1129','Shared Modules',['TA0002']],
  ['T1569','System Services',['TA0002','TA0003']],['T1204','User Execution',['TA0002']],
  ['T1047','Windows Management Instrumentation',['TA0002']],['T1072','Software Deployment Tools',['TA0002','TA0008']],
  ['T1098','Account Manipulation',['TA0003','TA0004']],['T1197','BITS Jobs',['TA0003','TA0005']],
  ['T1547','Boot or Logon Autostart',['TA0003','TA0004']],['T1176','Browser Extensions',['TA0003']],
  ['T1554','Compromise Host Software Binary',['TA0003']],['T1136','Create Account',['TA0003']],
  ['T1543','Create or Modify System Process',['TA0003','TA0004']],['T1546','Event Triggered Execution',['TA0003','TA0004']],
  ['T1574','Hijack Execution Flow',['TA0003','TA0004','TA0005']],['T1137','Office Application Startup',['TA0003']],
  ['T1542','Pre-OS Boot',['TA0003','TA0005']],['T1505','Server Software Component',['TA0003']],
  ['T1548','Abuse Elevation Control Mechanism',['TA0004','TA0005']],['T1134','Access Token Manipulation',['TA0004','TA0005']],
  ['T1484','Domain or Tenant Policy Modification',['TA0004','TA0005']],['T1068','Exploitation for Privilege Escalation',['TA0004']],
  ['T1055','Process Injection',['TA0004','TA0005']],['T1611','Escape to Host',['TA0004']],
  ['T1140','Deobfuscate/Decode Files',['TA0005']],['T1006','Direct Volume Access',['TA0005']],
  ['T1480','Execution Guardrails',['TA0005']],['T1211','Exploitation for Defense Evasion',['TA0005']],
  ['T1222','File and Directory Permissions Mod',['TA0005']],['T1564','Hide Artifacts',['TA0005']],
  ['T1562','Impair Defenses',['TA0005']],['T1070','Indicator Removal',['TA0005']],
  ['T1202','Indirect Command Execution',['TA0005']],['T1036','Masquerading',['TA0005']],
  ['T1112','Modify Registry',['TA0005']],['T1027','Obfuscated Files or Information',['TA0005']],
  ['T1647','Plist File Modification',['TA0005']],['T1620','Reflective Code Loading',['TA0005']],
  ['T1553','Subvert Trust Controls',['TA0005']],['T1218','System Binary Proxy Execution',['TA0005']],
  ['T1216','System Script Proxy Execution',['TA0005']],['T1127','Trusted Developer Utilities Proxy',['TA0005']],
  ['T1535','Unused/Unsupported Cloud Regions',['TA0005']],['T1497','Virtualization/Sandbox Evasion',['TA0005']],
  ['T1600','Weaken Encryption',['TA0005']],
  ['T1557','Adversary-in-the-Middle',['TA0006','TA0009']],['T1110','Brute Force',['TA0006']],
  ['T1555','Credentials from Password Stores',['TA0006']],['T1212','Exploitation for Credential Access',['TA0006']],
  ['T1187','Forced Authentication',['TA0006']],['T1606','Forge Web Credentials',['TA0006']],
  ['T1056','Input Capture',['TA0006','TA0009']],['T1040','Network Sniffing',['TA0006','TA0007']],
  ['T1003','OS Credential Dumping',['TA0006']],['T1528','Steal Application Access Token',['TA0006']],
  ['T1558','Steal or Forge Kerberos Tickets',['TA0006']],['T1539','Steal Web Session Cookie',['TA0006']],
  ['T1552','Unsecured Credentials',['TA0006']],
  ['T1087','Account Discovery',['TA0007']],['T1010','Application Window Discovery',['TA0007']],
  ['T1217','Browser Information Discovery',['TA0007']],['T1580','Cloud Infrastructure Discovery',['TA0007']],
  ['T1538','Cloud Service Dashboard',['TA0007']],['T1526','Cloud Service Discovery',['TA0007']],
  ['T1613','Container and Resource Discovery',['TA0007']],['T1622','Debugger Evasion',['TA0007']],
  ['T1482','Domain Trust Discovery',['TA0007']],['T1083','File and Directory Discovery',['TA0007']],
  ['T1615','Group Policy Discovery',['TA0007']],['T1046','Network Service Discovery',['TA0007']],
  ['T1135','Network Share Discovery',['TA0007']],['T1201','Password Policy Discovery',['TA0007']],
  ['T1120','Peripheral Device Discovery',['TA0007']],['T1069','Permission Groups Discovery',['TA0007']],
  ['T1057','Process Discovery',['TA0007']],['T1012','Query Registry',['TA0007']],
  ['T1018','Remote System Discovery',['TA0007']],['T1518','Software Discovery',['TA0007']],
  ['T1082','System Information Discovery',['TA0007']],['T1016','System Network Configuration Discovery',['TA0007']],
  ['T1049','System Network Connections Discovery',['TA0007']],['T1033','System Owner/User Discovery',['TA0007']],
  ['T1007','System Service Discovery',['TA0007']],['T1124','System Time Discovery',['TA0007']],
  ['T1210','Exploitation of Remote Services',['TA0008']],['T1534','Internal Spearphishing',['TA0008']],
  ['T1570','Lateral Tool Transfer',['TA0008']],['T1563','Remote Service Session Hijacking',['TA0008']],
  ['T1021','Remote Services',['TA0008']],['T1080','Taint Shared Content',['TA0008']],
  ['T1550','Use Alternate Authentication Material',['TA0005','TA0008']],
  ['T1560','Archive Collected Data',['TA0009']],['T1123','Audio Capture',['TA0009']],
  ['T1119','Automated Collection',['TA0009']],['T1185','Browser Session Hijacking',['TA0009']],
  ['T1115','Clipboard Data',['TA0009']],['T1530','Data from Cloud Storage',['TA0009']],
  ['T1213','Data from Information Repositories',['TA0009']],['T1005','Data from Local System',['TA0009']],
  ['T1039','Data from Network Shared Drive',['TA0009']],['T1025','Data from Removable Media',['TA0009']],
  ['T1074','Data Staged',['TA0009']],['T1114','Email Collection',['TA0009']],
  ['T1602','Data from Configuration Repository',['TA0009']],['T1113','Screen Capture',['TA0009']],
  ['T1125','Video Capture',['TA0009']],
  ['T1020','Automated Exfiltration',['TA0010']],['T1030','Data Transfer Size Limits',['TA0010']],
  ['T1048','Exfiltration Over Alt Protocol',['TA0010']],['T1041','Exfiltration Over C2 Channel',['TA0010']],
  ['T1011','Exfiltration Over Other Network',['TA0010']],['T1052','Exfiltration Over Physical Medium',['TA0010']],
  ['T1567','Exfiltration Over Web Service',['TA0010']],['T1537','Transfer Data to Cloud Account',['TA0010']],
  ['T1029','Scheduled Transfer',['TA0010']],
  ['T1071','Application Layer Protocol',['TA0011']],['T1092','Communication via Removable Media',['TA0011']],
  ['T1132','Data Encoding',['TA0011']],['T1001','Data Obfuscation',['TA0011']],
  ['T1568','Dynamic Resolution',['TA0011']],['T1573','Encrypted Channel',['TA0011']],
  ['T1008','Fallback Channels',['TA0011']],['T1105','Ingress Tool Transfer',['TA0011']],
  ['T1104','Multi-Stage Channels',['TA0011']],['T1095','Non-Application Layer Protocol',['TA0011']],
  ['T1571','Non-Standard Port',['TA0011']],['T1572','Protocol Tunneling',['TA0011']],
  ['T1090','Proxy',['TA0011']],['T1219','Remote Access Software',['TA0011']],
  ['T1205','Traffic Signaling',['TA0011','TA0003']],['T1102','Web Service',['TA0011']],
  ['T1531','Account Access Removal',['TA0040']],['T1485','Data Destruction',['TA0040']],
  ['T1486','Data Encrypted for Impact',['TA0040']],['T1565','Data Manipulation',['TA0040']],
  ['T1491','Defacement',['TA0040']],['T1561','Disk Wipe',['TA0040']],
  ['T1499','Endpoint Denial of Service',['TA0040']],['T1495','Firmware Corruption',['TA0040']],
  ['T1490','Inhibit System Recovery',['TA0040']],['T1498','Network Denial of Service',['TA0040']],
  ['T1496','Resource Hijacking',['TA0040']],['T1489','Service Stop',['TA0040']],
  ['T1529','System Shutdown/Reboot',['TA0040']],['T1657','Financial Theft',['TA0040']],
];

async function _runMitreAnalysis(payload) {
  const LANGCHAIN_URL = process.env.LANGCHAIN_URL || 'http://langchain-agent:8001';
  const r = await fetch(`${LANGCHAIN_URL}/mitre/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.LANGCHAIN_INTERNAL_TOKEN || ''}` },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(90000),
  });
  if (!r.ok) throw new Error(`AI service error: ${(await r.text()).slice(0, 200)}`);
  return r.json();
}

function _mitreCoverageScore(docCount, ruleCount, agentCount, lastSeenMs) {
  const alertScore = Math.min(1, (docCount  || 0) / 100);
  const ruleScore  = Math.min(1, (ruleCount || 0) / 5);
  const agentScore = Math.min(1, (agentCount|| 0) / 3);
  let recency = 0;
  if (lastSeenMs) {
    const age = Date.now() - lastSeenMs;
    if      (age < 86400000)    recency = 1.0;
    else if (age < 604800000)   recency = 0.7;
    else if (age < 2592000000)  recency = 0.4;
    else                        recency = 0.2;
  }
  return Math.round(((alertScore + ruleScore + agentScore + recency) / 4) * 100);
}

app.get('/api/mitre/coverage', authMW, async (req, res) => {
  try {
    const tf = (['24h','7d','30d','90d'].includes(req.query.timeframe) ? req.query.timeframe : '7d');
    const now = Date.now();
    if (_mitreCovCache && tf === _mitreCovCacheTf && now - _mitreCovCacheTime < 30000) return res.json(_mitreCovCache);
    const r = await osSearch({
      size: 0,
      query: { bool: { must: [
        { range: { '@timestamp': { gte: `now-${tf}` } } },
        { exists: { field: 'rule.mitre.id' } },
      ]}},
      aggs: {
        techniques: {
          terms: { field: 'rule.mitre.id', size: 500 },
          aggs: {
            rules:     { terms: { field: 'rule.id',           size: 20 } },
            agents:    { terms: { field: 'agent.name',        size: 20 } },
            tactics:   { terms: { field: 'rule.mitre.tactic', size:  5 } },
            decoders:  { terms: { field: 'decoder.name',      size: 10 } },
            max_level: { max:   { field: 'rule.level' } },
            last_seen: { max:   { field: '@timestamp' } },
          },
        },
        top_agents: { terms: { field: 'agent.name', size: 20 } },
      },
    });
    const coverage = {};
    for (const b of (r.aggregations?.techniques?.buckets || [])) {
      const ruleList    = b.rules?.buckets?.map(x => x.key)    || [];
      const agentList   = b.agents?.buckets?.map(x => x.key)   || [];
      const decoderList = b.decoders?.buckets?.map(x => x.key) || [];
      coverage[b.key] = {
        count:          b.doc_count,
        max_level:      Math.round(b.max_level?.value || 0),
        rules:          ruleList,
        agents:         agentList,
        decoders:       decoderList,
        tactics:        b.tactics?.buckets?.map(x => x.key) || [],
        last_seen:      b.last_seen?.value || null,
        coverage_score: _mitreCoverageScore(b.doc_count, ruleList.length, agentList.length, b.last_seen?.value),
        log_source_diversity: decoderList.length,
      };
    }
    const allAgents = (r.aggregations?.top_agents?.buckets || []).map(b => b.key);
    const result = { coverage, timeframe: tf, all_agents: allAgents };
    _mitreCovCache = result; _mitreCovCacheTime = now; _mitreCovCacheTf = tf;
    res.json(result);
  } catch (e) { console.error('[mitre/coverage]', e.message); res.status(502).json({ error: e.message }); }
});

app.post('/api/mitre/analyze', authMW, async (req, res) => {
  try {
    const { covered, gaps, log_sources, agents, summary } = req.body;
    if (!covered || !gaps) return res.status(400).json({ error: 'covered and gaps arrays required' });

    // Sanitize — send only IDs, names, counts and log source types; no raw alert data
    const payload = {
      covered_techniques: (covered || []).slice(0, 100).map(t => ({
        id: String(t.id || '').replace(/[^A-Z0-9.]/gi, ''),
        name: String(t.name || '').slice(0, 80),
        count: Number(t.count) || 0,
        score: Number(t.score) || 0,
        rule_count: Number(t.rule_count) || 0,
        tactics: Array.isArray(t.tactics) ? t.tactics.slice(0, 3) : [],
      })),
      gap_techniques: (gaps || []).slice(0, 150).map(t => ({
        id: String(t.id || '').replace(/[^A-Z0-9.]/gi, ''),
        name: String(t.name || '').slice(0, 80),
        tactics: Array.isArray(t.tactics) ? t.tactics.slice(0, 3) : [],
      })),
      log_sources:  (log_sources || []).slice(0, 10).map(s => String(s).slice(0, 50)),
      agents:       (agents     || []).slice(0, 20).map(a => String(a).slice(0, 50)),
      summary: {
        total_techniques: Number(summary?.total_techniques) || 0,
        covered_count:    Number(summary?.covered_count)    || 0,
        gap_count:        Number(summary?.gap_count)        || 0,
        coverage_pct:     Number(summary?.coverage_pct)     || 0,
      },
    };

    const result = await _runMitreAnalysis(payload);
    _mitreAutoAnalysis = { result, last_analyzed_at: Date.now(), source: 'manual', timeframe: _mitreCovCacheTf || '7d' };
    res.json(result);
  } catch (e) {
    console.error('[mitre/analyze]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/mitre/analysis', authMW, (req, res) => {
  if (!_mitreAutoAnalysis) return res.json({ available: false });
  res.json({ available: true, ..._mitreAutoAnalysis });
});

app.get('/api/mitre/technique/:id', authMW, async (req, res) => {
  try {
    const techId = req.params.id.toUpperCase().replace(/[^A-Z0-9.]/g, '');
    const tf = (['24h','7d','30d','90d'].includes(req.query.timeframe) ? req.query.timeframe : '7d');
    const r = await osSearch({
      size: 20,
      query: { bool: { must: [
        { range: { '@timestamp': { gte: `now-${tf}` } } },
        { term: { 'rule.mitre.id': techId } },
      ]}},
      sort: [{ '@timestamp': { order: 'desc' } }],
      aggs: {
        rules:    { terms: { field: 'rule.id', size: 20 }, aggs: {
          desc:  { terms: { field: 'rule.description', size: 1 } },
          level: { max:   { field: 'rule.level' } },
        }},
        agents:   { terms: { field: 'agent.name',        size: 20 } },
        decoders: { terms: { field: 'rule.decoder.name', size: 10 } },
        tactics:  { terms: { field: 'rule.mitre.tactic', size:  5 } },
        timeline: { date_histogram: { field: '@timestamp', calendar_interval: 'day' } },
      },
    });
    res.json({
      technique:     techId,
      timeframe:     tf,
      total:         r.hits?.total?.value || 0,
      recent_alerts: (r.hits?.hits || []).map(h => ({
        id:          h._id,
        timestamp:   h._source['@timestamp'],
        agent:       h._source.agent?.name || 'unknown',
        rule:        h._source.rule?.id,
        description: h._source.rule?.description,
        level:       h._source.rule?.level,
      })),
      rules:    (r.aggregations?.rules?.buckets    || []).map(b => ({ id: b.key, description: b.desc?.buckets?.[0]?.key || 'N/A', count: b.doc_count, level: Math.round(b.level?.value || 0) })),
      agents:   (r.aggregations?.agents?.buckets   || []).map(b => ({ name: b.key, count: b.doc_count })),
      decoders: (r.aggregations?.decoders?.buckets || []).map(b => b.key),
      tactics:  (r.aggregations?.tactics?.buckets  || []).map(b => b.key),
      timeline: (r.aggregations?.timeline?.buckets || []).map(b => ({ date: b.key_as_string?.slice(0,10), count: b.doc_count })),
    });
  } catch (e) { console.error('[mitre/technique]', e.message); res.status(502).json({ error: e.message }); }
});

// ── THEHIVE CASES ──
const CASE_CLOSED_STATUSES = new Set([
  'TruePositive','FalsePositive','Duplicate','Other','Indeterminate','Resolved',
  'True Positive','False Positive',
]);
const CASE_STATUS_LABELS = {
  'New':'New','InProgress':'In Progress','Resolved':'Resolved',
  'TruePositive':'True Positive','FalsePositive':'False Positive',
  'Duplicate':'Duplicate','Other':'Other','Indeterminate':'Indeterminate',
};

function mapCase(c) {
  const rawStatus  = c.status || 'New';
  return {
    id:          c._id,
    number:      c.number,
    title:       c.title,
    status:      rawStatus,
    statusLabel: CASE_STATUS_LABELS[rawStatus] || rawStatus,
    isClosed:    CASE_CLOSED_STATUSES.has(rawStatus),
    isInProgress: rawStatus === 'InProgress' || rawStatus === 'In Progress',
    severity:    c.severityLabel || hiveSevLabel(c.severity),
    severityNum: c.severity,
    assignee:    c.assignee,
    tags:        c.tags || [],
    tlp:         c.tlpLabel || 'AMBER',
    created:     c._createdAt,
    startDate:   c.startDate,
    description: c.description,
    mitre:       (c.tags || []).filter(t => t.startsWith('rule=')).map(t => t.replace('rule=', '')),
  };
}

// ── CASE STATS (30s in-memory cache) ──
let _hiveCaseStatsCache = null, _hiveCaseStatsCacheTime = 0;
app.get('/api/cases/stats', authMW, async (req, res) => {
  try {
    const now = Date.now();
    if (_hiveCaseStatsCache && now - _hiveCaseStatsCacheTime < 30000) return res.json(_hiveCaseStatsCache);
    const cnt = async (...filters) => {
      try {
        const d = await hiveQuery([{ _name: 'listCase' }, ...filters, { _name: 'count' }]);
        if (typeof d === 'number') return d;
        if (Array.isArray(d)) return d.length;
        return 0;
      } catch { return 0; }
    };
    const [total, newC, inProg, tp, fp, dup, resolved, other, crit, high, med, low] = await Promise.all([
      cnt(),
      cnt({ _name: 'filter', _field: 'status', _value: 'New' }),
      cnt({ _name: 'filter', _field: 'status', _value: 'InProgress' }),
      cnt({ _name: 'filter', _field: 'status', _value: 'TruePositive' }),
      cnt({ _name: 'filter', _field: 'status', _value: 'FalsePositive' }),
      cnt({ _name: 'filter', _field: 'status', _value: 'Duplicate' }),
      cnt({ _name: 'filter', _field: 'status', _value: 'Resolved' }),
      cnt({ _name: 'filter', _field: 'status', _value: 'Other' }),
      cnt({ _name: 'filter', _field: 'severity', _value: 4 }),
      cnt({ _name: 'filter', _field: 'severity', _value: 3 }),
      cnt({ _name: 'filter', _field: 'severity', _value: 2 }),
      cnt({ _name: 'filter', _field: 'severity', _value: 1 }),
    ]);
    _hiveCaseStatsCache = {
      total, new: newC, in_progress: inProg,
      true_positive: tp, false_positive: fp,
      closed: tp + fp + dup + resolved + other,
      critical: crit, high, medium: med, low,
    };
    _hiveCaseStatsCacheTime = now;
    res.json(_hiveCaseStatsCache);
  } catch (e) {
    console.error('[cases-stats]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/cases', authMW, async (req, res) => {
  try {
    const status    = req.query.status || '';
    const severity  = req.query.severity ? parseInt(req.query.severity) : 0;
    const q         = (req.query.q || '').trim();
    const time_from = req.query.time_from;
    const time_to   = req.query.time_to;
    const page      = Math.max(1, parseInt(req.query.page) || 1);
    const page_size = Math.min(100, Math.max(1, parseInt(req.query.page_size) || 20));

    const baseQ = [{ _name: 'listCase' }];
    if (status)    baseQ.push({ _name: 'filter', _field: 'status',     _value: status });
    if (severity)  baseQ.push({ _name: 'filter', _field: 'severity',   _value: severity });
    if (q)         baseQ.push({ _name: 'filter', _like:  { _field: 'title', _value: `*${q}*` } });
    if (time_from) baseQ.push({ _name: 'filter', _gte:   { _field: '_createdAt', _value: new Date(time_from).getTime() } });
    if (time_to)   baseQ.push({ _name: 'filter', _lte:   { _field: '_createdAt', _value: new Date(time_to).getTime() } });

    const sortedQ = [...baseQ, { _name: 'sort', _fields: [{ _createdAt: 'desc' }] }];
    const from = (page - 1) * page_size;

    const [rawItems, countResult] = await Promise.all([
      hiveQuery([...sortedQ, { _name: 'page', from, to: from + page_size }]),
      hiveQuery([...baseQ, { _name: 'count' }]).catch(() => null),
    ]);

    const items = Array.isArray(rawItems) ? rawItems : [];
    let total;
    if (typeof countResult === 'number') {
      total = countResult;
    } else if (Array.isArray(countResult)) {
      total = countResult.length;
    } else {
      total = from + items.length + (items.length === page_size ? 1 : 0);
    }

    const cases = items.map(mapCase);
    res.json({ cases, total, page, page_size, has_more: from + cases.length < total });
  } catch (e) {
    console.error('[cases]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── THEHIVE ALERT STATS (30s in-memory cache) ──
let _hiveStatsCache = null, _hiveStatsCacheTime = 0;
app.get('/api/hive-alerts/stats', authMW, async (req, res) => {
  try {
    const now = Date.now();
    if (_hiveStatsCache && now - _hiveStatsCacheTime < 30000) return res.json(_hiveStatsCache);
    const cntA = async (...filters) => {
      try {
        const d = await hiveQuery([{ _name: 'listAlert' }, ...filters, { _name: 'count' }]);
        if (typeof d === 'number') return d;
        if (Array.isArray(d)) return d.length;
        return 0;
      } catch { return 0; }
    };
    const cntC = async (status) => {
      try {
        const d = await hiveQuery([{ _name: 'listCase' }, { _name: 'filter', _field: 'status', _value: status }, { _name: 'count' }]);
        if (typeof d === 'number') return d;
        if (Array.isArray(d)) return d.length;
        return 0;
      } catch { return 0; }
    };
    const [total, newC, inProg, closed, crit, high, med, low, truePos, falsePos] = await Promise.all([
      cntA(),
      cntA({ _name: 'filter', _field: 'status', _value: 'New' }),
      cntA({ _name: 'filter', _field: 'status', _value: 'InProgress' }),
      cntA({ _name: 'filter', _field: 'status', _value: 'Imported' }),
      cntA({ _name: 'filter', _field: 'severity', _value: 4 }),
      cntA({ _name: 'filter', _field: 'severity', _value: 3 }),
      cntA({ _name: 'filter', _field: 'severity', _value: 2 }),
      cntA({ _name: 'filter', _field: 'severity', _value: 1 }),
      cntC('TruePositive'),
      cntC('FalsePositive'),
    ]);
    _hiveStatsCache = { total, new: newC, in_progress: inProg, closed, critical: crit, high, medium: med, low, true_positive: truePos, false_positive: falsePos };
    _hiveStatsCacheTime = now;
    res.json(_hiveStatsCache);
  } catch (e) {
    console.error('[hive-alerts-stats]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── THEHIVE ALERTS ──
app.get('/api/hive-alerts', authMW, async (req, res) => {
  try {
    const status    = req.query.status || '';
    const severity  = req.query.severity ? parseInt(req.query.severity) : 0;
    const q         = (req.query.q || '').trim();
    const time_from = req.query.time_from;
    const time_to   = req.query.time_to;
    const page      = Math.max(1, parseInt(req.query.page) || 1);
    const page_size = Math.min(100, Math.max(1, parseInt(req.query.page_size) || 20));

    const baseQ = [{ _name: 'listAlert' }];
    if (status)    baseQ.push({ _name: 'filter', _field: 'status',     _value: status });
    if (severity)  baseQ.push({ _name: 'filter', _field: 'severity',   _value: severity });
    if (q)         baseQ.push({ _name: 'filter', _like: { _field: 'title', _value: `*${q}*` } });
    if (time_from) baseQ.push({ _name: 'filter', _gte:  { _field: '_createdAt', _value: new Date(time_from).getTime() } });
    if (time_to)   baseQ.push({ _name: 'filter', _lte:  { _field: '_createdAt', _value: new Date(time_to).getTime() } });

    const sortedQ = [...baseQ, { _name: 'sort', _fields: [{ _createdAt: 'desc' }] }];
    const from = (page - 1) * page_size;

    const [rawItems, countResult] = await Promise.all([
      hiveQuery([...sortedQ, { _name: 'page', from, to: from + page_size }]),
      hiveQuery([...baseQ, { _name: 'count' }]).catch(() => null),
    ]);

    const items = Array.isArray(rawItems) ? rawItems : [];
    let total;
    if (typeof countResult === 'number') {
      total = countResult;
    } else if (Array.isArray(countResult)) {
      total = countResult.length;
    } else {
      total = from + items.length + (items.length === page_size ? 1 : 0);
    }

    const alerts = items.map(a => ({
      id:          a._id,
      title:       a.title,
      status:      a.status,
      severity:    a.severityLabel || hiveSevLabel(a.severity),
      source:      a.source,
      sourceRef:   a.sourceRef,
      tags:        a.tags || [],
      created:     a._createdAt,
      description: a.description,
    }));
    res.json({ alerts, total, page, page_size, has_more: from + alerts.length < total });
  } catch (e) {
    console.error('[hive-alerts]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── CREATE CASE ──
app.post('/api/cases/create', authMW, async (req, res) => {
  try {
    const { title, description, severity, tags } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    const r = await axios.post(`${HIVE_URL}/api/v1/case`,
      { title, description: description || '', severity: hiveSevNum(severity), tags: tags || ['soc-pilots'], tlp: 2, pap: 2, flag: false },
      { headers: { Authorization: `Bearer ${HIVE_KEY}`, 'Content-Type': 'application/json' }, httpsAgent, timeout: 15000 }
    );
    // Notification + email for new case
    db.createNotification(
      'case', `New Case: ${title}`,
      `Case created by ${req.user.username}. Severity: ${severity || 'medium'}.`,
      severity === 'critical' ? 'critical' : severity === 'high' ? 'warning' : 'info',
      null, { case_title: title, created_by: req.user.username }
    ).catch(() => {});
    email.sendToRecipients(
      `[SOCPilots] New Case Created: ${title}`,
      email.generateCaseCreatedEmail({ title, description, severity, createdBy: req.user.username })
    ).catch(() => {});
    res.json({ success: true, case: r.data });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// ── HUNT — OpenSearch + SOCPilots AI ──
app.post('/api/hunt', authMW, async (req, res) => {
  const { type, value } = req.body;
  if (!value) return res.status(400).json({ error: 'value required' });

  // First search OpenSearch directly
  const fieldMap = { ip: 'data.srcip', domain: 'data.srcip', hash: 'data.hash', user: 'data.dstuser', process: 'data.process_name', rule: 'rule.id' };
  const field = fieldMap[type] || 'data.srcip';

  let osResults = [];
  try {
    const r = await osSearch({
      size: 50,
      sort: [{ '@timestamp': 'desc' }],
      query: { bool: { should: [{ term: { [field]: value } }, { match: { full_log: value } }], minimum_should_match: 1 } },
    });
    osResults = r.hits.hits.map(h => ({
      id: h._id, timestamp: h._source['@timestamp'],
      description: h._source.rule?.description, severity: sevFromLevel(h._source.rule?.level),
      agent: h._source.agent?.name, srcIp: h._source.data?.srcip,
      mitre: h._source.rule?.mitre?.id || [],
    }));
  } catch (e) { console.error('[hunt-os]', e.message); }

  // AI analysis + hunt query generation (run in parallel)
  let aiAnalysis = '';
  let huntQueries = null;
  await Promise.allSettled([
    n8nAsk(
      `Threat hunt analysis for ${type}: "${value}". ` +
      `OpenSearch found ${osResults.length} matching alerts. ` +
      `Provide: risk assessment, MITRE mapping, recommended response actions, and IOC context.`,
      'soc-hunt', req.user
    ).then(r => { aiAnalysis = r.text || 'AI analysis unavailable'; })
     .catch(() => { aiAnalysis = 'AI analysis unavailable'; }),

    axios.post(`${LANGCHAIN_URL}/hunt-queries`,
      { type, value, context: `SIEM found ${osResults.length} matching alerts` },
      { timeout: 60_000, headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` } }
    ).then(r => { huntQueries = r.data; })
     .catch(() => {}),
  ]);

  res.json({ osResults, osTotal: osResults.length, aiAnalysis, huntQueries });
});

// ── CORRELATION ──
app.post('/api/correlate', authMW, async (req, res) => {
  const { indicator } = req.body;
  if (!indicator) return res.status(400).json({ error: 'indicator required' });

  const [osR, hiveR, aiR] = await Promise.allSettled([
    // OpenSearch search
    osSearch({
      size: 20, sort: [{ '@timestamp': 'desc' }],
      query: { multi_match: { query: indicator, fields: ['data.srcip', 'data.dstuser', 'full_log', 'rule.description', 'agent.name'] } },
    }),
    // SP-CM search
    hiveQuery([{ _name: 'listCase' }, { _name: 'filter', _field: 'title', _like: indicator }]),
    // AI correlation
    n8nAsk(`Correlate indicator "${indicator}" across Wazuh and SP-CM. Provide timeline, risk score, MITRE techniques, attack chain analysis.`, 'soc-correlate', req.user),
  ]);

  res.json({
    wazuhHits:  osR.value?.hits?.hits?.map(h => ({ id: h._id, ts: h._source['@timestamp'], desc: h._source.rule?.description, agent: h._source.agent?.name })) || [],
    hiveHits:   Array.isArray(hiveR.value) ? hiveR.value.map(c => ({ id: c._id, title: c.title, status: c.status })) : [],
    aiAnalysis: aiR.value?.text || 'AI unavailable',
  });
});

// ── AI CHAT RATE LIMITER ──
const _chatLimiter = new Map();
function chatRateOk(username) {
  const now = Date.now(), key = username || 'anon';
  const e = _chatLimiter.get(key) || { count: 0, reset: now + 60000 };
  if (now > e.reset) { e.count = 0; e.reset = now + 60000; }
  e.count++;
  _chatLimiter.set(key, e);
  return e.count <= 8; // 8 messages per 60s per user
}

// ── SOCPilots AI CHAT — routes through LangChain (tool-enabled) ──
// n8n still receives every message for automation (fire-and-forget).
// The analyst response comes from LangChain with live tool access.
app.post('/api/ai/chat', authMW, async (req, res) => {
  const { message, history, session_id } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'message required' });
  if (!chatRateOk(req.user?.username)) {
    return res.status(429).json({ error: 'Rate limit: max 8 messages per minute. Please wait.', rateLimit: true });
  }
  const sid = session_id || `soc_${req.user.username}`;
  // Fire n8n in background for automation pipeline (non-blocking)
  n8nAsk(message, sid, req.user, { history: (history || []).slice(-6) }).catch(() => {});
  try {
    const r = await axios.post(`${LANGCHAIN_URL}/chat`, {
      message,
      history:  (history || []).slice(-6),
      username: req.user.username,
      role:     req.user.role,
    }, { timeout: 120_000 });
    const response = r.data?.response || '';
    db.saveChatMessage(sid, req.user.username, 'user', message, {}).catch(() => {});
    if (response) db.saveChatMessage(sid, req.user.username, 'assistant', response, {}).catch(() => {});
    res.json({ response, ok: true, tools_used: r.data?.tools_used || 0, duration_ms: r.data?.duration_ms });
  } catch (e) {
    console.error('[ai/chat]', e.message);
    // Fallback: try n8n synchronously if LangChain is unavailable
    const r2 = await n8nAsk(message, sid, req.user, { history: (history || []).slice(-6) }).catch(() => ({ ok: false }));
    if (r2.ok) {
      const aiText = r2.text || '';
      db.saveChatMessage(sid, req.user.username, 'user', message, {}).catch(() => {});
      if (aiText) db.saveChatMessage(sid, req.user.username, 'assistant', aiText, {}).catch(() => {});
      return res.json(r2.raw || { response: aiText });
    }
    res.status(502).json({ error: 'SOCPilots AI unavailable' });
  }
});

// ── SOCPilots AI CHAT — SSE streaming endpoint ──
// Proxies the LangChain /chat/stream SSE, emitting tool progress events
// in real-time so the analyst sees which tools are being called.
app.post('/api/ai/chat/stream', authMW, async (req, res) => {
  const { message, history, session_id } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'message required' });
  if (!chatRateOk(req.user?.username)) {
    return res.status(429).json({ error: 'Rate limit: max 8 messages per minute.', rateLimit: true });
  }
  const sid = session_id || `soc_${req.user.username}`;
  // Fire n8n background automation hook (non-blocking)
  n8nAsk(message, sid, req.user, { history: (history || []).slice(-6) }).catch(() => {});

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');  // disable nginx response buffering
  res.flushHeaders();

  try {
    const lcRes = await axios({
      method: 'post',
      url: `${LANGCHAIN_URL}/chat/stream`,
      data: { message, history: (history || []).slice(-6), username: req.user.username, role: req.user.role },
      responseType: 'stream',
      timeout: 120_000,
    });
    lcRes.data.pipe(res);
    lcRes.data.on('end', () => res.end());
    lcRes.data.on('error', () => {
      res.write(`data: ${JSON.stringify({ type: 'error', data: 'Stream error' })}\n\n`);
      res.end();
    });
  } catch (e) {
    console.error('[ai/chat/stream]', e.message);
    res.write(`data: ${JSON.stringify({ type: 'error', data: 'SOCPilots AI unavailable' })}\n\n`);
    res.end();
  }
});

// ── SOCPilots AI CHAT — message persistence (called by frontend after streaming) ──
app.post('/api/ai/chat/persist', authMW, (req, res) => {
  const { session_id, user_msg, ai_msg } = req.body;
  const sid = session_id || `soc_${req.user.username}`;
  if (user_msg) db.saveChatMessage(sid, req.user.username, 'user', user_msg, {}).catch(() => {});
  if (ai_msg)  db.saveChatMessage(sid, req.user.username, 'assistant', ai_msg, {}).catch(() => {});
  res.json({ ok: true });
});

// ── AI INVESTIGATION — Dedicated workflow + DB persistence ──
app.post('/api/ai/investigate', authMW, async (req, res) => {
  const { alert, prompt, session_id, autoTriaged = false } = req.body;
  if (!prompt && !alert) return res.status(400).json({ error: 'alert or prompt required' });

  // Build alert key (deduplication)
  const alertKey = alert ? `${alert.ruleId}_${alert.timestamp}_${alert.agent}_${alert.srcIp||''}` : null;

  // Check if already investigated — return cached report
  if (alertKey) {
    try {
      const cached = await db.getInvestigationByAlertKey(alertKey);
      if (cached && !req.body.force) {
        return res.json({
          response: cached.report,
          cached: true,
          investigation_id: cached.id,
          created_at: cached.created_at,
          ok: true,
        });
      }
    } catch(e) { /* DB unavailable, continue */ }
  }

  const startTime = Date.now();
  
  // Rate limit per user
  if (!chatRateOk(req.user?.username)) {
    return res.status(429).json({
      error: 'Rate limit: max 8 investigations per minute. Please wait.',
      rateLimit: true,
    });
  }
  
  // Use dedicated investigation webhook
  const message = prompt || `Investigate alert: ${JSON.stringify(alert)}`;
  
  try {
    const r = await axios.post(N8N_INV, {
      action: 'investigate',
      message,
      alert: alert || null,
      session_id: session_id || `inv_${Date.now()}`,
      _user: req.user?.username || 'system',
      _role: req.user?.role || 'analyst',
    }, {
      timeout: 180000, // 3 minutes for deep investigation
      headers: { 'Content-Type': 'application/json' },
      validateStatus: () => true,
    });
    
    const d = r.data;
    
    // Handle 429
    const bodyStr = JSON.stringify(d || '');
    if (r.status === 429 || bodyStr.includes('Rate limit') || bodyStr.includes('rate_limited')) {
      return res.status(429).json({ error: 'Rate limit on investigation engine. Wait 60s.' });
    }
    
    const text = d?.response || d?.output || d?.text || d?.message ||
      (Array.isArray(d) ? (d[0]?.response || d[0]?.output || '') : '') || '';
    
    if (!text) {
      return res.status(502).json({ error: 'Empty response from investigation webhook. Check workflow is active.' });
    }

    // Save to DB
    let savedId = null;
    if (alert) {
      try {
        const alertSeverity = alert.severity || (alert.level >= 12 ? 'critical' : alert.level >= 8 ? 'high' : alert.level >= 5 ? 'medium' : 'low');

        // Alert deduplication: find or create group for this IP+rule within 5-minute window
        let groupId = null;
        let groupCount = 1;
        try {
          const grp = await db.upsertAlertGroup(alert.srcIp, alert.ruleId, alert.agent);
          groupId   = grp.id;
          groupCount = grp.count;
        } catch(e) { /* non-critical */ }

        // Composite risk score
        const compositeRisk = await computeCompositeRisk({
          level:      alert.level,
          severity:   alertSeverity,
          srcIp:      alert.srcIp,
          agent:      alert.agent,
          groupCount,
        }).catch(() => null);

        const saved = await db.saveInvestigation({
          alertId:      alert.id || alert._id,
          ruleId:       alert.ruleId,
          level:        alert.level,
          severity:     alertSeverity,
          agent:        alert.agent,
          srcIp:        alert.srcIp,
          description:  alert.description,
          mitre:        alert.mitre,
          timestamp:    alert.timestamp,
          report:       text,
          user:         req.user?.username || 'system',
          autoTriaged:  autoTriaged,
          durationMs:   Date.now() - startTime,
          rawAlert:     alert,
          compositeRisk,
          groupId,
        });
        savedId = saved.id;

        // Emit real-time event
        io.emit('investigation:new', {
          id:             savedId,
          ruleId:         alert.ruleId,
          severity:       alertSeverity,
          agent:          alert.agent,
          srcIp:          alert.srcIp,
          description:    alert.description,
          composite_risk: compositeRisk,
          group_count:    groupCount,
          mitre:          alert.mitre || [],
          mitre_tactic:   alert.mitreTactic || [],
          auto_triaged:   autoTriaged,
          timestamp:      new Date().toISOString(),
        });

        // Notification for manual investigations
        if (!autoTriaged) {
          db.createNotification(
            'alert', 'Investigation Complete',
            `Rule ${alert.ruleId} on ${alert.agent} — AI investigation finished.`,
            alertSeverity === 'critical' ? 'critical' : 'warning',
            req.user?.username || null,
            { investigation_id: savedId, rule_id: alert.ruleId, agent: alert.agent }
          ).catch(() => {});
        }

        // UEBA cross-correlation (non-blocking)
        runUebaCorrelation(savedId, alert).catch(() => {});

        // Cross-investigation memory — embed summary in socpilots_knowledge (non-blocking)
        (() => {
          const mitreTags = (alert.mitre || []).join(', ');
          const docTitle  = `Investigation: ${alert.ruleId} on ${alert.agent} (${alertSeverity})`;
          const docDesc   = `Rule ${alert.ruleId} triggered on agent ${alert.agent}. Severity: ${alertSeverity}. Src IP: ${alert.srcIp || 'N/A'}. MITRE: ${mitreTags || 'N/A'}. Description: ${alert.description || ''}. Report excerpt: ${text.slice(0, 400)}`;
          const kHeaders  = process.env.RAG_API_KEY ? { 'X-API-Key': process.env.RAG_API_KEY } : {};
          axios.post(`${KNOWLEDGE_URL}/add_document`, {
            item_id:     `inv_${savedId}`,
            title:       docTitle,
            description: docDesc,
            item_type:   'past_investigation',
            source:      'investigation',
            metadata:    { investigation_id: savedId, rule_id: alert.ruleId, agent: alert.agent, severity: alertSeverity, src_ip: alert.srcIp || null, mitre: alert.mitre || [] },
          }, { headers: kHeaders, timeout: 15000 }).catch(() => {});
        })();

      } catch(e) { console.warn('[DB] save investigation failed:', e.message); }
    }

    res.json({ response: text, ok: true, investigation_id: savedId, cached: false });
    
  } catch (e) {
    const isTimeout = e.code === 'ECONNABORTED' || e.message.includes('timeout');
    const isRefused = e.code === 'ECONNREFUSED';
    let msg = e.message;
    if (isTimeout) msg = 'Investigation timed out (>3min). Try again or check n8n.';
    if (isRefused) msg = 'Investigation webhook refused — is socpilots-investigation workflow active?';
    res.status(502).json({ error: msg });
  }
});

// ── INVESTIGATION HISTORY ──
app.get('/api/investigations', authMW, async (req, res) => {
  try {
    const { severity, agent, ruleId, q, sort_by, sort_dir, time_from, time_to } = req.query;
    const page      = parseInt(req.query.page)      || 1;
    const page_size = Math.min(parseInt(req.query.page_size) || parseInt(req.query.limit) || 50, 500);
    const [{ rows: items, total }, stats] = await Promise.all([
      db.listInvestigations({ severity, agent, ruleId, q, sort_by, sort_dir, time_from, time_to, page, page_size }),
      db.getInvestigationStats(),
    ]);
    res.json({ items, stats, total, page, page_size, has_more: page * page_size < total });
  } catch(e) {
    res.status(503).json({ error: 'DB unavailable: ' + e.message });
  }
});

// ── INVESTIGATION DETAIL ──
app.get('/api/investigations/:id', authMW, async (req, res) => {
  try {
    const inv = await db.getInvestigationById(parseInt(req.params.id));
    if (!inv) return res.status(404).json({ error: 'Not found' });
    res.json(inv);
  } catch(e) {
    res.status(503).json({ error: 'DB unavailable: ' + e.message });
  }
});

// ── ALERT GROUPS (deduplication view) ──
app.get('/api/alert-groups', authMW, async (req, res) => {
  try {
    const page      = parseInt(req.query.page)      || 1;
    const page_size = Math.min(parseInt(req.query.page_size) || parseInt(req.query.limit) || 50, 500);
    const { rows: groups, total } = await db.listAlertGroups({ page, page_size });
    res.json({ groups, total, page, page_size, has_more: page * page_size < total });
  } catch(e) {
    res.status(503).json({ error: e.message });
  }
});

// ── INVESTIGATED ALERT KEYS (used by frontend to mark investigated alerts) ──
app.get('/api/investigations/keys', authMW, async (req, res) => {
  try {
    const keys = await db.getInvestigatedAlertKeys();
    res.json({ keys, count: keys.length });
  } catch(e) {
    res.json({ keys: [], count: 0, error: e.message });
  }
});

// ── SETTINGS ──
app.get('/api/settings', authMW, async (req, res) => {
  try {
    const settings = await db.getAllSettings();
    res.json(settings);
  } catch(e) {
    res.status(503).json({ error: 'DB unavailable' });
  }
});

app.post('/api/settings', authMW, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  try {
    const updates = req.body || {};
    for (const [k, v] of Object.entries(updates)) {
      await db.setSetting(k, v, req.user.username);
    }
    const keys = Object.keys(updates);
    const desc = keys.some(k => k.startsWith('darksoc'))
      ? `Dark SOC settings updated by ${req.user.username}: ${keys.join(', ')}`
      : `Settings updated by ${req.user.username}: ${keys.join(', ')}`;
    db.createSystemEvent('settings', req.user.username, desc, 'ok', { keys, values: updates }).catch(() => {});
    res.json({ ok: true, updated: keys });
  } catch(e) {
    res.status(503).json({ error: e.message });
  }
});

// ── SMTP EMAIL CONFIGURATION ──────────────────────────────────
app.get('/api/settings/smtp', authMW, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  try {
    const config = await db.getSmtpSettings();
    // Redact password in response
    config.password = config.password ? '***' : '';
    res.json(config);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/settings/smtp', authMW, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  try {
    const config = req.body;
    const result = await db.updateSmtpSettings(config, req.user.username);
    // Redact password in response
    result.password = result.password ? '***' : '';
    res.json({ ok: true, config: result });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/settings/smtp/test', authMW, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  try {
    const result = await email.testSmtpConnection();
    if (result.success) {
      res.json({ ok: true, message: `Test email sent to ${result.to}`, messageId: result.messageId });
    } else {
      res.status(400).json({ error: result.error });
    }
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── INVESTIGATION TRUE/FALSE POSITIVE STATUS ──────────────────
app.get('/api/investigations/:id/tp-status', authMW, async (req, res) => {
  try {
    const status = await db.getInvestigationStatus(parseInt(req.params.id));
    if (!status) return res.status(404).json({ error: 'Investigation not found' });
    res.json(status);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/investigations/:id/tp-status', authMW, async (req, res) => {
  try {
    const investigationId = parseInt(req.params.id);
    const tp_status = req.body.tp_status;  // 'confirmed_tp', 'confirmed_fp', 'no_action'

    if (!['confirmed_tp', 'confirmed_fp', 'no_action'].includes(tp_status)) {
      return res.status(400).json({ error: 'Invalid tp_status value' });
    }

    const updated = await db.updateInvestigationStatus(investigationId, tp_status, req.user.username);
    if (!updated) {
      return res.status(404).json({ error: 'Investigation not found' });
    }

    // Sync status to TheHive if a case was created for this investigation
    const investigation = await db.getInvestigationById(investigationId);
    if (investigation?.hive_case_id && (tp_status === 'confirmed_tp' || tp_status === 'confirmed_fp')) {
      const isFP    = tp_status === 'confirmed_fp';
      const summary = isFP
        ? `Confirmed False Positive by analyst ${req.user.username} — no further action required.`
        : `Confirmed True Positive by analyst ${req.user.username} — incident response required.`;
      playbook.updateHiveCaseStatus(investigation.hive_case_id, isFP, summary)
        .catch(e => console.warn('[cases] TheHive status sync failed:', e.message));
    }

    // Send email + notification when marked as true positive
    if (tp_status === 'confirmed_tp') {
      if (investigation) {
        const emailBody = email.generateInvestigationTPEmail(investigation);
        email.sendToRecipients(
          `[SOCPilots] Investigation Confirmed as True Positive: ${investigation.rule_id}`,
          emailBody
        ).catch(() => {});
        db.createNotification(
          'alert', `True Positive Confirmed: Rule ${investigation.rule_id}`,
          `Investigation on ${investigation.agent} marked TP by ${req.user.username}.`,
          'critical', null,
          { investigation_id: investigationId }
        ).catch(() => {});
      }
    }

    res.json({ ok: true, status: updated });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// ─── DARK SOC — PLAYBOOK API ROUTES ────────────────────────────
// ═══════════════════════════════════════════════════════════════

// List all playbooks
app.get('/api/playbooks', authMW, async (req, res) => {
  try {
    const pbs = await db.listPlaybooks({});
    res.json({ playbooks: pbs, total: pbs.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Create new playbook (admin only)
app.post('/api/playbooks', authMW, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  try {
    const pb = await db.createPlaybook(req.body);
    res.json({ playbook: pb });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Update playbook (admin only)
app.patch('/api/playbooks/:id', authMW, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  try {
    const pb = await db.updatePlaybook(parseInt(req.params.id), req.body);
    if (!pb) return res.status(404).json({ error: 'not found' });
    res.json({ playbook: pb });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Delete playbook (admin only)
app.delete('/api/playbooks/:id', authMW, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  try {
    await db.deletePlaybook(parseInt(req.params.id));
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// List playbook executions
app.get('/api/playbook-executions', authMW, async (req, res) => {
  try {
    const page      = Math.max(parseInt(req.query.page) || 1, 1);
    const page_size = Math.min(parseInt(req.query.page_size) || parseInt(req.query.limit) || 50, 500);
    const [{ rows: execs, total }, stats] = await Promise.all([
      db.listPlaybookExecutions({ page, page_size }),
      db.getPlaybookExecStats(),
    ]);
    res.json({ executions: execs, stats, total, page, page_size, has_more: page * page_size < total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Manual playbook trigger (run against a specific alert key)
app.post('/api/playbooks/:id/run', authMW, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  try {
    const pb = await db.getPlaybookById(parseInt(req.params.id));
    if (!pb) return res.status(404).json({ error: 'playbook not found' });
    const { alert, investigationText, fpProbability } = req.body;
    if (!alert) return res.status(400).json({ error: 'alert required' });
    const result = await playbook.runPlaybook(pb, alert, investigationText || '', fpProbability || 0);
    res.json({ result });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Dark SOC status
app.get('/api/darksoc/status', authMW, async (req, res) => {
  try {
    const [settings, execStats, pbCount, pendingRow] = await Promise.all([
      db.getAllSettings(),
      db.getPlaybookExecStats(),
      db.listPlaybooks({ enabledOnly: true }).then(r => r.length),
      db.pool.query(`SELECT COUNT(*) AS cnt FROM isolation_approvals WHERE status='pending' AND expires_at > NOW()`),
    ]);
    const stats = {
      ...execStats,
      pending_approvals: parseInt(pendingRow.rows[0]?.cnt || 0),
    };
    res.json({
      darksoc_enabled:                settings.darksoc_enabled === 'true',
      hunt_enabled:                   settings.darksoc_hunt_enabled === 'true',
      lateral_monitor_enabled:        settings.darksoc_lateral_monitor_enabled === 'true',
      auto_triage_enabled:            settings.auto_triage_enabled === 'true',
      active_playbooks:               pbCount,
      execution_stats:                stats,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SYSTEM EVENTS — merged audit feed ──
app.get('/api/system-events', authMW, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '50'), 100);
  try {
    const [sysEvents, notifications, executions] = await Promise.all([
      db.listSystemEvents({ limit }),
      db.pool.query(`SELECT * FROM notifications ORDER BY created_at DESC LIMIT $1`, [limit]).then(r => r.rows),
      db.listPlaybookExecutions({ limit: 20 }),
    ]);

    const merged = [
      ...sysEvents.map(e => ({
        id:          `se_${e.id}`,
        source:      'system',
        event_type:  e.event_type,
        title:       e.description,
        description: e.description,
        status:      e.status,
        actor:       e.actor,
        metadata:    e.metadata,
        created_at:  e.created_at,
      })),
      ...notifications.map(n => ({
        id:          `notif_${n.id}`,
        source:      'notification',
        event_type:  (n.type === 'hunt' || n.type === 'threat_hunt') ? 'hunt'
                   : n.type === 'case'  ? 'case'
                   : 'alert',
        title:       n.title,
        description: n.message,
        status:      n.severity === 'critical' ? 'critical' : 'ok',
        actor:       n.username,
        metadata:    n.metadata,
        created_at:  n.created_at,
      })),
      ...(executions.rows || []).map(e => ({
        id:          `pb_${e.id}`,
        source:      'playbook',
        event_type:  'playbook',
        title:       `Playbook: ${e.playbook_name || '?'} — ${e.agent || '?'}`,
        description: `Rule ${e.rule_id || '?'} (${e.severity || '?'}) — Actions: ${(e.actions_taken || []).join(', ') || 'none'}`,
        status:      e.outcome === 'executed' ? 'ok' : e.outcome === 'skipped' ? 'skip' : 'fail',
        actor:       'darksoc',
        metadata:    { playbook_name: e.playbook_name, agent: e.agent, rule_id: e.rule_id, outcome: e.outcome },
        created_at:  e.created_at,
      })),
    ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, limit);

    // Platform-wide activity stats
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const todayISO = today.toISOString();
    const [invCount, huntCount, loginCount] = await Promise.all([
      db.pool.query(`SELECT COUNT(*) AS cnt FROM investigations WHERE created_at >= $1`, [todayISO]),
      db.pool.query(`SELECT COUNT(*) AS cnt FROM notifications WHERE type='hunt' AND created_at >= $1`, [todayISO]),
      db.pool.query(`SELECT COUNT(*) AS cnt FROM system_events WHERE event_type='auth' AND status='ok' AND created_at >= $1`, [todayISO]),
    ]);

    res.json({
      events: merged,
      activity_today: {
        investigations: parseInt(invCount.rows[0]?.cnt || 0),
        hunts:          parseInt(huntCount.rows[0]?.cnt || 0),
        logins:         parseInt(loginCount.rows[0]?.cnt || 0),
      },
    });
  } catch(e) {
    console.error('[system-events]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── TRIAGE QUEUE — FEEDER + PROCESSOR ──────────────────────────────────
// Feeder: enqueues ALL alert levels every 60s (last 2h, paginated).
// Processor: runs every 15s, dispatches by tier:
//   critical (≥12) → LangChain /investigate (direct, no n8n)
//   high     (9-11) → LangChain /triage (direct)
//   medium   (6-8)  → template assembly from rule history
//   low      (<6)   → bulk suppressed + 15min batch notifications

const LOW_BATCH_WINDOW_MIN = parseInt(process.env.LOW_BATCH_WINDOW_MIN || '240'); // 4 hours
const LOW_BATCH_MIN_COUNT  = parseInt(process.env.LOW_BATCH_MIN_COUNT  || '5');

// Actions that require human approval before execution
const DESTRUCTIVE_ACTIONS = new Set(['block_ip', 'isolate_host', 'kill_process', 'disable_user']);

// Map LangChain recommended_action strings → playbook action types
const ACTION_MAP = {
  block:       ['block_ip'],
  block_ip:    ['block_ip'],
  isolate:     ['isolate_host'],
  isolate_host:['isolate_host'],
  kill:        ['kill_process'],
  disable:     ['disable_user'],
  close:       ['close_case'],
  monitor:     ['create_case'],
  investigate: ['create_case'],
  review:      ['create_case'],
  create_case: ['create_case'],
};

function _extractStructuredVerdict(triageData, alert) {
  const fpProb     = triageData?.false_positive_probability || 0;
  const confidence = Math.max(0, Math.min(100, 100 - fpProb));
  const verdict    = fpProb >= 70 ? 'false_positive'
                   : confidence >= 65 ? 'true_positive'
                   : 'needs_review';
  const rawAction  = (triageData?.recommended_action || 'review').toLowerCase().replace(/ /g,'_');
  const actions    = ACTION_MAP[rawAction] || ['create_case'];
  const mitre      = triageData?.mitre_technique
                     ? [triageData.mitre_technique]
                     : (Array.isArray(alert.mitre) ? alert.mitre : []);
  return {
    verdict,
    confidence,
    fp_probability:       fpProb,
    mitre_techniques:     mitre,
    recommended_actions:  actions,
    summary:              (triageData?.summary || `Rule ${alert.ruleId||alert.rule_id} on ${alert.agent}`).slice(0, 300),
    risk_score:           Math.round(((alert.level || alert.rule_level || 0) / 15) * 100),
    requires_approval:    actions.some(a => DESTRUCTIVE_ACTIONS.has(a)) && verdict !== 'false_positive',
  };
}

function _buildMediumVerdict(alert) {
  return {
    verdict:             'needs_review',
    confidence:          40,
    fp_probability:      60,
    mitre_techniques:    Array.isArray(alert.mitre) ? alert.mitre : [],
    recommended_actions: ['create_case'],
    summary:             `Pattern match — rule ${alert.ruleId||alert.rule_id} on ${alert.agent} (level ${alert.level||alert.rule_level})`.slice(0, 300),
    risk_score:          Math.round(((alert.level || alert.rule_level || 0) / 15) * 100),
    requires_approval:   false,
  };
}

let _feederRunning    = false;
let _processorRunning = false;
let _lastLowBatch     = 0;

// ── Shared: save investigation + side-effects ─────────────────────────
async function _saveTriageInvestigation({ alert, report, tier, durationMs, queueId, structuredVerdict }) {
  const saved = await db.saveInvestigation({
    alertId:     alert.id,
    ruleId:      alert.ruleId,
    level:       alert.level,
    severity:    alert.severity,
    agent:       alert.agent,
    srcIp:       alert.srcIp,
    description: alert.description,
    mitre:       alert.mitre,
    timestamp:   alert.alertTimestamp || alert.timestamp,
    report,
    user:        'auto-triage',
    autoTriaged: true,
    durationMs:  durationMs || 0,
    rawAlert:    alert.raw || alert,
  });

  // Tag tier + structured verdict
  db.pool.query(
    `UPDATE investigations SET triage_tier=$1, structured_verdict=$2 WHERE id=$3`,
    [tier, structuredVerdict ? JSON.stringify(structuredVerdict) : null, saved.id]
  ).catch(() => {});

  // Cross-investigation RAG memory (non-blocking)
  const mitreTags = (alert.mitre || []).join(', ');
  const kHeaders  = process.env.RAG_API_KEY ? { 'X-API-Key': process.env.RAG_API_KEY } : {};
  axios.post(`${KNOWLEDGE_URL}/add_document`, {
    item_id:     `inv_${saved.id}`,
    title:       `Investigation: ${alert.ruleId} on ${alert.agent} (${alert.severity})`,
    description: `Rule ${alert.ruleId} triggered on agent ${alert.agent}. Severity: ${alert.severity}. ` +
                 `Src IP: ${alert.srcIp || 'N/A'}. MITRE: ${mitreTags || 'N/A'}. ` +
                 `Description: ${alert.description || ''}. Report excerpt: ${report.slice(0, 400)}`,
    item_type:   'past_investigation',
    source:      'investigation',
    metadata:    { investigation_id: saved.id, rule_id: alert.ruleId, agent: alert.agent,
                   severity: alert.severity, src_ip: alert.srcIp || null, mitre: alert.mitre || [] },
  }, { headers: kHeaders, timeout: 15000 }).catch(() => {});

  // Notification
  db.createNotification(
    'alert', 'New Investigation Auto-Triaged',
    `Alert ${alert.ruleId} (${alert.severity}) on ${alert.agent} was auto-investigated [${tier}].`,
    alert.severity === 'critical' ? 'critical' : 'warning',
    null, { investigation_id: saved.id, rule_id: alert.ruleId, agent: alert.agent, triage_tier: tier }
  ).catch(() => {});

  // Email (only critical + high to avoid noise)
  if (tier === 'critical' || tier === 'high') {
    email.sendToRecipients(
      `[SOCPilots] Auto-Triaged Investigation: ${alert.ruleId} on ${alert.agent}`,
      email.generateAutoTriageEmail({
        rule_id: alert.ruleId, agent: alert.agent, src_ip: alert.srcIp,
        severity: alert.severity, description: alert.description,
      })
    ).catch(() => {});
  }

  return saved;
}

// ── Execute playbooks immediately (non-destructive or already approved) ──
async function _executePlaybooks(alert, report, savedId, fpProbability, playbooks) {
  for (const pb of playbooks) {
    try {
      const execResult = await playbook.runPlaybook(pb, alert, report, fpProbability, savedId);
      const outcome    = execResult.skipped ? 'skipped' : 'executed';
      await db.savePlaybookExecution({
        playbookId:        pb.id,
        playbookName:      pb.name,
        investigationId:   savedId,
        alertKey:          alert.alertKey || alert.alert_key || '',
        agent:             alert.agent,
        srcIp:             alert.srcIp    || alert.src_ip,
        ruleId:            alert.ruleId   || alert.rule_id,
        severity:          alert.severity,
        fpProbability,
        consensusApproved: execResult.consensusApproved,
        actionsTaken:      execResult.actionsTaken || [],
        results:           execResult.results      || [],
        outcome,
        error:             execResult.error || null,
      });
      if (outcome === 'executed') {
        db.createNotification(
          'playbook', `Playbook Executed: ${pb.name}`,
          `Playbook "${pb.name}" ran on alert ${alert.ruleId||alert.rule_id} (${alert.agent}).`,
          'warning', null, { playbook_name: pb.name, investigation_id: savedId }
        ).catch(() => {});
        io.emit('darksoc:action', {
          playbook: pb.name, investigation_id: savedId,
          rule_id: alert.ruleId || alert.rule_id, agent: alert.agent,
          src_ip: alert.srcIp || alert.src_ip,
          actions_taken: execResult.actionsTaken || [], timestamp: new Date().toISOString(),
        });
      }
    } catch(e) {
      console.error(`[DarkSOC] Playbook "${pb.name}" error:`, e.message);
    }
  }
}

// ── Route playbook actions through approval gate or execute immediately ──
async function _routeActionsOrApproval(alert, report, savedId, fpProbability, verdict) {
  const matched = await db.getMatchingPlaybooks(
    alert.level || alert.rule_level || 0,
    alert.mitre || []
  );
  if (!matched.length) return;

  const hasDestructive = matched.some(pb =>
    (pb.actions || []).some(a => DESTRUCTIVE_ACTIONS.has(a.type))
  );

  if (hasDestructive && verdict?.requires_approval) {
    const approval = await db.createActionApproval({
      investigationId:    savedId,
      alertKey:           alert.alertKey || alert.alert_key,
      ruleId:             alert.ruleId   || alert.rule_id,
      agent:              alert.agent,
      srcIp:              alert.srcIp    || alert.src_ip,
      severity:           alert.severity,
      triageTier:         alert.triage_tier || 'unknown',
      verdict:            verdict.verdict,
      confidence:         verdict.confidence,
      riskScore:          verdict.risk_score,
      fpProbability,
      summary:            verdict.summary,
      recommendedActions: verdict.recommended_actions,
      playbookIds:        matched.map(pb => pb.id),
      alertData:          alert,
    });
    io.emit('approval:new', {
      id:                  approval.id,
      rule_id:             alert.ruleId || alert.rule_id,
      agent:               alert.agent,
      severity:            alert.severity,
      verdict:             verdict.verdict,
      confidence:          verdict.confidence,
      summary:             verdict.summary,
      recommended_actions: verdict.recommended_actions,
      expires_at:          approval.expires_at,
      created_at:          approval.created_at,
    });
    db.createNotification(
      'playbook', 'Action Approval Required',
      `Triage for rule ${alert.ruleId||alert.rule_id} on ${alert.agent} recommends ${(verdict.recommended_actions||[]).join(', ')} — awaiting analyst approval.`,
      'warning', null, { approval_id: approval.id, investigation_id: savedId }
    ).catch(() => {});
    console.log(`[TriageProcessor] APPROVAL QUEUED inv#${savedId} → approval#${approval.id}`);
  } else {
    await _executePlaybooks(alert, report, savedId, fpProbability, matched);
  }
}

// ── Medium tier: build report from OpenSearch rule history (no LLM) ──
async function _buildMediumReport(alert) {
  let total7d = 0, topAgents = '';
  try {
    const agg = await osSearch({
      size: 0,
      query: { bool: { filter: [
        { term: { 'rule.id': alert.ruleId } },
        { range: { '@timestamp': { gte: 'now-7d' } } },
      ]}},
      aggs: { agents: { terms: { field: 'agent.name', size: 10 } } },
    });
    total7d   = agg.hits?.total?.value || 0;
    topAgents = (agg.aggregations?.agents?.buckets || []).map(b => `${b.key} (${b.doc_count})`).join(', ');
  } catch(e) { /* non-fatal */ }

  return `## Pattern Analysis — Rule ${alert.ruleId}

| Field | Value |
|---|---|
| Rule ID | ${alert.ruleId} |
| Level | ${alert.level} (medium tier, 6–8) |
| Description | ${alert.description || 'N/A'} |
| Agent | ${alert.agent || 'N/A'} |
| Source IP | ${alert.srcIp || 'N/A'} |
| MITRE | ${(alert.mitre || []).join(', ') || 'None mapped'} |
| Alert Time | ${alert.alertTimestamp || 'N/A'} |

## Historical Pattern (Last 7 Days)

| Metric | Value |
|---|---|
| Total occurrences | ${total7d} |
| Top affected agents | ${topAgents || 'N/A'} |

## Assessment

Triaged by **pattern analysis** (no AI). Rule level ${alert.level} falls in the medium tier.

**Recommended Action:** Analyst review required. Verify frequency trend, affected scope, and whether rule level should be promoted to high/critical.`;
}

// ── FEEDER: OpenSearch → triage_queue ────────────────────────────────
async function triageFeeder() {
  if (_feederRunning) return;
  const enabled = await db.getSetting('auto_triage_enabled');
  if (enabled !== 'true') return;
  _feederRunning = true;
  try {
    let enqueued = 0;
    let searchAfter = null;
    const batchSize = 100;

    // Paginate up to 500 alerts from the last 2h (all levels)
    for (let page = 0; page < 5; page++) {
      const body = {
        size: batchSize,
        sort: [{ '@timestamp': { order: 'desc' } }, { '_id': { order: 'desc' } }],
        query: {
          bool: { filter: [{ range: { '@timestamp': { gte: 'now-2h' } } }] },
        },
        ...(searchAfter ? { search_after: searchAfter } : {}),
      };

      const r = await osSearch(body, IDX);
      const hits = r.hits?.hits || [];
      if (!hits.length) break;

      for (const h of hits) {
        const ruleId   = String(h._source.rule?.id || '');
        const ts       = h._source['@timestamp'];
        const agent    = h._source.agent?.name || '';
        const srcIp    = h._source.data?.srcip || h._source.data?.src_ip || '';
        const alertKey = `${ruleId}_${ts}_${agent}_${srcIp}`;

        await db.enqueueAlert({
          id:             h._id,
          alertKey,
          ruleId,
          level:          h._source.rule?.level || 0,
          severity:       h._source.rule?.level >= 12 ? 'critical'
                        : h._source.rule?.level >= 9  ? 'high'
                        : h._source.rule?.level >= 6  ? 'medium' : 'low',
          description:    h._source.rule?.description || '',
          agent,
          srcIp,
          mitre:          h._source.rule?.mitre?.id || [],
          fullLog:        (h._source.full_log || '').slice(0, 500),
          alertTimestamp: ts,
          timestamp:      ts,
          raw:            h._source,
        });
        enqueued++;
      }

      if (hits.length < batchSize) break;
      const last = hits[hits.length - 1];
      searchAfter = last.sort;
    }

    if (enqueued > 0) console.log(`[TriageFeeder] Enqueued up to ${enqueued} alerts (deduplicated by DB)`);
  } catch(e) {
    console.error('[TriageFeeder] Error:', e.message);
  } finally {
    _feederRunning = false;
  }
}

// ── PROCESSOR: triage_queue → investigations ──────────────────────────
async function triageProcessor() {
  if (_processorRunning) return;
  const enabled = await db.getSetting('auto_triage_enabled');
  if (enabled !== 'true') return;
  _processorRunning = true;

  try {
    // Reaper: reset stuck processing rows
    const reaped = await db.resetStuckQueueItems();
    if (reaped > 0) console.log(`[TriageProcessor] Reaped ${reaped} stuck items`);

    const darkSoc = await db.getSetting('darksoc_enabled');

    // ── Critical tier: LangChain /investigate (direct) ──────────
    const critItems = await db.claimNextQueueItems('critical', 3);
    for (const item of critItems) {
      const alert = { ...item, alertKey: item.alert_key, ruleId: item.rule_id,
                      level: item.rule_level, alertTimestamp: item.alert_timestamp,
                      mitre: item.mitre || [], fullLog: item.full_log };
      const start = Date.now();
      try {
        const prompt = `Auto-investigate this alert. Provide concise analysis with executive summary, MITRE mapping, risk assessment, and recommended actions.\n\nAlert:\n- Timestamp: ${item.alert_timestamp}\n- Rule: ${item.rule_id} (level ${item.rule_level})\n- Description: ${item.description}\n- Agent: ${item.agent}\n- Source IP: ${item.src_ip || 'N/A'}\n- MITRE: ${(item.mitre||[]).join(', ')}\n\nUse markdown tables. Be concise.`;

        const resp = await axios.post(`${LANGCHAIN_URL}/investigate`,
          { message: prompt, alert, session_id: `triage_crit_${item.rule_id}_${Date.now()}` },
          { timeout: 90000, headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` }, validateStatus: () => true }
        );
        const text = resp.data?.result || resp.data?.answer || resp.data?.response || resp.data?.text || '';
        if (!text) { await db.markQueueItemFailed(item.id, 'empty LangChain response'); continue; }

        let fpProbability = 0;
        let triageData    = null;
        try {
          const tr = await axios.post(`${LANGCHAIN_URL}/triage`, { alert },
            { timeout: 30000, headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` }, validateStatus: () => true });
          if (tr.status < 400) { triageData = tr.data; fpProbability = triageData?.false_positive_probability || 0; }
        } catch(e) { /* non-fatal */ }

        const verdict = _extractStructuredVerdict(triageData, alert);
        const saved   = await _saveTriageInvestigation({ alert, report: text, tier: 'critical', durationMs: Date.now()-start, queueId: item.id, structuredVerdict: verdict });
        await db.markQueueItemDone(item.id, saved.id);
        if (darkSoc === 'true') await _routeActionsOrApproval(alert, text, saved.id, fpProbability, verdict);
        console.log(`[TriageProcessor] CRITICAL ${item.rule_id} → inv#${saved.id} verdict=${verdict.verdict} (${Date.now()-start}ms)`);
      } catch(e) {
        console.warn(`[TriageProcessor] CRITICAL ${item.rule_id} failed:`, e.message);
        await db.markQueueItemFailed(item.id, e.message);
      }
    }

    // ── High tier: LangChain /triage (direct) ───────────────────
    const highItems = await db.claimNextQueueItems('high', 3);
    for (const item of highItems) {
      const alert = { ...item, alertKey: item.alert_key, ruleId: item.rule_id,
                      level: item.rule_level, alertTimestamp: item.alert_timestamp,
                      mitre: item.mitre || [], fullLog: item.full_log };
      const start = Date.now();
      try {
        const resp = await axios.post(`${LANGCHAIN_URL}/triage`,
          { alert },
          { timeout: 30000, headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` }, validateStatus: () => true }
        );
        const raw = resp.status < 400 ? resp.data : null;
        const prose = raw?.result || raw?.answer || raw?.response || raw?.text || raw?.summary || '';
        if (!prose) { await db.markQueueItemFailed(item.id, 'empty triage response'); continue; }

        const verdict    = _extractStructuredVerdict(raw, alert);
        const mitreTech  = raw?.mitre_technique || '';
        const indicators = (raw?.key_indicators || []).slice(0, 5).join(', ');
        const report = `## AI Triage Assessment — Rule ${item.rule_id}

| Field | Value |
|---|---|
| Verdict | ${verdict.verdict.replace('_',' ')} |
| Confidence | ${verdict.confidence}% |
| FP Probability | ${verdict.fp_probability}% |
| MITRE Technique | ${mitreTech || 'N/A'} |
| Recommended Actions | ${verdict.recommended_actions.join(', ')} |
| Key Indicators | ${indicators || 'N/A'} |

### Summary

${prose.slice(0, 2000)}`;
        const saved = await _saveTriageInvestigation({ alert, report, tier: 'high', durationMs: Date.now()-start, queueId: item.id, structuredVerdict: verdict });
        await db.markQueueItemDone(item.id, saved.id);
        if (darkSoc === 'true') await _routeActionsOrApproval(alert, report, saved.id, verdict.fp_probability, verdict);
        console.log(`[TriageProcessor] HIGH ${item.rule_id} → inv#${saved.id} verdict=${verdict.verdict} (${Date.now()-start}ms)`);
      } catch(e) {
        console.warn(`[TriageProcessor] HIGH ${item.rule_id} failed:`, e.message);
        await db.markQueueItemFailed(item.id, e.message);
      }
    }

    // ── Medium tier: pattern template (no LLM) ──────────────────
    const medItems = await db.claimNextQueueItems('medium', 5);
    for (const item of medItems) {
      const alert = { ...item, alertKey: item.alert_key, ruleId: item.rule_id,
                      level: item.rule_level, alertTimestamp: item.alert_timestamp,
                      mitre: item.mitre || [], fullLog: item.full_log };
      const start = Date.now();
      try {
        const verdict = _buildMediumVerdict(alert);
        const report  = await _buildMediumReport(alert);
        const saved   = await _saveTriageInvestigation({ alert, report, tier: 'medium', durationMs: Date.now()-start, queueId: item.id, structuredVerdict: verdict });
        await db.markQueueItemDone(item.id, saved.id);
        if (darkSoc === 'true') await _routeActionsOrApproval(alert, report, saved.id, verdict.fp_probability, verdict);
        console.log(`[TriageProcessor] MEDIUM ${item.rule_id} → inv#${saved.id} (${Date.now()-start}ms)`);
      } catch(e) {
        console.warn(`[TriageProcessor] MEDIUM ${item.rule_id} failed:`, e.message);
        await db.markQueueItemFailed(item.id, e.message);
      }
    }

    // ── Low tier: bulk suppress immediately ─────────────────────
    const suppressed = await db.claimAllPendingLowTier();
    if (suppressed.length > 0) console.log(`[TriageProcessor] Suppressed ${suppressed.length} low-tier items`);

    // ── Approval expiry reaper ───────────────────────────────────
    try {
      const expired = await db.listExpiredActionApprovals();
      for (const a of expired) {
        await db.resolveActionApproval(a.id, { status: 'expired', resolvedBy: 'system', resolveNote: '30-min TTL exceeded' });
        io.emit('approval:resolved', { id: a.id, status: 'expired' });
        console.log(`[TriageProcessor] Approval #${a.id} expired`);
      }
    } catch(e) { /* non-fatal */ }

    // ── Low tier: batch notification (every 15 min) ──────────────
    if (Date.now() - _lastLowBatch > 900_000) {
      _lastLowBatch = Date.now();
      try {
        const groups = await db.getPendingLowTierGroups(LOW_BATCH_WINDOW_MIN, LOW_BATCH_MIN_COUNT);
        for (const g of groups) {
          await db.createNotification(
            'alert',
            `Low-Severity Batch: ${g.count} events from ${g.agent || 'unknown'}`,
            `${g.count} low-severity events matching rule ${g.rule_id || 'N/A'} on agent ${g.agent || 'N/A'} in the last ${LOW_BATCH_WINDOW_MIN/60}h. Review in Alerts.`,
            'low', null,
            { rule_id: g.rule_id, agent: g.agent, count: g.count, triage_tier: 'low' }
          );
          await db.markLowTierGroupNotified(g.rule_id, g.agent, LOW_BATCH_WINDOW_MIN);
        }
        if (groups.length > 0) console.log(`[TriageProcessor] Sent ${groups.length} low-tier batch notifications`);
      } catch(e) { console.warn('[TriageProcessor] Low batch error:', e.message); }
    }
  } catch(e) {
    console.error('[TriageProcessor] Error:', e.message);
  } finally {
    _processorRunning = false;
  }
}

// Feeder: every 60s
setInterval(() => { triageFeeder(); }, 60000);
// Processor: every 15s
setInterval(() => { triageProcessor(); }, 15000);
// Boot delay: feeder after 30s, processor after 45s
setTimeout(() => { triageFeeder(); }, 30000);
setTimeout(() => { triageProcessor(); }, 45000);

// ── UEBA AUTO-INGEST from Wazuh/OpenSearch ─────────────────────────
// Polls OpenSearch every 2 min, maps alert fields → UEBA events
let _uebaLastRun = 0;
let _uebaRunning = false;

async function uebaIngestWorker() {
  if (_uebaRunning) return;
  if (Date.now() - _uebaLastRun < 110_000) return;
  _uebaRunning = true;
  _uebaLastRun = Date.now();
  try {
    const since = new Date(Date.now() - 130_000).toISOString(); // 130s ago (overlap)
    const body = {
      size: 100,
      sort: [{ '@timestamp': { order: 'asc' } }],
      query: {
        bool: {
          filter: [
            { range: { '@timestamp': { gte: since } } },
            { range: { 'rule.level': { gte: 3 } } },
          ],
        },
      },
      _source: [
        '@timestamp', 'agent.name', 'agent.ip',
        'data.srcip', 'data.dstip', 'data.dstuser', 'data.srcuser',
        'rule.id', 'rule.level', 'rule.description', 'rule.mitre',
        'full_log', 'data.win.system.computer', 'data.win.eventdata.targetUserName',
        'data.win.eventdata.subjectUserName', 'data.command',
      ],
    };

    const r = await osSearch(body, IDX);
    const hits = r.hits?.hits || [];
    if (hits.length === 0) return;

    let ingested = 0;
    for (const h of hits) {
      const s = h._source;
      const ts = s['@timestamp'];

      // Extract user — try multiple Wazuh field locations
      const user =
        s.data?.dstuser ||
        s.data?.srcuser ||
        s.data?.win?.eventdata?.targetUserName ||
        s.data?.win?.eventdata?.subjectUserName ||
        null;

      // Extract host
      const host =
        s.agent?.name ||
        s.data?.win?.system?.computer ||
        null;

      const src_ip  = s.data?.srcip  || s.data?.dstip || s.agent?.ip || null;
      const proc    = s.data?.command || null;
      const rule_id = String(s.rule?.id || '');
      const level   = s.rule?.level || 0;
      const severity = level >= 12 ? 'critical' : level >= 7 ? 'high' : level >= 4 ? 'medium' : 'low';

      // Skip if no user AND no host — nothing to graph
      if (!user && !host) continue;

      try {
        await ueba.ingestEvent({
          user:      user || host,  // fall back to host as actor if no user field
          host:      host,
          src_ip:    src_ip,
          process:   proc,
          action:    s.rule?.description || 'alert',
          timestamp: ts,
          alert_id:  h._id,
          rule_id:   rule_id,
          severity:  severity,
          success:   true,
        });
        ingested++;
      } catch (e) {
        // skip single-event errors silently
      }
    }
    if (ingested > 0) console.log(`[UEBA] Auto-ingested ${ingested}/${hits.length} events`);
  } catch (e) {
    if (!e.message?.includes('connect ECONNREFUSED')) {
      console.warn('[UEBA] Auto-ingest error:', e.message);
    }
  } finally {
    _uebaRunning = false;
  }
}

setInterval(() => { uebaIngestWorker(); }, 120_000);
setTimeout(() => { uebaIngestWorker(); }, 15_000); // first run 15s after boot

// ═══════════════════════════════════════════════════════════════
// ─── DARK SOC — AUTONOMOUS HUNT SCHEDULER (every 6 hours) ──────
// Pulls top IOCs from recent alerts, generates hunt queries via
// LangChain, executes against OpenSearch, creates cases on hits.
// ═══════════════════════════════════════════════════════════════
let _huntRunning = false;

async function huntScheduler() {
  if (_huntRunning) return;
  const enabled = await db.getSetting('darksoc_hunt_enabled').catch(() => 'false');
  if (enabled !== 'true') return;

  _huntRunning = true;
  console.log('[DarkSOC Hunt] Scheduled hunt started');

  try {
    // Step 1 — Find top source IPs from high/critical alerts (last 24h)
    const agg = await osSearch({
      size: 0,
      query: { bool: { filter: [
        { range: { '@timestamp': { gte: 'now-24h' } } },
        { range: { 'rule.level': { gte: 8 } } },
      ]}},
      aggs: { top_ips: { terms: { field: 'data.srcip', size: 10, min_doc_count: 3 } } },
    }).catch(() => null);

    const topIPs = (agg?.aggregations?.top_ips?.buckets || [])
      .filter(b => b.key && b.key !== '')
      .map(b => b.key);

    if (!topIPs.length) {
      console.log('[DarkSOC Hunt] No significant source IPs — skipping');
      _huntRunning = false;
      return;
    }

    // Step 2 — Generate hunt queries for each IP
    for (const ip of topIPs.slice(0, 3)) {
      try {
        const huntResp = await axios.post(`${LANGCHAIN_URL}/hunt-queries`,
          { type: 'ip', value: ip, context: 'Automated 6h threat hunt' },
          { timeout: 60_000, headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` }, validateStatus: () => true }
        );
        const queries = huntResp.data?.queries || [];

        // Step 3 — Execute queries against OpenSearch
        let totalHits = 0;
        for (const q of queries.slice(0, 3)) {
          try {
            const qBody = typeof q === 'string'
              ? { size: 0, query: { multi_match: { query: q, fields: ['data.srcip','full_log','agent.name'] } } }
              : q;
            const r = await osSearch(qBody, IDX, 0);
            totalHits += r.hits?.total?.value || 0;
          } catch { /* skip bad query */ }
        }

        // Step 4 — Create TheHive case if significant hits found
        if (totalHits >= 5) {
          console.log(`[DarkSOC Hunt] IP ${ip} hit ${totalHits} alerts — creating case`);
          await playbook.createHiveCase(
            { ruleId: 'HUNT', agent: 'auto-hunt', srcIp: ip, description: `Threat hunt hit: ${ip}`, mitre: [] },
            'high',
            `[DarkSOC Hunt] Suspicious IP ${ip} — ${totalHits} alert hits in 24h`
          ).catch(e => console.warn('[DarkSOC Hunt] Case creation failed:', e.message));
        }
      } catch(e) {
        console.warn(`[DarkSOC Hunt] Hunt for ${ip} failed:`, e.message);
      }
    }
  } catch(e) {
    console.error('[DarkSOC Hunt] Error:', e.message);
  } finally {
    _huntRunning = false;
    console.log('[DarkSOC Hunt] Done');
  }
}

setInterval(() => { huntScheduler(); }, 6 * 3600_000);   // every 6 hours
setTimeout (() => { huntScheduler(); }, 5 * 60_000);      // first run 5min after boot

// ═══════════════════════════════════════════════════════════════
// ─── DARK SOC — LATERAL MOVEMENT MONITOR (every 30 minutes) ────
// Checks UEBA graph for new lateral movement chains.
//
// Noise-reduction controls:
//   • Threshold  : deviation >= 80 AND hops >= 3 (both required)
//   • Observation: last 2 hours (reduces repeated detections per session)
//   • Cooldown   : 6 hours per user in DB (survives container restarts)
//   • Case limit : max 5 new cases per monitor run
// ═══════════════════════════════════════════════════════════════
const LATERAL_COOLDOWN_HOURS = 6;
const LATERAL_MIN_DEVIATION  = 80;
const LATERAL_MIN_HOPS       = 3;
const LATERAL_OBS_HOURS      = 2;
const LATERAL_MAX_CASES_RUN  = 5;

let _lateralRunning = false;

async function lateralMovementMonitor() {
  if (_lateralRunning) return;
  const enabled = await db.getSetting('darksoc_lateral_monitor_enabled').catch(() => 'false');
  if (enabled !== 'true') return;

  _lateralRunning = true;
  try {
    const chains  = await ueba.detectLateralMovement(LATERAL_OBS_HOURS);
    // Both conditions must be met — prevents low-hop or low-deviation noise
    const highRisk = chains.filter(c =>
      c.deviation >= LATERAL_MIN_DEVIATION && c.hops >= LATERAL_MIN_HOPS
    );

    let casesThisRun = 0;

    for (const chain of highRisk) {
      if (casesThisRun >= LATERAL_MAX_CASES_RUN) {
        console.log('[DarkSOC Lateral] Case cap reached for this run — deferring remaining');
        break;
      }

      // Persistent cooldown check — survives restarts
      const ageHours = await db.getLateralCaseAge(chain.user).catch(() => null);
      if (ageHours !== null && ageHours < LATERAL_COOLDOWN_HOURS) {
        console.log(`[DarkSOC Lateral] Cooldown active for "${chain.user}" (${ageHours.toFixed(1)}h ago) — skipping`);
        continue;
      }

      console.log(`[DarkSOC Lateral] Detected: ${chain.user} → ${(chain.dst_hosts||[]).join(' → ')} (deviation=${chain.deviation}, hops=${chain.hops})`);

      // ── Build rich description ──────────────────────────────
      const srcHosts = (chain.src_hosts || []).join(', ') || '—';
      const dstHosts = (chain.dst_hosts || []).join(' → ') || '—';
      const hopPath  = chain.src_hosts?.length
        ? [...new Set([...chain.src_hosts, ...chain.dst_hosts])].join(' → ')
        : dstHosts;

      // Fast LangChain triage for AI summary (15s timeout — non-blocking on failure)
      let aiSummary = '';
      try {
        const headers = { 'Content-Type': 'application/json' };
        if (LANGCHAIN_TOKEN) headers['Authorization'] = `Bearer ${LANGCHAIN_TOKEN}`;
        const triageResp = await axios.post(`${LANGCHAIN_URL}/triage`, {
          message: `Lateral movement detected. User: "${chain.user}". Accessed hosts: ${dstHosts}. Deviation score: ${chain.deviation}/100. Hops: ${chain.hops}. Risk score: ${chain.risk_score || 0}. Analyze if this is insider threat, compromised account, or legitimate admin activity. Be concise.`,
        }, { headers, timeout: 15000, validateStatus: () => true });
        if (triageResp.data?.result || triageResp.data?.answer || triageResp.data?.text) {
          aiSummary = `\n\n## AI Triage Assessment\n\n${(triageResp.data.result || triageResp.data.answer || triageResp.data.text || '').slice(0, 1200)}`;
        }
      } catch { /* non-fatal — case is created even without AI summary */ }

      const description = [
        `## Lateral Movement Detected — Automated UEBA Alert`,
        ``,
        `**Dark SOC engine detected suspicious lateral movement from the UEBA graph.**`,
        `This case was created automatically. An analyst must review and classify.`,
        ``,
        `## Movement Chain`,
        ``,
        `| Field | Value |`,
        `|---|---|`,
        `| User | \`${chain.user}\` |`,
        `| Hop Path | \`${hopPath}\` |`,
        `| Source Hosts | ${srcHosts} |`,
        `| Destination Hosts | ${dstHosts} |`,
        `| Total Hops | ${chain.hops} |`,
        `| Observation Window | Last ${LATERAL_OBS_HOURS} hours |`,
        `| Detected At | ${new Date().toISOString()} |`,
        ``,
        `## Risk Scores`,
        ``,
        `| Metric | Score |`,
        `|---|---|`,
        `| Deviation Score | **${chain.deviation}/100** |`,
        `| User Risk Score (UEBA) | ${chain.risk_score || 0}/100 |`,
        `| Alert Level | 14 (Critical) |`,
        ``,
        `## MITRE ATT&CK`,
        ``,
        `| Technique | Description |`,
        `|---|---|`,
        `| T1021 | Remote Services — lateral movement via SMB, RDP, SSH, WinRM |`,
        `| T1078 | Valid Accounts — use of legitimate credentials for lateral access |`,
        `| T1550 | Use Alternate Authentication Material — pass-the-hash / pass-the-ticket |`,
        ``,
        `## Analyst Checklist`,
        ``,
        `- [ ] Verify if user \`${chain.user}\` has legitimate reason to access these hosts`,
        `- [ ] Check if movement occurred outside business hours`,
        `- [ ] Review authentication logs on destination hosts`,
        `- [ ] Determine if credentials were recently compromised`,
        `- [ ] Check for concurrent sessions from different IPs (impossible travel)`,
        `- [ ] Escalate to IR team if confirmed malicious`,
        aiSummary,
      ].join('\n');

      const synAlert = {
        ruleId:      'UEBA-LM',
        level:       14,
        severity:    'critical',
        agent:       chain.src_hosts?.[0] || chain.user,
        srcIp:       '',
        description: `Lateral movement — ${chain.user}: ${chain.hops} hops across ${(chain.dst_hosts||[]).length} hosts. Deviation: ${chain.deviation}/100`,
        mitre:       ['T1021','T1078','T1550'],
        timestamp:   new Date().toISOString(),
        _chain:      chain,
      };

      // Create TheHive case with full description
      let hiveCaseId = null;
      try {
        const caseResp = await playbook.createHiveCaseRich(synAlert, 'critical',
          `[DarkSOC] Lateral Movement — ${chain.user} (${chain.hops} hops, score ${chain.deviation})`,
          description
        );
        hiveCaseId = caseResp?.caseId || caseResp?._id || null;
      } catch(e) {
        console.warn('[DarkSOC Lateral] Case error:', e.message);
      }

      // Record in DB for persistent dedup
      const hostKey = (chain.dst_hosts||[]).sort().join('|');
      await db.recordLateralCase(chain.user, hostKey, String(hiveCaseId || '')).catch(() => {});
      casesThisRun++;

      // Fire deep investigation to n8n (async — result goes into chat history)
      axios.post(N8N_INV, {
        action:     'investigate',
        message:    `Deep investigation: User "${chain.user}" performed lateral movement across ${chain.hops} hosts (${dstHosts}) in ${LATERAL_OBS_HOURS}h. Deviation: ${chain.deviation}/100. Risk: ${chain.risk_score || 0}/100. TheHive case: ${hiveCaseId || 'N/A'}. Determine root cause, timeline, and recommend containment.`,
        alert:      synAlert,
        session_id: `lateral_${Date.now()}`,
        _user:      'dark-soc',
        _role:      'system',
      }, { timeout: 180000, validateStatus: () => true }).catch(() => {});
    }
  } catch(e) {
    if (!e.message?.includes('ECONNREFUSED')) {
      console.warn('[DarkSOC Lateral] Error:', e.message);
    }
  } finally {
    _lateralRunning = false;
  }
}

setInterval(() => { lateralMovementMonitor(); }, 30 * 60_000);  // every 30 min
setTimeout (() => { lateralMovementMonitor(); }, 3 * 60_000);   // first run 3min after boot

// ═══════════════════════════════════════════════════════════════
// ─── OTX ALIENVAULT IOC FEED SYNC (every 6 hours) ───────────────
// Fetches subscribed threat pulses from OTX and stores indicators
// in otx_ioc_feed for cross-referencing against investigations.
// ═══════════════════════════════════════════════════════════════
async function otxFeedSync() {
  if (!OTX_API_KEY) return;
  try {
    const lastSync = await db.getSetting('otx_last_sync');
    // Default to 7 days back on first run to avoid massive initial pull
    const since = lastSync
      ? new Date(lastSync).toISOString()
      : new Date(Date.now() - 7 * 86400_000).toISOString();

    let nextUrl = `https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=${since}&limit=50`;
    let pagesFetched = 0;
    let totalSaved = 0;
    const MAX_PAGES = 20;
    const MAX_IOCS  = 5000;

    while (nextUrl && pagesFetched < MAX_PAGES && totalSaved < MAX_IOCS) {
      const resp = await axios.get(nextUrl, {
        headers: { 'X-OTX-API-KEY': OTX_API_KEY },
        timeout: 30_000,
      });
      const { results = [], next } = resp.data;
      for (const pulse of results) {
        if (totalSaved >= MAX_IOCS) break;
        const tags    = pulse.tags             || [];
        const malware = (pulse.malware_families || []).map(m => typeof m === 'object' ? m.display_name || m.id : String(m));
        for (const ioc of (pulse.indicators || [])) {
          if (ioc.is_active === false) continue;
          if (totalSaved >= MAX_IOCS) break;
          await db.upsertOtxIoc({
            pulseId:         pulse.id,
            pulseName:       pulse.name || '',
            indicatorType:   ioc.type   || 'unknown',
            indicator:       String(ioc.indicator || ''),
            description:     ioc.description || pulse.description || '',
            tags,
            malwareFamilies: malware,
            threatScore:     70,
          });
          totalSaved++;
        }
      }
      pagesFetched++;
      nextUrl = next || null;
    }

    await db.setSetting('otx_last_sync', new Date().toISOString(), 'system');
    console.log(`[OTX] Feed sync complete: ${totalSaved} IOCs across ${pagesFetched} page(s)`);
  } catch (e) {
    console.error(`[OTX] Feed sync error: ${e.message}`);
  }
}

setInterval(() => { otxFeedSync(); }, 6 * 3600_000);
setTimeout (() => { otxFeedSync(); }, 5 * 60_000);   // first run 5min after boot

// ═══════════════════════════════════════════════════════════════
// ─── UEBA WEEKLY DIGEST SCHEDULER ──────────────────────────────
// Runs hourly check; generates digest if >7d since last run.
// Survives webapp restarts via ueba_last_digest_at setting.
// ═══════════════════════════════════════════════════════════════

async function uebaDigestScheduler() {
  try {
    const enabled = await db.getSetting('ueba_digest_enabled').catch(() => 'false');
    if (enabled !== 'true') return;

    const lastRun = await db.getSetting('ueba_last_digest_at').catch(() => null);
    if (lastRun) {
      const age = Date.now() - new Date(lastRun).getTime();
      if (age < 7 * 86400_000) return; // not yet 7 days
    }

    console.log('[UEBA-Digest] Generating weekly digest...');
    const now = new Date();
    const periodStart = new Date(now.getTime() - 7 * 86400_000);

    // Fetch top-20 risk users from Neo4j (no time filter — uses persisted scores)
    let topEntities = [];
    try {
      console.log('[UEBA-Digest] fetching leaderboard...');
      const lb = await ueba.getRiskLeaderboard(20, 0, 24, '', 30);
      topEntities = lb.users || [];
      console.log(`[UEBA-Digest] leaderboard: ${topEntities.length} entities`);
    } catch (e) {
      console.error('[UEBA-Digest] leaderboard fetch failed:', e.message);
    }

    // Derive anomaly summary from top-entity profiles — no extra queries needed
    const anomalySummary = {};
    try {
      const totalAnomalies = topEntities.reduce((s, e) => s + (e.anomaly_count || 0), 0);
      const criticalCount  = topEntities.filter(e => (e.risk_score || 0) >= 90).length;
      const highCount      = topEntities.filter(e => (e.risk_score || 0) >= 70 && (e.risk_score || 0) < 90).length;
      if (totalAnomalies)  anomalySummary.total_anomalies_top20_entities = totalAnomalies;
      if (criticalCount)   anomalySummary.critical_risk_entities = criticalCount;
      if (highCount)       anomalySummary.high_risk_entities = highCount;
      console.log('[UEBA-Digest] anomaly summary:', JSON.stringify(anomalySummary));
    } catch (e) {
      console.error('[UEBA-Digest] anomaly summary failed:', e.message);
    }

    // Call LangChain for LLM-generated digest
    let digestMd = null;
    let llmSuccess = true;
    let llmError = null;
    try {
      const r = await axios.post(`${LANGCHAIN_URL}/ueba/digest`, {
        top_entities: topEntities,
        anomaly_summary: anomalySummary,
        period_days: 7,
      }, { timeout: 120_000 });
      digestMd = r.data.digest_md;
    } catch (e) {
      llmSuccess = false;
      llmError = e.message;
      console.error('[UEBA-Digest] LLM call failed:', e.message);
    }

    const highRiskCount = topEntities.filter(e => (e.risk_score || 0) >= 70).length;

    // Persist to DB
    const digest = await db.createUebaDigest({
      periodStart: periodStart.toISOString(),
      periodEnd: now.toISOString(),
      digestMd,
      entityCount: topEntities.length,
      highRiskCount,
      topEntities,
      success: llmSuccess,
      error: llmError,
      emailed: false,
    });

    // Update last-run timestamp
    await db.setSetting('ueba_last_digest_at', now.toISOString(), 'system');
    console.log(`[UEBA-Digest] Saved digest #${digest.id} (${topEntities.length} entities, ${highRiskCount} high-risk)`);

    // Optional email delivery
    const emailEnabled = await db.getSetting('ueba_digest_email_enabled').catch(() => 'false');
    if (emailEnabled === 'true' && digestMd) {
      try {
        const emailHtml = `<h2>Weekly UEBA Threat Digest</h2>
<p><strong>Period:</strong> ${periodStart.toISOString().slice(0, 10)} → ${now.toISOString().slice(0, 10)}</p>
<p><strong>Entities monitored:</strong> ${topEntities.length} | <strong>High-risk:</strong> ${highRiskCount}</p>
<hr>
<pre style="font-family:monospace;white-space:pre-wrap">${digestMd}</pre>`;
        await email.sendToRecipients(`SOCPilots UEBA Weekly Digest — ${now.toISOString().slice(0, 10)}`, emailHtml);
        await db.markUebaDigestEmailed(digest.id);
        console.log('[UEBA-Digest] Email sent');
      } catch (e) {
        console.error('[UEBA-Digest] Email send failed:', e.message);
      }
    }
  } catch (e) {
    console.error('[UEBA-Digest] scheduler error:', e.message);
  }
}

setInterval(() => { uebaDigestScheduler(); }, 3600_000);       // check every hour
setTimeout (() => { uebaDigestScheduler(); }, 15 * 60_000);    // first check 15min after boot

// ═══════════════════════════════════════════════════════════════
// ─── MITRE ATT&CK AUTO-ANALYSIS WORKER (every 24 hours) ────────
// Fetches live 7d coverage, computes covered vs gap techniques,
// calls LangChain /mitre/analyze, and caches the result so the
// UI shows fresh AI intelligence on every page open without a
// manual trigger. Manual "Analyze" button also updates this cache.
// ═══════════════════════════════════════════════════════════════
async function mitreAutoAnalyzer() {
  try {
    const os = await osSearch({
      size: 0,
      query: { bool: { must: [
        { range: { '@timestamp': { gte: 'now-7d' } } },
        { exists: { field: 'rule.mitre.id' } },
      ]}},
      aggs: {
        techniques: {
          terms: { field: 'rule.mitre.id', size: 500 },
          aggs: {
            rules:     { terms: { field: 'rule.id',       size: 20 } },
            agents:    { terms: { field: 'agent.name',    size: 20 } },
            max_level: { max:   { field: 'rule.level' } },
          },
        },
        top_agents: { terms: { field: 'agent.name', size: 20 } },
      },
    });

    const covMap = {};
    for (const b of (os.aggregations?.techniques?.buckets || [])) {
      covMap[b.key] = {
        count:  b.doc_count,
        rules:  b.rules?.buckets?.map(x => x.key) || [],
        agents: b.agents?.buckets?.map(x => x.key) || [],
        score:  Math.round(b.max_level?.value || 0),
      };
    }

    const covered = [], gaps = [];
    for (const [id, name, tacticIds] of _MITRE_TECHS_LIST) {
      const tactics = tacticIds.map(tid => _MITRE_TACTICS_MAP[tid] || tid);
      const d = covMap[id];
      if (d && d.count > 0) {
        covered.push({ id: String(id).replace(/[^A-Z0-9.]/gi, ''), name: String(name).slice(0, 80),
          tactics: tactics.slice(0, 3), count: d.count, score: d.score, rule_count: d.rules.length });
      } else {
        gaps.push({ id: String(id).replace(/[^A-Z0-9.]/gi, ''), name: String(name).slice(0, 80), tactics: tactics.slice(0, 3) });
      }
    }

    const allAgents = (os.aggregations?.top_agents?.buckets || []).map(b => b.key);
    const logSources = _logSourcesCache
      ? [...new Set((_logSourcesCache.sources || []).map(s => s.type).filter(Boolean))].slice(0, 10)
      : [];
    const totalTechs = _MITRE_TECHS_LIST.length;

    const result = await _runMitreAnalysis({
      covered_techniques: covered.slice(0, 100),
      gap_techniques:     gaps.slice(0, 150),
      log_sources:        logSources,
      agents:             allAgents.slice(0, 20).map(a => String(a).slice(0, 50)),
      summary: {
        total_techniques: totalTechs,
        covered_count:    covered.length,
        gap_count:        gaps.length,
        coverage_pct:     totalTechs ? Math.round(covered.length / totalTechs * 100) : 0,
      },
    });
    _mitreAutoAnalysis = { result, last_analyzed_at: Date.now(), source: 'auto', timeframe: '7d' };
    console.log(`[mitre-auto-analyze] Done — ${covered.length} covered, ${gaps.length} gaps`);
  } catch (e) {
    console.error('[mitre-auto-analyze]', e.message);
  }
}
setInterval(() => { mitreAutoAnalyzer(); }, 24 * 3600_000);
setTimeout (() => { mitreAutoAnalyzer(); }, 10 * 60_000);  // first run 10min after boot

// ═══════════════════════════════════════════════════════════════
// ─── LOG SOURCES AUTO-ANALYSIS WORKER (every 24 hours) ─────────
// Ensures the log source inventory is fresh, routes anomalous /
// unknown sources through the LangChain multi-LLM pipeline, and
// caches the enriched result for instant display on page load.
// ═══════════════════════════════════════════════════════════════
async function logSourcesAutoAnalyzer() {
  try {
    // Refresh source inventory if cache is missing or older than 1 hour
    if (!_logSourcesCache || Date.now() - _logSourcesCacheTime > 3600_000) {
      await _fetchLogSources();
    }
    if (!_logSourcesCache?.sources?.length) {
      console.log('[log-sources-auto-analyze] No sources available — skipping');
      return;
    }
    const sources = _logSourcesCache.sources;
    const toAnalyze = sources.filter(s => s.type === 'unknown' || s.anomaly || s.is_new || s.vendor === 'unknown');
    const payload = toAnalyze.length > 0 ? toAnalyze : sources.slice(0, 10);
    const result = await _runLogSourcesAnalysis(payload);
    _logSourcesAutoAnalysis = { result, last_analyzed_at: Date.now(), source: 'auto' };
    console.log(`[log-sources-auto-analyze] Done — ${result.sources_analyzed || 0} sources analyzed`);
  } catch (e) {
    console.error('[log-sources-auto-analyze]', e.message);
  }
}
setInterval(() => { logSourcesAutoAnalyzer(); }, 24 * 3600_000);
setTimeout (() => { logSourcesAutoAnalyzer(); }, 13 * 60_000);  // first run 13min after boot (staggered from MITRE)

// ═══════════════════════════════════════════════════════════════
// ─── LOG SOURCE SILENCE MONITOR (every 30 minutes) ─────────────
// Alerts when a log source stops sending events. Cloud API sources
// (e.g. Cloudflare, Azure) have wider tolerances than agent sources.
// Deduplicates via the notifications table to survive restarts.
// ═══════════════════════════════════════════════════════════════
async function logSourceSilenceMonitor() {
  try {
    const data = await _fetchLogSources();
    if (!data?.sources?.length) return;
    const now = Date.now();
    for (const src of data.sources) {
      if (!src.last_seen) continue;  // never seen — can't assess silence
      const ageHrs = (now - new Date(src.last_seen).getTime()) / 3600000;
      const isCloud = src.source_id?.startsWith('grp:');
      // Cloud API integrations tolerate longer gaps due to infrequent polling
      const warnHrs = isCloud ? 24 : 6;
      const critHrs = isCloud ? 72 : 24;
      if (ageHrs < warnHrs) continue;
      const sev      = ageHrs >= critHrs ? 'critical' : 'warning';
      const dedupHrs = sev === 'critical' ? 24 : 6;
      const already  = await db.recentNotificationExists('log_source_silent', { source_id: src.source_id }, dedupHrs);
      if (already) continue;
      const hrs     = Math.round(ageHrs);
      const title   = `Log Source Silent: ${src.source_name}`;
      const message = `No logs received from ${src.source_name} for ${hrs}h (last seen: ${src.last_seen})`;
      await db.createNotification('log_source_silent', title, message, sev, null, {
        source_id: src.source_id, source_name: src.source_name, last_seen: src.last_seen, age_hours: hrs,
      }).catch(() => {});
      io.emit('log_source:silent', {
        source_id: src.source_id, source_name: src.source_name,
        last_seen: src.last_seen, age_hours: hrs, severity: sev,
      });
      console.log(`[log-source-silence] ${sev.toUpperCase()} — ${src.source_name} silent for ${hrs}h`);
    }
  } catch (e) {
    console.error('[log-source-silence]', e.message);
  }
}
setInterval(() => { logSourceSilenceMonitor(); }, 30 * 60_000);
setTimeout (() => { logSourceSilenceMonitor(); }, 20 * 60_000);  // first run 20min after boot

// ═══════════════════════════════════════════════════════════════
// ─── AGENT DOWN MONITOR (every 30 minutes) ──────────────────────
// Detects Wazuh agents that have stopped sending any logs.
// Warning: silent >6h | Critical: silent >24h (or never seen).
// ═══════════════════════════════════════════════════════════════
async function agentDownMonitor() {
  try {
    const r = await osSearch({
      size: 0,
      aggs: {
        agents: {
          terms: { field: 'agent.name', size: 500 },
          aggs: {
            id:   { terms: { field: 'agent.id', size: 1 } },
            last: { max: { field: '@timestamp' } },
          },
        },
      },
    });
    const EXCLUDE = new Set(['wazuh.manager', 'wazuh-manager', 'manager']);
    const now = Date.now();
    for (const b of (r.aggregations?.agents?.buckets || [])) {
      if (EXCLUDE.has((b.key || '').toLowerCase())) continue;
      const lastMs  = b.last?.value || 0;
      const ageMs   = lastMs > 0 ? now - lastMs : Infinity;
      const ageHrs  = ageMs / 3600000;
      if (ageHrs < 6) continue;  // agent healthy
      const sev       = ageHrs >= 24 ? 'critical' : 'warning';
      const agentName = b.key;
      const agentId   = b.id?.buckets?.[0]?.key || 'unknown';
      const dedupHrs  = sev === 'critical' ? 24 : 6;
      const already   = await db.recentNotificationExists('agent_down', { agent_name: agentName }, dedupHrs);
      if (already) continue;
      const hrs     = lastMs > 0 ? Math.round(ageHrs) : null;
      const lastStr = lastMs > 0 ? new Date(lastMs).toISOString() : null;
      const title   = `Agent Down: ${agentName}`;
      const message = hrs !== null
        ? `Agent ${agentName} (ID: ${agentId}) has not sent logs for ${hrs}h`
        : `Agent ${agentName} (ID: ${agentId}) has never sent any logs`;
      await db.createNotification('agent_down', title, message, sev, null, {
        agent_name: agentName, agent_id: agentId, last_seen: lastStr, age_hours: hrs,
      }).catch(() => {});
      io.emit('agent:down', {
        agent_name: agentName, agent_id: agentId,
        severity: sev, age_hours: hrs, last_seen: lastStr,
      });
      console.log(`[agent-down] ${sev.toUpperCase()} — ${agentName} silent for ${hrs ?? '∞'}h`);
    }
  } catch (e) {
    console.error('[agent-down]', e.message);
  }
}
setInterval(() => { agentDownMonitor(); }, 30 * 60_000);
setTimeout (() => { agentDownMonitor(); }, 22 * 60_000);  // first run 22min after boot

// ═══════════════════════════════════════════════════════════════
// ─── DARK SOC — APPROVAL EXPIRY WORKER (every 2 minutes) ───────
// Scans isolation_approvals for any that have passed their expiry
// time and auto-rejects them (marks as expired, no isolation fired).
// ═══════════════════════════════════════════════════════════════
setInterval(() => { playbook.expireStaleApprovals(); }, 2 * 60_000);

// ═══════════════════════════════════════════════════════════════
// ─── PROTECTED ASSETS API ───────────────────────────────────────
// Manage the list of hosts that require special handling before
// auto-isolation. Tier: critical | protected | standard
// ═══════════════════════════════════════════════════════════════

// GET /api/protected-assets — list all protected hosts
app.get('/api/protected-assets', authMW, async (req, res) => {
  try {
    const rows = await db.listProtectedAssets();
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/protected-assets — add a host to the protected list
app.post('/api/protected-assets', authMW, adminOnly, async (req, res) => {
  const { identifier, label, tier, note } = req.body || {};
  if (!identifier) return res.status(400).json({ error: 'identifier required (hostname, agent name, or IP)' });
  try {
    const row = await db.addProtectedAsset({ identifier, label, tier, note });
    res.json(row);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PATCH /api/protected-assets/:id — update tier / label / note
app.patch('/api/protected-assets/:id', authMW, adminOnly, async (req, res) => {
  const { label, tier, note } = req.body || {};
  try {
    const row = await db.updateProtectedAsset(req.params.id, { label, tier, note });
    if (!row) return res.status(404).json({ error: 'not found' });
    res.json(row);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/protected-assets/:id — remove a host from the protected list
app.delete('/api/protected-assets/:id', authMW, adminOnly, async (req, res) => {
  try {
    await db.deleteProtectedAsset(req.params.id);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
// ─── ISOLATION APPROVALS API ────────────────────────────────────
// Analysts use these routes to review pending isolation requests
// and approve or reject them. Approved → immediate Wazuh isolate.
// ═══════════════════════════════════════════════════════════════

// GET /api/isolation-approvals — list pending (and recently resolved) approvals
app.get('/api/isolation-approvals', authMW, async (req, res) => {
  try {
    const status = req.query.status || null;
    const rows = await db.listIsolationApprovals({ status });
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/isolation-approvals/:id/approve
// Analyst approves → system immediately executes Wazuh isolate_host
app.post('/api/isolation-approvals/:id/approve', authMW, async (req, res) => {
  const { id } = req.params;
  const analyst = req.user?.username || 'analyst';
  const note = req.body?.note || '';
  try {
    const appr = await db.getIsolationApproval(id);
    if (!appr) return res.status(404).json({ error: 'Approval record not found' });
    if (appr.status !== 'pending') return res.status(409).json({ error: `Approval already ${appr.status}` });
    if (new Date(appr.expires_at) < new Date()) {
      await db.resolveIsolationApproval(id, { status: 'expired', resolvedBy: analyst, resolveNote: 'Expired before approval was processed.' });
      return res.status(410).json({ error: 'Approval window has expired — isolation cannot proceed' });
    }

    // Mark as approved first (so UI shows status immediately)
    await db.resolveIsolationApproval(id, { status: 'approved', resolvedBy: analyst, resolveNote: note });

    // Execute the actual isolation
    const isolResult = await playbook.executeIsolationNow({ ...appr, resolved_by: analyst });

    // Update to executed (or back to approved if it failed)
    const finalStatus = isolResult.success ? 'executed' : 'approved';
    if (finalStatus === 'executed') {
      await db.resolveIsolationApproval(id, {
        status: 'executed', resolvedBy: analyst,
        resolveNote: `${note} | Isolation result: ${isolResult.detail}`,
      });
    }

    res.json({
      ok: isolResult.success,
      approval_id: id,
      agent: appr.agent,
      isolation: isolResult,
      resolved_by: analyst,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/isolation-approvals/:id/reject
// Analyst rejects — no isolation is performed
app.post('/api/isolation-approvals/:id/reject', authMW, async (req, res) => {
  const { id } = req.params;
  const analyst = req.user?.username || 'analyst';
  const note = req.body?.note || 'Manually rejected by analyst';
  try {
    const appr = await db.getIsolationApproval(id);
    if (!appr) return res.status(404).json({ error: 'Approval record not found' });
    if (appr.status !== 'pending') return res.status(409).json({ error: `Approval already ${appr.status}` });

    await db.resolveIsolationApproval(id, { status: 'rejected', resolvedBy: analyst, resolveNote: note });
    res.json({ ok: true, approval_id: id, agent: appr.agent, resolved_by: analyst });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DETECTION RULES via n8n ──
app.get('/api/detection-rules', authMW, async (req, res) => {
  const r = await n8nAsk(
    'Use Wazuh MCP to list detection rules. Return JSON array: [{"id":"5710","level":8,"description":"SSH brute force","groups":"syslog,sshd","mitre":"T1110"}]',
    'soc-det-rules', req.user
  );
  if (!r.ok) return res.status(502).json({ error: 'n8n unavailable' });
  let rules = [];
  if (r.text) {
    const clean = r.text.replace(/```json\n?/g,'').replace(/```\n?/g,'').trim();
    try { const p = JSON.parse(clean); rules = Array.isArray(p) ? p : p.rules || []; }
    catch (e) { const m = clean.match(/\[[\s\S]*\]/); if (m) try { rules = JSON.parse(m[0]); } catch(e2) {} }
  }
  res.json({ rules, total: rules.length, rawText: rules.length ? undefined : r.text });
});

// ── REPORTS via SOCPilots AI ──
app.get('/api/reports/summary', authMW, async (req, res) => {
  const r = await n8nAsk(
    'Generate a professional SOC executive summary report for today. ' +
    'Use Wazuh MCP for alert data and SP-CM MCP for case data. Include: ' +
    '1) Alert volume and severity breakdown, 2) Top threats and MITRE techniques, ' +
    '3) Critical incidents requiring attention, 4) Case management status, ' +
    '5) Recommended immediate actions. Be concise and professional.',
    'soc-report', req.user
  );
  res.json({ text: r.text, ok: r.ok });
});

// ── Wazuh agent helpers used by scanner enrichment ─────────────
async function getWazuhAgentMap() {
  try {
    const r = await osSearch({
      size: 0,
      aggs: {
        agents: {
          terms: { field: 'agent.name', size: 500 },
          aggs: {
            id:      { terms: { field: 'agent.id',          size: 1 } },
            ip:      { terms: { field: 'agent.ip',          size: 1 } },
            os_name: { terms: { field: 'agent.os.name',     size: 1 } },
            os_plat: { terms: { field: 'agent.os.platform', size: 1 } },
            last:    { max:   { field: '@timestamp' } },
          },
        },
      },
    });
    const now = Date.now();
    const map = {};
    for (const b of (r.aggregations?.agents?.buckets || [])) {
      const agentIp = b.ip?.buckets?.[0]?.key;
      if (!agentIp) continue;
      const lastMs  = b.last?.value || 0;
      const diffHrs = lastMs > 0 ? (now - lastMs) / 3600000 : Infinity;
      const status  = lastMs === 0 ? 'disconnected' : diffHrs < 24 ? 'active' : 'inactive';
      const os_name = b.os_name?.buckets?.[0]?.key || b.os_plat?.buckets?.[0]?.key || '';
      map[agentIp] = { id: b.id?.buckets?.[0]?.key || '', name: b.key, status, os_name };
    }
    return map;
  } catch { return {}; }
}
function matchWazuhByHostname(agentMap, hostname) {
  if (!hostname) return null;
  const h = hostname.toLowerCase().split('.')[0];
  return Object.values(agentMap).find(a => a.name.toLowerCase().startsWith(h)) || null;
}

// ═══════════════════════════════════════════════════════════════
// ─── ASSET DISCOVERY ───────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════

app.get('/api/subnets', authMW, async (req, res) => {
  try {
    const subnets = await db.listSubnets();
    res.json({ subnets });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/subnets', authMW, async (req, res) => {
  const { cidr, label } = req.body;
  if (!cidr) return res.status(400).json({ error: 'cidr required' });
  // Basic CIDR validation
  if (!/^[\d.:/]+$/.test(cidr.trim())) return res.status(400).json({ error: 'invalid cidr format' });
  try {
    const subnet = await db.addSubnet(cidr, label || '');
    res.json({ subnet });
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ error: 'subnet already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/subnets/:id', authMW, async (req, res) => {
  try {
    await db.deleteSubnet(req.params.id);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/assets', authMW, async (req, res) => {
  try {
    const { status, q } = req.query;
    const page      = parseInt(req.query.page)      || 1;
    const page_size = Math.min(parseInt(req.query.page_size) || parseInt(req.query.limit) || 50, 500);
    const [{ rows: assets, total }, stats] = await Promise.all([
      db.listAssets({ status, q, page, page_size }),
      db.getAssetStats(),
    ]);
    res.json({ assets, stats, total, page, page_size, has_more: page * page_size < total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/assets/sync-agents', authMW, async (req, res) => {
  try {
    const agentMap = await getWazuhAgentMap();
    await db.bulkUpdateWazuhAgents(agentMap);
    // Also backfill hostnames from agent names for assets that have none
    await db.backfillHostnamesFromAgents();
    res.json({ ok: true, agents_synced: Object.keys(agentMap).length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/assets/resolve-hostnames
// Immediately fixes NULL hostnames in DB using:
//   1. Wazuh agent name (from wazuh_agents_cache matched by IP)
//   2. Reverse DNS lookup via the asset-scanner service
app.post('/api/assets/resolve-hostnames', authMW, async (req, res) => {
  try {
    // Step 1: Wazuh agent name backfill (fast, no network call)
    const wazuhFilled = await db.backfillHostnamesFromAgents();

    // Step 2: Ask asset-scanner to run rdns on remaining nulls
    let rdnsFilled = 0;
    try {
      const r = await axios.post(`${SCANNER_URL}/resolve-hostnames`, {}, { timeout: 60_000 });
      rdnsFilled = r.data?.resolved || 0;
    } catch (scanErr) {
      console.warn('[RESOLVE] Scanner rdns call failed:', scanErr.message);
    }

    res.json({ ok: true, wazuh_filled: wazuhFilled, rdns_filled: rdnsFilled });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/assets/scan/status', authMW, async (req, res) => {
  try {
    const job = await db.getLatestScanJob();
    res.json({ job });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/assets/scan', authMW, async (req, res) => {
  try {
    const subnets = await db.listSubnets();
    const enabled = subnets.filter(s => s.enabled).map(s => s.cidr);
    if (!enabled.length) return res.status(400).json({ error: 'No enabled subnets configured' });

    const existing = await db.getLatestScanJob();
    if (existing?.status === 'running') return res.status(409).json({ error: 'Scan already in progress' });

    const job = await db.createScanJob(enabled, req.user.username);
    res.json({ job });

    // Run scan async — don't await in request handler
    (async () => {
      try {
        console.log(`[SCAN] Starting job ${job.id} on subnets: ${enabled.join(', ')}`);
        const resp = await axios.post(`${SCANNER_URL}/scan`, { subnets: enabled }, { timeout: 310_000 });
        const hosts = resp.data?.hosts || [];

        // Fetch Wazuh agents for cross-reference
        const wazuhAgentMap = await getWazuhAgentMap();

        for (const host of hosts) {
          const matchedSubnet = subnets.find(s => ipInSubnet(host.ip, s.cidr));
          const wazuhAgent    = wazuhAgentMap[host.ip] || matchWazuhByHostname(wazuhAgentMap, host.hostname);
          // scanner returns { os, ports } — db expects { os_guess, open_ports }
          const osGuess = host.os_guess || host.os || wazuhAgent?.os_name || null;
          // Use Wazuh agent name as hostname fallback — agents always register
          // with their real machine hostname (fills the gap when nmap/rdns fails)
          const hostname = host.hostname || wazuhAgent?.name || null;
          await db.upsertAsset({
            ip:                 host.ip,
            hostname,
            mac:                host.mac      || null,
            vendor:             host.vendor   || null,
            os_guess:           osGuess,
            open_ports:         host.open_ports || host.ports || [],
            subnet_id:          matchedSubnet?.id || null,
            wazuh_agent_id:     wazuhAgent?.id     || null,
            wazuh_agent_name:   wazuhAgent?.name   || null,
            wazuh_agent_status: wazuhAgent?.status || null,
          });
        }
        await db.finishScanJob(job.id, hosts.length, null);
        console.log(`[SCAN] Job ${job.id} complete — ${hosts.length} hosts, ${Object.keys(wazuhAgentMap).length} Wazuh agents`);
        db.createSystemEvent('scan', job.started_by || 'system', `Asset scan completed: ${hosts.length} hosts discovered`, 'ok', { job_id: job.id, hosts_found: hosts.length }).catch(() => {});
      } catch(e) {
        console.error(`[SCAN] Job ${job.id} failed:`, e.message);
        await db.finishScanJob(job.id, 0, e.message);
        db.createSystemEvent('scan', job.started_by || 'system', `Asset scan failed: ${e.message}`, 'fail', { job_id: job.id }).catch(() => {});
      }
    })();
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Simple IP-in-subnet check (supports /8 to /32)
function ipInSubnet(ip, cidr) {
  try {
    if (!cidr.includes('/')) return ip === cidr;
    const [base, bits] = cidr.split('/');
    const mask = ~0 << (32 - parseInt(bits));
    const ipNum  = ip.split('.').reduce((a, o) => (a << 8) | parseInt(o), 0);
    const baseNum = base.split('.').reduce((a, o) => (a << 8) | parseInt(o), 0);
    return (ipNum & mask) === (baseNum & mask);
  } catch { return false; }
}

// ═══════════════════════════════════════════════════════════════
// ─── UEBA (Neo4j Graph Analytics) ──────────────────────────────
// ═══════════════════════════════════════════════════════════════

app.post('/api/ueba/event', authMW, async (req, res) => {
  try {
    await ueba.ingestEvent(req.body);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ueba/anomalies', authMW, async (req, res) => {
  try {
    const hours = Math.min(parseInt(req.query.hours || '24') || 24, 720);
    const timeout = new Promise((_,rej) => setTimeout(() => rej(new Error('timeout')), 30000));
    const data = await Promise.race([ueba.getAllAnomalies(hours), timeout]);
    res.json(data);
  } catch(e) {
    console.error('[ueba/anomalies]', e.message);
    // Return empty structure so the UI renders "no data" cards rather than spinning
    res.json({
      lateral_movement: [], impossible_travel: [], privilege_escalation: [],
      after_hours_access: [], high_frequency_logins: [], rare_processes: [],
      new_connections: [], multi_stage_attacks: [], shared_credentials: [],
    });
  }
});

app.get('/api/ueba/graph/:entity', authMW, async (req, res) => {
  try {
    const edges = await ueba.getEntityGraph(req.params.entity);
    res.json({ edges });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ueba/stats', authMW, async (req, res) => {
  try {
    const stats = await ueba.getUebaStats();
    res.json({ stats });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ueba/recalc', authMW, requireRole('admin'), async (req, res) => {
  try {
    const result = await ueba.backfillRiskScores();
    res.json({ ok: true, ...result });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
// ─── LANGCHAIN AGENT PROXY ─────────────────────────────────────
// ═══════════════════════════════════════════════════════════════

app.get('/api/langchain/health', authMW, async (req, res) => {
  try {
    const r = await axios.get(`${LANGCHAIN_URL}/health`, { timeout: 5_000 });
    res.json(r.data);
  } catch(e) {
    res.status(502).json({ status: 'offline', error: e.message });
  }
});

app.post('/api/langchain/investigate', authMW, async (req, res) => {
  try {
    const r = await axios.post(`${LANGCHAIN_URL}/investigate`, req.body, {
      timeout: 180_000,
      headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` },
    });
    res.json(r.data);
  } catch(e) {
    const msg = e.response?.data?.detail || e.message;
    res.status(502).json({ error: `LangChain agent error: ${msg}` });
  }
});

app.post('/api/langchain/triage', authMW, async (req, res) => {
  try {
    const r = await axios.post(`${LANGCHAIN_URL}/triage`, req.body, {
      timeout: 30_000,
      headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` },
    });
    res.json(r.data);
  } catch(e) {
    const msg = e.response?.data?.detail || e.message;
    res.status(502).json({ error: `LangChain triage error: ${msg}` });
  }
});

// ── DIRECT IOC ENRICHMENT — proxies to LangChain agent (Redis-cached) ──
app.post('/api/langchain/enrich', authMW, async (req, res) => {
  try {
    const r = await axios.post(`${LANGCHAIN_URL}/enrich`, req.body, {
      timeout: 30_000,
      headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` },
    });
    res.json(r.data);
  } catch(e) {
    const msg = e.response?.data?.detail || e.message;
    res.status(502).json({ error: `Enrichment error: ${msg}` });
  }
});

// ── AI HUNT QUERIES ──
app.post('/api/langchain/hunt-queries', authMW, async (req, res) => {
  try {
    const r = await axios.post(`${LANGCHAIN_URL}/hunt-queries`, req.body, {
      timeout: 60_000,
      headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` },
    });
    res.json(r.data);
  } catch(e) {
    const msg = e.response?.data?.detail || e.message;
    res.status(502).json({ error: `Hunt queries error: ${msg}` });
  }
});

// ── RAG / Vector Search endpoints ──────────────────────────────
const RAG_HEADERS = () => process.env.RAG_API_KEY ? { 'X-API-Key': process.env.RAG_API_KEY } : {};

app.post('/api/investigation/search-similar', authMW, async (req, res) => {
  try {
    const r = await axios.post(`${RAG_URL}/search/investigation`, req.body, { timeout: 15_000, headers: RAG_HEADERS() });
    res.json(r.data);
  } catch(e) {
    res.status(502).json({ error: `RAG investigation search failed: ${e.message}` });
  }
});

app.post('/api/hunting/search-patterns', authMW, async (req, res) => {
  try {
    const r = await axios.post(`${RAG_URL}/search/hunting`, req.body, { timeout: 15_000, headers: RAG_HEADERS() });
    res.json(r.data);
  } catch(e) {
    res.status(502).json({ error: `RAG hunting search failed: ${e.message}` });
  }
});

app.post('/api/ueba/analyze-anomaly', authMW, async (req, res) => {
  try {
    const { entity } = req.body;
    if (!entity) return res.status(400).json({ error: 'entity required' });

    // Fetch UEBA profile and behavioral baseline in parallel
    const [profile, fp] = await Promise.all([
      ueba.getUserProfile(entity).catch(() => null),
      ueba.assessEntityFP(entity).catch(() => null),
    ]);
    if (!profile) return res.status(404).json({ error: `Entity "${entity}" not found in UEBA graph` });

    // Call LangChain agent for direct LLM explanation (Mistral, no agent loop)
    const llmResp = await axios.post(
      `${LANGCHAIN_URL}/ueba/explain`,
      { entity, profile, fp_assessment: fp || null },
      { timeout: 30_000, headers: LANGCHAIN_TOKEN ? { Authorization: `Bearer ${LANGCHAIN_TOKEN}` } : {} }
    );

    res.json({
      explanation:   llmResp.data.explanation,
      entity,
      risk_score:    profile.risk_score,
      anomaly_count: profile.anomaly_count,
      profile,
      fp_assessment: fp || null,
    });
  } catch(e) {
    console.error('[ueba/analyze-anomaly]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/ueba/leaderboard', authMW, async (req, res) => {
  try {
    const page      = Math.max(parseInt(req.query.page) || 1, 1);
    const page_size = Math.min(parseInt(req.query.page_size) || parseInt(req.query.limit) || 20, 200);
    const hours     = Math.min(parseInt(req.query.hours || '24') || 24, 720);
    const q         = (req.query.q || '').trim().slice(0, 100);
    const min_score = Math.max(0, Math.min(100, parseInt(req.query.min_score || '0') || 0));
    const skip      = (page - 1) * page_size;
    const { users, total } = await ueba.getRiskLeaderboard(page_size, skip, hours, q, min_score);
    res.json({ users, total, page, page_size, hours, has_more: page * page_size < total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ueba/profile/:user', authMW, async (req, res) => {
  try {
    const profile = await ueba.getUserProfile(req.params.user);
    if (!profile) return res.status(404).json({ error: 'User not found in graph' });
    res.json({ profile });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ueba/correlations', authMW, async (req, res) => {
  try {
    const hours = parseInt(req.query.hours || '24');
    const withTimeout = (p, ms = 8000) =>
      Promise.race([p, new Promise(res => setTimeout(() => res([]), ms))]);
    const [multi_stage, shared_credentials] = await Promise.all([
      withTimeout(ueba.detectMultiStageAttack(hours)),
      withTimeout(ueba.detectSharedCredentials(hours)),
    ]);
    res.json({ multi_stage_attacks: multi_stage, shared_credentials });
  } catch(e) {
    console.error('[ueba/correlations]', e.message);
    res.json({ multi_stage_attacks: [], shared_credentials: [] });
  }
});

app.get('/api/ueba/graph-nodes/:entity', authMW, async (req, res) => {
  try {
    const data = await ueba.getGraphNodes(req.params.entity);
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ueba/path', authMW, async (req, res) => {
  try {
    const { from, to } = req.query;
    if (!from || !to) return res.status(400).json({ error: 'from and to query params required' });
    const path = await ueba.getAttackPath(from.trim(), to.trim());
    if (!path) return res.json({ found: false, from, to, message: 'No path found between these entities' });
    res.json({ found: true, ...path });
  } catch (e) {
    console.error('[ueba/path]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/ueba/baseline/:entity', authMW, async (req, res) => {
  try {
    const entity = req.params.entity.trim().slice(0, 200);
    const baseline = await ueba.computeEntityBaseline(entity);
    if (!baseline) return res.json({ entity, has_baseline: false, message: 'Entity not found in UEBA graph' });
    const fp = await ueba.assessEntityFP(entity);
    res.json({ entity, has_baseline: true, ...baseline, fp_assessment: fp });
  } catch (e) {
    console.error('[ueba/baseline]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── UEBA Digests ──────────────────────────────────────────────
app.get('/api/ueba/digests', authMW, async (req, res) => {
  try {
    const page      = Math.max(1, parseInt(req.query.page) || 1);
    const page_size = Math.min(50, Math.max(1, parseInt(req.query.page_size) || 10));
    const { rows, total } = await db.listUebaDigests(page, page_size);
    res.json({ items: rows, total, page, page_size, has_more: page * page_size < total });
  } catch (e) {
    console.error('[ueba/digests]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/ueba/digest/latest', authMW, async (req, res) => {
  try {
    const digest = await db.getLatestUebaDigest();
    res.json(digest || {});
  } catch (e) {
    console.error('[ueba/digest/latest]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/ueba/digest/:id', authMW, async (req, res) => {
  try {
    const digest = await db.getUebaDigest(parseInt(req.params.id));
    if (!digest) return res.status(404).json({ error: 'Not found' });
    res.json(digest);
  } catch (e) {
    console.error('[ueba/digest]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/ueba/digest/generate', authMW, requireRole('admin'), async (req, res) => {
  try {
    // Reset last-run timestamp so scheduler fires immediately
    await db.setSetting('ueba_digest_enabled', 'true', req.user.username);
    await db.setSetting('ueba_last_digest_at', '', req.user.username);
    res.json({ ok: true, message: 'UEBA digest generation triggered — check digests in a moment' });
    setImmediate(() => uebaDigestScheduler());
  } catch (e) {
    console.error('[ueba/digest/generate]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// ─── USERS API (admin only) ─────────────────────────────────────
// ═══════════════════════════════════════════════════════════════

app.get('/api/users', authMW, requireRole('admin'), async (req, res) => {
  try {
    const users = await db.listUsers();
    res.json({ users, total: users.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users', authMW, requireRole('admin'), async (req, res) => {
  const { username, password, role, display_name, email } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'valid email address required' });
  const validRoles = ['admin', 'l3', 'l2', 'l1'];
  if (role && !validRoles.includes(role)) return res.status(400).json({ error: 'invalid role' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const user = await db.createUser(username.toLowerCase().trim(), hash, role || 'l1', display_name || username, email || null);
    if (!user) return res.status(409).json({ error: 'username already exists' });
    res.json({ user });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/users/:id', authMW, requireRole('admin'), async (req, res) => {
  const { role, display_name, email, active } = req.body || {};
  try {
    const updated = await db.updateUser(parseInt(req.params.id), { role, display_name, email, active });
    if (!updated) return res.status(404).json({ error: 'user not found' });
    res.json({ user: updated });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', authMW, requireRole('admin'), async (req, res) => {
  try {
    const users = await db.listUsers();
    const target = users.find(u => u.id === parseInt(req.params.id));
    if (!target) return res.status(404).json({ error: 'user not found' });
    if (target.username === req.user.username) return res.status(400).json({ error: 'cannot delete yourself' });
    await db.deleteUser(parseInt(req.params.id));
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users/:id/password', authMW, async (req, res) => {
  const targetId = parseInt(req.params.id);
  const { password } = req.body || {};
  if (!password || password.length < 6) return res.status(400).json({ error: 'password must be at least 6 characters' });
  // Admin can reset anyone's password; users can only reset their own
  try {
    const users = await db.listUsers();
    const target = users.find(u => u.id === targetId);
    if (!target) return res.status(404).json({ error: 'user not found' });
    const isAdmin = (ROLE_HIERARCHY[req.user.role] || 0) >= ROLE_HIERARCHY.admin;
    const isSelf  = target.username === req.user.username;
    if (!isAdmin && !isSelf) return res.status(403).json({ error: 'Insufficient permissions' });
    const hash = bcrypt.hashSync(password, 10);
    await db.updateUserPassword(targetId, hash);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
// ─── NOTIFICATIONS API ──────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════

app.get('/api/notifications', authMW, async (req, res) => {
  try {
    const page       = Math.max(parseInt(req.query.page) || 1, 1);
    const page_size  = Math.min(parseInt(req.query.page_size) || 50, 200);
    const unreadOnly = req.query.unread === 'true';
    const { rows, total } = await db.listNotifications(
      req.user.username, page_size, (page - 1) * page_size, unreadOnly
    );
    res.json({ notifications: rows, total, page, page_size, has_more: page * page_size < total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/notifications/count', authMW, async (req, res) => {
  try {
    const unread = await db.countUnreadNotifications(req.user.username);
    res.json({ unread });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/notifications/read-all', authMW, async (req, res) => {
  try {
    const count = await db.markAllNotificationsRead(req.user.username);
    res.json({ ok: true, marked: count });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/notifications/:id/read', authMW, async (req, res) => {
  try {
    const result = await db.markNotificationRead(parseInt(req.params.id), req.user.username);
    if (!result) return res.status(404).json({ error: 'notification not found' });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
// ─── CHAT HISTORY API ───────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════

app.get('/api/chat/sessions', authMW, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const sessions = await db.listUserSessions(req.user.username, limit);
    res.json({ sessions, total: sessions.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/chat/sessions/:sid', authMW, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const messages = await db.getChatHistory(req.params.sid, limit);
    res.json({ messages, total: messages.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/chat/sessions/:sid', authMW, async (req, res) => {
  try {
    const deleted = await db.deleteSession(req.params.sid, req.user.username);
    res.json({ ok: true, deleted });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
// ─── HUNT SCHEDULES API ─────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════

app.get('/api/hunt/schedules', authMW, async (req, res) => {
  try {
    const page      = parseInt(req.query.page)      || 1;
    const page_size = Math.min(parseInt(req.query.page_size) || parseInt(req.query.limit) || 50, 200);
    const { rows: schedules, total } = await db.listHuntSchedules({ page, page_size });
    res.json({ schedules, total, page, page_size, has_more: page * page_size < total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/hunt/schedules', authMW, requireRole('l2'), async (req, res) => {
  const { name, query, cron_expr } = req.body || {};
  if (!name || !query) return res.status(400).json({ error: 'name and query required' });
  try {
    const schedule = await db.createHuntSchedule(name, query, cron_expr || '0 */6 * * *', req.user.username);
    res.json({ schedule });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/hunt/schedules/:id', authMW, requireRole('l2'), async (req, res) => {
  try {
    const updated = await db.updateHuntSchedule(parseInt(req.params.id), req.body);
    if (!updated) return res.status(404).json({ error: 'schedule not found' });
    res.json({ schedule: updated });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/hunt/schedules/:id', authMW, requireRole('l2'), async (req, res) => {
  try {
    await db.pool.query(`DELETE FROM hunt_schedules WHERE id=$1`, [parseInt(req.params.id)]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/hunt/schedules/:id/run', authMW, requireRole('l2'), async (req, res) => {
  try {
    const { rows: schedules } = await db.listHuntSchedules({ limit: 1000 });
    const sched = schedules.find(s => s.id === parseInt(req.params.id));
    if (!sched) return res.status(404).json({ error: 'schedule not found' });
    res.json({ ok: true, message: 'Hunt triggered', schedule_id: sched.id });
    // Run async
    (async () => {
      try {
        const huntResp = await axios.post(`${LANGCHAIN_URL}/hunt-queries`,
          { type: 'query', value: sched.query, context: `Manual run: ${sched.name}` },
          { timeout: 60_000, headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` }, validateStatus: () => true }
        );
        const result = { queries: huntResp.data?.queries || [], triggered_by: req.user.username };
        await db.updateHuntScheduleResult(sched.id, result);
        db.createNotification(
          'threat_hunt', `Hunt Complete: ${sched.name}`,
          `Hunt schedule "${sched.name}" ran and returned ${result.queries.length} queries.`,
          'info', req.user.username, { schedule_id: sched.id }
        ).catch(() => {});
      } catch(e) {
        await db.updateHuntScheduleResult(sched.id, { error: e.message }).catch(() => {});
      }
    })();
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════
// ─── PERFORMANCE METRICS API (admin only) ───────────────────────
// ═══════════════════════════════════════════════════════════════

app.get('/api/metrics/performance', authMW, requireRole('admin'), (req, res) => {
  const result = [];
  for (const [route, latencies] of routeLatencies.entries()) {
    if (!latencies.length) continue;
    const sorted = [...latencies].sort((a, b) => a - b);
    const p50 = sorted[Math.floor(sorted.length * 0.5)] || 0;
    const p95 = sorted[Math.floor(sorted.length * 0.95)] || 0;
    result.push({ route, p50, p95, count: sorted.length, avg: Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length) });
  }
  result.sort((a, b) => b.p95 - a.p95);
  res.json({ metrics: result, total: result.length });
});

// ═══════════════════════════════════════════════════════════════
// ─── HUNT SCHEDULE RUNNER ───────────────────────────────────────
// Parses 5-field cron expressions and runs enabled schedules when due
// ═══════════════════════════════════════════════════════════════
function cronNextRun(cronExpr) {
  // Simple cron parser: returns the next run Date based on the expression
  // Supports basic patterns: numbers and */N
  const parts = (cronExpr || '0 */6 * * *').split(' ');
  if (parts.length !== 5) return null;
  const [min, hour] = parts;
  const now = new Date();
  const next = new Date(now);
  next.setSeconds(0, 0);

  // For */N hour pattern compute interval in ms
  if (hour.startsWith('*/')) {
    const n = parseInt(hour.slice(2)) || 6;
    const intervalMs = n * 3600_000;
    return new Date(Math.ceil(now.getTime() / intervalMs) * intervalMs);
  }
  if (min.startsWith('*/')) {
    const n = parseInt(min.slice(2)) || 60;
    const intervalMs = n * 60_000;
    return new Date(Math.ceil(now.getTime() / intervalMs) * intervalMs);
  }
  // Specific hour/min daily
  const h = parseInt(hour) || 0;
  const m = parseInt(min) || 0;
  next.setHours(h, m, 0, 0);
  if (next <= now) next.setDate(next.getDate() + 1);
  return next;
}

async function startHuntScheduler() {
  setInterval(async () => {
    try {
      const { rows: schedules } = await db.listHuntSchedules({ limit: 1000 });
      const now = new Date();
      for (const sched of schedules) {
        if (!sched.enabled) continue;
        let isDue = false;
        if (!sched.last_run) {
          isDue = true;
        } else {
          const next = cronNextRun(sched.cron_expr);
          if (next && new Date(sched.last_run) < next && now >= next) isDue = true;
        }
        if (!isDue) continue;
        console.log(`[HuntScheduler] Running: ${sched.name}`);
        try {
          const huntResp = await axios.post(`${LANGCHAIN_URL}/hunt-queries`,
            { type: 'query', value: sched.query, context: `Scheduled: ${sched.name}` },
            { timeout: 60_000, headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` }, validateStatus: () => true }
          );
          const result = { queries: huntResp.data?.queries || [], scheduled: true };
          await db.updateHuntScheduleResult(sched.id, result);
          db.createNotification(
            'threat_hunt', `Hunt Complete: ${sched.name}`,
            `Scheduled hunt "${sched.name}" completed with ${result.queries.length} queries.`,
            'info', null, { schedule_id: sched.id }
          ).catch(() => {});
        } catch(e) {
          console.warn(`[HuntScheduler] ${sched.name} failed:`, e.message);
          await db.updateHuntScheduleResult(sched.id, { error: e.message }).catch(() => {});
        }
      }
    } catch(e) {
      console.warn('[HuntScheduler] tick error:', e.message);
    }
  }, 60_000); // check every 60 seconds
  console.log('[HuntScheduler] Started');
}

// ══════════════════════════════════════════════════════════════
// EVIDENCE FILE MANAGEMENT
// POST   /api/evidence/upload         — upload + embed file
// GET    /api/evidence                — list uploaded files
// GET    /api/evidence/:id            — single file metadata
// GET    /api/evidence/:id/download   — serve original file
// DELETE /api/evidence/:id            — delete file + embeddings
// POST   /api/evidence/search         — semantic search over evidence
// ══════════════════════════════════════════════════════════════

app.post('/api/evidence/upload', authMW, _evidenceUpload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const { alertId, caseId, investigationId } = req.body;

  // Persist metadata first so we have an ID
  let record;
  try {
    record = await db.createEvidenceFile({
      storedName:      req.file.filename,
      originalName:    req.file.originalname,
      mimeType:        req.file.mimetype,
      fileSize:        req.file.size,
      uploadedBy:      req.user.username,
      alertId:         alertId || null,
      caseId:          caseId  || null,
      investigationId: investigationId ? parseInt(investigationId) : null,
    });
  } catch(e) {
    console.error('[evidence] DB save failed:', e.message);
    // Clean up uploaded file
    fs.unlink(req.file.path, () => {});
    return res.status(500).json({ error: 'Database error saving file metadata' });
  }

  // Forward file to knowledge-ingestion for text extraction + embedding
  try {
    const fd = new FormData();
    fd.append('file', fs.createReadStream(req.file.path), {
      filename: req.file.originalname,
      contentType: req.file.mimetype,
    });
    fd.append('file_id',         String(record.id));
    fd.append('uploaded_by',     req.user.username);
    if (alertId)         fd.append('alert_id',         alertId);
    if (caseId)          fd.append('case_id',          caseId);
    if (investigationId) fd.append('investigation_id', investigationId);

    const kHeaders = { ...fd.getHeaders() };
    if (process.env.RAG_API_KEY) kHeaders['X-API-Key'] = process.env.RAG_API_KEY;

    const kResp = await axios.post(`${KNOWLEDGE_URL}/upload`, fd, {
      headers: kHeaders,
      timeout: 120000,
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
    });

    const { chunk_count = 0, point_ids = [], extracted_text_preview = '', sha256 } = kResp.data;

    await db.updateEvidenceFile(record.id, {
      chunk_count,
      qdrant_point_ids:  point_ids,
      extracted_preview: extracted_text_preview,
      scan_status:       'clean',
      sha256,
    });

    // Async VirusTotal hash check
    _vtHashCheck(record.id, sha256).catch(() => {});

    return res.json({
      ok: true,
      extracted_text: extracted_text_preview,
      file: { ...record, chunk_count, scan_status: 'clean', extracted_preview: extracted_text_preview, sha256 },
    });
  } catch(e) {
    console.error('[evidence] Knowledge-ingestion error:', e.message);
    await db.updateEvidenceFile(record.id, { scan_status: 'error' }).catch(() => {});
    return res.json({
      ok: true,
      warning: 'File saved but embedding failed — will be retried',
      file: record,
    });
  }
});

// Multer error handler for the upload route (file too large / unsupported type)
app.use('/api/evidence/upload', (err, req, res, next) => {
  if (err?.code === 'LIMIT_FILE_SIZE')   return res.status(413).json({ error: 'File too large (max 20 MB)' });
  if (err?.code === 'INVALID_FILE_TYPE') return res.status(415).json({ error: err.message });
  if (err) return res.status(400).json({ error: err.message });
  next();
});

async function _vtHashCheck(fileId, sha256) {
  if (!sha256 || !process.env.VIRUSTOTAL_API_KEY) return;
  try {
    const r = await axios.get(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
      timeout: 15000,
      validateStatus: s => s < 500,
    });
    if (r.status === 200) {
      const stats = r.data?.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const status = malicious > 0 ? 'malicious' : 'clean';
      await db.updateEvidenceFile(fileId, { scan_status: status, scan_result: stats });
    }
  } catch(e) {
    console.warn('[VT] hash check failed:', e.message);
  }
}

app.get('/api/evidence', authMW, async (req, res) => {
  try {
    const files = await db.listEvidenceFiles({
      limit:  parseInt(req.query.limit  || '50'),
      offset: parseInt(req.query.offset || '0'),
      uploadedBy: req.query.uploaded_by || undefined,
      caseId:     req.query.case_id     || undefined,
      alertId:    req.query.alert_id    || undefined,
    });
    res.json({ files, total: files.length });
  } catch(e) {
    console.error('[evidence] list error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/evidence/:id', authMW, async (req, res) => {
  try {
    const f = await db.getEvidenceFile(parseInt(req.params.id));
    if (!f) return res.status(404).json({ error: 'Not found' });
    res.json(f);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/evidence/:id/download', authMW, async (req, res) => {
  try {
    const f = await db.getEvidenceFile(parseInt(req.params.id));
    if (!f) return res.status(404).json({ error: 'Not found' });
    const filePath = path.join(EVIDENCE_DIR, f.stored_name);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found on disk' });
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(f.original_name)}"`);
    res.setHeader('Content-Type', f.mime_type || 'application/octet-stream');
    fs.createReadStream(filePath).pipe(res);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/evidence/:id', authMW, requireRole('l2'), async (req, res) => {
  try {
    const f = await db.getEvidenceFile(parseInt(req.params.id));
    if (!f) return res.status(404).json({ error: 'Not found' });
    // Remove from disk
    const filePath = path.join(EVIDENCE_DIR, f.stored_name);
    fs.unlink(filePath, () => {});
    // Remove Qdrant embeddings via knowledge-ingestion (best-effort)
    axios.post(`${KNOWLEDGE_URL}/evidence/delete`, { file_id: f.id }, {
      headers: process.env.RAG_API_KEY ? { 'X-API-Key': process.env.RAG_API_KEY } : {},
      timeout: 15000,
    }).catch(() => {});
    await db.deleteEvidenceFile(f.id);
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/evidence/search', authMW, async (req, res) => {
  const { query, limit, file_id, case_id } = req.body || {};
  if (!query) return res.status(400).json({ error: 'query required' });
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (process.env.RAG_API_KEY) headers['X-API-Key'] = process.env.RAG_API_KEY;
    const r = await axios.post(`${KNOWLEDGE_URL}/evidence/search`,
      { query, limit: limit || 5, file_id, case_id },
      { headers, timeout: 30000 }
    );
    res.json(r.data);
  } catch(e) {
    console.error('[evidence] search error:', e.message);
    res.status(502).json({ error: 'Evidence search unavailable' });
  }
});

// ═══════════════════════════════════════════════════════════════
// ─── PASSWORD RESET (no auth required) ─────────────────────────
// ═══════════════════════════════════════════════════════════════

app.post('/api/auth/forgot-password', async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'Username required' });

  try {
    const user = await db.getUserByUsername(username.toLowerCase().trim());
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.email) return res.status(400).json({ error: 'No email address on this account. Contact your admin.' });

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    await db.createPasswordResetToken(user.id, tokenHash, expiresAt);

    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    const host  = req.headers['x-forwarded-host'] || req.get('host');
    const resetLink = `${proto}://${host}/login?reset=${rawToken}`;

    const emailBody = email.generatePasswordResetEmail(resetLink, user.username);
    const result = await email.sendEmail(user.email, '[SOCPilots] Password Reset Request', emailBody);
    if (!result.success) {
      return res.status(503).json({ error: 'Failed to send reset email. Check SMTP configuration in Settings.' });
    }

    res.json({ ok: true, message: `Reset link sent to ${user.email}` });
  } catch(e) {
    console.error('[ForgotPassword]', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, new_password } = req.body || {};
  if (!token || !new_password) return res.status(400).json({ error: 'token and new_password required' });
  if (new_password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const record = await db.getPasswordResetToken(tokenHash);
    if (!record) return res.status(400).json({ error: 'Invalid or expired reset link' });

    const hash = bcrypt.hashSync(new_password, 10);
    await db.updateUserPassword(record.user_id, hash);
    await db.invalidatePasswordResetToken(tokenHash);

    res.json({ ok: true, message: 'Password updated. You can now log in.' });
  } catch(e) {
    console.error('[ResetPassword]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// ─── OTX ALIENVAULT IOC FEED API ────────────────────────────────
// ═══════════════════════════════════════════════════════════════

// GET /api/otx/stats — feed summary (total IOCs, last sync, breakdown by type)
app.get('/api/otx/stats', authMW, async (req, res) => {
  try {
    const stats = await db.getOtxStats();
    res.json({ ...stats, configured: Boolean(OTX_API_KEY) });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/otx/feeds — list IOCs from the feed (paginated, filterable)
app.get('/api/otx/feeds', authMW, async (req, res) => {
  try {
    const { type, search } = req.query;
    const page      = parseInt(req.query.page)      || 1;
    const page_size = Math.min(parseInt(req.query.page_size) || parseInt(req.query.limit) || 100, 500);
    const { rows: iocs, total } = await db.getOtxIocs({
      type:   type   || undefined,
      search: search || undefined,
      page, page_size,
    });
    res.json({ iocs, total, page, page_size, has_more: page * page_size < total, count: iocs.length });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/otx/check/:indicator — check if a specific indicator is in the feed
app.get('/api/otx/check/:indicator', authMW, async (req, res) => {
  try {
    const matches = await db.checkOtxIndicator(req.params.indicator);
    res.json({ indicator: req.params.indicator, matches, found: matches.length > 0 });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/otx/sync — manually trigger a feed sync (admin only)
app.post('/api/otx/sync', authMW, requireRole('admin'), async (req, res) => {
  if (!OTX_API_KEY) return res.status(503).json({ error: 'OTX_API_KEY not configured' });
  res.json({ ok: true, message: 'OTX sync triggered — check logs for progress' });
  setImmediate(() => otxFeedSync());
});

// ─── LOG SOURCES INTELLIGENCE ───────────────────────────────────

const LS_INTEGRATION_MAP = {
  // Cloud providers
  aws:             { type: 'cloud_api', vendor: 'AWS CloudTrail' },
  azure:           { type: 'cloud_api', vendor: 'Microsoft Azure' },
  'azure-ad':      { type: 'cloud_api', vendor: 'Microsoft Azure AD' },
  'azure-activity':{ type: 'cloud_api', vendor: 'Microsoft Azure' },
  'azure-storage': { type: 'cloud_api', vendor: 'Microsoft Azure' },
  'azure-security':{ type: 'cloud_api', vendor: 'Microsoft Azure' },
  'ms-graph':      { type: 'cloud_api', vendor: 'Microsoft 365' },
  office365:       { type: 'cloud_api', vendor: 'Microsoft 365' },
  gcp:             { type: 'cloud_api', vendor: 'Google Cloud Platform' },
  // Cloudflare
  cloudflare:      { type: 'cloud_api', vendor: 'Cloudflare' },
  'cloudflare-waf':{ type: 'waf',       vendor: 'Cloudflare WAF' },
  'cloudflare-dns':{ type: 'network',   vendor: 'Cloudflare DNS' },
  'cloudflare-access': { type: 'cloud_api', vendor: 'Cloudflare Access' },
  // Security services
  virustotal:      { type: 'cloud_api', vendor: 'VirusTotal' },
  'ms-defender':   { type: 'cloud_api', vendor: 'Microsoft Defender' },
  'windows-defender':{ type: 'cloud_api', vendor: 'Microsoft Defender' },
  sentinelone:     { type: 'cloud_api', vendor: 'SentinelOne' },
  crowdstrike:     { type: 'cloud_api', vendor: 'CrowdStrike' },
};

const LS_PROGRAM_MAP = {
  fortigate: { type: 'firewall', vendor: 'Fortinet' }, fgtd: { type: 'firewall', vendor: 'Fortinet' },
  paloalto:  { type: 'firewall', vendor: 'Palo Alto Networks' }, 'pan-os': { type: 'firewall', vendor: 'Palo Alto Networks' },
  checkpoint:{ type: 'firewall', vendor: 'Check Point' },
  'cisco-asa':{ type: 'firewall', vendor: 'Cisco ASA' },
  'cisco-ios':{ type: 'network', vendor: 'Cisco IOS' },
  'f5-bigip': { type: 'waf',      vendor: 'F5 BIG-IP' },
  bluecoat:   { type: 'proxy',    vendor: 'Blue Coat' },
  squid:      { type: 'proxy',    vendor: 'Squid Proxy' },
  cloudflared:{ type: 'cloud_api', vendor: 'Cloudflare' },
  cloudflare: { type: 'cloud_api', vendor: 'Cloudflare' },
};

const LS_DECODER_MAP = {
  'nginx-accesslog': { type: 'proxy',     vendor: 'nginx' },
  'nginx-errorlog':  { type: 'proxy',     vendor: 'nginx' },
  'apache-errorlog': { type: 'proxy',     vendor: 'Apache' },
  'apache-access':   { type: 'proxy',     vendor: 'Apache' },
  sshd:              { type: 'server',    vendor: 'OpenSSH' },
  syscheck_new_entry:{ type: 'server',    vendor: 'Wazuh FIM' },
  syscheck_deleted:  { type: 'server',    vendor: 'Wazuh FIM' },
  syscheck_integrity_changed: { type: 'server', vendor: 'Wazuh FIM' },
  // Cloudflare decoders
  cloudflare:        { type: 'cloud_api', vendor: 'Cloudflare' },
  'cloudflare-json': { type: 'cloud_api', vendor: 'Cloudflare' },
  'cloudflare-waf':  { type: 'waf',       vendor: 'Cloudflare WAF' },
  'cloudflare-access':{ type: 'cloud_api', vendor: 'Cloudflare Access' },
  // Azure decoders
  azure:             { type: 'cloud_api', vendor: 'Microsoft Azure' },
  'azure-ad':        { type: 'cloud_api', vendor: 'Microsoft Azure AD' },
  'azure-activity':  { type: 'cloud_api', vendor: 'Microsoft Azure' },
};

const LS_GROUP_MAP = {
  nginx:  { type: 'proxy',    vendor: 'nginx' },
  web:    { type: 'proxy',    vendor: null },
  apache: { type: 'proxy',    vendor: 'Apache' },
  syscheck: { type: 'server', vendor: 'Wazuh FIM' },
  firewall: { type: 'firewall', vendor: null },
  sshd:   { type: 'server',   vendor: 'OpenSSH' },
  authentication_failed: { type: 'server', vendor: null },
  pam:    { type: 'server',   vendor: null },
  // Cloudflare rule groups
  cloudflare:     { type: 'cloud_api', vendor: 'Cloudflare' },
  'cloudflare-waf':{ type: 'waf',      vendor: 'Cloudflare WAF' },
  'cloudflare-dns':{ type: 'network',  vendor: 'Cloudflare DNS' },
  cloudflare_waf: { type: 'waf',      vendor: 'Cloudflare WAF' },
  cloudflare_dns: { type: 'network',  vendor: 'Cloudflare DNS' },
  // Azure / Microsoft rule groups
  azure:    { type: 'cloud_api', vendor: 'Microsoft Azure' },
  azure_ad: { type: 'cloud_api', vendor: 'Microsoft Azure AD' },
  'azure-ad':{ type: 'cloud_api', vendor: 'Microsoft Azure AD' },
  office365:{ type: 'cloud_api', vendor: 'Microsoft 365' },
  'ms-defender':{ type: 'cloud_api', vendor: 'Microsoft Defender' },
  windows_defender: { type: 'cloud_api', vendor: 'Microsoft Defender' },
};

// Last-resort: match against agent name / integration name with regex
const LS_NAME_PATTERNS = [
  { re: /cloudflare/i,            type: 'cloud_api', vendor: 'Cloudflare',           confidence: 0.88 },
  { re: /azure[\s\-_]?ad/i,       type: 'cloud_api', vendor: 'Microsoft Azure AD',   confidence: 0.88 },
  { re: /azure/i,                  type: 'cloud_api', vendor: 'Microsoft Azure',      confidence: 0.85 },
  { re: /microsoft[\s\-_]?365/i,  type: 'cloud_api', vendor: 'Microsoft 365',        confidence: 0.88 },
  { re: /office[\s\-_]?365/i,     type: 'cloud_api', vendor: 'Microsoft 365',        confidence: 0.88 },
  { re: /ms[\s\-_]?graph/i,       type: 'cloud_api', vendor: 'Microsoft 365',        confidence: 0.88 },
  { re: /defender/i,              type: 'cloud_api', vendor: 'Microsoft Defender',   confidence: 0.85 },
  { re: /aws|cloudtrail/i,        type: 'cloud_api', vendor: 'AWS CloudTrail',        confidence: 0.85 },
  { re: /crowdstrike/i,           type: 'cloud_api', vendor: 'CrowdStrike',           confidence: 0.88 },
  { re: /sentinelone/i,           type: 'cloud_api', vendor: 'SentinelOne',           confidence: 0.88 },
  { re: /fortinet|fortigate/i,    type: 'firewall',  vendor: 'Fortinet',             confidence: 0.85 },
  { re: /palo\s?alto|pan.?os/i,   type: 'firewall',  vendor: 'Palo Alto Networks',   confidence: 0.85 },
  { re: /checkpoint/i,            type: 'firewall',  vendor: 'Check Point',           confidence: 0.85 },
  { re: /cisco[\s\-_]?asa/i,      type: 'firewall',  vendor: 'Cisco ASA',            confidence: 0.85 },
];

let _logSourcesCache = null, _logSourcesCacheTime = 0;
let _logSourcesAutoAnalysis = null;

async function _runLogSourcesAnalysis(sources) {
  const sanitized = sources.map(s => ({
    source_id: s.source_id, source_name: s.source_name, type: s.type,
    vendor: s.vendor, protocol: s.protocol, event_count_24h: s.event_count_24h,
    eps: s.eps, is_new: s.is_new, anomaly: s.anomaly,
    top_groups: s.top_groups, top_decoder: s.top_decoder,
    integration: s.integration, severity_dist: s.severity_dist,
    confidence: s.confidence,
  }));
  const LANGCHAIN_URL = process.env.LANGCHAIN_URL || 'http://langchain-agent:8001';
  const r = await fetch(`${LANGCHAIN_URL}/log-sources/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${process.env.LANGCHAIN_INTERNAL_TOKEN || ''}` },
    body: JSON.stringify({ sources: sanitized }),
    signal: AbortSignal.timeout(90000),
  });
  if (!r.ok) throw new Error(`AI service error: ${(await r.text()).slice(0, 200)}`);
  return r.json();
}

// Cloud vendor groups that warrant a dedicated virtual source entry.
// These are rule.groups values Wazuh assigns to cloud integration events.
const CLOUD_GROUP_VENDORS = {
  cloudflare:        { vendor: 'Cloudflare',            type: 'cloud_api' },
  'cloudflare-waf':  { vendor: 'Cloudflare WAF',        type: 'waf'       },
  cloudflare_waf:    { vendor: 'Cloudflare WAF',        type: 'waf'       },
  'cloudflare-dns':  { vendor: 'Cloudflare DNS',        type: 'network'   },
  cloudflare_dns:    { vendor: 'Cloudflare DNS',        type: 'network'   },
  azure:             { vendor: 'Microsoft Azure',       type: 'cloud_api' },
  azure_ad:          { vendor: 'Microsoft Azure AD',    type: 'cloud_api' },
  'azure-ad':        { vendor: 'Microsoft Azure AD',    type: 'cloud_api' },
  aws_cloudtrail:    { vendor: 'AWS CloudTrail',        type: 'cloud_api' },
  gcp:               { vendor: 'Google Cloud Platform', type: 'cloud_api' },
  office365:         { vendor: 'Microsoft 365',         type: 'cloud_api' },
  'ms-graph':        { vendor: 'Microsoft 365',         type: 'cloud_api' },
  'ms-defender':     { vendor: 'Microsoft Defender',    type: 'cloud_api' },
  windows_defender:  { vendor: 'Microsoft Defender',    type: 'cloud_api' },
  crowdstrike:       { vendor: 'CrowdStrike',           type: 'cloud_api' },
  sentinelone:       { vendor: 'SentinelOne',           type: 'cloud_api' },
};

async function _fetchLogSources() {

    const [r24h, r7d, rCloud24h, rCloud7d] = await Promise.all([
      osSearch({
        size: 0,
        query: { range: { '@timestamp': { gte: 'now-24h' } } },
        aggs: {
          by_source: {
            terms: { field: 'agent.id', size: 100 },
            aggs: {
              agent_name:  { terms: { field: 'agent.name',              size: 1 } },
              agent_ip:    { terms: { field: 'agent.ip',                size: 1 } },
              top_decoder: { terms: { field: 'decoder.name',            size: 5 } },
              top_groups:  { terms: { field: 'rule.groups',             size: 10 } },
              integration: { terms: { field: 'data.integration',        size: 3 } },
              program_name:{ terms: { field: 'predecoder.program_name', size: 3 } },
              severity_dist:{ terms: { field: 'rule.level',             size: 15 } },
              last_seen:   { max:   { field: '@timestamp' } },
              first_seen_24h: { min: { field: '@timestamp' } },
            },
          },
        },
      }),
      osSearch({
        size: 0,
        query: { range: { '@timestamp': { gte: 'now-7d' } } },
        aggs: {
          by_source: {
            terms: { field: 'agent.id', size: 100 },
            aggs: {
              count_7d:     { value_count: { field: 'agent.id' } },
              first_seen_7d:{ min: { field: '@timestamp' } },
            },
          },
        },
      }),
      // Cloud group aggregation (24h) — detects vendors sharing a manager agent
      osSearch({
        size: 0,
        query: { range: { '@timestamp': { gte: 'now-24h' } } },
        aggs: {
          by_cloud_group: {
            terms: { field: 'rule.groups', size: 100 },
            aggs: {
              last_seen:     { max:   { field: '@timestamp' } },
              severity_dist: { terms: { field: 'rule.level', size: 15 } },
            },
          },
        },
      }),
      // Cloud group 7d counts + last_seen (fallback for sources silent in last 24h)
      osSearch({
        size: 0,
        query: { range: { '@timestamp': { gte: 'now-7d' } } },
        aggs: {
          by_cloud_group: {
            terms: { field: 'rule.groups', size: 100 },
            aggs: {
              count_7d:  { value_count: { field: '@timestamp' } },
              last_seen: { max: { field: '@timestamp' } },
            },
          },
        },
      }),
    ]);

    const map7d = {};
    for (const b of (r7d.aggregations?.by_source?.buckets || [])) {
      map7d[b.key] = { count: b.count_7d?.value || 0, first_seen: b.first_seen_7d?.value || null };
    }

    const sources = [];
    for (const b of (r24h.aggregations?.by_source?.buckets || [])) {
      const id    = b.key;
      const name  = b.agent_name?.buckets?.[0]?.key  || `agent-${id}`;
      const ip    = b.agent_ip?.buckets?.[0]?.key     || 'unknown';
      const count24h = b.doc_count;
      const eps   = parseFloat((count24h / 86400).toFixed(3));
      const lastSeen = new Date(b.last_seen?.value || 0).toISOString();
      const firstSeen7d = map7d[id]?.first_seen ? new Date(map7d[id].first_seen).toISOString() : null;
      const isNew = firstSeen7d ? (Date.now() - new Date(firstSeen7d).getTime()) < 86400000 : false;

      const integKey  = b.integration?.buckets?.[0]?.key;
      const progKey   = (b.program_name?.buckets?.[0]?.key || '').toLowerCase();
      const decoderKey= (b.top_decoder?.buckets?.[0]?.key  || '').toLowerCase();
      const groups    = (b.top_groups?.buckets || []).map(x => x.key.toLowerCase());

      let type = 'server', vendor = null, protocol = 'agent', confidence = 0.65;

      if (integKey && LS_INTEGRATION_MAP[integKey]) {
        ({ type, vendor } = LS_INTEGRATION_MAP[integKey]);
        protocol = 'api'; confidence = 0.98;
      } else if (LS_PROGRAM_MAP[progKey]) {
        ({ type, vendor } = LS_PROGRAM_MAP[progKey]);
        protocol = 'syslog'; confidence = 0.90;
      } else if (LS_DECODER_MAP[decoderKey]) {
        ({ type, vendor } = LS_DECODER_MAP[decoderKey]);
        confidence = 0.80;
      } else {
        for (const g of groups) {
          if (LS_GROUP_MAP[g]) {
            type = LS_GROUP_MAP[g].type;
            if (!vendor && LS_GROUP_MAP[g].vendor) vendor = LS_GROUP_MAP[g].vendor;
            confidence = Math.max(confidence, 0.75);
            break;
          }
        }
      }

      // Name-pattern fallback: match agent name, integration key, or decoder against known vendors
      if (!vendor || vendor === 'unknown') {
        const haystack = `${name} ${integKey || ''} ${decoderKey} ${progKey}`.toLowerCase();
        for (const { re, type: t, vendor: v, confidence: c } of LS_NAME_PATTERNS) {
          if (re.test(haystack)) {
            type = t; vendor = v;
            confidence = Math.max(confidence, c);
            if (integKey) protocol = 'api';
            break;
          }
        }
      }

      const sevDist = {};
      for (const sv of (b.severity_dist?.buckets || [])) {
        const lvl = sv.key;
        const cat = lvl >= 12 ? 'critical' : lvl >= 8 ? 'high' : lvl >= 5 ? 'medium' : 'low';
        sevDist[cat] = (sevDist[cat] || 0) + sv.doc_count;
      }

      sources.push({
        source_id: id, source_name: name, source_ip: ip,
        type, vendor: vendor || 'unknown', protocol,
        event_count_24h: count24h, event_count_7d: map7d[id]?.count || 0,
        eps, last_seen: lastSeen, first_seen_7d: firstSeen7d,
        is_new: isNew, confidence,
        anomaly: false,
        severity_dist: sevDist,
        top_groups: groups.slice(0, 5),
        top_decoder: decoderKey,
        integration: integKey || null,
      });
    }

    // Build virtual cloud sources from rule.groups aggregation.
    // Cloud integrations often share the Wazuh manager agent — grouping by agent.id
    // alone only surfaces the dominant integration. This adds a dedicated entry for
    // every cloud vendor found in rule.groups that isn't already in the sources list.
    // Build lookup maps from the 24h cloud-group aggregation for EPS / severity / last_seen
    const cloudMap24h = {};
    for (const b of (rCloud24h.aggregations?.by_cloud_group?.buckets || [])) {
      cloudMap24h[b.key] = {
        count:      b.doc_count,
        last_seen:  b.last_seen?.value || null,
        sev_buckets: b.severity_dist?.buckets || [],
      };
    }

    const alreadyDetectedVendors = new Set(sources.map(s => s.vendor));
    // Use the 7d aggregation as the discovery window — cloud sources may be silent
    // in the last 24h but still configured and active within the past week.
    for (const b of (rCloud7d.aggregations?.by_cloud_group?.buckets || [])) {
      const grpKey = b.key.toLowerCase();
      const entry  = CLOUD_GROUP_VENDORS[grpKey];
      if (!entry) continue;
      if (alreadyDetectedVendors.has(entry.vendor)) continue;  // already shown via agent
      const c24h     = cloudMap24h[b.key] || {};
      const count24h = c24h.count || 0;
      const count7d  = b.count_7d?.value || 0;
      const sevDist  = {};
      for (const sv of (c24h.sev_buckets || [])) {
        const cat = sv.key >= 12 ? 'critical' : sv.key >= 8 ? 'high' : sv.key >= 5 ? 'medium' : 'low';
        sevDist[cat] = (sevDist[cat] || 0) + sv.doc_count;
      }
      sources.push({
        source_id:       `grp:${grpKey}`,
        source_name:     entry.vendor,
        source_ip:       'cloud',
        type:            entry.type,
        vendor:          entry.vendor,
        protocol:        'api',
        event_count_24h: count24h,
        event_count_7d:  count7d,
        eps:             parseFloat((count24h / 86400).toFixed(3)),
        last_seen:       c24h.last_seen
          ? new Date(c24h.last_seen).toISOString()
          : (b.last_seen?.value ? new Date(b.last_seen.value).toISOString() : null),
        first_seen_7d:   null,
        is_new:          false,
        confidence:      0.95,
        anomaly:         false,
        severity_dist:   sevDist,
        top_groups:      [grpKey],
        top_decoder:     '',
        integration:     grpKey,
      });
      alreadyDetectedVendors.add(entry.vendor);
    }

    // Anomaly: new source OR EPS >5x dataset average
    const avgEps = sources.length ? sources.reduce((s, x) => s + x.eps, 0) / sources.length : 0;
    for (const src of sources) {
      src.anomaly = src.is_new || (avgEps > 0 && src.eps > avgEps * 5 && src.eps > 5);
    }
    sources.sort((a, b) => (b.anomaly - a.anomaly) || (b.event_count_24h - a.event_count_24h));

    const totalEps = parseFloat(sources.reduce((s, x) => s + x.eps, 0).toFixed(3));
    const insights = [];
    const newCnt   = sources.filter(x => x.is_new).length;
    const anomCnt  = sources.filter(x => x.anomaly).length;
    const unkCnt   = sources.filter(x => x.vendor === 'unknown').length;
    const topSrc   = sources[0];

    if (newCnt  > 0) insights.push(`${newCnt} new log source(s) first seen in the last 24h`);
    if (anomCnt > 0) insights.push(`${anomCnt} source(s) showing anomalous EPS behaviour`);
    if (topSrc)      insights.push(`Highest-volume source: ${topSrc.source_name} — ${topSrc.eps.toFixed(2)} EPS`);
    if (unkCnt  > 0) insights.push(`${unkCnt} source(s) with unidentified vendor — AI Analysis recommended`);

    const result = {
      sources,
      summary: {
        total_sources: sources.length,
        total_events_24h: sources.reduce((s, x) => s + x.event_count_24h, 0),
        total_eps: totalEps,
        unknown_sources: unkCnt,
        anomaly_count: anomCnt,
        cloud_api_sources: sources.filter(x => x.type === 'cloud_api').length,
        new_sources_24h: newCnt,
        top_source: topSrc?.source_name || null,
      },
      insights,
    };

    _logSourcesCache = result;
    _logSourcesCacheTime = Date.now();
    return result;
}

app.get('/api/log-sources', authMW, async (req, res) => {
  try {
    if (_logSourcesCache && Date.now() - _logSourcesCacheTime < 60000) return res.json(_logSourcesCache);
    res.json(await _fetchLogSources());
  } catch (e) {
    console.error('[log-sources]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/log-sources/analyze', authMW, async (req, res) => {
  try {
    const { sources } = req.body;
    if (!Array.isArray(sources) || !sources.length) return res.status(400).json({ error: 'sources array required' });

    const result = await _runLogSourcesAnalysis(sources);
    _logSourcesAutoAnalysis = { result, last_analyzed_at: Date.now(), source: 'manual' };
    _logSourcesCache = null;
    res.json(result);
  } catch (e) {
    console.error('[log-sources/analyze]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/log-sources/analysis', authMW, (req, res) => {
  if (!_logSourcesAutoAnalysis) return res.json({ available: false });
  res.json({ available: true, ..._logSourcesAutoAnalysis });
});

// ── INVESTIGATION FEEDBACK ──
app.post('/api/investigations/:id/feedback', authMW, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { rating, comment } = req.body;
    if (rating !== 1 && rating !== -1) return res.status(400).json({ error: 'rating must be 1 or -1' });
    const result = await db.saveInvestigationFeedback(id, req.user.username, rating, comment);
    res.json({ ok: true, feedback: result });
  } catch (e) {
    console.error('[investigation/feedback]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/investigations/:id/feedback', authMW, async (req, res) => {
  try {
    const summary = await db.getInvestigationFeedbackSummary(parseInt(req.params.id));
    res.json(summary);
  } catch (e) {
    console.error('[investigation/feedback/get]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── ACTION APPROVALS ──
app.get('/api/action-approvals', authMW, async (req, res) => {
  try {
    const status = req.query.status || null;
    const rows   = await db.listActionApprovals({ status });
    res.json({ items: rows, total: rows.length });
  } catch(e) {
    console.error('[action-approvals/list]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/action-approvals/stats', authMW, async (req, res) => {
  try {
    const count = await db.countPendingActionApprovals();
    res.json({ pending: count });
  } catch(e) {
    console.error('[action-approvals/stats]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/action-approvals/:id/approve', authMW, requireRole('l2'), async (req, res) => {
  try {
    const approval = await db.getActionApproval(parseInt(req.params.id));
    if (!approval) return res.status(404).json({ error: 'Not found' });
    if (approval.status !== 'pending') return res.status(409).json({ error: `Already ${approval.status}` });
    if (new Date(approval.expires_at) < new Date()) {
      await db.resolveActionApproval(approval.id, { status: 'expired', resolvedBy: 'system' });
      return res.status(410).json({ error: 'Approval expired' });
    }

    // Reconstruct alert from stored data
    const alert = { ...(approval.alert_data || {}),
      alertKey: approval.alert_key, ruleId: approval.rule_id, rule_id: approval.rule_id,
      agent: approval.agent, srcIp: approval.src_ip, src_ip: approval.src_ip,
      severity: approval.severity };
    alert.level = alert.rule_level || alert.level || 0;
    alert.mitre = alert.mitre || [];

    const inv    = await db.getInvestigationById(approval.investigation_id);
    const report = inv?.report || '';
    const pbs    = (await Promise.all((approval.playbook_ids || []).map(id => db.getPlaybookById(id)))).filter(Boolean);

    await _executePlaybooks(alert, report, approval.investigation_id, parseFloat(approval.fp_probability) || 0, pbs);

    await db.resolveActionApproval(approval.id, {
      status:      'executed',
      resolvedBy:  req.user.username,
      resolveNote: req.body?.note || '',
    });
    io.emit('approval:resolved', { id: approval.id, status: 'executed', resolved_by: req.user.username });
    db.createSystemEvent('playbook', req.user.username,
      `Approved action for rule ${approval.rule_id} on ${approval.agent}`, 'ok').catch(() => {});
    res.json({ ok: true });
  } catch(e) {
    console.error('[action-approvals/approve]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/action-approvals/:id/reject', authMW, requireRole('l2'), async (req, res) => {
  try {
    const approval = await db.getActionApproval(parseInt(req.params.id));
    if (!approval) return res.status(404).json({ error: 'Not found' });
    if (approval.status !== 'pending') return res.status(409).json({ error: `Already ${approval.status}` });
    await db.resolveActionApproval(approval.id, {
      status:      'rejected',
      resolvedBy:  req.user.username,
      resolveNote: req.body?.note || '',
    });
    io.emit('approval:resolved', { id: approval.id, status: 'rejected', resolved_by: req.user.username });
    db.createSystemEvent('playbook', req.user.username,
      `Rejected action for rule ${approval.rule_id} on ${approval.agent}`, 'ok').catch(() => {});
    res.json({ ok: true });
  } catch(e) {
    console.error('[action-approvals/reject]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── TRIAGE QUEUE ──
app.get('/api/triage-queue/stats', authMW, async (req, res) => {
  try {
    const stats = await db.getQueueStats();
    res.json(stats);
  } catch(e) {
    console.error('[triage-queue/stats]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ─── STATIC (must be last — after all /api routes) ──────────────
app.use(express.static(path.join(__dirname, '../../frontend')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../../frontend/index.html')));

// Initialize DB schema on startup (non-blocking)
db.initSchema()
  .then(() => seedUsersFromEnv())
  .then(() => startHuntScheduler())
  .catch(e => console.error('[DB] init failed:', e.message));
ueba.initSchema()
  .then(() => ueba.backfillRiskScores())
  .catch(e => console.error('[NEO4J] init failed:', e.message));

httpServer.listen(PORT, '0.0.0.0', () => {
  const envFile = require('fs').existsSync(require('path').join(__dirname,'../../.env')) ? '✅ .env loaded' : '⚠ .env NOT found';
  console.log(`\n╔══════════════════════════════════════════════════════════════╗`);
  console.log(`║  SOC PILOTS COMMAND CENTER                                   ║`);
  console.log(`╠══════════════════════════════════════════════════════════════╣`);
  console.log(`║  Port     : ${PORT}                                                ║`);
  console.log(`║  Env      : ${envFile}                               ║`);
  console.log(`║  SIEM     : ${OS_URL}`);
  console.log(`║  SP-CM    : ${HIVE_URL}`);
  console.log(`║  n8n URL  : ${N8N_URL}`);
  console.log(`║  n8n Inv. : ${N8N_INV}`);
  console.log(`╠══════════════════════════════════════════════════════════════╣`);
  console.log(`║  To change config: edit .env then: docker compose restart webapp`);
  console.log(`╚══════════════════════════════════════════════════════════════╝\n`);
  ENV_USERS.forEach(u => console.log(`  USER: ${u.username} / ${u.role}`));
});

module.exports = app;
