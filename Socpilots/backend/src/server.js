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
const OPENAI_API_KEY    = process.env.OPENAI_API_KEY   || '';
const MISTRAL_API_KEY   = process.env.MISTRAL_API_KEY  || '';

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
      db.saveCorrelation({ ...correlation, source: 'ueba_triage' }).catch(() => {});
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

// ─── OPENSEARCH CONCURRENCY LIMITER ────────────────────────
// Caps simultaneous in-flight OpenSearch queries to prevent 429 storms
// when multiple background jobs fire together after container restart.
let _osInFlight = 0;
const _OS_MAX_CONCURRENT = 2;
const _osQueue = [];
function _osAcquire() {
  return new Promise(resolve => {
    if (_osInFlight < _OS_MAX_CONCURRENT) { _osInFlight++; resolve(); }
    else _osQueue.push(resolve);
  });
}
function _osRelease() {
  if (_osQueue.length) { const next = _osQueue.shift(); next(); }
  else _osInFlight = Math.max(0, _osInFlight - 1);
}
// Background jobs call this before issuing OS queries; skips the run if the
// queue is already backed up so user-facing requests are not starved.
function _osBackpressure(label) {
  if (_osQueue.length >= 4) {
    console.warn(`[${label}] OS queue depth ${_osQueue.length} — skipping this run`);
    return true;
  }
  return false;
}

// Auto-clear OS fielddata cache when circuit breaker trips — prevents 98% heap death-spiral
let _osClearCacheTime = 0;
async function _osClearFielddata() {
  const now = Date.now();
  if (now - _osClearCacheTime < 60_000) return; // at most once per minute
  _osClearCacheTime = now;
  try {
    await axios.post(`${OS_URL}/_cache/clear?fielddata=true`, null, {
      auth: { username: OS_USER, password: OS_PASS }, httpsAgent, timeout: 10000,
    });
    console.warn('[osSearch] 429 fielddata cache cleared — heap pressure relieved');
  } catch (e) {
    console.warn('[osSearch] cache clear failed:', e.message);
  }
}

// ─── OPENSEARCH HELPER ─────────────────────────────────────
// maxRetries: default 3 (~14s max). Pass 2 for fast-fail paths, higher for critical user routes.
async function osSearch(body, index = IDX, size = 200, _retry = 0, maxRetries = 3) {
  await _osAcquire();
  let r;
  try {
    r = await axios.post(`${OS_URL}/${index}/_search`, body, {
      auth: { username: OS_USER, password: OS_PASS },
      httpsAgent, timeout: 15000,
      headers: { 'Content-Type': 'application/json' },
      validateStatus: s => s < 500 || s === 503,
    });
  } catch (e) {
    _osRelease();
    if (e.response?.status === 429 && _retry < maxRetries) {
      const wait = (2 ** _retry) * 2000 + Math.random() * 1000;
      console.warn(`[osSearch] 429 — retry ${_retry + 1}/${maxRetries} in ${Math.round(wait)}ms`);
      if (_retry === 0) _osClearFielddata();
      await new Promise(res => setTimeout(res, wait));
      return osSearch(body, index, size, _retry + 1, maxRetries);
    }
    throw e;
  }
  _osRelease();
  if (r.status === 429 && _retry < maxRetries) {
    const wait = (2 ** _retry) * 2000 + Math.random() * 1000;
    console.warn(`[osSearch] 429 — retry ${_retry + 1}/${maxRetries} in ${Math.round(wait)}ms`);
    if (_retry === 0) _osClearFielddata(); // try freeing fielddata on first 429
    await new Promise(res => setTimeout(res, wait));
    return osSearch(body, index, size, _retry + 1, maxRetries);
  }
  if (r.status >= 400) throw new Error(`Request failed with status code ${r.status}`);
  return r.data;
}

async function osCount(body, index = IDX, _retry = 0, maxRetries = 3) {
  await _osAcquire();
  let r;
  try {
    r = await axios.post(`${OS_URL}/${index}/_count`, body, {
      auth: { username: OS_USER, password: OS_PASS },
      httpsAgent, timeout: 10000,
      headers: { 'Content-Type': 'application/json' },
      validateStatus: s => s < 500 || s === 503,
    });
  } catch (e) {
    _osRelease();
    if (e.response?.status === 429 && _retry < maxRetries) {
      const wait = (2 ** _retry) * 2000 + Math.random() * 1000;
      console.warn(`[osCount] 429 — retry ${_retry + 1}/${maxRetries} in ${Math.round(wait)}ms`);
      await new Promise(res => setTimeout(res, wait));
      return osCount(body, index, _retry + 1, maxRetries);
    }
    throw e;
  }
  _osRelease();
  if (r.status === 429 && _retry < maxRetries) {
    const wait = (2 ** _retry) * 2000 + Math.random() * 1000;
    console.warn(`[osCount] 429 — retry ${_retry + 1}/${maxRetries} in ${Math.round(wait)}ms`);
    await new Promise(res => setTimeout(res, wait));
    return osCount(body, index, _retry + 1, maxRetries);
  }
  if (r.status >= 400) throw new Error(`Request failed with status code ${r.status}`);
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
// Deterministic short ID for every alert — SOC-XXXXXXXX from OpenSearch _id
function alertShortId(opensearchId) {
  return 'SOC-' + crypto.createHash('md5').update(String(opensearchId)).digest('hex').slice(0, 8).toUpperCase();
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
const _dashCache = {};
const _dashCacheTime = {};
app.get('/api/dashboard', authMW, async (req, res) => {
  try {
    const hours   = parseInt(req.query.hours) || 24;
    const fromTs  = req.query.from || null;
    const toTs    = req.query.to   || null;
    const cacheKey = fromTs ? `${fromTs}_${toTs}` : `${hours}h`;
    const now = Date.now();

    if (_dashCache[cacheKey] && now - (_dashCacheTime[cacheKey] || 0) < 30000) {
      return res.json(_dashCache[cacheKey]);
    }

    const tsRange = fromTs
      ? { gte: fromTs, ...(toTs ? { lte: toTs } : {}) }
      : { gte: `now-${hours}h` };

    let calInterval = 'hour';
    if (fromTs && toTs) {
      const diffH = (new Date(toTs) - new Date(fromTs)) / 3600000;
      calInterval = diffH <= 48 ? 'hour' : diffH <= 336 ? '6h' : 'day';
    } else {
      calInterval = hours <= 48 ? 'hour' : hours <= 336 ? '6h' : 'day';
    }
    const boundsMin = fromTs || `now-${hours}h`;
    const boundsMax = toTs   || 'now';

    // 2 queries instead of 4: main agg provides counts + timeline; separate TheHive call
    const [agentAgg, hiveCases] = await Promise.allSettled([
      osSearch({
        size: 0,
        track_total_hits: true,
        aggs: {
          agents: { terms: { field: 'agent.name', size: 100 } },
          // Use filter aggs (not range agg) — range agg over-counts when combined with
          // a time-range query across many indices (OpenSearch fielddata scoping issue)
          sev_critical: { filter: { range: { 'rule.level': { gte: 12          } } } },
          sev_high:     { filter: { range: { 'rule.level': { gte: 8,  lt: 12  } } } },
          sev_medium:   { filter: { range: { 'rule.level': { gte: 5,  lt: 8   } } } },
          sev_low:      { filter: { range: { 'rule.level': {           lt: 5   } } } },
          over_time: {
            date_histogram: { field: '@timestamp', calendar_interval: calInterval, min_doc_count: 0,
              extended_bounds: { min: boundsMin, max: boundsMax }
            },
            aggs: {
              critical: { filter: { range: { 'rule.level': { gte: 12         } } } },
              high:     { filter: { range: { 'rule.level': { gte: 8, lt: 12  } } } },
              medium:   { filter: { range: { 'rule.level': { gte: 5, lt: 8   } } } },
              low:      { filter: { range: { 'rule.level': {          lt: 5   } } } },
            }
          }
        },
        query: { range: { '@timestamp': tsRange } }
      }, IDX, 200, 0, 2),
      hiveQuery([
        { _name: 'listCase' },
        { _name: 'filter', _field: 'status', _value: 'New' }
      ]).catch(() => null),
    ]);

    const aggs      = agentAgg.value?.aggregations;
    const periodCount = agentAgg.value?.hits?.total?.value || 0;
    const critCount   = aggs?.sev_critical?.doc_count || 0;
    const highCount   = aggs?.sev_high?.doc_count     || 0;
    const medCount    = aggs?.sev_medium?.doc_count   || 0;
    const lowCount    = aggs?.sev_low?.doc_count      || 0;
    const timeline = (aggs?.over_time?.buckets || []).map(b => ({
      time:     b.key_as_string || new Date(b.key).toISOString(),
      count:    b.doc_count,
      critical: b.critical?.doc_count || 0,
      high:     b.high?.doc_count     || 0,
      medium:   b.medium?.doc_count   || 0,
      low:      b.low?.doc_count      || 0,
    }));

    const osFailed = agentAgg.status === 'rejected';
    const result = {
      totalAlerts:    periodCount,
      alerts24h:      periodCount,
      criticalAlerts: critCount,
      highAlerts:     highCount,
      mediumAlerts:   medCount,
      lowAlerts:      lowCount,
      totalAgents:    aggs?.agents?.buckets?.length || 0,
      openCases:      Array.isArray(hiveCases.value) ? hiveCases.value.length : 0,
      timeline,
      sevBreakdown: { critical: critCount, high: highCount, medium: medCount, low: lowCount },
      periodLabel: fromTs
        ? `${new Date(fromTs).toLocaleDateString()} – ${toTs ? new Date(toTs).toLocaleDateString() : 'now'}`
        : `Last ${hours >= 720 ? Math.round(hours/720)+'mo' : hours >= 168 ? Math.round(hours/168)+'w' : hours >= 24 ? Math.round(hours/24)+'d' : hours+'h'}`,
      ...(osFailed ? { pending: true } : {}),
    };
    // Only cache when OS actually responded (don't cache zero-filled fallback from 429)
    if (!osFailed) { _dashCache[cacheKey] = result; _dashCacheTime[cacheKey] = now; }
    res.json(result);
  } catch (e) {
    console.error('[dashboard]', e.message);
    const firstKey = Object.keys(_dashCache)[0];
    if (firstKey) return res.json({ ..._dashCache[firstKey], stale: true });
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
    // Multi-severity: severities=critical,high,medium  (takes precedence over single severity)
    const VALID_SEVS = new Set(['critical','high','medium','low']);
    const sevList = req.query.severities
      ? req.query.severities.split(',').map(s => s.trim()).filter(s => VALID_SEVS.has(s))
      : (sev && VALID_SEVS.has(sev) ? [sev] : []);

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
    if (sevList.length) {
      const ranges = { critical: { gte: 12 }, high: { gte: 8, lt: 12 }, medium: { gte: 5, lt: 8 }, low: { lt: 5 } };
      if (sevList.length === 1) {
        must.push({ range: { 'rule.level': ranges[sevList[0]] } });
      } else {
        must.push({ bool: { should: sevList.map(s => ({ range: { 'rule.level': ranges[s] } })), minimum_should_match: 1 } });
      }
    }
    if (search) must.push({ multi_match: { query: search, fields: ['rule.description', 'full_log', 'agent.name', 'data.srcip', 'rule.id'] } });

    let body = {
      from: cappedFrom,
      size: cappedSize,
      track_total_hits: true,
      sort: [{ '@timestamp': 'desc' }],
      query: must.length ? { bool: { must } } : { match_all: {} },
      _source: ['@timestamp', 'rule', 'agent', 'data', 'srcip', 'full_log', 'location', 'manager'],
    };

    let r = await osSearch(body);
    let total = typeof r.hits.total === 'object' ? r.hits.total.value : (r.hits.total || 0);

    // If searching by SOC-XXXXXXXX short ID, fall back to scanning for _id match
    if (search && /^SOC-[0-9A-F]{8}$/i.test(search.trim()) && r.hits.hits.length === 0) {
      const scanBody = {
        size: 500,
        track_total_hits: true,
        sort: [{ '@timestamp': 'desc' }],
        query: must.length > (search ? 1 : 0) ? { bool: { must: must.filter(m => !m.multi_match) } } : { match_all: {} },
        _source: ['@timestamp', 'rule', 'agent', 'data', 'srcip', 'full_log', 'location', 'manager'],
      };
      const scanR = await osSearch(scanBody);
      const target = search.trim().toUpperCase();
      const matched = scanR.hits.hits.filter(h => alertShortId(h._id) === target);
      if (matched.length) { r = { hits: { hits: matched, total: { value: matched.length } } }; total = matched.length; }
    }

    const alerts = r.hits.hits.map(h => {
      const s = h._source;
      return {
        id:          h._id,
        short_id:    alertShortId(h._id),
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
      query: { range: { '@timestamp': { gte: 'now-7d' } } },
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
    // Serve stale cache on transient OpenSearch errors (429, 503) rather than failing
    if (_rulesCache) return res.json({ ..._rulesCache, stale: true });
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

// ── PROMOTE HIVE ALERT TO CASE ──
app.post('/api/hive-alerts/promote', authMW, async (req, res) => {
  try {
    const { alertId, title, severity } = req.body;
    if (!alertId) return res.status(400).json({ error: 'alertId required' });
    const r = await axios.post(
      `${HIVE_URL}/api/v1/alert/${alertId}/case`,
      {},
      { headers: { Authorization: `Bearer ${HIVE_KEY}`, 'Content-Type': 'application/json' }, httpsAgent, timeout: 15000 }
    );
    const caseData = r.data;
    db.createNotification('case_created', `Alert promoted to case`,
      `Alert ${alertId} promoted by ${req.user.username}`,
      'info', null, { alert_id: alertId }).catch(() => {});
    res.json({ ok: true, caseId: caseData._id || caseData.id, caseNumber: caseData.number });
  } catch (e) {
    console.error('[hive-alerts/promote]', e.message);
    res.status(502).json({ error: e.response?.data?.message || e.message });
  }
});

// ── IGNORE / CLOSE HIVE ALERT ──
app.post('/api/hive-alerts/:id/ignore', authMW, async (req, res) => {
  try {
    const { id } = req.params;
    await axios.patch(
      `${HIVE_URL}/api/v1/alert/${id}`,
      { status: 'Ignored' },
      { headers: { Authorization: `Bearer ${HIVE_KEY}`, 'Content-Type': 'application/json' }, httpsAgent, timeout: 10000 }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('[hive-alerts/ignore]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── ASSIGN HIVE ALERT ──
app.post('/api/hive-alerts/:id/assign', authMW, async (req, res) => {
  try {
    const { id } = req.params;
    const { assignee } = req.body;
    await axios.patch(
      `${HIVE_URL}/api/v1/alert/${id}`,
      { assignee: assignee || req.user.username },
      { headers: { Authorization: `Bearer ${HIVE_KEY}`, 'Content-Type': 'application/json' }, httpsAgent, timeout: 10000 }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('[hive-alerts/assign]', e.message);
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

// ── CASE DETAIL SUB-ROUTES ──
app.get('/api/cases/:id', authMW, async (req, res) => {
  try {
    const id = req.params.id;
    const r = await hiveQuery([{ _name: 'getCase', idOrName: id }]);
    if (!r || (Array.isArray(r) && r.length === 0)) return res.status(404).json({ error: 'Case not found' });
    const c = Array.isArray(r) ? r[0] : r;
    res.json(mapCase(c));
  } catch (e) {
    console.error('[case-detail]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/cases/:id/timeline', authMW, async (req, res) => {
  try {
    const id = req.params.id;
    const audits = await hiveQuery([
      { _name: 'getCase', idOrName: id },
      { _name: 'audits' },
      { _name: 'sort', _fields: [{ _createdAt: 'asc' }] },
      { _name: 'page', from: 0, to: 100 },
    ]);
    const items = Array.isArray(audits) ? audits : [];
    const events = items.map(a => {
      const by   = (a._createdBy || 'system').replace(/@.*/, '');
      const ts   = a._createdAt;
      const det  = a.details || {};
      const objT = a.objectType || 'Case';
      let type = 'update', txt = `${objT} updated`;
      if (objT === 'Alert')      { type = 'link';      txt = `Alert linked to case`; }
      else if (objT === 'Observable') { type = 'observable'; txt = `Observable added: ${det.data || det.dataType || 'indicator'}`; }
      else if (det.assignee)     { type = 'assign';    txt = `Assigned to ${det.assignee.replace(/@.*/, '')}`; }
      else if (det.status)       { type = 'status';    txt = `Status → ${det.status}`; }
      else if (det.title)        { type = 'create';    txt = `Case created: ${det.title}`; }
      else if (det.description)  { type = 'update';    txt = 'Description updated'; }
      return { ts, who: by, type, txt };
    });
    res.json({ events });
  } catch (e) {
    console.error('[case-timeline]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/cases/:id/observables', authMW, async (req, res) => {
  try {
    const id = req.params.id;
    const raw = await hiveQuery([
      { _name: 'getCase', idOrName: id },
      { _name: 'observables' },
      { _name: 'page', from: 0, to: 100 },
    ]);
    const items = Array.isArray(raw) ? raw : [];
    const observables = items.map(o => ({
      id:       o._id,
      type:     o.dataType || 'other',
      value:    o.data || '',
      tags:     o.tags || [],
      tlp:      o.tlpLabel || 'AMBER',
      ioc:      !!o.ioc,
      sighted:  o.sightedAt ? 1 : 0,
    }));
    res.json({ observables });
  } catch (e) {
    console.error('[case-observables]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/cases/:id/tasks', authMW, async (req, res) => {
  try {
    const id = req.params.id;
    const raw = await hiveQuery([
      { _name: 'getCase', idOrName: id },
      { _name: 'tasks' },
      { _name: 'page', from: 0, to: 50 },
    ]);
    const items = Array.isArray(raw) ? raw : [];
    const tasks = items.map(t => ({
      id:       t._id,
      title:    t.title || '(task)',
      status:   t.status || 'Waiting',
      assignee: (t.assignee || '').replace(/@.*/, '') || null,
      order:    t.order || 0,
      dueDate:  t.dueDate || null,
    }));
    res.json({ tasks });
  } catch (e) {
    console.error('[case-tasks]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/cases/:id/comments', authMW, async (req, res) => {
  try {
    const id = req.params.id;
    const raw = await hiveQuery([
      { _name: 'getCase', idOrName: id },
      { _name: 'comments' },
      { _name: 'page', from: 0, to: 50 },
    ]);
    const items = Array.isArray(raw) ? raw : [];
    const comments = items.map(c => ({
      id:      c._id,
      who:     (c._createdBy || 'system').replace(/@.*/, ''),
      when:    c._createdAt,
      message: c.message || '',
    }));
    res.json({ comments });
  } catch (e) {
    console.error('[case-comments]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/cases/:id/alerts', authMW, async (req, res) => {
  try {
    const id = req.params.id;
    const raw = await hiveQuery([
      { _name: 'getCase', idOrName: id },
      { _name: 'alerts' },
      { _name: 'sort', _fields: [{ _createdAt: 'desc' }] },
      { _name: 'page', from: 0, to: 30 },
    ]);
    const items = Array.isArray(raw) ? raw : [];
    const alerts = items.map(a => ({
      id:     a._id,
      ref:    a.sourceRef || a._id,
      title:  a.title || '(alert)',
      sev:    hiveSevLabel(a.severity),
      source: a.source || 'Wazuh',
      when:   a._createdAt,
      tags:   a.tags || [],
    }));
    res.json({ alerts });
  } catch (e) {
    console.error('[case-alerts]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/cases/:id/comments', authMW, async (req, res) => {
  try {
    const id      = req.params.id;
    const { message } = req.body;
    if (!message?.trim()) return res.status(400).json({ error: 'message required' });
    const r = await axios.post(`${HIVE_URL}/api/v1/case/${id}/comment`,
      { message: message.trim() },
      { headers: { Authorization: `Bearer ${HIVE_KEY}`, 'Content-Type': 'application/json' }, httpsAgent, timeout: 10000 }
    );
    res.json({ ok: true, id: r.data._id });
  } catch (e) {
    console.error('[case-comment-post]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── HUNT — OpenSearch + SOCPilots AI ──
app.post('/api/hunt', authMW, async (req, res) => {
  const { type, value } = req.body;
  if (!value) return res.status(400).json({ error: 'value required' });

  // First search OpenSearch directly
  // user type: search both srcuser and dstuser so both auth directions are covered
  const fieldMap = { ip: 'data.srcip', domain: 'data.srcip', hash: 'data.hash', process: 'data.process_name', rule: 'rule.id' };
  const field = fieldMap[type];

  let osResults = [];
  try {
    const shouldClauses = field
      ? [{ term: { [field]: value } }, { match: { full_log: value } }]
      : [
          { term: { 'data.srcuser': value } },
          { term: { 'data.dstuser': value } },
          { term: { 'data.win.eventdata.targetUserName': value } },
          { term: { 'data.win.eventdata.subjectUserName': value } },
          { match: { full_log: value } },
        ];
    const r = await osSearch({
      size: 50,
      sort: [{ '@timestamp': 'desc' }],
      query: { bool: { should: shouldClauses, minimum_should_match: 1 } },
    });
    osResults = r.hits.hits.map(h => ({
      id: h._id, timestamp: h._source['@timestamp'],
      description: h._source.rule?.description, severity: sevFromLevel(h._source.rule?.level),
      agent: h._source.agent?.name, srcIp: h._source.data?.srcip,
      mitre: h._source.rule?.mitre?.id || [],
    }));
  } catch (e) { console.error('[hunt-os]', e.message); }

  // Only call AI if there are real SIEM hits — avoids hallucinated analysis on empty results
  let aiAnalysis = osResults.length === 0
    ? `No SIEM alerts found for ${type} "${value}". The indicator is not present in the current OpenSearch index.`
    : '';
  let huntQueries = null;
  if (osResults.length > 0) {
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
  }

  res.json({ osResults, osTotal: osResults.length, aiAnalysis, huntQueries });
});

// ── CORRELATION ──
// ── CORRELATION HISTORY ──
app.get('/api/correlations', authMW, async (req, res) => {
  try {
    const { page = 1, page_size = 50, q, entity_type, min_risk, correlation_type, sort_by, sort_dir } = req.query;
    const { rows, total } = await db.getCorrelations({
      page: parseInt(page), page_size: parseInt(page_size),
      q, entity_type, min_risk, correlation_type, sort_by, sort_dir,
    });
    res.json({ items: rows, total, page: parseInt(page), page_size: parseInt(page_size), has_more: parseInt(page) * parseInt(page_size) < total });
  } catch (e) {
    console.error('[correlations]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/correlate', authMW, async (req, res) => {
  const { indicator } = req.body;
  if (!indicator) return res.status(400).json({ error: 'indicator required' });

  const corrPrompt = `Correlate indicator "${indicator}" across Wazuh SIEM and SP-CM. Provide: timeline of events, risk score (0-100), relevant MITRE ATT&CK techniques, attack chain analysis, and recommended response actions.`;

  const [osR, hiveR] = await Promise.allSettled([
    osSearch({
      size: 20, sort: [{ '@timestamp': 'desc' }],
      query: { multi_match: { query: indicator, fields: ['data.srcip', 'data.dstuser', 'full_log', 'rule.description', 'agent.name'] } },
    }),
    hiveQuery([{ _name: 'listCase' }, { _name: 'filter', _field: 'title', _like: indicator }]),
  ]);

  // AI correlation — LangChain primary, n8n fallback
  let aiAnalysis = 'Analysis unavailable — AI services unreachable';
  try {
    const r = await axios.post(`${LANGCHAIN_URL}/chat`, {
      message: corrPrompt, history: [],
      username: req.user?.username || 'system', role: req.user?.role || 'l2',
    }, { timeout: 60_000 });
    if (r.data?.response) aiAnalysis = r.data.response;
  } catch (_) {
    try {
      const n = await n8nAsk(corrPrompt, 'soc-correlate', req.user);
      if (n?.text) aiAnalysis = n.text;
    } catch (_) {}
  }

  const wazuhHits = osR.value?.hits?.hits?.map(h => ({ id: h._id, ts: h._source['@timestamp'], desc: h._source.rule?.description, agent: h._source.agent?.name })) || [];
  const hiveHits  = Array.isArray(hiveR.value) ? hiveR.value.map(c => ({ id: c._id, title: c.title, status: c.status })) : [];

  db.saveCorrelation({
    indicator, entity: indicator, source: 'manual',
    wazuh_hits: wazuhHits, hive_hits: hiveHits, ai_analysis: aiAnalysis,
  }).catch(() => {});

  res.json({ wazuhHits, hiveHits, aiAnalysis });
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
  const { alert, prompt, session_id, autoTriaged = false, deep_mode = false } = req.body;
  if (!prompt && !alert) return res.status(400).json({ error: 'alert or prompt required' });

  // Build alert key (deduplication) — deep mode bypasses cache so analyst gets fresh deep report
  const alertKey = alert ? `${alert.ruleId}_${alert.timestamp}_${alert.agent}_${alert.srcIp||''}` : null;

  // Check if already investigated — return cached report (skip for deep mode or force)
  if (alertKey && !deep_mode) {
    try {
      const cached = await db.getInvestigationByAlertKey(alertKey);
      if (cached && !req.body.force) {
        return res.json({
          response:         cached.report,
          structured:       cached.structured_verdict || null,
          deep_mode:        cached.deep_mode || false,
          cached:           true,
          investigation_id: cached.id,
          created_at:       cached.created_at,
          ok:               true,
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

  const message = prompt || `Investigate alert: ${JSON.stringify(alert)}`;

  // Fire n8n in background for automation pipelines — non-blocking, result ignored
  axios.post(N8N_INV, {
    action: 'investigate', message, alert: alert || null, deep_mode,
    session_id: session_id || `inv_${Date.now()}`,
    _user: req.user?.username || 'system', _role: req.user?.role || 'analyst',
  }, { timeout: 60_000, headers: { 'Content-Type': 'application/json' }, validateStatus: () => true })
    .catch(() => {});

  try {
    let text = '', structured = null;

    if (deep_mode) {
      // Deep mode: dedicated ReAct /investigate endpoint with 8+ tool calls + structured extractor
      const r = await axios.post(`${LANGCHAIN_URL}/investigate`, {
        message,
        model:     'auto',
        deep_mode: true,
      }, {
        timeout: 185_000,
        headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` },
      });
      const d = r.data;
      text       = d?.report || d?.response || d?.output || '';
      structured = d?.structured || null;
    } else {
      // Standard mode: fast tool-calling agent via /chat
      const r = await axios.post(`${LANGCHAIN_URL}/chat`, {
        message,
        history:  [],
        username: req.user?.username || 'system',
        role:     req.user?.role || 'analyst',
      }, {
        timeout: 180_000,
        headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` },
      });
      const d = r.data;
      text = d?.response || d?.output || d?.text || d?.report || d?.message ||
        (Array.isArray(d) ? (d[0]?.response || d[0]?.output || '') : '') || '';
    }

    if (!text) {
      return res.status(502).json({ error: 'LangChain agent returned an empty response. Check langchain-agent logs.' });
    }

    // Save to DB
    let savedId = null;
    if (alert) {
      try {
        const alertSeverity = alert.severity || (alert.level >= 12 ? 'critical' : alert.level >= 8 ? 'high' : alert.level >= 5 ? 'medium' : 'low');

        // Alert deduplication: find or create group for this IP+rule within 5-minute window
        let groupId = null, groupCount = 1;
        try {
          const grp = await db.upsertAlertGroup(alert.srcIp, alert.ruleId, alert.agent);
          groupId    = grp.id;
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
          alertId:          alert.id || alert._id,
          ruleId:           alert.ruleId,
          level:            alert.level,
          severity:         alertSeverity,
          agent:            alert.agent,
          srcIp:            alert.srcIp,
          description:      alert.description,
          mitre:            alert.mitre,
          timestamp:        alert.timestamp,
          report:           text,
          user:             req.user?.username || 'system',
          autoTriaged:      autoTriaged,
          durationMs:       Date.now() - startTime,
          rawAlert:         alert,
          compositeRisk,
          groupId,
          deepMode:         deep_mode,
          structuredVerdict: structured,
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
          deep_mode,
          timestamp:      new Date().toISOString(),
        });

        // Notification for manual investigations
        const notifTitle = deep_mode ? 'Deep Investigation Complete' : 'Investigation Complete';
        if (!autoTriaged) {
          db.createNotification(
            'alert', notifTitle,
            `Rule ${alert.ruleId} on ${alert.agent} — AI investigation finished.`,
            alertSeverity === 'critical' ? 'critical' : 'warning',
            req.user?.username || null,
            { investigation_id: savedId, rule_id: alert.ruleId, agent: alert.agent, deep_mode }
          ).catch(() => {});
        }

        // UEBA cross-correlation (non-blocking)
        runUebaCorrelation(savedId, alert).catch(() => {});

        // Cross-investigation memory — embed in RAG knowledge base (non-blocking)
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

    res.json({ response: text, structured, deep_mode, ok: true, investigation_id: savedId, cached: false });

  } catch (e) {
    const isTimeout = e.code === 'ECONNABORTED' || e.message?.includes('timeout');
    const isRefused = e.code === 'ECONNREFUSED';
    let msg = e.response?.data?.detail || e.message;
    if (isTimeout) msg = 'Investigation timed out (>3min). The alert may be complex — try again.';
    if (isRefused) msg = 'LangChain agent unreachable — check socpilots-langchain container.';
    console.error('[investigate]', msg);
    res.status(502).json({ error: msg });
  }
});

// ── INVESTIGATION HISTORY ──
app.get('/api/investigations', authMW, async (req, res) => {
  try {
    const { severity, agent, ruleId, q, sort_by, sort_dir, time_from, time_to } = req.query;
    const page      = parseInt(req.query.page)      || 1;
    const page_size = Math.min(parseInt(req.query.page_size) || parseInt(req.query.limit) || 50, 500);
    const [{ rows: rawItems, total }, stats] = await Promise.all([
      db.listInvestigations({ severity, agent, ruleId, q, sort_by, sort_dir, time_from, time_to, page, page_size }),
      db.getInvestigationStats(),
    ]);
    const items = rawItems.map(inv => ({
      ...inv,
      alert_short_id: inv.alert_id ? alertShortId(inv.alert_id) : null,
    }));
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
    const [related, comments] = await Promise.all([
      db.getRelatedInvestigations(inv.id, { srcIp: inv.src_ip, ruleId: inv.rule_id, agent: inv.agent }),
      db.getInvComments(inv.id),
    ]);
    const alert_short_id = inv.alert_id ? alertShortId(inv.alert_id) : null;
    res.json({ ...inv, alert_short_id, related, comments });
  } catch(e) {
    res.status(503).json({ error: 'DB unavailable: ' + e.message });
  }
});

// ── ALERT GROUPS (deduplication view) ──
app.get('/api/alert-groups', authMW, async (req, res) => {
  try {
    const page      = parseInt(req.query.page)      || 1;
    const page_size = Math.min(parseInt(req.query.page_size) || parseInt(req.query.limit) || 50, 500);
    const { severity, rule_id, agent, q } = req.query;
    const { rows: groups, total } = await db.listAlertGroups({ page, page_size, severity, rule_id, agent, q });
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

    // Invalidate FP cache so next triage cycle picks up the new ground truth
    if (tp_status === 'confirmed_tp' || tp_status === 'confirmed_fp') {
      refreshRuleFpCache().catch(() => {});
    }

    // Async: generate draft detection rule for every confirmed TP
    if (tp_status === 'confirmed_tp' && investigation) {
      generateDraftRule(investigation).catch(() => {});
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

// ── Per-rule FP rate cache ────────────────────────────────────────────────
// Refreshed from `investigations` table every 10 min.
// Blended with LangChain's real-time FP probability using Beta smoothing.
let _ruleFpCache = new Map(); // ruleId → { fp_count, tp_count, total_labelled }
let _ruleFpCacheTime = 0;

async function refreshRuleFpCache() {
  try {
    const rows = await db.getRuleFpRates();
    const next  = new Map();
    for (const r of rows) {
      next.set(String(r.rule_id), {
        fp_count:       parseInt(r.fp_count)       || 0,
        tp_count:       parseInt(r.tp_count)       || 0,
        total_labelled: parseInt(r.total_labelled) || 0,
        fp_rate_raw:    parseFloat(r.fp_rate_raw)  || 0,
      });
    }
    _ruleFpCache     = next;
    _ruleFpCacheTime = Date.now();
    console.log(`[FpCache] Refreshed — ${next.size} rules with ground truth`);
  } catch(e) {
    console.warn('[FpCache] Refresh failed:', e.message);
  }
}

// Beta smoothing + linear ramp blend.
// Prior: α=3, β=7 (30% FP with 10 pseudo-observations)
// Historical weight ramps from 0 → 0.7 as sample count grows 0 → 30.
function _getAdjustedFp(ruleId, langchainFp) {
  const entry = _ruleFpCache.get(String(ruleId));
  if (!entry || entry.total_labelled < 1) {
    return { adjusted_fp: langchainFp, langchain_fp: langchainFp, historical_rate: null, sample_count: 0, weight: 0 };
  }
  const { fp_count, total_labelled } = entry;
  const posteriorFp   = ((3 + fp_count) / (10 + total_labelled)) * 100;
  const w_hist        = Math.min(total_labelled / 30, 1) * 0.7;
  const adjusted_fp   = Math.round(w_hist * posteriorFp + (1 - w_hist) * langchainFp);
  return {
    adjusted_fp,
    langchain_fp:    langchainFp,
    historical_rate: Math.round(posteriorFp),
    sample_count:    total_labelled,
    weight:          Math.round(w_hist * 100),
  };
}

// Start: load on boot (after 20s so DB is ready) + every 10 min
setTimeout(() => refreshRuleFpCache(), 20000);
setInterval(() => refreshRuleFpCache(), 600000);

// ── Alert Suppression Cache ───────────────────────────────────────────────
let _suppressionCache = [];

async function refreshSuppressionCache() {
  try {
    _suppressionCache = await db.listSuppressions({ enabledOnly: true });
  } catch(e) { console.warn('[SuppCache] Refresh failed:', e.message); }
}

function _checkSuppressed(alert) {
  const now = Date.now();
  for (const s of _suppressionCache) {
    if (s.expires_at && new Date(s.expires_at).getTime() <= now) continue;
    if (s.rule_id       && s.rule_id !== String(alert.ruleId || '')) continue;
    if (s.agent_pattern && !(alert.agent || '').toLowerCase().includes(s.agent_pattern.toLowerCase())) continue;
    if (s.src_ip_pattern && !(alert.srcIp || '').startsWith(s.src_ip_pattern)) continue;
    if (s.min_level != null && (alert.level || 0) < s.min_level) continue;
    if (s.max_level != null && (alert.level || 0) > s.max_level) continue;
    return s;
  }
  return null;
}

setTimeout(() => refreshSuppressionCache(), 22000);
setInterval(() => refreshSuppressionCache(), 300000);

// ── AI Detection Rule Generator ───────────────────────────────────────────
async function generateDraftRule(investigation) {
  if (!OPENAI_API_KEY && !MISTRAL_API_KEY) return;
  try {
    const mitreList = (() => {
      try { return (Array.isArray(investigation.mitre) ? investigation.mitre : JSON.parse(investigation.mitre || '[]')).join(', ') || 'N/A'; }
      catch { return 'N/A'; }
    })();
    const reportExcerpt = (investigation.report || '').slice(0, 2000);
    const prompt = `You are a detection engineer. A security incident has been confirmed as a TRUE POSITIVE.
Generate detection rules to catch this attack pattern in the future.

Investigation context:
- Rule ID fired: ${investigation.rule_id || 'N/A'}
- Severity: ${investigation.severity || 'N/A'}
- Agent/Host: ${investigation.agent || 'N/A'}
- Alert description: ${investigation.description || 'N/A'}
- MITRE ATT&CK: ${mitreList}
- Investigation summary: ${reportExcerpt}

Generate:
1. A Wazuh XML detection rule (use rule id 199000-199999, valid XML with <group>, <rule>, <description>, <group name>, <mitre> tags)
2. A Sigma rule in YAML format (title, status, description, logsource, detection, condition, tags)

Return ONLY valid JSON with exactly these two fields (no markdown fences):
{"wazuh_xml":"...","sigma_yaml":"..."}`;

    let content = null;
    if (OPENAI_API_KEY) {
      const r = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: 'gpt-4o',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0,
      }, { headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' }, timeout: 60000 });
      content = r.data.choices[0]?.message?.content;
    } else if (MISTRAL_API_KEY) {
      const r = await axios.post('https://api.mistral.ai/v1/chat/completions', {
        model: 'mistral-large-latest',
        messages: [
          { role: 'system', content: 'You are a detection engineer. Return only valid JSON.' },
          { role: 'user', content: prompt },
        ],
        temperature: 0,
      }, { headers: { Authorization: `Bearer ${MISTRAL_API_KEY}`, 'Content-Type': 'application/json' }, timeout: 60000 });
      content = r.data.choices[0]?.message?.content;
    }

    if (!content) return;
    // Strip markdown fences if present
    const cleaned = content.replace(/^```(?:json)?\n?/,'').replace(/\n?```$/,'').trim();
    let parsed;
    try { parsed = JSON.parse(cleaned); } catch {
      // Last-resort: extract JSON block from the response
      const m = cleaned.match(/\{[\s\S]*\}/);
      if (!m) return;
      try { parsed = JSON.parse(m[0]); } catch { return; }
    }
    if (!parsed.wazuh_xml && !parsed.sigma_yaml) return;

    const mitreArr = (() => {
      try { return Array.isArray(investigation.mitre) ? investigation.mitre : JSON.parse(investigation.mitre || '[]'); }
      catch { return []; }
    })();

    const draft = await db.saveDraftRule({
      investigationId: investigation.id,
      ruleId:      investigation.rule_id,
      agent:       investigation.agent,
      severity:    investigation.severity,
      description: investigation.description,
      mitreT:      mitreArr,
      wazuhXml:    parsed.wazuh_xml,
      sigmaYaml:   parsed.sigma_yaml,
    });

    db.createNotification(
      'investigation', 'Draft Detection Rule Generated',
      `AI generated a draft Wazuh + Sigma rule for TP investigation on rule ${investigation.rule_id} (${investigation.agent}). Review in Dark SOC.`,
      'low', null, { draft_rule_id: draft.id, investigation_id: investigation.id }
    ).catch(() => {});
    console.log(`[DraftRules] Generated draft rule #${draft.id} for inv#${investigation.id}`);
  } catch(e) {
    console.warn(`[DraftRules] Generation failed for inv#${investigation?.id}:`, e.message);
  }
}

function _extractStructuredVerdict(triageData, alert, fpBlend = null) {
  const fpProb     = fpBlend ? fpBlend.adjusted_fp : (triageData?.false_positive_probability || 0);
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
    fp_blend_info:        fpBlend || null,
    mitre_techniques:     mitre,
    recommended_actions:  actions,
    summary:              (triageData?.summary || `Rule ${alert.ruleId||alert.rule_id} on ${alert.agent}`).slice(0, 300),
    risk_score:           Math.round(((alert.level || alert.rule_level || 0) / 15) * 100),
    requires_approval:    actions.some(a => DESTRUCTIVE_ACTIONS.has(a)) && verdict !== 'false_positive',
  };
}

function _buildMediumVerdict(alert, fpBlend = null) {
  const fpProb = fpBlend ? fpBlend.adjusted_fp : 60;
  return {
    verdict:             fpProb >= 70 ? 'false_positive' : 'needs_review',
    confidence:          Math.max(0, Math.min(100, 100 - fpProb)),
    fp_probability:      fpProb,
    fp_blend_info:       fpBlend || null,
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
  let uebaRisk = 0;
  if (alert.agent) {
    try {
      const profile = await ueba.getUserProfile(alert.agent);
      uebaRisk = profile?.risk_score || 0;
    } catch (_) {}
  }
  const matched = await db.getMatchingPlaybooks(
    alert.level || alert.rule_level || 0,
    alert.mitre || [],
    uebaRisk
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
    const uebaNote = uebaRisk >= 50 ? ` [UEBA risk: ${uebaRisk}]` : '';
    db.createNotification(
      'playbook', 'Action Approval Required',
      `Triage for rule ${alert.ruleId||alert.rule_id} on ${alert.agent}${uebaNote} recommends ${(verdict.recommended_actions||[]).join(', ')} — awaiting analyst approval.`,
      'warning', null, { approval_id: approval.id, investigation_id: savedId, ueba_risk: uebaRisk }
    ).catch(() => {});
    console.log(`[TriageProcessor] APPROVAL QUEUED inv#${savedId} → approval#${approval.id} (ueba_risk=${uebaRisk})`);
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
  if (_osBackpressure('triageFeeder')) return;
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
        const level    = h._source.rule?.level || 0;
        const alertKey = `${ruleId}_${ts}_${agent}_${srcIp}`;

        const suppressed = _checkSuppressed({ ruleId, agent, srcIp, level });
        if (suppressed) {
          db.bumpSuppressionHit(suppressed.id).catch(() => {});
          continue;
        }

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
  if (_osBackpressure('triageProcessor')) return;
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

        const fpBlend = _getAdjustedFp(item.rule_id, fpProbability);
        const verdict = _extractStructuredVerdict(triageData, alert, fpBlend);
        const saved   = await _saveTriageInvestigation({ alert, report: text, tier: 'critical', durationMs: Date.now()-start, queueId: item.id, structuredVerdict: verdict });
        await db.markQueueItemDone(item.id, saved.id);
        if (darkSoc === 'true') await _routeActionsOrApproval(alert, text, saved.id, fpBlend.adjusted_fp, verdict);
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

        const fpBlend    = _getAdjustedFp(item.rule_id, raw?.false_positive_probability || 0);
        const verdict    = _extractStructuredVerdict(raw, alert, fpBlend);
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
        if (darkSoc === 'true') await _routeActionsOrApproval(alert, report, saved.id, fpBlend.adjusted_fp, verdict);
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
        const fpBlend = _getAdjustedFp(item.rule_id, 60);
        const verdict = _buildMediumVerdict(alert, fpBlend);
        const report  = await _buildMediumReport(alert);
        const saved   = await _saveTriageInvestigation({ alert, report, tier: 'medium', durationMs: Date.now()-start, queueId: item.id, structuredVerdict: verdict });
        await db.markQueueItemDone(item.id, saved.id);
        if (darkSoc === 'true') await _routeActionsOrApproval(alert, report, saved.id, fpBlend.adjusted_fp, verdict);
        console.log(`[TriageProcessor] MEDIUM ${item.rule_id} → inv#${saved.id} (${Date.now()-start}ms)`);
      } catch(e) {
        console.warn(`[TriageProcessor] MEDIUM ${item.rule_id} failed:`, e.message);
        await db.markQueueItemFailed(item.id, e.message);
      }
    }

    // ── Low tier: UEBA promotion check before bulk suppress ─────
    try {
      const allPlaybooks = await db.listPlaybooks({ enabledOnly: true });
      const uebaPlaybooks = allPlaybooks.filter(pb => pb.ueba_risk_min != null);
      if (uebaPlaybooks.length > 0 && darkSoc === 'true') {
        const minUebaThreshold = Math.min(...uebaPlaybooks.map(pb => pb.ueba_risk_min));
        const pendingLow = await db.pool.query(
          `SELECT id, rule_id, agent, alert_data FROM triage_queue WHERE status='pending' AND triage_tier='low'`
        );
        const toPromote = [];
        for (const item of pendingLow.rows) {
          const agentName = item.agent;
          if (!agentName) continue;
          try {
            const profile = await ueba.getUserProfile(agentName);
            const risk = profile?.risk_score || 0;
            if (risk >= minUebaThreshold) toPromote.push(item.id);
          } catch (_) {}
        }
        if (toPromote.length > 0) {
          await db.pool.query(
            `UPDATE triage_queue SET triage_tier='medium' WHERE id = ANY($1::int[])`,
            [toPromote]
          );
          console.log(`[TriageProcessor] UEBA promoted ${toPromote.length} low→medium items`);
        }
      }
    } catch(e) { console.warn('[TriageProcessor] UEBA low-tier promotion error:', e.message); }

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
// Boot delay: feeder after 90s, processor after 120s (give OS time to settle before first run)
setTimeout(() => { triageFeeder(); }, 90000);
setTimeout(() => { triageProcessor(); }, 120000);

// ── UEBA AUTO-INGEST from Wazuh/OpenSearch ─────────────────────────
// Polls OpenSearch every 2 min, maps alert fields → UEBA events
let _uebaLastRun = 0;
let _uebaRunning = false;

async function uebaIngestWorker() {
  if (_uebaRunning) return;
  if (Date.now() - _uebaLastRun < 110_000) return;
  if (_osBackpressure('uebaIngest')) return;
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
setTimeout(() => { uebaIngestWorker(); }, 60_000); // first run 60s after boot (staggered from triage)

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
  if (_osBackpressure('lateralMovement')) return;
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
app.get('/api/reports', authMW, async (req, res) => {
  res.json({ items: [], total: 0 });
});

app.get('/api/vulns', authMW, async (req, res) => {
  res.json({ items: [], total: 0 });
});

app.get('/api/reports/summary', authMW, async (req, res) => {
  const TYPE_PROMPTS = {
    exec:       'Generate a professional SOC executive summary for today. Include: 1) Alert volume and severity breakdown, 2) Top threats and MITRE techniques observed, 3) Critical incidents requiring attention, 4) Case management status, 5) Recommended immediate actions. Use markdown headers. Be concise and professional.',
    threat:     'Generate a threat intelligence report. Include: 1) Top IOC categories observed, 2) MITRE ATT&CK techniques detected, 3) Most active threat actors or campaigns, 4) High-risk source IPs and domains, 5) Recommended detection improvements. Use markdown.',
    compliance: 'Generate a compliance status report. Include: 1) SOC 2 / ISO 27001 control coverage summary, 2) Log source coverage and gaps, 3) Unanswered alerts SLA breach risk, 4) User access anomalies, 5) Recommended remediation steps. Use markdown.',
    incident:   'Generate an incident retrospective report. Include: 1) Incident timeline summary, 2) Root cause analysis, 3) Affected systems and blast radius, 4) Response actions taken, 5) Lessons learned and prevention recommendations. Use markdown.',
  };
  const prompt = TYPE_PROMPTS[req.query.type] || TYPE_PROMPTS.exec;

  // Try n8n first
  const r = await n8nAsk(prompt, 'soc-report', req.user);
  if (r.ok && r.text) return res.json({ text: r.text, ok: true });

  // n8n unavailable — fall back to LangChain /chat directly
  try {
    const lc = await axios.post(`${LANGCHAIN_URL}/chat`, {
      message: prompt, history: [],
      username: req.user?.username || 'system',
      role:     req.user?.role     || 'analyst',
    }, { timeout: 120_000, headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` } });
    const text = lc.data?.response || lc.data?.output || lc.data?.text || '';
    if (text) return res.json({ text, ok: true });
  } catch (e) { console.error('[reports/summary]', e.message); }

  res.status(502).json({ ok: false, error: 'AI engine unavailable — n8n and LangChain unreachable' });
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

app.delete('/api/ueba/data', authMW, requireRole('admin'), async (req, res) => {
  try {
    const daysOld = Math.max(1, parseInt(req.query.older_than_days) || 30);
    const result = await ueba.purgeOldData(daysOld);
    console.log(`[UEBA] Purge by ${req.user.username}: >=${daysOld}d old — rels=${result.relationships} nodes=${result.nodes} resets=${result.risk_scores_reset}`);
    res.json({ ok: true, days_old: daysOld, ...result });
  } catch(e) { res.status(500).json({ error: e.message }); }
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
    db.logAudit(req.user.username, 'user.create', 'user', user.id,
      { target_username: username, role: role || 'l1' }, req.ip);
    res.json({ user });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/users/:id', authMW, requireRole('admin'), async (req, res) => {
  const { role, display_name, email, active } = req.body || {};
  try {
    const updated = await db.updateUser(parseInt(req.params.id), { role, display_name, email, active });
    if (!updated) return res.status(404).json({ error: 'user not found' });
    db.logAudit(req.user.username, 'user.update', 'user', req.params.id,
      { target_username: updated.username, role, display_name, active }, req.ip);
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
    db.logAudit(req.user.username, 'user.delete', 'user', req.params.id,
      { target_username: target.username }, req.ip);
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
    db.logAudit(req.user.username, isSelf ? 'password.self_change' : 'password.admin_reset',
      'user', targetId, { target_username: target.username }, req.ip);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/audit-log ───────────────────────────────────────────
app.get('/api/audit-log', authMW, async (req, res) => {
  try {
    const page          = Math.max(parseInt(req.query.page) || 1, 1);
    const page_size     = Math.min(parseInt(req.query.page_size) || 50, 200);
    const isAdmin       = (ROLE_HIERARCHY[req.user.role] || 0) >= ROLE_HIERARCHY.admin;
    // Non-admins can only see their own activity
    const filterUser    = isAdmin ? (req.query.username || null) : req.user.username;
    const action        = isAdmin ? (req.query.action        || null) : null;
    const resource_type = isAdmin ? (req.query.resource_type || null) : null;
    const date_from     = req.query.date_from || null;
    const date_to       = req.query.date_to   || null;
    const { rows, total } = await db.listAuditLog({
      page, page_size,
      username: filterUser, action, resource_type, date_from, date_to
    });
    res.json({ items: rows, total, page, page_size, has_more: page * page_size < total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/audit-log/actions', authMW, requireRole('admin'), async (req, res) => {
  try {
    const actions = await db.getAuditActions();
    res.json({ actions });
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
  aws:                  { type: 'cloud_api', vendor: 'AWS CloudTrail' },
  'aws-cloudtrail':     { type: 'cloud_api', vendor: 'AWS CloudTrail' },
  'aws-guardduty':      { type: 'cloud_api', vendor: 'AWS GuardDuty' },
  'aws-securityhub':    { type: 'cloud_api', vendor: 'AWS Security Hub' },
  'aws-waf':            { type: 'waf',       vendor: 'AWS WAF' },
  'aws-s3':             { type: 'cloud_api', vendor: 'AWS S3' },
  azure:                { type: 'cloud_api', vendor: 'Microsoft Azure' },
  'azure-ad':           { type: 'cloud_api', vendor: 'Microsoft Azure AD' },
  'azure-activity':     { type: 'cloud_api', vendor: 'Microsoft Azure' },
  'azure-storage':      { type: 'cloud_api', vendor: 'Microsoft Azure' },
  'azure-security':     { type: 'cloud_api', vendor: 'Microsoft Azure' },
  'ms-graph':           { type: 'cloud_api', vendor: 'Microsoft 365' },
  office365:            { type: 'cloud_api', vendor: 'Microsoft 365' },
  gcp:                  { type: 'cloud_api', vendor: 'Google Cloud Platform' },
  'google-workspace':   { type: 'cloud_api', vendor: 'Google Workspace' },
  'google-cloud':       { type: 'cloud_api', vendor: 'Google Cloud Platform' },
  gsuite:               { type: 'cloud_api', vendor: 'Google Workspace' },
  google:               { type: 'cloud_api', vendor: 'Google Workspace' },
  // Cloudflare
  cloudflare:           { type: 'cloud_api', vendor: 'Cloudflare' },
  'cloudflare-waf':     { type: 'waf',       vendor: 'Cloudflare WAF' },
  'cloudflare-dns':     { type: 'network',   vendor: 'Cloudflare DNS' },
  'cloudflare-access':  { type: 'cloud_api', vendor: 'Cloudflare Access' },
  // Identity providers
  okta:                 { type: 'cloud_api', vendor: 'Okta' },
  'okta-system-log':    { type: 'cloud_api', vendor: 'Okta' },
  duo:                  { type: 'cloud_api', vendor: 'Duo Security' },
  'ping-identity':      { type: 'cloud_api', vendor: 'Ping Identity' },
  onelogin:             { type: 'cloud_api', vendor: 'OneLogin' },
  // Developer platforms
  github:               { type: 'cloud_api', vendor: 'GitHub' },
  'github-audit':       { type: 'cloud_api', vendor: 'GitHub' },
  gitlab:               { type: 'cloud_api', vendor: 'GitLab' },
  // Collaboration / SaaS
  slack:                { type: 'cloud_api', vendor: 'Slack' },
  zoom:                 { type: 'cloud_api', vendor: 'Zoom' },
  box:                  { type: 'cloud_api', vendor: 'Box' },
  dropbox:              { type: 'cloud_api', vendor: 'Dropbox' },
  salesforce:           { type: 'cloud_api', vendor: 'Salesforce' },
  servicenow:           { type: 'cloud_api', vendor: 'ServiceNow' },
  jira:                 { type: 'cloud_api', vendor: 'Jira / Confluence' },
  // Security services
  virustotal:           { type: 'cloud_api', vendor: 'VirusTotal' },
  'ms-defender':        { type: 'cloud_api', vendor: 'Microsoft Defender' },
  'windows-defender':   { type: 'cloud_api', vendor: 'Microsoft Defender' },
  sentinelone:          { type: 'cloud_api', vendor: 'SentinelOne' },
  crowdstrike:          { type: 'cloud_api', vendor: 'CrowdStrike' },
  'carbon-black':       { type: 'cloud_api', vendor: 'VMware Carbon Black' },
  carbonblack:          { type: 'cloud_api', vendor: 'VMware Carbon Black' },
  cylance:              { type: 'cloud_api', vendor: 'Cylance (BlackBerry)' },
  tenable:              { type: 'cloud_api', vendor: 'Tenable.io' },
  'qualys':             { type: 'cloud_api', vendor: 'Qualys' },
  'rapid7':             { type: 'cloud_api', vendor: 'Rapid7 InsightVM' },
  'darktrace':          { type: 'cloud_api', vendor: 'Darktrace' },
  'vectra':             { type: 'cloud_api', vendor: 'Vectra AI' },
};

const LS_PROGRAM_MAP = {
  // Fortinet
  fortigate:        { type: 'firewall', vendor: 'Fortinet' },
  fgtd:             { type: 'firewall', vendor: 'Fortinet' },
  fortianalyzer:    { type: 'cloud_api', vendor: 'Fortinet FortiAnalyzer' },
  fortiproxy:       { type: 'proxy',   vendor: 'Fortinet FortiProxy' },
  fortisiem:        { type: 'cloud_api', vendor: 'Fortinet FortiSIEM' },
  // Palo Alto
  paloalto:         { type: 'firewall', vendor: 'Palo Alto Networks' },
  'pan-os':         { type: 'firewall', vendor: 'Palo Alto Networks' },
  'panos':          { type: 'firewall', vendor: 'Palo Alto Networks' },
  panorama:         { type: 'firewall', vendor: 'Palo Alto Panorama' },
  // Check Point
  checkpoint:       { type: 'firewall', vendor: 'Check Point' },
  'check-point':    { type: 'firewall', vendor: 'Check Point' },
  // Cisco
  'cisco-asa':      { type: 'firewall', vendor: 'Cisco ASA' },
  'cisco-ios':      { type: 'network',  vendor: 'Cisco IOS' },
  'cisco-ftd':      { type: 'firewall', vendor: 'Cisco FTD (Firepower)' },
  'cisco-meraki':   { type: 'network',  vendor: 'Cisco Meraki' },
  'cisco-ise':      { type: 'cloud_api', vendor: 'Cisco ISE' },
  'cisco-nx-os':    { type: 'network',  vendor: 'Cisco NX-OS' },
  // Juniper
  juniper:          { type: 'firewall', vendor: 'Juniper Networks' },
  'junos':          { type: 'firewall', vendor: 'Juniper Networks' },
  'srx':            { type: 'firewall', vendor: 'Juniper SRX' },
  // F5
  'f5-bigip':       { type: 'waf',      vendor: 'F5 BIG-IP' },
  'f5-asm':         { type: 'waf',      vendor: 'F5 ASM' },
  'f5-ltm':         { type: 'network',  vendor: 'F5 LTM' },
  // Sophos
  sophos:           { type: 'firewall', vendor: 'Sophos' },
  'sophos-xg':      { type: 'firewall', vendor: 'Sophos XG Firewall' },
  // Zscaler
  zscaler:          { type: 'proxy',    vendor: 'Zscaler' },
  'zscaler-zia':    { type: 'proxy',    vendor: 'Zscaler ZIA' },
  'zscaler-zpa':    { type: 'cloud_api', vendor: 'Zscaler ZPA' },
  // Proxies & load balancers
  bluecoat:         { type: 'proxy',    vendor: 'Blue Coat' },
  squid:            { type: 'proxy',    vendor: 'Squid Proxy' },
  haproxy:          { type: 'proxy',    vendor: 'HAProxy' },
  traefik:          { type: 'proxy',    vendor: 'Traefik' },
  varnish:          { type: 'proxy',    vendor: 'Varnish Cache' },
  // Barracuda
  barracuda:        { type: 'waf',      vendor: 'Barracuda WAF' },
  'barracuda-waf':  { type: 'waf',      vendor: 'Barracuda WAF' },
  // pfSense / OPNsense
  pfsense:          { type: 'firewall', vendor: 'pfSense' },
  opnsense:         { type: 'firewall', vendor: 'OPNsense' },
  // Cloudflare
  cloudflared:      { type: 'cloud_api', vendor: 'Cloudflare' },
  cloudflare:       { type: 'cloud_api', vendor: 'Cloudflare' },
  // Misc network
  'mikrotik':       { type: 'network',  vendor: 'MikroTik' },
  'ubiquiti':       { type: 'network',  vendor: 'Ubiquiti UniFi' },
  'aruba':          { type: 'network',  vendor: 'Aruba Networks' },
};

const LS_DECODER_MAP = {
  // Web servers / proxies
  'nginx-accesslog':      { type: 'proxy',     vendor: 'nginx' },
  'nginx-errorlog':       { type: 'proxy',     vendor: 'nginx' },
  'apache-errorlog':      { type: 'proxy',     vendor: 'Apache' },
  'apache-access':        { type: 'proxy',     vendor: 'Apache' },
  'iis':                  { type: 'proxy',     vendor: 'Microsoft IIS' },
  'haproxy':              { type: 'proxy',     vendor: 'HAProxy' },
  'traefik':              { type: 'proxy',     vendor: 'Traefik' },
  // Linux / server
  sshd:                   { type: 'server',    vendor: 'OpenSSH' },
  syscheck_new_entry:     { type: 'server',    vendor: 'Wazuh FIM' },
  syscheck_deleted:       { type: 'server',    vendor: 'Wazuh FIM' },
  syscheck_integrity_changed: { type: 'server', vendor: 'Wazuh FIM' },
  'linux-kernel':         { type: 'server',    vendor: 'Linux Kernel' },
  'auditd':               { type: 'server',    vendor: 'Linux Auditd' },
  'sudo':                 { type: 'server',    vendor: 'Linux sudo' },
  'cron':                 { type: 'server',    vendor: 'Linux cron' },
  // Windows
  'sysmon':               { type: 'server',    vendor: 'Sysmon (Windows)' },
  'windows-eventchannel': { type: 'server',    vendor: 'Windows Event Log' },
  'windows_eventchannel': { type: 'server',    vendor: 'Windows Event Log' },
  'win-eventchannel':     { type: 'server',    vendor: 'Windows Event Log' },
  'win_eventchannel':     { type: 'server',    vendor: 'Windows Event Log' },
  'mssql':                { type: 'server',    vendor: 'Microsoft SQL Server' },
  'iis-access':           { type: 'proxy',     vendor: 'Microsoft IIS' },
  // Network IDS/IPS
  'suricata':             { type: 'network',   vendor: 'Suricata IDS' },
  'zeek':                 { type: 'network',   vendor: 'Zeek IDS' },
  'snort':                { type: 'network',   vendor: 'Snort IDS' },
  // Cloudflare decoders
  cloudflare:             { type: 'cloud_api', vendor: 'Cloudflare' },
  'cloudflare-json':      { type: 'cloud_api', vendor: 'Cloudflare' },
  'cloudflare-waf':       { type: 'waf',       vendor: 'Cloudflare WAF' },
  'cloudflare-access':    { type: 'cloud_api', vendor: 'Cloudflare Access' },
  // Azure / Microsoft decoders
  azure:                  { type: 'cloud_api', vendor: 'Microsoft Azure' },
  'azure-ad':             { type: 'cloud_api', vendor: 'Microsoft Azure AD' },
  'azure-activity':       { type: 'cloud_api', vendor: 'Microsoft Azure' },
  // AWS decoders
  'aws-cloudtrail':       { type: 'cloud_api', vendor: 'AWS CloudTrail' },
  'aws-guardduty':        { type: 'cloud_api', vendor: 'AWS GuardDuty' },
  // Google decoders
  'google-workspace':     { type: 'cloud_api', vendor: 'Google Workspace' },
  'gcp-pubsub':           { type: 'cloud_api', vendor: 'Google Cloud Platform' },
  // Okta decoder
  'okta':                 { type: 'cloud_api', vendor: 'Okta' },
  // Network device decoders
  'cisco-asa':            { type: 'firewall',  vendor: 'Cisco ASA' },
  'cisco-ftd':            { type: 'firewall',  vendor: 'Cisco FTD (Firepower)' },
  'pf':                   { type: 'firewall',  vendor: 'pfSense' },
  'sophos':               { type: 'firewall',  vendor: 'Sophos' },
  'f5-bigip':             { type: 'waf',       vendor: 'F5 BIG-IP' },
};

const LS_GROUP_MAP = {
  // Web servers
  nginx:                { type: 'proxy',     vendor: 'nginx' },
  web:                  { type: 'proxy',     vendor: null },
  apache:               { type: 'proxy',     vendor: 'Apache' },
  iis:                  { type: 'proxy',     vendor: 'Microsoft IIS' },
  haproxy:              { type: 'proxy',     vendor: 'HAProxy' },
  // Linux
  syscheck:             { type: 'server',    vendor: 'Wazuh FIM' },
  sshd:                 { type: 'server',    vendor: 'OpenSSH' },
  authentication_failed:{ type: 'server',    vendor: null },
  pam:                  { type: 'server',    vendor: null },
  auditd:               { type: 'server',    vendor: 'Linux Auditd' },
  // Windows
  sysmon:               { type: 'server',    vendor: 'Sysmon (Windows)' },
  windows:              { type: 'server',    vendor: 'Windows Event Log' },
  win_evt:              { type: 'server',    vendor: 'Windows Event Log' },
  mssql:                { type: 'server',    vendor: 'Microsoft SQL Server' },
  // Firewalls (generic group names)
  firewall:             { type: 'firewall',  vendor: null },
  'cisco-asa':          { type: 'firewall',  vendor: 'Cisco ASA' },
  'cisco-ftd':          { type: 'firewall',  vendor: 'Cisco FTD (Firepower)' },
  juniper:              { type: 'firewall',  vendor: 'Juniper Networks' },
  sophos:               { type: 'firewall',  vendor: 'Sophos' },
  pfsense:              { type: 'firewall',  vendor: 'pfSense' },
  opnsense:             { type: 'firewall',  vendor: 'OPNsense' },
  // Network IDS/IPS
  suricata:             { type: 'network',   vendor: 'Suricata IDS' },
  zeek:                 { type: 'network',   vendor: 'Zeek IDS' },
  snort:                { type: 'network',   vendor: 'Snort IDS' },
  // Cloud: Cloudflare
  cloudflare:           { type: 'cloud_api', vendor: 'Cloudflare' },
  'cloudflare-waf':     { type: 'waf',       vendor: 'Cloudflare WAF' },
  'cloudflare-dns':     { type: 'network',   vendor: 'Cloudflare DNS' },
  cloudflare_waf:       { type: 'waf',       vendor: 'Cloudflare WAF' },
  cloudflare_dns:       { type: 'network',   vendor: 'Cloudflare DNS' },
  // Cloud: Microsoft
  azure:                { type: 'cloud_api', vendor: 'Microsoft Azure' },
  azure_ad:             { type: 'cloud_api', vendor: 'Microsoft Azure AD' },
  'azure-ad':           { type: 'cloud_api', vendor: 'Microsoft Azure AD' },
  office365:            { type: 'cloud_api', vendor: 'Microsoft 365' },
  'ms-defender':        { type: 'cloud_api', vendor: 'Microsoft Defender' },
  windows_defender:     { type: 'cloud_api', vendor: 'Microsoft Defender' },
  // Cloud: AWS
  aws:                  { type: 'cloud_api', vendor: 'AWS CloudTrail' },
  aws_cloudtrail:       { type: 'cloud_api', vendor: 'AWS CloudTrail' },
  aws_guardduty:        { type: 'cloud_api', vendor: 'AWS GuardDuty' },
  // Cloud: Google
  gcp:                  { type: 'cloud_api', vendor: 'Google Cloud Platform' },
  google_workspace:     { type: 'cloud_api', vendor: 'Google Workspace' },
  gsuite:               { type: 'cloud_api', vendor: 'Google Workspace' },
  // Cloud: Identity
  okta:                 { type: 'cloud_api', vendor: 'Okta' },
  duo:                  { type: 'cloud_api', vendor: 'Duo Security' },
  // Cloud: Dev / Collaboration
  github:               { type: 'cloud_api', vendor: 'GitHub' },
  gitlab:               { type: 'cloud_api', vendor: 'GitLab' },
  slack:                { type: 'cloud_api', vendor: 'Slack' },
  // Cloud: Security
  crowdstrike:          { type: 'cloud_api', vendor: 'CrowdStrike' },
  sentinelone:          { type: 'cloud_api', vendor: 'SentinelOne' },
  carbonblack:          { type: 'cloud_api', vendor: 'VMware Carbon Black' },
  tenable:              { type: 'cloud_api', vendor: 'Tenable.io' },
};

// Last-resort: match against agent name / integration name / decoder / groups with regex
const LS_NAME_PATTERNS = [
  // Cloud: Cloudflare
  { re: /cloudflare/i,                     type: 'cloud_api', vendor: 'Cloudflare',                confidence: 0.88 },
  // Cloud: Microsoft
  { re: /azure[\s\-_]?ad/i,               type: 'cloud_api', vendor: 'Microsoft Azure AD',        confidence: 0.88 },
  { re: /azure/i,                          type: 'cloud_api', vendor: 'Microsoft Azure',           confidence: 0.85 },
  { re: /microsoft[\s\-_]?365/i,          type: 'cloud_api', vendor: 'Microsoft 365',             confidence: 0.88 },
  { re: /office[\s\-_]?365/i,             type: 'cloud_api', vendor: 'Microsoft 365',             confidence: 0.88 },
  { re: /ms[\s\-_]?graph/i,               type: 'cloud_api', vendor: 'Microsoft 365',             confidence: 0.88 },
  { re: /defender/i,                       type: 'cloud_api', vendor: 'Microsoft Defender',        confidence: 0.85 },
  // Cloud: AWS
  { re: /aws|cloudtrail/i,                 type: 'cloud_api', vendor: 'AWS CloudTrail',            confidence: 0.85 },
  { re: /guardduty/i,                      type: 'cloud_api', vendor: 'AWS GuardDuty',             confidence: 0.87 },
  // Cloud: Google
  { re: /google[\s\-_]?workspace|gsuite/i, type: 'cloud_api', vendor: 'Google Workspace',         confidence: 0.88 },
  { re: /google[\s\-_]?cloud|gcp/i,        type: 'cloud_api', vendor: 'Google Cloud Platform',    confidence: 0.87 },
  // Cloud: Identity
  { re: /okta/i,                           type: 'cloud_api', vendor: 'Okta',                      confidence: 0.90 },
  { re: /duo[\s\-_]?security|duo\.com/i,   type: 'cloud_api', vendor: 'Duo Security',              confidence: 0.88 },
  { re: /ping[\s\-_]?identity/i,           type: 'cloud_api', vendor: 'Ping Identity',             confidence: 0.87 },
  { re: /onelogin/i,                        type: 'cloud_api', vendor: 'OneLogin',                 confidence: 0.88 },
  // Cloud: EDR / Security
  { re: /crowdstrike/i,                    type: 'cloud_api', vendor: 'CrowdStrike',               confidence: 0.90 },
  { re: /sentinelone/i,                    type: 'cloud_api', vendor: 'SentinelOne',               confidence: 0.90 },
  { re: /carbon[\s\-_]?black/i,            type: 'cloud_api', vendor: 'VMware Carbon Black',       confidence: 0.88 },
  { re: /cylance/i,                         type: 'cloud_api', vendor: 'Cylance (BlackBerry)',     confidence: 0.87 },
  { re: /darktrace/i,                       type: 'cloud_api', vendor: 'Darktrace',                confidence: 0.88 },
  { re: /vectra/i,                          type: 'cloud_api', vendor: 'Vectra AI',                confidence: 0.87 },
  { re: /tenable/i,                         type: 'cloud_api', vendor: 'Tenable.io',               confidence: 0.87 },
  { re: /qualys/i,                          type: 'cloud_api', vendor: 'Qualys',                   confidence: 0.87 },
  // Cloud: Dev / Collab
  { re: /github/i,                          type: 'cloud_api', vendor: 'GitHub',                   confidence: 0.88 },
  { re: /gitlab/i,                          type: 'cloud_api', vendor: 'GitLab',                   confidence: 0.88 },
  { re: /salesforce/i,                      type: 'cloud_api', vendor: 'Salesforce',               confidence: 0.87 },
  // Firewalls
  { re: /fortinet|fortigate/i,             type: 'firewall',  vendor: 'Fortinet',                  confidence: 0.87 },
  { re: /palo[\s\-_]?alto|pan.?os/i,       type: 'firewall',  vendor: 'Palo Alto Networks',        confidence: 0.87 },
  { re: /check[\s\-_]?point/i,             type: 'firewall',  vendor: 'Check Point',               confidence: 0.87 },
  { re: /cisco[\s\-_]?asa/i,               type: 'firewall',  vendor: 'Cisco ASA',                 confidence: 0.87 },
  { re: /cisco[\s\-_]?ftd|firepower/i,     type: 'firewall',  vendor: 'Cisco FTD (Firepower)',     confidence: 0.87 },
  { re: /cisco[\s\-_]?meraki/i,            type: 'network',   vendor: 'Cisco Meraki',              confidence: 0.87 },
  { re: /juniper|junos|srx\d/i,            type: 'firewall',  vendor: 'Juniper Networks',          confidence: 0.87 },
  { re: /sophos/i,                          type: 'firewall',  vendor: 'Sophos',                   confidence: 0.87 },
  { re: /pfsense/i,                         type: 'firewall',  vendor: 'pfSense',                  confidence: 0.87 },
  { re: /opnsense/i,                        type: 'firewall',  vendor: 'OPNsense',                 confidence: 0.87 },
  { re: /barracuda/i,                       type: 'waf',       vendor: 'Barracuda WAF',            confidence: 0.87 },
  // Network / Proxy
  { re: /zscaler/i,                         type: 'proxy',     vendor: 'Zscaler',                  confidence: 0.88 },
  { re: /haproxy/i,                         type: 'proxy',     vendor: 'HAProxy',                  confidence: 0.88 },
  { re: /f5[\s\-_]?big.?ip|f5[\s\-_]?asm/i,type: 'waf',      vendor: 'F5 BIG-IP',                confidence: 0.88 },
  // Windows / Sysmon
  { re: /sysmon/i,                          type: 'server',    vendor: 'Sysmon (Windows)',         confidence: 0.90 },
  // IDS/IPS
  { re: /suricata/i,                        type: 'network',   vendor: 'Suricata IDS',             confidence: 0.90 },
  { re: /zeek|bro[\s\-_]?ids/i,            type: 'network',   vendor: 'Zeek IDS',                 confidence: 0.90 },
  { re: /snort/i,                           type: 'network',   vendor: 'Snort IDS',                confidence: 0.88 },
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
  // Cloudflare
  cloudflare:           { vendor: 'Cloudflare',              type: 'cloud_api' },
  'cloudflare-waf':     { vendor: 'Cloudflare WAF',          type: 'waf'       },
  cloudflare_waf:       { vendor: 'Cloudflare WAF',          type: 'waf'       },
  'cloudflare-dns':     { vendor: 'Cloudflare DNS',          type: 'network'   },
  cloudflare_dns:       { vendor: 'Cloudflare DNS',          type: 'network'   },
  // Microsoft
  azure:                { vendor: 'Microsoft Azure',         type: 'cloud_api' },
  azure_ad:             { vendor: 'Microsoft Azure AD',      type: 'cloud_api' },
  'azure-ad':           { vendor: 'Microsoft Azure AD',      type: 'cloud_api' },
  office365:            { vendor: 'Microsoft 365',           type: 'cloud_api' },
  'ms-graph':           { vendor: 'Microsoft 365',           type: 'cloud_api' },
  'ms-defender':        { vendor: 'Microsoft Defender',      type: 'cloud_api' },
  windows_defender:     { vendor: 'Microsoft Defender',      type: 'cloud_api' },
  // AWS
  aws:                  { vendor: 'AWS CloudTrail',          type: 'cloud_api' },
  aws_cloudtrail:       { vendor: 'AWS CloudTrail',          type: 'cloud_api' },
  'aws-cloudtrail':     { vendor: 'AWS CloudTrail',          type: 'cloud_api' },
  aws_guardduty:        { vendor: 'AWS GuardDuty',           type: 'cloud_api' },
  'aws-guardduty':      { vendor: 'AWS GuardDuty',           type: 'cloud_api' },
  aws_securityhub:      { vendor: 'AWS Security Hub',        type: 'cloud_api' },
  aws_waf:              { vendor: 'AWS WAF',                  type: 'waf'       },
  // Google
  gcp:                  { vendor: 'Google Cloud Platform',   type: 'cloud_api' },
  google_workspace:     { vendor: 'Google Workspace',        type: 'cloud_api' },
  gsuite:               { vendor: 'Google Workspace',        type: 'cloud_api' },
  google:               { vendor: 'Google Workspace',        type: 'cloud_api' },
  'google-workspace':   { vendor: 'Google Workspace',        type: 'cloud_api' },
  // Identity
  okta:                 { vendor: 'Okta',                     type: 'cloud_api' },
  duo:                  { vendor: 'Duo Security',             type: 'cloud_api' },
  // Dev / Collaboration
  github:               { vendor: 'GitHub',                   type: 'cloud_api' },
  gitlab:               { vendor: 'GitLab',                   type: 'cloud_api' },
  slack:                { vendor: 'Slack',                    type: 'cloud_api' },
  salesforce:           { vendor: 'Salesforce',               type: 'cloud_api' },
  // EDR / Security
  crowdstrike:          { vendor: 'CrowdStrike',              type: 'cloud_api' },
  sentinelone:          { vendor: 'SentinelOne',              type: 'cloud_api' },
  carbonblack:          { vendor: 'VMware Carbon Black',      type: 'cloud_api' },
  'carbon-black':       { vendor: 'VMware Carbon Black',      type: 'cloud_api' },
  tenable:              { vendor: 'Tenable.io',               type: 'cloud_api' },
  qualys:               { vendor: 'Qualys',                   type: 'cloud_api' },
  darktrace:            { vendor: 'Darktrace',                type: 'cloud_api' },
};

async function _fetchLogSources(maxRetries = 2) {

    // Two queries instead of four: use filter aggs to get both 24h and 7d counts in one round-trip
    const [rAgents, rCloud] = await Promise.all([
      // Agent sources: single 7d query with a filter sub-agg for 24h counts
      osSearch({
        size: 0,
        query: { range: { '@timestamp': { gte: 'now-7d' } } },
        aggs: {
          by_source: {
            terms: { field: 'agent.id', size: 100 },
            aggs: {
              agent_name:    { terms: { field: 'agent.name',              size: 1 } },
              agent_ip:      { terms: { field: 'agent.ip',                size: 1 } },
              top_decoder:   { terms: { field: 'decoder.name',            size: 5 } },
              top_groups:    { terms: { field: 'rule.groups',             size: 10 } },
              integration:   { terms: { field: 'data.integration',        size: 3 } },
              program_name:  { terms: { field: 'predecoder.program_name', size: 3 } },
              severity_dist: { terms: { field: 'rule.level',              size: 15 } },
              last_seen:     { max:   { field: '@timestamp' } },
              first_seen_7d: { min:   { field: '@timestamp' } },
              count_7d:      { value_count: { field: 'agent.id' } },
              last_24h: {
                filter: { range: { '@timestamp': { gte: 'now-24h' } } },
                aggs: { count: { value_count: { field: 'agent.id' } } },
              },
            },
          },
        },
      }, IDX, 200, 0, maxRetries),
      // Cloud group sources: single 7d query with 24h filter sub-agg
      osSearch({
        size: 0,
        query: { range: { '@timestamp': { gte: 'now-7d' } } },
        aggs: {
          by_cloud_group: {
            terms: { field: 'rule.groups', size: 100 },
            aggs: {
              last_seen:     { max:   { field: '@timestamp' } },
              count_7d:      { value_count: { field: '@timestamp' } },
              severity_dist: { terms: { field: 'rule.level', size: 15 } },
              last_24h: {
                filter: { range: { '@timestamp': { gte: 'now-24h' } } },
                aggs: { count: { value_count: { field: '@timestamp' } } },
              },
            },
          },
        },
      }, IDX, 200, 0, maxRetries),
    ]);

    // Remap to match the shape the rest of the function expects
    const r24h    = { aggregations: { by_source:      { buckets: (rAgents.aggregations?.by_source?.buckets || []).map(b => ({ ...b, doc_count: b.last_24h?.count?.value || 0 })) } } };
    const r7d     = { aggregations: { by_source:      { buckets: rAgents.aggregations?.by_source?.buckets || [] } } };
    const rCloud24h = { aggregations: { by_cloud_group: { buckets: (rCloud.aggregations?.by_cloud_group?.buckets || []).map(b => ({ ...b, doc_count: b.last_24h?.count?.value || 0 })) } } };
    const rCloud7d  = { aggregations: { by_cloud_group: { buckets: rCloud.aggregations?.by_cloud_group?.buckets || [] } } };

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

    // ── Onboarding history: upsert every source, notify truly new ones ──
    try {
      const unnotifiedBefore = await db.getUnnotifiedLogSources();
      const knownIds = new Set(unnotifiedBefore.map(r => r.source_id));

      const toNotify = [];
      for (const src of sources) {
        const row = await db.upsertLogSourceHistory(src);
        // is_insert=true means this source_id has never been seen before
        if (row.is_insert) toNotify.push(row);
      }

      if (toNotify.length) {
        await db.markLogSourcesNotified(toNotify.map(r => r.id));
        for (const row of toNotify) {
          await db.createNotification(
            'log_source_onboarded',
            `New log source onboarded: ${row.source_name}`,
            `Vendor: ${row.vendor || 'unknown'} | Type: ${row.type || 'unknown'} | Protocol: ${row.protocol || 'unknown'} | First seen: ${new Date().toISOString()}`,
            'info', null,
            { source_id: row.source_id, source_name: row.source_name, vendor: row.vendor, type: row.type }
          );
          io.emit('log_source:new', {
            source_id:   row.source_id,
            source_name: row.source_name,
            vendor:      row.vendor,
            type:        row.type,
            protocol:    row.protocol,
            first_seen:  row.first_seen,
          });
        }
        console.log(`[log-sources] ${toNotify.length} new source(s) onboarded and notified`);
      }

      // Also notify any previously unseen sources that escaped the first pass
      const stillUnnotified = unnotifiedBefore.filter(r => !knownIds.has(r.source_id));
      if (stillUnnotified.length) {
        await db.markLogSourcesNotified(stillUnnotified.map(r => r.id));
      }
    } catch (histErr) {
      console.error('[log-sources] history upsert error:', histErr.message);
    }

    _logSourcesCache = result;
    _logSourcesCacheTime = Date.now();
    return result;
}

app.get('/api/log-sources', authMW, async (req, res) => {
  try {
    if (_logSourcesCache && Date.now() - _logSourcesCacheTime < 300000) return res.json(_logSourcesCache);
    // maxRetries=2: fail fast (~6s) so UI sees pending quickly; frontend auto-retries on pending:true
    res.json(await _fetchLogSources(2));
  } catch (e) {
    console.error('[log-sources]', e.message);
    if (_logSourcesCache) return res.json({ ..._logSourcesCache, stale: true });
    // No cache yet (startup) — return empty but valid so UI shows 0 sources, not an error
    res.json({ sources: [], summary: { total_sources: 0, total_eps: 0, anomaly_count: 0, unknown_sources: 0, total_events_24h: 0 }, insights: [], pending: true });
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

app.get('/api/log-sources/history', authMW, async (req, res) => {
  try {
    const page      = Math.max(parseInt(req.query.page) || 1, 1);
    const page_size = Math.min(parseInt(req.query.page_size) || 50, 200);
    const { rows, total } = await db.getLogSourceHistory({ page, page_size });
    res.json({ items: rows, total, page, page_size, has_more: page * page_size < total });
  } catch (e) {
    console.error('[log-sources/history]', e.message);
    res.status(502).json({ error: e.message });
  }
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

// ── INVESTIGATION COMMENTS ──
app.get('/api/investigations/:id/comments', authMW, async (req, res) => {
  try {
    const comments = await db.getInvComments(parseInt(req.params.id));
    res.json({ comments });
  } catch (e) {
    console.error('[inv/comments/get]', e.message);
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/investigations/:id/comments', authMW, async (req, res) => {
  try {
    const { body } = req.body;
    if (!body?.trim()) return res.status(400).json({ error: 'body required' });
    const comment = await db.saveInvComment(parseInt(req.params.id), req.user.username, body.trim());
    res.json({ ok: true, comment });
  } catch (e) {
    console.error('[inv/comments/post]', e.message);
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

app.get('/api/fp-stats', authMW, async (req, res) => {
  try {
    const rows = await db.getRuleFpRates();
    const enriched = rows.map(r => {
      const fp_count       = parseInt(r.fp_count)       || 0;
      const total_labelled = parseInt(r.total_labelled) || 0;
      const posteriorFp    = ((3 + fp_count) / (10 + total_labelled)) * 100;
      const w_hist         = Math.min(total_labelled / 30, 1) * 0.7;
      return {
        rule_id:         r.rule_id,
        fp_count,
        tp_count:        parseInt(r.tp_count) || 0,
        total_labelled,
        fp_rate_raw:     parseFloat(r.fp_rate_raw) || 0,
        fp_rate_adjusted: Math.round(posteriorFp * 10) / 10,
        hist_weight_pct: Math.round(w_hist * 100),
      };
    });
    res.json({
      items:          enriched,
      cache_age_min:  _ruleFpCacheTime ? Math.round((Date.now() - _ruleFpCacheTime) / 60000) : null,
      total_rules:    enriched.length,
    });
  } catch(e) {
    console.error('[fp-stats]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── Draft Detection Rules ─────────────────────────────────────────────────
app.get('/api/draft-rules', authMW, async (req, res) => {
  try {
    const page      = Math.max(parseInt(req.query.page) || 1, 1);
    const page_size = Math.min(parseInt(req.query.page_size) || 20, 100);
    const status    = req.query.status || null;
    const [{ rows, total }, stats] = await Promise.all([
      db.listDraftRules({ status, page, page_size }),
      db.getDraftRuleStats(),
    ]);
    res.json({ rules: rows, stats, total, page, page_size, has_more: page * page_size < total });
  } catch(e) { res.status(502).json({ error: e.message }); }
});

app.patch('/api/draft-rules/:id/status', authMW, requireRole('l2'), async (req, res) => {
  try {
    const { status } = req.body;
    if (!['pending_review','approved','dismissed'].includes(status)) {
      return res.status(400).json({ error: 'invalid status' });
    }
    const r = await db.updateDraftRuleStatus(parseInt(req.params.id), status);
    if (!r) return res.status(404).json({ error: 'not found' });
    res.json({ rule: r });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/draft-rules/:id', authMW, requireRole('l2'), async (req, res) => {
  try {
    await db.deleteDraftRule(parseInt(req.params.id));
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Manual trigger: regenerate draft rule for a specific investigation
app.post('/api/draft-rules/generate/:inv_id', authMW, requireRole('l2'), async (req, res) => {
  try {
    const inv = await db.getInvestigationById(parseInt(req.params.inv_id));
    if (!inv) return res.status(404).json({ error: 'investigation not found' });
    if (!OPENAI_API_KEY && !MISTRAL_API_KEY) return res.status(503).json({ error: 'no AI key configured' });
    generateDraftRule(inv).catch(() => {});
    res.json({ ok: true, message: 'rule generation triggered asynchronously' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Alert Suppressions ────────────────────────────────────────────────────
app.get('/api/suppressions', authMW, async (req, res) => {
  try {
    const [rows, stats] = await Promise.all([db.listSuppressions(), db.getSuppressionStats()]);
    res.json({ suppressions: rows, stats, total: rows.length });
  } catch(e) { res.status(502).json({ error: e.message }); }
});

app.post('/api/suppressions', authMW, requireRole('l2'), async (req, res) => {
  try {
    const s = await db.createSuppression({ ...req.body, created_by: req.user.username });
    refreshSuppressionCache().catch(() => {});
    res.json({ suppression: s });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/suppressions/:id', authMW, requireRole('l2'), async (req, res) => {
  try {
    const s = await db.updateSuppression(parseInt(req.params.id), req.body);
    if (!s) return res.status(404).json({ error: 'not found' });
    refreshSuppressionCache().catch(() => {});
    res.json({ suppression: s });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/suppressions/:id', authMW, requireRole('l2'), async (req, res) => {
  try {
    await db.deleteSuppression(parseInt(req.params.id));
    refreshSuppressionCache().catch(() => {});
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════
// ARTIFACTS & IOC INTELLIGENCE
// ══════════════════════════════════════════════════════════════════

// ── IOC Extraction (regex engine) ────────────────────────────────
const IOC_PATTERNS = {
  ip:       /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  domain:   /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|br|fr|it|nl|es|se|no|fi|jp|au|ca|in|pk|mx|za|sg|hk|my|id|ph|vn|th|ae|sa|tr|pl|cz|ro|hu|bg|ua|gr|pt|dk|nz|nz|info|biz|online|xyz|club|site|web|tech|app|dev|cloud|ai|mobi|name|pro)\b/gi,
  url:      /https?:\/\/[^\s"'<>\])\}]+/g,
  email:    /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
  md5:      /\b[a-fA-F0-9]{32}\b/g,
  sha1:     /\b[a-fA-F0-9]{40}\b/g,
  sha256:   /\b[a-fA-F0-9]{64}\b/g,
  cve:      /\bCVE-\d{4}-\d{4,7}\b/gi,
  registry: /\bHKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s"']{3,}\b/gi,
};

const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|::1|fe80|localhost)/i;

function extractIOCsFromText(text) {
  if (!text || typeof text !== 'string') return [];
  const seen = new Set();
  const results = [];
  for (const [type, re] of Object.entries(IOC_PATTERNS)) {
    re.lastIndex = 0;
    const matches = text.match(re) || [];
    for (const m of matches) {
      const key = `${type}:${m.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      // Skip private IPs
      if (type === 'ip' && PRIVATE_IP_RE.test(m)) continue;
      // Skip domains that look like file extensions
      if (type === 'domain' && m.split('.').length < 2) continue;
      results.push({ indicator: m, ioc_type: type });
    }
  }
  return results;
}

// ── Whitelist in-memory cache ─────────────────────────────────────
let _wlCache = [], _wlCacheTime = 0;

async function refreshWlCache() {
  try {
    const r = await db.pool.query(
      `SELECT indicator, ioc_type FROM ioc_whitelist
       WHERE enabled=TRUE AND (expires_at IS NULL OR expires_at > NOW())`
    );
    _wlCache = r.rows;
    _wlCacheTime = Date.now();
  } catch(e) { console.error('[whitelist-cache]', e.message); }
}

async function isWhitelisted(indicator) {
  if (Date.now() - _wlCacheTime > 300_000) await refreshWlCache();
  const lo = (indicator || '').toLowerCase();
  return _wlCache.some(e => e.indicator.toLowerCase() === lo);
}

// ── Enrichment engine ─────────────────────────────────────────────
const VT_BASE     = 'https://www.virustotal.com/api/v3';
const ABIP_BASE   = 'https://api.abuseipdb.com/api/v2';
const SHODAN_BASE = 'https://api.shodan.io';
const GN_BASE     = 'https://api.greynoise.io/v3/community';
const US_BASE     = 'https://urlscan.io/api/v1';

async function callVT(path) {
  const k = process.env.VIRUSTOTAL_API_KEY;
  if (!k) return null;
  try {
    const r = await fetch(`${VT_BASE}${path}`, { headers: { 'x-apikey': k }, signal: AbortSignal.timeout(12000) });
    if (!r.ok) return null;
    return r.json();
  } catch { return null; }
}

// OpenCTI GraphQL enrichment — returns score, description, active indicators, threat actors/malware
async function callOpenCTI(indicator) {
  const url = process.env.OPENCTI_URL;
  const key = process.env.OPENCTI_API_KEY;
  if (!url || !key) return null;
  const query = `{
    stixCyberObservables(filters: {mode: and, filters: [{key: "value", values: ["${indicator.replace(/"/g, '\\"')}"]}], filterGroups: []}) {
      edges { node {
        id entity_type observable_value
        x_opencti_score x_opencti_description
        created_at updated_at
        indicators { edges { node { name pattern valid_from valid_until confidence } } }
        stixCoreRelationships { edges { node {
          relationship_type
          to {
            ... on ThreatActor { name }
            ... on Malware { name description }
            ... on AttackPattern { name x_mitre_id }
            ... on Campaign { name description }
          }
        } } }
      } }
    }
  }`;
  try {
    const r = await fetch(`${url}/graphql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${key}` },
      body: JSON.stringify({ query }),
      signal: AbortSignal.timeout(12000)
    });
    if (!r.ok) return null;
    const json = await r.json();
    const node = json?.data?.stixCyberObservables?.edges?.[0]?.node;
    if (!node) return null;
    const indicators = node.indicators?.edges?.map(e => e.node) || [];
    const relations  = node.stixCoreRelationships?.edges?.map(e => e.node).filter(n => n.to && Object.keys(n.to).length) || [];
    const now = Date.now();
    const activeIndicators = indicators.filter(i => i.valid_until && new Date(i.valid_until).getTime() > now);
    return {
      score: node.x_opencti_score || 0,
      description: node.x_opencti_description || '',
      entity_type: node.entity_type,
      created_at: node.created_at,
      updated_at: node.updated_at,
      indicators: activeIndicators.length,
      threat_actors: relations.filter(r => r.to?.name && !r.to?.x_mitre_id && !r.to?.description?.includes('malware')).map(r => r.to.name),
      malware: relations.filter(r => r.to?.description !== undefined).map(r => r.to.name).filter(Boolean),
      attack_patterns: relations.filter(r => r.to?.x_mitre_id).map(r => ({ name: r.to.name, mitre_id: r.to.x_mitre_id })),
      campaigns: relations.filter(r => r.relationship_type === 'attributed-to' || r.relationship_type === 'part-of').map(r => r.to.name).filter(Boolean),
      is_active_indicator: activeIndicators.length > 0
    };
  } catch { return null; }
}

async function enrichIOC(ioc) {
  const { id, indicator, ioc_type } = ioc;
  const results = {};

  if (ioc_type === 'ip') {
    // VirusTotal
    const vt = await callVT(`/ip_addresses/${encodeURIComponent(indicator)}`);
    if (vt?.data?.attributes) {
      const a = vt.data.attributes;
      results.virustotal = { malicious: a.last_analysis_stats?.malicious || 0, total: Object.values(a.last_analysis_stats || {}).reduce((s,v)=>s+v,0), reputation: a.reputation, country: a.country, asn: a.asn, as_owner: a.as_owner, network: a.network };
      await db.saveIOCEnrichment(id, 'virustotal', results.virustotal, 'success');
    }
    // AbuseIPDB
    const abKey = process.env.ABUSEIPDB_API_KEY;
    if (abKey) {
      try {
        const r = await fetch(`${ABIP_BASE}/check?ipAddress=${encodeURIComponent(indicator)}&maxAgeInDays=90`, { headers: { Key: abKey, Accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
        if (r.ok) { const d = await r.json(); results.abuseipdb = d.data; await db.saveIOCEnrichment(id, 'abuseipdb', d.data, 'success'); }
      } catch { await db.saveIOCEnrichment(id, 'abuseipdb', null, 'error', 'timeout'); }
    }
    // Shodan
    const shKey = process.env.SHODAN_API_KEY;
    if (shKey) {
      try {
        const r = await fetch(`${SHODAN_BASE}/shodan/host/${encodeURIComponent(indicator)}?key=${shKey}`, { signal: AbortSignal.timeout(10000) });
        if (r.ok) { const d = await r.json(); results.shodan = { ports: d.ports, hostnames: d.hostnames, country: d.country_name, org: d.org, vulns: Object.keys(d.vulns||{}) }; await db.saveIOCEnrichment(id, 'shodan', results.shodan, 'success'); }
      } catch { await db.saveIOCEnrichment(id, 'shodan', null, 'error', 'timeout'); }
    }
    // GreyNoise (commercial — only runs when API key is set)
    const gnKey = process.env.GREYNOISE_API_KEY;
    if (gnKey) {
      try {
        const r = await fetch(`${GN_BASE}/${encodeURIComponent(indicator)}`, { headers: { key: gnKey }, signal: AbortSignal.timeout(10000) });
        if (r.ok) { const d = await r.json(); results.greynoise = { noise: d.noise, riot: d.riot, classification: d.classification, name: d.name, message: d.message }; await db.saveIOCEnrichment(id, 'greynoise', results.greynoise, 'success'); }
      } catch { await db.saveIOCEnrichment(id, 'greynoise', null, 'error', 'timeout'); }
    }
    // OpenCTI
    const octi = await callOpenCTI(indicator);
    if (octi) { results.opencti = octi; await db.saveIOCEnrichment(id, 'opencti', octi, 'success'); }
  } else if (ioc_type === 'domain') {
    const vt = await callVT(`/domains/${encodeURIComponent(indicator)}`);
    if (vt?.data?.attributes) {
      const a = vt.data.attributes;
      results.virustotal = { malicious: a.last_analysis_stats?.malicious || 0, total: Object.values(a.last_analysis_stats || {}).reduce((s,v)=>s+v,0), reputation: a.reputation, categories: a.categories, creation_date: a.creation_date, registrar: a.registrar };
      await db.saveIOCEnrichment(id, 'virustotal', results.virustotal, 'success');
    }
    // URLScan
    const usKey = process.env.URLSCAN_API_KEY;
    if (usKey) {
      try {
        const r = await fetch(`${US_BASE}/search/?q=domain:${encodeURIComponent(indicator)}&size=1`, { headers: { 'API-Key': usKey }, signal: AbortSignal.timeout(12000) });
        if (r.ok) { const d = await r.json(); if (d.results?.[0]) { results.urlscan = { task: d.results[0].task, stats: d.results[0].stats, verdict: d.results[0].verdicts }; await db.saveIOCEnrichment(id, 'urlscan', results.urlscan, 'success'); } }
      } catch { await db.saveIOCEnrichment(id, 'urlscan', null, 'error', 'timeout'); }
    }
    // OpenCTI
    const octi = await callOpenCTI(indicator);
    if (octi) { results.opencti = octi; await db.saveIOCEnrichment(id, 'opencti', octi, 'success'); }
  } else if (ioc_type === 'url') {
    const usKey = process.env.URLSCAN_API_KEY;
    if (usKey) {
      try {
        const sr = await fetch(`${US_BASE}/search/?q=${encodeURIComponent(indicator)}&size=1`, { headers: { 'API-Key': usKey }, signal: AbortSignal.timeout(12000) });
        if (sr.ok) { const d = await sr.json(); if (d.results?.[0]) { results.urlscan = d.results[0].verdicts; await db.saveIOCEnrichment(id, 'urlscan', results.urlscan, 'success'); } }
      } catch { await db.saveIOCEnrichment(id, 'urlscan', null, 'error', 'timeout'); }
    }
    // OpenCTI (query the URL's domain component as fallback)
    const octi = await callOpenCTI(indicator);
    if (octi) { results.opencti = octi; await db.saveIOCEnrichment(id, 'opencti', octi, 'success'); }
  } else if (['md5','sha1','sha256'].includes(ioc_type)) {
    const vt = await callVT(`/files/${encodeURIComponent(indicator)}`);
    if (vt?.data?.attributes) {
      const a = vt.data.attributes;
      results.virustotal = { malicious: a.last_analysis_stats?.malicious || 0, total: Object.values(a.last_analysis_stats || {}).reduce((s,v)=>s+v,0), meaningful_name: a.meaningful_name, type_description: a.type_description, size: a.size, tags: a.tags, popular_threat_name: a.popular_threat_classification?.suggested_threat_label };
      await db.saveIOCEnrichment(id, 'virustotal', results.virustotal, 'success');
    }
    // OpenCTI hash lookup
    const octi = await callOpenCTI(indicator);
    if (octi) { results.opencti = octi; await db.saveIOCEnrichment(id, 'opencti', octi, 'success'); }
  } else if (ioc_type === 'cve') {
    // OpenCTI CVE lookup
    const octi = await callOpenCTI(indicator);
    if (octi) { results.opencti = octi; await db.saveIOCEnrichment(id, 'opencti', octi, 'success'); }
  }

  // OTX cross-reference (all types via existing feed)
  try {
    const otx = await db.pool.query(
      `SELECT pulse_name, indicator_type, tags, malware_families, threat_score
       FROM otx_ioc_feed WHERE indicator=$1 LIMIT 5`, [indicator]
    );
    if (otx.rows.length) {
      results.otx = otx.rows;
      await db.saveIOCEnrichment(id, 'otx', otx.rows, 'success');
    }
  } catch { /* non-fatal */ }

  // Derive overall reputation from enrichment results
  const vtMal    = results.virustotal?.malicious || 0;
  const abConf   = results.abuseipdb?.abuseConfidenceScore || 0;
  const gnClass  = results.greynoise?.classification;
  const otxHit   = results.otx?.length > 0;
  const octiScore = results.opencti?.score || 0;
  const octiActive = results.opencti?.is_active_indicator || false;
  let reputation = 'unknown', risk = 0, confidence = 0;
  if (vtMal >= 5 || abConf >= 50 || gnClass === 'malicious' || octiScore >= 70) {
    reputation = 'malicious';
    risk = Math.min(100, Math.max(vtMal * 8, abConf, gnClass === 'malicious' ? 80 : 0, octiScore));
    confidence = 90;
  } else if (vtMal >= 1 || abConf >= 10 || otxHit || gnClass === 'unknown' || octiScore >= 40 || octiActive) {
    reputation = 'suspicious';
    risk = Math.max(vtMal * 5, abConf * 0.5, otxHit ? 40 : 0, octiScore * 0.6);
    confidence = 70;
  } else if (gnClass === 'benign' && vtMal === 0 && abConf === 0 && octiScore < 20) {
    reputation = 'trusted'; risk = 5; confidence = 80;
  }
  await db.updateIOC(id, { reputation, risk_score: Math.round(risk), confidence, enriched_at: new Date() });
  return { results, reputation, risk_score: Math.round(risk) };
}

// ── Alert → IOC auto-ingestion job ────────────────────────────────
let _iocIngestRunning = false;
let _iocIngestLastRun = null;
let _iocIngestLastCount = 0;

async function autoIngestAlerts(windowMinutes = 15) {
  if (_iocIngestRunning) return;
  if (_osBackpressure('autoIngestAlerts')) return;
  _iocIngestRunning = true;
  let newCount = 0, updCount = 0;
  try {
    // Reload whitelist before starting
    await refreshWlCache();

    // Query OpenSearch for alerts in the window — pull key IOC fields
    const since = `now-${windowMinutes}m`;
    let r;
    try {
      r = await osSearch({
        size: 500,
        // Request parent objects so all subfields are included
        _source: ['@timestamp', 'rule', 'agent', 'data', 'syscheck', 'full_log', 'srcip', 'location'],
        query: { bool: { must: [
          { range: { '@timestamp': { gte: since } } },
          { range: { 'rule.level': { gte: 3 } } },   // skip informational
        ]}}
      });
    } catch(e) {
      console.error('[ioc-ingest] OpenSearch error:', e.message);
      return;
    }

    const hits = r.hits?.hits || [];
    const seen = new Set();  // dedup within this run

    for (const hit of hits) {
      const s = hit._source || {};
      const ruleId = s.rule?.id || 'unknown';
      const ruleLevel = s.rule?.level || 0;
      const agentName = s.agent?.name || '';
      const candidates = [];

      // ── Structured IP fields ────────────────────────────────────
      const ipFields = [
        s.data?.srcip, s.data?.dstip, s.data?.dest_ip, s.data?.src_ip,
        s.data?.win?.eventdata?.sourceIp, s.data?.win?.eventdata?.destinationIp,
      ];
      for (const ip of ipFields) {
        if (ip && typeof ip === 'string' && !PRIVATE_IP_RE.test(ip))
          candidates.push({ indicator: ip, ioc_type: 'ip' });
      }

      // ── Hash fields (syscheck) ──────────────────────────────────
      const hashes = [
        [s.syscheck?.sha256_after, 'sha256'], [s.syscheck?.sha256_before, 'sha256'],
        [s.syscheck?.sha1_after,   'sha1'],   [s.syscheck?.sha1_before,   'sha1'],
        [s.syscheck?.md5_after,    'md5'],    [s.syscheck?.md5_before,    'md5'],
      ];
      for (const [h, ht] of hashes) {
        if (h && typeof h === 'string') candidates.push({ indicator: h.toLowerCase(), ioc_type: ht });
      }

      // ── URL / domain fields ─────────────────────────────────────
      if (s.data?.url)                         candidates.push({ indicator: s.data.url, ioc_type: 'url' });
      if (s.data?.win?.eventdata?.queryName)   candidates.push({ indicator: s.data.win.eventdata.queryName, ioc_type: 'domain' });
      if (s.data?.win?.eventdata?.destinationHostname) candidates.push({ indicator: s.data.win.eventdata.destinationHostname, ioc_type: 'hostname' });

      // ── Text extraction from description + full_log ─────────────
      const textSources = [s.rule?.description, s.full_log].filter(Boolean).join(' ');
      if (textSources) {
        const extracted = extractIOCsFromText(textSources);
        for (const e of extracted) candidates.push(e);
      }

      // ── Upsert each unique candidate ────────────────────────────
      for (const { indicator, ioc_type } of candidates) {
        const ind = String(indicator).trim();
        if (!ind || ind.length < 3 || ind.length > 512) continue;
        const key = `${ioc_type}:${ind.toLowerCase()}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (await isWhitelisted(ind)) continue;

        try {
          const result = await db.upsertIOC(ind, ioc_type, {
            reputation: 'unknown', source: 'alert',
            source_ref: `rule:${ruleId}`,
            notes: `Auto-extracted from Wazuh rule ${ruleId} (level ${ruleLevel}) on agent ${agentName}`,
            created_by: 'system',
          });
          if (result?.is_insert) newCount++;
          else updCount++;
        } catch(e) { /* skip individual upsert errors */ }
      }
    }

    _iocIngestLastRun = new Date().toISOString();
    _iocIngestLastCount = newCount;
    if (newCount > 0 || updCount > 0)
      console.log(`[ioc-ingest] window=${windowMinutes}m hits=${hits.length} new=${newCount} updated=${updCount}`);

    // Create notification if significant new IOCs found
    if (newCount >= 5) {
      db.createNotification('investigation', 'IOC Auto-Ingest', `${newCount} new indicators extracted from ${hits.length} alerts`, 'low', 'system', {}).catch(()=>{});
    }
  } catch(e) {
    console.error('[ioc-ingest] job error:', e.message);
  } finally {
    _iocIngestRunning = false;
  }
  // Kick off enrichment for newly ingested IOCs immediately
  if (newCount > 0 && !_enrichRunning) {
    setTimeout(() => autoEnrichJob(Math.min(newCount, 10)), 5000);
  }
  return { new: newCount, updated: updCount };
}

// ── IOC auto-enrichment job ───────────────────────────────────────
let _enrichRunning  = false;
let _enrichLastRun  = null;
let _enrichLastCount = 0;

const _VT_TYPES = new Set(['ip', 'domain', 'md5', 'sha1', 'sha256']);

async function autoEnrichJob(batchSize = 10) {
  if (_enrichRunning) return { skipped: true };
  _enrichRunning = true;
  let enriched = 0;
  try {
    // Prioritise IPs/domains (most actionable), then URLs, CVEs, then hashes; oldest first
    const r = await db.pool.query(
      `SELECT id, indicator, ioc_type FROM ioc_store
       WHERE enriched_at IS NULL
       ORDER BY
         CASE ioc_type WHEN 'ip' THEN 1 WHEN 'domain' THEN 2 WHEN 'url' THEN 3 WHEN 'cve' THEN 4 ELSE 5 END,
         created_at ASC
       LIMIT $1`,
      [batchSize]
    );
    const iocs = r.rows;
    if (iocs.length) console.log(`[ioc-enrich] batch start — ${iocs.length} IOCs`);
    for (const ioc of iocs) {
      try {
        await enrichIOC(ioc);
        enriched++;
      } catch(e) {
        console.error(`[ioc-enrich] failed ${ioc.indicator.slice(0, 40)}:`, e.message);
      }
      // VT free tier: 4/min → 16 s gap; non-VT types: 1 s
      const delay = _VT_TYPES.has(ioc.ioc_type) ? 16000 : 1000;
      await new Promise(res => setTimeout(res, delay));
    }
  } catch(e) {
    console.error('[ioc-enrich] job error:', e.message);
  } finally {
    _enrichRunning   = false;
    _enrichLastRun   = new Date().toISOString();
    _enrichLastCount = enriched;
    if (enriched) console.log(`[ioc-enrich] done — enriched ${enriched} IOCs`);
  }
  return { enriched };
}

// ── IOC Store routes ──────────────────────────────────────────────
app.get('/api/ioc-store/stats', authMW, async (req, res) => {
  try {
    const stats = await db.getIOCStats();
    const queueR = await db.pool.query(`SELECT COUNT(*) AS cnt FROM ioc_store WHERE enriched_at IS NULL`);
    const enrichQueue = parseInt(queueR.rows[0]?.cnt || 0);
    // Enrichment source status
    const sources = [
      { name: 'VirusTotal',    key: 'VIRUSTOTAL_API_KEY',    configured: !!process.env.VIRUSTOTAL_API_KEY },
      { name: 'AbuseIPDB',     key: 'ABUSEIPDB_API_KEY',     configured: !!process.env.ABUSEIPDB_API_KEY },
      { name: 'Shodan',        key: 'SHODAN_API_KEY',         configured: !!process.env.SHODAN_API_KEY },
      { name: 'OTX AlienVault',  key: 'OTX_API_KEY',            configured: !!process.env.OTX_API_KEY },
      { name: 'OpenCTI',         key: 'OPENCTI_URL',            configured: !!(process.env.OPENCTI_URL && process.env.OPENCTI_API_KEY), note: 'Active — threat actors, malware, MITRE ATT&CK' },
      { name: 'URLScan.io',      key: 'URLSCAN_API_KEY',        configured: !!process.env.URLSCAN_API_KEY },
      { name: 'GreyNoise',       key: 'GREYNOISE_API_KEY',      configured: !!process.env.GREYNOISE_API_KEY, note: 'Commercial — key required' },
      { name: 'Hybrid Analysis', key: 'HYBRID_ANALYSIS_API_KEY',configured: !!process.env.HYBRID_ANALYSIS_API_KEY },
      { name: 'MISP',            key: 'MISP_URL',               configured: !!(process.env.MISP_URL && process.env.MISP_API_KEY) },
      { name: 'CrowdSec',        key: 'CROWDSEC_API_KEY',       configured: !!process.env.CROWDSEC_API_KEY, note: 'Commercial — key required' },
    ];
    res.json({
      ...stats,
      enrichment_sources: sources,
      ingest:  { last_run: _iocIngestLastRun, running: _iocIngestRunning, last_new: _iocIngestLastCount },
      enrich:  { last_run: _enrichLastRun,    running: _enrichRunning,    last_count: _enrichLastCount, queue: enrichQueue },
    });
  } catch(e) { console.error('[ioc-store/stats]', e.message); res.status(502).json({ error: e.message }); }
});

// Manual trigger — runs the ingest job now (returns immediately if already running)
app.post('/api/ioc-store/ingest-alerts', authMW, requireRole('l2'), async (req, res) => {
  if (_iocIngestRunning) return res.json({ status: 'already_running' });
  const window = Math.min(parseInt(req.body?.window_minutes) || 60, 1440); // cap at 24h
  autoIngestAlerts(window).catch(() => {});
  res.json({ status: 'started', window_minutes: window });
});

// Manual trigger — enrich unenriched IOCs (rate-limited background job)
app.post('/api/ioc-store/enrich-all', authMW, requireRole('l2'), async (req, res) => {
  if (_enrichRunning) return res.json({ status: 'already_running' });
  const batchSize = Math.min(parseInt(req.body?.batch_size) || 10, 50);
  autoEnrichJob(batchSize).catch(() => {});
  res.json({ status: 'started', batch_size: batchSize });
});

app.get('/api/ioc-store', authMW, async (req, res) => {
  try {
    const { page, page_size, ioc_type, reputation, q, sort_by, sort_dir } = req.query;
    const { rows, total } = await db.listIOCs({ page, page_size, ioc_type, reputation, q, sort_by, sort_dir });
    res.json({ items: rows, total, page: parseInt(page)||1, page_size: parseInt(page_size)||50, has_more: (parseInt(page)||1)*(parseInt(page_size)||50) < total });
  } catch(e) { console.error('[ioc-store]', e.message); res.status(502).json({ error: e.message }); }
});

app.post('/api/ioc-store', authMW, async (req, res) => {
  try {
    const { indicator, ioc_type, reputation, confidence, risk_score, source, notes, tags, mitre_techniques, threat_actors, malware_families } = req.body;
    if (!indicator?.trim() || !ioc_type) return res.status(400).json({ error: 'indicator and ioc_type required' });
    if (await isWhitelisted(indicator.trim())) return res.status(409).json({ error: 'Indicator is whitelisted — remove from whitelist before adding' });
    const row = await db.upsertIOC(indicator.trim(), ioc_type, { reputation, confidence, risk_score, source: source || 'manual', notes, tags, mitre_techniques, threat_actors, malware_families, created_by: req.user.username });
    res.json(row);
  } catch(e) { console.error('[ioc-store POST]', e.message); res.status(500).json({ error: e.message }); }
});

app.get('/api/ioc-store/export', authMW, async (req, res) => {
  try {
    const fmt = req.query.format || 'json';
    const r = await db.pool.query(`SELECT * FROM ioc_store ORDER BY last_seen DESC LIMIT 10000`);
    if (fmt === 'csv') {
      const cols = ['id','indicator','ioc_type','reputation','confidence','risk_score','source','first_seen','last_seen'];
      const csv = [cols.join(','), ...r.rows.map(row => cols.map(c => `"${(row[c]??'').toString().replace(/"/g,'""')}"`).join(','))].join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="iocs.csv"');
      return res.send(csv);
    }
    res.setHeader('Content-Disposition', 'attachment; filename="iocs.json"');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ioc-store/extract', authMW, async (req, res) => {
  try {
    const { text, auto_save = false } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'text required' });
    const extracted = extractIOCsFromText(text);
    let saved = 0;
    if (auto_save) {
      for (const ioc of extracted) {
        if (!(await isWhitelisted(ioc.indicator))) {
          await db.upsertIOC(ioc.indicator, ioc.ioc_type, { source: 'extraction', created_by: req.user.username });
          saved++;
        }
      }
    }
    res.json({ extracted, count: extracted.length, saved });
  } catch(e) { console.error('[ioc-store/extract]', e.message); res.status(500).json({ error: e.message }); }
});

app.post('/api/ioc-store/import', authMW, requireRole('l2'), async (req, res) => {
  try {
    const { items } = req.body;
    if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'items array required' });
    let imported = 0, skipped = 0;
    for (const item of items) {
      if (!item.indicator || !item.ioc_type) { skipped++; continue; }
      if (await isWhitelisted(item.indicator)) { skipped++; continue; }
      try { await db.upsertIOC(item.indicator.trim(), item.ioc_type, { ...item, source: item.source || 'import', created_by: req.user.username }); imported++; }
      catch { skipped++; }
    }
    res.json({ imported, skipped });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ioc-store/:id', authMW, async (req, res) => {
  try {
    const ioc = await db.getIOC(parseInt(req.params.id));
    if (!ioc) return res.status(404).json({ error: 'not found' });
    const [enrichments, relations] = await Promise.all([db.getIOCEnrichments(ioc.id), db.getIOCRelations(ioc.id)]);
    res.json({ ...ioc, enrichments, relations });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/ioc-store/:id', authMW, async (req, res) => {
  try {
    const updated = await db.updateIOC(parseInt(req.params.id), req.body);
    if (!updated) return res.status(404).json({ error: 'not found' });
    res.json(updated);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/ioc-store/:id', authMW, requireRole('l2'), async (req, res) => {
  try {
    await db.deleteIOC(parseInt(req.params.id));
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ioc-store/:id/enrich', authMW, async (req, res) => {
  try {
    const ioc = await db.getIOC(parseInt(req.params.id));
    if (!ioc) return res.status(404).json({ error: 'not found' });
    if (await isWhitelisted(ioc.indicator)) return res.status(409).json({ error: 'Indicator is whitelisted — enrichment skipped' });
    const result = await enrichIOC(ioc);
    res.json({ ok: true, ...result });
  } catch(e) { console.error('[ioc-store/enrich]', e.message); res.status(500).json({ error: e.message }); }
});

app.get('/api/ioc-store/:id/enrichments', authMW, async (req, res) => {
  try {
    const enr = await db.getIOCEnrichments(parseInt(req.params.id));
    res.json(enr);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ioc-store/:id/relations', authMW, async (req, res) => {
  try {
    const rels = await db.getIOCRelations(parseInt(req.params.id));
    res.json(rels);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ioc-store/:id/relations', authMW, async (req, res) => {
  try {
    const { entity_type, entity_id, entity_label, rel_type } = req.body;
    if (!entity_type || !entity_id) return res.status(400).json({ error: 'entity_type and entity_id required' });
    const rel = await db.addIOCRelation(parseInt(req.params.id), entity_type, entity_id, entity_label, rel_type);
    res.json(rel);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Whitelist routes ──────────────────────────────────────────────
app.get('/api/ioc-whitelist/export', authMW, requireRole('l2'), async (req, res) => {
  try {
    const r = await db.pool.query(`SELECT indicator,ioc_type,category,reason,added_by,expires_at,enabled FROM ioc_whitelist ORDER BY created_at DESC`);
    const fmt = req.query.format || 'json';
    if (fmt === 'csv') {
      const cols = ['indicator','ioc_type','category','reason','added_by','expires_at','enabled'];
      const csv = [cols.join(','), ...r.rows.map(row => cols.map(c => `"${(row[c]??'').toString().replace(/"/g,'""')}"`).join(','))].join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="whitelist.csv"');
      return res.send(csv);
    }
    res.setHeader('Content-Disposition', 'attachment; filename="whitelist.json"');
    res.json(r.rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ioc-whitelist/check', authMW, async (req, res) => {
  try {
    const { indicator, ioc_type } = req.body;
    if (!indicator) return res.status(400).json({ error: 'indicator required' });
    const entry = await db.checkWhitelisted(indicator, ioc_type || 'any');
    res.json({ whitelisted: !!entry, entry: entry || null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/ioc-whitelist/import', authMW, requireRole('l2'), async (req, res) => {
  try {
    const { items } = req.body;
    if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'items array required' });
    const result = await db.bulkImportWhitelist(items, req.user.username);
    _wlCacheTime = 0; // invalidate cache
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ioc-whitelist', authMW, async (req, res) => {
  try {
    const { page, page_size, ioc_type, category, q, show_expired } = req.query;
    const { rows, total } = await db.listWhitelist({ page, page_size, ioc_type, category, q, show_expired: show_expired === 'true' });
    res.json({ items: rows, total, page: parseInt(page)||1, page_size: parseInt(page_size)||50, has_more: (parseInt(page)||1)*(parseInt(page_size)||50) < total });
  } catch(e) { res.status(502).json({ error: e.message }); }
});

app.post('/api/ioc-whitelist', authMW, requireRole('l2'), async (req, res) => {
  try {
    const { indicator, ioc_type, category, reason, expires_at, approved_by } = req.body;
    if (!indicator?.trim() || !ioc_type || !category) return res.status(400).json({ error: 'indicator, ioc_type, category required' });
    // Risk warning: check if IOC is known malicious
    const existing = await db.pool.query(`SELECT reputation, risk_score FROM ioc_store WHERE indicator=$1 AND ioc_type=$2`, [indicator.trim(), ioc_type]);
    let risk_warning = null;
    if (existing.rows[0]?.reputation === 'malicious') risk_warning = `Warning: This indicator has been classified as MALICIOUS (risk: ${existing.rows[0].risk_score}/100)`;
    else if (existing.rows[0]?.reputation === 'suspicious') risk_warning = `Warning: This indicator was previously flagged as SUSPICIOUS (risk: ${existing.rows[0].risk_score}/100)`;
    const entry = await db.createWhitelistEntry({ indicator: indicator.trim(), ioc_type, category, reason, expires_at: expires_at || null, approved_by, risk_warning }, req.user.username);
    _wlCacheTime = 0;
    res.json(entry);
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Indicator already whitelisted' });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/ioc-whitelist/:id', authMW, async (req, res) => {
  try {
    const e = await db.getWhitelistEntry(parseInt(req.params.id));
    if (!e) return res.status(404).json({ error: 'not found' });
    const audit = await db.getWhitelistAudit(e.id);
    res.json({ ...e, audit });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/ioc-whitelist/:id', authMW, requireRole('l2'), async (req, res) => {
  try {
    const updated = await db.updateWhitelistEntry(parseInt(req.params.id), req.body, req.user.username);
    if (!updated) return res.status(404).json({ error: 'not found' });
    _wlCacheTime = 0;
    res.json(updated);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/ioc-whitelist/:id', authMW, requireRole('admin'), async (req, res) => {
  try {
    const ok = await db.deleteWhitelistEntry(parseInt(req.params.id), req.user.username);
    if (!ok) return res.status(404).json({ error: 'not found' });
    _wlCacheTime = 0;
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ioc-whitelist/:id/audit', authMW, async (req, res) => {
  try {
    const audit = await db.getWhitelistAudit(parseInt(req.params.id));
    res.json(audit);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── PAGE HELP CHAT ───────────────────────────────────────────────
const PAGE_CONTEXTS = {
  dashboard: {
    title: 'Dashboard',
    desc: 'Real-time security operations overview showing the health of your entire SOC environment at a glance.',
    sections: [
      { name: 'KPI Cards (top row)', desc: 'Six metric tiles: Total Alerts (last 24h), Active Agents, Offline Agents, Open Cases, Threat Hunt runs, and a MITRE Coverage score. Each card is clickable and navigates to the relevant module.' },
      { name: 'Alert Severity Chart', desc: 'Bar chart showing alert volume broken down by severity (critical/high/medium/low) over the selected time range. Helps spot spikes and trends.' },
      { name: 'Top Rules / Top Agents', desc: 'Side-by-side tables showing which detection rules fired most and which agents generated most alerts in the last 24 hours.' },
      { name: 'MITRE ATT&CK Widget', desc: 'Mini heatmap showing your current ATT&CK technique coverage. High coverage = green, no coverage = dark. Click "View Full Matrix" to go to the full ATT&CK Coverage page.' },
      { name: 'Recent Critical Alerts', desc: 'Live table of the last 10 critical-severity alerts. Click any row to jump to the Alerts page filtered on that event.' },
      { name: 'Live Threat Map preview', desc: 'Globe widget showing real-time attack origin arcs. Hover arcs to see source country and targeted service.' },
    ]
  },
  agents: {
    title: 'Agents',
    desc: 'Wazuh endpoint agent inventory — every host reporting to your SIEM.',
    sections: [
      { name: 'Status Summary (header cards)', desc: 'Four KPI tiles: Total, Active, Disconnected, Never Connected. Gives instant fleet health view.' },
      { name: 'Agent Table', desc: 'Full agent list with columns: Name, ID, IP, OS, Version, Groups, Last Keep-Alive, Status badge. Active = green, Disconnected = red, Never Connected = grey.' },
      { name: 'Search & Filter bar', desc: 'Filter agents by status (active / disconnected / never_connected) using the dropdown, or free-text search by name or IP.' },
      { name: 'Agent detail modal', desc: 'Click any agent row to open a side panel showing full OS info, installed agent groups, last event time, and a button to jump to that agent\'s alerts.' },
      { name: 'Agent-down alerts', desc: 'Agents that go offline trigger automatic notifications. The Disconnected count in the header turns orange when any agents are down.' },
    ]
  },
  alerts: {
    title: 'Alerts',
    desc: 'Live feed of all SIEM alerts ingested from Wazuh via OpenSearch. This is your primary triage queue.',
    sections: [
      { name: 'Filter bar', desc: 'Filter by: Severity (critical/high/medium/low), Time Range (1h to 90d), Agent name, Source IP, and free-text search over rule description. Combine multiple filters.' },
      { name: 'Alert table', desc: 'Paginated list with columns: Timestamp, Severity badge, Rule description, Agent, Source IP, Rule ID, MITRE technique. Click any row to open the detail modal.' },
      { name: 'Alert detail modal', desc: 'Full alert breakdown: rule metadata, MITRE ATT&CK tags, raw log data, agent info. Contains action buttons: Investigate (sends to AI Investigation), Create Case (opens in TheHive), Enrich IOC.' },
      { name: 'Bulk Investigate', desc: 'Checkbox-select multiple alerts then click "Investigate Selected" to run AI triage on all of them at once. Results go to the Investigation history.' },
      { name: 'Pagination', desc: 'Navigate pages with Prev/Next buttons. Change page size (25/50/100/200) with the dropdown. Total alert count shown in header.' },
    ]
  },
  rules: {
    title: 'Detection Rules',
    desc: 'All Wazuh detection rules that have fired at least once in the last 7 days, aggregated from OpenSearch.',
    sections: [
      { name: 'Stats header', desc: 'Four KPI tiles: Total Active Rules, Critical Rules, High Rules, and Most Active Rule (the one with highest fire count today).' },
      { name: 'Filter & Search bar', desc: 'Filter rules by Severity level (critical/high/medium/low) or Decoder type (syslog, windows, etc.). Free-text search matches rule ID, description, or group name.' },
      { name: 'Rules table', desc: 'Columns: Rule ID, Level badge, Description, Groups (tags), MITRE technique IDs, Decoder, First Seen, Last Seen, Fires count (24h). Sortable by level or count.' },
      { name: 'Rule ID range', desc: 'Wazuh built-in rules are 1–99999. Custom rules you deploy via Create Rules are in the 200000–299999 range and are highlighted.' },
      { name: 'MITRE column', desc: 'Shows which ATT&CK technique IDs this rule maps to. Click a technique badge to jump to that technique in the ATT&CK Coverage page.' },
    ]
  },
  mitre: {
    title: 'ATT&CK Coverage',
    desc: 'MITRE ATT&CK Enterprise heatmap showing which techniques your detection rules cover, based on real alert activity.',
    sections: [
      { name: 'Coverage heatmap', desc: 'A 14-column grid (one column per tactic) × ~190 technique rows. Cell color = coverage level: Cyan/bright = High (10+ alerts), Teal = Medium (3-9), Dark teal = Low (1-2), Very dark = None (0 alerts matching this technique).' },
      { name: 'Timeframe filter', desc: 'Select 24h / 7d / 30d / 90d to see coverage over different periods. Coverage changes based on actual alert activity in that window.' },
      { name: 'Tactic columns', desc: '14 enterprise tactics in kill-chain order: Reconnaissance → Resource Development → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Command & Control → Exfiltration → Impact.' },
      { name: 'Technique drill-down', desc: 'Click any technique cell to open a detail modal showing: recent alerts that matched, agents involved, decoder, daily timeline histogram, and associated Wazuh rules.' },
      { name: 'Coverage stats bar', desc: 'Header shows total technique count by coverage level. Useful to quickly see your coverage gap percentage.' },
      { name: 'Export Navigator', desc: 'Click "Export Navigator" to download a MITRE ATT&CK Navigator 4.9 compatible JSON. Import this into navigator.attack.mitre.org to visualize coverage in the official tool.' },
    ]
  },
  'log-sources': {
    title: 'Log Sources',
    desc: 'Overview of all active log sources feeding your SIEM — agents, syslog forwarders, and cloud integrations.',
    sections: [
      { name: 'Source cards', desc: 'Each connected log source appears as a card showing: source name/IP, type (Windows Agent, Linux Agent, Syslog, Cloud API), last event timestamp, and events-per-minute rate.' },
      { name: 'Silence detection', desc: 'Sources that stop sending logs trigger a "SILENT" alert badge. The auto-analysis job checks silence every 15 minutes and creates a notification if a source goes quiet unexpectedly.' },
      { name: 'Event rate sparkline', desc: 'Mini bar chart on each card shows event volume over the last 24 hours. A flat/zero line indicates a silent source.' },
      { name: 'Source type filters', desc: 'Filter bar lets you view only Windows agents, Linux agents, Syslog sources, or Cloud integrations separately.' },
      { name: 'Auto-analysis summary', desc: 'The header shows the last auto-analysis run time and how many sources were analyzed. Analysis checks for silence, rate anomalies, and missing expected source types.' },
    ]
  },
  artifacts: {
    title: 'Artifacts & IOC',
    desc: 'Indicators of Compromise (IOCs) automatically extracted from SIEM alerts and linked to investigations. This is your evidence locker — raw indicators before enrichment.',
    sections: [
      { name: 'Stats header', desc: 'KPI tiles: Total IOCs collected, IPs, Domains, Hashes, and URLs in the database. Also shows last auto-ingest time.' },
      { name: 'IOC table', desc: 'All collected artifacts with columns: Indicator value, Type (ip/domain/hash/url), Threat Score, First Seen, Last Seen, Times Seen, linked Investigation, and Enrichment status badge.' },
      { name: 'Threat Score', desc: 'A 0–100 score calculated from enrichment results. Red (70+) = high risk, Orange (40–70) = medium, Grey = unenriched. OTX-known indicators get an automatic score boost.' },
      { name: 'Auto-ingest', desc: 'Every 15 minutes, the platform scans SIEM alerts and extracts IPs, domains, and hashes automatically. The badge in the header shows how many were ingested in the last run.' },
      { name: 'Enrichment panel', desc: 'Click any IOC row to open the enrichment panel showing results from VirusTotal, AbuseIPDB, GreyNoise, CrowdSec, and OTX. Enrichment runs automatically for new artifacts.' },
      { name: 'Filters', desc: 'Filter by Type (ip/domain/hash/url), Threat Score range, enrichment status, or free-text search. Sort by threat score or first seen date.' },
    ]
  },
  cases: {
    title: 'Cases',
    desc: 'TheHive case management integration. All security cases created from investigations or manually. Cases track the full incident lifecycle from creation to closure.',
    sections: [
      { name: 'Case table', desc: 'Lists all TheHive cases with: Case ID, Title, Severity badge, Status (Open/In Progress/Resolved/Closed), TLP classification, PAP level, Assignee, and Created date.' },
      { name: 'Timeframe filter', desc: 'Filter cases by creation date: Today, Last 7 days, Last 30 days, or All time. Severity filter (critical/high/medium/low) also available.' },
      { name: 'Case detail modal', desc: 'Click any case to open a modal showing full case description, observables (IOCs attached to the case), tasks, and audit timeline.' },
      { name: 'Create Case button', desc: 'Opens a form to manually create a new TheHive case. Can pre-fill from an alert using the "Create Case" button in the Alert detail modal.' },
      { name: 'Status badges', desc: 'Open = red, In Progress = orange, Resolved = blue, Closed = green. TLP colors follow standard classification: TLP:RED, TLP:AMBER, TLP:GREEN, TLP:WHITE.' },
    ]
  },
  'hive-alerts': {
    title: 'SP-CM Alerts',
    desc: 'TheHive alert triage queue (SP-CM = Security Platform Case Management). These are alerts pushed into TheHive waiting for analyst review before becoming full cases.',
    sections: [
      { name: 'Alert triage table', desc: 'Columns: Alert ID, Title, Severity, Source, Status (New/Updated/Ignored), TLP, Date. New alerts are highlighted. Click any to open in TheHive.' },
      { name: 'Timeframe & Severity filters', desc: 'Same filter bar as Cases page — filter by date range and severity. Counts update as you filter.' },
      { name: 'Alert detail modal', desc: 'Shows full TheHive alert details including source rule, artifacts/observables, and raw data payload. Contains a "Promote to Case" button to create a full investigation case.' },
      { name: 'Status flow', desc: 'Alerts start as New → move to Updated when an analyst adds notes → Ignored if dismissed. Only Promoted alerts become Cases.' },
    ]
  },
  hunt: {
    title: 'Threat Hunt',
    desc: 'Scheduled and ad-hoc threat hunting engine. Run AI-powered hunts against your SIEM data using hypothesis-driven queries.',
    sections: [
      { name: 'Run Hunt now', desc: 'Enter a hunt description or hypothesis (e.g., "Look for lateral movement via SMB from non-standard workstations") and click Run. The AI agent searches OpenSearch and returns findings with MITRE mapping.' },
      { name: 'Hunt Schedules table', desc: 'All recurring hunts with name, schedule (cron expression), last run time, last result summary, and enabled/disabled toggle. Click a schedule to edit or run immediately.' },
      { name: 'Create Schedule', desc: 'Form to add a recurring hunt: name, description/hypothesis, cron schedule (e.g., "0 8 * * *" = daily at 8am), and active toggle.' },
      { name: 'Hunt History', desc: 'Results from past hunt runs showing timestamp, hunt name, findings count, and AI-generated summary. Click any row to see the full hunt report.' },
      { name: 'Hunt templates', desc: 'Pre-built hunt hypotheses for common scenarios: credential stuffing, lateral movement, exfiltration, persistence mechanisms. Click a template to pre-fill the hunt form.' },
    ]
  },
  ioc: {
    title: 'IOC Enrichment',
    desc: 'Manual IOC lookup and enrichment tool. Enter any IP, domain, file hash, or URL to get a full threat intelligence profile from multiple sources.',
    sections: [
      { name: 'Enrichment form', desc: 'Input field for the indicator value + type selector (IP / Domain / Hash / URL). Click Enrich to query all configured threat intel sources simultaneously.' },
      { name: 'Enrichment results panel', desc: 'Results from each source shown in separate cards: VirusTotal (malicious votes, engine detections, categories), AbuseIPDB (confidence score, country, ISP, abuse reports), Shodan (open ports, services, OS, CVEs), OTX AlienVault (pulse count, campaigns, malware families).' },
      { name: 'Threat verdict', desc: 'A combined verdict at the top (MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN) based on weighted scores from all sources. Includes a 0–100 composite score.' },
      { name: 'OTX Feed table', desc: 'Below the enrichment form, a live table of the latest IOCs from your OTX subscription — pulled every 6 hours. Shows indicator, type, pulse name, threat actor tags. Click any to auto-fill the enrichment form.' },
      { name: 'Cache indicator', desc: 'Results are cached in Redis for 1 hour to avoid redundant API calls. A "Cached" badge appears on results served from cache. Click "Refresh" to force a new lookup.' },
    ]
  },
  correlate: {
    title: 'Correlation',
    desc: 'Alert correlation engine that groups related alerts into attack chains, with live UEBA↔SIEM correlation feed, alert deduplication, manual IOC correlation, and full correlation history.',
    sections: [
      { name: 'Live / History tabs', desc: 'Two tabs at the top: "Live" shows the real-time UEBA↔SIEM feed and alert groups; "History" shows all past saved correlations in a searchable paginated table with risk, MITRE tactics, and source filters.' },
      { name: 'Live feed filter bar', desc: 'Above the live feed: filter by minimum UEBA risk (40+/70+/90+), correlation type (UEBA Triage, Lateral Movement, Privilege Escalation, Manual), and free-text search over entity name or MITRE tactic. Filters apply instantly without re-fetching.' },
      { name: 'Live UEBA↔SIEM feed', desc: 'Real-time stream of correlations pushed via WebSocket. Each row shows: entity name, severity badge, correlation type, UEBA risk score, anomaly count, and MITRE tactic pills. Feed is capped at 100 rows; Clear button resets it.' },
      { name: 'Alert Groups table', desc: 'Below the live feed: deduplicated alert groups — same rule firing from the same source IP within a 5-minute window. Columns: Source IP, Rule ID, Agent, Severity, Count badge, First/Last Seen. Use the filter bar above to narrow by severity or search by rule/IP/agent.' },
      { name: 'Alert groups filter bar', desc: 'Severity dropdown (critical/high/medium/low) and free-text search field. Type a rule ID, IP address, or agent name; results update with 300ms debounce.' },
      { name: 'Manual IOC correlation', desc: 'Enter any indicator (IP, hash, domain, username) and click Correlate. Runs against both SIEM (OpenSearch) and SP-CM (TheHive) and returns matching hits plus an AI correlation narrative.' },
      { name: 'Correlation graph', desc: 'D3.js force-directed graph showing the indicator at center, with SIEM alert nodes (orange) and Hive case nodes (purple) as connected satellites. Drag nodes to rearrange, scroll to zoom. Click a SIEM or Hive node to expand an inline detail card below the graph showing alert/case fields.' },
      { name: 'Correlation History tab', desc: 'Paginated table of all saved correlations. Filter by free text (entity/rule), minimum risk score, and source (UEBA Triage vs Manual). Expand any row to see full SIEM hits and Hive hits JSON.' },
    ]
  },
  threatmap: {
    title: 'Live Threat Map',
    desc: 'Real-time 3D globe visualization showing attack origins targeting your organization, derived from SIEM source IPs.',
    sections: [
      { name: 'Globe visualization', desc: 'Animated 3D globe with colored arcs showing attack trajectories. Arc origin = attacker source country. Arc target = YOUR ORG marker. Arc color follows severity: red = critical, orange = high, yellow = medium.' },
      { name: 'Attack counter', desc: 'Live counter in the corner showing total attacks in the current session and attacks per minute rate.' },
      { name: 'Arc hover tooltip', desc: 'Hover any arc to see: source country, source IP, rule that triggered, severity, and timestamp.' },
      { name: 'Data source', desc: 'Arcs are drawn from SIEM alerts that have a source IP address. The map polls for new alerts every 30 seconds and adds new arcs dynamically.' },
      { name: 'Country stats panel', desc: 'Right panel shows top attacking countries ranked by alert count, with flag icons and percentage of total attacks.' },
    ]
  },
  'create-rules': {
    title: 'Create Detection Rules',
    desc: 'Build, test, and deploy custom Wazuh SIEM detection rules via an AI-assisted workflow. Rules are written to your SIEM in real-time through the MCP bridge.',
    sections: [
      { name: 'Rule Builder (form)', desc: 'Fill in: Rule Name (human label), Severity Level (1–15, where 12+ = critical), Rule Group (e.g., "authentication", "web"), Match Pattern (the string Wazuh looks for in logs), MITRE Technique ID (optional, e.g. T1110), and Description. The form validates inputs before allowing test or deploy.' },
      { name: 'Generated Rule XML', desc: 'Auto-generated Wazuh XML rule based on your form inputs. Shows the exact XML that will be written to custom_rules.xml on the SIEM. The rule ID is randomly assigned in the 200000–299999 range (the Wazuh custom rules namespace). You can review this before deploying.' },
      { name: 'Test Rule (Dry Run)', desc: 'Sends the rule to the AI agent for syntax validation and logical review WITHOUT writing it to the SIEM. The agent checks: XML validity, pattern correctness, potential false positive rate, and MITRE mapping accuracy. Use this before every deploy.' },
      { name: 'Deploy to SIEM', desc: 'Sends the rule to your Wazuh manager via the MCP bridge (add_wazuh_rule tool). The rule becomes active immediately — no SIEM restart required. Requires analyst or admin role. A success response includes the assigned rule ID and verification status.' },
      { name: 'Deployed Custom Rules table', desc: 'Shows all rules currently in the 200000–299999 ID range that have fired at least once. Columns: Rule ID, Level badge, Description, Groups, MITRE, 24h fire count. Proves the rule is working after deployment.' },
      { name: 'AI Rule Templates', desc: 'Pre-built rule templates for common scenarios (brute force, privilege escalation, data exfiltration, web attacks). Click a template to auto-fill the Rule Builder form.' },
    ]
  },
  investigation: {
    title: 'AI Investigation',
    desc: 'AI-powered security investigation engine. Select an alert or describe an incident — the AI runs a multi-step ReAct investigation using 6 specialized tools and produces a full analysis report with analyst collaboration features.',
    sections: [
      { name: 'Alert selector', desc: 'Left panel shows recent SIEM alerts you can click to pre-load into the investigation. Alternatively type a free-text description of the incident in the input box.' },
      { name: 'Investigation input', desc: 'Text area where you describe what to investigate. Can be an IOC (IP, hash, domain), an alert rule ID, an agent name, or a plain English description like "unusual PowerShell from finance workstation".' },
      { name: 'Investigation report', desc: 'The AI agent\'s output: timeline of findings, IOC reputation verdicts, UEBA entity risk scores, MITRE techniques identified, correlated cases in TheHive, asset context, and recommended response actions.' },
      { name: 'Agent reasoning steps', desc: 'Expandable section showing the ReAct reasoning chain: each tool the agent called (search_alerts, enrich_ip, check_cases, query_ueba, query_assets, query_shodan), the inputs it used, and what it found. Useful for understanding WHY the AI reached its conclusion.' },
      { name: 'Auto-triage settings', desc: 'Toggle to enable automatic investigation of new high/critical alerts as they arrive. Threshold selector sets minimum severity for auto-triage.' },
      { name: 'Investigation history', desc: 'Paginated table of all saved investigations with severity badge, rule ID, alert description, agent, source IP, and triage method (Auto vs Manual). Click "View" on any row to open the detail modal.' },
      { name: 'Investigation detail modal — Report tab', desc: 'Full AI-generated investigation report with markdown formatting. Header bar shows severity, rule ID, triage method, timestamp. Footer has Download PDF and Copy Report buttons. Thumbs-up/down feedback buttons let you rate report quality.' },
      { name: 'Investigation detail modal — Comments tab', desc: 'Analyst comment thread for collaborative investigation. Any authenticated analyst can add a comment; comments persist in the database and appear for all team members. Press Ctrl+Enter or click Post. Useful for noting follow-up actions, FP/TP verdicts, or additional context the AI missed.' },
      { name: 'Investigation detail modal — Related tab', desc: 'Up to 5 recent investigations that share the same source IP, rule ID, or agent as the current one. Shows severity, rule, alert description, and a View button to jump directly to each related report. Helps identify recurring patterns or multi-stage attacks across different time windows.' },
    ]
  },
  copilot: {
    title: 'SOCPilots AI Copilot',
    desc: 'Conversational AI assistant for your SOC. Ask security questions, get alert explanations, request threat analysis, or have a contextual discussion about an active incident.',
    sections: [
      { name: 'Chat interface', desc: 'Standard conversational chat. The AI has access to your SIEM data and can query it on your behalf. Conversations are grouped by day in the left history panel.' },
      { name: 'Alert context attach', desc: 'Click the paper-clip / attach button to link a specific SIEM alert to your question. The AI receives the full alert metadata and raw log as context for its answer.' },
      { name: 'Chat history', desc: 'Left sidebar shows past conversation sessions grouped by date. Click any session to reload it. History is stored per user in the database.' },
      { name: 'Suggested prompts', desc: 'Quick-start buttons appear when chat is empty: "Summarize today\'s threats", "What is our highest-risk agent?", "Explain this alert", etc.' },
      { name: 'Model', desc: 'Uses the LangChain ReAct agent (GPT-4) as the backend. Responses may include tool calls to search alerts, enrich IOCs, or query UEBA — shown as expandable "tool use" blocks in the chat.' },
    ]
  },
  langchain: {
    title: 'LangChain Agent',
    desc: 'Direct interface to the LangChain ReAct investigation agent. Use this for controlled, single-shot investigations and to test agent behavior.',
    sections: [
      { name: 'Health status', desc: 'Header shows whether the langchain-agent service is reachable and which LLM is active (primary: GPT-4, fallback: Mistral). Green = healthy, Red = unreachable.' },
      { name: 'Investigate endpoint', desc: 'Deep multi-step investigation mode. The agent runs up to 10 reasoning steps using all 6 tools. Returns a comprehensive report. Best for complex incidents.' },
      { name: 'Triage endpoint', desc: 'Fast single-step triage. Returns a quick severity assessment and recommended action. Best for high-volume alert processing.' },
      { name: 'Enrich endpoint', desc: 'IOC enrichment mode. Enter an indicator and the agent runs VirusTotal + AbuseIPDB + OTX lookups and returns a structured threat profile.' },
      { name: 'Attach alert', desc: 'Attach a SIEM alert to provide the agent with full context (rule, raw log, agent, source IP) before running the investigation.' },
      { name: 'Reasoning trace', desc: 'Output panel shows each reasoning step: Thought → Action (tool name + input) → Observation (tool result) → Final Answer. Useful for debugging agent behavior.' },
    ]
  },
  assets: {
    title: 'Assets',
    desc: 'Network asset inventory. Assets are discovered via nmap scanning and cross-referenced with Wazuh agent enrollment to identify unmonitored hosts.',
    sections: [
      { name: 'Asset table', desc: 'All discovered assets with: IP address, Hostname, OS detection, Open ports list, Criticality tier (critical/high/medium/low), Wazuh Agent status (Enrolled / Not Enrolled), Last Seen, and Status.' },
      { name: 'Subnet management', desc: 'Define your network subnets (CIDR ranges) to scope asset discovery scans. Subnets panel shows each range, when it was last scanned, and asset count.' },
      { name: 'Scan management', desc: '"Scan Now" triggers an immediate nmap scan of all configured subnets. Scan job status updates in real-time. Scan history shows past jobs with duration and assets found.' },
      { name: 'Coverage gap detection', desc: 'Assets that are NOT enrolled in Wazuh are highlighted with an "Unmonitored" badge — these are blind spots in your detection coverage.' },
      { name: 'Criticality tiers', desc: 'Assign criticality to assets: Critical (core infrastructure), High (important servers), Medium (workstations), Low (IoT/peripherals). Criticality affects Dark SOC playbook behavior — critical assets are never auto-isolated.' },
      { name: 'Asset detail modal', desc: 'Click any asset row for full detail: all open ports with service names, OS fingerprint, Wazuh agent ID (if enrolled), vulnerability count from Wazuh, and action buttons.' },
    ]
  },
  ueba: {
    title: 'UEBA',
    desc: 'User and Entity Behavior Analytics. Tracks user and host behavior over time in a Neo4j graph and scores anomalies like impossible travel, lateral movement, and privilege escalation.',
    sections: [
      { name: 'Risk leaderboard', desc: 'Top-risk entities ranked by composite score (0–100). Shows username/hostname, risk score, top anomaly type, and last activity. Red = high risk, needs investigation.' },
      { name: 'Anomaly feed', desc: 'Recent detected anomalies with type, entity, score weight, and timestamp. Anomaly types: Impossible Travel (95pts), Lateral Movement (85), Privilege Escalation (80), New Host Access (75), New Process (70), After-Hours Access (55), High Frequency Login (50).' },
      { name: 'Entity behavior modal', desc: 'Click any entity to see its full behavior profile: typical login hours heatmap, known hosts, process history, baseline vs. current deviation, and full anomaly list with timestamps.' },
      { name: 'Entity force graph', desc: '"View Graph" button opens a D3.js force-directed graph showing relationships between users, hosts, processes, and network connections. Node size = risk score. Edge weight = relationship frequency.' },
      { name: 'Weekly Digest', desc: 'AI-generated weekly summary of the highest-risk users and behavioral trends. Admin can generate on-demand. Digest is emailed if SMTP is configured.' },
      { name: 'Filters', desc: 'Filter leaderboard by time window (24h/7d/30d) or anomaly type. Search by entity name.' },
    ]
  },
  reports: {
    title: 'Reports',
    desc: 'Security metrics and reporting for management and compliance. Generate summaries of SOC activity over custom time periods.',
    sections: [
      { name: 'Metrics overview', desc: 'KPI summary: total alerts, investigations completed, cases created, Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), and false positive rate for the selected period.' },
      { name: 'Alert trend chart', desc: 'Line chart of alert volume per day over the report period. Shows severity breakdown as stacked areas.' },
      { name: 'Top threats section', desc: 'Top 10 rules by fire count, top 10 attacking IPs, top 5 targeted agents, and most-detected MITRE techniques.' },
      { name: 'Coverage report', desc: 'ATT&CK coverage snapshot: total techniques covered, coverage percentage by tactic, and gap list (techniques with 0 detections).' },
      { name: 'Export', desc: 'Download report as JSON or use the browser print function for PDF. Future: scheduled email delivery.' },
    ]
  },
  evidence: {
    title: 'Evidence Upload',
    desc: 'Upload investigation evidence files for AI-powered semantic search. Files are OCR-processed and embedded into the Qdrant vector database for natural language retrieval.',
    sections: [
      { name: 'Upload zone', desc: 'Drag-and-drop or click to upload files. Supported formats: PDF, Excel (.xlsx), CSV, TXT, images (PNG/JPG — OCR applied). Max file size enforced by nginx (default 50MB).' },
      { name: 'Processing pipeline', desc: 'After upload: text is extracted (or OCR\'d for images), chunked into ~500-token segments, embedded using BAAI/bge-small-en-v1.5, and stored in the socpilots_evidence Qdrant collection.' },
      { name: 'Evidence library', desc: 'Table of all uploaded files with filename, type, upload date, page/chunk count, and status (processing/ready/failed).' },
      { name: 'Semantic search', desc: 'Search box at the top queries all evidence files using natural language. Results show the most relevant text chunks with source file and confidence score. Used by the LangChain agent during investigations.' },
      { name: 'Delete evidence', desc: 'Each file row has a Delete button. Deletion removes both the database record and all associated vector embeddings from Qdrant.' },
    ]
  },
  darksoc: {
    title: 'Dark SOC',
    desc: 'Automated response engine. When enabled, Dark SOC executes playbook actions automatically when alerts meet configured criteria — without requiring analyst approval (except for destructive actions).',
    sections: [
      { name: 'Enable/Disable toggle', desc: 'Master switch for the entire Dark SOC engine. DISABLED by default. When disabled, playbooks still run in simulation mode (logged but no real actions taken). Enable only after reviewing and testing all playbooks.' },
      { name: 'Playbook library', desc: 'All configured response playbooks. Each has: name, trigger condition (severity + rule groups), actions list, and enabled/disabled toggle. Six action types: Block IP, Isolate Host, Kill Process, Disable User, Create Case, Close Case.' },
      { name: 'Execution log', desc: 'Audit trail of every playbook action attempted: timestamp, playbook name, action type, target (IP/host/user), result (success/failed/skipped), and the analyst who approved (for consensus actions).' },
      { name: 'Consensus approvals', desc: 'Isolate Host and Disable User require two-step consensus — a second analyst or LLM must agree before the action executes. Pending approvals appear here with a 30-minute expiry timer.' },
      { name: 'Protected assets', desc: 'Assets in this list are NEVER auto-isolated regardless of playbook rules. Add your critical servers, domain controllers, and core infrastructure here. Critical-tier assets auto-escalate instead of isolating.' },
      { name: 'False positive gate', desc: 'Each destructive action (block/isolate/disable) checks the FP probability before executing. If false positive likelihood exceeds the configured threshold, the action is skipped and logged.' },
    ]
  },
  users: {
    title: 'User Management',
    desc: 'SOCPilots user administration (admin role required). Create, edit, and deactivate analyst accounts.',
    sections: [
      { name: 'User table', desc: 'All platform users with: username, display name, role badge, last login time, and active status. Admins can click any row to edit.' },
      { name: 'Role system', desc: 'Four roles in hierarchy order: L1 (Viewer — read-only, no investigations), L2 / Analyst (standard analyst — can investigate and create cases), L3 / Senior Analyst (can manage playbooks and rules), Admin (full access including user management and Dark SOC).' },
      { name: 'Create user', desc: '"Add User" button opens a form: username, password, display name, role selector. Password is bcrypt-hashed at creation.' },
      { name: 'Edit / deactivate', desc: 'Click a user row to edit display name, role, or reset password. Deactivate instead of delete to preserve audit trails — deactivated users cannot log in.' },
    ]
  },
  settings: {
    title: 'Settings',
    desc: 'Platform configuration for integrations, notifications, and SOC-wide behavior settings.',
    sections: [
      { name: 'SMTP email settings', desc: 'Configure outbound email for alert notifications and weekly digests: SMTP host, port, TLS toggle, sender address, username/password. Test button sends a test email.' },
      { name: 'OTX AlienVault sync', desc: 'OTX feed configuration: API key status (read-only — set in .env), last sync time, IOC count, and manual "Sync Now" button. Feed syncs automatically every 6 hours.' },
      { name: 'Dark SOC toggle', desc: 'Shortcut to enable/disable the Dark SOC engine. Same as the toggle on the Dark SOC page.' },
      { name: 'Notification preferences', desc: 'Configure which event types generate in-app notifications: new investigations, case creation, playbook actions, correlations. Severity threshold for notifications.' },
      { name: 'Integration health', desc: 'Status panel showing connectivity to all integrated services: Wazuh SIEM, TheHive, n8n, LangChain Agent, RAG service, Neo4j UEBA, Qdrant. Red = unreachable, Green = healthy.' },
    ]
  },
  notifications: {
    title: 'Notifications',
    desc: 'Full notification history. All platform events that generated a notification, paginated and filterable.',
    sections: [
      { name: 'Notification list', desc: 'All notifications with: type icon, title, message, severity badge, timestamp, and read/unread status. Click any row to mark as read and navigate to the related module.' },
      { name: 'Notification types', desc: 'Investigation (new AI investigation completed), Case Created (TheHive case opened), True Positive (confirmed TP from investigation), Correlation (new alert cluster found), Playbook (Dark SOC action executed).' },
      { name: 'Mark all read', desc: '"Mark All Read" button clears the unread count badge in the bell icon in the header.' },
      { name: 'Filters', desc: 'Filter by read/unread status or notification type. Sorted newest-first.' },
      { name: 'Bell badge', desc: 'The bell icon in the top-right header shows unread count. Updates live via WebSocket when new events arrive — no page refresh needed.' },
    ]
  },
  sla: {
    title: 'SLA Management',
    desc: 'Track response and resolution SLAs for investigations, cases, and SIEM alerts. Monitor breach risk, pause/resume timers, and manage SLA policies.',
    sections: [
      { name: 'KPI Cards', desc: 'Five tiles: Active SLAs (running timers), Breached (past deadline), Paused (suspended timers), Compliance Rate (% resolved on time in last 30 days), Average MTTR (mean time to resolve in last 30 days).' },
      { name: 'Active tab', desc: 'All currently running SLA timers. Each row shows entity, type (investigation/case/alert), severity, policy name, elapsed time, remaining time, risk bar (green < 70%, yellow 70-89%, red 90%+), owner, and Pause/Done buttons.' },
      { name: 'Breached tab', desc: 'SLAs that exceeded their deadline. Shows elapsed time and how far over the SLA window the entity went. Use Resolve button to mark the entity as handled.' },
      { name: 'All SLAs tab', desc: 'Full paginated list of every SLA instance. Filter by status (running/paused/completed/breached/cancelled) and entity type. Click any row to open the audit log detail modal.' },
      { name: 'Policies tab', desc: 'CRUD for SLA policies (admin only). Each policy defines response minutes, resolution minutes, target entity type, severity tier, and an escalation chain (notify/escalate actions at 70%/90%/100% thresholds). Four default policies are pre-seeded.' },
      { name: 'Start SLA button', desc: 'Manually start an SLA timer for any entity. Select entity type, enter the ID, optional label, and severity. The system auto-selects the best matching policy.' },
      { name: 'SLA detail modal', desc: 'Opens on row click. Shows full timing breakdown (elapsed, remaining, pause duration), breach percentage, owner, and full chronological audit log of every timer event (started, paused, resumed, threshold hits, breached, completed).' },
      { name: 'Background ticker', desc: 'A 60-second server-side ticker monitors all running SLAs. At 70%: sends a warning notification. At 90%: sends critical escalation notification. At 100%: marks SLA as breached, sends breach alert, and emits a WebSocket event for live updates.' },
    ]
  }
};

app.post('/api/help/chat', authMW, async (req, res) => {
  try {
    const { page, question, history = [] } = req.body;
    if (!question?.trim()) return res.status(400).json({ error: 'question required' });
    if (!OPENAI_API_KEY && !MISTRAL_API_KEY) {
      return res.status(503).json({ error: 'No AI key configured. Set OPENAI_API_KEY or MISTRAL_API_KEY in .env' });
    }

    const ctx = PAGE_CONTEXTS[page] || { title: page, desc: 'SOCPilots security operations platform page.', sections: [] };
    const sectionsText = ctx.sections.map(s => `• ${s.name}: ${s.desc}`).join('\n');

    const systemPrompt = `You are the SOCPilots platform guide, embedded directly in the UI.
The analyst is currently on the "${ctx.title}" page.

Page purpose: ${ctx.desc}

Sections and elements on this page:
${sectionsText}

Your rules:
- Answer only about what exists on THIS page and this platform. Do not reference external docs.
- Be concise and direct — analysts are mid-shift. No filler phrases.
- If asked "explain everything" or "explain this page", give a structured overview of every section listed above.
- Use bullet points for multi-part answers. Keep answers under 250 words unless the analyst asks for more detail.
- Never say you don't know about a feature listed above — all context is provided to you.
- You may reference other SOCPilots pages by name if explaining a workflow that spans pages.`;

    const messages = [
      { role: 'system', content: systemPrompt },
      ...history.slice(-8),
      { role: 'user', content: question.trim() }
    ];

    let answer;
    if (OPENAI_API_KEY) {
      const r = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: 'gpt-4o-mini',
        max_tokens: 600,
        temperature: 0.3,
        messages,
      }, {
        headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
        timeout: 30000,
      });
      answer = r.data.choices[0].message.content;
    } else {
      const r = await axios.post('https://api.mistral.ai/v1/chat/completions', {
        model: 'mistral-small-latest',
        max_tokens: 600,
        temperature: 0.3,
        messages,
      }, {
        headers: { Authorization: `Bearer ${MISTRAL_API_KEY}`, 'Content-Type': 'application/json' },
        timeout: 30000,
      });
      answer = r.data.choices[0].message.content;
    }

    res.json({ answer });
  } catch (e) {
    console.error('[help-chat]', e.message);
    res.status(502).json({ error: 'AI service unavailable. Check OPENAI_API_KEY in .env' });
  }
});

// ═══════════════════════════════════════════════════════════════
// ─── SLA MANAGEMENT ─────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════

// Compute derived fields (elapsed, remaining, breach%) from stored timestamps
function computeSlaStatus(inst) {
  const now = Date.now();
  const startMs = new Date(inst.started_at).getTime();
  const totalPaused = parseInt(inst.total_paused_ms || 0);
  let elapsedMs;
  if (inst.status === 'paused' && inst.paused_at) {
    elapsedMs = new Date(inst.paused_at).getTime() - startMs - totalPaused;
  } else if (['completed', 'breached', 'cancelled'].includes(inst.status) && inst.completed_at) {
    elapsedMs = new Date(inst.completed_at).getTime() - startMs - totalPaused;
  } else {
    elapsedMs = now - startMs - totalPaused;
  }
  const durationMs  = inst.response_minutes * 60_000;
  const remainingMs = Math.max(0, durationMs - elapsedMs);
  const pct         = Math.min(Math.round((elapsedMs / durationMs) * 100), 9999);
  const fmt = ms => {
    const s = Math.floor(Math.abs(ms) / 1000);
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  };
  let riskLevel = 'ok';
  if      (inst.status === 'completed' || inst.status === 'cancelled') riskLevel = inst.status;
  else if (pct >= 100) riskLevel = 'breached';
  else if (pct >= 90)  riskLevel = 'critical';
  else if (pct >= 70)  riskLevel = 'at_risk';
  return { ...inst, elapsed_ms: elapsedMs, remaining_ms: remainingMs,
    elapsed_human: fmt(elapsedMs), remaining_human: fmt(remainingMs),
    breach_pct: pct, risk_level: riskLevel };
}

// Annotate SLA instances where entity_type === 'alert' with a human-readable short ID
function withSlaShortId(inst) {
  if (inst && inst.entity_type === 'alert' && inst.entity_id) {
    return { ...inst, entity_short_id: alertShortId(inst.entity_id) };
  }
  return inst;
}
const computeSla = inst => withSlaShortId(computeSlaStatus(inst));

// ── SLA Policy CRUD ──────────────────────────────────────────────
app.get('/api/sla/policies', authMW, async (req, res) => {
  try {
    const policies = await db.listSlaPolicies();
    res.json({ policies, total: policies.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sla/policies', authMW, requireRole('admin'), async (req, res) => {
  try {
    const { name, description, entity_type, severity, response_minutes, resolution_minutes, escalation_chain } = req.body;
    if (!name || !response_minutes || !resolution_minutes)
      return res.status(400).json({ error: 'name, response_minutes, resolution_minutes required' });
    const p = await db.createSlaPolicy({
      name, description, entityType: entity_type, severity,
      responseMinutes: parseInt(response_minutes), resolutionMinutes: parseInt(resolution_minutes),
      escalationChain: escalation_chain || [], createdBy: req.user.username,
    });
    res.status(201).json(p);
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Policy name already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/sla/policies/:id', authMW, requireRole('admin'), async (req, res) => {
  try {
    const { name, description, entity_type, severity, response_minutes, resolution_minutes, escalation_chain, active } = req.body;
    if (!name || !response_minutes || !resolution_minutes)
      return res.status(400).json({ error: 'name, response_minutes, resolution_minutes required' });
    const p = await db.updateSlaPolicy(parseInt(req.params.id), {
      name, description, entityType: entity_type, severity,
      responseMinutes: parseInt(response_minutes), resolutionMinutes: parseInt(resolution_minutes),
      escalationChain: escalation_chain || [], active,
    });
    if (!p) return res.status(404).json({ error: 'policy not found' });
    res.json(p);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/sla/policies/:id', authMW, requireRole('admin'), async (req, res) => {
  try {
    const ok = await db.deleteSlaPolicy(parseInt(req.params.id));
    if (!ok) return res.status(404).json({ error: 'policy not found' });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SLA Instance lifecycle ───────────────────────────────────────
app.post('/api/sla/start', authMW, requireRole('l2'), async (req, res) => {
  try {
    const { entity_type, entity_id, entity_label, severity, sla_type } = req.body;
    if (!entity_type || !entity_id)
      return res.status(400).json({ error: 'entity_type and entity_id required' });
    const policy = await db.getSlaPolicyForEntity(entity_type, severity);
    if (!policy) return res.status(404).json({ error: 'No SLA policy found for entity type and severity' });
    const inst = await db.createSlaInstance({
      policyId: policy.id, policyName: policy.name,
      entityType: entity_type, entityId: String(entity_id),
      entityLabel: entity_label || null, severity: severity || null,
      slaType: sla_type || 'response',
      responseMinutes: policy.response_minutes,
      resolutionMinutes: policy.resolution_minutes,
      owner: req.user.username,
    });
    await db.createSlaEvent({ slaInstanceId: inst.id, eventType: 'started', actor: req.user.username, newStatus: 'running' });
    res.status(201).json(computeSlaStatus(inst));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sla/instances/:id/pause', authMW, requireRole('l2'), async (req, res) => {
  try {
    const inst = await db.pauseSlaInstance(parseInt(req.params.id), req.user.username, req.body.reason);
    if (!inst) return res.status(404).json({ error: 'SLA not found or not running' });
    res.json(computeSlaStatus(inst));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sla/instances/:id/resume', authMW, requireRole('l2'), async (req, res) => {
  try {
    const inst = await db.resumeSlaInstance(parseInt(req.params.id), req.user.username, req.body.reason);
    if (!inst) return res.status(404).json({ error: 'SLA not found or not paused' });
    res.json(computeSlaStatus(inst));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sla/instances/:id/stop', authMW, requireRole('l2'), async (req, res) => {
  try {
    const inst = await db.completeSlaInstance(parseInt(req.params.id), req.user.username, req.body.reason);
    if (!inst) return res.status(404).json({ error: 'SLA not found or already finished' });
    res.json(computeSlaStatus(inst));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sla/instances/:id/cancel', authMW, requireRole('l2'), async (req, res) => {
  try {
    const inst = await db.cancelSlaInstance(parseInt(req.params.id), req.user.username, req.body.reason);
    if (!inst) return res.status(404).json({ error: 'SLA not found' });
    res.json(computeSlaStatus(inst));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sla/instances/:id', authMW, async (req, res) => {
  try {
    const inst = await db.getSlaInstance(parseInt(req.params.id));
    if (!inst) return res.status(404).json({ error: 'not found' });
    res.json(computeSla(inst));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sla/instances/:id/events', authMW, async (req, res) => {
  try {
    const events = await db.listSlaEvents(parseInt(req.params.id));
    res.json({ events, total: events.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sla/instances', authMW, async (req, res) => {
  try {
    const page      = Math.max(parseInt(req.query.page) || 1, 1);
    const page_size = Math.min(parseInt(req.query.page_size) || 50, 200);
    const { rows, total } = await db.listSlaInstances({
      page, pageSize: page_size,
      status: req.query.status || undefined,
      entityType: req.query.entity_type || undefined,
    });
    res.json({ items: rows.map(computeSla), total, page, page_size, has_more: page * page_size < total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sla/entity', authMW, async (req, res) => {
  try {
    const { type, id } = req.query;
    if (!type || !id) return res.status(400).json({ error: 'type and id required' });
    const inst = await db.getSlaForEntity(type, id);
    if (!inst) return res.status(404).json({ error: 'no SLA found' });
    res.json(computeSlaStatus(inst));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SLA Dashboard & list views ───────────────────────────────────
app.get('/api/sla/dashboard', authMW, async (req, res) => {
  try {
    const stats = await db.getSlaDashboardStats();
    res.json(stats);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sla/active', authMW, async (req, res) => {
  try {
    const page      = Math.max(parseInt(req.query.page) || 1, 1);
    const page_size = Math.min(parseInt(req.query.page_size) || 50, 200);
    const { rows, total } = await db.listSlaInstances({ page, pageSize: page_size, status: 'running', entityType: req.query.entity_type || undefined });
    res.json({ items: rows.map(computeSla), total, page, page_size, has_more: page * page_size < total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sla/breached', authMW, async (req, res) => {
  try {
    const page      = Math.max(parseInt(req.query.page) || 1, 1);
    const page_size = Math.min(parseInt(req.query.page_size) || 50, 200);
    const { rows, total } = await db.listSlaInstances({ page, pageSize: page_size, status: 'breached', entityType: req.query.entity_type || undefined });
    res.json({ items: rows.map(computeSla), total, page, page_size, has_more: page * page_size < total });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SLA policy map (severity → response/resolution minutes) ─────
app.get('/api/sla/policy-map', authMW, async (req, res) => {
  try {
    const map = await db.getSlaPolicyMap();
    res.json(map);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SLA alerts view — auto-starts SLA for all high/medium/critical ──
// Fetches SIEM alerts, upserts SLA instance per alert (backdated to alert
// timestamp), returns each alert enriched with live SLA status.
app.get('/api/sla/alerts', authMW, async (req, res) => {
  try {
    const hours    = Math.min(parseInt(req.query.hours) || 24, 168);
    const sevList  = ['critical', 'high', 'medium'];
    const policyMap = await db.getSlaPolicyMap();

    // Fetch high/medium/critical alerts from OpenSearch
    const osBody = {
      size: 200,
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: {
        bool: {
          must: [{ terms: { 'rule.level': [5,6,7,8,9,10,11,12,13,14,15] } }],
          filter: [{ range: { '@timestamp': { gte: `now-${hours}h` } } }],
        }
      },
      _source: ['@timestamp','rule.id','rule.level','rule.description','rule.mitre',
                'agent.name','data.srcip','data.dstip','full_log'],
    };
    const osResp = await osSearch(osBody).catch(() => ({ hits: { hits: [] } }));
    const hits   = osResp?.hits?.hits || [];

    // Determine severity per alert
    const severityOf = level => {
      const l = parseInt(level);
      if (l >= 12) return 'critical';
      if (l >= 8)  return 'high';
      if (l >= 5)  return 'medium';
      return 'low';
    };

    // Filter to high/medium/critical only
    const alerts = hits
      .map(h => ({ _id: h._id, short_id: alertShortId(h._id), ...h._source }))
      .filter(a => sevList.includes(severityOf(a.rule?.level)));

    if (!alerts.length) return res.json({ alerts: [], total: 0 });

    // Upsert SLA instances in parallel (max 50 at once to avoid DB overload)
    const batch = alerts.slice(0, 100);
    const slaInstances = await Promise.all(batch.map(async a => {
      const sev    = severityOf(a.rule?.level);
      const policy = policyMap[sev];
      if (!policy) return null;
      const inst = await db.upsertSlaForAlert({
        alertId:          a._id,
        alertLabel:       (a.rule?.description || '').slice(0, 200),
        severity:         sev,
        alertTimestamp:   a['@timestamp'],
        policyId:         null,
        policyName:       `${sev.charAt(0).toUpperCase() + sev.slice(1)} Severity SLA`,
        responseMinutes:  policy.response_minutes,
        resolutionMinutes: policy.resolution_minutes,
      }).catch(() => null);
      return { alert: a, sla: inst };
    }));

    // Compute live SLA status for each
    const result = slaInstances
      .filter(Boolean)
      .map(({ alert, sla }) => {
        if (!sla) return { alert, sla: null, sla_status: 'no_policy' };
        return { alert, sla: computeSla(sla) };
      });

    res.json({ alerts: result, total: result.length });
  } catch(e) {
    console.error('[sla/alerts]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── SLA breach detection ticker (runs every 60s) ─────────────────
async function slaTickerRun() {
  try {
    const instances = await db.getActiveSlaInstances();
    for (const inst of instances) {
      const elapsedMs  = Date.now() - new Date(inst.started_at).getTime() - parseInt(inst.total_paused_ms || 0);
      const durationMs = inst.response_minutes * 60_000;
      const pct        = (elapsedMs / durationMs) * 100;
      const updates    = {};
      const label      = inst.entity_label || `${inst.entity_type} ${inst.entity_id}`;

      if (!inst.notified_70 && pct >= 70) {
        updates.notified_70 = true;
        await db.createNotification('sla', `SLA At Risk: ${label}`,
          `${inst.policy_name || 'SLA'} has used ${Math.round(pct)}% of its ${inst.response_minutes}m window.`,
          'medium', null, { sla_instance_id: inst.id, breach_pct: Math.round(pct) });
        await db.createSlaEvent({ slaInstanceId: inst.id, eventType: 'threshold_70', reason: `${Math.round(pct)}% elapsed` });
      }
      if (!inst.notified_90 && pct >= 90) {
        updates.notified_90 = true;
        await db.createNotification('sla', `SLA Critical (90%): ${label}`,
          `${inst.policy_name || 'SLA'} for ${label} has consumed 90% of its ${inst.response_minutes}m window. Escalate immediately.`,
          'high', null, { sla_instance_id: inst.id, breach_pct: Math.round(pct) });
        await db.createSlaEvent({ slaInstanceId: inst.id, eventType: 'threshold_90', reason: `${Math.round(pct)}% elapsed` });
      }
      if (!inst.notified_breach && pct >= 100) {
        updates.notified_breach = true;
        updates.status = 'breached';
        await db.createNotification('sla', `SLA BREACHED: ${label}`,
          `${inst.policy_name || 'SLA'} for ${label} exceeded its ${inst.response_minutes}m SLA window by ${Math.round((elapsedMs - durationMs) / 60_000)}m.`,
          'critical', null, { sla_instance_id: inst.id, breach_pct: Math.round(pct) });
        await db.createSlaEvent({ slaInstanceId: inst.id, eventType: 'breached', reason: 'SLA window exceeded', prevStatus: 'running', newStatus: 'breached' });
        io.emit('sla:breached', { id: inst.id, entity_type: inst.entity_type, entity_id: inst.entity_id, label });
      }

      if (Object.keys(updates).length) await db.applySlaTickerUpdates(inst.id, updates);
    }
  } catch(e) { console.error('[SLA-TICKER]', e.message); }
}

// ─── STATIC (must be last — after all /api routes) ──────────────
// Serve .jsx files as JS so Babel standalone can load them
app.use(express.static(path.join(__dirname, '../../frontend'), {
  setHeaders(res, filePath) {
    if (filePath.endsWith('.jsx')) res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    if (filePath.endsWith('.css')) res.setHeader('Content-Type', 'text/css; charset=utf-8');
  },
}));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../../frontend/index.html')));

// Initialize DB schema on startup (non-blocking)
db.initSchema()
  .then(() => seedUsersFromEnv())
  .then(() => startHuntScheduler())
  .then(() => {
    // IOC auto-ingest: every 15 min; first run 2 min after boot to let OpenSearch warm up
    setInterval(() => autoIngestAlerts(15), 15 * 60_000);
    setTimeout(()  => autoIngestAlerts(60), 2 * 60_000);  // first run: last 60 min
    // IOC auto-enrich: every 30 min; first run 5 min after boot (staggered from ingest)
    setInterval(() => autoEnrichJob(10),    30 * 60_000);
    setTimeout(()  => autoEnrichJob(10),     5 * 60_000);
    // SLA breach detection: every 60s
    setInterval(slaTickerRun, 60_000);
    setTimeout(slaTickerRun, 10_000);
  })
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
