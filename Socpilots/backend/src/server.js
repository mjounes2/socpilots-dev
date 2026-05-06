// ============================================================
// SOC PILOTS — Production Backend
// OpenSearch (Wazuh) + SP-CM (direct) + n8n (AI/Hunt/Rules)
// ============================================================
const express  = require('express');
const axios    = require('axios');
const https    = require('https');
const crypto   = require('crypto');
const path     = require('path');
const bcrypt   = require('bcryptjs');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });
const db       = require('./db');
const ueba     = require('./neo4j');
const playbook = require('./playbook-engine');
const email    = require('./email-service');

const app  = express();
const PORT = process.env.PORT || 3000;
app.use(express.json({ limit: '10mb' }));

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
const LANGCHAIN_TOKEN   = process.env.LANGCHAIN_INTERNAL_TOKEN || '';
const MCP_WAZUH_URL     = process.env.MCP_WAZUH_URL    || 'http://mcp-wazuh:3001';

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
      return { ok: false, error: 'Rate limit exceeded (429) — Mistral API quota reached. Wait 60s and retry.', raw: d };
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
      if (!valid) return res.status(401).json({ error: 'Invalid username or password' });
      await db.updateLastLogin(uname);
      const token = mkToken(dbUser.username, dbUser.role, dbUser.display_name);
      console.log(`[LOGIN] ${dbUser.username} (db, role=${dbUser.role})`);
      return res.json({ token, username: dbUser.username, role: dbUser.role, display_name: dbUser.display_name });
    }
  } catch(e) {
    console.warn('[LOGIN] DB lookup error:', e.message);
  }

  // 2. Fall back to env users (backward compat)
  const u = ENV_USERS.find(u =>
    u.username.toLowerCase() === uname && u.password === password
  );
  if (!u) return res.status(401).json({ error: 'Invalid username or password' });
  const token = mkToken(u.username, u.role, u.username);
  console.log(`[LOGIN] ${u.username} (env, role=${u.role})`);
  res.json({ token, username: u.username, role: u.role, display_name: u.username });
});

app.post('/api/logout', authMW, (req, res) => {
  sessions.delete((req.headers.authorization || '').replace('Bearer ', '').trim());
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
    const limit  = Math.min(parseInt(req.query.limit) || 100, 500);
    const sev    = req.query.severity; // critical|high|medium|low
    const search = req.query.q;
    const hours  = parseInt(req.query.hours) || 0;
    const fromTs = req.query.from || null;
    const toTs   = req.query.to   || null;
    const agent  = req.query.agent;
    const srcip  = req.query.srcip;

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
      size: limit,
      sort: [{ '@timestamp': 'desc' }],
      query: must.length ? { bool: { must } } : { match_all: {} },
      _source: ['@timestamp', 'rule', 'agent', 'data', 'srcip', 'full_log', 'location', 'manager'],
    };

    const r = await osSearch(body);
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
    res.json({ alerts, total: r.hits.total?.value || alerts.length });
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
app.get('/api/rules', authMW, async (req, res) => {
  try {
    const r = await osSearch({
      size: 0,
      aggs: {
        rules: {
          terms: { field: 'rule.id', size: 1000, order: { max_level: 'desc' } },
          aggs: {
            desc:      { terms: { field: 'rule.description', size: 1 } },
            max_level: { max: { field: 'rule.level' } },
            groups:    { terms: { field: 'rule.groups', size: 5 } },
            mitre:     { terms: { field: 'rule.mitre.id', size: 3 } },
          },
        },
      },
    });

    const rules = r.aggregations.rules.buckets.map(b => ({
      id:          b.key,
      level:       Math.round(b.max_level?.value || 0),
      description: b.desc?.buckets?.[0]?.key || 'N/A',
      severity:    sevFromLevel(b.max_level?.value),
      groups:      b.groups?.buckets?.map(g => g.key).join(', ') || '',
      mitre:       b.mitre?.buckets?.[0]?.key || '',
      count:       b.doc_count,
    }));

    res.json({ rules, total: rules.length });
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

// ── THEHIVE CASES ──
app.get('/api/cases', authMW, async (req, res) => {
  try {
    const status = req.query.status; // New|InProgress|Resolved
    let query = [{ _name: 'listCase' }];
    if (status) query.push({ _name: 'filter', _field: 'status', _value: status });
    query.push({ _name: 'sort', _fields: [{ _createdAt: 'desc' }] });
    const data = await hiveQuery(query);
    // SP-CM status field values (all in c.status):
    //   Open statuses:   New, InProgress
    //   Closed statuses: TruePositive, FalsePositive, Duplicate, Other, Indeterminate, Resolved
    const CLOSED_STATUSES = new Set([
      'TruePositive','FalsePositive','Duplicate','Other','Indeterminate','Resolved',
      'True Positive','False Positive', // handle spaces too
    ]);
    const STATUS_LABELS = {
      'New':           'New',
      'InProgress':    'In Progress',
      'Resolved':      'Resolved',
      'TruePositive':  'True Positive',
      'FalsePositive': 'False Positive',
      'Duplicate':     'Duplicate',
      'Other':         'Other',
      'Indeterminate': 'Indeterminate',
    };
    const cases = (Array.isArray(data) ? data : []).map(c => {
      const rawStatus   = c.status || 'New';
      const stage       = c.stage  || '';
      const isClosed    = CLOSED_STATUSES.has(rawStatus);
      const isInProgress = rawStatus === 'InProgress' || rawStatus === 'In Progress';
      const statusLabel = STATUS_LABELS[rawStatus] || rawStatus;

      return {
        id:           c._id,
        number:       c.number,
        title:        c.title,
        status:       rawStatus,       // exact SP-CM value
        statusLabel,                   // human readable
        stage,
        isClosed,
        isInProgress,
        severity:     c.severityLabel || hiveSevLabel(c.severity),
        severityNum:  c.severity,
        assignee:     c.assignee,
        tags:         c.tags || [],
        tlp:          c.tlpLabel || 'AMBER',
        created:      c._createdAt,
        startDate:    c.startDate,
        description:  c.description,
        mitre:        (c.tags || []).filter(t => t.startsWith('rule=')).map(t => t.replace('rule=', '')),
      };
    });
    res.json({ cases, total: cases.length });
  } catch (e) {
    console.error('[cases]', e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── THEHIVE ALERTS ──
app.get('/api/hive-alerts', authMW, async (req, res) => {
  try {
    const status = req.query.status;
    let query = [{ _name: 'listAlert' }];
    if (status) query.push({ _name: 'filter', _field: 'status', _value: status });
    query.push({ _name: 'sort', _fields: [{ _createdAt: 'desc' }] });
    const data = await hiveQuery(query);
    const alerts = (Array.isArray(data) ? data : []).map(a => ({
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
    res.json({ alerts, total: alerts.length });
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

// ── SOCPilots AI CHAT ──
app.post('/api/ai/chat', authMW, async (req, res) => {
  const { message, history, session_id } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'message required' });
  // Rate limit per user to prevent Mistral 429
  if (!chatRateOk(req.user?.username)) {
    return res.status(429).json({
      error: 'Rate limit: max 8 messages per minute. Please wait.',
      rateLimit: true,
    });
  }
  const sid = session_id || `soc_${req.user.username}`;
  const r = await n8nAsk(message, sid, req.user, {
    history: (history || []).slice(-6), // reduced from 10 to 6
  });
  if (!r.ok) {
    const errMsg = r.error || 'SOCPilots AI unavailable';
    return res.status(r.error?.includes('Rate limit') ? 429 : 502).json({ error: errMsg });
  }
  // Persist chat messages to DB (non-blocking)
  const aiText = r.text || '';
  db.saveChatMessage(sid, req.user.username, 'user', message, {}).catch(() => {});
  if (aiText) db.saveChatMessage(sid, req.user.username, 'assistant', aiText, {}).catch(() => {});
  res.json(r.raw || { response: aiText });
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
        const saved = await db.saveInvestigation({
          alertId:      alert.id || alert._id,
          ruleId:       alert.ruleId,
          level:        alert.level,
          severity:     alert.severity || (alert.level >= 12 ? 'critical' : 'high'),
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
        });
        savedId = saved.id;
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
    const { severity, agent, ruleId, q, limit=100, offset=0 } = req.query;
    const items = await db.listInvestigations({
      severity, agent, ruleId, q,
      limit: Math.min(parseInt(limit)||100, 500),
      offset: parseInt(offset)||0,
    });
    const stats = await db.getInvestigationStats();
    res.json({ items, stats, total: items.length });
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
    res.json({ ok: true, updated: Object.keys(updates) });
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

    // Send email notification if marked as true positive
    if (tp_status === 'confirmed_tp') {
      const investigation = await db.getInvestigationById(investigationId);
      if (investigation) {
        const emailBody = email.generateInvestigationTPEmail(investigation);
        await email.sendToRecipients(
          `[SOCPilots] Investigation Confirmed as True Positive: ${investigation.rule_id}`,
          emailBody
        );
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
    const limit  = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;
    const [execs, stats] = await Promise.all([
      db.listPlaybookExecutions({ limit, offset }),
      db.getPlaybookExecStats(),
    ]);
    res.json({ executions: execs, stats, total: execs.length });
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
    const [settings, execStats, pbCount] = await Promise.all([
      db.getAllSettings(),
      db.getPlaybookExecStats(),
      db.listPlaybooks({ enabledOnly: true }).then(r => r.length),
    ]);
    res.json({
      darksoc_enabled:                settings.darksoc_enabled === 'true',
      hunt_enabled:                   settings.darksoc_hunt_enabled === 'true',
      lateral_monitor_enabled:        settings.darksoc_lateral_monitor_enabled === 'true',
      auto_triage_enabled:            settings.auto_triage_enabled === 'true',
      active_playbooks:               pbCount,
      execution_stats:                execStats,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AUTO-TRIAGE WORKER ──
let _lastAutoTriageRun = 0;
let _autoTriageRunning = false;

async function autoTriageWorker() {
  if (_autoTriageRunning) return;
  _autoTriageRunning = true;
  try {
    const enabled = await db.getSetting('auto_triage_enabled');
    if (enabled !== 'true') { _autoTriageRunning = false; return; }

    const minLevel = parseInt(await db.getSetting('auto_triage_min_level') || '12');
    const intervalSec = parseInt(await db.getSetting('auto_triage_interval_sec') || '60');

    // Don't run more often than configured
    if (Date.now() - _lastAutoTriageRun < intervalSec * 1000) {
      _autoTriageRunning = false;
      return;
    }
    _lastAutoTriageRun = Date.now();

    console.log(`[AutoTriage] Running (minLevel=${minLevel})`);

    // Fetch recent high+critical alerts (last 30 min)
    const body = {
      size: 20,
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: {
        bool: {
          filter: [
            { range: { 'rule.level': { gte: minLevel } } },
            { range: { '@timestamp': { gte: 'now-30m' } } },
          ],
        },
      },
    };

    const r = await osSearch(body, IDX);
    const alerts = (r.hits?.hits || []).map(h => ({
      id:          h._id,
      timestamp:   h._source['@timestamp'],
      ruleId:      String(h._source.rule?.id || ''),
      level:       h._source.rule?.level || 0,
      severity:    h._source.rule?.level >= 12 ? 'critical' : 'high',
      description: h._source.rule?.description || '',
      agent:       h._source.agent?.name || '',
      srcIp:       h._source.data?.srcip || h._source.data?.src_ip || '',
      mitre:       h._source.rule?.mitre?.id || [],
      fullLog:     (h._source.full_log || '').slice(0, 500),
    }));

    let triaged = 0;
    for (const alert of alerts) {
      const alertKey = `${alert.ruleId}_${alert.timestamp}_${alert.agent}_${alert.srcIp||''}`;
      const existing = await db.getInvestigationByAlertKey(alertKey);
      if (existing) continue; // Already investigated

      console.log(`[AutoTriage] Investigating ${alert.ruleId} (${alert.severity})`);

      try {
        const start   = Date.now();
        const darkSoc = await db.getSetting('darksoc_enabled');

        const prompt = `Auto-investigate this alert. Provide concise analysis with executive summary, MITRE mapping, risk assessment, and recommended actions.

Alert:
- Timestamp: ${alert.timestamp}
- Rule: ${alert.ruleId} (level ${alert.level})
- Description: ${alert.description}
- Agent: ${alert.agent}
- Source IP: ${alert.srcIp}
- MITRE: ${(alert.mitre||[]).join(', ')}

Use markdown tables. Be concise.`;

        // ── Step 1: Deep investigation via n8n ──────────────────
        const r = await axios.post(N8N_INV, {
          action: 'investigate',
          message: prompt,
          alert,
          session_id: `auto_${alert.ruleId}_${Date.now()}`,
          _user: 'auto-triage',
          _role: 'system',
        }, { timeout: 180000, validateStatus: () => true });

        const text = r.data?.response || r.data?.output || r.data?.text || '';
        if (!text) continue;

        // ── Step 2: Save investigation ──────────────────────────
        let savedId = null;
        try {
          const saved = await db.saveInvestigation({
            alertId:      alert.id,
            ruleId:       alert.ruleId,
            level:        alert.level,
            severity:     alert.severity,
            agent:        alert.agent,
            srcIp:        alert.srcIp,
            description:  alert.description,
            mitre:        alert.mitre,
            timestamp:    alert.timestamp,
            report:       text,
            user:         'auto-triage',
            autoTriaged:  true,
            durationMs:   Date.now() - start,
            rawAlert:     alert,
          });
          savedId = saved.id;
          triaged++;
          // Notify about auto-triaged investigation
          db.createNotification(
            'alert', 'New Investigation Auto-Triaged',
            `Alert ${alert.ruleId} (${alert.severity}) on ${alert.agent} was auto-investigated.`,
            alert.severity === 'critical' ? 'critical' : 'warning',
            null, { investigation_id: savedId, rule_id: alert.ruleId, agent: alert.agent }
          ).catch(() => {});
        } catch(e) { console.warn('[AutoTriage] DB save failed:', e.message); }

        // ── Step 3: Dark SOC — Triage + Playbook execution ──────
        if (darkSoc !== 'true') continue;

        let fpProbability = 0;
        let triageResult  = null;
        try {
          const triageResp = await axios.post(`${LANGCHAIN_URL}/triage`,
            { alert, model: 'mistral' },
            { timeout: 45000, headers: { Authorization: `Bearer ${LANGCHAIN_TOKEN}` }, validateStatus: () => true }
          );
          if (triageResp.status < 400 && triageResp.data) {
            triageResult   = triageResp.data;
            fpProbability  = triageResult.false_positive_probability || 0;
            console.log(`[DarkSOC] Triage for ${alert.ruleId}: FP=${fpProbability}%, action=${triageResult.recommended_action}`);
          }
        } catch(e) { console.warn('[DarkSOC] Triage call failed:', e.message); }

        // Match and run playbooks
        const matchedPlaybooks = await db.getMatchingPlaybooks(alert.level, alert.mitre || []);
        for (const pb of matchedPlaybooks) {
          console.log(`[DarkSOC] Running playbook "${pb.name}" for alert ${alert.ruleId}`);
          try {
            const execResult = await playbook.runPlaybook(pb, alert, text, fpProbability);
            const outcome    = execResult.skipped ? 'skipped' : 'executed';

            await db.savePlaybookExecution({
              playbookId:        pb.id,
              playbookName:      pb.name,
              investigationId:   savedId,
              alertKey:          `${alert.ruleId}_${alert.timestamp}_${alert.agent}_${alert.srcIp||''}`,
              agent:             alert.agent,
              srcIp:             alert.srcIp,
              ruleId:            alert.ruleId,
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
                `Playbook "${pb.name}" ran on alert ${alert.ruleId} (${alert.agent}).`,
                'warning', null, { playbook_name: pb.name, investigation_id: savedId }
              ).catch(() => {});
            }
          } catch(e) {
            console.error(`[DarkSOC] Playbook "${pb.name}" execution error:`, e.message);
          }
        }
      } catch(e) {
        console.warn(`[AutoTriage] Failed ${alert.ruleId}: ${e.message}`);
      }
    }

    if (triaged > 0) console.log(`[AutoTriage] Investigated ${triaged} new alerts`);
  } catch(e) {
    console.error('[AutoTriage] Error:', e.message);
  } finally {
    _autoTriageRunning = false;
  }
}

// Run auto-triage every 60s (only investigates if enabled in DB)
setInterval(() => { autoTriageWorker(); }, 60000);
// Run once at startup after 30s
setTimeout(() => { autoTriageWorker(); }, 30000);

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
// Checks UEBA graph for new lateral movement chains, auto-creates
// a TheHive case + triggers investigation for each new chain.
// ═══════════════════════════════════════════════════════════════
let _lateralRunning  = false;
const _lateralSeen   = new Set(); // in-memory dedup (resets on restart)

async function lateralMovementMonitor() {
  if (_lateralRunning) return;
  const enabled = await db.getSetting('darksoc_lateral_monitor_enabled').catch(() => 'false');
  if (enabled !== 'true') return;

  _lateralRunning = true;
  try {
    const chains = await ueba.detectLateralMovement(1); // last 1 hour
    const highRisk = chains.filter(c => c.deviation >= 70 || c.hops >= 3);

    for (const chain of highRisk) {
      const key = `${chain.user}|${(chain.dst_hosts||[]).sort().join(',')}`;
      if (_lateralSeen.has(key)) continue;
      _lateralSeen.add(key);

      console.log(`[DarkSOC Lateral] Detected: ${chain.user} → ${(chain.dst_hosts||[]).join(' → ')} (deviation=${chain.deviation})`);

      // Create synthetic alert
      const synAlert = {
        ruleId:      'UEBA-LM',
        level:       14,
        severity:    'critical',
        agent:       chain.src_hosts?.[0] || chain.user,
        srcIp:       '',
        description: `Lateral movement: ${chain.user} accessed ${chain.hops} hosts in 1h`,
        mitre:       ['T1021','T1078','T1550'],
        timestamp:   new Date().toISOString(),
      };

      // Create TheHive case
      await playbook.createHiveCase(synAlert, 'critical',
        `[DarkSOC] Lateral Movement — ${chain.user} (${chain.hops} hops, deviation ${chain.deviation})`
      ).catch(e => console.warn('[DarkSOC Lateral] Case error:', e.message));

      // Trigger n8n investigation
      axios.post(N8N_INV, {
        action: 'investigate',
        message: `Investigate lateral movement: user "${chain.user}" accessed hosts ${(chain.dst_hosts||[]).join(', ')} within 1 hour. Deviation score: ${chain.deviation}. MITRE: T1021, T1078. Determine if this is insider threat or compromised account.`,
        alert: synAlert,
        session_id: `lateral_${Date.now()}`,
        _user: 'dark-soc',
        _role: 'system',
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
    const [assets, stats] = await Promise.all([
      db.listAssets({ status, q }),
      db.getAssetStats(),
    ]);
    res.json({ assets, stats });
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
      } catch(e) {
        console.error(`[SCAN] Job ${job.id} failed:`, e.message);
        await db.finishScanJob(job.id, 0, e.message);
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
    const data = await ueba.getAllAnomalies();
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
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
    const { entity, anomaly_description } = req.body;
    if (!anomaly_description) return res.status(400).json({ error: 'anomaly_description required' });

    // Run RAG retrieval + UEBA profile in parallel
    const [ragResult, uebaProfile] = await Promise.allSettled([
      axios.post(`${RAG_URL}/search/investigation`,
        { query: anomaly_description, limit: 5 },
        { timeout: 15_000, headers: RAG_HEADERS() }
      ),
      entity ? ueba.getUserProfile(entity).catch(() => null) : Promise.resolve(null),
    ]);

    res.json({
      rag_context: ragResult.status === 'fulfilled' ? ragResult.value.data : null,
      ueba_profile: uebaProfile.status === 'fulfilled' ? uebaProfile.value : null,
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/ueba/leaderboard', authMW, async (req, res) => {
  try {
    const users = await ueba.getRiskLeaderboard(parseInt(req.query.limit) || 20);
    res.json({ users });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/ueba/profile/:user', authMW, async (req, res) => {
  try {
    const profile = await ueba.getUserProfile(req.params.user);
    if (!profile) return res.status(404).json({ error: 'User not found in graph' });
    res.json({ profile });
  } catch(e) { res.status(500).json({ error: e.message }); }
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
    const limit     = Math.min(parseInt(req.query.limit) || 50, 200);
    const unreadOnly = req.query.unread === 'true';
    const items = await db.listNotifications(req.user.username, limit, unreadOnly);
    res.json({ notifications: items, total: items.length });
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
    const schedules = await db.listHuntSchedules();
    res.json({ schedules, total: schedules.length });
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
    const schedules = await db.listHuntSchedules();
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

// ─── STATIC (last) ─────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../../frontend')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../../frontend/index.html')));

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
      const schedules = await db.listHuntSchedules();
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

// Initialize DB schema on startup (non-blocking)
db.initSchema()
  .then(() => seedUsersFromEnv())
  .then(() => startHuntScheduler())
  .catch(e => console.error('[DB] init failed:', e.message));
ueba.initSchema().catch(e => console.error('[NEO4J] init failed:', e.message));

app.listen(PORT, '0.0.0.0', () => {
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
