// ============================================================
// SOC PILOTS — Production Backend
// OpenSearch (Wazuh) + SP-CM (direct) + n8n (AI/Hunt/Rules)
// ============================================================
const express = require('express');
const axios   = require('axios');
const https   = require('https');
const crypto  = require('crypto');
const path    = require('path');
require('dotenv').config({ path: path.join(__dirname, '../../.env') });
const db    = require('./db');
const ueba  = require('./neo4j');

const app  = express();
const PORT = process.env.PORT || 3000;
app.use(express.json({ limit: '10mb' }));

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
const LANGCHAIN_TOKEN   = process.env.LANGCHAIN_INTERNAL_TOKEN || '';

// Skip SSL verify (Wazuh self-signed cert)
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// ─── AUTH ──────────────────────────────────────────────────
const USERS = (process.env.SOC_USERS || '')
  .split(',').map(u => {
    const [username, password, role = 'analyst'] = u.trim().split(':');
    return { username, password, role };
  }).filter(u => u.username && u.password);

const sessions = new Map();
function mkToken(username, role) {
  const t = crypto.randomBytes(32).toString('hex');
  sessions.set(t, { username, role, exp: Date.now() + 8 * 3600 * 1000 });
  return t;
}
function authMW(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '').trim();
  const s = sessions.get(t);
  if (!s || s.exp < Date.now()) { sessions.delete(t); return res.status(401).json({ error: 'Unauthorized' }); }
  req.user = s; next();
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
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS.find(u =>
    u.username.toLowerCase() === (username || '').toLowerCase().trim() &&
    u.password === password
  );
  if (!u) return res.status(401).json({ error: 'Invalid username or password' });
  const token = mkToken(u.username, u.role);
  console.log(`[LOGIN] ${u.username}`);
  res.json({ token, username: u.username, role: u.role });
});

app.post('/api/logout', authMW, (req, res) => {
  sessions.delete((req.headers.authorization || '').replace('Bearer ', '').trim());
  res.json({ success: true });
});

app.get('/api/me', authMW, (req, res) => res.json(req.user));

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
    // Run 5 queries in parallel
    const [totalAlerts, critAlerts, last24h, agentAgg, hiveCases] = await Promise.allSettled([
      // Total alerts count
      osCount({ query: { match_all: {} } }),
      // Critical alerts (level >= 12)
      osCount({ query: { range: { 'rule.level': { gte: 12 } } } }),
      // Last 24h
      osCount({ query: { range: { '@timestamp': { gte: 'now-24h' } } } }),
      // Unique agents
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
            date_histogram: { field: '@timestamp', calendar_interval: 'hour', min_doc_count: 0,
              extended_bounds: { min: 'now-24h', max: 'now' }
            },
            aggs: {
              critical: { filter: { range: { 'rule.level': { gte: 12 } } } },
              high:     { filter: { range: { 'rule.level': { gte: 8, lt: 12 } } } },
              medium:   { filter: { range: { 'rule.level': { gte: 5, lt: 8  } } } },
              low:      { filter: { range: { 'rule.level': { lt: 5 } } } },
            }
          }
        },
        query: { range: { '@timestamp': { gte: 'now-24h' } } }
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
      totalAlerts:    totalAlerts.value || 0,
      alerts24h:      last24h.value || 0,
      criticalAlerts: critAlerts.value || 0,
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
      }
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
    const agent  = req.query.agent;
    const srcip  = req.query.srcip;

    const must = [];
    if (hours)  must.push({ range: { '@timestamp': { gte: `now-${hours}h` } } });
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

  // Then ask AI for analysis
  let aiAnalysis = '';
  try {
    const r = await n8nAsk(
      `Threat hunt analysis for ${type}: "${value}". ` +
      `OpenSearch found ${osResults.length} matching alerts. ` +
      `Provide: risk assessment, MITRE mapping, recommended response actions, and IOC context.`,
      'soc-hunt', req.user
    );
    aiAnalysis = r.text;
  } catch (e) { aiAnalysis = 'AI analysis unavailable'; }

  res.json({ osResults, osTotal: osResults.length, aiAnalysis });
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
  const r = await n8nAsk(message, session_id || `soc_${req.user.username}`, req.user, {
    history: (history || []).slice(-6), // reduced from 10 to 6
  });
  if (!r.ok) {
    const errMsg = r.error || 'SOCPilots AI unavailable';
    return res.status(r.error?.includes('Rate limit') ? 429 : 502).json({ error: errMsg });
  }
  res.json(r.raw || { response: r.text });
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
        const start = Date.now();
        const prompt = `Auto-investigate this alert. Provide concise analysis with executive summary, MITRE mapping, risk assessment, and recommended actions.

Alert:
- Timestamp: ${alert.timestamp}
- Rule: ${alert.ruleId} (level ${alert.level})
- Description: ${alert.description}
- Agent: ${alert.agent}
- Source IP: ${alert.srcIp}
- MITRE: ${(alert.mitre||[]).join(', ')}

Use markdown tables. Be concise.`;

        const r = await axios.post(N8N_INV, {
          action: 'investigate',
          message: prompt,
          alert,
          session_id: `auto_${alert.ruleId}_${Date.now()}`,
          _user: 'auto-triage',
          _role: 'system',
        }, { timeout: 180000, validateStatus: () => true });

        const text = r.data?.response || r.data?.output || r.data?.text || '';
        if (text) {
          await db.saveInvestigation({
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
          triaged++;
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
            id:   { terms: { field: 'agent.id', size: 1 } },
            ip:   { terms: { field: 'agent.ip', size: 1 } },
            last: { max: { field: '@timestamp' } },
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
      map[agentIp] = { id: b.id?.buckets?.[0]?.key || '', name: b.key, status };
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
    res.json({ ok: true, agents_synced: Object.keys(agentMap).length });
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
          await db.upsertAsset({
            ...host,
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

// ─── STATIC (last) ─────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../../frontend')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../../frontend/index.html')));

// Initialize DB schema on startup (non-blocking)
db.initSchema().catch(e => console.error('[DB] init failed:', e.message));
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
  USERS.forEach(u => console.log(`  USER: ${u.username} / ${u.role}`));
});

module.exports = app;
