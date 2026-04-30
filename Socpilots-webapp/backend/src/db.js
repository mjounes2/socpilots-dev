// ============================================================
//  SOCPilots — PostgreSQL Database Layer
//  Stores investigation reports, artifacts, audit logs
// ============================================================
const { Pool } = require('pg');

const pool = new Pool({
  host:     process.env.PG_HOST     || 'postgres',
  port:     parseInt(process.env.PG_PORT     || '5432'),
  database: process.env.PG_DATABASE || 'socpilots',
  user:     process.env.PG_USER     || 'socpilots',
  password: process.env.PG_PASSWORD || 'socpilots_2024',
  max:      10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('[DB] Unexpected pool error:', err.message);
});

// ── Initialize schema on startup ─────────────────────────
async function initSchema() {
  const queries = [
    // Investigations table
    `CREATE TABLE IF NOT EXISTS investigations (
      id           SERIAL PRIMARY KEY,
      alert_key    VARCHAR(255) NOT NULL,
      alert_id     VARCHAR(100),
      rule_id      VARCHAR(50),
      rule_level   INT,
      severity     VARCHAR(20),
      agent        VARCHAR(100),
      src_ip       VARCHAR(50),
      description  TEXT,
      mitre        TEXT,
      timestamp    TIMESTAMPTZ,
      report       TEXT,
      report_short TEXT,
      created_by   VARCHAR(50),
      auto_triaged BOOLEAN DEFAULT false,
      duration_ms  INT,
      created_at   TIMESTAMPTZ DEFAULT NOW(),
      raw_alert    JSONB
    )`,
    `CREATE INDEX IF NOT EXISTS idx_inv_alert_key ON investigations(alert_key)`,
    `CREATE INDEX IF NOT EXISTS idx_inv_created   ON investigations(created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_inv_rule      ON investigations(rule_id)`,
    `CREATE INDEX IF NOT EXISTS idx_inv_severity  ON investigations(severity)`,
    `CREATE INDEX IF NOT EXISTS idx_inv_agent     ON investigations(agent)`,

    // Artifacts (IOCs extracted from investigations)
    `CREATE TABLE IF NOT EXISTS artifacts (
      id              SERIAL PRIMARY KEY,
      investigation_id INT REFERENCES investigations(id) ON DELETE CASCADE,
      artifact_type   VARCHAR(20),
      value           VARCHAR(500),
      threat_score    INT,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_art_value ON artifacts(value)`,
    `CREATE INDEX IF NOT EXISTS idx_art_type  ON artifacts(artifact_type)`,

    // Settings (auto-triage toggle, config)
    `CREATE TABLE IF NOT EXISTS settings (
      key        VARCHAR(50) PRIMARY KEY,
      value      TEXT,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      updated_by VARCHAR(50)
    )`,

    // Default settings
    `INSERT INTO settings(key,value,updated_by) VALUES
      ('auto_triage_enabled','false','system'),
      ('auto_triage_min_level','12','system'),
      ('auto_triage_interval_sec','60','system')
     ON CONFLICT(key) DO NOTHING`,
  ];

  for (const q of queries) {
    try { await pool.query(q); }
    catch(e) { console.error('[DB] Schema error:', e.message, q.slice(0,60)); }
  }
  console.log('[DB] Schema initialized');
}

// ── Investigations CRUD ──────────────────────────────────
async function saveInvestigation(data) {
  const q = `INSERT INTO investigations
    (alert_key, alert_id, rule_id, rule_level, severity, agent, src_ip,
     description, mitre, timestamp, report, report_short, created_by,
     auto_triaged, duration_ms, raw_alert)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
    RETURNING id, created_at`;

  const alertKey = `${data.ruleId}_${data.timestamp}_${data.agent}_${data.srcIp||''}`;
  const reportShort = (data.report || '').slice(0, 300);

  const vals = [
    alertKey,
    data.alertId || null,
    data.ruleId || null,
    parseInt(data.level) || 0,
    data.severity || 'unknown',
    data.agent || null,
    data.srcIp || null,
    (data.description || '').slice(0, 1000),
    JSON.stringify(data.mitre || []),
    data.timestamp ? new Date(data.timestamp) : new Date(),
    data.report || '',
    reportShort,
    data.user || 'system',
    data.autoTriaged || false,
    data.durationMs || 0,
    JSON.stringify(data.rawAlert || {}),
  ];

  const r = await pool.query(q, vals);
  return r.rows[0];
}

async function getInvestigationByAlertKey(alertKey) {
  const r = await pool.query(
    `SELECT * FROM investigations WHERE alert_key=$1 ORDER BY created_at DESC LIMIT 1`,
    [alertKey]
  );
  return r.rows[0] || null;
}

async function listInvestigations({ limit=100, offset=0, severity, agent, ruleId, q } = {}) {
  let where = ['1=1'];
  let params = [];
  if (severity) { params.push(severity); where.push(`severity=$${params.length}`); }
  if (agent)    { params.push(agent);    where.push(`agent=$${params.length}`); }
  if (ruleId)   { params.push(ruleId);   where.push(`rule_id=$${params.length}`); }
  if (q) {
    params.push(`%${q}%`);
    where.push(`(description ILIKE $${params.length} OR src_ip ILIKE $${params.length} OR report_short ILIKE $${params.length})`);
  }
  params.push(limit, offset);
  const sql = `SELECT id, alert_key, rule_id, rule_level, severity, agent, src_ip,
    description, mitre, timestamp, report_short, created_by, auto_triaged,
    duration_ms, created_at FROM investigations
    WHERE ${where.join(' AND ')}
    ORDER BY created_at DESC LIMIT $${params.length-1} OFFSET $${params.length}`;
  const r = await pool.query(sql, params);
  return r.rows;
}

async function getInvestigationById(id) {
  const r = await pool.query(`SELECT * FROM investigations WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

async function getInvestigationStats() {
  const r = await pool.query(`
    SELECT
      COUNT(*)                                        AS total,
      COUNT(*) FILTER (WHERE auto_triaged=true)       AS auto_triaged,
      COUNT(*) FILTER (WHERE severity='critical')     AS critical,
      COUNT(*) FILTER (WHERE severity='high')         AS high,
      COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS last_24h,
      AVG(duration_ms)::INT                           AS avg_duration_ms
    FROM investigations
  `);
  return r.rows[0];
}

async function getInvestigatedAlertKeys() {
  const r = await pool.query(`
    SELECT DISTINCT alert_key FROM investigations
    ORDER BY alert_key
  `);
  return r.rows.map(x => x.alert_key);
}

// ── Settings ─────────────────────────────────────────────
async function getSetting(key) {
  const r = await pool.query(`SELECT value FROM settings WHERE key=$1`, [key]);
  return r.rows[0]?.value || null;
}

async function setSetting(key, value, user) {
  await pool.query(`
    INSERT INTO settings(key,value,updated_by,updated_at)
    VALUES($1,$2,$3,NOW())
    ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, updated_by=EXCLUDED.updated_by, updated_at=NOW()
  `, [key, String(value), user || 'system']);
}

async function getAllSettings() {
  const r = await pool.query(`SELECT key, value, updated_at, updated_by FROM settings`);
  const out = {};
  r.rows.forEach(row => out[row.key] = row.value);
  return out;
}

// ── Artifacts ────────────────────────────────────────────
async function saveArtifacts(investigationId, artifacts) {
  if (!artifacts?.length) return;
  for (const art of artifacts) {
    try {
      await pool.query(
        `INSERT INTO artifacts(investigation_id, artifact_type, value, threat_score) VALUES($1,$2,$3,$4)`,
        [investigationId, art.type, art.value, art.score || null]
      );
    } catch(e) { /* skip duplicates */ }
  }
}

// ── Health check ─────────────────────────────────────────
async function ping() {
  try {
    await pool.query('SELECT 1');
    return true;
  } catch { return false; }
}

module.exports = {
  pool,
  initSchema,
  saveInvestigation,
  getInvestigationByAlertKey,
  getInvestigationById,
  listInvestigations,
  getInvestigationStats,
  getInvestigatedAlertKeys,
  getSetting,
  setSetting,
  getAllSettings,
  saveArtifacts,
  ping,
};
