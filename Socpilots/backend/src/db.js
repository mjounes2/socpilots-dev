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

    // Asset Discovery — subnets
    `CREATE TABLE IF NOT EXISTS subnets (
      id         SERIAL PRIMARY KEY,
      cidr       VARCHAR(50) NOT NULL UNIQUE,
      label      VARCHAR(100),
      enabled    BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,

    // Asset Discovery — discovered hosts
    `CREATE TABLE IF NOT EXISTS assets (
      id                  SERIAL PRIMARY KEY,
      ip                  VARCHAR(50) NOT NULL UNIQUE,
      hostname            VARCHAR(255),
      mac                 VARCHAR(20),
      vendor              VARCHAR(100),
      os_guess            VARCHAR(255),
      status              VARCHAR(10) DEFAULT 'online',
      open_ports          JSONB DEFAULT '[]',
      subnet_id           INTEGER REFERENCES subnets(id) ON DELETE SET NULL,
      wazuh_agent_id      VARCHAR(20),
      wazuh_agent_name    VARCHAR(100),
      wazuh_agent_status  VARCHAR(20),
      risk_score          INT DEFAULT 0,
      first_seen          TIMESTAMPTZ DEFAULT NOW(),
      last_seen           TIMESTAMPTZ DEFAULT NOW()
    )`,
    // Add new columns to existing assets table (safe to run repeatedly)
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS vendor             VARCHAR(100)`,
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS wazuh_agent_id     VARCHAR(20)`,
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS wazuh_agent_name   VARCHAR(100)`,
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS wazuh_agent_status VARCHAR(20)`,
    `ALTER TABLE assets ADD COLUMN IF NOT EXISTS risk_score         INT DEFAULT 0`,
    `CREATE INDEX IF NOT EXISTS idx_assets_ip     ON assets(ip)`,
    `CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status)`,

    // Asset Discovery — scan job history
    `CREATE TABLE IF NOT EXISTS scan_jobs (
      id             SERIAL PRIMARY KEY,
      status         VARCHAR(20) DEFAULT 'running',
      started_at     TIMESTAMPTZ DEFAULT NOW(),
      finished_at    TIMESTAMPTZ,
      subnets_scanned TEXT[],
      hosts_found    INTEGER DEFAULT 0,
      started_by     VARCHAR(50),
      error          TEXT
    )`,

    // ── Dark SOC — Automated Playbooks ─────────────────────────
    `CREATE TABLE IF NOT EXISTS playbooks (
      id                    SERIAL PRIMARY KEY,
      name                  VARCHAR(100) NOT NULL,
      description           TEXT,
      mitre_techniques      TEXT[]       DEFAULT '{}',
      min_rule_level        INT          DEFAULT 12,
      threat_score_threshold INT         DEFAULT 70,
      fp_confidence_max     INT          DEFAULT 40,
      actions               JSONB        NOT NULL DEFAULT '[]',
      require_consensus     BOOLEAN      DEFAULT false,
      enabled               BOOLEAN      DEFAULT true,
      created_at            TIMESTAMPTZ  DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_pb_enabled ON playbooks(enabled)`,

    // ── Dark SOC — Playbook Execution Log ──────────────────────
    `CREATE TABLE IF NOT EXISTS playbook_executions (
      id                 SERIAL PRIMARY KEY,
      playbook_id        INT REFERENCES playbooks(id) ON DELETE SET NULL,
      playbook_name      VARCHAR(100),
      investigation_id   INT REFERENCES investigations(id) ON DELETE SET NULL,
      alert_key          VARCHAR(255),
      agent              VARCHAR(100),
      src_ip             VARCHAR(50),
      rule_id            VARCHAR(50),
      severity           VARCHAR(20),
      fp_probability     INT,
      consensus_approved BOOLEAN,
      actions_taken      JSONB    DEFAULT '[]',
      results            JSONB    DEFAULT '[]',
      outcome            VARCHAR(20) DEFAULT 'executed',
      error              TEXT,
      created_at         TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_pe_created   ON playbook_executions(created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_pe_alert_key ON playbook_executions(alert_key)`,

    // ── Protected Assets — hosts that need human approval before isolation ─
    `CREATE TABLE IF NOT EXISTS protected_assets (
      id          SERIAL PRIMARY KEY,
      identifier  VARCHAR(255) NOT NULL UNIQUE,  -- hostname, Wazuh agent name, or IP
      label       VARCHAR(100),                   -- friendly name e.g. "Production DB"
      tier        VARCHAR(20) NOT NULL DEFAULT 'protected',
                  -- 'critical'  → NEVER isolate, block attacker IP + escalate
                  -- 'protected' → require human approval before isolation (30min TTL)
                  -- 'standard'  → auto-isolate as normal (same as not being in this table)
      note        TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_pa_identifier ON protected_assets(identifier)`,

    // ── Isolation Approvals — deferred isolation pending analyst decision ─
    `CREATE TABLE IF NOT EXISTS isolation_approvals (
      id            SERIAL PRIMARY KEY,
      agent         VARCHAR(100) NOT NULL,
      src_ip        VARCHAR(50),
      alert_data    JSONB        NOT NULL DEFAULT '{}',
      playbook_name VARCHAR(100),
      hive_case_id  VARCHAR(50),
      status        VARCHAR(20)  NOT NULL DEFAULT 'pending',
                    -- pending | approved | rejected | expired | executed
      resolved_at   TIMESTAMPTZ,
      resolved_by   VARCHAR(100),
      resolve_note  TEXT,
      expires_at    TIMESTAMPTZ  NOT NULL,
      created_at    TIMESTAMPTZ  DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_ia_status  ON isolation_approvals(status)`,
    `CREATE INDEX IF NOT EXISTS idx_ia_expires ON isolation_approvals(expires_at)`,

    // ── Default Settings for Dark SOC ──────────────────────────
    `INSERT INTO settings(key,value,updated_by) VALUES
      ('darksoc_enabled','false','system'),
      ('darksoc_hunt_enabled','false','system'),
      ('darksoc_lateral_monitor_enabled','false','system'),
      ('isolation_approval_timeout_min','30','system')
     ON CONFLICT(key) DO NOTHING`,

    // ── Seed Default Playbooks (5 built-in) ────────────────────
    `INSERT INTO playbooks(name,description,mitre_techniques,min_rule_level,fp_confidence_max,actions,require_consensus,enabled)
     VALUES
       (
         'Brute Force IP Block',
         'Automatically block the source IP when a brute-force attack is detected.',
         ARRAY['T1110','T1110.001','T1110.003'],
         8, 40,
         '[{"type":"block_ip","duration":3600},{"type":"create_case","severity":"high"}]'::jsonb,
         false, true
       ),
       (
         'RCE Host Isolation',
         'Isolate the endpoint when remote code execution is confirmed. Requires AI consensus.',
         ARRAY['T1059','T1059.001','T1059.003','T1190','T1203'],
         12, 20,
         '[{"type":"isolate_host"},{"type":"create_case","severity":"critical"}]'::jsonb,
         true, true
       ),
       (
         'Malware Process Kill',
         'Kill the malicious process and create a case for tracking.',
         ARRAY['T1204','T1055','T1036','T1053'],
         10, 30,
         '[{"type":"kill_process"},{"type":"create_case","severity":"high"}]'::jsonb,
         false, true
       ),
       (
         'Privilege Escalation Case',
         'Create a high-severity case when privilege escalation is detected.',
         ARRAY['T1068','T1548','T1134','T1078'],
         10, 40,
         '[{"type":"create_case","severity":"high"}]'::jsonb,
         false, true
       ),
       (
         'Auto False-Positive Close',
         'Auto-close alerts where FP probability is very high (≥85%).',
         ARRAY[]::TEXT[],
         0, 85,
         '[{"type":"close_case","reason":"auto_fp_high_confidence"}]'::jsonb,
         false, true
       )
     ON CONFLICT (name) DO NOTHING`,
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

// ── Asset Discovery — Subnets ────────────────────────────
async function listSubnets() {
  const r = await pool.query(`SELECT * FROM subnets ORDER BY id`);
  return r.rows;
}
async function addSubnet(cidr, label) {
  const r = await pool.query(
    `INSERT INTO subnets(cidr, label) VALUES($1,$2) RETURNING *`,
    [cidr.trim(), (label||'').trim()]
  );
  return r.rows[0];
}
async function deleteSubnet(id) {
  await pool.query(`DELETE FROM subnets WHERE id=$1`, [id]);
}

// ── Asset Discovery — Assets ─────────────────────────────
async function listAssets({ status, q, limit=500 } = {}) {
  let where = ['1=1'], params = [];
  if (status) { params.push(status); where.push(`status=$${params.length}`); }
  if (q) { params.push(`%${q}%`); where.push(`(ip ILIKE $${params.length} OR hostname ILIKE $${params.length} OR os_guess ILIKE $${params.length})`); }
  params.push(limit);
  const r = await pool.query(
    `SELECT a.*, s.cidr as subnet_cidr, s.label as subnet_label
     FROM assets a LEFT JOIN subnets s ON a.subnet_id=s.id
     WHERE ${where.join(' AND ')} ORDER BY a.ip LIMIT $${params.length}`,
    params
  );
  return r.rows;
}
async function upsertAsset({ ip, hostname, mac, vendor, os_guess, open_ports, subnet_id,
                             wazuh_agent_id, wazuh_agent_name, wazuh_agent_status }) {
  const r = await pool.query(
    `INSERT INTO assets(ip, hostname, mac, vendor, os_guess, open_ports, subnet_id, status, last_seen)
     VALUES($1,$2,$3,$4,$5,$6,$7,'online',NOW())
     ON CONFLICT(ip) DO UPDATE SET
       hostname=COALESCE(EXCLUDED.hostname, assets.hostname),
       mac=COALESCE(EXCLUDED.mac, assets.mac),
       vendor=COALESCE(EXCLUDED.vendor, assets.vendor),
       os_guess=COALESCE(EXCLUDED.os_guess, assets.os_guess),
       open_ports=EXCLUDED.open_ports, status='online',
       last_seen=NOW(),
       subnet_id=COALESCE(EXCLUDED.subnet_id, assets.subnet_id)
     RETURNING *`,
    [ip, hostname||null, mac||null, vendor||null, os_guess||null,
     JSON.stringify(open_ports||[]), subnet_id||null]
  );
  // Update Wazuh agent info if provided
  if (wazuh_agent_id || wazuh_agent_name) {
    await pool.query(
      `UPDATE assets SET wazuh_agent_id=$1, wazuh_agent_name=$2, wazuh_agent_status=$3 WHERE ip=$4`,
      [wazuh_agent_id||null, wazuh_agent_name||null, wazuh_agent_status||null, ip]
    );
  }
  return r.rows[0];
}

async function bulkUpdateWazuhAgents(agentMap) {
  // agentMap: { [ip]: { id, name, status, os_name? } }
  for (const [ip, agent] of Object.entries(agentMap)) {
    await pool.query(
      `UPDATE assets
       SET wazuh_agent_id=$1, wazuh_agent_name=$2, wazuh_agent_status=$3,
           os_guess=COALESCE(os_guess, NULLIF($5,''))
       WHERE ip=$4`,
      [agent.id, agent.name, agent.status, ip, agent.os_name || '']
    );
  }
}
async function getAssetStats() {
  const r = await pool.query(`
    SELECT
      COUNT(*) AS total,
      COUNT(*) FILTER (WHERE status='online')  AS online,
      COUNT(*) FILTER (WHERE status='offline') AS offline,
      COUNT(*) FILTER (WHERE first_seen > NOW() - INTERVAL '24 hours') AS new_today
    FROM assets
  `);
  return r.rows[0];
}

// ── Asset Discovery — Scan Jobs ──────────────────────────
async function createScanJob(subnets, user) {
  const r = await pool.query(
    `INSERT INTO scan_jobs(subnets_scanned, started_by) VALUES($1,$2) RETURNING *`,
    [subnets, user]
  );
  return r.rows[0];
}
async function finishScanJob(id, hostsFound, error) {
  const r = await pool.query(
    `UPDATE scan_jobs SET status=$1, finished_at=NOW(), hosts_found=$2, error=$3
     WHERE id=$4 RETURNING *`,
    [error ? 'error' : 'done', hostsFound||0, error||null, id]
  );
  return r.rows[0];
}
async function getLatestScanJob() {
  const r = await pool.query(`SELECT * FROM scan_jobs ORDER BY started_at DESC LIMIT 1`);
  return r.rows[0] || null;
}

// ── Dark SOC — Playbooks ─────────────────────────────────────

async function listPlaybooks({ enabledOnly = false } = {}) {
  const where = enabledOnly ? 'WHERE enabled=true' : '';
  const r = await pool.query(`SELECT * FROM playbooks ${where} ORDER BY min_rule_level DESC, id`);
  return r.rows;
}

async function getPlaybookById(id) {
  const r = await pool.query(`SELECT * FROM playbooks WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

async function createPlaybook({ name, description, mitre_techniques, min_rule_level, fp_confidence_max, actions, require_consensus, enabled }) {
  const r = await pool.query(`
    INSERT INTO playbooks(name,description,mitre_techniques,min_rule_level,fp_confidence_max,actions,require_consensus,enabled)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *
  `, [
    name, description || '',
    mitre_techniques || [],
    min_rule_level ?? 12,
    fp_confidence_max ?? 40,
    JSON.stringify(actions || []),
    require_consensus ?? false,
    enabled ?? true,
  ]);
  return r.rows[0];
}

async function updatePlaybook(id, fields) {
  const allowed = ['name','description','mitre_techniques','min_rule_level','fp_confidence_max','actions','require_consensus','enabled'];
  const sets = [], vals = [];
  for (const [k, v] of Object.entries(fields)) {
    if (!allowed.includes(k)) continue;
    vals.push(k === 'actions' ? JSON.stringify(v) : v);
    sets.push(`${k}=$${vals.length}`);
  }
  if (!sets.length) return null;
  vals.push(id);
  const r = await pool.query(
    `UPDATE playbooks SET ${sets.join(',')} WHERE id=$${vals.length} RETURNING *`, vals
  );
  return r.rows[0] || null;
}

async function deletePlaybook(id) {
  await pool.query(`DELETE FROM playbooks WHERE id=$1`, [id]);
}

async function getMatchingPlaybooks(ruleLevel, mitreTechniques = []) {
  const r = await pool.query(
    `SELECT * FROM playbooks WHERE enabled=true AND min_rule_level <= $1 ORDER BY min_rule_level DESC, id`,
    [ruleLevel || 0]
  );
  return r.rows.filter(pb => {
    const pbMitre = pb.mitre_techniques || [];
    if (!pbMitre.length) return true;
    return pbMitre.some(t => (mitreTechniques || []).includes(t));
  });
}

// ── Dark SOC — Playbook Executions ───────────────────────────

async function savePlaybookExecution({ playbookId, playbookName, investigationId, alertKey,
  agent, srcIp, ruleId, severity, fpProbability, consensusApproved, actionsTaken, results, outcome, error }) {
  const r = await pool.query(`
    INSERT INTO playbook_executions(
      playbook_id, playbook_name, investigation_id, alert_key,
      agent, src_ip, rule_id, severity, fp_probability,
      consensus_approved, actions_taken, results, outcome, error
    ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
    RETURNING id, created_at
  `, [
    playbookId || null, playbookName || '', investigationId || null, alertKey || '',
    agent || '', srcIp || '', ruleId || '', severity || '',
    fpProbability ?? null, consensusApproved ?? null,
    JSON.stringify(actionsTaken || []), JSON.stringify(results || []),
    outcome || 'executed', error || null,
  ]);
  return r.rows[0];
}

async function listPlaybookExecutions({ limit = 100, offset = 0 } = {}) {
  const r = await pool.query(
    `SELECT * FROM playbook_executions ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  return r.rows;
}

async function getPlaybookExecStats() {
  const r = await pool.query(`
    SELECT COUNT(*) AS total,
      COUNT(*) FILTER (WHERE outcome='executed') AS executed,
      COUNT(*) FILTER (WHERE outcome='skipped')  AS skipped,
      COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') AS last_24h
    FROM playbook_executions
  `);
  return r.rows[0];
}

// ── Protected Assets ─────────────────────────────────────────

async function listProtectedAssets() {
  const r = await pool.query(`SELECT * FROM protected_assets ORDER BY tier, identifier`);
  return r.rows;
}

// Checks if an agent name / hostname / IP is protected. Returns {tier, label, id} or null.
async function getProtectedAsset(identifier) {
  if (!identifier) return null;
  const r = await pool.query(
    `SELECT * FROM protected_assets WHERE identifier ILIKE $1 LIMIT 1`,
    [identifier.trim()]
  );
  return r.rows[0] || null;
}

async function addProtectedAsset({ identifier, label, tier, note }) {
  const validTiers = ['critical', 'protected', 'standard'];
  const safeTier = validTiers.includes(tier) ? tier : 'protected';
  const r = await pool.query(
    `INSERT INTO protected_assets(identifier, label, tier, note)
     VALUES($1,$2,$3,$4)
     ON CONFLICT(identifier) DO UPDATE SET label=EXCLUDED.label, tier=EXCLUDED.tier, note=EXCLUDED.note
     RETURNING *`,
    [identifier.trim(), label || '', safeTier, note || '']
  );
  return r.rows[0];
}

async function updateProtectedAsset(id, { label, tier, note }) {
  const validTiers = ['critical', 'protected', 'standard'];
  const safeTier = tier && validTiers.includes(tier) ? tier : undefined;
  const sets = [], vals = [];
  if (label !== undefined) { vals.push(label); sets.push(`label=$${vals.length}`); }
  if (safeTier)            { vals.push(safeTier); sets.push(`tier=$${vals.length}`); }
  if (note !== undefined)  { vals.push(note); sets.push(`note=$${vals.length}`); }
  if (!sets.length) return null;
  vals.push(id);
  const r = await pool.query(
    `UPDATE protected_assets SET ${sets.join(',')} WHERE id=$${vals.length} RETURNING *`, vals
  );
  return r.rows[0] || null;
}

async function deleteProtectedAsset(id) {
  await pool.query(`DELETE FROM protected_assets WHERE id=$1`, [id]);
}

// ── Isolation Approvals ───────────────────────────────────────

async function createIsolationApproval({ agent, srcIp, alertData, playbookName, hiveCaseId, timeoutMin = 30 }) {
  const expiresAt = new Date(Date.now() + timeoutMin * 60 * 1000);
  const r = await pool.query(
    `INSERT INTO isolation_approvals(agent, src_ip, alert_data, playbook_name, hive_case_id, status, expires_at)
     VALUES($1,$2,$3,$4,$5,'pending',$6) RETURNING *`,
    [agent, srcIp || '', JSON.stringify(alertData || {}), playbookName || '', hiveCaseId || '', expiresAt]
  );
  return r.rows[0];
}

async function getIsolationApproval(id) {
  const r = await pool.query(`SELECT * FROM isolation_approvals WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

async function listIsolationApprovals({ status } = {}) {
  const where = status ? `WHERE status=$1` : `WHERE status IN ('pending','approved')`;
  const params = status ? [status] : [];
  const r = await pool.query(
    `SELECT * FROM isolation_approvals ${where} ORDER BY created_at DESC LIMIT 50`, params
  );
  return r.rows;
}

async function resolveIsolationApproval(id, { status, resolvedBy, resolveNote }) {
  const validStatuses = ['approved', 'rejected', 'expired', 'executed'];
  if (!validStatuses.includes(status)) throw new Error(`Invalid status: ${status}`);
  const r = await pool.query(
    `UPDATE isolation_approvals
     SET status=$1, resolved_at=NOW(), resolved_by=$2, resolve_note=$3
     WHERE id=$4 RETURNING *`,
    [status, resolvedBy || 'system', resolveNote || '', id]
  );
  return r.rows[0] || null;
}

// Returns all approvals that are still pending but have passed their expiry time
async function listExpiredApprovals() {
  const r = await pool.query(
    `SELECT * FROM isolation_approvals WHERE status='pending' AND expires_at < NOW()`
  );
  return r.rows;
}

// ── Hostname Backfill ─────────────────────────────────────────
// Sets hostname = wazuh_agent_name for any asset that has a linked
// Wazuh agent but a null/empty hostname column. Returns count updated.
async function backfillHostnamesFromAgents() {
  const r = await pool.query(`
    UPDATE assets
    SET hostname = wazuh_agent_name
    WHERE wazuh_agent_name IS NOT NULL
      AND wazuh_agent_name != ''
      AND (hostname IS NULL OR hostname = '')
  `);
  return r.rowCount || 0;
}

// ── Health check ─────────────────────────────────────────────
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
  listSubnets,
  addSubnet,
  deleteSubnet,
  listAssets,
  upsertAsset,
  bulkUpdateWazuhAgents,
  getAssetStats,
  createScanJob,
  finishScanJob,
  getLatestScanJob,
  // Dark SOC — Playbooks
  listPlaybooks,
  getPlaybookById,
  createPlaybook,
  updatePlaybook,
  deletePlaybook,
  getMatchingPlaybooks,
  savePlaybookExecution,
  listPlaybookExecutions,
  getPlaybookExecStats,
  backfillHostnamesFromAgents,
  // Dark SOC — Protected Assets
  listProtectedAssets,
  getProtectedAsset,
  addProtectedAsset,
  updateProtectedAsset,
  deleteProtectedAsset,
  // Dark SOC — Isolation Approvals
  createIsolationApproval,
  getIsolationApproval,
  listIsolationApprovals,
  resolveIsolationApproval,
  listExpiredApprovals,
};
