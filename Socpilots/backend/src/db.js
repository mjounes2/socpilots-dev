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
    // Add tp_status column for True Positive / False Positive tracking
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS tp_status VARCHAR(30) DEFAULT NULL`,
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS tp_marked_by VARCHAR(50)`,
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS tp_marked_at TIMESTAMPTZ`,

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
      ('auto_triage_interval_sec','60','system'),
      ('smtp_enabled','false','system'),
      ('smtp_host','','system'),
      ('smtp_port','587','system'),
      ('smtp_user','','system'),
      ('smtp_password','','system'),
      ('smtp_from_address','','system'),
      ('smtp_use_tls','true','system'),
      ('smtp_use_ssl','false','system'),
      ('smtp_auth_required','false','system'),
      ('smtp_recipients','','system')
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
      name                  VARCHAR(100) NOT NULL UNIQUE,
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
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_pb_name_unique ON playbooks(name)`,
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

    // ── Users table — DB-backed accounts ──────────────────────
    `CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      VARCHAR(50) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      role          VARCHAR(20) NOT NULL DEFAULT 'l1',
      display_name  VARCHAR(100),
      email         VARCHAR(100),
      active        BOOLEAN DEFAULT true,
      last_login    TIMESTAMPTZ,
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      updated_at    TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)`,

    // ── Notifications ──────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS notifications (
      id         SERIAL PRIMARY KEY,
      type       VARCHAR(30) NOT NULL,
      title      VARCHAR(255) NOT NULL,
      message    TEXT,
      severity   VARCHAR(20) DEFAULT 'info',
      read       BOOLEAN DEFAULT false,
      username   VARCHAR(50),
      metadata   JSONB DEFAULT '{}',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_notifications_username ON notifications(username)`,
    `CREATE INDEX IF NOT EXISTS idx_notifications_created  ON notifications(created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_notifications_read     ON notifications(read) WHERE read = false`,

    // ── Password reset tokens ──────────────────────────────────
    `CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash VARCHAR(64) NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at    TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_prt_token_hash ON password_reset_tokens(token_hash)`,
    `CREATE INDEX IF NOT EXISTS idx_prt_user_id    ON password_reset_tokens(user_id)`,

    // ── Chat sessions ───────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS chat_sessions (
      id         SERIAL PRIMARY KEY,
      session_id VARCHAR(100) NOT NULL,
      username   VARCHAR(50) NOT NULL,
      role       VARCHAR(20) DEFAULT 'user',
      content    TEXT NOT NULL,
      metadata   JSONB DEFAULT '{}',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_chat_sessions_session ON chat_sessions(session_id)`,
    `CREATE INDEX IF NOT EXISTS idx_chat_sessions_user    ON chat_sessions(username)`,
    `CREATE INDEX IF NOT EXISTS idx_chat_sessions_created ON chat_sessions(created_at DESC)`,

    // ── Hunt schedules ──────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS hunt_schedules (
      id          SERIAL PRIMARY KEY,
      name        VARCHAR(100) NOT NULL,
      query       TEXT NOT NULL,
      cron_expr   VARCHAR(50) NOT NULL DEFAULT '0 */6 * * *',
      enabled     BOOLEAN DEFAULT true,
      last_run    TIMESTAMPTZ,
      last_result JSONB,
      created_by  VARCHAR(50),
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )`,

    // Evidence files uploaded for AI analysis
    `CREATE TABLE IF NOT EXISTS evidence_files (
      id                SERIAL PRIMARY KEY,
      stored_name       VARCHAR(255) NOT NULL,
      original_name     VARCHAR(255) NOT NULL,
      mime_type         VARCHAR(100),
      file_size         BIGINT,
      sha256            VARCHAR(64),
      uploaded_by       VARCHAR(50),
      alert_id          VARCHAR(100),
      case_id           VARCHAR(100),
      investigation_id  INT REFERENCES investigations(id) ON DELETE SET NULL,
      qdrant_point_ids  JSONB DEFAULT '[]',
      extracted_preview TEXT,
      chunk_count       INT DEFAULT 0,
      scan_status       VARCHAR(20) DEFAULT 'pending',
      scan_result       JSONB,
      created_at        TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_evf_uploaded_by ON evidence_files(uploaded_by)`,
    `CREATE INDEX IF NOT EXISTS idx_evf_sha256      ON evidence_files(sha256)`,
    `CREATE INDEX IF NOT EXISTS idx_evf_case_id     ON evidence_files(case_id)`,
    `CREATE INDEX IF NOT EXISTS idx_evf_created     ON evidence_files(created_at DESC)`,

    // Persistent dedup for UEBA lateral movement cases
    // Prevents re-firing cases on container restart or within the cooldown window
    `CREATE TABLE IF NOT EXISTS lateral_movement_cases (
      id          SERIAL PRIMARY KEY,
      user_key    VARCHAR(255) NOT NULL,
      host_key    TEXT         NOT NULL,
      hive_case   VARCHAR(100),
      created_at  TIMESTAMPTZ  DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_lmc_user_key ON lateral_movement_cases(user_key)`,
    `CREATE INDEX IF NOT EXISTS idx_lmc_created  ON lateral_movement_cases(created_at DESC)`,

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
  await seedDefaultHuntSchedules();
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

// ── SMTP Email Configuration ──────────────────────────────
async function getSmtpSettings() {
  const settings = await getAllSettings();
  return {
    enabled: settings.smtp_enabled === 'true',
    host: settings.smtp_host || '',
    port: parseInt(settings.smtp_port || '587'),
    user: settings.smtp_user || '',
    password: settings.smtp_password || '',
    from_address: settings.smtp_from_address || '',
    use_tls: settings.smtp_use_tls === 'true',
    use_ssl: settings.smtp_use_ssl === 'true',
    auth_required: settings.smtp_auth_required === 'true',
    recipients: (settings.smtp_recipients || '').split(',').map(e => e.trim()).filter(e => e)
  };
}

async function updateSmtpSettings(config, user = 'admin') {
  const updates = {
    'smtp_enabled': String(config.enabled || false),
    'smtp_host': config.host || '',
    'smtp_port': String(config.port || 587),
    'smtp_user': config.user || '',
    'smtp_password': config.password || '',
    'smtp_from_address': config.from_address || '',
    'smtp_use_tls': String(config.use_tls !== false),
    'smtp_use_ssl': String(config.use_ssl === true),
    'smtp_auth_required': String(config.auth_required === true),
    'smtp_recipients': (config.recipients || []).join(',')
  };
  for (const [key, value] of Object.entries(updates)) {
    await setSetting(key, value, user);
  }
  return await getSmtpSettings();
}

// ── Investigation TP/FP Status ────────────────────────────
async function updateInvestigationStatus(investigationId, tp_status, user) {
  const r = await pool.query(`
    UPDATE investigations
    SET tp_status=$1, tp_marked_by=$2, tp_marked_at=NOW()
    WHERE id=$3
    RETURNING id, tp_status, tp_marked_by, tp_marked_at
  `, [tp_status, user, investigationId]);
  return r.rows[0] || null;
}

async function getInvestigationStatus(investigationId) {
  const r = await pool.query(`
    SELECT id, tp_status, tp_marked_by, tp_marked_at FROM investigations WHERE id=$1
  `, [investigationId]);
  return r.rows[0] || null;
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

// ── Users CRUD ───────────────────────────────────────────────
async function createUser(username, passwordHash, role, displayName, email) {
  const r = await pool.query(
    `INSERT INTO users(username, password_hash, role, display_name, email)
     VALUES($1,$2,$3,$4,$5)
     ON CONFLICT(username) DO NOTHING
     RETURNING *`,
    [username, passwordHash, role || 'l1', displayName || null, email || null]
  );
  return r.rows[0] || null;
}

async function getUserByUsername(username) {
  const r = await pool.query(
    `SELECT * FROM users WHERE username=$1 AND active=true`, [username]
  );
  return r.rows[0] || null;
}

async function listUsers() {
  const r = await pool.query(
    `SELECT id, username, role, display_name, email, active, last_login, created_at, updated_at
     FROM users ORDER BY created_at`
  );
  return r.rows;
}

async function updateUser(id, fields) {
  const allowed = ['role', 'display_name', 'email', 'active'];
  const sets = [], vals = [];
  for (const [k, v] of Object.entries(fields)) {
    if (!allowed.includes(k)) continue;
    vals.push(v);
    sets.push(`${k}=$${vals.length}`);
  }
  if (!sets.length) return null;
  sets.push(`updated_at=NOW()`);
  vals.push(id);
  const r = await pool.query(
    `UPDATE users SET ${sets.join(',')} WHERE id=$${vals.length}
     RETURNING id, username, role, display_name, email, active, last_login, created_at, updated_at`,
    vals
  );
  return r.rows[0] || null;
}

async function updateUserPassword(id, passwordHash) {
  const r = await pool.query(
    `UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2 RETURNING id`,
    [passwordHash, id]
  );
  return r.rows[0] || null;
}

async function deleteUser(id) {
  await pool.query(`DELETE FROM users WHERE id=$1`, [id]);
}

async function updateLastLogin(username) {
  await pool.query(
    `UPDATE users SET last_login=NOW() WHERE username=$1`, [username]
  );
}

// ── Notifications CRUD ───────────────────────────────────────
async function createNotification(type, title, message, severity, username, metadata) {
  const r = await pool.query(
    `INSERT INTO notifications(type, title, message, severity, username, metadata)
     VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
    [type, title, message || null, severity || 'info', username || null, JSON.stringify(metadata || {})]
  );
  return r.rows[0];
}

async function listNotifications(username, limit = 50, unreadOnly = false) {
  const params = [username, limit];
  let unreadClause = unreadOnly ? 'AND read=false' : '';
  const r = await pool.query(
    `SELECT * FROM notifications
     WHERE (username=$1 OR username IS NULL) ${unreadClause}
     ORDER BY created_at DESC LIMIT $2`,
    params
  );
  return r.rows;
}

async function markNotificationRead(id, username) {
  const r = await pool.query(
    `UPDATE notifications SET read=true
     WHERE id=$1 AND (username=$2 OR username IS NULL) RETURNING id`,
    [id, username]
  );
  return r.rows[0] || null;
}

async function markAllNotificationsRead(username) {
  const r = await pool.query(
    `UPDATE notifications SET read=true
     WHERE (username=$1 OR username IS NULL) AND read=false`,
    [username]
  );
  return r.rowCount || 0;
}

async function countUnreadNotifications(username) {
  const r = await pool.query(
    `SELECT COUNT(*) AS count FROM notifications
     WHERE (username=$1 OR username IS NULL) AND read=false`,
    [username]
  );
  return parseInt(r.rows[0]?.count || '0');
}

// ── Chat sessions CRUD ───────────────────────────────────────
async function saveChatMessage(sessionId, username, role, content, metadata) {
  const r = await pool.query(
    `INSERT INTO chat_sessions(session_id, username, role, content, metadata)
     VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [sessionId, username, role || 'user', content, JSON.stringify(metadata || {})]
  );
  return r.rows[0];
}

async function getChatHistory(sessionId, limit = 50) {
  const r = await pool.query(
    `SELECT * FROM chat_sessions WHERE session_id=$1
     ORDER BY created_at ASC LIMIT $2`,
    [sessionId, limit]
  );
  return r.rows;
}

async function listUserSessions(username, limit = 20) {
  const r = await pool.query(
    `SELECT session_id,
            MAX(created_at) AS last_message,
            COUNT(*) AS count,
            (ARRAY_AGG(content ORDER BY created_at DESC))[1] AS last_content
     FROM chat_sessions WHERE username=$1
     GROUP BY session_id ORDER BY last_message DESC LIMIT $2`,
    [username, limit]
  );
  return r.rows;
}

async function deleteSession(sessionId, username) {
  const r = await pool.query(
    `DELETE FROM chat_sessions WHERE session_id=$1 AND username=$2`,
    [sessionId, username]
  );
  return r.rowCount || 0;
}

// ── Hunt schedules CRUD ──────────────────────────────────────
async function listHuntSchedules() {
  const r = await pool.query(`SELECT * FROM hunt_schedules ORDER BY id`);
  return r.rows;
}

async function createHuntSchedule(name, query, cronExpr, createdBy) {
  const r = await pool.query(
    `INSERT INTO hunt_schedules(name, query, cron_expr, created_by)
     VALUES($1,$2,$3,$4) RETURNING *`,
    [name, query, cronExpr || '0 */6 * * *', createdBy || 'system']
  );
  return r.rows[0];
}

async function updateHuntSchedule(id, fields) {
  const allowed = ['name', 'query', 'cron_expr', 'enabled'];
  const sets = [], vals = [];
  for (const [k, v] of Object.entries(fields)) {
    if (!allowed.includes(k)) continue;
    vals.push(v);
    sets.push(`${k}=$${vals.length}`);
  }
  if (!sets.length) return null;
  vals.push(id);
  const r = await pool.query(
    `UPDATE hunt_schedules SET ${sets.join(',')} WHERE id=$${vals.length} RETURNING *`, vals
  );
  return r.rows[0] || null;
}

async function updateHuntScheduleResult(id, result) {
  const r = await pool.query(
    `UPDATE hunt_schedules SET last_run=NOW(), last_result=$1 WHERE id=$2 RETURNING *`,
    [JSON.stringify(result || {}), id]
  );
  return r.rows[0] || null;
}

// ── Seed Default Hunt Schedules ──────────────────────────────
async function seedDefaultHuntSchedules() {
  try {
    const count = await pool.query(`SELECT COUNT(*) AS c FROM hunt_schedules`);
    if (parseInt(count.rows[0].c) > 0) return; // already seeded

    const defaults = [
      ['Lateral Movement Detection',   'Find lateral movement in the last 24 hours',                                                          '0 */6 * * *'],
      ['Abnormal Authentication',      'Detect abnormal authentication patterns and failed logins',                                           '0 */4 * * *'],
      ['Ransomware Indicators',        'Hunt for ransomware indicators including shadow copy deletion and mass file encryption',               '0 8 * * *'],
      ['C2 Beaconing',                 'Identify command and control beaconing patterns and DNS tunneling',                                   '0 */12 * * *'],
      ['Privilege Escalation Hunt',    'Find privilege escalation attempts and suspicious sudo usage',                                        '0 6 * * *'],
    ];

    for (const [name, query, cron_expr] of defaults) {
      await pool.query(
        `INSERT INTO hunt_schedules(name, query, cron_expr, created_by)
         VALUES($1,$2,$3,'system') ON CONFLICT DO NOTHING`,
        [name, query, cron_expr]
      );
    }
    console.log('[DB] Default hunt schedules seeded');
  } catch(e) {
    console.error('[DB] seedDefaultHuntSchedules error:', e.message);
  }
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
  getSmtpSettings,
  updateSmtpSettings,
  updateInvestigationStatus,
  getInvestigationStatus,
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
  // Users CRUD
  createUser,
  getUserByUsername,
  listUsers,
  updateUser,
  updateUserPassword,
  deleteUser,
  updateLastLogin,
  // Notifications CRUD
  createNotification,
  listNotifications,
  markNotificationRead,
  markAllNotificationsRead,
  countUnreadNotifications,
  // Chat sessions CRUD
  saveChatMessage,
  getChatHistory,
  listUserSessions,
  deleteSession,
  // Hunt schedules CRUD
  listHuntSchedules,
  createHuntSchedule,
  updateHuntSchedule,
  updateHuntScheduleResult,
  // Evidence files CRUD
  createEvidenceFile,
  updateEvidenceFile,
  listEvidenceFiles,
  getEvidenceFile,
  deleteEvidenceFile,
  // Lateral movement dedup
  getLateralCaseAge,
  recordLateralCase,
  // Password reset
  createPasswordResetToken,
  getPasswordResetToken,
  invalidatePasswordResetToken,
};

// ── Evidence Files CRUD ──────────────────────────────────

async function createEvidenceFile({ storedName, originalName, mimeType, fileSize, sha256, uploadedBy, alertId, caseId, investigationId }) {
  const r = await pool.query(
    `INSERT INTO evidence_files
       (stored_name, original_name, mime_type, file_size, sha256, uploaded_by,
        alert_id, case_id, investigation_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     RETURNING *`,
    [storedName, originalName, mimeType || null, fileSize || 0, sha256 || null,
     uploadedBy || null, alertId || null, caseId || null, investigationId || null]
  );
  return r.rows[0];
}

async function updateEvidenceFile(id, fields) {
  const allowed = ['qdrant_point_ids','extracted_preview','chunk_count','scan_status','scan_result','sha256'];
  const sets = [];
  const vals = [];
  for (const [k, v] of Object.entries(fields)) {
    if (allowed.includes(k)) {
      vals.push(typeof v === 'object' && v !== null ? JSON.stringify(v) : v);
      sets.push(`${k}=$${vals.length}`);
    }
  }
  if (!sets.length) return null;
  vals.push(id);
  const r = await pool.query(
    `UPDATE evidence_files SET ${sets.join(',')} WHERE id=$${vals.length} RETURNING *`,
    vals
  );
  return r.rows[0];
}

async function listEvidenceFiles({ limit = 50, offset = 0, uploadedBy, caseId, alertId } = {}) {
  let where = ['1=1'];
  const vals = [];
  if (uploadedBy) { vals.push(uploadedBy); where.push(`uploaded_by=$${vals.length}`); }
  if (caseId)     { vals.push(caseId);     where.push(`case_id=$${vals.length}`); }
  if (alertId)    { vals.push(alertId);    where.push(`alert_id=$${vals.length}`); }
  vals.push(limit, offset);
  const r = await pool.query(
    `SELECT * FROM evidence_files WHERE ${where.join(' AND ')}
     ORDER BY created_at DESC LIMIT $${vals.length-1} OFFSET $${vals.length}`,
    vals
  );
  return r.rows;
}

async function getEvidenceFile(id) {
  const r = await pool.query(`SELECT * FROM evidence_files WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

async function deleteEvidenceFile(id) {
  const r = await pool.query(`DELETE FROM evidence_files WHERE id=$1 RETURNING *`, [id]);
  return r.rows[0] || null;
}

// ── Password Reset Tokens ───────────────────────────────────
async function createPasswordResetToken(userId, tokenHash, expiresAt) {
  // Invalidate any existing unused tokens for this user first
  await pool.query(
    `UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL`,
    [userId]
  );
  const r = await pool.query(
    `INSERT INTO password_reset_tokens(user_id, token_hash, expires_at)
     VALUES($1,$2,$3) RETURNING *`,
    [userId, tokenHash, expiresAt]
  );
  return r.rows[0];
}

async function getPasswordResetToken(tokenHash) {
  const r = await pool.query(
    `SELECT t.*, u.username, u.email FROM password_reset_tokens t
     JOIN users u ON u.id = t.user_id
     WHERE t.token_hash=$1 AND t.used_at IS NULL AND t.expires_at > NOW()`,
    [tokenHash]
  );
  return r.rows[0] || null;
}

async function invalidatePasswordResetToken(tokenHash) {
  await pool.query(
    `UPDATE password_reset_tokens SET used_at=NOW() WHERE token_hash=$1`,
    [tokenHash]
  );
}

// ── Lateral Movement Dedup ───────────────────────────────────

// Returns hours since last case for this user, or null if never seen
async function getLateralCaseAge(userKey) {
  const r = await pool.query(
    `SELECT EXTRACT(EPOCH FROM (NOW() - created_at)) / 3600 AS hours_ago
     FROM lateral_movement_cases
     WHERE user_key = $1
     ORDER BY created_at DESC LIMIT 1`,
    [userKey]
  );
  if (!r.rows.length) return null;
  return parseFloat(r.rows[0].hours_ago);
}

async function recordLateralCase(userKey, hostKey, hiveCaseId) {
  await pool.query(
    `INSERT INTO lateral_movement_cases(user_key, host_key, hive_case) VALUES($1,$2,$3)`,
    [userKey, hostKey, hiveCaseId || null]
  );
}
