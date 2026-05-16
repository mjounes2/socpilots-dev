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
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS hive_case_id VARCHAR(50)`,

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

    // ── System Events (auth, settings, scans, errors) ─────────
    `CREATE TABLE IF NOT EXISTS system_events (
      id          SERIAL PRIMARY KEY,
      event_type  VARCHAR(30) NOT NULL,
      actor       VARCHAR(100),
      description TEXT NOT NULL,
      status      VARCHAR(20) DEFAULT 'ok',
      metadata    JSONB DEFAULT '{}',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_se_created ON system_events(created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_se_type    ON system_events(event_type)`,

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

    // ── Alert deduplication groups ──────────────────────────────
    `CREATE TABLE IF NOT EXISTS alert_groups (
      id          SERIAL PRIMARY KEY,
      src_ip      VARCHAR(50),
      rule_id     VARCHAR(50),
      agent       VARCHAR(100),
      count       INT DEFAULT 1,
      first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      window_end  TIMESTAMPTZ NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS idx_ag_lookup ON alert_groups(src_ip, rule_id, window_end)`,

    // ── OTX AlienVault IOC Feed ─────────────────────────────────
    `CREATE TABLE IF NOT EXISTS otx_ioc_feed (
      id               SERIAL PRIMARY KEY,
      pulse_id         VARCHAR(100) NOT NULL,
      pulse_name       TEXT         NOT NULL,
      indicator_type   VARCHAR(50)  NOT NULL,
      indicator        VARCHAR(500) NOT NULL,
      description      TEXT,
      tags             TEXT[]       DEFAULT '{}',
      malware_families TEXT[]       DEFAULT '{}',
      threat_score     INT          DEFAULT 50,
      fetched_at       TIMESTAMPTZ  DEFAULT NOW(),
      UNIQUE(pulse_id, indicator)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_otx_indicator ON otx_ioc_feed(indicator)`,
    `CREATE INDEX IF NOT EXISTS idx_otx_type      ON otx_ioc_feed(indicator_type)`,
    `CREATE INDEX IF NOT EXISTS idx_otx_fetched   ON otx_ioc_feed(fetched_at DESC)`,

    // Add composite_risk and group_id to investigations
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS composite_risk INT`,
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS group_id INT REFERENCES alert_groups(id)`,

    // ── Investigation Feedback ─────────────────────────────────
    `CREATE TABLE IF NOT EXISTS investigation_feedback (
      id                SERIAL PRIMARY KEY,
      investigation_id  INTEGER REFERENCES investigations(id) ON DELETE CASCADE,
      username          TEXT NOT NULL,
      rating            SMALLINT NOT NULL CHECK (rating IN (-1, 1)),
      comment           TEXT,
      created_at        TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(investigation_id, username)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_inv_feedback_inv ON investigation_feedback(investigation_id)`,

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

    // ── UEBA Weekly Digests ────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS ueba_digests (
      id               SERIAL PRIMARY KEY,
      generated_at     TIMESTAMPTZ DEFAULT NOW(),
      period_start     TIMESTAMPTZ,
      period_end       TIMESTAMPTZ,
      digest_md        TEXT,
      digest_type      VARCHAR(20) DEFAULT 'weekly',
      entity_count     INT DEFAULT 0,
      high_risk_count  INT DEFAULT 0,
      top_entities     JSONB,
      success          BOOL DEFAULT true,
      error            TEXT,
      emailed          BOOL DEFAULT false
    )`,
    `CREATE INDEX IF NOT EXISTS idx_ueba_digests_at ON ueba_digests(generated_at DESC)`,

    // ── Triage Queue ───────────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS triage_queue (
      id               SERIAL PRIMARY KEY,
      alert_id         TEXT NOT NULL,
      alert_key        VARCHAR(255) NOT NULL,
      rule_id          TEXT,
      rule_level       INT DEFAULT 0,
      severity         TEXT,
      triage_tier      TEXT,
      agent            TEXT,
      src_ip           TEXT,
      description      TEXT,
      mitre            TEXT[],
      full_log         TEXT,
      alert_timestamp  TIMESTAMPTZ,
      priority_score   NUMERIC(6,2) DEFAULT 0,
      status           TEXT DEFAULT 'pending',
      claimed_at       TIMESTAMPTZ,
      queued_at        TIMESTAMPTZ DEFAULT NOW(),
      processed_at     TIMESTAMPTZ,
      investigation_id INTEGER REFERENCES investigations(id),
      error_msg        TEXT,
      notified         BOOLEAN DEFAULT false,
      raw_alert        JSONB,
      UNIQUE(alert_key)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_tq_claim  ON triage_queue(status, priority_score DESC, queued_at)`,
    `CREATE INDEX IF NOT EXISTS idx_tq_tier   ON triage_queue(triage_tier, status)`,
    `CREATE INDEX IF NOT EXISTS idx_tq_queued ON triage_queue(queued_at DESC)`,

    // triage_tier + structured_verdict on investigations
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS triage_tier VARCHAR(20)`,
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS structured_verdict JSONB`,
    // deep mode flag + extracted verdict/confidence for quick filtering
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS deep_mode BOOLEAN DEFAULT false`,
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS verdict VARCHAR(30)`,
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS confidence_score INT`,
    `ALTER TABLE investigations ADD COLUMN IF NOT EXISTS fp_probability INT`,

    // ── AI-generated Draft Detection Rules ────────────────────────
    `CREATE TABLE IF NOT EXISTS draft_rules (
      id               SERIAL PRIMARY KEY,
      investigation_id INT REFERENCES investigations(id) ON DELETE CASCADE,
      rule_id          TEXT,
      agent            TEXT,
      severity         TEXT,
      description      TEXT,
      mitre_techniques TEXT[] DEFAULT '{}',
      wazuh_xml        TEXT,
      sigma_yaml       TEXT,
      status           TEXT DEFAULT 'pending_review',
      generated_by     TEXT DEFAULT 'ai',
      created_at       TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_draft_rules_inv ON draft_rules(investigation_id)`,
    `CREATE INDEX IF NOT EXISTS idx_draft_rules_status ON draft_rules(status)`,

    // ── UEBA-triggered playbooks threshold ────────────────────────
    `ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS ueba_risk_min INTEGER DEFAULT NULL`,

    // ── Alert Suppression Engine ───────────────────────────────────
    `CREATE TABLE IF NOT EXISTS alert_suppressions (
      id              SERIAL PRIMARY KEY,
      name            VARCHAR(100) NOT NULL,
      description     TEXT,
      rule_id         TEXT DEFAULT NULL,
      agent_pattern   TEXT DEFAULT NULL,
      src_ip_pattern  TEXT DEFAULT NULL,
      min_level       INT  DEFAULT NULL,
      max_level       INT  DEFAULT NULL,
      expires_at      TIMESTAMPTZ DEFAULT NULL,
      hit_count       BIGINT DEFAULT 0,
      last_hit_at     TIMESTAMPTZ DEFAULT NULL,
      created_by      TEXT DEFAULT NULL,
      enabled         BOOLEAN DEFAULT true,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_supp_enabled ON alert_suppressions(enabled)`,
    `CREATE INDEX IF NOT EXISTS idx_supp_expires ON alert_suppressions(expires_at)`,

    // ── Action Approvals (human-in-the-loop gate for destructive actions) ──
    `CREATE TABLE IF NOT EXISTS action_approvals (
      id               SERIAL PRIMARY KEY,
      investigation_id INTEGER REFERENCES investigations(id) ON DELETE CASCADE,
      alert_key        VARCHAR(255),
      rule_id          TEXT,
      agent            TEXT,
      src_ip           TEXT,
      severity         TEXT,
      triage_tier      TEXT,
      verdict          TEXT,
      confidence       INT DEFAULT 0,
      risk_score       INT DEFAULT 0,
      fp_probability   NUMERIC(5,2) DEFAULT 0,
      summary          TEXT,
      recommended_actions TEXT[],
      playbook_ids     INTEGER[],
      alert_data       JSONB,
      status           TEXT DEFAULT 'pending',
      resolved_at      TIMESTAMPTZ,
      resolved_by      TEXT,
      resolve_note     TEXT,
      expires_at       TIMESTAMPTZ NOT NULL,
      created_at       TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_aa_status  ON action_approvals(status)`,
    `CREATE INDEX IF NOT EXISTS idx_aa_expires ON action_approvals(expires_at)`,
    `CREATE INDEX IF NOT EXISTS idx_aa_inv     ON action_approvals(investigation_id)`,
    // Log Source Onboarding History
    `CREATE TABLE IF NOT EXISTS log_source_history (
      id           SERIAL PRIMARY KEY,
      source_id    TEXT NOT NULL UNIQUE,
      source_name  TEXT NOT NULL,
      source_ip    TEXT,
      vendor       TEXT,
      type         TEXT,
      protocol     TEXT,
      integration  TEXT,
      top_decoder  TEXT,
      top_groups   TEXT[],
      notified     BOOLEAN DEFAULT FALSE,
      first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_lsh_first_seen ON log_source_history(first_seen DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_lsh_notified   ON log_source_history(notified)`,

    // ── Artifacts & IOC Intelligence ─────────────────────────────
    `CREATE TABLE IF NOT EXISTS ioc_store (
      id               SERIAL PRIMARY KEY,
      indicator        TEXT NOT NULL,
      ioc_type         VARCHAR(50) NOT NULL,
      reputation       VARCHAR(20) DEFAULT 'unknown',
      confidence       INT DEFAULT 0,
      risk_score       INT DEFAULT 0,
      source           VARCHAR(100) DEFAULT 'manual',
      source_ref       TEXT,
      tags             TEXT[] DEFAULT '{}',
      notes            TEXT,
      mitre_techniques TEXT[] DEFAULT '{}',
      threat_actors    TEXT[] DEFAULT '{}',
      malware_families TEXT[] DEFAULT '{}',
      is_whitelisted   BOOLEAN DEFAULT FALSE,
      enriched_at      TIMESTAMPTZ,
      first_seen       TIMESTAMPTZ DEFAULT NOW(),
      last_seen        TIMESTAMPTZ DEFAULT NOW(),
      created_by       TEXT,
      created_at       TIMESTAMPTZ DEFAULT NOW(),
      updated_at       TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(indicator, ioc_type)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_ioc_indicator   ON ioc_store(indicator)`,
    `CREATE INDEX IF NOT EXISTS idx_ioc_type        ON ioc_store(ioc_type)`,
    `CREATE INDEX IF NOT EXISTS idx_ioc_reputation  ON ioc_store(reputation)`,
    `CREATE INDEX IF NOT EXISTS idx_ioc_risk        ON ioc_store(risk_score DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_ioc_last_seen   ON ioc_store(last_seen DESC)`,
    `CREATE TABLE IF NOT EXISTS ioc_enrichments (
      id         SERIAL PRIMARY KEY,
      ioc_id     INT REFERENCES ioc_store(id) ON DELETE CASCADE,
      source     VARCHAR(50) NOT NULL,
      result     JSONB,
      status     VARCHAR(20) DEFAULT 'pending',
      error      TEXT,
      fetched_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(ioc_id, source)
    )`,
    `CREATE TABLE IF NOT EXISTS ioc_relations (
      id           SERIAL PRIMARY KEY,
      ioc_id       INT REFERENCES ioc_store(id) ON DELETE CASCADE,
      entity_type  VARCHAR(50) NOT NULL,
      entity_id    TEXT NOT NULL,
      entity_label TEXT,
      rel_type     VARCHAR(50) DEFAULT 'observed_in',
      created_at   TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(ioc_id, entity_type, entity_id)
    )`,
    `CREATE TABLE IF NOT EXISTS ioc_whitelist (
      id           SERIAL PRIMARY KEY,
      indicator    TEXT NOT NULL,
      ioc_type     VARCHAR(50) NOT NULL,
      category     VARCHAR(50) NOT NULL,
      reason       TEXT,
      added_by     TEXT,
      approved_by  TEXT,
      expires_at   TIMESTAMPTZ,
      enabled      BOOLEAN DEFAULT TRUE,
      risk_warning TEXT,
      created_at   TIMESTAMPTZ DEFAULT NOW(),
      updated_at   TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(indicator, ioc_type)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_wl_indicator ON ioc_whitelist(indicator)`,
    `CREATE INDEX IF NOT EXISTS idx_wl_enabled   ON ioc_whitelist(enabled)`,
    `CREATE TABLE IF NOT EXISTS ioc_whitelist_audit (
      id           SERIAL PRIMARY KEY,
      whitelist_id INT,
      action       VARCHAR(20) NOT NULL,
      performed_by TEXT,
      details      JSONB,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_wla_wid ON ioc_whitelist_audit(whitelist_id)`,

    // ── Correlation Persistence ───────────────────────────────────
    `CREATE TABLE IF NOT EXISTS correlations (
      id               SERIAL PRIMARY KEY,
      entity           TEXT NOT NULL,
      entity_type      TEXT,
      ueba_risk        INT  DEFAULT 0,
      ueba_anomalies   INT  DEFAULT 0,
      siem_rule        TEXT,
      siem_severity    TEXT,
      mitre            TEXT[] DEFAULT '{}',
      mitre_tactic     TEXT[] DEFAULT '{}',
      correlation_type TEXT,
      investigation_id INT  REFERENCES investigations(id) ON DELETE SET NULL,
      indicator        TEXT,
      wazuh_hits       JSONB DEFAULT '[]',
      hive_hits        JSONB DEFAULT '[]',
      ai_analysis      TEXT,
      source           TEXT DEFAULT 'ueba_triage',
      created_at       TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_corr_entity     ON correlations(entity)`,
    `CREATE INDEX IF NOT EXISTS idx_corr_created_at ON correlations(created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_corr_ueba_risk  ON correlations(ueba_risk DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_corr_type       ON correlations(correlation_type)`,
    // Analyst comments on investigations
    `CREATE TABLE IF NOT EXISTS investigation_comments (
      id               SERIAL PRIMARY KEY,
      investigation_id INT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
      username         TEXT NOT NULL,
      body             TEXT NOT NULL,
      created_at       TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_inv_comments_inv ON investigation_comments(investigation_id)`,

    // ── SLA Policies ──────────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS sla_policies (
      id                  SERIAL PRIMARY KEY,
      name                VARCHAR(100) NOT NULL UNIQUE,
      description         TEXT,
      entity_type         VARCHAR(30)  NOT NULL DEFAULT 'all',
      severity            VARCHAR(20)  NOT NULL DEFAULT 'all',
      response_minutes    INT          NOT NULL DEFAULT 60,
      resolution_minutes  INT          NOT NULL DEFAULT 480,
      escalation_chain    JSONB        NOT NULL DEFAULT '[]',
      active              BOOLEAN      DEFAULT true,
      created_by          VARCHAR(50),
      created_at          TIMESTAMPTZ  DEFAULT NOW(),
      updated_at          TIMESTAMPTZ  DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_sla_pol_active ON sla_policies(active)`,
    `CREATE INDEX IF NOT EXISTS idx_sla_pol_sev    ON sla_policies(severity)`,

    // ── SLA Instances (live timers) ───────────────────────────────
    `CREATE TABLE IF NOT EXISTS sla_instances (
      id                  SERIAL PRIMARY KEY,
      policy_id           INT          REFERENCES sla_policies(id) ON DELETE SET NULL,
      policy_name         VARCHAR(100),
      entity_type         VARCHAR(30)  NOT NULL,
      entity_id           TEXT         NOT NULL,
      entity_label        TEXT,
      severity            VARCHAR(20),
      sla_type            VARCHAR(30)  NOT NULL DEFAULT 'response',
      response_minutes    INT          NOT NULL DEFAULT 60,
      resolution_minutes  INT          NOT NULL DEFAULT 480,
      status              VARCHAR(20)  NOT NULL DEFAULT 'running',
      owner               VARCHAR(100),
      started_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      paused_at           TIMESTAMPTZ,
      completed_at        TIMESTAMPTZ,
      total_paused_ms     BIGINT       NOT NULL DEFAULT 0,
      notified_70         BOOLEAN      NOT NULL DEFAULT false,
      notified_90         BOOLEAN      NOT NULL DEFAULT false,
      notified_breach     BOOLEAN      NOT NULL DEFAULT false,
      escalation_level    INT          NOT NULL DEFAULT 0,
      last_escalated_at   TIMESTAMPTZ,
      created_at          TIMESTAMPTZ  DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_sla_inst_entity  ON sla_instances(entity_type, entity_id)`,
    `CREATE INDEX IF NOT EXISTS idx_sla_inst_status  ON sla_instances(status)`,
    `CREATE INDEX IF NOT EXISTS idx_sla_inst_created ON sla_instances(created_at DESC)`,

    // ── SLA Events (full audit log) ───────────────────────────────
    `CREATE TABLE IF NOT EXISTS sla_events (
      id                  SERIAL PRIMARY KEY,
      sla_instance_id     INT          NOT NULL REFERENCES sla_instances(id) ON DELETE CASCADE,
      event_type          VARCHAR(30)  NOT NULL,
      actor               VARCHAR(100),
      reason              TEXT,
      prev_status         VARCHAR(20),
      new_status          VARCHAR(20),
      metadata            JSONB        DEFAULT '{}',
      created_at          TIMESTAMPTZ  DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_sla_events_inst ON sla_events(sla_instance_id)`,
    `CREATE INDEX IF NOT EXISTS idx_sla_events_type ON sla_events(event_type)`,
    `CREATE INDEX IF NOT EXISTS idx_sla_events_created ON sla_events(created_at DESC)`,

    // ── Audit log ──────────────────────────────────────────────────
    `CREATE TABLE IF NOT EXISTS audit_log (
      id            BIGSERIAL PRIMARY KEY,
      username      VARCHAR(100) NOT NULL,
      action        VARCHAR(100) NOT NULL,
      resource_type VARCHAR(100),
      resource_id   TEXT,
      details       JSONB DEFAULT '{}',
      ip_address    TEXT,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_audit_username   ON audit_log(username)`,
    `CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_log(action)`,
    `CREATE INDEX IF NOT EXISTS idx_audit_resource   ON audit_log(resource_type, resource_id)`,
    `CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at DESC)`,

    // ── Default SLA policies (idempotent) ─────────────────────────
    `INSERT INTO sla_policies(name,description,entity_type,severity,response_minutes,resolution_minutes,escalation_chain,created_by)
     VALUES
       ('Critical Incident SLA','Critical severity — 15 min response / 2 hr resolution','all','critical',15,120,
        '[{"at_pct":70,"action":"notify","target":"soc-lead"},{"at_pct":90,"action":"escalate","target":"incident-commander"}]'::jsonb,'system'),
       ('High Severity SLA','High severity — 30 min response / 4 hr resolution','all','high',30,240,
        '[{"at_pct":70,"action":"notify","target":"soc-lead"},{"at_pct":90,"action":"escalate","target":"soc-lead"}]'::jsonb,'system'),
       ('Medium Severity SLA','Medium severity — 2 hr response / 24 hr resolution','all','medium',120,1440,
        '[{"at_pct":80,"action":"notify","target":"analyst"},{"at_pct":100,"action":"escalate","target":"soc-lead"}]'::jsonb,'system'),
       ('Low Severity SLA','Low severity — 8 hr response / 72 hr resolution','all','low',480,4320,
        '[{"at_pct":80,"action":"notify","target":"analyst"},{"at_pct":100,"action":"escalate","target":"soc-lead"}]'::jsonb,'system')
     ON CONFLICT (name) DO NOTHING`,
  ];

  for (const q of queries) {
    try { await pool.query(q); }
    catch(e) { console.error('[DB] Schema error:', e.message, q.slice(0,60)); }
  }
  await seedDefaultHuntSchedules();
  console.log('[DB] Schema initialized');
}

// ── Alert Groups (deduplication) CRUD ────────────────────
async function upsertAlertGroup(srcIp, ruleId, agent) {
  const windowMinutes = 5;
  const now = new Date();
  // Check for existing open group within the 5-minute window
  const existing = await pool.query(
    `SELECT id, count FROM alert_groups
     WHERE src_ip=$1 AND rule_id=$2 AND window_end > $3
     ORDER BY window_end DESC LIMIT 1`,
    [srcIp || null, ruleId || null, now]
  );
  if (existing.rows.length) {
    const row = existing.rows[0];
    await pool.query(
      `UPDATE alert_groups SET count=count+1, last_seen=$1 WHERE id=$2`,
      [now, row.id]
    );
    return { id: row.id, count: row.count + 1, is_new: false };
  }
  const windowEnd = new Date(now.getTime() + windowMinutes * 60_000);
  const r = await pool.query(
    `INSERT INTO alert_groups(src_ip, rule_id, agent, count, first_seen, last_seen, window_end)
     VALUES ($1,$2,$3,1,$4,$4,$5) RETURNING id`,
    [srcIp || null, ruleId || null, agent || null, now, windowEnd]
  );
  return { id: r.rows[0].id, count: 1, is_new: true };
}

async function listAlertGroups({ limit = 50, offset = 0, page, page_size, severity, rule_id, agent, q } = {}) {
  if (page !== undefined) { page_size = Math.min(parseInt(page_size)||50, 500); offset = (Math.max(parseInt(page)||1,1)-1)*page_size; limit = page_size; }
  const params = [];
  const where = [];
  if (severity) where.push(`ag.severity = $${params.push(severity)}`);
  if (rule_id)  where.push(`ag.rule_id  = $${params.push(rule_id)}`);
  if (agent)    where.push(`ag.agent    ILIKE $${params.push('%'+agent+'%')}`);
  if (q)        where.push(`(ag.rule_id ILIKE $${params.push('%'+q+'%')} OR ag.src_ip ILIKE $${params.length} OR ag.agent ILIKE $${params.length})`);
  const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';
  params.push(limit, offset);
  const r = await pool.query(
    `SELECT ag.*, COUNT(i.id)::int AS investigation_count,
            COUNT(*) OVER() AS total_count
     FROM alert_groups ag
     LEFT JOIN investigations i ON i.group_id = ag.id
     ${whereClause}
     GROUP BY ag.id
     ORDER BY ag.last_seen DESC LIMIT $${params.length-1} OFFSET $${params.length}`,
    params
  );
  const total = r.rows.length ? parseInt(r.rows[0].total_count) : 0;
  const rows = r.rows.map(({ total_count, ...row }) => row);
  return { rows, total };
}

// ── Investigations CRUD ──────────────────────────────────
async function saveInvestigation(data) {
  const q = `INSERT INTO investigations
    (alert_key, alert_id, rule_id, rule_level, severity, agent, src_ip,
     description, mitre, timestamp, report, report_short, created_by,
     auto_triaged, duration_ms, raw_alert, composite_risk, group_id,
     deep_mode, structured_verdict, verdict, confidence_score, fp_probability)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
    RETURNING id, created_at`;

  const alertKey    = `${data.ruleId}_${data.timestamp}_${data.agent}_${data.srcIp||''}`;
  const reportShort = (data.report || '').slice(0, 300);
  const sv          = data.structuredVerdict || null;

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
    data.compositeRisk != null ? parseInt(data.compositeRisk) : null,
    data.groupId || null,
    data.deepMode || false,
    sv ? JSON.stringify(sv) : null,
    sv?.verdict || null,
    sv?.confidence_score != null ? parseInt(sv.confidence_score) : null,
    sv?.false_positive_probability != null ? parseInt(sv.false_positive_probability) : null,
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

async function listInvestigations({ limit=50, offset=0, page, page_size, severity, agent, ruleId, q, time_from, time_to, sort_by='created_at', sort_dir='desc' } = {}) {
  const ALLOWED_SORT = { created_at:1, severity:1, rule_level:1, agent:1, src_ip:1, duration_ms:1 };
  const col = ALLOWED_SORT[sort_by] ? sort_by : 'created_at';
  const dir = sort_dir === 'asc' ? 'ASC' : 'DESC';
  if (page !== undefined) { page_size = Math.min(parseInt(page_size)||50, 500); offset = (Math.max(parseInt(page)||1,1)-1)*page_size; limit = page_size; }
  else { limit = Math.min(parseInt(limit)||50, 500); offset = parseInt(offset)||0; }
  let where = ['1=1'], params = [];
  if (severity)  { params.push(severity);  where.push(`severity=$${params.length}`); }
  if (agent)     { params.push(agent);     where.push(`agent=$${params.length}`); }
  if (ruleId)    { params.push(ruleId);    where.push(`rule_id=$${params.length}`); }
  if (time_from) { params.push(time_from); where.push(`created_at >= $${params.length}`); }
  if (time_to)   { params.push(time_to);   where.push(`created_at <= $${params.length}`); }
  if (q) {
    params.push(`%${q}%`);
    where.push(`(description ILIKE $${params.length} OR src_ip ILIKE $${params.length} OR report_short ILIKE $${params.length})`);
  }
  params.push(limit, offset);
  const sql = `SELECT id, alert_key, rule_id, rule_level, severity, agent, src_ip,
    description, mitre, timestamp, report_short, created_by, auto_triaged,
    duration_ms, created_at, tp_status, hive_case_id,
    COUNT(*) OVER() AS total_count
    FROM investigations
    WHERE ${where.join(' AND ')}
    ORDER BY ${col} ${dir} LIMIT $${params.length-1} OFFSET $${params.length}`;
  const r = await pool.query(sql, params);
  const total = r.rows.length ? parseInt(r.rows[0].total_count) : 0;
  const rows = r.rows.map(({ total_count, ...row }) => row);
  return { rows, total };
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

async function updateInvestigationHiveCaseId(investigationId, hiveCaseId) {
  await pool.query(
    `UPDATE investigations SET hive_case_id=$1 WHERE id=$2`,
    [String(hiveCaseId), investigationId]
  );
}

// ── Artifacts ────────────────────────────────────────────
async function saveArtifacts(investigationId, artifacts) {
  if (!artifacts?.length) return;
  for (const art of artifacts) {
    try {
      // Cross-reference against OTX feed — boost threat score for known-bad IOCs
      let score = art.score || null;
      try {
        const otxMatch = await pool.query(
          `SELECT threat_score FROM otx_ioc_feed WHERE indicator=$1 LIMIT 1`,
          [art.value]
        );
        if (otxMatch.rows.length && score == null) score = otxMatch.rows[0].threat_score;
        else if (otxMatch.rows.length && score != null) score = Math.max(score, otxMatch.rows[0].threat_score);
      } catch { /* non-fatal */ }

      await pool.query(
        `INSERT INTO artifacts(investigation_id, artifact_type, value, threat_score) VALUES($1,$2,$3,$4)`,
        [investigationId, art.type, art.value, score]
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
async function listAssets({ status, q, limit=50, offset=0, page, page_size } = {}) {
  if (page !== undefined) { page_size = Math.min(parseInt(page_size)||50, 500); offset = (Math.max(parseInt(page)||1,1)-1)*page_size; limit = page_size; }
  else { limit = Math.min(parseInt(limit)||50, 500); offset = parseInt(offset)||0; }
  let where = ['1=1'], params = [];
  if (status) { params.push(status); where.push(`status=$${params.length}`); }
  if (q) { params.push(`%${q}%`); where.push(`(ip ILIKE $${params.length} OR hostname ILIKE $${params.length} OR os_guess ILIKE $${params.length})`); }
  params.push(limit, offset);
  const r = await pool.query(
    `SELECT a.*, s.cidr as subnet_cidr, s.label as subnet_label,
            COUNT(*) OVER() AS total_count
     FROM assets a LEFT JOIN subnets s ON a.subnet_id=s.id
     WHERE ${where.join(' AND ')} ORDER BY a.ip LIMIT $${params.length-1} OFFSET $${params.length}`,
    params
  );
  const total = r.rows.length ? parseInt(r.rows[0].total_count) : 0;
  const rows = r.rows.map(({ total_count, ...row }) => row);
  return { rows, total };
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

async function createPlaybook({ name, description, mitre_techniques, min_rule_level, fp_confidence_max, actions, require_consensus, enabled, ueba_risk_min }) {
  const r = await pool.query(`
    INSERT INTO playbooks(name,description,mitre_techniques,min_rule_level,fp_confidence_max,actions,require_consensus,enabled,ueba_risk_min)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *
  `, [
    name, description || '',
    mitre_techniques || [],
    min_rule_level ?? 12,
    fp_confidence_max ?? 40,
    JSON.stringify(actions || []),
    require_consensus ?? false,
    enabled ?? true,
    ueba_risk_min ?? null,
  ]);
  return r.rows[0];
}

async function updatePlaybook(id, fields) {
  const allowed = ['name','description','mitre_techniques','min_rule_level','fp_confidence_max','actions','require_consensus','enabled','ueba_risk_min'];
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

// ── Alert Suppressions ────────────────────────────────────────

async function listSuppressions({ enabledOnly = false } = {}) {
  const where = enabledOnly
    ? `WHERE enabled=true AND (expires_at IS NULL OR expires_at > NOW())`
    : '';
  const r = await pool.query(
    `SELECT * FROM alert_suppressions ${where} ORDER BY created_at DESC`
  );
  return r.rows;
}

async function createSuppression({ name, description, rule_id, agent_pattern, src_ip_pattern, min_level, max_level, expires_at, created_by, enabled }) {
  const r = await pool.query(
    `INSERT INTO alert_suppressions(name,description,rule_id,agent_pattern,src_ip_pattern,min_level,max_level,expires_at,created_by,enabled)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
    [
      name, description || null,
      rule_id    || null, agent_pattern  || null, src_ip_pattern || null,
      min_level  ?? null, max_level      ?? null,
      expires_at || null, created_by     || null,
      enabled    ?? true,
    ]
  );
  return r.rows[0];
}

async function updateSuppression(id, fields) {
  const allowed = ['name','description','rule_id','agent_pattern','src_ip_pattern','min_level','max_level','expires_at','enabled'];
  const sets = [], vals = [];
  for (const [k, v] of Object.entries(fields)) {
    if (!allowed.includes(k)) continue;
    vals.push(v);
    sets.push(`${k}=$${vals.length}`);
  }
  if (!sets.length) return null;
  vals.push(id);
  const r = await pool.query(
    `UPDATE alert_suppressions SET ${sets.join(',')} WHERE id=$${vals.length} RETURNING *`, vals
  );
  return r.rows[0] || null;
}

async function deleteSuppression(id) {
  await pool.query(`DELETE FROM alert_suppressions WHERE id=$1`, [id]);
}

async function bumpSuppressionHit(id) {
  await pool.query(
    `UPDATE alert_suppressions SET hit_count=hit_count+1, last_hit_at=NOW() WHERE id=$1`, [id]
  );
}

async function getSuppressionStats() {
  const r = await pool.query(
    `SELECT
       COUNT(*) FILTER (WHERE enabled=true AND (expires_at IS NULL OR expires_at > NOW())) AS active,
       COUNT(*) FILTER (WHERE enabled=false) AS disabled,
       COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at <= NOW()) AS expired,
       COALESCE(SUM(hit_count),0) AS total_hits,
       COUNT(*) FILTER (WHERE last_hit_at > NOW() - INTERVAL '24 hours') AS fired_today
     FROM alert_suppressions`
  );
  return r.rows[0];
}

// ── Draft Detection Rules (AI-generated after TP confirmation) ───

async function saveDraftRule({ investigationId, ruleId, agent, severity, description, mitreT, wazuhXml, sigmaYaml }) {
  const r = await pool.query(
    `INSERT INTO draft_rules(investigation_id,rule_id,agent,severity,description,mitre_techniques,wazuh_xml,sigma_yaml)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [investigationId||null, ruleId||null, agent||null, severity||null,
     (description||'').slice(0,1000), mitreT||[], wazuhXml||null, sigmaYaml||null]
  );
  return r.rows[0];
}

async function listDraftRules({ status, page = 1, page_size = 20 } = {}) {
  const params = [];
  let where = '';
  if (status) { params.push(status); where = `WHERE status=$${params.length}`; }
  const offset = (page - 1) * page_size;
  params.push(page_size, offset);
  const r = await pool.query(
    `SELECT dr.*, i.rule_level, i.report_short,
       COUNT(*) OVER() AS total_count
     FROM draft_rules dr
     LEFT JOIN investigations i ON i.id = dr.investigation_id
     ${where}
     ORDER BY dr.created_at DESC
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );
  const total = r.rows[0]?.total_count ? parseInt(r.rows[0].total_count) : 0;
  return { rows: r.rows.map(({ total_count, ...row }) => row), total };
}

async function updateDraftRuleStatus(id, status) {
  const r = await pool.query(
    `UPDATE draft_rules SET status=$1 WHERE id=$2 RETURNING *`, [status, id]
  );
  return r.rows[0] || null;
}

async function deleteDraftRule(id) {
  await pool.query(`DELETE FROM draft_rules WHERE id=$1`, [id]);
}

async function getDraftRuleStats() {
  const r = await pool.query(
    `SELECT
       COUNT(*) FILTER (WHERE status='pending_review') AS pending,
       COUNT(*) FILTER (WHERE status='approved')       AS approved,
       COUNT(*) FILTER (WHERE status='dismissed')      AS dismissed,
       COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') AS generated_7d
     FROM draft_rules`
  );
  return r.rows[0];
}

async function getMatchingPlaybooks(ruleLevel, mitreTechniques = [], uebaRisk = 0) {
  const r = await pool.query(
    `SELECT * FROM playbooks WHERE enabled=true AND (
       min_rule_level <= $1
       OR ($2::int > 0 AND ueba_risk_min IS NOT NULL AND ueba_risk_min <= $2::int)
     ) ORDER BY min_rule_level DESC, id`,
    [ruleLevel || 0, uebaRisk || 0]
  );
  return r.rows.filter(pb => {
    const pbMitre = pb.mitre_techniques || [];
    if (!pbMitre.length) return true;
    return pbMitre.some(t => (mitreTechniques || []).includes(t));
  }).map(pb => ({
    ...pb,
    _triggered_by: (uebaRisk > 0 && pb.ueba_risk_min != null && uebaRisk >= pb.ueba_risk_min)
      ? 'ueba' : 'rule_level',
  }));
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

async function listPlaybookExecutions({ limit = 50, offset = 0, page, page_size } = {}) {
  if (page !== undefined) { page_size = Math.min(parseInt(page_size)||50, 500); offset = (Math.max(parseInt(page)||1,1)-1)*page_size; limit = page_size; }
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count FROM playbook_executions ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  const total = r.rows.length ? parseInt(r.rows[0].total_count) : 0;
  const rows = r.rows.map(({ total_count, ...row }) => row);
  return { rows, total };
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

async function recentNotificationExists(type, metadataFilter, hours) {
  const r = await pool.query(
    `SELECT 1 FROM notifications
     WHERE type=$1 AND metadata @> $2::jsonb
     AND created_at > NOW() - ($3 || ' hours')::INTERVAL LIMIT 1`,
    [type, JSON.stringify(metadataFilter), hours.toString()]
  );
  return r.rows.length > 0;
}

async function saveInvestigationFeedback(investigationId, username, rating, comment) {
  const r = await pool.query(
    `INSERT INTO investigation_feedback(investigation_id, username, rating, comment)
     VALUES($1,$2,$3,$4)
     ON CONFLICT (investigation_id, username) DO UPDATE
     SET rating=$3, comment=$4, created_at=NOW()
     RETURNING *`,
    [investigationId, username, rating, comment || null]
  );
  return r.rows[0];
}

async function getInvestigationFeedbackSummary(investigationId) {
  const r = await pool.query(
    `SELECT
       COALESCE(AVG(rating::float), 0) AS avg_rating,
       COUNT(*)                         AS count,
       COUNT(CASE WHEN rating = 1  THEN 1 END) AS thumbs_up,
       COUNT(CASE WHEN rating = -1 THEN 1 END) AS thumbs_down
     FROM investigation_feedback WHERE investigation_id = $1`,
    [investigationId]
  );
  return r.rows[0];
}

async function listNotifications(username, limit = 50, offset = 0, unreadOnly = false) {
  const unreadClause = unreadOnly ? 'AND read=false' : '';
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count FROM notifications
     WHERE (username=$1 OR username IS NULL) ${unreadClause}
     ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
    [username, limit, offset]
  );
  const total = r.rows.length ? parseInt(r.rows[0].total_count) : 0;
  const rows = r.rows.map(({ total_count, ...row }) => row);
  return { rows, total };
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
async function listHuntSchedules({ limit=50, offset=0, page, page_size } = {}) {
  if (page !== undefined) { page_size = Math.min(parseInt(page_size)||50, 200); offset = (Math.max(parseInt(page)||1,1)-1)*page_size; limit = page_size; }
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count FROM hunt_schedules ORDER BY id LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  const total = r.rows.length ? parseInt(r.rows[0].total_count) : 0;
  const rows = r.rows.map(({ total_count, ...row }) => row);
  return { rows, total };
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

// ── OTX AlienVault IOC Feed ───────────────────────────────────
async function upsertOtxIoc({ pulseId, pulseName, indicatorType, indicator, description, tags, malwareFamilies, threatScore }) {
  await pool.query(`
    INSERT INTO otx_ioc_feed(pulse_id, pulse_name, indicator_type, indicator, description, tags, malware_families, threat_score, fetched_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,NOW())
    ON CONFLICT(pulse_id, indicator) DO UPDATE
      SET pulse_name=EXCLUDED.pulse_name, description=EXCLUDED.description,
          tags=EXCLUDED.tags, malware_families=EXCLUDED.malware_families,
          threat_score=EXCLUDED.threat_score, fetched_at=NOW()
  `, [pulseId, pulseName, indicatorType, indicator, description || '', tags || [], malwareFamilies || [], threatScore || 50]);
}

async function getOtxIocs({ type, search, limit = 100, offset = 0, page, page_size } = {}) {
  if (page !== undefined) { page_size = Math.min(parseInt(page_size)||100, 500); offset = (Math.max(parseInt(page)||1,1)-1)*page_size; limit = page_size; }
  const conditions = [];
  const params = [];
  if (type) { params.push(type); conditions.push(`indicator_type=$${params.length}`); }
  if (search) { params.push(`%${search}%`); conditions.push(`indicator ILIKE $${params.length}`); }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  params.push(limit, offset);
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count FROM otx_ioc_feed ${where} ORDER BY fetched_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );
  const total = r.rows.length ? parseInt(r.rows[0].total_count) : 0;
  const rows = r.rows.map(({ total_count, ...row }) => row);
  return { rows, total };
}

async function getOtxStats() {
  const r = await pool.query(`
    SELECT
      COUNT(*) AS total,
      MAX(fetched_at) AS last_sync,
      COUNT(*) FILTER (WHERE indicator_type='IPv4') AS ipv4_count,
      COUNT(*) FILTER (WHERE indicator_type='domain') AS domain_count,
      COUNT(*) FILTER (WHERE indicator_type IN ('FileHash-MD5','FileHash-SHA1','FileHash-SHA256')) AS hash_count,
      COUNT(*) FILTER (WHERE indicator_type='URL') AS url_count
    FROM otx_ioc_feed
  `);
  return r.rows[0];
}

async function checkOtxIndicator(indicator) {
  const r = await pool.query(
    `SELECT pulse_id, pulse_name, indicator_type, tags, malware_families, threat_score, fetched_at
     FROM otx_ioc_feed WHERE indicator=$1 LIMIT 5`,
    [indicator]
  );
  return r.rows;
}

// ── UEBA Digests ──────────────────────────────────────────────
async function createUebaDigest({ periodStart, periodEnd, digestMd, entityCount, highRiskCount, topEntities, success, error, emailed }) {
  const r = await pool.query(
    `INSERT INTO ueba_digests(period_start, period_end, digest_md, entity_count, high_risk_count, top_entities, success, error, emailed)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [
      periodStart || null, periodEnd || null, digestMd || null,
      entityCount || 0, highRiskCount || 0,
      topEntities ? JSON.stringify(topEntities) : null,
      success !== false, error || null, emailed === true,
    ]
  );
  return r.rows[0];
}

async function listUebaDigests(page = 1, pageSize = 10) {
  const offset = (page - 1) * pageSize;
  const r = await pool.query(
    `SELECT id, generated_at, period_start, period_end, digest_type, entity_count, high_risk_count, success, emailed, error,
            COUNT(*) OVER() AS total_count
     FROM ueba_digests ORDER BY generated_at DESC LIMIT $1 OFFSET $2`,
    [pageSize, offset]
  );
  return { rows: r.rows, total: parseInt(r.rows[0]?.total_count || 0) };
}

async function getUebaDigest(id) {
  const r = await pool.query(`SELECT * FROM ueba_digests WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

async function getLatestUebaDigest() {
  const r = await pool.query(`SELECT * FROM ueba_digests WHERE success=true ORDER BY generated_at DESC LIMIT 1`);
  return r.rows[0] || null;
}

async function markUebaDigestEmailed(id) {
  await pool.query(`UPDATE ueba_digests SET emailed=true WHERE id=$1`, [id]);
}

// ── Triage Queue ─────────────────────────────────────────────

function _triageTier(level) {
  if (level >= 12) return 'critical';
  if (level >= 9)  return 'high';
  if (level >= 6)  return 'medium';
  return 'low';
}

async function enqueueAlert(alert) {
  const tier = _triageTier(alert.level || 0);
  const score = (alert.level || 0) * 6;
  await pool.query(
    `INSERT INTO triage_queue
       (alert_id, alert_key, rule_id, rule_level, severity, triage_tier, agent, src_ip,
        description, mitre, full_log, alert_timestamp, priority_score, raw_alert)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
     ON CONFLICT (alert_key) DO NOTHING`,
    [
      alert.id || '',
      alert.alertKey,
      alert.ruleId || null,
      alert.level || 0,
      alert.severity || tier,
      tier,
      alert.agent || null,
      alert.srcIp || null,
      (alert.description || '').slice(0, 1000),
      alert.mitre || [],
      (alert.fullLog || '').slice(0, 500),
      alert.timestamp ? new Date(alert.timestamp) : new Date(),
      score,
      alert.raw || null,
    ]
  );
}

async function claimNextQueueItems(tier, limit) {
  const r = await pool.query(
    `WITH claimed AS (
       SELECT id FROM triage_queue
       WHERE status = 'pending' AND triage_tier = $1
       ORDER BY priority_score DESC, queued_at ASC
       LIMIT $2
       FOR UPDATE SKIP LOCKED
     )
     UPDATE triage_queue SET status='processing', claimed_at=NOW()
     WHERE id IN (SELECT id FROM claimed)
     RETURNING *`,
    [tier, limit]
  );
  return r.rows;
}

async function claimAllPendingLowTier() {
  const r = await pool.query(
    `UPDATE triage_queue SET status='suppressed', processed_at=NOW()
     WHERE status='pending' AND triage_tier='low'
     RETURNING id, rule_id, agent`
  );
  return r.rows;
}

async function markQueueItemDone(id, investigationId) {
  await pool.query(
    `UPDATE triage_queue SET status='done', processed_at=NOW(), investigation_id=$2 WHERE id=$1`,
    [id, investigationId || null]
  );
}

async function markQueueItemFailed(id, errorMsg) {
  await pool.query(
    `UPDATE triage_queue SET status='failed', processed_at=NOW(), error_msg=$2 WHERE id=$1`,
    [id, (errorMsg || '').slice(0, 500)]
  );
}

async function resetStuckQueueItems() {
  const r = await pool.query(
    `UPDATE triage_queue SET status='pending', claimed_at=NULL
     WHERE status='processing' AND claimed_at < NOW() - INTERVAL '10 minutes'
     RETURNING id`
  );
  return r.rowCount;
}

async function getQueueStats() {
  const r = await pool.query(
    `SELECT
       COUNT(*) FILTER (WHERE status='pending')    AS pending,
       COUNT(*) FILTER (WHERE status='processing') AS processing,
       COUNT(*) FILTER (WHERE status='done')       AS done,
       COUNT(*) FILTER (WHERE status='failed')     AS failed,
       COUNT(*) FILTER (WHERE status='suppressed' OR status='batched') AS suppressed,
       COUNT(*) FILTER (WHERE status='pending' AND triage_tier='critical') AS pending_critical,
       COUNT(*) FILTER (WHERE status='pending' AND triage_tier='high')     AS pending_high,
       COUNT(*) FILTER (WHERE status='pending' AND triage_tier='medium')   AS pending_medium,
       COUNT(*) FILTER (WHERE status='pending' AND triage_tier='low')      AS pending_low,
       COUNT(*) FILTER (WHERE queued_at > NOW() - INTERVAL '1 hour')       AS queued_1h,
       COUNT(*) FILTER (WHERE queued_at > NOW() - INTERVAL '24 hours')     AS queued_24h
     FROM triage_queue`
  );
  const row = r.rows[0];
  return {
    pending:          parseInt(row.pending) || 0,
    processing:       parseInt(row.processing) || 0,
    done:             parseInt(row.done) || 0,
    failed:           parseInt(row.failed) || 0,
    suppressed:       parseInt(row.suppressed) || 0,
    pending_critical: parseInt(row.pending_critical) || 0,
    pending_high:     parseInt(row.pending_high) || 0,
    pending_medium:   parseInt(row.pending_medium) || 0,
    pending_low:      parseInt(row.pending_low) || 0,
    queued_1h:        parseInt(row.queued_1h) || 0,
    queued_24h:       parseInt(row.queued_24h) || 0,
  };
}

async function getPendingLowTierGroups(windowMinutes, minCount) {
  const r = await pool.query(
    `SELECT rule_id, agent, COUNT(*) AS count
     FROM triage_queue
     WHERE triage_tier='low' AND status='suppressed' AND notified=false
       AND queued_at > NOW() - ($1 || ' minutes')::INTERVAL
     GROUP BY rule_id, agent
     HAVING COUNT(*) >= $2
     ORDER BY count DESC`,
    [windowMinutes, minCount]
  );
  return r.rows.map(row => ({
    rule_id: row.rule_id,
    agent:   row.agent,
    count:   parseInt(row.count),
  }));
}

async function markLowTierGroupNotified(ruleId, agent, windowMinutes) {
  await pool.query(
    `UPDATE triage_queue SET notified=true
     WHERE triage_tier='low' AND status='suppressed' AND notified=false
       AND rule_id=$1 AND agent=$2
       AND queued_at > NOW() - ($3 || ' minutes')::INTERVAL`,
    [ruleId, agent, windowMinutes]
  );
}

// ── Rule FP Rate Statistics ───────────────────────────────────
// Aggregates confirmed_fp / confirmed_tp markings per rule.
// Returns rows only for rules with at least 1 labelled investigation.
async function getRuleFpRates() {
  const r = await pool.query(
    `SELECT
       rule_id,
       COUNT(*)                                                              AS total_labelled,
       COUNT(CASE WHEN tp_status = 'confirmed_fp' THEN 1 END)               AS fp_count,
       COUNT(CASE WHEN tp_status = 'confirmed_tp' THEN 1 END)               AS tp_count,
       ROUND(100.0 * COUNT(CASE WHEN tp_status = 'confirmed_fp' THEN 1 END)
             / NULLIF(COUNT(*), 0), 1)                                      AS fp_rate_raw
     FROM investigations
     WHERE tp_status IN ('confirmed_fp', 'confirmed_tp')
       AND rule_id IS NOT NULL
     GROUP BY rule_id
     ORDER BY fp_rate_raw DESC`
  );
  return r.rows;
}

// ── Action Approvals ─────────────────────────────────────────

async function createActionApproval({
  investigationId, alertKey, ruleId, agent, srcIp, severity, triageTier,
  verdict, confidence, riskScore, fpProbability, summary,
  recommendedActions, playbookIds, alertData, timeoutMin = 30,
}) {
  const expiresAt = new Date(Date.now() + timeoutMin * 60_000);
  const r = await pool.query(
    `INSERT INTO action_approvals(
       investigation_id, alert_key, rule_id, agent, src_ip, severity, triage_tier,
       verdict, confidence, risk_score, fp_probability, summary,
       recommended_actions, playbook_ids, alert_data, expires_at
     ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
     RETURNING *`,
    [
      investigationId || null, alertKey || '', ruleId || '', agent || '', srcIp || null,
      severity || '', triageTier || '', verdict || 'needs_review',
      confidence || 0, riskScore || 0, fpProbability || 0, summary || '',
      recommendedActions || [], playbookIds || [],
      JSON.stringify(alertData || {}), expiresAt,
    ]
  );
  return r.rows[0];
}

async function getActionApproval(id) {
  const r = await pool.query(`SELECT * FROM action_approvals WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

async function listActionApprovals({ status } = {}) {
  const where  = status ? `WHERE aa.status=$1` : `WHERE aa.status='pending' AND aa.expires_at > NOW()`;
  const params = status ? [status] : [];
  const r = await pool.query(
    `SELECT aa.*, i.report AS investigation_report, i.structured_verdict AS investigation_verdict
     FROM action_approvals aa
     LEFT JOIN investigations i ON i.id = aa.investigation_id
     ${where}
     ORDER BY aa.created_at DESC LIMIT 100`,
    params
  );
  return r.rows;
}

async function resolveActionApproval(id, { status, resolvedBy, resolveNote }) {
  const valid = ['approved', 'rejected', 'expired', 'executed'];
  if (!valid.includes(status)) throw new Error(`Invalid approval status: ${status}`);
  const r = await pool.query(
    `UPDATE action_approvals
     SET status=$1, resolved_at=NOW(), resolved_by=$2, resolve_note=$3
     WHERE id=$4 RETURNING *`,
    [status, resolvedBy || 'system', resolveNote || '', id]
  );
  return r.rows[0] || null;
}

async function listExpiredActionApprovals() {
  const r = await pool.query(
    `SELECT * FROM action_approvals WHERE status='pending' AND expires_at < NOW()`
  );
  return r.rows;
}

async function countPendingActionApprovals() {
  const r = await pool.query(
    `SELECT COUNT(*) AS count FROM action_approvals
     WHERE status='pending' AND expires_at > NOW()`
  );
  return parseInt(r.rows[0]?.count) || 0;
}

// ── Health check ─────────────────────────────────────────────
async function ping() {
  try {
    await pool.query('SELECT 1');
    return true;
  } catch { return false; }
}

// ── Artifacts / IOC Store ─────────────────────────────────────
async function upsertIOC(indicator, iocType, data = {}) {
  const r = await pool.query(
    `INSERT INTO ioc_store
       (indicator, ioc_type, reputation, confidence, risk_score, source, source_ref,
        tags, notes, mitre_techniques, threat_actors, malware_families, created_by,
        first_seen, last_seen)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),NOW())
     ON CONFLICT (indicator, ioc_type) DO UPDATE
       SET reputation=EXCLUDED.reputation, confidence=EXCLUDED.confidence,
           risk_score=EXCLUDED.risk_score, source=EXCLUDED.source,
           source_ref=EXCLUDED.source_ref, tags=EXCLUDED.tags,
           notes=EXCLUDED.notes, mitre_techniques=EXCLUDED.mitre_techniques,
           threat_actors=EXCLUDED.threat_actors, malware_families=EXCLUDED.malware_families,
           last_seen=NOW(), updated_at=NOW()
     RETURNING *, (xmax = 0) AS is_insert`,
    [indicator, iocType,
     data.reputation || 'unknown', data.confidence || 0, data.risk_score || 0,
     data.source || 'manual', data.source_ref || null,
     data.tags || [], data.notes || null,
     data.mitre_techniques || [], data.threat_actors || [], data.malware_families || [],
     data.created_by || null]
  );
  return r.rows[0];
}

async function getIOC(id) {
  const r = await pool.query(`SELECT * FROM ioc_store WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

async function listIOCs({ page = 1, page_size = 50, ioc_type, reputation, q, sort_by = 'last_seen', sort_dir = 'desc' } = {}) {
  const ALLOWED_SORT = { last_seen: 'last_seen', first_seen: 'first_seen', risk_score: 'risk_score', created_at: 'created_at', indicator: 'indicator' };
  const col = ALLOWED_SORT[sort_by] || 'last_seen';
  const dir = sort_dir === 'asc' ? 'ASC' : 'DESC';
  page_size = Math.min(parseInt(page_size) || 50, 200);
  const offset = (Math.max(parseInt(page) || 1, 1) - 1) * page_size;
  const conditions = ['1=1'];
  const vals = [];
  if (ioc_type) { conditions.push(`ioc_type=$${vals.push(ioc_type)}`); }
  if (reputation) { conditions.push(`reputation=$${vals.push(reputation)}`); }
  if (q) { conditions.push(`(indicator ILIKE $${vals.push('%'+q+'%')} OR notes ILIKE $${vals.length})`); }
  const where = conditions.join(' AND ');
  vals.push(page_size, offset);
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count FROM ioc_store WHERE ${where}
     ORDER BY ${col} ${dir} LIMIT $${vals.length - 1} OFFSET $${vals.length}`,
    vals
  );
  return { rows: r.rows, total: parseInt(r.rows[0]?.total_count || 0) };
}

async function updateIOC(id, data) {
  const allowed = ['reputation','confidence','risk_score','tags','notes','mitre_techniques','threat_actors','malware_families','is_whitelisted','enriched_at','source','source_ref'];
  const sets = [], vals = [];
  for (const [k, v] of Object.entries(data)) {
    if (allowed.includes(k)) { vals.push(v); sets.push(`${k}=$${vals.length}`); }
  }
  if (!sets.length) return null;
  vals.push(id);
  const r = await pool.query(
    `UPDATE ioc_store SET ${sets.join(',')},updated_at=NOW() WHERE id=$${vals.length} RETURNING *`, vals
  );
  return r.rows[0] || null;
}

async function deleteIOC(id) {
  await pool.query(`DELETE FROM ioc_store WHERE id=$1`, [id]);
}

async function getIOCStats() {
  const r = await pool.query(`
    SELECT
      COUNT(*)                                              AS total,
      COUNT(*) FILTER (WHERE reputation='malicious')        AS malicious,
      COUNT(*) FILTER (WHERE reputation='suspicious')       AS suspicious,
      COUNT(*) FILTER (WHERE reputation='trusted')          AS trusted,
      COUNT(*) FILTER (WHERE reputation='unknown')          AS unknown_rep,
      COUNT(*) FILTER (WHERE enriched_at IS NOT NULL)       AS enriched,
      COUNT(*) FILTER (WHERE last_seen > NOW()-INTERVAL '24h') AS seen_24h,
      COUNT(*) FILTER (WHERE first_seen > NOW()-INTERVAL '24h') AS new_24h
    FROM ioc_store`);
  const byType = await pool.query(
    `SELECT ioc_type, COUNT(*) AS cnt FROM ioc_store GROUP BY ioc_type ORDER BY cnt DESC`
  );
  return { summary: r.rows[0], by_type: byType.rows };
}

async function saveIOCEnrichment(iocId, source, result, status, error) {
  const r = await pool.query(
    `INSERT INTO ioc_enrichments (ioc_id, source, result, status, error, fetched_at)
     VALUES ($1,$2,$3,$4,$5,NOW())
     ON CONFLICT (ioc_id, source) DO UPDATE
       SET result=$3, status=$4, error=$5, fetched_at=NOW()
     RETURNING *`,
    [iocId, source, result ? JSON.stringify(result) : null, status || 'success', error || null]
  );
  // Stamp enriched_at on parent
  if (status === 'success') {
    await pool.query(`UPDATE ioc_store SET enriched_at=NOW(), updated_at=NOW() WHERE id=$1`, [iocId]);
  }
  return r.rows[0];
}

async function getIOCEnrichments(iocId) {
  const r = await pool.query(
    `SELECT * FROM ioc_enrichments WHERE ioc_id=$1 ORDER BY fetched_at DESC`, [iocId]
  );
  return r.rows;
}

async function addIOCRelation(iocId, entityType, entityId, entityLabel, relType) {
  const r = await pool.query(
    `INSERT INTO ioc_relations (ioc_id, entity_type, entity_id, entity_label, rel_type)
     VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (ioc_id, entity_type, entity_id) DO UPDATE SET entity_label=$4, rel_type=$5
     RETURNING *`,
    [iocId, entityType, entityId, entityLabel || null, relType || 'observed_in']
  );
  return r.rows[0];
}

async function getIOCRelations(iocId) {
  const r = await pool.query(
    `SELECT * FROM ioc_relations WHERE ioc_id=$1 ORDER BY created_at DESC`, [iocId]
  );
  return r.rows;
}

async function listIOCsByEntity(entityType, entityId) {
  const r = await pool.query(
    `SELECT s.*, r.rel_type, r.entity_label FROM ioc_store s
     JOIN ioc_relations r ON r.ioc_id=s.id
     WHERE r.entity_type=$1 AND r.entity_id=$2 ORDER BY s.risk_score DESC`,
    [entityType, entityId]
  );
  return r.rows;
}

// ── IOC Whitelist ─────────────────────────────────────────────
async function createWhitelistEntry(data, username) {
  const r = await pool.query(
    `INSERT INTO ioc_whitelist
       (indicator, ioc_type, category, reason, added_by, approved_by, expires_at, enabled, risk_warning)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [data.indicator, data.ioc_type, data.category, data.reason || null,
     username, data.approved_by || null, data.expires_at || null,
     data.enabled !== false, data.risk_warning || null]
  );
  await pool.query(
    `INSERT INTO ioc_whitelist_audit (whitelist_id, action, performed_by, details)
     VALUES ($1,'created',$2,$3)`,
    [r.rows[0].id, username, JSON.stringify(r.rows[0])]
  );
  // Mark IOC as whitelisted if it exists
  await pool.query(
    `UPDATE ioc_store SET is_whitelisted=TRUE, updated_at=NOW()
     WHERE indicator=$1 AND ioc_type=$2`, [data.indicator, data.ioc_type]
  );
  return r.rows[0];
}

async function updateWhitelistEntry(id, data, username) {
  const old = await pool.query(`SELECT * FROM ioc_whitelist WHERE id=$1`, [id]);
  if (!old.rows[0]) return null;
  const allowed = ['category','reason','approved_by','expires_at','enabled','risk_warning'];
  const sets = [], vals = [];
  for (const [k, v] of Object.entries(data)) {
    if (allowed.includes(k)) { vals.push(v); sets.push(`${k}=$${vals.length}`); }
  }
  if (!sets.length) return old.rows[0];
  vals.push(id);
  const r = await pool.query(
    `UPDATE ioc_whitelist SET ${sets.join(',')},updated_at=NOW() WHERE id=$${vals.length} RETURNING *`, vals
  );
  await pool.query(
    `INSERT INTO ioc_whitelist_audit (whitelist_id, action, performed_by, details)
     VALUES ($1,$2,$3,$4)`,
    [id, data.enabled !== undefined ? (data.enabled ? 'enabled' : 'disabled') : 'updated',
     username, JSON.stringify({ old: old.rows[0], new: r.rows[0] })]
  );
  return r.rows[0];
}

async function deleteWhitelistEntry(id, username) {
  const old = await pool.query(`SELECT * FROM ioc_whitelist WHERE id=$1`, [id]);
  if (!old.rows[0]) return false;
  await pool.query(`DELETE FROM ioc_whitelist WHERE id=$1`, [id]);
  await pool.query(
    `INSERT INTO ioc_whitelist_audit (whitelist_id, action, performed_by, details)
     VALUES ($1,'deleted',$2,$3)`,
    [id, username, JSON.stringify(old.rows[0])]
  );
  await pool.query(
    `UPDATE ioc_store SET is_whitelisted=FALSE, updated_at=NOW()
     WHERE indicator=$1 AND ioc_type=$2`,
    [old.rows[0].indicator, old.rows[0].ioc_type]
  );
  return true;
}

async function listWhitelist({ page = 1, page_size = 50, ioc_type, category, q, show_expired = false } = {}) {
  page_size = Math.min(parseInt(page_size) || 50, 200);
  const offset = (Math.max(parseInt(page) || 1, 1) - 1) * page_size;
  const conditions = ['1=1'];
  const vals = [];
  if (ioc_type) { conditions.push(`ioc_type=$${vals.push(ioc_type)}`); }
  if (category) { conditions.push(`category=$${vals.push(category)}`); }
  if (q) { conditions.push(`indicator ILIKE $${vals.push('%'+q+'%')}`); }
  if (!show_expired) { conditions.push(`(expires_at IS NULL OR expires_at > NOW())`); }
  const where = conditions.join(' AND ');
  vals.push(page_size, offset);
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count FROM ioc_whitelist
     WHERE ${where} ORDER BY created_at DESC LIMIT $${vals.length-1} OFFSET $${vals.length}`,
    vals
  );
  return { rows: r.rows, total: parseInt(r.rows[0]?.total_count || 0) };
}

async function getWhitelistEntry(id) {
  const r = await pool.query(`SELECT * FROM ioc_whitelist WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

async function checkWhitelisted(indicator, iocType) {
  const r = await pool.query(
    `SELECT id, category, reason, expires_at FROM ioc_whitelist
     WHERE indicator=$1 AND (ioc_type=$2 OR ioc_type='any')
       AND enabled=TRUE AND (expires_at IS NULL OR expires_at > NOW())
     LIMIT 1`,
    [indicator, iocType]
  );
  return r.rows[0] || null;
}

async function getWhitelistAudit(whitelistId) {
  const r = await pool.query(
    `SELECT * FROM ioc_whitelist_audit WHERE whitelist_id=$1 ORDER BY created_at DESC LIMIT 50`,
    [whitelistId]
  );
  return r.rows;
}

async function bulkImportWhitelist(entries, username) {
  let imported = 0, skipped = 0;
  for (const e of entries) {
    try {
      await createWhitelistEntry(e, username);
      imported++;
    } catch { skipped++; }
  }
  return { imported, skipped };
}

// ── Log Source Onboarding History ────────────────────────────
async function upsertLogSourceHistory(src) {
  const r = await pool.query(
    `INSERT INTO log_source_history
       (source_id, source_name, source_ip, vendor, type, protocol,
        integration, top_decoder, top_groups, first_seen, last_seen)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())
     ON CONFLICT (source_id) DO UPDATE
       SET source_name=$2, source_ip=$3, vendor=$4, type=$5, protocol=$6,
           integration=$7, top_decoder=$8, top_groups=$9, last_seen=NOW()
     RETURNING *, (xmax = 0) AS is_insert`,
    [
      src.source_id, src.source_name, src.source_ip || null,
      src.vendor || null, src.type || null, src.protocol || null,
      src.integration || null, src.top_decoder || null,
      src.top_groups || [],
    ]
  );
  return r.rows[0];
}

async function getUnnotifiedLogSources() {
  const r = await pool.query(
    `SELECT * FROM log_source_history WHERE notified=FALSE ORDER BY first_seen ASC`
  );
  return r.rows;
}

async function markLogSourcesNotified(ids) {
  if (!ids.length) return;
  await pool.query(
    `UPDATE log_source_history SET notified=TRUE WHERE id=ANY($1)`,
    [ids]
  );
}

async function getLogSourceHistory({ page = 1, page_size = 50 } = {}) {
  page_size = Math.min(parseInt(page_size) || 50, 200);
  const offset = (Math.max(parseInt(page) || 1, 1) - 1) * page_size;
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count
     FROM log_source_history
     ORDER BY first_seen DESC
     LIMIT $1 OFFSET $2`,
    [page_size, offset]
  );
  return { rows: r.rows, total: parseInt(r.rows[0]?.total_count || 0) };
}

// ── Correlation Persistence ───────────────────────────────────────
async function saveCorrelation(data) {
  const r = await pool.query(
    `INSERT INTO correlations
       (entity, entity_type, ueba_risk, ueba_anomalies, siem_rule, siem_severity,
        mitre, mitre_tactic, correlation_type, investigation_id, indicator,
        wazuh_hits, hive_hits, ai_analysis, source)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
     RETURNING id`,
    [
      data.entity        || null,
      data.entity_type   || null,
      data.ueba_risk     || 0,
      data.ueba_anomalies || 0,
      data.siem_rule     || null,
      data.siem_severity || null,
      data.mitre         || [],
      data.mitre_tactic  || [],
      data.correlation_type || null,
      data.investigation_id || null,
      data.indicator     || null,
      JSON.stringify(data.wazuh_hits || []),
      JSON.stringify(data.hive_hits  || []),
      data.ai_analysis   || null,
      data.source        || 'ueba_triage',
    ]
  );
  return r.rows[0];
}

async function getCorrelations({ page = 1, page_size = 50, q, entity_type, min_risk, correlation_type, sort_by = 'created_at', sort_dir = 'desc' } = {}) {
  const ALLOWED_SORT = { created_at: 'created_at', ueba_risk: 'ueba_risk', entity: 'entity' };
  const col = ALLOWED_SORT[sort_by] || 'created_at';
  const dir = sort_dir === 'asc' ? 'ASC' : 'DESC';
  const offset = (page - 1) * page_size;
  const params = [];
  const where = [];
  if (q) {
    params.push(`%${q}%`);
    where.push(`(entity ILIKE $${params.length} OR correlation_type ILIKE $${params.length} OR siem_rule ILIKE $${params.length} OR indicator ILIKE $${params.length})`);
  }
  if (entity_type) { params.push(entity_type); where.push(`entity_type = $${params.length}`); }
  if (min_risk)    { params.push(parseInt(min_risk)); where.push(`ueba_risk >= $${params.length}`); }
  if (correlation_type) { params.push(correlation_type); where.push(`correlation_type = $${params.length}`); }
  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  params.push(page_size, offset);
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count FROM correlations
     ${whereClause} ORDER BY ${col} ${dir} LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );
  return { rows: r.rows, total: parseInt(r.rows[0]?.total_count || 0) };
}

// ── Investigation Comments ────────────────────────────────
async function saveInvComment(investigationId, username, body) {
  const r = await pool.query(
    `INSERT INTO investigation_comments (investigation_id, username, body)
     VALUES ($1, $2, $3) RETURNING *`,
    [investigationId, username, body]
  );
  return r.rows[0];
}

async function getInvComments(investigationId) {
  const r = await pool.query(
    `SELECT * FROM investigation_comments
     WHERE investigation_id = $1 ORDER BY created_at ASC`,
    [investigationId]
  );
  return r.rows;
}

// ── Related Investigations ────────────────────────────────
async function getRelatedInvestigations(invId, { srcIp, ruleId, agent } = {}) {
  const conditions = [`id != $1`];
  const params = [invId];
  const or = [];
  if (srcIp  && srcIp  !== '—') or.push(`src_ip = $${params.push(srcIp)}`);
  if (ruleId && ruleId !== '—') or.push(`rule_id = $${params.push(ruleId)}`);
  if (agent  && agent  !== '—') or.push(`agent = $${params.push(agent)}`);
  if (!or.length) return [];
  conditions.push(`(${or.join(' OR ')})`);
  const r = await pool.query(
    `SELECT id, created_at, severity, rule_id, description, agent, src_ip, auto_triaged
     FROM investigations WHERE ${conditions.join(' AND ')}
     ORDER BY created_at DESC LIMIT 5`,
    params
  );
  return r.rows;
}

// ── Audit Log ─────────────────────────────────────────────────────────
async function logAudit(username, action, resourceType, resourceId, details = {}, ip = null) {
  try {
    await pool.query(
      `INSERT INTO audit_log(username, action, resource_type, resource_id, details, ip_address)
       VALUES($1,$2,$3,$4,$5,$6)`,
      [username || 'system', action, resourceType || null, resourceId ? String(resourceId) : null,
       JSON.stringify(details), ip || null]
    );
  } catch(e) {
    console.error('[audit] log error:', e.message);
  }
}

async function listAuditLog({ page = 1, page_size = 50, username, action, resource_type, date_from, date_to } = {}) {
  const offset = (page - 1) * page_size;
  const conds = [];
  const params = [page_size, offset];
  if (username)      conds.push(`username = $${params.push(username)}`);
  if (action)        conds.push(`action = $${params.push(action)}`);
  if (resource_type) conds.push(`resource_type = $${params.push(resource_type)}`);
  if (date_from)     conds.push(`created_at >= $${params.push(date_from)}`);
  if (date_to)       conds.push(`created_at <= $${params.push(date_to)}`);
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count
     FROM audit_log ${where}
     ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
    params
  );
  return { rows: r.rows, total: parseInt(r.rows[0]?.total_count || 0) };
}

async function getAuditActions() {
  const r = await pool.query(`SELECT DISTINCT action FROM audit_log ORDER BY action`);
  return r.rows.map(x => x.action);
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
  saveInvComment,
  getInvComments,
  getRelatedInvestigations,
  getSetting,
  setSetting,
  getAllSettings,
  getSmtpSettings,
  updateSmtpSettings,
  updateInvestigationStatus,
  getInvestigationStatus,
  updateInvestigationHiveCaseId,
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
  // Draft Detection Rules
  saveDraftRule,
  listDraftRules,
  updateDraftRuleStatus,
  deleteDraftRule,
  getDraftRuleStats,
  // Alert Suppressions
  listSuppressions,
  createSuppression,
  updateSuppression,
  deleteSuppression,
  bumpSuppressionHit,
  getSuppressionStats,
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
  recentNotificationExists,
  listNotifications,
  // Investigation Feedback
  saveInvestigationFeedback,
  getInvestigationFeedbackSummary,
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
  // System events
  createSystemEvent,
  listSystemEvents,
  // Alert deduplication groups
  upsertAlertGroup,
  listAlertGroups,
  // OTX AlienVault IOC feed
  upsertOtxIoc,
  getOtxIocs,
  getOtxStats,
  checkOtxIndicator,
  // UEBA Digests
  createUebaDigest,
  listUebaDigests,
  // FP Rate Stats
  getRuleFpRates,
  // Action Approvals
  createActionApproval,
  getActionApproval,
  listActionApprovals,
  resolveActionApproval,
  listExpiredActionApprovals,
  countPendingActionApprovals,
  // Triage Queue
  enqueueAlert,
  claimNextQueueItems,
  claimAllPendingLowTier,
  markQueueItemDone,
  markQueueItemFailed,
  resetStuckQueueItems,
  getQueueStats,
  getPendingLowTierGroups,
  markLowTierGroupNotified,
  getUebaDigest,
  getLatestUebaDigest,
  markUebaDigestEmailed,
  // Log Source Onboarding History
  upsertLogSourceHistory,
  getUnnotifiedLogSources,
  markLogSourcesNotified,
  getLogSourceHistory,
  // IOC Store
  upsertIOC,
  getIOC,
  listIOCs,
  updateIOC,
  deleteIOC,
  getIOCStats,
  saveIOCEnrichment,
  getIOCEnrichments,
  addIOCRelation,
  getIOCRelations,
  listIOCsByEntity,
  // IOC Whitelist
  createWhitelistEntry,
  updateWhitelistEntry,
  deleteWhitelistEntry,
  listWhitelist,
  getWhitelistEntry,
  checkWhitelisted,
  getWhitelistAudit,
  bulkImportWhitelist,
  // Correlation Persistence
  saveCorrelation,
  getCorrelations,
  // Audit Log
  logAudit,
  listAuditLog,
  getAuditActions,
  // SLA Management
  listSlaPolicies,
  getSlaPolicy,
  getSlaPolicyForEntity,
  createSlaPolicy,
  updateSlaPolicy,
  deleteSlaPolicy,
  createSlaInstance,
  upsertSlaForAlert,
  getSlaForEntityBatch,
  getSlaPolicyMap,
  getSlaInstance,
  getSlaForEntity,
  listSlaInstances,
  pauseSlaInstance,
  resumeSlaInstance,
  completeSlaInstance,
  cancelSlaInstance,
  applySlaTickerUpdates,
  getActiveSlaInstances,
  createSlaEvent,
  listSlaEvents,
  getSlaDashboardStats,
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

// ── System Events ────────────────────────────────────────────
async function createSystemEvent(eventType, actor, description, status = 'ok', metadata = {}) {
  const r = await pool.query(
    `INSERT INTO system_events(event_type, actor, description, status, metadata)
     VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [eventType, actor || null, description, status, JSON.stringify(metadata)]
  );
  return r.rows[0];
}

async function listSystemEvents({ limit = 50, offset = 0, eventType } = {}) {
  const vals = [];
  const where = eventType ? (vals.push(eventType), [`event_type=$${vals.length}`]) : [];
  vals.push(limit, offset);
  const r = await pool.query(
    `SELECT * FROM system_events ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
     ORDER BY created_at DESC LIMIT $${vals.length - 1} OFFSET $${vals.length}`,
    vals
  );
  return r.rows;
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

// ── SLA Policies CRUD ────────────────────────────────────────────
async function listSlaPolicies() {
  const r = await pool.query(`SELECT * FROM sla_policies ORDER BY severity, name`);
  return r.rows;
}

async function getSlaPolicy(id) {
  const r = await pool.query(`SELECT * FROM sla_policies WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

async function getSlaPolicyForEntity(entityType, severity) {
  const r = await pool.query(
    `SELECT * FROM sla_policies
     WHERE active=true
       AND (entity_type=$1 OR entity_type='all')
       AND (severity=$2   OR severity='all')
     ORDER BY
       (CASE WHEN entity_type=$1 THEN 0 ELSE 1 END),
       (CASE WHEN severity=$2   THEN 0 ELSE 1 END)
     LIMIT 1`,
    [entityType, severity || 'low']
  );
  return r.rows[0] || null;
}

async function createSlaPolicy({ name, description, entityType, severity, responseMinutes, resolutionMinutes, escalationChain, createdBy }) {
  const r = await pool.query(
    `INSERT INTO sla_policies(name,description,entity_type,severity,response_minutes,resolution_minutes,escalation_chain,created_by)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [name, description || null, entityType || 'all', severity || 'all',
     responseMinutes, resolutionMinutes, JSON.stringify(escalationChain || []), createdBy || null]
  );
  return r.rows[0];
}

async function updateSlaPolicy(id, { name, description, entityType, severity, responseMinutes, resolutionMinutes, escalationChain, active }) {
  const r = await pool.query(
    `UPDATE sla_policies SET name=$2,description=$3,entity_type=$4,severity=$5,
       response_minutes=$6,resolution_minutes=$7,escalation_chain=$8,active=$9,updated_at=NOW()
     WHERE id=$1 RETURNING *`,
    [id, name, description || null, entityType || 'all', severity || 'all',
     responseMinutes, resolutionMinutes, JSON.stringify(escalationChain || []),
     active !== false]
  );
  return r.rows[0] || null;
}

async function deleteSlaPolicy(id) {
  const r = await pool.query(`DELETE FROM sla_policies WHERE id=$1 RETURNING id`, [id]);
  return r.rowCount > 0;
}

// ── SLA Instances lifecycle ───────────────────────────────────────
async function createSlaInstance({ policyId, policyName, entityType, entityId, entityLabel, severity, slaType, responseMinutes, resolutionMinutes, owner, startedAt }) {
  const r = await pool.query(
    `INSERT INTO sla_instances(policy_id,policy_name,entity_type,entity_id,entity_label,severity,sla_type,response_minutes,resolution_minutes,owner,status,started_at)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'running',$11) RETURNING *`,
    [policyId || null, policyName || null, entityType, String(entityId),
     entityLabel || null, severity || null, slaType || 'response',
     responseMinutes, resolutionMinutes, owner || null,
     startedAt ? new Date(startedAt) : new Date()]
  );
  return r.rows[0];
}

// Find-or-create SLA for a SIEM alert — backdates started_at to alert timestamp
async function upsertSlaForAlert({ alertId, alertLabel, severity, alertTimestamp, policyId, policyName, responseMinutes, resolutionMinutes }) {
  const existing = await pool.query(
    `SELECT * FROM sla_instances WHERE entity_type='alert' AND entity_id=$1 ORDER BY created_at DESC LIMIT 1`,
    [String(alertId)]
  );
  if (existing.rows[0]) return existing.rows[0];
  const r = await pool.query(
    `INSERT INTO sla_instances(policy_id,policy_name,entity_type,entity_id,entity_label,severity,sla_type,response_minutes,resolution_minutes,owner,status,started_at)
     VALUES($1,$2,'alert',$3,$4,$5,'response',$6,$7,'system','running',$8) RETURNING *`,
    [policyId || null, policyName || null, String(alertId), alertLabel || null,
     severity || null, responseMinutes, resolutionMinutes,
     alertTimestamp ? new Date(alertTimestamp) : new Date()]
  );
  return r.rows[0];
}

// Batch lookup: returns map of entity_id → sla instance (latest per entity)
async function getSlaForEntityBatch(entityType, ids) {
  if (!ids || !ids.length) return {};
  const r = await pool.query(
    `SELECT DISTINCT ON (entity_id) * FROM sla_instances
     WHERE entity_type=$1 AND entity_id = ANY($2)
     ORDER BY entity_id, created_at DESC`,
    [entityType, ids.map(String)]
  );
  const map = {};
  for (const row of r.rows) map[row.entity_id] = row;
  return map;
}

// Return map of severity → {response_minutes, resolution_minutes} from active policies
async function getSlaPolicyMap() {
  const r = await pool.query(
    `SELECT severity, MIN(response_minutes) AS response_minutes, MIN(resolution_minutes) AS resolution_minutes
     FROM sla_policies WHERE active=true AND entity_type IN ('all','alert')
     GROUP BY severity ORDER BY severity`
  );
  const map = {};
  for (const row of r.rows) {
    map[row.severity] = { response_minutes: parseInt(row.response_minutes), resolution_minutes: parseInt(row.resolution_minutes) };
  }
  // Ensure defaults exist even if no policy seeded
  if (!map.critical) map.critical = { response_minutes: 15,  resolution_minutes: 120 };
  if (!map.high)     map.high     = { response_minutes: 30,  resolution_minutes: 240 };
  if (!map.medium)   map.medium   = { response_minutes: 120, resolution_minutes: 1440 };
  return map;
}

async function getSlaInstance(id) {
  const r = await pool.query(`SELECT * FROM sla_instances WHERE id=$1`, [id]);
  return r.rows[0] || null;
}

async function getSlaForEntity(entityType, entityId) {
  const r = await pool.query(
    `SELECT * FROM sla_instances WHERE entity_type=$1 AND entity_id=$2 ORDER BY created_at DESC LIMIT 1`,
    [entityType, String(entityId)]
  );
  return r.rows[0] || null;
}

async function listSlaInstances({ page = 1, pageSize = 50, status, entityType } = {}) {
  const vals = [];
  const where = [];
  if (status)     { vals.push(status);     where.push(`status=$${vals.length}`); }
  if (entityType) { vals.push(entityType); where.push(`entity_type=$${vals.length}`); }
  const offset = (page - 1) * pageSize;
  vals.push(pageSize, offset);
  const r = await pool.query(
    `SELECT *, COUNT(*) OVER() AS total_count FROM sla_instances
     ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
     ORDER BY created_at DESC LIMIT $${vals.length - 1} OFFSET $${vals.length}`,
    vals
  );
  return { rows: r.rows, total: parseInt(r.rows[0]?.total_count || 0) };
}

async function pauseSlaInstance(id, actor, reason) {
  const inst = await getSlaInstance(id);
  if (!inst || inst.status !== 'running') return null;
  const r = await pool.query(
    `UPDATE sla_instances SET status='paused', paused_at=NOW() WHERE id=$1 RETURNING *`, [id]
  );
  if (r.rowCount) await createSlaEvent({ slaInstanceId: id, eventType: 'paused', actor, reason, prevStatus: 'running', newStatus: 'paused' });
  return r.rows[0] || null;
}

async function resumeSlaInstance(id, actor, reason) {
  const inst = await getSlaInstance(id);
  if (!inst || inst.status !== 'paused') return null;
  const pausedMs = inst.paused_at ? Date.now() - new Date(inst.paused_at).getTime() : 0;
  const r = await pool.query(
    `UPDATE sla_instances SET status='running', paused_at=NULL, total_paused_ms=total_paused_ms+$2 WHERE id=$1 RETURNING *`,
    [id, pausedMs]
  );
  if (r.rowCount) await createSlaEvent({ slaInstanceId: id, eventType: 'resumed', actor, reason, prevStatus: 'paused', newStatus: 'running' });
  return r.rows[0] || null;
}

async function completeSlaInstance(id, actor, reason) {
  const inst = await getSlaInstance(id);
  if (!inst || !['running', 'paused', 'breached'].includes(inst.status)) return null;
  const r = await pool.query(
    `UPDATE sla_instances SET status='completed', completed_at=NOW() WHERE id=$1 RETURNING *`, [id]
  );
  if (r.rowCount) await createSlaEvent({ slaInstanceId: id, eventType: 'completed', actor, reason, prevStatus: inst.status, newStatus: 'completed' });
  return r.rows[0] || null;
}

async function cancelSlaInstance(id, actor, reason) {
  const inst = await getSlaInstance(id);
  if (!inst) return null;
  const r = await pool.query(
    `UPDATE sla_instances SET status='cancelled', completed_at=NOW() WHERE id=$1 AND status NOT IN ('completed','cancelled') RETURNING *`, [id]
  );
  if (r.rowCount) await createSlaEvent({ slaInstanceId: id, eventType: 'cancelled', actor, reason, prevStatus: inst.status, newStatus: 'cancelled' });
  return r.rows[0] || null;
}

async function applySlaTickerUpdates(id, updates) {
  const sets = [];
  const vals = [id];
  const add = (col, val) => { if (val !== undefined) { vals.push(val); sets.push(`${col}=$${vals.length}`); } };
  add('notified_70',     updates.notified_70);
  add('notified_90',     updates.notified_90);
  add('notified_breach', updates.notified_breach);
  add('status',          updates.status);
  add('escalation_level', updates.escalation_level);
  add('last_escalated_at', updates.last_escalated_at);
  if (!sets.length) return null;
  const r = await pool.query(`UPDATE sla_instances SET ${sets.join(',')} WHERE id=$1 RETURNING *`, vals);
  return r.rows[0] || null;
}

async function getActiveSlaInstances() {
  const r = await pool.query(`SELECT * FROM sla_instances WHERE status='running' ORDER BY started_at`);
  return r.rows;
}

// ── SLA Events (audit log) ────────────────────────────────────────
async function createSlaEvent({ slaInstanceId, eventType, actor, reason, prevStatus, newStatus, metadata = {} }) {
  const r = await pool.query(
    `INSERT INTO sla_events(sla_instance_id,event_type,actor,reason,prev_status,new_status,metadata)
     VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [slaInstanceId, eventType, actor || null, reason || null, prevStatus || null, newStatus || null, JSON.stringify(metadata)]
  );
  return r.rows[0];
}

async function listSlaEvents(slaInstanceId) {
  const r = await pool.query(
    `SELECT * FROM sla_events WHERE sla_instance_id=$1 ORDER BY created_at DESC`, [slaInstanceId]
  );
  return r.rows;
}

// ── SLA Analytics ─────────────────────────────────────────────────
async function getSlaDashboardStats() {
  const counts = await pool.query(`
    SELECT
      COUNT(*) FILTER (WHERE status='running')   AS active_count,
      COUNT(*) FILTER (WHERE status='breached')  AS breached_count,
      COUNT(*) FILTER (WHERE status='completed') AS completed_count,
      COUNT(*) FILTER (WHERE status='paused')    AS paused_count
    FROM sla_instances WHERE created_at > NOW() - INTERVAL '7 days'
  `);
  const mttr = await pool.query(`
    SELECT ROUND(AVG(
      EXTRACT(EPOCH FROM (completed_at - started_at)) / 60.0 - total_paused_ms / 60000.0
    ))::INT AS mttr_minutes
    FROM sla_instances
    WHERE status='completed' AND completed_at IS NOT NULL
      AND created_at > NOW() - INTERVAL '30 days'
  `);
  const compliance = await pool.query(`
    SELECT
      COUNT(*) FILTER (WHERE status IN ('completed','breached')) AS total_done,
      COUNT(*) FILTER (WHERE status='completed' AND notified_breach=false) AS on_time
    FROM sla_instances WHERE created_at > NOW() - INTERVAL '30 days'
  `);
  const c  = counts.rows[0];
  const cp = compliance.rows[0];
  const complRate = parseInt(cp.total_done) > 0
    ? Math.round((parseInt(cp.on_time) / parseInt(cp.total_done)) * 100) : null;
  return {
    active:          parseInt(c.active_count),
    breached:        parseInt(c.breached_count),
    completed:       parseInt(c.completed_count),
    paused:          parseInt(c.paused_count),
    mttr_minutes:    mttr.rows[0].mttr_minutes || null,
    compliance_rate: complRate,
  };
}
