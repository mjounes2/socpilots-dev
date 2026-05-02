-- ============================================================
--  SOCPilots — Asset Scan Extended Schema
--  Extends the base assets table with coverage gap tracking,
--  Wazuh agent cache, scan history, and deployment queue.
-- ============================================================

-- Wazuh agents cache (populated from Wazuh API)
CREATE TABLE IF NOT EXISTS wazuh_agents_cache (
  id             SERIAL PRIMARY KEY,
  agent_id       VARCHAR(20) UNIQUE NOT NULL,
  agent_name     VARCHAR(100),
  agent_ip       VARCHAR(50),
  agent_ip_alt   VARCHAR(50),   -- secondary IP if agent has multiple
  status         VARCHAR(20),   -- active, disconnected, never_connected, pending
  version        VARCHAR(50),
  os_name        VARCHAR(255),
  os_platform    VARCHAR(50),
  os_arch        VARCHAR(20),
  last_keepalive TIMESTAMPTZ,
  date_add       TIMESTAMPTZ,
  group_name     VARCHAR(100),
  manager_host   VARCHAR(100),
  synced_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_wazuh_agent_ip     ON wazuh_agents_cache(agent_ip);
CREATE INDEX IF NOT EXISTS idx_wazuh_agent_name   ON wazuh_agents_cache(agent_name);
CREATE INDEX IF NOT EXISTS idx_wazuh_agent_status ON wazuh_agents_cache(status);

-- Coverage gaps (assets without adequate Wazuh coverage)
CREATE TABLE IF NOT EXISTS coverage_gaps (
  id                   SERIAL PRIMARY KEY,
  asset_id             INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  asset_ip             VARCHAR(50) NOT NULL,
  asset_hostname       VARCHAR(255),
  gap_type             VARCHAR(50) NOT NULL,  -- missing_agent, disconnected_agent, outdated_agent
  severity             VARCHAR(20) NOT NULL,  -- critical, high, medium, low
  open_ports           JSONB DEFAULT '[]',
  os_guess             VARCHAR(255),
  risk_score           INT DEFAULT 0,
  detected_at          TIMESTAMPTZ DEFAULT NOW(),
  resolved_at          TIMESTAMPTZ,
  resolution_notes     TEXT,
  in_deployment_queue  BOOLEAN DEFAULT FALSE,
  thehive_case_id      VARCHAR(50),
  auto_remediation     BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_gaps_asset_ip  ON coverage_gaps(asset_ip);
CREATE INDEX IF NOT EXISTS idx_gaps_severity  ON coverage_gaps(severity);
CREATE INDEX IF NOT EXISTS idx_gaps_resolved  ON coverage_gaps(resolved_at);
CREATE INDEX IF NOT EXISTS idx_gaps_type      ON coverage_gaps(gap_type);

-- Scan history (one row per completed scan)
CREATE TABLE IF NOT EXISTS scan_history (
  id                  SERIAL PRIMARY KEY,
  scan_id             UUID DEFAULT gen_random_uuid(),
  scan_type           VARCHAR(50) DEFAULT 'full',  -- full, nmap, arp, wazuh_only
  subnets_scanned     TEXT[],
  hosts_discovered    INTEGER DEFAULT 0,
  agents_synced       INTEGER DEFAULT 0,
  gaps_found          INTEGER DEFAULT 0,
  gaps_resolved       INTEGER DEFAULT 0,
  coverage_before     DECIMAL(5,2),
  coverage_after      DECIMAL(5,2),
  duration_seconds    INTEGER,
  started_at          TIMESTAMPTZ DEFAULT NOW(),
  completed_at        TIMESTAMPTZ,
  triggered_by        VARCHAR(50),    -- 'schedule', 'manual', 'api', 'n8n'
  status              VARCHAR(20) DEFAULT 'running',
  error_message       TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_history_started ON scan_history(started_at DESC);

-- Deployment queue (hosts needing Wazuh agent deployment)
CREATE TABLE IF NOT EXISTS deployment_queue (
  id             SERIAL PRIMARY KEY,
  asset_id       INTEGER REFERENCES assets(id) ON DELETE CASCADE,
  asset_ip       VARCHAR(50) NOT NULL,
  asset_hostname VARCHAR(255),
  os_type        VARCHAR(50),    -- linux, windows, macos, unknown
  priority       VARCHAR(20) DEFAULT 'high',   -- critical, high, medium, low
  status         VARCHAR(30) DEFAULT 'pending', -- pending, in_progress, deployed, failed, skipped
  gap_id         INTEGER REFERENCES coverage_gaps(id) ON DELETE SET NULL,
  thehive_case_id VARCHAR(50),
  deployment_method VARCHAR(50),   -- manual, ansible, script, ssh
  created_at     TIMESTAMPTZ DEFAULT NOW(),
  started_at     TIMESTAMPTZ,
  completed_at   TIMESTAMPTZ,
  assigned_to    VARCHAR(100),
  notes          TEXT,
  retry_count    INT DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_deploy_status   ON deployment_queue(status);
CREATE INDEX IF NOT EXISTS idx_deploy_priority ON deployment_queue(priority);

-- Coverage metrics snapshots (for trending)
CREATE TABLE IF NOT EXISTS coverage_metrics (
  id                  SERIAL PRIMARY KEY,
  recorded_at         TIMESTAMPTZ DEFAULT NOW(),
  total_assets        INTEGER DEFAULT 0,
  covered_assets      INTEGER DEFAULT 0,
  coverage_percentage DECIMAL(5,2),
  critical_gaps       INTEGER DEFAULT 0,
  high_gaps           INTEGER DEFAULT 0,
  pending_deployments INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_coverage_metrics_time ON coverage_metrics(recorded_at DESC);

-- Default insert to ensure metrics table has at least one row
INSERT INTO coverage_metrics(total_assets, covered_assets, coverage_percentage)
VALUES (0, 0, 0.00)
ON CONFLICT DO NOTHING;
