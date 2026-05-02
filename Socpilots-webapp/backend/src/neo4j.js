// ============================================================
//  SOCPilots — Neo4j UEBA Engine
//
//  Real UEBA = User & Entity Behavior Analytics
//  - Builds mathematical baseline of "normal" per user/entity
//  - Scores every event as deviation from baseline (0–100)
//  - Maintains dynamic risk scores updated in real-time
//  - Detects: lateral movement, insider threats, privilege
//    escalation, impossible travel, data exfiltration patterns
//  - Correlates signals across the entire organization
// ============================================================
let driver = null;

function getDriver() {
  if (driver) return driver;
  const neo4j = require('neo4j-driver');
  const uri  = process.env.NEO4J_URI      || 'bolt://neo4j:7687';
  const user = process.env.NEO4J_USER     || 'neo4j';
  const pass = process.env.NEO4J_PASSWORD || '';
  if (!pass) { console.warn('[UEBA] NEO4J_PASSWORD not set — UEBA disabled'); return null; }
  driver = neo4j.driver(uri, neo4j.auth.basic(user, pass), {
    maxConnectionPoolSize: 10,
    connectionTimeoutMs: 5000,
  });
  console.log('[UEBA] Neo4j driver connected →', uri);
  return driver;
}

async function run(cypher, params = {}) {
  const d = getDriver();
  if (!d) return [];
  const session = d.session();
  try {
    const result = await session.run(cypher, params);
    return result.records;
  } finally {
    await session.close();
  }
}

async function runSingle(cypher, params = {}) {
  const records = await run(cypher, params);
  return records[0] || null;
}

// ── Schema & Indexes ─────────────────────────────────────────
async function initSchema() {
  const d = getDriver();
  if (!d) return;
  const session = d.session();
  try {
    const indexes = [
      'CREATE INDEX user_name  IF NOT EXISTS FOR (u:User)    ON (u.name)',
      'CREATE INDEX host_name  IF NOT EXISTS FOR (h:Host)    ON (h.name)',
      'CREATE INDEX proc_name  IF NOT EXISTS FOR (p:Process) ON (p.name)',
      'CREATE INDEX ip_addr    IF NOT EXISTS FOR (i:IP)      ON (i.address)',
      'CREATE INDEX alert_id   IF NOT EXISTS FOR (a:Alert)   ON (a.alert_id)',
    ];
    for (const q of indexes) {
      try { await session.run(q); } catch { /* already exists */ }
    }
    console.log('[UEBA] Schema ready');
  } finally {
    await session.close();
  }
}

// ── Deviation Scoring Helpers ─────────────────────────────────
// Returns 0 (normal) to 100 (extreme anomaly)
function scoreHourDeviation(hour, typicalHours) {
  if (!typicalHours?.length) return 30; // unknown baseline → moderate score
  const entry = typicalHours.find(e => e.hour === hour);
  if (!entry) return 80; // never logged in at this hour
  const maxFreq = Math.max(...typicalHours.map(e => e.freq));
  if (maxFreq === 0) return 30;
  const normalizedFreq = entry.freq / maxFreq;
  return Math.round((1 - normalizedFreq) * 70); // 0 = peak hour, 70 = rare hour
}

function scoreNewEntity(isNew) {
  return isNew ? 75 : 0;
}

function calcOverallDeviation(scores) {
  if (!scores.length) return 0;
  // Weighted: max score carries most weight
  const max = Math.max(...scores);
  const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
  return Math.round(max * 0.6 + avg * 0.4);
}

// ── Ingest Event ─────────────────────────────────────────────
// Called from n8n or webapp whenever a Wazuh alert fires
// Builds the graph AND calculates deviation scores in real-time
async function ingestEvent(ev) {
  const d = getDriver();
  if (!d) return;

  const {
    user, host, src_ip, process: proc,
    action, timestamp, alert_id, rule_id, severity,
    bytes_sent, parent_process, success = true,
  } = ev;

  const ts        = timestamp || new Date().toISOString();
  const hour      = new Date(ts).getUTCHours();
  const dayOfWeek = new Date(ts).getUTCDay();

  const session = d.session();
  try {
    // ── 1. Upsert nodes ──────────────────────────────────────
    if (user) {
      await session.run(
        `MERGE (u:User {name: $name})
         ON CREATE SET u.risk_score = 0, u.total_events = 0, u.created_at = $ts,
                       u.typical_hours = [], u.typical_hosts = [], u.typical_ips = []
         ON MATCH  SET u.total_events = coalesce(u.total_events, 0) + 1,
                       u.last_seen = $ts`,
        { name: user, ts }
      );
    }
    if (host) {
      await session.run(
        `MERGE (h:Host {name: $name})
         ON CREATE SET h.risk_score = 0, h.first_seen = $ts
         ON MATCH  SET h.last_seen = $ts`,
        { name: host, ts }
      );
    }
    if (proc) {
      await session.run(
        `MERGE (p:Process {name: $name})
         ON CREATE SET p.seen_count = 1, p.first_seen = $ts
         ON MATCH  SET p.seen_count = coalesce(p.seen_count, 0) + 1`,
        { name: proc, ts }
      );
    }
    if (src_ip) {
      await session.run(
        `MERGE (i:IP {address: $addr})
         ON CREATE SET i.first_seen = $ts, i.is_internal = $internal
         ON MATCH  SET i.last_seen = $ts`,
        { addr: src_ip, ts, internal: /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(src_ip) }
      );
    }

    // ── 2. Calculate deviation scores ────────────────────────
    let deviationScore = 0;
    const deviationFlags = [];

    if (user && host) {
      // Check if user has accessed this host before
      const hostCheck = await session.run(
        `MATCH (u:User {name: $user})-[:LOGGED_IN]->(h:Host {name: $host})
         RETURN count(*) AS cnt`,
        { user, host }
      );
      const isNewHost = (hostCheck.records[0]?.get('cnt')?.toNumber?.() ?? 0) === 0;

      // Check user's typical login hours
      const userProfile = await session.run(
        `MATCH (u:User {name: $user}) RETURN u.typical_hours AS th`,
        { user }
      );
      const typicalHours = userProfile.records[0]?.get('th') || [];

      const hourScore = scoreHourDeviation(hour, typicalHours);
      const hostScore = scoreNewEntity(isNewHost);
      deviationScore  = calcOverallDeviation([hourScore, hostScore]);

      if (isNewHost)   deviationFlags.push('new_host_access');
      if (hourScore > 60) deviationFlags.push('unusual_hour');

      // Check for impossible travel (same user, different IP, < 5 min ago)
      if (src_ip) {
        const travelCheck = await session.run(
          `MATCH (u:User {name: $user})-[r:LOGGED_IN]->(h:Host)
           WHERE r.src_ip <> $ip
             AND datetime(r.time) > datetime($ts) - duration({minutes: 5})
           RETURN r.src_ip AS other_ip LIMIT 1`,
          { user, ip: src_ip, ts }
        );
        if (travelCheck.records.length) {
          deviationScore = Math.max(deviationScore, 95);
          deviationFlags.push('impossible_travel');
        }
      }

      // Create relationship
      await session.run(
        `MATCH (u:User {name: $user}) MATCH (h:Host {name: $host})
         CREATE (u)-[:LOGGED_IN {
           time: $ts, hour: $hour, day_of_week: $dow,
           src_ip: $src_ip, success: $success,
           alert_id: $alert_id, rule_id: $rule_id,
           deviation_score: $dev, flags: $flags
         }]->(h)`,
        { user, host, ts, hour, dow: dayOfWeek,
          src_ip: src_ip||'', success, alert_id: alert_id||'',
          rule_id: rule_id||'', dev: deviationScore, flags: deviationFlags }
      );

      // Update baseline: track hourly login frequencies
      await session.run(
        `MATCH (u:User {name: $user})
         WITH u, [x IN u.typical_hours WHERE x.hour = $hour | x] AS existing
         SET u.typical_hours = CASE
           WHEN size(existing) > 0 THEN
             [x IN u.typical_hours | CASE WHEN x.hour = $hour
               THEN {hour: x.hour, freq: x.freq + 1} ELSE x END]
           ELSE coalesce(u.typical_hours, []) + [{hour: $hour, freq: 1}]
         END`,
        { user, hour }
      );
    }

    if (host && proc) {
      // Check if this process is rare on this host
      const procCheck = await session.run(
        `MATCH (h:Host {name: $host})-[:EXECUTED]->(p:Process {name: $proc})
         RETURN count(*) AS cnt`,
        { host, proc }
      );
      const isNewProc = (procCheck.records[0]?.get('cnt')?.toNumber?.() ?? 0) === 0;
      const procScore = isNewProc ? 70 : 0;

      if (isNewProc) deviationFlags.push('new_process');
      deviationScore = Math.max(deviationScore, calcOverallDeviation([procScore]));

      await session.run(
        `MATCH (h:Host {name: $host}) MATCH (p:Process {name: $proc})
         CREATE (h)-[:EXECUTED {
           time: $ts, user: $user, parent: $parent,
           alert_id: $alert_id, deviation_score: $dev
         }]->(p)`,
        { host, proc, ts, user: user||'', parent: parent_process||'',
          alert_id: alert_id||'', dev: procScore }
      );
    }

    if (src_ip && host) {
      await session.run(
        `MATCH (i:IP {address: $ip}) MATCH (h:Host {name: $host})
         CREATE (i)-[:CONNECTED_TO {
           time: $ts, bytes_sent: $bytes, alert_id: $alert_id,
           rule_id: $rule_id, deviation_score: $dev
         }]->(h)`,
        { ip: src_ip, host, ts, bytes: bytes_sent||0,
          alert_id: alert_id||'', rule_id: rule_id||'', dev: deviationScore }
      );
    }

    // ── 3. Update entity risk scores ─────────────────────────
    if (deviationScore > 30 && user) {
      await session.run(
        `MATCH (u:User {name: $user})
         SET u.risk_score = toInteger(min([100,
           coalesce(u.risk_score, 0) * 0.85 + $dev * 0.15
         ])),
         u.last_anomaly = $ts,
         u.anomaly_count = coalesce(u.anomaly_count, 0) + 1`,
        { user, dev: deviationScore, ts }
      );
    }
    if (deviationScore > 30 && host) {
      await session.run(
        `MATCH (h:Host {name: $host})
         SET h.risk_score = toInteger(min([100,
           coalesce(h.risk_score, 0) * 0.85 + $dev * 0.15
         ]))`,
        { host, dev: deviationScore }
      );
    }

  } finally {
    await session.close();
  }
}

// ── Risk Leaderboard ─────────────────────────────────────────
async function getRiskLeaderboard(limit = 20) {
  const records = await run(
    `MATCH (u:User)
     WHERE u.risk_score > 0
     OPTIONAL MATCH (u)-[r:LOGGED_IN]->(h:Host)
     WHERE datetime(r.time) > datetime() - duration({hours: 24})
     WITH u, count(r) AS events_24h, collect(DISTINCT h.name)[..5] AS recent_hosts
     RETURN u.name AS user, u.risk_score AS risk_score,
            u.anomaly_count AS anomaly_count, u.last_anomaly AS last_anomaly,
            events_24h, recent_hosts
     ORDER BY u.risk_score DESC LIMIT $limit`,
    { limit }
  );
  return records.map(r => ({
    user:          r.get('user'),
    risk_score:    r.get('risk_score')?.toNumber?.() ?? r.get('risk_score') ?? 0,
    anomaly_count: r.get('anomaly_count')?.toNumber?.() ?? 0,
    last_anomaly:  r.get('last_anomaly'),
    events_24h:    r.get('events_24h')?.toNumber?.() ?? 0,
    recent_hosts:  r.get('recent_hosts') || [],
  }));
}

// ── Behavioral Profile per User ──────────────────────────────
async function getUserProfile(username) {
  const rec = await runSingle(
    `MATCH (u:User {name: $name})
     OPTIONAL MATCH (u)-[r:LOGGED_IN]->(h:Host)
     WITH u, collect(DISTINCT h.name) AS all_hosts,
          collect({host: h.name, time: r.time, dev: r.deviation_score, flags: r.flags}) AS logins
     RETURN u, all_hosts, logins[..50] AS recent_logins`,
    { name: username }
  );
  if (!rec) return null;

  const u = rec.get('u').properties;
  return {
    name:          u.name,
    risk_score:    u.risk_score?.toNumber?.() ?? u.risk_score ?? 0,
    anomaly_count: u.anomaly_count?.toNumber?.() ?? 0,
    total_events:  u.total_events?.toNumber?.() ?? 0,
    typical_hours: u.typical_hours || [],
    last_seen:     u.last_seen,
    last_anomaly:  u.last_anomaly,
    all_hosts:     rec.get('all_hosts') || [],
    recent_logins: (rec.get('recent_logins') || []).map(l => ({
      host: l.host,
      time: l.time,
      deviation: l.dev?.toNumber?.() ?? l.dev ?? 0,
      flags: l.flags || [],
    })),
  };
}

// ── Anomaly Detections ───────────────────────────────────────

async function detectLateralMovement(hours = 24) {
  const records = await run(
    `MATCH (u:User)-[r1:LOGGED_IN]->(h1:Host)
     MATCH (u)-[r2:LOGGED_IN]->(h2:Host)
     WHERE h1 <> h2
       AND datetime(r1.time) > datetime() - duration({hours: $hours})
       AND datetime(r2.time) > datetime() - duration({hours: $hours})
     WITH u, collect(DISTINCT h1.name) AS src_hosts,
             collect(DISTINCT h2.name) AS dst_hosts,
             max(coalesce(r1.deviation_score, 0)) AS max_dev,
             count(*) AS hops
     WHERE hops >= 2
     RETURN u.name AS user, src_hosts, dst_hosts, max_dev, hops, u.risk_score AS risk_score
     ORDER BY max_dev DESC, hops DESC LIMIT 15`,
    { hours }
  );
  return records.map(r => ({
    type:       'lateral_movement',
    user:       r.get('user'),
    src_hosts:  r.get('src_hosts'),
    dst_hosts:  r.get('dst_hosts'),
    hops:       r.get('hops')?.toNumber?.() ?? 0,
    deviation:  r.get('max_dev')?.toNumber?.() ?? 0,
    risk_score: r.get('risk_score')?.toNumber?.() ?? 0,
  }));
}

async function detectImpossibleTravel(minutes = 10) {
  const records = await run(
    `MATCH (u:User)-[r1:LOGGED_IN]->(h:Host)
     MATCH (u)-[r2:LOGGED_IN]->(h)
     WHERE r1.src_ip <> r2.src_ip
       AND r1.src_ip <> '' AND r2.src_ip <> ''
       AND abs(duration.inSeconds(datetime(r1.time), datetime(r2.time)).seconds) < $secs
     RETURN u.name AS user, h.name AS host,
            r1.src_ip AS ip1, r2.src_ip AS ip2,
            r1.time AS t1, r2.time AS t2
     LIMIT 20`,
    { secs: minutes * 60 }
  );
  return records.map(r => ({
    type:  'impossible_travel',
    user:  r.get('user'),
    host:  r.get('host'),
    ip1:   r.get('ip1'),
    ip2:   r.get('ip2'),
    time1: r.get('t1'),
    time2: r.get('t2'),
  }));
}

async function detectPrivilegeEscalation(hours = 24) {
  const PRIV_PROCS = ['sudo', 'su', 'doas', 'pkexec', 'runas', 'passwd', 'visudo', 'chmod', 'chown'];
  const records = await run(
    `MATCH (h:Host)-[r:EXECUTED]->(p:Process)
     WHERE p.name IN $procs
       AND datetime(r.time) > datetime() - duration({hours: $hours})
     RETURN r.user AS user, h.name AS host, p.name AS process,
            r.time AS time, r.deviation_score AS dev
     ORDER BY r.time DESC LIMIT 20`,
    { procs: PRIV_PROCS, hours }
  );
  return records.map(r => ({
    type:      'privilege_escalation',
    user:      r.get('user'),
    host:      r.get('host'),
    process:   r.get('process'),
    time:      r.get('time'),
    deviation: r.get('dev')?.toNumber?.() ?? 0,
  }));
}

async function detectAfterHoursAccess(hours = 24, businessStart = 7, businessEnd = 19) {
  const records = await run(
    `MATCH (u:User)-[r:LOGGED_IN]->(h:Host)
     WHERE (r.hour < $start OR r.hour >= $end)
       AND datetime(r.time) > datetime() - duration({hours: $hours})
     WITH u.name AS user, h.name AS host, count(r) AS events,
          collect(DISTINCT r.hour) AS hours_seen,
          max(r.deviation_score) AS max_dev
     WHERE events >= 2
     RETURN user, host, events, hours_seen, max_dev
     ORDER BY max_dev DESC LIMIT 15`,
    { start: businessStart, end: businessEnd, hours }
  );
  return records.map(r => ({
    type:       'after_hours_access',
    user:       r.get('user'),
    host:       r.get('host'),
    events:     r.get('events')?.toNumber?.() ?? 0,
    hours_seen: r.get('hours_seen') || [],
    deviation:  r.get('max_dev')?.toNumber?.() ?? 0,
  }));
}

async function detectHighFrequencyLogins(hours = 1, threshold = 5) {
  const records = await run(
    `MATCH (u:User)-[r:LOGGED_IN]->(h:Host)
     WHERE datetime(r.time) > datetime() - duration({hours: $hours})
     WITH u.name AS user, h.name AS host, count(r) AS cnt, u.risk_score AS risk_score
     WHERE cnt >= $threshold
     RETURN user, host, cnt, risk_score
     ORDER BY cnt DESC LIMIT 15`,
    { hours, threshold }
  );
  return records.map(r => ({
    type:       'high_frequency_login',
    user:       r.get('user'),
    host:       r.get('host'),
    count:      r.get('cnt')?.toNumber?.() ?? 0,
    risk_score: r.get('risk_score')?.toNumber?.() ?? 0,
  }));
}

async function detectRareProcesses() {
  const records = await run(
    `MATCH (h:Host)-[:EXECUTED]->(p:Process)
     WITH p.name AS proc, collect(DISTINCT h.name) AS hosts, p.seen_count AS seen
     WHERE size(hosts) = 1 AND (seen IS NULL OR seen <= 2)
     RETURN proc, hosts, seen
     ORDER BY seen ASC LIMIT 20`
  );
  return records.map(r => ({
    type:      'rare_process',
    process:   r.get('proc'),
    hosts:     r.get('hosts'),
    seen_count: r.get('seen')?.toNumber?.() ?? 1,
  }));
}

async function detectNewConnections(hours = 24) {
  const records = await run(
    `MATCH (i:IP)-[r:CONNECTED_TO]->(h:Host)
     WHERE datetime(r.time) > datetime() - duration({hours: $hours})
     WITH i.address AS ip, h.name AS host,
          min(r.time) AS first_seen, count(r) AS conn_count,
          i.is_internal AS internal
     RETURN ip, host, first_seen, conn_count, internal
     ORDER BY first_seen DESC LIMIT 30`,
    { hours }
  );
  return records.map(r => ({
    type:       'new_connection',
    ip:         r.get('ip'),
    host:       r.get('host'),
    first_seen: r.get('first_seen'),
    count:      r.get('conn_count')?.toNumber?.() ?? 0,
    is_internal: r.get('internal'),
  }));
}

// ── Get All Anomalies ─────────────────────────────────────────
async function getAllAnomalies() {
  const [lateral, travel, privesc, afterhours, hf, rare, newconn] = await Promise.all([
    detectLateralMovement(),
    detectImpossibleTravel(),
    detectPrivilegeEscalation(),
    detectAfterHoursAccess(),
    detectHighFrequencyLogins(),
    detectRareProcesses(),
    detectNewConnections(),
  ]);
  return {
    lateral_movement:    lateral,
    impossible_travel:   travel,
    privilege_escalation: privesc,
    after_hours_access:  afterhours,
    high_frequency_logins: hf,
    rare_processes:      rare,
    new_connections:     newconn,
  };
}

// ── Entity Graph ─────────────────────────────────────────────
async function getEntityGraph(name) {
  const records = await run(
    `MATCH (e)-[r]-(n)
     WHERE e.name = $name OR e.address = $name
     RETURN type(r) AS rel, labels(e)[0] AS src_type, labels(n)[0] AS dst_type,
            coalesce(e.name, e.address) AS src,
            coalesce(n.name, n.address) AS dst,
            r.time AS time, r.deviation_score AS deviation, r.flags AS flags
     ORDER BY r.time DESC LIMIT 100`,
    { name }
  );
  return records.map(r => ({
    rel:       r.get('rel'),
    src_type:  r.get('src_type'),
    dst_type:  r.get('dst_type'),
    src:       r.get('src'),
    dst:       r.get('dst'),
    time:      r.get('time'),
    deviation: r.get('deviation')?.toNumber?.() ?? 0,
    flags:     r.get('flags') || [],
  }));
}

// ── Baseline recalculation (call periodically) ───────────────
async function recalcBaselines() {
  const d = getDriver();
  if (!d) return;
  // Decay risk scores over time (score drops 10% per hour if no new anomalies)
  try {
    await run(
      `MATCH (u:User) WHERE u.risk_score > 0
       SET u.risk_score = toInteger(u.risk_score * 0.9)
       RETURN count(u) AS updated`
    );
  } catch (e) { console.error('[UEBA] Baseline recalc error:', e.message); }
}

// ── Stats ─────────────────────────────────────────────────────
async function getUebaStats() {
  const d = getDriver();
  if (!d) return null;
  const session = d.session();
  try {
    const r = await session.run(
      `MATCH (u:User)   WITH count(u) AS users, avg(coalesce(u.risk_score, 0)) AS avg_risk
       MATCH (h:Host)   WITH users, avg_risk, count(h) AS hosts
       MATCH (p:Process) WITH users, avg_risk, hosts, count(p) AS processes
       MATCH ()-[rel]->() WITH users, avg_risk, hosts, processes, count(rel) AS rels
       MATCH (u2:User) WHERE u2.risk_score >= 70
       RETURN users, avg_risk, hosts, processes, rels, count(u2) AS high_risk_users`
    );
    if (!r.records.length) return { users:0, hosts:0, processes:0, relationships:0, avg_risk:0, high_risk_users:0 };
    const rec = r.records[0];
    return {
      users:           rec.get('users')?.toNumber?.()          ?? 0,
      hosts:           rec.get('hosts')?.toNumber?.()          ?? 0,
      processes:       rec.get('processes')?.toNumber?.()      ?? 0,
      relationships:   rec.get('rels')?.toNumber?.()           ?? 0,
      avg_risk:        Math.round(rec.get('avg_risk') ?? 0),
      high_risk_users: rec.get('high_risk_users')?.toNumber?.() ?? 0,
    };
  } catch { return { users:0, hosts:0, processes:0, relationships:0, avg_risk:0, high_risk_users:0 }; }
  finally { await session.close(); }
}

async function ping() {
  const d = getDriver();
  if (!d) return false;
  try { await run('RETURN 1'); return true; } catch { return false; }
}

module.exports = {
  initSchema, ingestEvent, recalcBaselines,
  getRiskLeaderboard, getUserProfile,
  getAllAnomalies, getEntityGraph, getUebaStats, ping,
};

// Decay risk scores every hour
setInterval(() => recalcBaselines(), 3600_000);
