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

// Centralised anomaly severity weights (0–100 scale)
const ANOMALY_WEIGHTS = {
  impossible_travel:    95,
  lateral_movement:     85,
  privilege_escalation: 80,
  new_host_access:      75,
  new_process:          70,
  after_hours_access:   55,
  high_frequency_login: 50,
};

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

function toNeo4jParams(params) {
  const neo4j = require('neo4j-driver');
  const out = {};
  for (const [k, v] of Object.entries(params)) {
    out[k] = Number.isInteger(v) ? neo4j.int(v) : v;
  }
  return out;
}

async function run(cypher, params = {}) {
  const d = getDriver();
  if (!d) return [];
  const session = d.session();
  try {
    const result = await session.run(cypher, toNeo4jParams(params));
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
  return isNew ? ANOMALY_WEIGHTS.new_host_access : 0;
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
          deviationScore = Math.max(deviationScore, ANOMALY_WEIGHTS.impossible_travel);
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
      const procScore = isNewProc ? ANOMALY_WEIGHTS.new_process : 0;

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
         WITH u, coalesce(u.risk_score, 0) * 0.85 + $dev * 0.15 AS newScore
         SET u.risk_score = toInteger(CASE WHEN newScore > 100 THEN 100 ELSE newScore END),
             u.last_anomaly = $ts,
             u.anomaly_count = coalesce(u.anomaly_count, 0) + 1`,
        { user, dev: deviationScore, ts }
      );
    }
    if (deviationScore > 30 && host) {
      await session.run(
        `MATCH (h:Host {name: $host})
         WITH h, coalesce(h.risk_score, 0) * 0.85 + $dev * 0.15 AS newScore
         SET h.risk_score = toInteger(CASE WHEN newScore > 100 THEN 100 ELSE newScore END)`,
        { host, dev: deviationScore }
      );
    }

  } finally {
    await session.close();
  }
}

// ── Risk Leaderboard ─────────────────────────────────────────
async function getRiskLeaderboard(limit = 20, skip = 0, hours = 24, q = '', minScore = 0) {
  const d = getDriver();
  if (!d) return { users: [], total: 0 };
  const neo4j = require('neo4j-driver');
  const s1 = d.session(), s2 = d.session();
  const searchClause = q
    ? `AND toLower(u.name) CONTAINS toLower($q)`
    : '';
  try {
    const [dataRes, countRes] = await Promise.all([
      s1.run(
        `MATCH (u:User)
         WHERE u.total_events > 0 AND coalesce(u.risk_score, 0) >= $minScore ${searchClause}
         OPTIONAL MATCH (u)-[r:LOGGED_IN]->(h:Host)
         WHERE r.time >= toString(datetime() - duration({hours: $hours}))
         WITH u, count(r) AS events_period, collect(DISTINCT h.name)[..5] AS recent_hosts
         RETURN u.name AS user,
                coalesce(u.risk_score, 0) AS risk_score,
                coalesce(u.anomaly_count, 0) AS anomaly_count,
                u.last_anomaly AS last_anomaly,
                u.baseline_computed_at AS baseline_computed_at,
                events_period, recent_hosts
         ORDER BY risk_score DESC, u.total_events DESC SKIP $skip LIMIT $limit`,
        { limit: neo4j.int(limit), skip: neo4j.int(skip), hours: neo4j.int(hours), q, minScore: neo4j.int(minScore) }
      ),
      s2.run(
        `MATCH (u:User) WHERE u.total_events > 0 AND coalesce(u.risk_score, 0) >= $minScore ${searchClause} RETURN count(u) AS total`,
        { q, minScore: neo4j.int(minScore) }
      ),
    ]);
    const users = dataRes.records.map(r => ({
      user:                  r.get('user'),
      risk_score:            r.get('risk_score')?.toNumber?.() ?? r.get('risk_score') ?? 0,
      anomaly_count:         r.get('anomaly_count')?.toNumber?.() ?? 0,
      last_anomaly:          r.get('last_anomaly'),
      baseline_computed_at:  r.get('baseline_computed_at') || null,
      events_period:         r.get('events_period')?.toNumber?.() ?? 0,
      recent_hosts:          r.get('recent_hosts') || [],
    }));
    const total = countRes.records[0]?.get('total')?.toNumber?.() ?? 0;
    return { users, total };
  } finally { await Promise.all([s1.close(), s2.close()]); }
}

// ── Behavioral Profile per User / Host / IP ──────────────────
async function getUserProfile(entity) {
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(entity);

  // IP address — look up IP node and its connections
  if (isIp) {
    const records = await run(
      `MATCH (i:IP {address: $addr})
       OPTIONAL MATCH (i)-[r:CONNECTED_TO]->(h:Host)
       OPTIONAL MATCH (u:User)-[l:LOGGED_IN]->(h2:Host)
       WHERE l.src_ip = $addr
       WITH i,
            collect(DISTINCT {host: h.name, time: r.time, dev: r.deviation_score, rule: r.rule_id}) AS connections,
            collect(DISTINCT {user: u.name, host: h2.name, time: l.time, dev: l.deviation_score, flags: l.flags}) AS user_logins
       RETURN i, connections[..30] AS connections, user_logins[..30] AS user_logins`,
      { addr: entity }
    );
    if (!records.length) return null;
    const props = records[0].get('i').properties;
    const connections = records[0].get('connections') || [];
    const userLogins  = records[0].get('user_logins') || [];
    return {
      name:         entity,
      entity_type:  'ip',
      is_internal:  props.is_internal ?? false,
      first_seen:   props.first_seen,
      last_seen:    props.last_seen,
      risk_score:   0,
      connections:  connections.filter(c => c.host),
      recent_logins: userLogins.filter(l => l.user).map(l => ({
        host:      l.host,
        user:      l.user,
        time:      l.time,
        deviation: l.dev?.toNumber?.() ?? l.dev ?? 0,
        flags:     l.flags || [],
      })),
      all_hosts: [...new Set(connections.map(c => c.host).filter(Boolean))],
    };
  }

  // User or Host — try User first, then Host
  const rec = await runSingle(
    `MATCH (u:User {name: $name})
     OPTIONAL MATCH (u)-[r:LOGGED_IN]->(h:Host)
     WITH u, collect(DISTINCT h.name) AS all_hosts,
          collect({host: h.name, time: r.time, dev: r.deviation_score, flags: r.flags, src_ip: r.src_ip}) AS logins
     RETURN u, all_hosts, logins[..50] AS recent_logins`,
    { name: entity }
  );

  if (rec) {
    const u = rec.get('u').properties;
    return {
      name:          u.name,
      entity_type:   'user',
      risk_score:    u.risk_score?.toNumber?.() ?? u.risk_score ?? 0,
      anomaly_count: u.anomaly_count?.toNumber?.() ?? 0,
      total_events:  u.total_events?.toNumber?.() ?? 0,
      typical_hours: u.typical_hours || [],
      last_seen:     u.last_seen,
      last_anomaly:  u.last_anomaly,
      all_hosts:     rec.get('all_hosts') || [],
      recent_logins: (rec.get('recent_logins') || []).map(l => ({
        host:      l.host,
        time:      l.time,
        src_ip:    l.src_ip,
        deviation: l.dev?.toNumber?.() ?? l.dev ?? 0,
        flags:     l.flags || [],
      })),
    };
  }

  // Try Host node
  const hrec = await runSingle(
    `MATCH (h:Host {name: $name})
     OPTIONAL MATCH (u:User)-[r:LOGGED_IN]->(h)
     WITH h, collect(DISTINCT u.name) AS users,
          collect({user: u.name, time: r.time, dev: r.deviation_score, flags: r.flags}) AS logins
     RETURN h, users, logins[..50] AS recent_logins`,
    { name: entity }
  );
  if (hrec) {
    const h = hrec.get('h').properties;
    return {
      name:          h.name,
      entity_type:   'host',
      risk_score:    h.risk_score?.toNumber?.() ?? h.risk_score ?? 0,
      first_seen:    h.first_seen,
      last_seen:     h.last_seen,
      all_users:     hrec.get('users') || [],
      recent_logins: (hrec.get('recent_logins') || []).map(l => ({
        user:      l.user,
        time:      l.time,
        deviation: l.dev?.toNumber?.() ?? l.dev ?? 0,
        flags:     l.flags || [],
      })),
    };
  }

  return null;
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

// ── Multi-Stage Attack Correlation ───────────────────────────
// Same user triggered ≥2 distinct anomaly flag types in window
async function detectMultiStageAttack(hours = 24) {
  const records = await run(
    `MATCH (u:User)-[r:LOGGED_IN]->(h:Host)
     WHERE datetime(r.time) > datetime() - duration({hours: $hours})
       AND size(r.flags) > 0
     WITH u.name AS user, u.risk_score AS risk_score,
          collect(DISTINCT r.flags) AS all_flag_lists,
          count(DISTINCT h.name) AS host_count,
          max(coalesce(r.deviation_score, 0)) AS max_dev
     WITH user, risk_score, host_count, max_dev,
          reduce(s=[], fl IN all_flag_lists | s + [f IN fl WHERE NOT f IN s | f]) AS unique_flags
     WHERE size(unique_flags) >= 2
     RETURN user, risk_score, unique_flags, host_count, max_dev
     ORDER BY size(unique_flags) DESC, max_dev DESC LIMIT 15`,
    { hours }
  );
  return records.map(r => ({
    type:         'multi_stage_attack',
    user:         r.get('user'),
    risk_score:   r.get('risk_score')?.toNumber?.() ?? 0,
    flags:        r.get('unique_flags') || [],
    host_count:   r.get('host_count')?.toNumber?.() ?? 0,
    max_deviation: r.get('max_dev')?.toNumber?.() ?? 0,
  }));
}

// ── Shared Credentials / Credential Abuse ────────────────────
// Same src_ip used by ≥2 distinct users in window — possible cred sharing or pivot
async function detectSharedCredentials(hours = 24) {
  const records = await run(
    `MATCH (u:User)-[r:LOGGED_IN]->(h:Host)
     WHERE datetime(r.time) > datetime() - duration({hours: $hours})
       AND r.src_ip <> ''
     WITH r.src_ip AS ip, collect(DISTINCT u.name) AS users,
          collect(DISTINCT h.name) AS hosts, count(r) AS total_logins
     WHERE size(users) >= 2
     RETURN ip, users, hosts, total_logins
     ORDER BY size(users) DESC, total_logins DESC LIMIT 15`,
    { hours }
  );
  return records.map(r => ({
    type:         'shared_credentials',
    ip:           r.get('ip'),
    users:        r.get('users') || [],
    hosts:        r.get('hosts') || [],
    total_logins: r.get('total_logins')?.toNumber?.() ?? 0,
  }));
}

// ── Force-Graph Data for Entity Visualisation ─────────────────
// Returns { nodes: [...], edges: [...] } in D3-force format
async function getGraphNodes(entity) {
  const records = await run(
    `MATCH (e)-[r]-(n)
     WHERE e.name = $name OR e.address = $name
     RETURN labels(e)[0]                AS src_type,
            coalesce(e.name, e.address) AS src,
            coalesce(e.risk_score, 0)   AS src_risk,
            coalesce(e.total_events, 0) AS src_events,
            coalesce(e.anomaly_count, 0) AS src_anomalies,
            e.last_seen                 AS src_last_seen,
            e.last_anomaly              AS src_last_anomaly,
            type(r)                     AS rel,
            labels(n)[0]               AS dst_type,
            coalesce(n.name, n.address) AS dst,
            coalesce(n.risk_score, 0)   AS dst_risk,
            coalesce(n.total_events, 0) AS dst_events,
            coalesce(n.anomaly_count, 0) AS dst_anomalies,
            n.last_seen                 AS dst_last_seen,
            n.last_anomaly              AS dst_last_anomaly,
            r.deviation_score           AS deviation,
            r.flags                     AS flags,
            r.time                      AS time
     ORDER BY r.time DESC LIMIT 120`,
    { name: entity }
  );

  const nodesMap = new Map();
  const edges = [];

  const addNode = (id, type, risk, events, anomalies, last_seen, last_anomaly) => {
    if (!nodesMap.has(id)) {
      nodesMap.set(id, {
        id,
        type:        type || 'Unknown',
        risk:        risk?.toNumber?.()       ?? risk       ?? 0,
        events:      events?.toNumber?.()     ?? events     ?? 0,
        anomalies:   anomalies?.toNumber?.()  ?? anomalies  ?? 0,
        last_seen:   last_seen   || null,
        last_anomaly: last_anomaly || null,
      });
    }
  };

  for (const r of records) {
    const src = r.get('src'); const dst = r.get('dst');
    if (!src || !dst) continue;
    addNode(src, r.get('src_type'), r.get('src_risk'),
            r.get('src_events'), r.get('src_anomalies'),
            r.get('src_last_seen'), r.get('src_last_anomaly'));
    addNode(dst, r.get('dst_type'), r.get('dst_risk'),
            r.get('dst_events'), r.get('dst_anomalies'),
            r.get('dst_last_seen'), r.get('dst_last_anomaly'));
    edges.push({
      source:    src,
      target:    dst,
      rel:       r.get('rel'),
      deviation: r.get('deviation')?.toNumber?.() ?? 0,
      flags:     r.get('flags') || [],
      time:      r.get('time'),
    });
  }

  return { nodes: [...nodesMap.values()], edges };
}

// ── Get All Anomalies ─────────────────────────────────────────
// Each detection query gets an individual 8s timeout — slow queries return []
// rather than blocking the whole response. Uses allSettled so one failure
// never prevents the other 8 results from rendering.
async function getAllAnomalies(hours = 24) {
  const withTimeout = (promise, ms = 8000) =>
    Promise.race([promise, new Promise(res => setTimeout(() => res([]), ms))]);

  const [lateral, travel, privesc, afterhours, hf, rare, newconn, multistage, sharedcreds] =
    await Promise.allSettled([
      withTimeout(detectLateralMovement(hours)),
      withTimeout(detectImpossibleTravel()),
      withTimeout(detectPrivilegeEscalation(hours)),
      withTimeout(detectAfterHoursAccess(hours)),
      withTimeout(detectHighFrequencyLogins()),
      withTimeout(detectRareProcesses()),
      withTimeout(detectNewConnections(hours)),
      withTimeout(detectMultiStageAttack(hours)),
      withTimeout(detectSharedCredentials(hours)),
    ]).then(results => results.map(r => (r.status === 'fulfilled' ? r.value : [])));

  return {
    lateral_movement:      lateral,
    impossible_travel:     travel,
    privilege_escalation:  privesc,
    after_hours_access:    afterhours,
    high_frequency_logins: hf,
    rare_processes:        rare,
    new_connections:       newconn,
    multi_stage_attacks:   multistage,
    shared_credentials:    sharedcreds,
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
    // Use OPTIONAL MATCH + inline high_risk aggregation so the query always
    // returns exactly 1 row even when no users have risk_score >= 70.
    const r = await session.run(
      `MATCH (u:User)
       WITH count(u) AS users,
            avg(coalesce(u.risk_score, 0)) AS avg_risk,
            sum(CASE WHEN coalesce(u.risk_score, 0) >= 70 THEN 1 ELSE 0 END) AS high_risk_users
       OPTIONAL MATCH (h:Host)
       WITH users, avg_risk, high_risk_users, count(h) AS hosts
       OPTIONAL MATCH (p:Process)
       WITH users, avg_risk, high_risk_users, hosts, count(p) AS processes
       OPTIONAL MATCH ()-[rel]->()
       RETURN users, avg_risk, high_risk_users, hosts, processes, count(rel) AS rels`
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

// ── Risk Score Backfill ────────────────────────────────────────
// Recalculates risk_score for all users based on historical LOGGED_IN
// relationship deviation scores using the EWMA closed-form approximation:
//   score ≈ avg_dev * (1 - 0.85^n)  where n = anomaly event count
async function backfillRiskScores() {
  const d = getDriver();
  if (!d) return { updated: 0 };
  try {
    const recs = await run(
      `MATCH (u:User)-[r:LOGGED_IN]->()
       WHERE r.deviation_score > 30
       WITH u, count(r) AS n, avg(r.deviation_score) AS avgDev
       WITH u, n, avgDev,
            toInteger(CASE WHEN avgDev*(1.0-0.85^n) > 100 THEN 100
                           ELSE avgDev*(1.0-0.85^n) END) AS score
       SET u.risk_score = score, u.anomaly_count = n
       RETURN count(u) AS updated`
    );
    const updated = recs[0]?.get('updated')?.toNumber?.() ?? 0;
    console.log(`[UEBA] Risk score backfill complete — ${updated} users updated`);

    // Fire-and-forget: compute 30d behavioral baseline for top-100 risk users
    setImmediate(async () => {
      try {
        const topUsers = await run(
          `MATCH (u:User) WHERE u.risk_score IS NOT NULL
           RETURN u.name AS name ORDER BY u.risk_score DESC LIMIT 100`
        );
        let baselined = 0;
        for (const r of topUsers) {
          const name = r.get('name');
          if (name) { await computeEntityBaseline(name); baselined++; }
        }
        if (baselined) console.log(`[UEBA] Baseline computed for ${baselined} top-risk users`);
      } catch (e) {
        console.error('[UEBA] Baseline backfill error:', e.message);
      }
    });

    return { updated };
  } catch(e) {
    console.error('[UEBA] Backfill error:', e.message);
    return { updated: 0, error: e.message };
  }
}

// ── Per-Entity Behavioral Baseline (30-day rolling) ──────────────────
// Populates typical_hosts (string list), baseline_hours_json (JSON string),
// baseline_avg_events, and baseline_computed_at on the User node.
// Re-uses existing typical_hours / typical_hosts properties for new storage.
// 6-hour TTL guard prevents expensive re-computation on every call.
async function computeEntityBaseline(entity) {
  // Check TTL — return stored baseline if fresh
  const stored = await runSingle(
    `MATCH (u:User {name: $name})
     RETURN u.baseline_computed_at AS computed_at,
            u.typical_hosts        AS hosts,
            u.baseline_hours_json  AS hours_json,
            u.baseline_avg_events  AS avg_events`,
    { name: entity }
  );

  if (stored) {
    const computedAt = stored.get('computed_at');
    if (computedAt && Date.now() - new Date(computedAt).getTime() < 6 * 3600 * 1000) {
      let typicalHours = [];
      try { typicalHours = JSON.parse(stored.get('hours_json') || '[]'); } catch {}
      return {
        entity,
        typical_hours:        typicalHours,
        typical_hosts:        stored.get('hosts') || [],
        baseline_avg_events:  stored.get('avg_events')?.toNumber?.() ?? stored.get('avg_events') ?? 0,
        baseline_computed_at: computedAt,
        from_cache:           true,
      };
    }
  }

  // Entity not found in graph
  if (!stored) return null;

  // Query 30d of LOGGED_IN relationships
  const recs = await run(
    `MATCH (u:User {name: $name})-[r:LOGGED_IN]->(h:Host)
     WHERE datetime(r.time) > datetime() - duration({days: 30})
     RETURN datetime(r.time).hour AS hr, h.name AS host`,
    { name: entity }
  );

  if (!recs.length) {
    return { entity, typical_hours: [], typical_hosts: [], baseline_avg_events: 0,
             baseline_computed_at: null, from_cache: false, events_analyzed: 0 };
  }

  const hourCounts = {};
  const hostSet    = new Set();
  for (const rec of recs) {
    const hr   = rec.get('hr')?.toNumber?.()   ?? rec.get('hr')   ?? 0;
    const host = rec.get('host');
    hourCounts[hr] = (hourCounts[hr] || 0) + 1;
    if (host) hostSet.add(host);
  }

  const typicalHours = Object.entries(hourCounts)
    .map(([hour, freq]) => ({ hour: parseInt(hour), freq }))
    .sort((a, b) => b.freq - a.freq);

  const typicalHosts = [...hostSet];
  const avgEvents    = Math.round(recs.length / 30);
  const computedAt   = new Date().toISOString();

  await run(
    `MATCH (u:User {name: $name})
     SET u.typical_hosts        = $hosts,
         u.baseline_hours_json  = $hoursJson,
         u.baseline_avg_events  = $avgEvents,
         u.baseline_computed_at = $computedAt`,
    { name: entity, hosts: typicalHosts, hoursJson: JSON.stringify(typicalHours), avgEvents, computedAt }
  );

  return {
    entity,
    typical_hours:        typicalHours,
    typical_hosts:        typicalHosts,
    baseline_avg_events:  avgEvents,
    baseline_computed_at: computedAt,
    from_cache:           false,
    events_analyzed:      recs.length,
  };
}

// Assesses false-positive likelihood for an entity's recent anomalies.
// Only after_hours_access and new_host_access types are assessable —
// other anomaly types are left unscored to avoid false confidence.
async function assessEntityFP(entity) {
  const baseline = await computeEntityBaseline(entity);
  if (!baseline || (!baseline.typical_hours.length && !baseline.typical_hosts.length)) {
    return { entity, assessable: false, reason: 'No baseline data' };
  }

  const recs = await run(
    `MATCH (u:User {name: $name})-[r:LOGGED_IN]->(h:Host)
     WHERE datetime(r.time) > datetime() - duration({hours: 24})
       AND any(f IN r.flags WHERE f IN ['after_hours_access','unusual_hour','new_host_access'])
     RETURN datetime(r.time).hour AS hr, h.name AS host, r.flags AS flags, r.time AS time
     ORDER BY r.time DESC LIMIT 50`,
    { name: entity }
  );

  if (!recs.length) {
    return { entity, assessable: false, reason: 'No anomalous events in last 24h' };
  }

  const hourSet = new Set(baseline.typical_hours.map(e => e.hour));
  const hostSet = new Set(baseline.typical_hosts);
  const factors = [];
  let withinCount = 0, totalCount = 0;

  for (const rec of recs) {
    const hr    = rec.get('hr')?.toNumber?.()   ?? rec.get('hr')   ?? 0;
    const host  = rec.get('host');
    const flags = rec.get('flags') || [];
    const time  = rec.get('time');

    if (flags.includes('after_hours_access') || flags.includes('unusual_hour')) {
      totalCount++;
      const inBaseline = hourSet.has(hr);
      if (inBaseline) withinCount++;
      factors.push({
        type:      'after_hours_access',
        fp_likely: inBaseline,
        detail:    `Hour ${hr}h ${inBaseline ? 'is within' : 'is outside'} 30d baseline (${hourSet.size} typical hours tracked)`,
        time,
      });
    }

    if (flags.includes('new_host_access')) {
      totalCount++;
      const inBaseline = hostSet.has(host);
      if (inBaseline) withinCount++;
      factors.push({
        type:      'new_host_access',
        fp_likely: inBaseline,
        detail:    `Host "${host}" ${inBaseline ? 'is a known host in' : 'is absent from'} 30d baseline (${hostSet.size} hosts tracked)`,
        time,
      });
    }
  }

  if (!totalCount) {
    return { entity, assessable: false, reason: 'No assessable anomaly types in recent events' };
  }

  return {
    entity,
    assessable:       true,
    fp_score:         Math.round((withinCount / totalCount) * 100),
    within_baseline:  withinCount === totalCount,
    events_assessed:  totalCount,
    factors:          factors.slice(0, 20),
  };
}

async function ping() {
  const d = getDriver();
  if (!d) return false;
  try { await run('RETURN 1'); return true; } catch { return false; }
}

// ── Attack-Path Finding ───────────────────────────────────────
// Returns shortest path between two entities using Neo4j shortestPath().
// Returns null when no path exists or entities are not in graph.
async function getAttackPath(fromEntity, toEntity) {
  const records = await run(
    `MATCH (a), (b)
     WHERE (a.name = $from OR a.address = $from)
       AND (b.name = $to   OR b.address = $to)
     WITH a, b LIMIT 1
     MATCH path = shortestPath((a)-[*..10]-(b))
     WITH path, nodes(path) AS ns, relationships(path) AS rs
     RETURN
       [n IN ns | {
         id:         coalesce(n.name, n.address),
         type:       labels(n)[0],
         risk:       coalesce(n.risk_score, 0),
         events:     coalesce(n.total_events, 0),
         anomalies:  coalesce(n.anomaly_count, 0),
         last_seen:  n.last_seen,
         last_anomaly: n.last_anomaly
       }] AS path_nodes,
       [r IN rs | {
         rel:       type(r),
         deviation: coalesce(r.deviation_score, 0),
         flags:     r.flags,
         time:      r.time
       }] AS path_rels,
       length(path) AS hops
     LIMIT 1`,
    { from: fromEntity, to: toEntity }
  );
  if (!records.length) return null;
  const rec = records[0];
  const pathNodes = rec.get('path_nodes').map(n => ({
    id:          n.id,
    type:        n.type || 'Unknown',
    risk:        n.risk?.toNumber?.()       ?? n.risk       ?? 0,
    events:      n.events?.toNumber?.()     ?? n.events     ?? 0,
    anomalies:   n.anomalies?.toNumber?.()  ?? n.anomalies  ?? 0,
    last_seen:   n.last_seen   || null,
    last_anomaly: n.last_anomaly || null,
  }));
  const pathEdges = rec.get('path_rels').map((e, i) => ({
    source:    pathNodes[i]?.id,
    target:    pathNodes[i + 1]?.id,
    rel:       e.rel,
    deviation: e.deviation?.toNumber?.() ?? e.deviation ?? 0,
    flags:     e.flags || [],
    time:      e.time,
  }));
  const hops = rec.get('hops')?.toNumber?.() ?? rec.get('hops') ?? 0;
  const maxDeviation = pathEdges.length ? Math.max(...pathEdges.map(e => e.deviation)) : 0;
  return { nodes: pathNodes, edges: pathEdges, hops, maxDeviation, from: fromEntity, to: toEntity };
}

// ── 24h Anomaly Timeline per Entity (for sparkline) ─────────────
// Returns 24 hourly buckets: [{hour_offset:-23..0, count, max_deviation}]
async function getEntityTimeline(entity, hours = 24) {
  const buckets = Array.from({ length: hours }, (_, i) => ({
    hour_offset: -(hours - 1 - i),
    count: 0,
    max_deviation: 0,
  }));

  try {
    const recs = await run(
      `MATCH (e)-[r]-()
       WHERE (e.name = $name OR e.address = $name)
         AND r.time IS NOT NULL
         AND datetime(r.time) > datetime() - duration({hours: $hours})
       RETURN datetime(r.time) AS t,
              coalesce(r.deviation_score, 0) AS dev,
              r.flags AS flags`,
      { name: entity, hours: require('neo4j-driver').int(hours) }
    );

    const now = Date.now();
    for (const rec of recs) {
      const t = rec.get('t');
      if (!t) continue;
      const ts = new Date(
        Number(t.year) + '-' +
        String(Number(t.month)).padStart(2, '0') + '-' +
        String(Number(t.day)).padStart(2, '0') + 'T' +
        String(Number(t.hour)).padStart(2, '0') + ':' +
        String(Number(t.minute)).padStart(2, '0') + ':00Z'
      ).getTime();
      if (!ts) continue;
      const hoursAgo = Math.floor((now - ts) / 3_600_000);
      if (hoursAgo < 0 || hoursAgo >= hours) continue;
      const idx = hours - 1 - hoursAgo;
      const dev = rec.get('dev')?.toNumber?.() ?? rec.get('dev') ?? 0;
      const flags = rec.get('flags') || [];
      // Count only anomalous events (deviation >= 30 OR has flags)
      if (dev >= 30 || flags.length > 0) {
        buckets[idx].count++;
        if (dev > buckets[idx].max_deviation) buckets[idx].max_deviation = dev;
      }
    }
  } catch (e) {
    console.warn('[UEBA] getEntityTimeline error:', e.message);
  }

  return buckets;
}

// ── Critical Watchlist — top N risk entities with rich detail ───
// One query returns: top entities + their recent anomaly flag breakdown
// for the watchlist hero cards.
async function getCriticalWatchlist(limit = 5, hours = 24) {
  const d = getDriver();
  if (!d) return [];
  const neo4j = require('neo4j-driver');
  try {
    const recs = await run(
      `MATCH (u:User)
       WHERE coalesce(u.risk_score, 0) >= 40
       OPTIONAL MATCH (u)-[r:LOGGED_IN]->(h:Host)
       WHERE r.time IS NOT NULL
         AND datetime(r.time) > datetime() - duration({hours: $hours})
       WITH u,
            count(r) AS events,
            collect(DISTINCT h.name)[..5] AS hosts,
            [f IN apoc.coll.flatten(collect(r.flags)) | f] AS allFlags
       RETURN u.name AS entity,
              'user' AS entity_type,
              coalesce(u.risk_score, 0) AS risk_score,
              coalesce(u.anomaly_count, 0) AS anomaly_count,
              u.last_anomaly AS last_anomaly,
              u.last_seen AS last_seen,
              events,
              hosts,
              allFlags AS flags
       ORDER BY risk_score DESC, u.total_events DESC LIMIT $limit`,
      { limit: neo4j.int(limit), hours: neo4j.int(hours) }
    ).catch(async () => {
      // Fallback if APOC not available — fetch flags manually
      return run(
        `MATCH (u:User)
         WHERE coalesce(u.risk_score, 0) >= 40
         OPTIONAL MATCH (u)-[r:LOGGED_IN]->(h:Host)
         WHERE r.time IS NOT NULL
           AND datetime(r.time) > datetime() - duration({hours: $hours})
         WITH u, count(r) AS events,
              collect(DISTINCT h.name)[..5] AS hosts,
              collect(r.flags) AS flagLists
         RETURN u.name AS entity,
                'user' AS entity_type,
                coalesce(u.risk_score, 0) AS risk_score,
                coalesce(u.anomaly_count, 0) AS anomaly_count,
                u.last_anomaly AS last_anomaly,
                u.last_seen AS last_seen,
                events, hosts,
                flagLists AS flags
         ORDER BY risk_score DESC, u.total_events DESC LIMIT $limit`,
        { limit: neo4j.int(limit), hours: neo4j.int(hours) }
      );
    });

    return recs.map(r => {
      // Flatten flag lists if returned as array of arrays
      const rawFlags = r.get('flags') || [];
      const flatFlags = Array.isArray(rawFlags[0])
        ? rawFlags.flat().filter(Boolean)
        : rawFlags.filter(Boolean);
      // Tally flag types
      const flagCounts = {};
      for (const f of flatFlags) flagCounts[f] = (flagCounts[f] || 0) + 1;
      return {
        entity:        r.get('entity'),
        entity_type:   r.get('entity_type'),
        risk_score:    r.get('risk_score')?.toNumber?.() ?? r.get('risk_score') ?? 0,
        anomaly_count: r.get('anomaly_count')?.toNumber?.() ?? 0,
        last_anomaly:  r.get('last_anomaly'),
        last_seen:     r.get('last_seen'),
        events:        r.get('events')?.toNumber?.() ?? 0,
        hosts:         r.get('hosts') || [],
        flag_breakdown: flagCounts,
      };
    });
  } catch (e) {
    console.warn('[UEBA] getCriticalWatchlist error:', e.message);
    return [];
  }
}

async function purgeOldData(daysOld = 30) {
  const cutoff = new Date(Date.now() - daysOld * 86400_000).toISOString();
  const results = {};

  // Delete relationships older than cutoff
  const relDel = await run(
    `MATCH ()-[r]->()
     WHERE r.timestamp IS NOT NULL AND r.timestamp < $cutoff
     WITH r LIMIT 50000
     DELETE r RETURN count(r) AS deleted`,
    { cutoff }
  );
  results.relationships = relDel[0]?.deleted?.toNumber?.() ?? 0;

  // Delete orphaned non-User nodes (Process, IP nodes with no recent activity)
  const nodeDel = await run(
    `MATCH (n)
     WHERE NOT n:User AND NOT n:Host
       AND (n.last_seen < $cutoff OR (n.last_seen IS NULL AND n.first_seen < $cutoff))
     WITH n LIMIT 10000
     DETACH DELETE n RETURN count(n) AS deleted`,
    { cutoff }
  );
  results.nodes = nodeDel[0]?.deleted?.toNumber?.() ?? 0;

  // Reset risk scores to 0 for users/hosts with no recent activity
  const resetDel = await run(
    `MATCH (n)
     WHERE (n:User OR n:Host)
       AND n.last_seen < $cutoff
     SET n.risk_score = 0, n.anomaly_count = 0
     RETURN count(n) AS reset`,
    { cutoff }
  );
  results.risk_scores_reset = resetDel[0]?.reset?.toNumber?.() ?? 0;

  return results;
}

module.exports = {
  initSchema, ingestEvent, recalcBaselines, backfillRiskScores,
  getRiskLeaderboard, getUserProfile,
  getAllAnomalies, getEntityGraph, getUebaStats, ping,
  detectLateralMovement,
  detectMultiStageAttack, detectSharedCredentials,
  getGraphNodes, getAttackPath,
  computeEntityBaseline, assessEntityFP,
  getEntityTimeline, getCriticalWatchlist,
  purgeOldData,
  ANOMALY_WEIGHTS,
};

// Decay risk scores every hour
setInterval(() => recalcBaselines(), 3600_000);
