// ============================================================
//  SOCPilots — Neo4j UEBA Layer
//  Graph-based User & Entity Behavior Analytics
//  Community Edition — free forever
// ============================================================
let driver = null;

function getDriver() {
  if (driver) return driver;
  const neo4j = require('neo4j-driver');
  const uri  = process.env.NEO4J_URI      || 'bolt://neo4j:7687';
  const user = process.env.NEO4J_USER     || 'neo4j';
  const pass = process.env.NEO4J_PASSWORD || '';
  if (!pass) { console.warn('[NEO4J] NEO4J_PASSWORD not set — UEBA disabled'); return null; }
  driver = neo4j.driver(uri, neo4j.auth.basic(user, pass), {
    maxConnectionPoolSize: 5,
    connectionTimeoutMs: 5000,
  });
  console.log('[NEO4J] Driver initialised →', uri);
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

// Create indexes on first use (idempotent)
async function initSchema() {
  const d = getDriver();
  if (!d) return;
  const session = d.session();
  try {
    for (const q of [
      'CREATE INDEX user_name IF NOT EXISTS FOR (u:User)    ON (u.name)',
      'CREATE INDEX host_name IF NOT EXISTS FOR (h:Host)    ON (h.name)',
      'CREATE INDEX proc_name IF NOT EXISTS FOR (p:Process) ON (p.name)',
      'CREATE INDEX ip_addr   IF NOT EXISTS FOR (i:IP)      ON (i.address)',
    ]) {
      try { await session.run(q); } catch { /* already exists */ }
    }
    console.log('[NEO4J] Schema ready');
  } finally {
    await session.close();
  }
}

// ── Ingest event from Wazuh/n8n ──────────────────────────
async function ingestEvent(ev) {
  const { user, host, src_ip, process: proc, action, timestamp, alert_id, rule_id } = ev;
  const ts = timestamp || new Date().toISOString();

  const merges = [];
  const params = { ts, alert_id: alert_id||'', rule_id: rule_id||'' };

  if (user && host) {
    params.user = user; params.host = host;
    merges.push(`
      MERGE (u:User {name: $user})
      MERGE (h:Host {name: $host})
      CREATE (u)-[:LOGGED_IN {time: $ts, alert_id: $alert_id, rule_id: $rule_id}]->(h)
    `);
  }
  if (host && proc) {
    params.host2 = host; params.proc = proc;
    merges.push(`
      MERGE (h:Host {name: $host2})
      MERGE (p:Process {name: $proc})
      CREATE (h)-[:EXECUTED {time: $ts, user: $user, alert_id: $alert_id}]->(p)
    `);
  }
  if (host && src_ip && src_ip !== host) {
    params.host3 = host; params.src = src_ip;
    merges.push(`
      MERGE (h:Host {name: $host3})
      MERGE (i:IP {address: $src})
      CREATE (i)-[:CONNECTED_TO {time: $ts, alert_id: $alert_id}]->(h)
    `);
  }

  for (const q of merges) {
    try { await run(q, params); } catch (e) { console.error('[NEO4J] ingest error:', e.message); }
  }
}

// ── UEBA Anomaly Detections ──────────────────────────────

async function detectLateralMovement(hours = 24) {
  const records = await run(`
    MATCH (u:User)-[r1:LOGGED_IN]->(h1:Host)
    MATCH (u)-[r2:LOGGED_IN]->(h2:Host)
    WHERE h1 <> h2
      AND datetime(r1.time) > datetime() - duration({hours: $hours})
      AND datetime(r2.time) > datetime() - duration({hours: $hours})
    RETURN u.name AS user,
           collect(DISTINCT h1.name + ' → ' + h2.name) AS hops,
           count(*) AS event_count
    ORDER BY event_count DESC LIMIT 20
  `, { hours });
  return records.map(r => ({
    type: 'lateral_movement',
    user: r.get('user'),
    hops: r.get('hops'),
    count: r.get('event_count').toNumber?.() ?? r.get('event_count'),
  }));
}

async function detectRareProcesses(minHosts = 1) {
  const records = await run(`
    MATCH (h:Host)-[:EXECUTED]->(p:Process)
    WITH p.name AS proc, collect(DISTINCT h.name) AS hosts
    WHERE size(hosts) <= $minHosts
    RETURN proc, hosts, size(hosts) AS host_count
    ORDER BY host_count ASC LIMIT 20
  `, { minHosts });
  return records.map(r => ({
    type: 'rare_process',
    process: r.get('proc'),
    hosts: r.get('hosts'),
    host_count: r.get('host_count').toNumber?.() ?? r.get('host_count'),
  }));
}

async function detectHighFrequencyLogins(hours = 1, threshold = 5) {
  const records = await run(`
    MATCH (u:User)-[r:LOGGED_IN]->(h:Host)
    WHERE datetime(r.time) > datetime() - duration({hours: $hours})
    WITH u.name AS user, h.name AS host, count(r) AS login_count
    WHERE login_count >= $threshold
    RETURN user, host, login_count
    ORDER BY login_count DESC LIMIT 20
  `, { hours, threshold });
  return records.map(r => ({
    type: 'high_frequency_login',
    user: r.get('user'),
    host: r.get('host'),
    count: r.get('login_count').toNumber?.() ?? r.get('login_count'),
  }));
}

async function detectNewConnectionSources(hours = 24) {
  const records = await run(`
    MATCH (i:IP)-[r:CONNECTED_TO]->(h:Host)
    WHERE datetime(r.time) > datetime() - duration({hours: $hours})
    WITH i.address AS ip, h.name AS host, min(r.time) AS first_seen, count(r) AS conn_count
    RETURN ip, host, first_seen, conn_count
    ORDER BY first_seen DESC LIMIT 30
  `, { hours });
  return records.map(r => ({
    type: 'new_connection',
    ip: r.get('ip'),
    host: r.get('host'),
    first_seen: r.get('first_seen'),
    count: r.get('conn_count').toNumber?.() ?? r.get('conn_count'),
  }));
}

async function getAllAnomalies() {
  const [lateral, rare, hf, newconn] = await Promise.all([
    detectLateralMovement(),
    detectRareProcesses(),
    detectHighFrequencyLogins(),
    detectNewConnectionSources(),
  ]);
  return { lateral_movement: lateral, rare_processes: rare, high_frequency_logins: hf, new_connections: newconn };
}

async function getEntityGraph(name) {
  const records = await run(`
    MATCH (e {name: $name})-[r]-(n)
    RETURN type(r) AS rel, labels(e)[0] AS src_type, labels(n)[0] AS dst_type,
           e.name AS src, n.name AS dst, r.time AS time
    ORDER BY r.time DESC LIMIT 100
  `, { name });
  return records.map(r => ({
    rel:      r.get('rel'),
    src_type: r.get('src_type'),
    dst_type: r.get('dst_type'),
    src:      r.get('src'),
    dst:      r.get('dst'),
    time:     r.get('time'),
  }));
}

async function getUebaStats() {
  const d = getDriver();
  if (!d) return null;
  const session = d.session();
  try {
    const r = await session.run(`
      MATCH (u:User) WITH count(u) AS users
      MATCH (h:Host) WITH users, count(h) AS hosts
      MATCH (p:Process) WITH users, hosts, count(p) AS processes
      MATCH ()-[r]->() WITH users, hosts, processes, count(r) AS relationships
      RETURN users, hosts, processes, relationships
    `);
    if (!r.records.length) return { users:0, hosts:0, processes:0, relationships:0 };
    const rec = r.records[0];
    return {
      users:         rec.get('users').toNumber?.()         ?? rec.get('users'),
      hosts:         rec.get('hosts').toNumber?.()         ?? rec.get('hosts'),
      processes:     rec.get('processes').toNumber?.()     ?? rec.get('processes'),
      relationships: rec.get('relationships').toNumber?.() ?? rec.get('relationships'),
    };
  } catch { return { users:0, hosts:0, processes:0, relationships:0 }; }
  finally { await session.close(); }
}

async function ping() {
  const d = getDriver();
  if (!d) return false;
  try { await run('RETURN 1'); return true; } catch { return false; }
}

module.exports = { initSchema, ingestEvent, getAllAnomalies, getEntityGraph, getUebaStats, ping };
