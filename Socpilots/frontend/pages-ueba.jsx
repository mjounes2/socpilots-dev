// UEBA — User & Entity Behavior Analytics
const {
  useState: useStateU,
  useEffect: useEffectU,
  useMemo: useMemoU,
  useCallback: useCallbackU,
} = React;

const ANOMALY_PANELS = [
  { key: 'lateral_movement',      label: 'Lateral Movement',      weight: 85, sev: 'high'     },
  { key: 'impossible_travel',     label: 'Impossible Travel',     weight: 95, sev: 'critical'  },
  { key: 'privilege_escalation',  label: 'Privilege Escalation',  weight: 80, sev: 'high'     },
  { key: 'after_hours_access',    label: 'After-Hours Access',    weight: 55, sev: 'medium'   },
  { key: 'high_frequency_logins', label: 'High-Freq Logins',      weight: 50, sev: 'medium'   },
  { key: 'rare_processes',        label: 'Rare Processes',        weight: 70, sev: 'high'     },
];

// Normalise each anomaly record to a common { entity, detail, score, time } shape
function normalizeAnomaly(item, key) {
  switch (key) {
    case 'lateral_movement':
      return {
        entity: item.user || '—',
        detail: `${item.hops || 0} hops · ${(item.src_hosts || []).join(', ')} → ${(item.dst_hosts || []).join(', ')}`,
        score:  item.deviation ?? item.risk_score ?? 0,
        time:   null,
      };
    case 'impossible_travel':
      return {
        entity: item.user || '—',
        detail: `${item.ip1} → ${item.ip2} on ${item.host}`,
        score:  95,
        time:   item.time1,
      };
    case 'privilege_escalation':
      return {
        entity: item.user || '—',
        detail: `${item.process} on ${item.host}`,
        score:  item.deviation ?? 80,
        time:   item.time,
      };
    case 'after_hours_access':
      return {
        entity: item.user || '—',
        detail: `${item.events} events on ${item.host} · hours: ${(item.hours_seen || []).join(', ')}`,
        score:  item.deviation ?? 55,
        time:   null,
      };
    case 'high_frequency_logins':
      return {
        entity: item.user || '—',
        detail: `${item.count} logins → ${item.host} in 1h`,
        score:  item.risk_score ?? 50,
        time:   null,
      };
    case 'rare_processes':
      return {
        entity: item.process || '—',
        detail: `seen ${item.seen_count ?? 1}× on ${(item.hosts || []).join(', ')}`,
        score:  70,
        time:   null,
      };
    default:
      return {
        entity: item.user || item.entity || '—',
        detail: Object.entries(item).filter(([k]) => !['type'].includes(k)).map(([k,v]) => `${k}: ${v}`).join(' · '),
        score:  item.deviation ?? 0,
        time:   null,
      };
  }
}

// ── Risk Bar ─────────────────────────────────────────────────────
function RiskBar({ risk }) {
  const pct   = Math.min(100, Math.max(0, risk));
  const color = pct >= 70 ? 'var(--crit)' : pct >= 40 ? 'var(--high)' : 'var(--low)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, background: 'var(--bg-3)', borderRadius: 4, height: 6 }}>
        <div style={{ width: pct + '%', height: 6, borderRadius: 4, background: color, transition: 'width .4s' }} />
      </div>
      <span className="mono" style={{ fontSize: 11, color, width: 28, textAlign: 'right', flexShrink: 0 }}>{pct}</span>
    </div>
  );
}

// ── Anomaly Panel ─────────────────────────────────────────────────
function AnomalyPanel({ panel, items }) {
  const normalized = useMemoU(
    () => (items || []).map(it => normalizeAnomaly(it, panel.key)),
    [items, panel.key]
  );
  return (
    <Card
      title={panel.label}
      sub={`weight: ${panel.weight} · ${normalized.length} event${normalized.length !== 1 ? 's' : ''}`}
      actions={<SevChip sev={panel.sev} />}
      span={6}
    >
      {normalized.length === 0 ? (
        <div className="empty mono">No anomalies detected</div>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
          {normalized.map((item, i) => (
            <li key={i} style={{
              background: 'var(--bg-2)', border: '1px solid var(--ln)',
              borderRadius: 5, padding: '9px 12px',
              display: 'flex', flexDirection: 'column', gap: 4,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="mono" style={{ fontSize: 12, color: 'var(--acc)', fontWeight: 500 }}>
                  {item.entity}
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {item.time && (
                    <span className="mono dim" style={{ fontSize: 10 }}>{item.time.slice(0, 16).replace('T', ' ')}</span>
                  )}
                  <span className="mono" style={{
                    fontSize: 10, padding: '1px 7px', borderRadius: 10,
                    background: item.score >= 80 ? 'var(--crit-bg)' : item.score >= 60 ? 'var(--high-bg)' : 'var(--bg-3)',
                    color:      item.score >= 80 ? 'var(--crit)'    : item.score >= 60 ? 'var(--high)'    : 'var(--fg-2)',
                    border:     '1px solid var(--ln)',
                  }}>W:{item.score}</span>
                </div>
              </div>
              <div style={{ fontSize: 11.5, color: 'var(--fg-2)', lineHeight: 1.4 }}>{item.detail}</div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

// ── Entity Profile Display ────────────────────────────────────────
function ProfileView({ profile }) {
  if (profile.error) {
    return <div className="mono" style={{ color: 'var(--crit)', fontSize: 12 }}>{profile.error}</div>;
  }
  const p = profile.profile || profile;

  const rows = [
    ['Entity',        p.name],
    ['Type',          p.entity_type],
    ['Risk Score',    p.risk_score != null ? String(p.risk_score) : '—'],
    ['Anomalies',     p.anomaly_count != null ? String(p.anomaly_count) : '—'],
    ['Total Events',  p.total_events != null ? String(p.total_events) : '—'],
    ['Last Seen',     p.last_seen ? p.last_seen.slice(0, 16).replace('T', ' ') : '—'],
    ['Last Anomaly',  p.last_anomaly ? p.last_anomaly.slice(0, 16).replace('T', ' ') : '—'],
    ['Hosts',         Array.isArray(p.all_hosts) && p.all_hosts.length > 0 ? p.all_hosts.join(', ') : Array.isArray(p.all_users) && p.all_users.length > 0 ? p.all_users.join(', ') : '—'],
  ].filter(([, v]) => v && v !== '—');

  return (
    <div>
      <div style={{
        display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10,
        background: 'var(--bg-2)', border: '1px solid var(--ln)',
        borderRadius: 6, padding: 14, marginBottom: 12,
      }}>
        {rows.map(([k, v]) => (
          <div key={k}>
            <div style={{ fontSize: 9.5, fontFamily: 'var(--mono)', color: 'var(--fg-3)', letterSpacing: 1, textTransform: 'uppercase', marginBottom: 2 }}>{k}</div>
            <div className="mono" style={{ fontSize: 12, color: 'var(--fg-0)' }}>{v}</div>
          </div>
        ))}
      </div>
      {Array.isArray(p.recent_logins) && p.recent_logins.length > 0 && (
        <div>
          <div style={{ fontSize: 10, color: 'var(--fg-3)', letterSpacing: 1, fontFamily: 'var(--mono)', marginBottom: 6 }}>RECENT LOGINS</div>
          {p.recent_logins.slice(0, 5).map((l, i) => (
            <div key={i} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '5px 10px', background: 'var(--bg-2)', borderRadius: 4,
              border: '1px solid var(--ln)', marginBottom: 4,
              fontSize: 11,
            }}>
              <span className="mono" style={{ color: 'var(--fg-1)' }}>{l.host || l.user || '—'}</span>
              <span className="mono dim">{l.time ? l.time.slice(0, 16).replace('T', ' ') : ''}</span>
              {l.deviation > 0 && (
                <span className="mono" style={{
                  color: l.deviation >= 70 ? 'var(--crit)' : l.deviation >= 40 ? 'var(--high)' : 'var(--fg-3)',
                  fontSize: 10,
                }}>dev:{l.deviation}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────
function PageUEBA() {
  const API  = window.SOC_API;

  const [tf,          setTf]          = useStateU('24h');
  const [refreshKey,  setRefreshKey]  = useStateU(0);
  const [loading,     setLoading]     = useStateU(false);

  const [stats,       setStats]       = useStateU(null);
  const [leaderboard, setLeaderboard] = useStateU([]);
  const [lbTotal,     setLbTotal]     = useStateU(0);
  const [anomalies,   setAnomalies]   = useStateU({});

  // Leaderboard filters (client-side)
  const [lbSearch,    setLbSearch]    = useStateU('');
  const [lbMinRisk,   setLbMinRisk]   = useStateU('');

  // Entity lookup
  const [entityInput,   setEntityInput]   = useStateU('');
  const [entityProfile, setEntityProfile] = useStateU(null);
  const [entityLoading, setEntityLoading] = useStateU(false);

  // Attack path
  const [pathFrom,    setPathFrom]    = useStateU('');
  const [pathTo,      setPathTo]      = useStateU('');
  const [pathResult,  setPathResult]  = useStateU(null);
  const [pathLoading, setPathLoading] = useStateU(false);

  // AI digest
  const [digest,        setDigest]        = useStateU(null);
  const [digestLoading, setDigestLoading] = useStateU(false);

  const hours = tf === '7d' ? 168 : tf === '30d' ? 720 : 24;

  useEffectU(() => {
    let cancelled = false;
    setLoading(true);

    async function fetchAll() {
      try {
        const [statsRes, lbRes, anomRes] = await Promise.all([
          API.get('/api/ueba/stats'),
          API.get(`/api/ueba/leaderboard?page=1&page_size=30&hours=${hours}`),
          API.get(`/api/ueba/anomalies?hours=${hours}`),
        ]);
        if (cancelled) return;

        // Fix 1: stats is wrapped in { stats: {...} }
        if (statsRes && !statsRes.error) {
          setStats(statsRes.stats || statsRes);
        }

        // Fix 2: leaderboard returns { users:[...], total } — field is `user` not `name`
        if (lbRes && !lbRes.error) {
          const rows = (lbRes.users || lbRes.items || []).map(r => ({
            name:       r.user || r.name,
            risk:       r.risk_score ?? r.risk ?? 0,
            anomalies:  r.anomaly_count ?? r.anomalies ?? 0,
            lastActive: r.last_anomaly || r.lastActive || '—',
            type:       r.entity_type || 'User',
            events:     r.events_period ?? 0,
            hosts:      r.recent_hosts || [],
          }));
          setLeaderboard(rows);
          setLbTotal(lbRes.total || rows.length);
        }

        // Fix 3: anomalies endpoint returns all types in one object — spread directly
        if (anomRes && !anomRes.error) {
          setAnomalies(anomRes);
        }
      } catch {
        // leave existing state
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchAll();
    API.get('/api/ueba/digest/latest').then(r => {
      if (!cancelled && r && !r.error && r.text) setDigest(r.text);
    }).catch(() => {});

    return () => { cancelled = true; };
  }, [tf, refreshKey]);

  // Client-side leaderboard filter
  const filteredLb = useMemoU(() => {
    let rows = leaderboard;
    if (lbSearch.trim()) {
      const q = lbSearch.toLowerCase();
      rows = rows.filter(r => (r.name || '').toLowerCase().includes(q));
    }
    if (lbMinRisk !== '' && !isNaN(Number(lbMinRisk))) {
      rows = rows.filter(r => r.risk >= Number(lbMinRisk));
    }
    return rows;
  }, [leaderboard, lbSearch, lbMinRisk]);

  const lookupEntity = useCallbackU(async () => {
    const name = entityInput.trim();
    if (!name) return;
    setEntityLoading(true);
    setEntityProfile(null);
    const r = await API.get(`/api/ueba/profile/${encodeURIComponent(name)}`);
    // Fix 4: profile is wrapped in { profile: {...} }
    setEntityProfile(r && !r.error ? (r.profile ? r : { profile: r }) : { error: r?.error || 'Not found in graph' });
    setEntityLoading(false);
  }, [entityInput]);

  const findPath = useCallbackU(async () => {
    if (!pathFrom.trim() || !pathTo.trim()) return;
    setPathLoading(true);
    setPathResult(null);
    const r = await API.get(`/api/ueba/path?from=${encodeURIComponent(pathFrom.trim())}&to=${encodeURIComponent(pathTo.trim())}`);
    setPathResult(r && !r.error ? r : { error: r?.error || 'No path found' });
    setPathLoading(false);
  }, [pathFrom, pathTo]);

  const generateDigest = useCallbackU(async () => {
    setDigestLoading(true);
    const r = await API.post('/api/ueba/digest/generate', { timeframe: tf });
    if (r && !r.error) {
      // Digest generation is async — poll for it after 3s
      setTimeout(async () => {
        const d = await API.get('/api/ueba/digest/latest');
        if (d && !d.error && d.text) setDigest(d.text);
        setDigestLoading(false);
      }, 3000);
    } else {
      setDigestLoading(false);
    }
  }, [tf]);

  const s = stats || {};
  const users     = s.users     ?? 0;
  const hosts     = s.hosts     ?? 0;
  const processes = s.processes ?? 0;
  const edges     = s.relationships ?? s.edges ?? 0;
  const avgRisk   = s.avg_risk  ?? s.avgRisk  ?? 0;
  const highRisk  = s.high_risk_users ?? s.highRisk ?? 0;

  return (
    <div className="page" data-screen-label="UEBA">
      <Topbar
        title="UEBA"
        sub="User &amp; Entity Behavior Analytics · Neo4j graph"
        actions={<>
          {['24h', '7d', '30d'].map(t => (
            <button key={t} className={tf === t ? 'btn btn-primary' : 'btn btn-ghost'} onClick={() => setTf(t)}>{t}</button>
          ))}
          <button className="btn btn-ghost" onClick={() => setRefreshKey(k => k + 1)} disabled={loading}>
            <Icon.refresh width="13" height="13"/> {loading ? 'Loading…' : 'Refresh'}
          </button>
        </>}
      />

      <div className="page-body">

        {/* ── KPI Strip ── */}
        <div className="kpi-grid">
          <div className="kpi">
            <div className="kpi-label">Users Tracked</div>
            <div className="kpi-value">{users.toLocaleString()}</div>
            <div className="kpi-foot"><span className="kpi-sub">in graph</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Hosts in Graph</div>
            <div className="kpi-value">{hosts.toLocaleString()}</div>
            <div className="kpi-foot"><span className="kpi-sub">monitored</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Processes Observed</div>
            <div className="kpi-value">{processes.toLocaleString()}</div>
            <div className="kpi-foot"><span className="kpi-sub">unique</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Graph Edges</div>
            <div className="kpi-value">{edges.toLocaleString()}</div>
            <div className="kpi-foot"><span className="kpi-sub">relationships</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Avg Risk Score</div>
            <div className="kpi-value">{avgRisk}</div>
            <div className="kpi-foot"><span className="kpi-sub">across entities</span></div>
          </div>
          <div className="kpi" data-sev={highRisk > 0 ? 'critical' : undefined}>
            <div className="kpi-label">High Risk (≥ 70)</div>
            <div className="kpi-value mono" style={{ color: highRisk > 0 ? 'var(--crit)' : undefined }}>{highRisk}</div>
            <div className="kpi-foot"><span className="kpi-sub">need review</span></div>
          </div>
        </div>

        {/* ── Risk Leaderboard ── */}
        <Card
          title="Risk Leaderboard"
          sub={`${lbTotal} entities · sorted by risk score`}
          actions={<>
            <input
              className="mono"
              style={{
                background: 'var(--bg-2)', border: '1px solid var(--ln)',
                borderRadius: 4, padding: '4px 10px', fontSize: 11.5,
                color: 'var(--fg-0)', width: 160,
              }}
              placeholder="Search entity…"
              value={lbSearch}
              onChange={e => setLbSearch(e.target.value)}
            />
            <input
              className="mono"
              type="number" min="0" max="100"
              style={{
                background: 'var(--bg-2)', border: '1px solid var(--ln)',
                borderRadius: 4, padding: '4px 10px', fontSize: 11.5,
                color: 'var(--fg-0)', width: 88,
              }}
              placeholder="Min score"
              value={lbMinRisk}
              onChange={e => setLbMinRisk(e.target.value)}
            />
            <button className="btn btn-ghost btn-sm" onClick={() => { setLbSearch(''); setLbMinRisk(''); }}>Reset</button>
          </>}
        >
          {loading && leaderboard.length === 0 ? (
            <div className="loading"><Spinner size={22}/> Loading leaderboard…</div>
          ) : filteredLb.length === 0 ? (
            <div className="empty mono">No entities{lbSearch || lbMinRisk ? ' match filter' : ' tracked yet'}</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 42 }}>RANK</th>
                  <th>ENTITY</th>
                  <th style={{ width: 64 }}>TYPE</th>
                  <th style={{ width: 200 }}>RISK SCORE</th>
                  <th style={{ width: 90 }}>ANOMALIES</th>
                  <th style={{ width: 130 }}>LAST ANOMALY</th>
                  <th style={{ width: 80 }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredLb.map((row, idx) => (
                  <tr key={row.name || idx}>
                    <td className="mono dim" style={{ textAlign: 'center' }}>#{idx + 1}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                        <SevDot sev={row.risk >= 70 ? 'critical' : row.risk >= 40 ? 'high' : 'low'} />
                        <span className="mono" style={{ fontSize: 12.5 }}>{row.name}</span>
                      </div>
                    </td>
                    <td>
                      <Chip mono tone={row.type === 'host' ? 'warn' : 'default'}>
                        {row.type || 'user'}
                      </Chip>
                    </td>
                    <td><RiskBar risk={row.risk} /></td>
                    <td className="mono" style={{ textAlign: 'center' }}>
                      <span style={{ color: row.anomalies > 3 ? 'var(--crit)' : row.anomalies > 0 ? 'var(--high)' : 'var(--fg-3)' }}>
                        {row.anomalies}
                      </span>
                    </td>
                    <td className="mono dim" style={{ fontSize: 11 }}>
                      {row.lastActive && row.lastActive !== '—'
                        ? row.lastActive.slice(0, 16).replace('T', ' ')
                        : '—'}
                    </td>
                    <td>
                      <button className="btn btn-ghost btn-sm" style={{ fontSize: 11 }}
                        onClick={() => { setEntityInput(row.name); setEntityProfile(null); }}>
                        Profile
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        {/* ── Entity Lookup + Attack Path ── */}
        <div className="grid-12">
          <Card title="Entity Lookup" sub="query behavioral profile from graph" span={6}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
              <input
                className="mono"
                style={{
                  flex: 1, background: 'var(--bg-2)', border: '1px solid var(--ln)',
                  borderRadius: 4, padding: '6px 10px', fontSize: 12, color: 'var(--fg-0)',
                }}
                placeholder="Username, hostname, or IP address…"
                value={entityInput}
                onChange={e => setEntityInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && lookupEntity()}
              />
              <button className="btn btn-primary" onClick={lookupEntity} disabled={entityLoading || !entityInput.trim()}>
                {entityLoading ? <><Spinner size={12}/> Querying…</> : 'Profile'}
              </button>
            </div>
            {entityProfile ? (
              <ProfileView profile={entityProfile} />
            ) : (
              <div className="empty mono">Enter an entity name and click Profile</div>
            )}
          </Card>

          <Card title="Attack Path Finder" sub="shortest lateral-movement path in graph" span={6}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  className="mono"
                  style={{ flex: 1, background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 4, padding: '6px 10px', fontSize: 12, color: 'var(--fg-0)' }}
                  placeholder="From entity…"
                  value={pathFrom}
                  onChange={e => setPathFrom(e.target.value)}
                />
                <input
                  className="mono"
                  style={{ flex: 1, background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 4, padding: '6px 10px', fontSize: 12, color: 'var(--fg-0)' }}
                  placeholder="To entity…"
                  value={pathTo}
                  onChange={e => setPathTo(e.target.value)}
                />
                <button className="btn btn-primary" onClick={findPath} disabled={pathLoading || !pathFrom.trim() || !pathTo.trim()}>
                  {pathLoading ? '…' : 'Find'}
                </button>
              </div>
              {pathResult ? (
                pathResult.error ? (
                  <div className="mono" style={{ color: 'var(--fg-2)', fontSize: 12, padding: '8px 0' }}>{pathResult.error}</div>
                ) : !pathResult.found ? (
                  <div className="mono" style={{ color: 'var(--fg-3)', fontSize: 12, padding: '8px 0' }}>No path found between these entities.</div>
                ) : (
                  <div style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 6, padding: 12 }}>
                    {Array.isArray(pathResult.path) ? (
                      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 6 }}>
                        {pathResult.path.map((node, i) => (
                          <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span className="mono" style={{
                              fontSize: 11.5, padding: '2px 8px',
                              background: 'var(--bg-3)', border: '1px solid var(--ln)',
                              borderRadius: 4, color: 'var(--acc)',
                            }}>{node}</span>
                            {i < pathResult.path.length - 1 && (
                              <span style={{ color: 'var(--fg-3)', fontSize: 12 }}>→</span>
                            )}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <pre className="mono" style={{ fontSize: 11, color: 'var(--fg-1)', margin: 0, whiteSpace: 'pre-wrap' }}>
                        {JSON.stringify(pathResult, null, 2)}
                      </pre>
                    )}
                    {pathResult.hops != null && (
                      <div className="mono dim" style={{ fontSize: 10.5, marginTop: 8 }}>
                        {pathResult.hops} hop{pathResult.hops !== 1 ? 's' : ''}{pathResult.totalRisk != null ? ` · total risk ${pathResult.totalRisk}` : ''}
                      </div>
                    )}
                  </div>
                )
              ) : (
                <div className="empty mono">Enter source and destination entities</div>
              )}
            </div>
          </Card>
        </div>

        {/* ── Anomaly Panels ── */}
        <div className="grid-12">
          <AnomalyPanel panel={ANOMALY_PANELS[0]} items={anomalies.lateral_movement} />
          <AnomalyPanel panel={ANOMALY_PANELS[1]} items={anomalies.impossible_travel} />
        </div>
        <div className="grid-12">
          <AnomalyPanel panel={ANOMALY_PANELS[2]} items={anomalies.privilege_escalation} />
          <AnomalyPanel panel={ANOMALY_PANELS[3]} items={anomalies.after_hours_access} />
        </div>
        <div className="grid-12">
          <AnomalyPanel panel={ANOMALY_PANELS[4]} items={anomalies.high_frequency_logins} />
          <AnomalyPanel panel={ANOMALY_PANELS[5]} items={anomalies.rare_processes} />
        </div>

        {/* ── AI Behavior Digest ── */}
        <Card
          title="AI Behavior Digest"
          sub="LangChain ReAct analysis of UEBA graph"
          actions={
            <button className="btn btn-primary" onClick={generateDigest} disabled={digestLoading}>
              <Icon.brain width="13" height="13"/>
              {digestLoading ? ' Generating…' : ' Generate Digest'}
            </button>
          }
        >
          {digest ? (
            <div style={{
              background: 'var(--bg-2)', border: '1px solid var(--ln)',
              borderRadius: 6, padding: 16,
              fontSize: 13, lineHeight: 1.65,
              color: 'var(--fg-1)', whiteSpace: 'pre-wrap',
            }}>{digest}</div>
          ) : (
            <div className="empty mono">No digest yet — click Generate Digest to create one</div>
          )}
        </Card>

      </div>
    </div>
  );
}

Object.assign(window, { PageUEBA });
