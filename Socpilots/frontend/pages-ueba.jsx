// UEBA (User & Entity Behavior Analytics) page
const { useState: useStateU, useEffect: useEffectU, useMemo: useMemoU } = React;

// ============= FALLBACK DATA =============
const FALLBACK_UEBA_STATS = { users: 47, hosts: 23, processes: 312, edges: 1847, avgRisk: 23, highRisk: 4 };

const FALLBACK_LEADERBOARD = [
  { name: 'svc_backup',   type: 'User', risk: 88, anomalies: 7, lastActive: '2m ago' },
  { name: 'admin',        type: 'User', risk: 76, anomalies: 5, lastActive: '14m ago' },
  { name: 'win-dc-01',    type: 'Host', risk: 71, anomalies: 4, lastActive: '4s ago' },
  { name: 'jdoe',         type: 'User', risk: 54, anomalies: 2, lastActive: '1h ago' },
  { name: 'db-primary',   type: 'Host', risk: 48, anomalies: 3, lastActive: '12s ago' },
  { name: 'svc_deploy',   type: 'User', risk: 42, anomalies: 1, lastActive: '3h ago' },
  { name: 'k8s-worker-1', type: 'Host', risk: 31, anomalies: 1, lastActive: '3s ago' },
  { name: 'bjones',       type: 'User', risk: 18, anomalies: 0, lastActive: '2d ago' },
];

const FALLBACK_ANOMALIES = {
  lateral_movement: [
    { entity: 'svc_backup', detail: 'Accessed 6 hosts in 4min via SMB', time: '2m ago', score: 85 },
    { entity: 'admin',      detail: 'RDP from jump-host to win-dc-01 after hours', time: '18m ago', score: 72 },
  ],
  impossible_travel: [
    { entity: 'jdoe', detail: 'Login from US then EU within 12min', time: '47m ago', score: 95 },
  ],
  privilege_escalation: [
    { entity: 'svc_backup', detail: 'Token impersonation on db-primary', time: '5m ago', score: 81 },
  ],
  after_hours_access: [
    { entity: 'admin',  detail: 'Login at 03:22 UTC from 10.0.4.45', time: '3h ago', score: 55 },
    { entity: 'bjones', detail: 'VPN access Saturday 01:15 UTC', time: '2d ago', score: 42 },
  ],
  high_freq_logins: [
    { entity: 'svc_deploy', detail: '147 auth events in 10min', time: '1h ago', score: 50 },
  ],
  rare_processes: [
    { entity: 'win-dc-01',  detail: 'mshta.exe spawned from winlogon.exe', time: '22m ago', score: 78 },
    { entity: 'db-primary', detail: 'certutil.exe with -urlcache flag', time: '1h ago', score: 65 },
  ],
};

const ANOMALY_PANELS = [
  { key: 'lateral_movement',   label: 'Lateral Movement',     weight: 85, sev: 'high' },
  { key: 'impossible_travel',  label: 'Impossible Travel',    weight: 95, sev: 'critical' },
  { key: 'privilege_escalation', label: 'Privilege Escalation', weight: 80, sev: 'high' },
  { key: 'after_hours_access', label: 'After Hours Access',   weight: 55, sev: 'medium' },
  { key: 'high_freq_logins',   label: 'High Frequency Logins', weight: 50, sev: 'medium' },
  { key: 'rare_processes',     label: 'Rare Processes',       weight: 70, sev: 'high' },
];

// ============= RISK BAR =============
function RiskBar({ risk }) {
  const color = risk >= 70 ? '#ff4444' : risk >= 40 ? '#ff9800' : 'var(--acc)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, background: 'var(--bg-3)', borderRadius: 4, height: 6 }}>
        <div style={{ width: risk + '%', height: 6, borderRadius: 4, background: color, transition: 'width .3s' }} />
      </div>
      <span className="mono" style={{ fontSize: 11, color, width: 28, textAlign: 'right', flexShrink: 0 }}>{risk}</span>
    </div>
  );
}

// ============= ANOMALY PANEL =============
function AnomalyPanel({ panel, items }) {
  const list = items || [];
  return (
    <Card
      title={panel.label}
      sub={`weight: ${panel.weight} · ${list.length} event${list.length !== 1 ? 's' : ''}`}
      actions={<>
        <SevChip sev={panel.sev} />
      </>}
      span={6}
    >
      {list.length === 0 ? (
        <div className="empty mono">No anomalies detected</div>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {list.map((item, i) => (
            <li key={i} style={{
              background: 'var(--bg-2)',
              border: '1px solid var(--ln)',
              borderRadius: 6,
              padding: '10px 12px',
              display: 'flex',
              flexDirection: 'column',
              gap: 4,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="mono" style={{ fontSize: 12, color: 'var(--acc)', fontWeight: 500 }}>{item.entity}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{item.time}</span>
                  <span className="mono" style={{
                    fontSize: 10,
                    padding: '1px 6px',
                    borderRadius: 3,
                    background: item.score >= 80 ? 'oklch(0.30 0.08 22 / 0.22)' : 'var(--bg-3)',
                    color: item.score >= 80 ? 'var(--crit)' : item.score >= 60 ? 'var(--high)' : 'var(--fg-2)',
                  }}>W:{item.score}</span>
                </div>
              </div>
              <div style={{ fontSize: 11.5, color: 'var(--fg-2)' }}>{item.detail}</div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

// ============= MAIN PAGE =============
function PageUEBA() {
  const [tf, setTf]                   = useStateU('24h');
  const [stats, setStats]             = useStateU(FALLBACK_UEBA_STATS);
  const [leaderboard, setLeaderboard] = useStateU(FALLBACK_LEADERBOARD);
  const [anomalies, setAnomalies]     = useStateU(FALLBACK_ANOMALIES);
  const [digest, setDigest]           = useStateU(null);
  const [digestLoading, setDigestLoading] = useStateU(false);
  const [loading, setLoading]         = useStateU(false);

  // Leaderboard filter state
  const [lbSearch, setLbSearch]   = useStateU('');
  const [lbMinRisk, setLbMinRisk] = useStateU('');

  // Entity lookup state
  const [entityInput, setEntityInput]   = useStateU('');
  const [entityProfile, setEntityProfile] = useStateU(null);
  const [entityLoading, setEntityLoading] = useStateU(false);
  const [pathFrom, setPathFrom]   = useStateU('');
  const [pathTo, setPathTo]       = useStateU('');
  const [pathResult, setPathResult] = useStateU(null);
  const [pathLoading, setPathLoading] = useStateU(false);

  // Fetch all data on mount and timeframe change
  useEffectU(() => {
    let cancelled = false;
    setLoading(true);

    async function fetchAll() {
      try {
        const [statsRes, lbRes] = await Promise.all([
          window.SOC_API.get('/api/ueba/stats'),
          window.SOC_API.get('/api/ueba/leaderboard?page=1&page_size=20'),
        ]);
        if (cancelled) return;
        if (statsRes && !statsRes.error) setStats(statsRes);
        if (lbRes && !lbRes.error) {
          setLeaderboard(lbRes.items || lbRes.users || FALLBACK_LEADERBOARD);
        }

        // Fetch anomaly panels in parallel
        const anomalyFetches = ANOMALY_PANELS.map(p =>
          window.SOC_API.get(`/api/ueba/anomalies?type=${p.key}&hours=${tf === '24h' ? 24 : tf === '7d' ? 168 : 720}`)
            .then(r => [p.key, r])
        );
        const anomalyResults = await Promise.all(anomalyFetches);
        if (cancelled) return;
        const merged = { ...FALLBACK_ANOMALIES };
        anomalyResults.forEach(([key, res]) => {
          if (res && !res.error && Array.isArray(res.items || res)) {
            merged[key] = res.items || res;
          }
        });
        setAnomalies(merged);
      } catch {
        // keep fallback data
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchAll();

    // Fetch latest digest
    window.SOC_API.get('/api/ueba/digest/latest').then(r => {
      if (r && !r.error && r.text) setDigest(r.text);
    }).catch(() => {});

    return () => { cancelled = true; };
  }, [tf]);

  // Filtered leaderboard (client-side)
  const filteredLb = useMemoU(() => {
    let rows = leaderboard;
    if (lbSearch.trim()) {
      const q = lbSearch.toLowerCase();
      rows = rows.filter(r => r.name.toLowerCase().includes(q));
    }
    if (lbMinRisk !== '' && !isNaN(Number(lbMinRisk))) {
      rows = rows.filter(r => r.risk >= Number(lbMinRisk));
    }
    return rows;
  }, [leaderboard, lbSearch, lbMinRisk]);

  async function lookupEntity() {
    if (!entityInput.trim()) return;
    setEntityLoading(true);
    setEntityProfile(null);
    try {
      const r = await window.SOC_API.get(`/api/ueba/profile/${encodeURIComponent(entityInput.trim())}`);
      setEntityProfile(r && !r.error ? r : { error: r?.error || 'Not found' });
    } catch {
      setEntityProfile({ error: 'Request failed' });
    }
    setEntityLoading(false);
  }

  async function findPath() {
    if (!pathFrom.trim() || !pathTo.trim()) return;
    setPathLoading(true);
    setPathResult(null);
    try {
      const r = await window.SOC_API.get(`/api/ueba/attack-path?from=${encodeURIComponent(pathFrom.trim())}&to=${encodeURIComponent(pathTo.trim())}`);
      setPathResult(r && !r.error ? r : { error: r?.error || 'No path found' });
    } catch {
      setPathResult({ error: 'Request failed' });
    }
    setPathLoading(false);
  }

  async function generateDigest() {
    setDigestLoading(true);
    try {
      const r = await window.SOC_API.post('/api/ueba/digest/generate', { timeframe: tf });
      if (r && !r.error) setDigest(r.text || r.digest || 'Digest generated.');
    } catch {
      // ignore
    }
    setDigestLoading(false);
  }

  const s = stats || FALLBACK_UEBA_STATS;

  return (
    <div className="page" data-screen-label="UEBA">
      <Topbar
        title="UEBA"
        sub="User &amp; Entity Behavior Analytics · Neo4j graph"
        actions={<>
          {['24h', '7d', '30d'].map(t => (
            <button
              key={t}
              className={tf === t ? 'btn btn-primary' : 'btn btn-ghost'}
              onClick={() => setTf(t)}
            >{t}</button>
          ))}
          <button className="btn btn-ghost" onClick={() => setTf(tf)}>
            <Icon.refresh width="13" height="13" /> Refresh
          </button>
        </>}
      />

      <div className="page-body">

        {/* KPI Strip */}
        <div className="kpi-grid">
          <div className="kpi">
            <div className="kpi-label">Users Tracked</div>
            <div className="kpi-value">{s.users}</div>
            <div className="kpi-foot"><span className="kpi-sub">in graph</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Hosts in Graph</div>
            <div className="kpi-value">{s.hosts}</div>
            <div className="kpi-foot"><span className="kpi-sub">monitored</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Processes Observed</div>
            <div className="kpi-value">{s.processes}</div>
            <div className="kpi-foot"><span className="kpi-sub">unique</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Graph Edges</div>
            <div className="kpi-value">{(s.edges || 0).toLocaleString()}</div>
            <div className="kpi-foot"><span className="kpi-sub">relationships</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Avg Risk Score</div>
            <div className="kpi-value">{s.avgRisk}</div>
            <div className="kpi-foot"><span className="kpi-sub">across entities</span></div>
          </div>
          <div className="kpi" data-sev={s.highRisk > 0 ? 'critical' : undefined}>
            <div className="kpi-label">High Risk (≥70)</div>
            <div className="kpi-value">{s.highRisk}</div>
            <div className="kpi-foot"><span className="kpi-sub">need review</span></div>
          </div>
        </div>

        {/* Risk Leaderboard */}
        <Card
          title="Risk Leaderboard"
          sub="entity risk scores · sorted by score desc"
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
              style={{
                background: 'var(--bg-2)', border: '1px solid var(--ln)',
                borderRadius: 4, padding: '4px 10px', fontSize: 11.5,
                color: 'var(--fg-0)', width: 80,
              }}
              placeholder="Min score"
              value={lbMinRisk}
              onChange={e => setLbMinRisk(e.target.value)}
              type="number" min="0" max="100"
            />
            <button className="btn btn-ghost btn-sm" onClick={() => { setLbSearch(''); setLbMinRisk(''); }}>
              Reset
            </button>
          </>}
        >
          {filteredLb.length === 0 ? (
            <div className="empty mono">No entities match filter</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 42 }}>RANK</th>
                  <th>ENTITY</th>
                  <th style={{ width: 64 }}>TYPE</th>
                  <th style={{ width: 200 }}>RISK SCORE</th>
                  <th style={{ width: 90 }}>ANOMALIES</th>
                  <th style={{ width: 110 }}>LAST ACTIVE</th>
                  <th style={{ width: 90 }}>ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {filteredLb.map((row, idx) => (
                  <tr key={row.name}>
                    <td className="mono dim" style={{ textAlign: 'center' }}>#{idx + 1}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                        <SevDot sev={row.risk >= 70 ? 'critical' : row.risk >= 40 ? 'high' : 'low'} />
                        <span className="mono" style={{ fontSize: 12.5 }}>{row.name}</span>
                      </div>
                    </td>
                    <td>
                      <Chip mono tone={row.type === 'Host' ? 'warn' : 'default'}>{row.type}</Chip>
                    </td>
                    <td><RiskBar risk={row.risk} /></td>
                    <td className="mono" style={{ textAlign: 'center' }}>
                      <span style={{ color: row.anomalies > 3 ? 'var(--crit)' : row.anomalies > 0 ? 'var(--high)' : 'var(--fg-3)' }}>
                        {row.anomalies}
                      </span>
                    </td>
                    <td className="mono dim" style={{ fontSize: 11 }}>{row.lastActive}</td>
                    <td>
                      <button
                        className="btn btn-ghost btn-sm"
                        style={{ fontSize: 11 }}
                        onClick={() => { setEntityInput(row.name); }}
                      >Profile</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        {/* Entity Lookup + Attack Path Finder */}
        <div className="grid-12">
          <Card title="Entity Lookup" sub="query entity profile from graph" span={6}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
              <input
                className="mono"
                style={{
                  flex: 1, background: 'var(--bg-2)', border: '1px solid var(--ln)',
                  borderRadius: 4, padding: '6px 10px', fontSize: 12,
                  color: 'var(--fg-0)',
                }}
                placeholder="Enter entity name (user, host, IP)…"
                value={entityInput}
                onChange={e => setEntityInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && lookupEntity()}
              />
              <button className="btn btn-primary" onClick={lookupEntity} disabled={entityLoading}>
                {entityLoading ? 'Loading…' : 'Graph'}
              </button>
            </div>
            {entityProfile ? (
              entityProfile.error ? (
                <div className="mono" style={{ color: 'var(--crit)', fontSize: 12 }}>{entityProfile.error}</div>
              ) : (
                <div style={{
                  background: 'var(--bg-2)', border: '1px solid var(--ln)',
                  borderRadius: 6, padding: 14,
                }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                    {Object.entries(entityProfile).map(([k, v]) => (
                      <div key={k}>
                        <div style={{ fontSize: 9.5, fontFamily: 'var(--mono)', color: 'var(--fg-3)', letterSpacing: 1, textTransform: 'uppercase', marginBottom: 2 }}>{k}</div>
                        <div className="mono" style={{ fontSize: 12, color: 'var(--fg-0)' }}>{String(v)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )
            ) : (
              <div className="empty mono">Enter an entity name and click Graph</div>
            )}
          </Card>

          <Card title="Attack Path Finder" sub="shortest lateral movement path in graph" span={6}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  className="mono"
                  style={{
                    flex: 1, background: 'var(--bg-2)', border: '1px solid var(--ln)',
                    borderRadius: 4, padding: '6px 10px', fontSize: 12,
                    color: 'var(--fg-0)',
                  }}
                  placeholder="From entity…"
                  value={pathFrom}
                  onChange={e => setPathFrom(e.target.value)}
                />
                <input
                  className="mono"
                  style={{
                    flex: 1, background: 'var(--bg-2)', border: '1px solid var(--ln)',
                    borderRadius: 4, padding: '6px 10px', fontSize: 12,
                    color: 'var(--fg-0)',
                  }}
                  placeholder="To entity…"
                  value={pathTo}
                  onChange={e => setPathTo(e.target.value)}
                />
                <button className="btn btn-primary" onClick={findPath} disabled={pathLoading}>
                  {pathLoading ? '…' : 'Find Path'}
                </button>
              </div>
              {pathResult ? (
                pathResult.error ? (
                  <div className="mono" style={{ color: 'var(--med)', fontSize: 12 }}>{pathResult.error}</div>
                ) : (
                  <div style={{
                    background: 'var(--bg-2)', border: '1px solid var(--ln)',
                    borderRadius: 6, padding: 12,
                  }}>
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
                      <div className="mono" style={{ fontSize: 10.5, color: 'var(--fg-3)', marginTop: 8 }}>
                        {pathResult.hops} hop{pathResult.hops !== 1 ? 's' : ''} · risk {pathResult.totalRisk ?? '—'}
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

        {/* Anomaly Panels — 3 rows of 2 */}
        <div className="grid-12">
          <AnomalyPanel panel={ANOMALY_PANELS[0]} items={anomalies.lateral_movement} />
          <AnomalyPanel panel={ANOMALY_PANELS[1]} items={anomalies.impossible_travel} />
        </div>
        <div className="grid-12">
          <AnomalyPanel panel={ANOMALY_PANELS[2]} items={anomalies.privilege_escalation} />
          <AnomalyPanel panel={ANOMALY_PANELS[3]} items={anomalies.after_hours_access} />
        </div>
        <div className="grid-12">
          <AnomalyPanel panel={ANOMALY_PANELS[4]} items={anomalies.high_freq_logins} />
          <AnomalyPanel panel={ANOMALY_PANELS[5]} items={anomalies.rare_processes} />
        </div>

        {/* Weekly AI Digest */}
        <Card
          title="AI Behavior Digest"
          sub="weekly summary · LangChain ReAct analysis"
          actions={<>
            <button
              className="btn btn-primary"
              onClick={generateDigest}
              disabled={digestLoading}
            >
              <Icon.brain width="13" height="13" />
              {digestLoading ? ' Generating…' : ' Generate Digest'}
            </button>
          </>}
        >
          {digest ? (
            <div style={{
              background: 'var(--bg-2)', border: '1px solid var(--ln)',
              borderRadius: 6, padding: 16,
              fontFamily: 'var(--sans)', fontSize: 13, lineHeight: 1.65,
              color: 'var(--fg-1)', whiteSpace: 'pre-wrap',
            }}>
              {digest}
            </div>
          ) : (
            <div className="empty mono">No digest available — click Generate Digest to create one</div>
          )}
        </Card>

      </div>
    </div>
  );
}

Object.assign(window, { PageUEBA });
