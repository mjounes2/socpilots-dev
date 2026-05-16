// Dashboard + Alerts pages — wired to real backend APIs
const { useState: useState1, useMemo: useMemo1, useEffect: useEffect1, useCallback: useCallback1 } = React;

// ============= DASHBOARD =============
function PageDashboard() {
  const API = window.SOC_API;
  const [dash, setDash] = useState1(null);
  const [topRules, setTopRules] = useState1([]);
  const [topAgents, setTopAgents] = useState1([]);
  const [topIPs, setTopIPs] = useState1([]);
  const [recentAlerts, setRecentAlerts] = useState1([]);
  const [loading, setLoading] = useState1(true);
  const [timeframe, setTimeframe] = useState1('24');

  const load = useCallback1(async (hours) => {
    setLoading(true);
    const [dashData, rulesData, agentsData, ipsData, alertsData] = await Promise.all([
      API.get(`/api/dashboard?hours=${hours}`),
      API.get('/api/stats/top-rules'),
      API.get('/api/stats/top-agents'),
      API.get('/api/stats/top-ips'),
      API.get(`/api/alerts?hours=${hours}&page=1&page_size=8`),
    ]);
    setDash(dashData);
    setTopRules(Array.isArray(rulesData) ? rulesData : []);
    setTopAgents(Array.isArray(agentsData) ? agentsData : []);
    setTopIPs(Array.isArray(ipsData) ? ipsData : []);
    const rawAlerts = alertsData?.items || alertsData?.alerts || [];
    setRecentAlerts(rawAlerts.map(adaptAlert));
    setLoading(false);
  }, []);

  useEffect1(() => { load(timeframe); }, [timeframe]);

  if (loading) return (
    <div className="page" data-screen-label="01 Dashboard">
      <Topbar title="Dashboard" sub="Loading…" />
      <div className="page-body" style={{display:'flex',alignItems:'center',justifyContent:'center',height:300}}>
        <Spinner />
      </div>
    </div>
  );

  const timeline = (dash?.timeline || []).map(t => ({
    hour: new Date(t.time).getUTCHours(),
    critical: t.critical || 0,
    high: t.high || 0,
    medium: t.medium || 0,
    low: t.low || 0,
  }));

  const sevDist = [
    { level: 'crit', color: 'crit', count: dash?.criticalAlerts || 0 },
    { level: 'high', color: 'high', count: dash?.highAlerts || 0 },
    { level: 'med',  color: 'med',  count: dash?.mediumAlerts || 0 },
    { level: 'low',  color: 'low',  count: dash?.lowAlerts || 0 },
  ].filter(d => d.count > 0);

  const spark = timeline.map(t => t.critical + t.high + t.medium + t.low);

  const adaptedRules = topRules.map(r => ({
    id: r.id,
    name: r.desc || r.description || r.id,
    mitre: Array.isArray(r.mitre) ? (r.mitre[0] || '—') : (r.mitre || '—'),
    sev: r.severity || API.sevFromLevel(r.level),
    count: r.count,
  }));

  const adaptedAgents = topAgents.map((a, i) => ({
    id: i + 1,
    name: a.name,
    os: a.os || '—',
    status: 'active',
    last: a.last_seen ? API.relTs(a.last_seen) : 'recently',
    alerts: a.count,
  }));

  const hours = parseInt(timeframe);
  const label = hours === 1 ? 'Last 1h' : hours === 24 ? 'Last 24h' : hours === 168 ? 'Last 7d' : `Last ${hours}h`;

  return (
    <div className="page" data-screen-label="01 Dashboard">
      <Topbar
        title="Dashboard"
        sub={`${label} · SIEM + SP-CM · live`}
        actions={<>
          <button className="btn btn-ghost" onClick={() => load(timeframe)}>
            <Icon.refresh width="13" height="13" /> Refresh
          </button>
          <select className="btn btn-ghost" style={{background:'transparent',border:'none',color:'var(--txt)',cursor:'pointer'}}
            value={timeframe} onChange={e => setTimeframe(e.target.value)}>
            <option value="1">Last 1h</option>
            <option value="24">Last 24h</option>
            <option value="168">Last 7d</option>
            <option value="720">Last 30d</option>
          </select>
        </>}
      />

      <div className="page-body">
        {/* KPI Strip */}
        <div className="kpi-grid">
          <KpiCard label={`Alerts (${label})`}
            value={(dash?.totalAlerts || dash?.alerts24h || 0).toLocaleString()}
            sub="total SIEM alerts"
            spark={spark} />
          <KpiCard label="Critical alerts"
            value={(dash?.criticalAlerts || 0).toLocaleString()}
            sub="rule level ≥ 12" sev="critical" big />
          <KpiCard label="Active agents"
            value={dash?.totalAgents || 0}
            sub="reporting to SIEM" />
          <KpiCard label="Open cases (SP-CM)"
            value={(dash?.openCases || 0).toLocaleString()}
            sub="awaiting triage" />
          <KpiCard label="High severity"
            value={(dash?.highAlerts || 0).toLocaleString()}
            sub="rule level 8–11" sev="high" />
          <KpiCard label="Medium severity"
            value={(dash?.mediumAlerts || 0).toLocaleString()}
            sub="rule level 5–7" />
        </div>

        {/* Row 1: timeline + severity donut */}
        <div className="grid-12">
          <Card title="Alert timeline" sub={`${label} · stacked by severity`} span={8}
            actions={<><Chip>stack</Chip></>}>
            {timeline.length > 0
              ? <AlertTimeline data={timeline} />
              : <EmptyState icon="📊" text="No timeline data available" />}
          </Card>
          <Card title="Severity mix" sub={label} span={4}>
            {sevDist.length > 0
              ? <SeverityDonut data={sevDist} />
              : <EmptyState icon="🔵" text="No alert data" />}
          </Card>
        </div>

        {/* Row 2: top source IPs + recent alerts */}
        <div className="grid-12">
          <Card title="Top source IPs" sub="24h · external attack sources" span={7}
            actions={topIPs.length > 0 ? <Chip mono>{topIPs.reduce((a,b)=>a+b.count,0).toLocaleString()} hits</Chip> : null}>
            {topIPs.length > 0
              ? <TopIPsTable ips={topIPs} />
              : <EmptyState icon="🌐" text="No external source IP data" />}
          </Card>
          <Card title="Recent alerts" sub="live feed" span={5}
            actions={<span className="live-pip"><span className="pip" />LIVE</span>}>
            {recentAlerts.length > 0
              ? <RecentAlertsFeed alerts={recentAlerts} />
              : <EmptyState icon="🔔" text="No recent alerts" />}
          </Card>
        </div>

        {/* Row 3: top rules + top agents */}
        <div className="grid-12">
          <Card title="Top triggered rules" sub="24h · sorted by volume" span={7}>
            {adaptedRules.length > 0
              ? <TopRulesTable rules={adaptedRules} />
              : <EmptyState icon="📋" text="No rule data" />}
          </Card>
          <Card title="Top noisy agents" sub="24h · by alert count" span={5}>
            {adaptedAgents.length > 0
              ? <TopAgentsList agents={adaptedAgents} />
              : <EmptyState icon="🖥" text="No agent data" />}
          </Card>
        </div>
      </div>
    </div>
  );
}

function EmptyState({ icon, text }) {
  return (
    <div style={{display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',
      padding:'2rem',color:'var(--txt-3)',gap:8}}>
      <span style={{fontSize:28}}>{icon}</span>
      <span style={{fontSize:12}}>{text}</span>
    </div>
  );
}

function KpiCard({ label, value, sub, trend, spark, sev, big, mono }) {
  return (
    <div className={`kpi ${big ? 'kpi-big' : ''}`} data-sev={sev}>
      <div className="kpi-label">{label}</div>
      <div className={`kpi-value ${mono ? 'mono' : ''}`}>{value}</div>
      <div className="kpi-foot">
        {trend != null && (
          <span className={`kpi-trend ${trend >= 0 ? 'up' : 'down'}`}>
            {trend >= 0 ? <Icon.arrowUp width="11" height="11"/> : <Icon.arrowDn width="11" height="11"/>}
            {Math.abs(trend)}%
          </span>
        )}
        {sub && <span className="kpi-sub">{sub}</span>}
      </div>
      {spark && spark.length > 0 && <div className="kpi-spark"><Sparkline data={spark} height={28} color="var(--acc)" /></div>}
    </div>
  );
}

// ====== Stacked-area timeline (SVG) ======
function AlertTimeline({ data }) {
  if (!data || data.length < 2) return <EmptyState icon="📊" text="Insufficient timeline data" />;
  const w = 800, h = 220, pad = { l: 36, r: 12, t: 12, b: 26 };
  const innerW = w - pad.l - pad.r;
  const innerH = h - pad.t - pad.b;
  const layers = ['low', 'medium', 'high', 'critical'];
  const layerColor = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)' };

  const stack = data.map(d => {
    let acc = 0;
    return layers.map(L => {
      const v0 = acc; acc += (d[L] || 0); return [v0, acc];
    });
  });
  const maxY = Math.max(...stack.flatMap(s => s.map(p => p[1])), 1);
  const x = (i) => pad.l + (i / Math.max(data.length - 1, 1)) * innerW;
  const y = (v) => pad.t + innerH - (v / maxY) * innerH;

  const paths = layers.map((L, li) => {
    const top = stack.map((s, i) => [x(i), y(s[li][1])]);
    const bot = stack.map((s, i) => [x(i), y(s[li][0])]).reverse();
    const all = [...top, ...bot];
    return { L, d: all.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ') + 'Z' };
  });

  const yTicks = [0, Math.round(maxY / 2), maxY];

  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} className="chart">
      {yTicks.map((t, i) => (
        <g key={i}>
          <line x1={pad.l} x2={w - pad.r} y1={y(t)} y2={y(t)} stroke="var(--ln)" strokeDasharray="2 4" />
          <text x={pad.l - 8} y={y(t) + 3} textAnchor="end" className="chart-tick">{t >= 1000 ? `${(t/1000).toFixed(0)}k` : t}</text>
        </g>
      ))}
      {data.map((d, i) => i % Math.max(1, Math.floor(data.length / 6)) === 0 && (
        <text key={i} x={x(i)} y={h - 8} textAnchor="middle" className="chart-tick">{String(d.hour).padStart(2, '0')}:00</text>
      ))}
      {paths.map(p => (
        <path key={p.L} d={p.d} fill={layerColor[p.L]} opacity={p.L === 'low' ? 0.45 : 0.78} />
      ))}
      <g transform={`translate(${pad.l},${pad.t - 2})`}>
        {layers.slice().reverse().map((L, i) => (
          <g key={L} transform={`translate(${i * 78},0)`}>
            <rect width="8" height="8" fill={layerColor[L]} />
            <text x="12" y="8" className="chart-legend">{L}</text>
          </g>
        ))}
      </g>
    </svg>
  );
}

// ====== Severity donut ======
function SeverityDonut({ data }) {
  const total = data.reduce((a, b) => a + b.count, 0);
  if (total === 0) return <EmptyState icon="🔵" text="No alerts" />;
  const r = 70, c = 2 * Math.PI * r;
  let offset = 0;
  const colorMap = { crit: 'var(--crit)', high: 'var(--high)', med: 'var(--med)', low: 'var(--low)' };
  const labelMap = { crit: 'critical', high: 'high', med: 'medium', low: 'low' };
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 200 200" width="200" height="200">
        <circle cx="100" cy="100" r={r} fill="none" stroke="var(--ln)" strokeWidth="1" />
        {data.map((d, i) => {
          const frac = d.count / total;
          const len = c * frac;
          const dasharray = `${len} ${c - len}`;
          const el = (
            <circle key={i} cx="100" cy="100" r={r} fill="none"
              stroke={colorMap[d.color]} strokeWidth="22"
              strokeDasharray={dasharray} strokeDashoffset={-offset}
              transform="rotate(-90 100 100)" />
          );
          offset += len;
          return el;
        })}
        <text x="100" y="96" textAnchor="middle" className="donut-num">{total.toLocaleString()}</text>
        <text x="100" y="116" textAnchor="middle" className="donut-lbl">alerts</text>
      </svg>
      <ul className="donut-legend">
        {data.map(d => (
          <li key={d.level}>
            <SevDot sev={labelMap[d.level] || d.level} />
            <span className="dl-lvl">{labelMap[d.level] || d.level}</span>
            <span className="dl-pct mono">{Math.round(d.count / total * 100)}%</span>
            <span className="dl-cnt mono">{d.count.toLocaleString()}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ====== Top source IPs table (replaces WorldMap — no geo data) ======
function TopIPsTable({ ips }) {
  const max = Math.max(...ips.map(ip => ip.count), 1);
  const sevFor = (count) => count > 1000 ? 'critical' : count > 200 ? 'high' : count > 50 ? 'medium' : 'low';
  return (
    <table className="data-table">
      <thead><tr>
        <th>#</th>
        <th>SOURCE IP</th>
        <th style={{width:60}}>SEV</th>
        <th style={{width:160}}>HIT COUNT</th>
      </tr></thead>
      <tbody>
        {ips.map((ip, i) => {
          const sev = sevFor(ip.count);
          return (
            <tr key={ip.ip}>
              <td className="mono dim">{i + 1}</td>
              <td className="mono">{ip.ip}</td>
              <td><SevChip sev={sev} /></td>
              <td>
                <div className="bar-wrap">
                  <div className="bar" data-sev={sev} style={{ width: `${ip.count/max*100}%` }} />
                  <span className="bar-val mono">{ip.count.toLocaleString()}</span>
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// ====== Recent alerts feed ======
function RecentAlertsFeed({ alerts }) {
  return (
    <ul className="feed">
      {alerts.map((a, i) => (
        <li key={`${a.id}-${i}`} className="feed-item" data-sev={a.sev}>
          <div className="feed-sev"><SevDot sev={a.sev} size={6} /></div>
          <div className="feed-body">
            <div className="feed-row1">
              <span className="feed-rule">{a.rule}</span>
              {a.mitre && a.mitre !== '—' && <span className="feed-mitre mono">{a.mitre}</span>}
            </div>
            <div className="feed-row2 mono">
              <span>{a.agent}</span>
              {a.srcIp && a.srcIp !== '—' && <><span className="feed-dim">←</span><span>{a.srcIp}</span></>}
              <span className="feed-dim">·</span>
              <span className="feed-time">{relTime(a.time)}</span>
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}

function relTime(t) {
  if (!t) return '—';
  const d = t instanceof Date ? t : new Date(t);
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m/60)}h ago`;
}

// ====== Top rules table ======
function TopRulesTable({ rules }) {
  const max = Math.max(...rules.map(r => r.count), 1);
  return (
    <table className="data-table">
      <thead><tr>
        <th style={{width:60}}>RULE</th>
        <th>DESCRIPTION</th>
        <th style={{width:90}}>MITRE</th>
        <th style={{width:60}}>SEV</th>
        <th style={{width:140}}>COUNT</th>
      </tr></thead>
      <tbody>
        {rules.map(r => (
          <tr key={r.id}>
            <td className="mono dim">{r.id}</td>
            <td style={{maxWidth:220,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}} title={r.name}>{r.name}</td>
            <td className="mono">{r.mitre !== '—' ? <span className="link">{r.mitre}</span> : <span className="dim">—</span>}</td>
            <td><SevChip sev={r.sev} /></td>
            <td>
              <div className="bar-wrap">
                <div className="bar" data-sev={r.sev} style={{ width: `${r.count/max*100}%` }} />
                <span className="bar-val mono">{r.count.toLocaleString()}</span>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ====== Top agents list ======
function TopAgentsList({ agents }) {
  return (
    <ul className="agent-list">
      {agents.map(a => (
        <li key={a.id} className="agent-row">
          <div className="agent-id mono">#{a.id}</div>
          <div className="agent-info">
            <div className="agent-name">
              <SevDot sev="low" size={6} />
              {a.name}
            </div>
            <div className="agent-meta mono">{a.os !== '—' ? `${a.os} · ` : ''}{a.last}</div>
          </div>
          <div className="agent-count mono">{a.alerts.toLocaleString()}</div>
        </li>
      ))}
    </ul>
  );
}

// ============= ALERTS PAGE =============
function adaptAlert(a) {
  const sev = a.severity || window.SOC_API.sevFromLevel(a.level);
  const mitre = Array.isArray(a.mitre) ? (a.mitre[0] || '—') : (a.mitre || '—');
  return {
    id: a.id || a._id,
    sev,
    rule: a.description || a.rule || '—',
    mitre,
    agent: a.agent || '—',
    srcIp: a.srcIp || a.src_ip || '—',
    geo: a.location || a.geo || '—',
    ruleId: a.ruleId || a.rule_id,
    level: a.level,
    fullLog: a.fullLog || a.full_log,
    groups: a.groups,
    time: new Date(a.timestamp || a.time || Date.now()),
    raw: a,
  };
}

function PageAlerts() {
  const API = window.SOC_API;
  const [alerts, setAlerts] = useState1([]);
  const [total, setTotal] = useState1(0);
  const [page, setPage] = useState1(1);
  const [pageSize] = useState1(50);
  const [sevFilter, setSevFilter] = useState1('all');
  const [selected, setSelected] = useState1(null);
  const [loading, setLoading] = useState1(true);
  const [enriching, setEnriching] = useState1(false);
  const [enrichData, setEnrichData] = useState1(null);

  const load = useCallback1(async (p, sev) => {
    setLoading(true);
    const params = new URLSearchParams({ hours: 24, page: p, page_size: pageSize });
    if (sev && sev !== 'all') params.set('severity', sev);
    const data = await API.get(`/api/alerts?${params}`);
    const items = (data?.items || data?.alerts || []).map(adaptAlert);
    setAlerts(items);
    setTotal(data?.total || items.length);
    if (items.length > 0 && !selected) setSelected(items[0]);
    setLoading(false);
  }, [pageSize]);

  useEffect1(() => {
    setPage(1);
    setSelected(null);
    load(1, sevFilter);
  }, [sevFilter]);

  const sevCounts = useMemo1(() => {
    const counts = { all: total, critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach(a => { if (counts[a.sev] !== undefined) counts[a.sev]++; });
    return counts;
  }, [alerts, total]);

  const handlePrev = () => { const p = page - 1; setPage(p); load(p, sevFilter); };
  const handleNext = () => { const p = page + 1; setPage(p); load(p, sevFilter); };
  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="page" data-screen-label="02 Alerts">
      <Topbar
        title="Alerts"
        sub="Live feed · SIEM · last 24h"
        actions={<>
          <button className="btn btn-ghost" onClick={() => load(page, sevFilter)}>
            <Icon.refresh width="13" height="13" /> Refresh
          </button>
        </>}
      />
      <div className="page-body">
        <div className="alerts-toolbar">
          <div className="seg">
            {['all','critical','high','medium','low'].map(s => (
              <button key={s} className={`seg-btn ${sevFilter===s?'on':''}`} onClick={()=>setSevFilter(s)}>
                {s !== 'all' && <SevDot sev={s} size={6} />}
                {s}
                <span className="seg-count mono">{sevCounts[s] || 0}</span>
              </button>
            ))}
          </div>
          <div className="alerts-filters">
            <span className="mono dim" style={{fontSize:11}}>
              {total.toLocaleString()} total · page {page}/{totalPages || 1}
            </span>
            {page > 1 && <button className="btn btn-ghost" style={{padding:'2px 8px'}} onClick={handlePrev}>← Prev</button>}
            {page < totalPages && <button className="btn btn-ghost" style={{padding:'2px 8px'}} onClick={handleNext}>Next →</button>}
          </div>
        </div>

        <div className="alerts-layout">
          <div className="alerts-table-wrap">
            {loading
              ? <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:200}}><Spinner /></div>
              : alerts.length === 0
                ? <div style={{padding:32,textAlign:'center',color:'var(--txt-3)'}}>No alerts found</div>
                : (
                  <table className="alerts-table">
                    <thead>
                      <tr>
                        <th className="th-sev"></th>
                        <th>TIME</th>
                        <th>RULE ID</th>
                        <th>DESCRIPTION</th>
                        <th>MITRE</th>
                        <th>AGENT</th>
                        <th>SRC IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.map((a, idx) => (
                        <tr key={`${a.id}-${idx}`}
                          className={selected?.id === a.id ? 'sel' : ''}
                          onClick={() => { setSelected(a); setEnrichData(null); }}>
                          <td><span className="sev-bar" data-sev={a.sev} /></td>
                          <td className="mono dim">{relTime(a.time)}</td>
                          <td className="mono">{a.ruleId || '—'}</td>
                          <td style={{maxWidth:240,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}
                            title={a.rule}>{a.rule}</td>
                          <td className="mono">{a.mitre !== '—' ? <span className="link">{a.mitre}</span> : <span className="dim">—</span>}</td>
                          <td className="mono">{a.agent}</td>
                          <td className="mono">{a.srcIp}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )
            }
          </div>
          <aside className="alerts-detail">
            {selected && <AlertDetail alert={selected} enrichData={enrichData} setEnrichData={setEnrichData} enriching={enriching} setEnriching={setEnriching} />}
          </aside>
        </div>
      </div>
    </div>
  );
}

function AlertDetail({ alert, enrichData, setEnrichData, enriching, setEnriching }) {
  const API = window.SOC_API;

  const enrich = async () => {
    if (!alert.srcIp || alert.srcIp === '—') return;
    setEnriching(true);
    const data = await API.get(`/api/langchain/enrich?ip=${encodeURIComponent(alert.srcIp)}`);
    setEnrichData(data);
    setEnriching(false);
  };

  const createCase = async () => {
    const res = await API.post('/api/cases', {
      title: alert.rule,
      description: `Alert ${alert.id}: ${alert.rule}\nAgent: ${alert.agent}\nSrc IP: ${alert.srcIp}`,
      severity: alert.sev,
      source_alert_id: alert.id,
    });
    if (res && !res.error) {
      window.socToast?.({ title: 'Case created', sub: `${res.caseId || res.id} · linked to alert`, tone: 'ok' });
    } else {
      window.socToast?.({ title: 'Failed to create case', sub: res?.error || 'Unknown error', tone: 'crit' });
    }
  };

  return (
    <div className="detail">
      <div className="detail-head">
        <SevChip sev={alert.sev} />
        <span className="mono dim" style={{fontSize:11}}>{alert.ruleId}</span>
      </div>
      <h2 className="detail-title">{alert.rule}</h2>
      <div className="detail-time mono">{alert.time instanceof Date ? alert.time.toISOString().slice(0,19).replace('T',' ') : alert.time} UTC</div>

      <div className="detail-grid">
        <div className="detail-cell">
          <div className="dc-label">AGENT</div>
          <div className="dc-value mono">{alert.agent}</div>
        </div>
        <div className="detail-cell">
          <div className="dc-label">MITRE</div>
          <div className="dc-value mono">{alert.mitre}</div>
        </div>
        <div className="detail-cell">
          <div className="dc-label">SOURCE IP</div>
          <div className="dc-value mono">{alert.srcIp}</div>
        </div>
        <div className="detail-cell">
          <div className="dc-label">LEVEL</div>
          <div className="dc-value mono">{alert.level}</div>
        </div>
        {alert.groups && (
          <div className="detail-cell" style={{gridColumn:'1/-1'}}>
            <div className="dc-label">GROUPS</div>
            <div className="dc-value mono" style={{wordBreak:'break-all'}}>
              {Array.isArray(alert.groups) ? alert.groups.join(', ') : alert.groups}
            </div>
          </div>
        )}
      </div>

      {alert.fullLog && (
        <div className="detail-section">
          <div className="ds-title">Raw log</div>
          <pre style={{fontSize:10,background:'var(--bg-0)',padding:8,borderRadius:4,
            overflowX:'auto',maxHeight:120,whiteSpace:'pre-wrap',wordBreak:'break-all',
            color:'var(--txt-2)'}}>
            {typeof alert.fullLog === 'string' ? alert.fullLog : JSON.stringify(alert.fullLog, null, 2)}
          </pre>
        </div>
      )}

      {alert.srcIp && alert.srcIp !== '—' && (
        <div className="detail-section">
          <div className="ds-title">
            IOC enrichment
            {!enrichData && !enriching && (
              <button className="btn btn-ghost" style={{marginLeft:8,padding:'2px 8px',fontSize:11}}
                onClick={enrich}>Enrich IP</button>
            )}
            {enriching && <span className="dim" style={{marginLeft:8,fontSize:11}}>Enriching…</span>}
          </div>
          {enrichData && (
            <div className="ioc-row">
              <div className="ioc-key mono">{alert.srcIp}</div>
              <div className="ioc-vals">
                {enrichData.virustotal?.malicious > 0 &&
                  <Chip mono tone="crit">VT {enrichData.virustotal.malicious}/{enrichData.virustotal.total}</Chip>}
                {enrichData.abuseipdb?.abuseConfidenceScore > 0 &&
                  <Chip mono tone={enrichData.abuseipdb.abuseConfidenceScore > 50 ? 'crit' : 'warn'}>
                    AbuseIPDB {enrichData.abuseipdb.abuseConfidenceScore}%
                  </Chip>}
                {enrichData.abuseipdb?.countryCode &&
                  <Chip mono>{enrichData.abuseipdb.countryCode}</Chip>}
                {enrichData.abuseipdb?.isp &&
                  <Chip mono tone="dim">{enrichData.abuseipdb.isp}</Chip>}
                {enrichData.otx?.pulse_count > 0 &&
                  <Chip mono tone="warn">OTX {enrichData.otx.pulse_count} pulses</Chip>}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="detail-actions">
        <button className="btn btn-primary" onClick={createCase}>
          <Icon.folder width="13" height="13"/> Create case
        </button>
        <button className="btn btn-ghost" onClick={() =>
          window.socToast?.({ title: 'Alert suppressed', sub: `${alert.id} · 24h`, tone: 'default' })}>
          Suppress
        </button>
      </div>
    </div>
  );
}

Object.assign(window, { PageDashboard, PageAlerts });
