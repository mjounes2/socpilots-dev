// Dashboard + Alerts pages
const { useState: useState1, useMemo: useMemo1, useEffect: useEffect1 } = React;

// ============= DASHBOARD =============
function PageDashboard() {
  const [state, setState] = useState1({ loading: true, data: null });

  useEffect1(() => {
    Promise.all([
      window.SOC_API.get('/api/dashboard'),
      window.SOC_API.get('/api/stats/top-rules'),
      window.SOC_API.get('/api/stats/top-agents'),
      window.SOC_API.get('/api/alerts?page=1&page_size=8&hours=24'),
      window.SOC_API.get('/api/stats/top-ips'),
    ]).then(([dash, topRules, topAgents, alertsResp, topIps]) => {
      setState({ loading: false, data: { dash, topRules, topAgents, alertsResp, topIps } });
    });
  }, []);

  if (state.loading || !state.data) {
    return (
      <div className="page" data-screen-label="01 Dashboard">
        <Topbar title="Dashboard" sub="Last 24 hours · SIEM + SP-CM · live" actions={<>
          <button className="btn btn-ghost"><Icon.refresh width="13" height="13" /> Refresh</button>
          <button className="btn btn-ghost">Last 24h <Icon.chevron width="12" height="12" /></button>
          <button className="btn btn-primary"><Icon.plus width="13" height="13" /> New Case</button>
        </>} />
        <div className="page-body">
          <div className="loading mono">Loading…</div>
        </div>
      </div>
    );
  }

  const { dash, topRules, topAgents, alertsResp, topIps } = state.data;

  // Map timeline: real API has .time ISO string, component wants .hour number
  const timeline = (dash?.timeline || []).map(t => ({
    hour: new Date(t.time).getHours(),
    critical: t.critical || 0,
    high: t.high || 0,
    medium: t.medium || 0,
    low: t.low || 0,
  }));

  // Map severity donut
  const severityDist = [
    { level: 'critical', count: dash?.criticalAlerts || 0, color: 'crit' },
    { level: 'high',     count: dash?.highAlerts    || 0, color: 'high' },
    { level: 'medium',   count: dash?.mediumAlerts  || 0, color: 'med'  },
    { level: 'low',      count: dash?.lowAlerts     || 0, color: 'low'  },
  ];

  // Map top rules: desc → name, severity → sev, first mitre tag or ''
  const mappedTopRules = (topRules || []).map(r => ({
    id:    r.id,
    name:  r.desc,
    mitre: r.mitre?.[0] || '',
    count: r.count,
    sev:   r.severity,
  }));

  // Map top agents: name, count → alerts, synthetic fields
  const mappedTopAgents = (topAgents || []).map(a => ({
    id:     '',
    name:   a.name,
    os:     '',
    alerts: a.count,
    last:   '',
    status: 'active',
  }));

  // Map recent alerts: timestamp → Date, description → rule, etc.
  const recentAlerts = ((alertsResp?.alerts || []).slice(0, 8)).map(a => ({
    id:     a.id,
    time:   new Date(a.timestamp),
    agent:  a.agent,
    srcIp:  a.srcIp,
    rule:   a.description,
    mitre:  Array.isArray(a.mitre) ? a.mitre[0] || '' : a.mitre || '',
    sev:    a.severity,
    geo:    '',
  }));

  // WorldMap: no geo data from API, use fallback card
  const topIpsList = topIps || [];
  const totalHits = (dash?.alerts24h || 0);

  return (
    <div className="page" data-screen-label="01 Dashboard">
      <Topbar
        title="Dashboard"
        sub="Last 24 hours · SIEM + SP-CM · live"
        actions={<>
          <button className="btn btn-ghost"><Icon.refresh width="13" height="13" /> Refresh</button>
          <button className="btn btn-ghost">Last 24h <Icon.chevron width="12" height="12" /></button>
          <button className="btn btn-primary"><Icon.plus width="13" height="13" /> New Case</button>
        </>}
      />

      <div className="page-body">
        {/* KPI Strip */}
        <div className="kpi-grid">
          <KpiCard label="Alerts (24h)" value={(dash?.alerts24h || 0).toLocaleString()}
            trend={null} sub="vs. prev. 24h"
            spark={timeline.map(t => t.critical + t.high + t.medium + t.low)} />
          <KpiCard label="Critical alerts" value={dash?.criticalAlerts || 0}
            sub="awaiting triage" sev="critical" big />
          <KpiCard label="Active agents" value={dash?.totalAgents || 0}
            sub="monitored" />
          <KpiCard label="Open cases" value={dash?.openCases || 0}
            trend={null} sub="across 4 lanes" />
          <KpiCard label="MTTD" value="—" sub="mean time to detect" mono />
          <KpiCard label="MTTR" value="—" sub="mean time to respond" mono />
        </div>

        {/* Row 1: timeline + severity donut */}
        <div className="grid-12">
          <Card title="Alert timeline" sub="hourly · last 24h · stacked by severity" span={8}
            actions={<><Chip>stack</Chip><Chip tone="dim">line</Chip></>}>
            {timeline.length > 0
              ? <AlertTimeline data={timeline} />
              : <div className="empty mono">No timeline data</div>}
          </Card>
          <Card title="Severity mix" sub="last 24h" span={4}>
            <SeverityDonut data={severityDist} />
          </Card>
        </div>

        {/* Row 2: attack origins (fallback, no geo) + recent alerts */}
        <div className="grid-12">
          <Card title="Attack origins" sub="top source IPs · last 24h" span={7}
            actions={<><Chip mono>{totalHits.toLocaleString()} hits / 24h</Chip></>}>
            <AttackOriginsTable ips={topIpsList} />
          </Card>
          <Card title="Recent alerts" sub="live feed" span={5}
            actions={<><span className="live-pip"><span className="pip" />LIVE</span></>}>
            <RecentAlertsFeed alerts={recentAlerts} />
          </Card>
        </div>

        {/* Row 3: top rules + top agents */}
        <div className="grid-12">
          <Card title="Top triggered rules" sub="24h · with MITRE mapping" span={7}>
            <TopRulesTable rules={mappedTopRules} />
          </Card>
          <Card title="Top noisy agents" sub="alert count" span={5}>
            <TopAgentsList agents={mappedTopAgents} />
          </Card>
        </div>
      </div>
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
      {spark && <div className="kpi-spark"><Sparkline data={spark} height={28} color="var(--acc)" /></div>}
    </div>
  );
}

// ====== Stacked-area timeline (SVG) ======
function AlertTimeline({ data }) {
  const w = 800, h = 220, pad = { l: 36, r: 12, t: 12, b: 26 };
  const innerW = w - pad.l - pad.r;
  const innerH = h - pad.t - pad.b;
  const layers = ['low', 'medium', 'high', 'critical'];
  const layerColor = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)' };

  // Build stacked values
  const stack = data.map(d => {
    let acc = 0;
    return layers.map(L => {
      const v0 = acc; acc += d[L]; return [v0, acc];
    });
  });
  const maxY = Math.max(...stack.flatMap(s => s.map(p => p[1])));
  const x = (i) => pad.l + (i / (data.length - 1)) * innerW;
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
      {/* Grid */}
      {yTicks.map((t, i) => (
        <g key={i}>
          <line x1={pad.l} x2={w - pad.r} y1={y(t)} y2={y(t)} stroke="var(--ln)" strokeDasharray="2 4" />
          <text x={pad.l - 8} y={y(t) + 3} textAnchor="end" className="chart-tick">{t}</text>
        </g>
      ))}
      {/* X labels */}
      {data.map((d, i) => i % 4 === 0 && (
        <text key={i} x={x(i)} y={h - 8} textAnchor="middle" className="chart-tick">{String(d.hour).padStart(2, '0')}:00</text>
      ))}
      {/* Layers */}
      {paths.map(p => (
        <path key={p.L} d={p.d} fill={layerColor[p.L]} opacity={p.L === 'low' ? 0.45 : 0.78} />
      ))}
      {/* Legend */}
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
  const r = 70, c = 2 * Math.PI * r;
  let offset = 0;
  const colorMap = { crit: 'var(--crit)', high: 'var(--high)', med: 'var(--med)', low: 'var(--low)' };
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 200 200" width="200" height="200">
        <circle cx="100" cy="100" r={r} fill="none" stroke="var(--ln)" strokeWidth="1" />
        {data.map((d, i) => {
          const frac = total > 0 ? d.count / total : 0;
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
        <text x="100" y="116" textAnchor="middle" className="donut-lbl">alerts · 24h</text>
      </svg>
      <ul className="donut-legend">
        {data.map(d => (
          <li key={d.level}>
            <SevDot sev={d.level === 'crit' ? 'critical' : d.level === 'high' ? 'high' : d.level === 'med' ? 'medium' : 'low'} />
            <span className="dl-lvl">{d.level === 'crit' ? 'critical' : d.level === 'med' ? 'medium' : d.level}</span>
            <span className="dl-pct mono">{total > 0 ? Math.round(d.count / total * 100) : 0}%</span>
            <span className="dl-cnt mono">{d.count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ====== Attack origins fallback (no geo data from API) ======
function AttackOriginsTable({ ips }) {
  if (!ips || ips.length === 0) {
    return <div className="empty mono">No attack origin data available</div>;
  }
  const max = Math.max(...ips.map(i => i.count));
  return (
    <table className="data-table">
      <thead><tr>
        <th>SOURCE IP</th>
        <th style={{width:140}}>HIT COUNT</th>
      </tr></thead>
      <tbody>
        {ips.map((ip, idx) => (
          <tr key={idx}>
            <td className="mono">{ip.ip}</td>
            <td>
              <div className="bar-wrap">
                <div className="bar" data-sev={ip.count > 30 ? 'critical' : ip.count > 15 ? 'high' : ip.count > 7 ? 'medium' : 'low'}
                  style={{ width: `${ip.count / max * 100}%` }} />
                <span className="bar-val mono">{ip.count}</span>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ====== Recent alerts feed ======
function RecentAlertsFeed({ alerts }) {
  return (
    <ul className="feed">
      {alerts.map(a => (
        <li key={a.id} className="feed-item" data-sev={a.sev}>
          <div className="feed-sev"><SevDot sev={a.sev} size={6} /></div>
          <div className="feed-body">
            <div className="feed-row1">
              <span className="feed-rule">{a.rule}</span>
              <span className="feed-mitre mono">{a.mitre}</span>
            </div>
            <div className="feed-row2 mono">
              <span>{a.agent}</span>
              <span className="feed-dim">←</span>
              <span>{a.srcIp}</span>
              <span className="feed-dim">·</span>
              <span className="feed-geo">{a.geo}</span>
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
  const ms = t instanceof Date ? t.getTime() : new Date(t).getTime();
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

// ====== Top rules table ======
function TopRulesTable({ rules }) {
  if (!rules || rules.length === 0) return <div className="empty mono">No rule data</div>;
  const max = Math.max(...rules.map(r => r.count));
  return (
    <table className="data-table">
      <thead><tr>
        <th style={{width:60}}>RULE</th>
        <th>NAME</th>
        <th style={{width:90}}>MITRE</th>
        <th style={{width:60}}>SEV</th>
        <th style={{width:140}}>COUNT</th>
      </tr></thead>
      <tbody>
        {rules.map(r => (
          <tr key={r.id}>
            <td className="mono dim">{r.id}</td>
            <td>{r.name}</td>
            <td className="mono"><a href="#" className="link">{r.mitre}</a></td>
            <td><SevChip sev={r.sev} /></td>
            <td>
              <div className="bar-wrap">
                <div className="bar" data-sev={r.sev} style={{ width: `${r.count / max * 100}%` }} />
                <span className="bar-val mono">{r.count}</span>
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
      {agents.map((a, idx) => (
        <li key={a.id || idx} className="agent-row">
          <div className="agent-id mono">#{a.id}</div>
          <div className="agent-info">
            <div className="agent-name">
              <SevDot sev={a.status === 'active' ? 'low' : 'offline'} size={6} />
              {a.name}
            </div>
            <div className="agent-meta mono">{a.os} · {a.last}</div>
          </div>
          <div className="agent-count mono">{a.alerts}</div>
        </li>
      ))}
    </ul>
  );
}

// ============= ALERTS PAGE =============
function PageAlerts() {
  const [sevFilter, setSevFilter] = useState1('all');
  const [alerts, setAlerts] = useState1([]);
  const [total, setTotal] = useState1(0);
  const [loading, setLoading] = useState1(true);
  const [selected, setSelected] = useState1(null);

  useEffect1(() => {
    setLoading(true);
    setSelected(null);
    const url = sevFilter === 'all'
      ? '/api/alerts?page=1&page_size=50&hours=24'
      : `/api/alerts?severity=${sevFilter}&page=1&page_size=50&hours=24`;
    window.SOC_API.get(url).then(resp => {
      const raw = resp?.alerts || [];
      const mapped = raw.map(a => ({
        id:        a.id,
        time:      new Date(a.timestamp),
        agent:     a.agent,
        srcIp:     a.srcIp,
        rule:      a.description,
        mitre:     Array.isArray(a.mitre) ? a.mitre[0] || '' : a.mitre || '',
        sev:       a.severity,
        geo:       '',
        // Keep raw fields for AlertDetail
        timestamp: a.timestamp,
        ruleId:    a.ruleId,
        level:     a.level,
        agentIp:   a.agentIp,
        mitreTactic: a.mitreTactic,
      }));
      setAlerts(mapped);
      setTotal(resp?.total || mapped.length);
      setLoading(false);
    });
  }, [sevFilter]);

  // Set selected to first alert after load
  useEffect1(() => {
    if (!selected && alerts.length > 0) {
      setSelected(alerts[0]);
    }
  }, [alerts]);

  return (
    <div className="page" data-screen-label="02 Alerts">
      <Topbar
        title="Alerts"
        sub="Live feed · SIEM"
        actions={<>
          <button className="btn btn-ghost"><Icon.refresh width="13" height="13" /> Auto-refresh</button>
          <button className="btn btn-ghost"><Icon.filter width="13" height="13" /> Saved views</button>
          <button className="btn btn-primary">Bulk → New case</button>
        </>}
      />
      <div className="page-body">
        <div className="alerts-toolbar">
          <div className="seg">
            {['all','critical','high','medium','low'].map(s => (
              <button key={s} className={`seg-btn ${sevFilter===s?'on':''}`} onClick={()=>setSevFilter(s)}>
                {s !== 'all' && <SevDot sev={s} size={6} />}
                {s}
                <span className="seg-count mono">
                  {s === 'all' ? alerts.length : alerts.filter(a => a.sev === s).length}
                </span>
              </button>
            ))}
          </div>
          <div className="alerts-filters">
            <Chip mono icon={<Icon.filter width="11" height="11" />}>agent: any</Chip>
            <Chip mono>src.ip: any</Chip>
            <Chip mono>mitre: any</Chip>
            <Chip mono>time: 24h</Chip>
            <button className="btn-icon"><Icon.plus width="13" height="13" /></button>
          </div>
        </div>

        <div className="alerts-layout">
          <div className="alerts-table-wrap">
            <table className="alerts-table">
              <thead>
                <tr>
                  <th className="th-sev"></th>
                  <th>TIME</th>
                  <th>ALERT ID</th>
                  <th>RULE</th>
                  <th>MITRE</th>
                  <th>AGENT</th>
                  <th>SRC IP</th>
                  <th>GEO</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="8" className="loading mono" style={{textAlign:'center',padding:'2rem'}}>Loading…</td>
                  </tr>
                ) : alerts.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="empty mono" style={{textAlign:'center',padding:'2rem'}}>No alerts found</td>
                  </tr>
                ) : (
                  alerts.map((a, idx) => (
                    <tr key={`${a.id}-${idx}`} className={selected?.id === a.id ? 'sel' : ''} onClick={()=>setSelected(a)}>
                      <td><span className="sev-bar" data-sev={a.sev} /></td>
                      <td className="mono dim">{relTime(a.time)}</td>
                      <td className="mono">{a.id}</td>
                      <td>{a.rule}</td>
                      <td className="mono"><a href="#" className="link">{a.mitre}</a></td>
                      <td className="mono">{a.agent}</td>
                      <td className="mono">{a.srcIp}</td>
                      <td className="mono dim">{a.geo}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <aside className="alerts-detail">
            {selected && <AlertDetail alert={selected} />}
          </aside>
        </div>
      </div>
    </div>
  );
}

function AlertDetail({ alert }) {
  const timeStr = (() => {
    try {
      return new Date(alert.timestamp).toISOString().slice(0, 19).replace('T', ' ');
    } catch {
      return alert.time instanceof Date
        ? alert.time.toISOString().slice(0, 19).replace('T', ' ')
        : String(alert.timestamp || '');
    }
  })();

  return (
    <div className="detail">
      <div className="detail-head">
        <SevChip sev={alert.sev} />
        <span className="mono dim">{alert.id}</span>
        <button className="btn-icon detail-close"><Icon.x width="14" height="14"/></button>
      </div>
      <h2 className="detail-title">{alert.rule}</h2>
      <div className="detail-time mono">{timeStr} UTC</div>

      <div className="detail-grid">
        <div className="detail-cell">
          <div className="dc-label">AGENT</div>
          <div className="dc-value mono">{alert.agent}</div>
        </div>
        <div className="detail-cell">
          <div className="dc-label">MITRE</div>
          <div className="dc-value mono"><a className="link" href="#">{alert.mitre}</a></div>
        </div>
        <div className="detail-cell">
          <div className="dc-label">SOURCE IP</div>
          <div className="dc-value mono">{alert.srcIp}</div>
        </div>
        <div className="detail-cell">
          <div className="dc-label">GEO</div>
          <div className="dc-value mono">{alert.geo}</div>
        </div>
      </div>

      <div className="detail-section">
        <div className="ds-title">AI verdict <span className="ds-tag">SOCPilots AI</span></div>
        <div className="ai-verdict">
          <span className="av-pill">true positive · 96%</span>
          <p>The base64-encoded PowerShell payload spawned by cmd.exe matches behavior consistent with Cobalt Strike beaconing. Source IP is a known Tor exit. Recommend immediate containment of <span className="mono">{alert.agent}</span>.</p>
        </div>
      </div>

      <div className="detail-section">
        <div className="ds-title">IOC enrichment</div>
        <div className="ioc-row">
          <div className="ioc-key mono">{alert.srcIp}</div>
          <div className="ioc-vals">
            <Chip mono tone="crit">VT 18/94</Chip>
            <Chip mono tone="crit">AbuseIPDB 100%</Chip>
            <Chip mono tone="warn">Tor exit</Chip>
          </div>
        </div>
      </div>

      <div className="detail-actions">
        <button className="btn btn-primary" onClick={() => window.socToast?.({title:'Case created', sub: 'CASE-4473 · linked to ' + alert.id, tone:'ok'})}><Icon.folder width="13" height="13"/> Create case</button>
        <button className="btn btn-ghost" onClick={() => window.socToast?.({title:'Isolation queued', sub: alert.agent + ' · cordoned in 2.4s', tone:'crit'})}>Isolate agent</button>
        <button className="btn btn-ghost" onClick={() => window.socToast?.({title:'Alert suppressed', sub: alert.id + ' · 24h', tone:'default'})}>Suppress</button>
      </div>
    </div>
  );
}

Object.assign(window, { PageDashboard, PageAlerts, KpiCard });
