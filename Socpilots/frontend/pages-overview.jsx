// Dashboard + Alerts pages
const { useState: useState1, useMemo: useMemo1, useEffect: useEffect1 } = React;

// ============= DASHBOARD =============
function PageDashboard() {
  const D = window.SOC_DATA;
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
          <KpiCard label="Alerts (24h)" value={D.KPIS.alerts24h.toLocaleString()}
            trend={D.KPIS.alertsTrend} sub="vs. prev. 24h"
            spark={D.TIMELINE_24H.map(t => t.critical + t.high + t.medium + t.low)} />
          <KpiCard label="Critical alerts" value={D.KPIS.criticalAlerts}
            sub="awaiting triage" sev="critical" big />
          <KpiCard label="Active agents" value={`${D.KPIS.activeAgents}/${D.KPIS.agentsTotal}`}
            sub={`${D.KPIS.agentsTotal - D.KPIS.activeAgents} offline`} />
          <KpiCard label="Open cases" value={D.KPIS.openCases}
            trend={D.KPIS.casesTrend} sub="across 4 lanes" />
          <KpiCard label="MTTD" value={D.KPIS.mttd} sub="mean time to detect" mono />
          <KpiCard label="MTTR" value={D.KPIS.mttr} sub="mean time to respond" mono />
        </div>

        {/* Row 1: timeline + severity donut */}
        <div className="grid-12">
          <Card title="Alert timeline" sub="hourly · last 24h · stacked by severity" span={8}
            actions={<><Chip>stack</Chip><Chip tone="dim">line</Chip></>}>
            <AlertTimeline data={D.TIMELINE_24H} />
          </Card>
          <Card title="Severity mix" sub="last 24h" span={4}>
            <SeverityDonut data={D.SEVERITY_DIST} />
          </Card>
        </div>

        {/* Row 2: world map + recent alerts */}
        <div className="grid-12">
          <Card title="Attack origins" sub="real-time · live IP geolocation" span={7}
            actions={<><Chip mono>{D.ATTACK_ORIGINS.reduce((a,b)=>a+b.count,0)} hits / 24h</Chip></>}>
            <WorldMap origins={D.ATTACK_ORIGINS} target={D.TARGET} />
          </Card>
          <Card title="Recent alerts" sub="live feed" span={5}
            actions={<><span className="live-pip"><span className="pip" />LIVE</span></>}>
            <RecentAlertsFeed alerts={D.RECENT_ALERTS.slice(0, 8)} />
          </Card>
        </div>

        {/* Row 3: top rules + top agents */}
        <div className="grid-12">
          <Card title="Top triggered rules" sub="24h · with MITRE mapping" span={7}>
            <TopRulesTable rules={D.TOP_RULES} />
          </Card>
          <Card title="Top noisy agents" sub="alert count" span={5}>
            <TopAgentsList agents={D.TOP_AGENTS} />
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
        <text x="100" y="116" textAnchor="middle" className="donut-lbl">alerts · 24h</text>
      </svg>
      <ul className="donut-legend">
        {data.map(d => (
          <li key={d.level}>
            <SevDot sev={d.level === 'crit' ? 'critical' : d.level === 'high' ? 'high' : d.level === 'med' ? 'medium' : 'low'} />
            <span className="dl-lvl">{d.level === 'crit' ? 'critical' : d.level === 'med' ? 'medium' : d.level}</span>
            <span className="dl-pct mono">{Math.round(d.count / total * 100)}%</span>
            <span className="dl-cnt mono">{d.count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ====== World attack map ======
function WorldMap({ origins, target }) {
  // Equirectangular projection, 720x360 viewport
  const W = 720, H = 320;
  const proj = (lat, lng) => [ ((lng + 180) / 360) * W, ((90 - lat) / 180) * H ];
  const [tx, ty] = proj(target.lat, target.lng);
  const maxCount = Math.max(...origins.map(o => o.count));

  // A rough world silhouette as dotted continents (procedural — many tiny circles)
  // We use a simple low-res grid mask hand-tuned to read as continents.
  const continents = useMemo1(() => {
    const dots = [];
    // Continent silhouettes — coarse but unmistakable
    // Each is a list of [lng, lat] sample points; we'll perturb
    const regions = [
      // NORTH AMERICA
      ...gridFill(-165,-55, 25, 72, 8),
      // SOUTH AMERICA
      ...gridFill(-82,-35, -34, 12, 8),
      // EUROPE
      ...gridFill(-10, 36, 40, 70, 6),
      // AFRICA
      ...gridFill(-18,-35, 52, 36, 7),
      // ASIA
      ...gridFill(40, 8, 145, 70, 8),
      // OCEANIA
      ...gridFill(112,-44, 155,-12, 6),
    ];
    return regions.map((p, i) => proj(p[1], p[0]));
  }, []);

  function gridFill(lng0, lat0, lng1, lat1, step) {
    const out = [];
    for (let ln = lng0; ln <= lng1; ln += step) {
      for (let lt = lat0; lt <= lat1; lt += step) {
        // Apply land-mass mask
        if (insideLandmass(ln, lt)) out.push([ln, lt]);
      }
    }
    return out;
  }
  // Very rough land mask (intentionally lo-fi — reads as continents)
  function insideLandmass(lng, lat) {
    // North America
    if (lng >= -135 && lng <= -55 && lat >= 25 && lat <= 70 && !(lng > -75 && lat > 50)) return true;
    // Central / Greenland sliver
    if (lng >= -55 && lng <= -20 && lat >= 60 && lat <= 80) return true;
    // South America
    if (lng >= -82 && lng <= -35 && lat >= -55 && lat <= 12 && !(lng > -45 && lat > 0 && lat < 8)) return true;
    // Europe
    if (lng >= -10 && lng <= 40 && lat >= 36 && lat <= 70) return true;
    // Africa
    if (lng >= -18 && lng <= 52 && lat >= -35 && lat <= 36 && !(lng < 10 && lat < -8)) return true;
    // Middle east bridge
    if (lng >= 30 && lng <= 60 && lat >= 12 && lat <= 40) return true;
    // Asia
    if (lng >= 40 && lng <= 145 && lat >= 8 && lat <= 75 && !(lng > 130 && lat < 25)) return true;
    // SE Asia / Indonesia
    if (lng >= 95 && lng <= 140 && lat >= -10 && lat <= 8) return true;
    // Australia
    if (lng >= 112 && lng <= 155 && lat >= -44 && lat <= -12) return true;
    return false;
  }

  return (
    <div className="map-wrap">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height="auto" className="map">
        {/* Latitude lines */}
        {[-60,-30,0,30,60].map(l => {
          const [, py] = proj(l, 0);
          return <line key={l} x1="0" x2={W} y1={py} y2={py} stroke="var(--ln)" strokeDasharray="1 6" opacity=".5" />;
        })}
        {/* Continent dots */}
        {continents.map(([x,y], i) => (
          <circle key={i} cx={x} cy={y} r="1.4" fill="var(--map-land)" />
        ))}
        {/* Attack arcs */}
        {origins.map((o, i) => {
          const [ox, oy] = proj(o.lat, o.lng);
          const mx = (ox + tx) / 2;
          const my = Math.min(oy, ty) - Math.abs(ox - tx) * 0.18 - 10;
          const r = 4 + (o.count / maxCount) * 9;
          const sev = o.count > 30 ? 'critical' : o.count > 15 ? 'high' : o.count > 7 ? 'medium' : 'low';
          const stroke = sev === 'critical' ? 'var(--crit)' : sev === 'high' ? 'var(--high)' : sev === 'medium' ? 'var(--med)' : 'var(--low)';
          return (
            <g key={i}>
              <path d={`M${ox} ${oy} Q${mx} ${my} ${tx} ${ty}`} fill="none" stroke={stroke} strokeWidth="0.8" opacity=".55" />
              <circle cx={ox} cy={oy} r={r} fill={stroke} opacity=".18" />
              <circle cx={ox} cy={oy} r={Math.max(2, r * 0.4)} fill={stroke}>
                <animate attributeName="opacity" values="1;.3;1" dur={`${1.6 + i * 0.1}s`} repeatCount="indefinite"/>
              </circle>
              <text x={ox + r + 4} y={oy + 3} className="map-label">{o.country} · {o.count}</text>
            </g>
          );
        })}
        {/* Target */}
        <g>
          <circle cx={tx} cy={ty} r="6" fill="none" stroke="var(--acc)" strokeWidth="1.2">
            <animate attributeName="r" values="6;14;6" dur="2.4s" repeatCount="indefinite"/>
            <animate attributeName="opacity" values="1;0;1" dur="2.4s" repeatCount="indefinite"/>
          </circle>
          <circle cx={tx} cy={ty} r="3.5" fill="var(--acc)" />
          <text x={tx + 8} y={ty - 6} className="map-label-target">HQ</text>
        </g>
      </svg>
    </div>
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
  const s = Math.round((Date.now() - t.getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m/60)}h ago`;
}

// ====== Top rules table ======
function TopRulesTable({ rules }) {
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
                <div className="bar" data-sev={r.sev} style={{ width: `${r.count/max*100}%` }} />
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
      {agents.map(a => (
        <li key={a.id} className="agent-row">
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
  const D = window.SOC_DATA;
  const [sevFilter, setSevFilter] = useState1('all');
  const [selected, setSelected] = useState1(D.RECENT_ALERTS[0]);
  const allAlerts = useMemo1(() => {
    // Pad to ~30 by recycling
    const out = [];
    while (out.length < 28) {
      D.RECENT_ALERTS.forEach((a, i) => {
        if (out.length < 28) out.push({ ...a, id: a.id.slice(0, -2) + String((parseInt(a.id.slice(-2))-out.length)).padStart(2,'0') });
      });
    }
    return out;
  }, []);

  const filtered = sevFilter === 'all' ? allAlerts : allAlerts.filter(a => a.sev === sevFilter);

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
                  {s === 'all' ? allAlerts.length : allAlerts.filter(a => a.sev === s).length}
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
                {filtered.map((a, idx) => (
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
                ))}
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
  return (
    <div className="detail">
      <div className="detail-head">
        <SevChip sev={alert.sev} />
        <span className="mono dim">{alert.id}</span>
        <button className="btn-icon detail-close"><Icon.x width="14" height="14"/></button>
      </div>
      <h2 className="detail-title">{alert.rule}</h2>
      <div className="detail-time mono">{alert.time.toISOString().slice(0,19).replace('T',' ')} UTC</div>

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

Object.assign(window, { PageDashboard, PageAlerts });
