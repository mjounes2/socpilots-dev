// Dashboard + Alerts — production-parity layout
const { useState: useState1, useMemo: useMemo1, useEffect: useEffect1, useCallback: useCallback1, useRef: useRef1 } = React;

// ─── World map continent outlines (same as production) ────────
const DASH_CONTINENTS = [
  // North America
  [[-168,72],[-140,70],[-125,68],[-110,68],[-95,68],[-85,65],[-78,62],[-70,60],[-65,58],[-62,54],[-60,50],[-65,44],[-68,42],[-70,38],[-76,36],[-80,32],[-82,28],[-84,24],[-90,20],[-86,16],[-83,12],[-78,8],[-76,10],[-80,14],[-86,20],[-90,16],[-92,18],[-96,20],[-98,22],[-100,26],[-104,30],[-108,34],[-114,30],[-118,26],[-118,30],[-122,36],[-124,40],[-128,44],[-132,52],[-140,58],[-148,60],[-152,58],[-160,62],[-164,66],[-168,70]],
  // Greenland
  [[-44,84],[-20,84],[-16,80],[-20,76],[-30,76],[-40,78],[-48,82],[-44,84]],
  // South America
  [[-78,12],[-72,12],[-68,10],[-62,8],[-52,4],[-50,0],[-48,-4],[-46,-8],[-40,-14],[-38,-18],[-38,-22],[-42,-22],[-44,-26],[-50,-30],[-52,-34],[-58,-38],[-62,-42],[-66,-46],[-68,-50],[-72,-52],[-68,-56],[-64,-52],[-60,-52],[-56,-46],[-52,-42],[-50,-38],[-48,-30],[-48,-26],[-44,-22],[-42,-18],[-40,-14],[-42,-10],[-48,-8],[-52,-4],[-54,0],[-56,4],[-62,6],[-64,2],[-70,-2],[-74,-4],[-78,0],[-80,4],[-78,8],[-76,10],[-78,12]],
  // Europe
  [[-10,36],[-8,38],[-8,42],[-4,44],[0,44],[4,44],[8,44],[12,46],[16,48],[20,48],[24,48],[26,46],[28,44],[30,42],[28,40],[26,38],[22,38],[18,38],[14,38],[10,38],[6,40],[2,42],[0,44],[-4,48],[-6,48],[-8,52],[-6,54],[-2,54],[2,54],[6,56],[8,58],[12,60],[18,62],[24,64],[28,66],[26,68],[22,70],[16,70],[12,68],[8,66],[4,62],[2,58],[0,56],[-4,54],[-6,54],[-8,52],[-10,48],[-8,44],[-8,38],[-10,36]],
  // Scandinavia
  [[5,58],[8,56],[12,56],[16,58],[20,60],[24,62],[26,66],[22,68],[18,70],[14,72],[10,70],[8,66],[6,62],[5,58]],
  // Africa
  [[-18,16],[-16,20],[-18,24],[-14,26],[-10,28],[-6,30],[-2,30],[4,32],[8,32],[12,30],[16,28],[20,26],[24,22],[28,18],[32,14],[36,10],[40,8],[42,12],[44,10],[42,8],[38,4],[36,0],[34,-4],[32,-8],[30,-14],[28,-18],[28,-24],[26,-30],[24,-34],[26,-38],[28,-40],[30,-40],[32,-38],[34,-34],[36,-28],[34,-22],[34,-16],[36,-10],[38,-4],[40,0],[40,4],[36,8],[34,12],[30,14],[26,16],[22,16],[18,16],[14,14],[10,12],[6,10],[4,6],[0,4],[-4,4],[-8,4],[-12,8],[-14,10],[-16,12],[-18,16]],
  // Asia (mainland)
  [[26,42],[30,44],[36,46],[42,50],[48,54],[54,58],[60,62],[66,66],[72,68],[80,68],[88,68],[96,66],[100,62],[104,58],[110,56],[116,54],[122,52],[128,50],[132,48],[136,44],[138,40],[136,36],[132,34],[130,30],[126,26],[122,22],[118,18],[114,14],[110,10],[106,4],[104,0],[100,-4],[96,-6],[92,-2],[90,4],[88,8],[86,14],[84,18],[82,22],[78,26],[74,28],[70,22],[66,16],[62,12],[60,14],[56,18],[52,22],[50,26],[46,28],[44,26],[40,26],[38,30],[34,32],[32,36],[28,38],[26,40]],
  // Indian Subcontinent
  [[62,22],[66,18],[70,14],[72,8],[76,6],[80,8],[82,12],[84,16],[82,20],[78,24],[74,28],[70,22],[66,18],[62,22]],
  // Southeast Asia
  [[100,0],[102,-4],[104,-6],[106,-8],[108,-6],[112,-2],[116,2],[120,4],[122,8],[118,12],[114,16],[110,20],[106,16],[104,10],[100,4],[100,0]],
  // Japan
  [[130,34],[132,36],[136,40],[140,42],[140,38],[138,34],[134,32],[130,32],[130,34]],
  // Australia
  [[114,-22],[118,-20],[122,-18],[128,-16],[132,-12],[136,-12],[140,-14],[144,-16],[148,-20],[152,-24],[152,-28],[150,-32],[148,-36],[144,-38],[140,-38],[134,-36],[128,-32],[122,-28],[116,-26],[114,-22]],
  // New Zealand
  [[168,-46],[170,-44],[172,-42],[174,-40],[172,-38],[170,-36],[168,-36],[166,-44],[168,-46]],
];

// Simple first-octet geo heuristic (same logic as production GEO_HEURISTIC)
const _geoCache = {};
function dashGeoH(ip) {
  if (_geoCache[ip]) return _geoCache[ip];
  const f = parseInt((ip || '0').split('.')[0]);
  let g;
  if      (f <= 50)  g = { lat: 51 + (f % 7) * 2.5,     lon: 8  + (f % 11) * 3   };
  else if (f <= 80)  g = { lat: 40 + (f % 9) * 1.5,     lon: -75 + (f % 13) * 4  };
  else if (f <= 120) g = { lat: 32 + (f % 11) * 2,      lon: 75  + (f % 9) * 5   };
  else if (f <= 160) g = { lat: 22 + (f % 7) * 3,       lon: 25  + (f % 11) * 5  };
  else if (f <= 200) g = { lat: 36 + (f % 5) * 2,       lon: 105 + (f % 7) * 5   };
  else               g = { lat: (f * 79 % 140) - 70,    lon: (f * 137 % 360) - 180 };
  return (_geoCache[ip] = g);
}

// ─── Canvas world map ─────────────────────────────────────────
function DashWorldMap({ ips }) {
  const cvRef   = useRef1(null);
  const wrapRef = useRef1(null);

  useEffect1(() => {
    const cv   = cvRef.current;
    const wrap = wrapRef.current;
    if (!cv || !wrap) return;
    const W = wrap.clientWidth || 400;
    const H = 160;
    cv.width  = W;
    cv.height = H;
    const ctx = cv.getContext('2d');

    ctx.fillStyle = '#060d1a';
    ctx.fillRect(0, 0, W, H);

    // Grid lines
    ctx.strokeStyle = 'rgba(0,229,255,.04)';
    ctx.lineWidth = 0.4;
    for (let lon = -180; lon <= 180; lon += 30) {
      const x = ((lon + 180) / 360) * W;
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
    }
    for (let lat = -90; lat <= 90; lat += 30) {
      const y = ((90 - lat) / 180) * H;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }
    // Equator
    ctx.strokeStyle = 'rgba(0,229,255,.08)';
    ctx.lineWidth = 0.8;
    const eq = (90 / 180) * H;
    ctx.beginPath(); ctx.moveTo(0, eq); ctx.lineTo(W, eq); ctx.stroke();

    const ll2xy = (lat, lon) => ({
      x: ((lon + 180) / 360) * W,
      y: ((90 - lat)  / 180) * H,
    });

    // Continents
    DASH_CONTINENTS.forEach(pts => {
      ctx.beginPath();
      pts.forEach(([lon, lat], i) => {
        const { x, y } = ll2xy(lat, lon);
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      });
      ctx.closePath();
      ctx.fillStyle   = 'rgba(14,36,72,.92)';
      ctx.fill();
      ctx.strokeStyle = 'rgba(0,229,255,.22)';
      ctx.lineWidth   = 0.8;
      ctx.stroke();
    });

    // Attack dots
    (ips || []).slice(0, 25).forEach(({ ip, count }) => {
      const g = dashGeoH(ip);
      const { x, y } = ll2xy(g.lat, g.lon);
      if (x < 4 || x > W - 4 || y < 4 || y > H - 4) return;
      const size = Math.min(5 + Math.log2((count || 1) + 1) * 1.5, 16);
      const clr  = count > 20 ? '#ff1744' : count > 10 ? '#ff6d00' : '#ffab00';
      ctx.beginPath();
      ctx.arc(x, y, size / 2, 0, Math.PI * 2);
      ctx.fillStyle  = clr;
      ctx.shadowBlur = size + 4;
      ctx.shadowColor = clr;
      ctx.fill();
      ctx.shadowBlur = 0;
    });
  }, [ips]);

  return (
    <div ref={wrapRef} style={{ position: 'relative', background: '#060d1a', borderRadius: 4, overflow: 'hidden' }}>
      <canvas ref={cvRef} height="160" style={{ display: 'block', width: '100%' }} />
    </div>
  );
}

// ─── Severity breakdown bars ──────────────────────────────────
function SevBars({ breakdown, total }) {
  const items = [
    { l: 'Critical', v: breakdown?.critical || 0, c: 'var(--crit)' },
    { l: 'High',     v: breakdown?.high     || 0, c: 'var(--high)' },
    { l: 'Medium',   v: breakdown?.medium   || 0, c: 'var(--med)'  },
    { l: 'Low',      v: breakdown?.low      || 0, c: 'var(--low)'  },
  ];
  const t = total || items.reduce((a, b) => a + b.v, 0) || 1;
  return (
    <div>
      {items.map(item => {
        const pct = Math.round((item.v / t) * 100);
        return (
          <div key={item.l} style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 11, fontFamily: 'var(--mono)' }}>
              <span style={{ color: item.c }}>{item.l}</span>
              <span style={{ color: 'var(--fg-2)' }}>
                {item.v.toLocaleString()}
                <span style={{ color: 'var(--fg-3)', marginLeft: 4 }}>({pct}%)</span>
              </span>
            </div>
            <div style={{ height: 6, borderRadius: 3, background: 'var(--bg-3)', overflow: 'hidden' }}>
              <div style={{ width: pct + '%', height: '100%', background: item.c, borderRadius: 3, transition: 'width .5s' }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── MITRE widget ─────────────────────────────────────────────
function DashMitre({ data }) {
  if (!data?.tactics?.length) return <EmptyState icon="🎯" text="No MITRE data" />;
  return (
    <div>
      <div style={{ fontSize: 9, color: 'var(--fg-3)', fontFamily: 'var(--mono)', marginBottom: 6, letterSpacing: 1 }}>TACTICS</div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 10 }}>
        {data.tactics.slice(0, 8).map(t => (
          <span key={t.name} style={{ padding: '2px 6px', background: 'rgba(255,171,0,.1)', border: '1px solid rgba(255,171,0,.2)', borderRadius: 3, fontSize: 8, fontFamily: 'var(--mono)', color: 'var(--med)' }}>
            {t.name} <span style={{ color: 'var(--fg-3)' }}>{t.count}</span>
          </span>
        ))}
      </div>
      <div style={{ fontSize: 9, color: 'var(--fg-3)', fontFamily: 'var(--mono)', marginBottom: 6, letterSpacing: 1 }}>TECHNIQUES</div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
        {(data.techniques || []).slice(0, 12).map(t => (
          <span key={t.id} style={{ padding: '2px 6px', background: 'var(--acc-bg)', border: '1px solid rgba(0,229,255,.2)', borderRadius: 3, fontSize: 8, fontFamily: 'var(--mono)', color: 'var(--acc)' }}>
            {t.id} <span style={{ color: 'var(--fg-3)' }}>{t.count}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

// ─── Empty state ──────────────────────────────────────────────
function EmptyState({ icon, text }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '1.5rem', color: 'var(--fg-3)', gap: 8 }}>
      <span style={{ fontSize: 26 }}>{icon}</span>
      <span style={{ fontSize: 12 }}>{text}</span>
    </div>
  );
}

// ─── KPI card ─────────────────────────────────────────────────
function KpiCard({ label, value, sub, spark, sev }) {
  return (
    <div className="kpi" data-sev={sev}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-foot">
        {sub && <span className="kpi-sub">{sub}</span>}
      </div>
      {spark && spark.length > 0 && (
        <div className="kpi-spark">
          <DashSpark data={spark} height={28} color="var(--acc)" />
        </div>
      )}
    </div>
  );
}

// ─── Mini sparkline for KPI card (local — does not shadow global Sparkline) ──
function DashSpark({ data, height = 28, color = 'var(--acc)' }) {
  if (!data || data.length < 2) return null;
  const max = Math.max(...data, 1);
  const w = 100, h = height;
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - (v / max) * h * 0.9}`).join(' ');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" opacity="0.7" />
    </svg>
  );
}

// ─── Stacked area timeline (SVG) ─────────────────────────────
function AlertTimeline({ data }) {
  if (!data || data.length < 2) return <EmptyState icon="📊" text="Insufficient timeline data" />;
  const w = 800, h = 180, pad = { l: 36, r: 12, t: 12, b: 26 };
  const innerW = w - pad.l - pad.r;
  const innerH = h - pad.t - pad.b;
  const layers = ['low', 'medium', 'high', 'critical'];
  const layerColor = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)' };

  const stack = data.map(d => {
    let acc = 0;
    return layers.map(L => { const v0 = acc; acc += (d[L] || 0); return [v0, acc]; });
  });
  const maxY = Math.max(...stack.flatMap(s => s.map(p => p[1])), 1);
  const x = i => pad.l + (i / Math.max(data.length - 1, 1)) * innerW;
  const y = v => pad.t + innerH - (v / maxY) * innerH;

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
          <text x={pad.l - 8} y={y(t) + 3} textAnchor="end" className="chart-tick">
            {t >= 1000 ? `${(t / 1000).toFixed(0)}k` : t}
          </text>
        </g>
      ))}
      {data.map((d, i) => i % Math.max(1, Math.floor(data.length / 6)) === 0 && (
        <text key={i} x={x(i)} y={h - 8} textAnchor="middle" className="chart-tick">
          {String(d.hour).padStart(2, '0')}:00
        </text>
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

// ─── Severity donut (SVG) ─────────────────────────────────────
function SeverityDonut({ data }) {
  const total = data.reduce((a, b) => a + b.count, 0);
  if (total === 0) return <EmptyState icon="🔵" text="No alerts" />;
  const r = 60, c = 2 * Math.PI * r;
  let offset = 0;
  const colorMap  = { crit: 'var(--crit)', high: 'var(--high)', med: 'var(--med)', low: 'var(--low)' };
  const labelMap  = { crit: 'critical',    high: 'high',        med: 'medium',     low: 'low'        };
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 180 180" width="180" height="180">
        <circle cx="90" cy="90" r={r} fill="none" stroke="var(--ln)" strokeWidth="1" />
        {data.map((d, i) => {
          const frac = d.count / total;
          const len  = c * frac;
          const el = (
            <circle key={i} cx="90" cy="90" r={r} fill="none"
              stroke={colorMap[d.color]} strokeWidth="20"
              strokeDasharray={`${len} ${c - len}`}
              strokeDashoffset={-offset}
              transform="rotate(-90 90 90)" />
          );
          offset += len;
          return el;
        })}
        <text x="90" y="86"  textAnchor="middle" className="donut-num">{total.toLocaleString()}</text>
        <text x="90" y="104" textAnchor="middle" className="donut-lbl">alerts</text>
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

// ─── PageDashboard ────────────────────────────────────────────
function PageDashboard() {
  const API = window.SOC_API;

  const [dash,          setDash]          = useState1(null);
  const [topRules,      setTopRules]      = useState1([]);
  const [topAgents,     setTopAgents]     = useState1([]);
  const [topIPs,        setTopIPs]        = useState1([]);
  const [recentAlerts,  setRecentAlerts]  = useState1([]);
  const [closedCases,   setClosedCases]   = useState1(0);
  const [agentCounts,   setAgentCounts]   = useState1({ total: 0, active: 0, disc: 0, ids: [] });
  const [mitreData,     setMitreData]     = useState1(null);
  const [loading,       setLoading]       = useState1(true);

  const [hours,         setHours]         = useState1(24);
  const [showCustom,    setShowCustom]    = useState1(false);
  const [customFrom,    setCustomFrom]    = useState1('');
  const [customTo,      setCustomTo]      = useState1('');
  const [liveLabel,     setLiveLabel]     = useState1('Last 24h');

  const load = useCallback1(async (h, from, to) => {
    setLoading(true);
    const params = new URLSearchParams();
    if (from && to) {
      params.set('from', new Date(from).toISOString());
      params.set('to',   new Date(to + 'T23:59:59').toISOString());
    } else {
      params.set('hours', h);
    }

    const [dashData, rulesData, agentsData, ipsData, alertsData, mitreD] = await Promise.all([
      API.get(`/api/dashboard?${params}`),
      API.get('/api/stats/top-rules'),
      API.get('/api/agents'),
      API.get('/api/stats/top-ips'),
      API.get(`/api/alerts?severity=critical&hours=${h}&page=1&page_size=8`),
      API.get('/api/stats/mitre'),
    ]);

    setDash(dashData);
    setLiveLabel(dashData?.periodLabel || `Last ${h}h`);
    setTopRules(Array.isArray(rulesData) ? rulesData : []);
    setTopIPs(Array.isArray(ipsData)   ? ipsData   : []);
    setMitreData(mitreD);

    const agents = agentsData?.agents || [];
    const active = agents.filter(a => a.status === 'active').length;
    const disc   = agents.filter(a => a.status !== 'active').length;
    setAgentCounts({ total: agents.length, active, disc, ids: agents.slice(0, 3).map(a => a.id) });
    setTopAgents(agents.slice(0, 7));

    const rawAlerts = alertsData?.items || alertsData?.alerts || [];
    setRecentAlerts(rawAlerts.map(adaptAlert));

    // Closed cases — non-blocking
    Promise.all([
      API.get('/api/cases?status=TruePositive'),
      API.get('/api/cases?status=FalsePositive'),
      API.get('/api/cases?status=Duplicate'),
    ]).then(([tp, fp, dup]) => {
      setClosedCases((tp?.cases?.length || 0) + (fp?.cases?.length || 0) + (dup?.cases?.length || 0));
    }).catch(() => {});

    setLoading(false);
  }, []);

  useEffect1(() => { load(hours, '', ''); }, [hours]);

  const applyCustom = () => {
    if (customFrom && customTo) {
      setLiveLabel(`${customFrom} → ${customTo}`);
      load(hours, customFrom, customTo);
    }
  };

  const setRange = h => { setShowCustom(false); setHours(h); };

  const timeline = (dash?.timeline || []).map(t => ({
    hour:     new Date(t.time).getUTCHours(),
    critical: t.critical || 0,
    high:     t.high     || 0,
    medium:   t.medium   || 0,
    low:      t.low      || 0,
  }));

  const sevDist = [
    { level: 'crit', color: 'crit', count: dash?.criticalAlerts || 0 },
    { level: 'high', color: 'high', count: dash?.highAlerts     || 0 },
    { level: 'med',  color: 'med',  count: dash?.mediumAlerts   || 0 },
    { level: 'low',  color: 'low',  count: dash?.lowAlerts      || 0 },
  ].filter(d => d.count > 0);

  const spark = timeline.map(t => t.critical + t.high + t.medium + t.low);

  const PRESETS = [
    { h: 1,    label: '1h'  },
    { h: 6,    label: '6h'  },
    { h: 24,   label: '24h' },
    { h: 168,  label: '7d'  },
    { h: 720,  label: '30d' },
    { h: 2160, label: '90d' },
  ];

  // Shared card styles
  const card = { background: 'var(--bg-1)', border: '1px solid var(--ln)', borderRadius: 6, padding: '12px 14px' };
  const hd   = { display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10,
                 fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--fg-3)', letterSpacing: 1, textTransform: 'uppercase' };

  const nav = id => window.socNav?.(id);

  if (loading) return (
    <div className="page" data-screen-label="01 Dashboard">
      <Topbar title="SOC COMMAND CENTER" sub="Connecting to SIEM + SP-CM…" />
      <div className="page-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300 }}>
        <Spinner />
      </div>
    </div>
  );

  return (
    <div className="page" data-screen-label="01 Dashboard">
      <Topbar
        title="SOC COMMAND CENTER"
        sub={`${liveLabel} · SIEM + SP-CM · ${new Date().toLocaleTimeString('en', { hour12: false })} UTC`}
        actions={<>
          <span className="live-pip"><span className="pip" />LIVE</span>
          <button className="btn btn-ghost" onClick={() => load(hours, showCustom ? customFrom : '', showCustom ? customTo : '')}>
            <Icon.refresh width="13" height="13" /> Refresh
          </button>
        </>}
      />

      <div className="page-body">

        {/* ── Time range filter bar ── */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, padding: '8px 12px',
                      background: 'var(--bg-1)', border: '1px solid var(--ln)', borderRadius: 4, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--fg-3)', letterSpacing: 1, whiteSpace: 'nowrap' }}>
            TIME RANGE
          </span>
          <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
            {PRESETS.map(p => (
              <button key={p.h}
                className={`btn ${hours === p.h && !showCustom ? 'btn-primary' : 'btn-ghost'}`}
                style={{ padding: '3px 9px', fontSize: 11 }}
                onClick={() => setRange(p.h)}>
                {p.label}
              </button>
            ))}
            <button
              className={`btn ${showCustom ? 'btn-primary' : 'btn-ghost'}`}
              style={{ padding: '3px 9px', fontSize: 11 }}
              onClick={() => setShowCustom(s => !s)}>
              Custom ▾
            </button>
          </div>
          {showCustom && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <input type="datetime-local" value={customFrom} onChange={e => setCustomFrom(e.target.value)}
                style={{ width: 155, padding: '4px 8px', fontSize: 11, background: 'var(--bg-2)',
                         border: '1px solid var(--ln)', borderRadius: 3, color: 'var(--fg-0)' }} />
              <span style={{ color: 'var(--fg-3)', fontSize: 11 }}>→</span>
              <input type="datetime-local" value={customTo} onChange={e => setCustomTo(e.target.value)}
                style={{ width: 155, padding: '4px 8px', fontSize: 11, background: 'var(--bg-2)',
                         border: '1px solid var(--ln)', borderRadius: 3, color: 'var(--fg-0)' }} />
              <button className="btn btn-primary" style={{ padding: '3px 10px', fontSize: 11 }} onClick={applyCustom}>
                Apply
              </button>
            </div>
          )}
          <span style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--acc)', marginLeft: 4 }}>{liveLabel}</span>
        </div>

        {/* ── Row 1: Alert KPI cards ── */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 10, marginBottom: 10 }}>
          <KpiCard label="Total Alerts"  value={(dash?.totalAlerts    || 0).toLocaleString()} sub={liveLabel} spark={spark} />
          <KpiCard label="Critical"      value={(dash?.criticalAlerts || 0).toLocaleString()} sub="level ≥ 12" sev="critical" />
          <KpiCard label="High"          value={(dash?.highAlerts     || 0).toLocaleString()} sub="level 8–11" />
          <KpiCard label="Medium"        value={(dash?.mediumAlerts   || 0).toLocaleString()} sub="level 5–7" />
          <KpiCard label="Open Cases"    value={(dash?.openCases      || 0).toLocaleString()} sub="SP-CM" />
          <KpiCard label="Closed Cases"  value={closedCases.toLocaleString()}                  sub="SP-CM resolved" />
        </div>

        {/* ── Row 2: Agent status cards ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 12 }}>
          {/* Total Agents */}
          <div style={{ ...card, cursor: 'pointer' }} onClick={() => nav('agents')}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 40, height: 40, borderRadius: '50%',
                            background: 'rgba(0,229,255,.1)', border: '1px solid rgba(0,229,255,.3)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" strokeWidth="2">
                  <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
                </svg>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--fg-3)', letterSpacing: 1 }}>TOTAL AGENTS</div>
                <div style={{ fontSize: 28, fontWeight: 500, lineHeight: 1.1, marginTop: 2 }}>{agentCounts.total || '—'}</div>
                <div style={{ fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--fg-3)', marginTop: 2 }}>monitored endpoints</div>
              </div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 9, textAlign: 'right', color: 'var(--acc)' }}>
                {agentCounts.ids.join(' · ')}{agentCounts.total > 3 ? ` +${agentCounts.total - 3}` : ''}
              </div>
            </div>
          </div>
          {/* Active Agents */}
          <div style={{ ...card, cursor: 'pointer', borderColor: 'rgba(0,230,118,.25)' }} onClick={() => nav('agents')}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 40, height: 40, borderRadius: '50%',
                            background: 'rgba(0,230,118,.1)', border: '1px solid rgba(0,230,118,.3)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, position: 'relative' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#00e676" strokeWidth="2">
                  <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
                </svg>
                <div style={{ position: 'absolute', top: 0, right: 0, width: 10, height: 10,
                              background: 'var(--low)', borderRadius: '50%', border: '2px solid var(--bg-0)',
                              boxShadow: '0 0 6px var(--low)' }} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--fg-3)', letterSpacing: 1 }}>ACTIVE AGENTS</div>
                <div style={{ fontSize: 28, fontWeight: 500, lineHeight: 1.1, marginTop: 2, color: 'var(--low)' }}>{agentCounts.active || '—'}</div>
                <div style={{ fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--fg-3)', marginTop: 2 }}>online — last 24h</div>
              </div>
              <div style={{ padding: '4px 8px', background: 'rgba(0,230,118,.1)', border: '1px solid rgba(0,230,118,.25)',
                            borderRadius: 3, fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--low)' }}>ONLINE</div>
            </div>
          </div>
          {/* Disconnected */}
          <div style={{ ...card, cursor: 'pointer', borderColor: agentCounts.disc === 0 ? 'rgba(0,230,118,.25)' : 'rgba(255,23,68,.25)' }}
               onClick={() => nav('agents')}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 40, height: 40, borderRadius: '50%',
                            background: 'rgba(255,23,68,.1)', border: '1px solid rgba(255,23,68,.3)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ff1744" strokeWidth="2">
                  <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
                  <line x1="18" y1="6" x2="18" y2="6.01" strokeWidth="3"/>
                </svg>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--fg-3)', letterSpacing: 1 }}>DISCONNECTED</div>
                <div style={{ fontSize: 28, fontWeight: 500, lineHeight: 1.1, marginTop: 2, color: 'var(--crit)' }}>{agentCounts.disc || '—'}</div>
                <div style={{ fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--fg-3)', marginTop: 2 }}>inactive / offline</div>
              </div>
              {agentCounts.disc === 0
                ? <div style={{ padding: '4px 8px', background: 'rgba(0,230,118,.1)', border: '1px solid rgba(0,230,118,.25)',
                                borderRadius: 3, fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--low)' }}>ALL ONLINE</div>
                : <div style={{ padding: '4px 8px', background: 'rgba(255,23,68,.1)', border: '1px solid rgba(255,23,68,.25)',
                                borderRadius: 3, fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--crit)' }}>OFFLINE</div>
              }
            </div>
          </div>
        </div>

        {/* ── Row 3: Timeline | Severity donut | World map ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1.3fr .7fr 1fr', gap: 12, marginBottom: 12 }}>
          {/* Timeline */}
          <div style={card}>
            <div style={hd}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="13" height="13">
                  <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                </svg>
                ALERT TIMELINE — {liveLabel.toUpperCase()}
              </span>
              <span className="live-pip"><span className="pip" />LIVE</span>
            </div>
            {timeline.length > 0
              ? <AlertTimeline data={timeline} />
              : <EmptyState icon="📊" text="No timeline data" />}
          </div>
          {/* Severity donut */}
          <div style={card}>
            <div style={hd}>SEVERITY</div>
            {sevDist.length > 0
              ? <SeverityDonut data={sevDist} />
              : <EmptyState icon="🔵" text="No alert data" />}
          </div>
          {/* World map */}
          <div style={{ ...card, padding: 12 }}>
            <div style={{ ...hd, marginBottom: 6 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="13" height="13">
                  <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
                  <path d="M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/>
                </svg>
                ATTACK ORIGINS
              </span>
              <span style={{ fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--crit)' }}>{topIPs.length} IPs</span>
            </div>
            <DashWorldMap ips={topIPs} />
          </div>
        </div>

        {/* ── Row 4: Top Agents | Top IPs | Top Rules | MITRE ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1.1fr', gap: 12, marginBottom: 12 }}>
          {/* Top Agents */}
          <div style={card}>
            <div style={hd}>TOP AGENTS</div>
            {topAgents.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                {topAgents.slice(0, 7).map((a, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 9, color: 'var(--fg-3)', fontFamily: 'var(--mono)', minWidth: 14 }}>{i + 1}</span>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--low)', flexShrink: 0 }} />
                    <span style={{ flex: 1, fontSize: 12, fontFamily: 'var(--mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.name}
                    </span>
                    <span style={{ fontSize: 10, color: 'var(--acc)', fontFamily: 'var(--mono)' }}>
                      {(a.alertCount || a.count || 0).toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            ) : <EmptyState icon="🖥" text="No agent data" />}
          </div>

          {/* Top Attack IPs */}
          <div style={card}>
            <div style={hd}>TOP ATTACK IPs</div>
            {topIPs.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                {topIPs.slice(0, 7).map((d, i) => {
                  const sev = d.count > 1000 ? 'critical' : d.count > 200 ? 'high' : 'medium';
                  return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: 9, color: 'var(--fg-3)', fontFamily: 'var(--mono)', minWidth: 14 }}>{i + 1}</span>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--crit)', flexShrink: 0 }} />
                      <span style={{ flex: 1, fontSize: 12, fontFamily: 'var(--mono)' }}>{d.ip}</span>
                      <SevChip sev={sev} />
                    </div>
                  );
                })}
              </div>
            ) : <EmptyState icon="🌐" text="No IP data" />}
          </div>

          {/* Top Rules */}
          <div style={card}>
            <div style={hd}>TOP RULES</div>
            {topRules.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                {topRules.slice(0, 7).map((r, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <span style={{ fontSize: 9, color: 'var(--fg-3)', fontFamily: 'var(--mono)', minWidth: 14 }}>{i + 1}</span>
                    <SevChip sev={r.severity} />
                    <span style={{ flex: 1, fontSize: 10, fontFamily: 'var(--mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.desc || r.description}
                    </span>
                    <span style={{ fontSize: 9, color: 'var(--fg-2)', fontFamily: 'var(--mono)' }}>{r.count}</span>
                  </div>
                ))}
              </div>
            ) : <EmptyState icon="📋" text="No rule data" />}
          </div>

          {/* MITRE ATT&CK */}
          <div style={card}>
            <div style={hd}>MITRE ATT&amp;CK</div>
            <DashMitre data={mitreData} />
          </div>
        </div>

        {/* ── Row 5: Recent Critical + Severity Bars ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 12 }}>
          {/* Recent Critical Alerts */}
          <div style={card}>
            <div style={{ ...hd, marginBottom: 8 }}>
              <span>RECENT CRITICAL ALERTS</span>
              <button className="btn btn-ghost" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => nav('alerts')}>
                View All →
              </button>
            </div>
            {recentAlerts.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {recentAlerts.slice(0, 8).map((a, i) => (
                  <div key={i} style={{ padding: '7px 9px', background: 'var(--bg-0)',
                                       border: '1px solid var(--ln)', borderLeft: '2px solid var(--crit)', borderRadius: 3 }}>
                    <div style={{ fontSize: 12, fontFamily: 'var(--mono)', marginBottom: 3, lineHeight: 1.3 }}>{a.rule}</div>
                    <div style={{ display: 'flex', gap: 8, fontSize: 9, color: 'var(--fg-3)', fontFamily: 'var(--mono)', flexWrap: 'wrap' }}>
                      <span style={{ color: 'var(--acc)' }}>{a.agent}</span>
                      {a.srcIp && a.srcIp !== '—' && <span>{a.srcIp}</span>}
                      {a.mitre && a.mitre !== '—' && (
                        <span style={{ padding: '1px 4px', background: 'var(--acc-bg)', border: '1px solid rgba(0,229,255,.2)',
                                       borderRadius: 2, fontSize: 7, color: 'var(--acc)' }}>{a.mitre}</span>
                      )}
                      <span style={{ marginLeft: 'auto' }}>{relTime(a.time)}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : <EmptyState icon="🔔" text="No critical alerts in last 24h" />}
          </div>

          {/* Severity Breakdown */}
          <div style={card}>
            <div style={hd}>SEVERITY BREAKDOWN</div>
            <SevBars breakdown={dash?.sevBreakdown} total={dash?.totalAlerts} />
          </div>
        </div>

      </div>
    </div>
  );
}

// ─── Alert data adapter ───────────────────────────────────────
function adaptAlert(a) {
  const sev   = a.severity || window.SOC_API.sevFromLevel(a.level);
  const mitre = Array.isArray(a.mitre) ? (a.mitre[0] || '—') : (a.mitre || '—');
  return {
    id:      a.id || a._id,
    sev,
    rule:    a.description || a.rule || '—',
    mitre,
    agent:   a.agent || '—',
    srcIp:   a.srcIp || a.src_ip || '—',
    geo:     a.location || a.geo || '—',
    ruleId:  a.ruleId || a.rule_id,
    level:   a.level,
    fullLog: a.fullLog || a.full_log,
    groups:  a.groups,
    time:    new Date(a.timestamp || a.time || Date.now()),
    raw:     a,
  };
}

function relTime(t) {
  if (!t) return '—';
  const d = t instanceof Date ? t : new Date(t);
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 60)  return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60)  return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

// ─── PageAlerts ───────────────────────────────────────────────
function PageAlerts() {
  const API = window.SOC_API;
  const [alerts,     setAlerts]     = useState1([]);
  const [total,      setTotal]      = useState1(0);
  const [page,       setPage]       = useState1(1);
  const [pageSize]                  = useState1(50);
  const [sevFilter,  setSevFilter]  = useState1('all');
  const [selected,   setSelected]   = useState1(null);
  const [loading,    setLoading]    = useState1(true);
  const [enriching,  setEnriching]  = useState1(false);
  const [enrichData, setEnrichData] = useState1(null);

  const load = useCallback1(async (p, sev) => {
    setLoading(true);
    const params = new URLSearchParams({ hours: 24, page: p, page_size: pageSize });
    if (sev && sev !== 'all') params.set('severity', sev);
    const data  = await API.get(`/api/alerts?${params}`);
    const items = (data?.items || data?.alerts || []).map(adaptAlert);
    setAlerts(items);
    setTotal(data?.total || items.length);
    if (items.length > 0 && !selected) setSelected(items[0]);
    setLoading(false);
  }, [pageSize]);

  useEffect1(() => { setPage(1); setSelected(null); load(1, sevFilter); }, [sevFilter]);

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
            {['all', 'critical', 'high', 'medium', 'low'].map(s => (
              <button key={s} className={`seg-btn ${sevFilter === s ? 'on' : ''}`} onClick={() => setSevFilter(s)}>
                {s !== 'all' && <SevDot sev={s} size={6} />}
                {s}
                <span className="seg-count mono">{sevCounts[s] || 0}</span>
              </button>
            ))}
          </div>
          <div className="alerts-filters">
            <span className="mono dim" style={{ fontSize: 11 }}>
              {total.toLocaleString()} total · page {page}/{totalPages || 1}
            </span>
            {page > 1         && <button className="btn btn-ghost" style={{ padding: '2px 8px' }} onClick={handlePrev}>← Prev</button>}
            {page < totalPages && <button className="btn btn-ghost" style={{ padding: '2px 8px' }} onClick={handleNext}>Next →</button>}
          </div>
        </div>

        <div className="alerts-layout">
          <div className="alerts-table-wrap">
            {loading
              ? <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200 }}><Spinner /></div>
              : alerts.length === 0
                ? <div style={{ padding: 32, textAlign: 'center', color: 'var(--fg-3)' }}>No alerts found</div>
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
                          <td style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
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
            {selected && (
              <AlertDetail alert={selected} enrichData={enrichData} setEnrichData={setEnrichData}
                enriching={enriching} setEnriching={setEnriching} />
            )}
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
      title:          alert.rule,
      description:    `Alert ${alert.id}: ${alert.rule}\nAgent: ${alert.agent}\nSrc IP: ${alert.srcIp}`,
      severity:       alert.sev,
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
        <span className="mono dim" style={{ fontSize: 11 }}>{alert.ruleId}</span>
      </div>
      <h2 className="detail-title">{alert.rule}</h2>
      <div className="detail-time mono">
        {alert.time instanceof Date ? alert.time.toISOString().slice(0, 19).replace('T', ' ') : alert.time} UTC
      </div>

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
          <div className="detail-cell" style={{ gridColumn: '1/-1' }}>
            <div className="dc-label">GROUPS</div>
            <div className="dc-value mono" style={{ wordBreak: 'break-all' }}>
              {Array.isArray(alert.groups) ? alert.groups.join(', ') : alert.groups}
            </div>
          </div>
        )}
      </div>

      {alert.fullLog && (
        <div className="detail-section">
          <div className="ds-title">Raw log</div>
          <pre style={{ fontSize: 10, background: 'var(--bg-0)', padding: 8, borderRadius: 4,
                        overflowX: 'auto', maxHeight: 120, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                        color: 'var(--fg-2)' }}>
            {typeof alert.fullLog === 'string' ? alert.fullLog : JSON.stringify(alert.fullLog, null, 2)}
          </pre>
        </div>
      )}

      {alert.srcIp && alert.srcIp !== '—' && (
        <div className="detail-section">
          <div className="ds-title">
            IOC enrichment
            {!enrichData && !enriching && (
              <button className="btn btn-ghost" style={{ marginLeft: 8, padding: '2px 8px', fontSize: 11 }}
                onClick={enrich}>Enrich IP</button>
            )}
            {enriching && <span className="dim" style={{ marginLeft: 8, fontSize: 11 }}>Enriching…</span>}
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
          <Icon.folder width="13" height="13" /> Create case
        </button>
        <button className="btn btn-ghost"
          onClick={() => window.socToast?.({ title: 'Alert suppressed', sub: `${alert.id} · 24h`, tone: 'default' })}>
          Suppress
        </button>
      </div>
    </div>
  );
}

Object.assign(window, { PageDashboard, PageAlerts });
