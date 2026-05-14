// Live Threat Map — real GeoJSON, animated arcs
const { useState: useM_, useEffect: useME, useRef: useMR, useMemo: useMM } = React;

// Extra attack-origin events (more variety than the dashboard subset)
const MAP_ORIGINS = [
  { lng: 37.6,   lat: 55.7,  count: 47, country: 'RU', city: 'Moscow',     sev: 'critical' },
  { lng: 116.4,  lat: 39.9,  count: 38, country: 'CN', city: 'Beijing',    sev: 'critical' },
  { lng: 51.4,   lat: 35.7,  count: 22, country: 'IR', city: 'Tehran',     sev: 'high' },
  { lng: 4.9,    lat: 52.4,  count: 18, country: 'NL', city: 'Amsterdam',  sev: 'high' },
  { lng: -3.7,   lat: 40.4,  count: 14, country: 'ES', city: 'Madrid',     sev: 'medium' },
  { lng: 127.0,  lat: 37.5,  count: 11, country: 'KR', city: 'Seoul',      sev: 'medium' },
  { lng: 121.5,  lat: 25.0,  count: 9,  country: 'TW', city: 'Taipei',     sev: 'medium' },
  { lng: -99.1,  lat: 19.4,  count: 7,  country: 'MX', city: 'Mexico City',sev: 'low' },
  { lng: -46.6,  lat: -23.5, count: 5,  country: 'BR', city: 'São Paulo',  sev: 'low' },
  { lng: 77.2,   lat: 28.6,  count: 4,  country: 'IN', city: 'New Delhi',  sev: 'low' },
  { lng: 28.9,   lat: 41.0,  count: 4,  country: 'TR', city: 'Istanbul',   sev: 'low' },
  { lng: 25.3,   lat: 54.7,  count: 3,  country: 'LT', city: 'Vilnius',    sev: 'low' },
  { lng: 30.5,   lat: 50.5,  count: 21, country: 'UA', city: 'Kyiv',       sev: 'high' },
  { lng: 105.8,  lat: 21.0,  count: 8,  country: 'VN', city: 'Hanoi',      sev: 'medium' },
  { lng: -74.0,  lat: 40.7,  count: 12, country: 'US', city: 'New York',   sev: 'medium' },
  { lng: 13.4,   lat: 52.5,  count: 7,  country: 'DE', city: 'Berlin',     sev: 'low' },
];

const MAP_TARGETS = [
  { lng: 36.3, lat: 33.5, label: 'HQ · Damascus DC' },
  { lng: -0.1, lat: 51.5, label: 'EU edge · London' },
  { lng: -122.4, lat: 37.8, label: 'US edge · SF' },
];

const SEV_COLOR = {
  critical: 'oklch(0.68 0.20 22)',
  high: 'oklch(0.78 0.16 50)',
  medium: 'oklch(0.85 0.16 90)',
  low: 'oklch(0.78 0.14 150)',
};

function PageMap() {
  const wrapRef = useMR(null);
  const [dims, setDims] = useM_({ w: 1200, h: 600 });
  const [world, setWorld] = useM_(null);
  const [loadErr, setLoadErr] = useM_(null);
  const [tick, setTick] = useM_(0);
  const [playing, setPlaying] = useM_(true);
  const [feed, setFeed] = useM_(() => seedFeed());
  const [highlight, setHighlight] = useM_(null);

  // Resize observer
  useME(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver(entries => {
      for (const e of entries) {
        const w = Math.max(600, e.contentRect.width);
        setDims({ w, h: w * 0.55 });
      }
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, []);

  // Fetch GeoJSON (TopoJSON from world-atlas)
  useME(() => {
    let cancelled = false;
    async function load() {
      try {
        // wait briefly for the topojson-client + d3 UMD scripts to settle
        for (let i = 0; i < 40 && (!window.topojson || !window.d3); i++) {
          await new Promise(r => setTimeout(r, 50));
        }
        if (!window.topojson || !window.d3) throw new Error('map libs missing');
        const r = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json');
        if (!r.ok) throw new Error('fetch failed');
        const topo = await r.json();
        if (cancelled) return;
        const fc = window.topojson.feature(topo, topo.objects.countries);
        setWorld(fc);
      } catch (e) {
        if (!cancelled) setLoadErr(String(e.message || e));
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  // Arc animation ticker
  useME(() => {
    if (!playing) return;
    let raf;
    let last = performance.now();
    const loop = (t) => {
      const dt = t - last;
      last = t;
      setTick(x => x + dt);
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, [playing]);

  // Synthesize new feed events every ~2.5s
  useME(() => {
    if (!playing) return;
    const t = setInterval(() => {
      const o = MAP_ORIGINS[Math.floor(Math.random() * MAP_ORIGINS.length)];
      const id = 'WZ-' + Math.floor(9280000 + Math.random() * 9000);
      setFeed(f => [{ id, time: new Date(), origin: o, msg: pickMsg(o) }, ...f].slice(0, 30));
    }, 2500);
    return () => clearInterval(t);
  }, [playing]);

  // Compute projection
  const { proj, pathFn } = useMM(() => {
    if (!world || !window.d3) return { proj: null, pathFn: null };
    const p = window.d3.geoNaturalEarth1().fitExtent([[8, 8], [dims.w - 8, dims.h - 8]], world);
    const pf = window.d3.geoPath(p);
    return { proj: p, pathFn: pf };
  }, [world, dims]);

  // Compute country paths once
  const countryPaths = useMM(() => {
    if (!world || !pathFn) return [];
    return world.features.map((f, i) => ({ id: i, d: pathFn(f) }));
  }, [world, pathFn]);

  // Total stats
  const totalHits = MAP_ORIGINS.reduce((a, b) => a + b.count, 0);
  const critHits  = MAP_ORIGINS.filter(o => o.sev === 'critical').reduce((a,b)=>a+b.count, 0);
  const topByCount = [...MAP_ORIGINS].sort((a,b) => b.count - a.count).slice(0, 6);

  return (
    <div className="page" data-screen-label="12 Live Threat Map">
      <Topbar
        title="Live Threat Map"
        sub="Real-time attack geolocation · Natural Earth projection"
        actions={<>
          <Chip mono tone="ok"><span className="pip pip-ok"/> LIVE · {feed.length} events</Chip>
          <button className="btn btn-ghost" onClick={() => setPlaying(p => !p)}>
            {playing ? 'Pause' : 'Resume'}
          </button>
          <button className="btn btn-ghost">Replay 1h</button>
          <button className="btn btn-primary">Full screen</button>
        </>}
      />
      <div className="page-body map-page-body">
        <div className="map-layout">
          <div className="map-stage" ref={wrapRef}>
            {!world && !loadErr && (
              <div className="map-loading">
                <div className="map-spin"/>
                <div className="mono">loading world geometry · Natural Earth 1:110m</div>
              </div>
            )}
            {loadErr && (
              <div className="map-loading">
                <div className="mono" style={{color: 'var(--high)'}}>map data unavailable · {loadErr}</div>
                <div className="mono dim" style={{marginTop: 6}}>Check network connection to cdn.jsdelivr.net</div>
              </div>
            )}
            {world && proj && (
              <MapSVG
                world={world}
                countryPaths={countryPaths}
                proj={proj}
                w={dims.w}
                h={dims.h}
                origins={MAP_ORIGINS}
                targets={MAP_TARGETS}
                tick={tick}
                highlight={highlight}
                onHover={setHighlight}
              />
            )}

            {/* HUD overlays */}
            <div className="map-hud map-hud-tl">
              <div className="hud-block">
                <div className="hud-num">{totalHits.toLocaleString()}</div>
                <div className="hud-lbl mono">HITS · 24H</div>
              </div>
              <div className="hud-block hud-crit">
                <div className="hud-num">{critHits}</div>
                <div className="hud-lbl mono">CRITICAL</div>
              </div>
              <div className="hud-block">
                <div className="hud-num">{MAP_ORIGINS.length}</div>
                <div className="hud-lbl mono">COUNTRIES</div>
              </div>
              <div className="hud-block">
                <div className="hud-num">{MAP_TARGETS.length}</div>
                <div className="hud-lbl mono">TARGETS</div>
              </div>
            </div>

            <div className="map-hud map-hud-bl">
              <div className="hud-legend">
                <div className="hud-legend-row"><span className="sev-dot" data-sev="critical"/> <span className="mono">critical</span></div>
                <div className="hud-legend-row"><span className="sev-dot" data-sev="high"/> <span className="mono">high</span></div>
                <div className="hud-legend-row"><span className="sev-dot" data-sev="medium"/> <span className="mono">medium</span></div>
                <div className="hud-legend-row"><span className="sev-dot" data-sev="low"/> <span className="mono">low</span></div>
              </div>
            </div>

            <div className="map-hud map-hud-br mono">
              <div>PROJ · Natural Earth 1</div>
              <div>SRC · world-atlas@2.0.2</div>
              <div>RES · 1:110m</div>
            </div>
          </div>

          <aside className="map-side">
            <Card title="Top origins" sub="last 24h">
              <ul className="map-top-list">
                {topByCount.map(o => (
                  <li key={o.country}
                      className={`mtl-row ${highlight === o.country ? 'on' : ''}`}
                      onMouseEnter={() => setHighlight(o.country)}
                      onMouseLeave={() => setHighlight(null)}>
                    <span className="mtl-country mono">{o.country}</span>
                    <span className="mtl-city">{o.city}</span>
                    <div className="mtl-bar">
                      <div className="mtl-bar-fill" style={{
                        width: `${(o.count / topByCount[0].count) * 100}%`,
                        background: SEV_COLOR[o.sev],
                      }}/>
                    </div>
                    <span className="mtl-count mono">{o.count}</span>
                  </li>
                ))}
              </ul>
            </Card>

            <Card title="Targets" sub="protected infrastructure">
              <ul className="map-target-list">
                {MAP_TARGETS.map((t, i) => (
                  <li key={i}>
                    <Icon.target width="14" height="14"/>
                    <div>
                      <div className="mtl-target-label">{t.label}</div>
                      <div className="mtl-target-coord mono">{t.lat.toFixed(2)}, {t.lng.toFixed(2)}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </Card>

            <Card title="Live ticker" sub={playing ? 'streaming' : 'paused'}
              actions={<span className="live-pip"><span className="pip"/>LIVE</span>}>
              <ul className="map-ticker">
                {feed.slice(0, 8).map(f => (
                  <li key={f.id}>
                    <span className="mt-time mono">{f.time.toISOString().slice(11,19)}</span>
                    <span className="mt-flag mono"
                          style={{color: SEV_COLOR[f.origin.sev]}}>{f.origin.country}</span>
                    <span className="mt-msg">{f.msg}</span>
                  </li>
                ))}
              </ul>
            </Card>
          </aside>
        </div>
      </div>
    </div>
  );
}

function MapSVG({ world, countryPaths, proj, w, h, origins, targets, tick, highlight, onHover }) {
  // Pre-project origin & target points
  const oPts = useMM(() => origins.map(o => ({ ...o, p: proj([o.lng, o.lat]) })), [origins, proj]);
  const tPts = useMM(() => targets.map(t => ({ ...t, p: proj([t.lng, t.lat]) })), [targets, proj]);

  // Build arcs (each origin → nearest target by lng difference for visual variety)
  const arcs = useMM(() => {
    if (!window.d3) return [];
    return origins.flatMap((o, i) => {
      const tgt = targets[i % targets.length];
      // Sample the great circle in 64 steps via geoInterpolate
      const interp = window.d3.geoInterpolate([o.lng, o.lat], [tgt.lng, tgt.lat]);
      const steps = 64;
      const pts = [];
      for (let s = 0; s <= steps; s++) {
        const g = interp(s / steps);
        const p = proj(g);
        if (p) pts.push(p);
      }
      return [{
        id: `${o.country}-${i}`,
        from: o,
        to: tgt,
        pts,
        sev: o.sev,
      }];
    });
  }, [origins, targets, proj]);

  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height="auto" className="map map-real">
      <defs>
        {/* Sphere gradient — subtle "ocean" feel */}
        <radialGradient id="ocean" cx="50%" cy="40%" r="70%">
          <stop offset="0%" stopColor="oklch(0.20 0.014 250)"/>
          <stop offset="100%" stopColor="oklch(0.14 0.012 250)"/>
        </radialGradient>
        <linearGradient id="arc-crit" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={SEV_COLOR.critical} stopOpacity="0.05"/>
          <stop offset="100%" stopColor={SEV_COLOR.critical} stopOpacity="0.8"/>
        </linearGradient>
        <linearGradient id="arc-high" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={SEV_COLOR.high} stopOpacity="0.05"/>
          <stop offset="100%" stopColor={SEV_COLOR.high} stopOpacity="0.8"/>
        </linearGradient>
        <linearGradient id="arc-medium" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={SEV_COLOR.medium} stopOpacity="0.05"/>
          <stop offset="100%" stopColor={SEV_COLOR.medium} stopOpacity="0.8"/>
        </linearGradient>
        <linearGradient id="arc-low" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor={SEV_COLOR.low} stopOpacity="0.05"/>
          <stop offset="100%" stopColor={SEV_COLOR.low} stopOpacity="0.8"/>
        </linearGradient>
        {/* Glow filter for dots */}
        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3"/>
          <feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>

      {/* Ocean sphere */}
      {window.d3 && (() => {
        const sphereD = window.d3.geoPath(proj)({ type: 'Sphere' });
        return <path d={sphereD} fill="url(#ocean)"/>;
      })()}

      {/* Graticule */}
      {window.d3 && (() => {
        const g = window.d3.geoGraticule().step([20, 20])();
        const d = window.d3.geoPath(proj)(g);
        return <path d={d} fill="none" stroke="oklch(0.28 0.014 250)" strokeWidth="0.4" opacity="0.5"/>;
      })()}

      {/* Countries */}
      {countryPaths.map(c => (
        <path key={c.id} d={c.d}
          fill="oklch(0.22 0.014 250)"
          stroke="oklch(0.32 0.016 250)"
          strokeWidth="0.4"
        />
      ))}

      {/* Arcs */}
      {arcs.map(a => {
        const pathD = pointsToPath(a.pts);
        const isHi = highlight === a.from.country;
        return (
          <g key={a.id} opacity={highlight && !isHi ? 0.18 : 1}>
            <path d={pathD}
              fill="none"
              stroke={`url(#arc-${a.sev})`}
              strokeWidth={isHi ? 1.6 : 0.9}
              opacity="0.7"
            />
            {/* Animated traveling dot */}
            <ArcTraveler arc={a} tick={tick}/>
          </g>
        );
      })}

      {/* Origin pulses */}
      {oPts.map(o => {
        const r = 3 + (o.count / 50) * 6;
        const sevColor = SEV_COLOR[o.sev];
        const isHi = highlight === o.country;
        return (
          <g key={o.country}
             onMouseEnter={() => onHover(o.country)}
             onMouseLeave={() => onHover(null)}
             style={{cursor: 'pointer'}}>
            <circle cx={o.p[0]} cy={o.p[1]} r={r * 2.2}
              fill={sevColor} opacity={isHi ? 0.22 : 0.12}>
              <animate attributeName="r" values={`${r};${r*3};${r}`} dur="2.6s" repeatCount="indefinite"/>
              <animate attributeName="opacity" values="0.25;0;0.25" dur="2.6s" repeatCount="indefinite"/>
            </circle>
            <circle cx={o.p[0]} cy={o.p[1]} r={r} fill={sevColor} filter="url(#glow)"/>
            <circle cx={o.p[0]} cy={o.p[1]} r={Math.max(1, r * 0.5)} fill="#fff" opacity="0.9"/>
            {isHi && (
              <g>
                <text x={o.p[0] + r + 6} y={o.p[1] - 3} className="map-real-label"
                  fill={sevColor} fontWeight="600">{o.city.toUpperCase()}</text>
                <text x={o.p[0] + r + 6} y={o.p[1] + 9} className="map-real-label-sub">
                  {o.country} · {o.count} hits
                </text>
              </g>
            )}
          </g>
        );
      })}

      {/* Targets */}
      {tPts.map((t, i) => (
        <g key={i}>
          <circle cx={t.p[0]} cy={t.p[1]} r="6" fill="none"
            stroke="oklch(0.82 0.14 200)" strokeWidth="1.2">
            <animate attributeName="r" values="6;16;6" dur="2.4s" repeatCount="indefinite"/>
            <animate attributeName="opacity" values="1;0;1" dur="2.4s" repeatCount="indefinite"/>
          </circle>
          <circle cx={t.p[0]} cy={t.p[1]} r="4"
            fill="oklch(0.82 0.14 200)" filter="url(#glow)"/>
          <rect x={t.p[0] - 1} y={t.p[1] - 1} width="2" height="2" fill="#fff"/>
          <text x={t.p[0] + 10} y={t.p[1] + 3} className="map-real-target">
            {t.label}
          </text>
        </g>
      ))}
    </svg>
  );
}

function ArcTraveler({ arc, tick }) {
  // tick is monotonically increasing ms — use modulo to loop
  const period = 3000 + (arc.from.count * 30) % 1500;
  const t = ((tick % period) / period);
  const idx = Math.floor(t * (arc.pts.length - 1));
  const p = arc.pts[idx];
  if (!p) return null;
  const sevColor = SEV_COLOR[arc.sev];
  return (
    <>
      <circle cx={p[0]} cy={p[1]} r="2.5" fill={sevColor} filter="url(#glow)"/>
      <circle cx={p[0]} cy={p[1]} r="1.2" fill="#fff"/>
    </>
  );
}

function pointsToPath(pts) {
  if (!pts.length) return '';
  // Break on antimeridian jumps (large distance between consecutive points)
  let d = '';
  let last = null;
  for (let i = 0; i < pts.length; i++) {
    const p = pts[i];
    if (!last) { d += `M${p[0].toFixed(1)} ${p[1].toFixed(1)}`; last = p; continue; }
    const dx = Math.abs(p[0] - last[0]);
    if (dx > 200) d += `M${p[0].toFixed(1)} ${p[1].toFixed(1)}`;
    else          d += `L${p[0].toFixed(1)} ${p[1].toFixed(1)}`;
    last = p;
  }
  return d;
}

function seedFeed() {
  const out = [];
  for (let i = 0; i < 8; i++) {
    const o = MAP_ORIGINS[i % MAP_ORIGINS.length];
    out.push({
      id: 'WZ-' + (9281047 - i * 3),
      time: new Date(Date.now() - i * 1200),
      origin: o,
      msg: pickMsg(o),
    });
  }
  return out;
}

function pickMsg(o) {
  const pool = [
    'SSH brute-force attempt',
    'Suspicious PowerShell payload',
    'SQL injection on /api/v2',
    'Tor exit connection detected',
    'Port scan · 1024 ports',
    'Phishing URL clicked',
    'Audit log clearing attempt',
    'C2 beacon pattern',
  ];
  return pool[(o.count + o.lat.toString().length) % pool.length];
}

Object.assign(window, { PageMap });
