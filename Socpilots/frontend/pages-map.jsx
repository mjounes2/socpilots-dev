// Live Threat Map — real GeoJSON, animated arcs, live top-IPs from API
const { useState: useM_, useEffect: useME, useRef: useMR, useMemo: useMM } = React;

// Geo heuristic: map first octet ranges to approximate lat/lng + country
function geoHeuristic(ip) {
  const first = parseInt((ip || '').split('.')[0]) || 0;
  const GEO_TABLE = [
    { range: [1,  9],   lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [14,14],   lng: 139.7, lat: 35.7,  country: 'JP', city: 'Tokyo'      },
    { range: [23,23],   lng: -77.0, lat: 38.9,  country: 'US', city: 'Virginia'   },
    { range: [27,27],   lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [31,31],   lng: 37.6,  lat: 55.7,  country: 'RU', city: 'Moscow'     },
    { range: [36,36],   lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [37,37],   lng: 37.6,  lat: 55.7,  country: 'RU', city: 'Moscow'     },
    { range: [43,43],   lng: 139.7, lat: 35.7,  country: 'JP', city: 'Tokyo'      },
    { range: [45,45],   lng: -77.0, lat: 38.9,  country: 'US', city: 'Ashburn'    },
    { range: [46,46],   lng: 37.6,  lat: 55.7,  country: 'RU', city: 'Moscow'     },
    { range: [51,51],   lng: 4.9,   lat: 52.4,  country: 'NL', city: 'Amsterdam'  },
    { range: [52,52],   lng: -77.0, lat: 38.9,  country: 'US', city: 'Virginia'   },
    { range: [54,54],   lng: -122.3,lat: 47.6,  country: 'US', city: 'Seattle'    },
    { range: [58,60],   lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [77,79],   lng: 25.0,  lat: 60.2,  country: 'FI', city: 'Helsinki'   },
    { range: [80,80],   lng: 4.9,   lat: 52.4,  country: 'NL', city: 'Amsterdam'  },
    { range: [81,81],   lng: 13.4,  lat: 52.5,  country: 'DE', city: 'Berlin'     },
    { range: [83,83],   lng: 2.3,   lat: 48.9,  country: 'FR', city: 'Paris'      },
    { range: [84,85],   lng: 13.4,  lat: 52.5,  country: 'DE', city: 'Frankfurt'  },
    { range: [86,86],   lng: 37.6,  lat: 55.7,  country: 'RU', city: 'Moscow'     },
    { range: [91,91],   lng: 37.6,  lat: 55.7,  country: 'RU', city: 'Moscow'     },
    { range: [92,93],   lng: 4.9,   lat: 52.4,  country: 'NL', city: 'Amsterdam'  },
    { range: [94,95],   lng: 4.9,   lat: 52.4,  country: 'NL', city: 'Amsterdam'  },
    { range: [103,103], lng: 103.8, lat: 1.4,   country: 'SG', city: 'Singapore'  },
    { range: [104,104], lng: -94.6, lat: 38.9,  country: 'US', city: 'Kansas'     },
    { range: [107,107], lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [110,112], lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [117,117], lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [118,118], lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [120,120], lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [121,121], lng: 121.5, lat: 25.0,  country: 'TW', city: 'Taipei'     },
    { range: [122,125], lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [138,138], lng: 151.2, lat: -33.8, country: 'AU', city: 'Sydney'     },
    { range: [140,140], lng: 139.7, lat: 35.7,  country: 'JP', city: 'Tokyo'      },
    { range: [149,149], lng: 37.6,  lat: 55.7,  country: 'RU', city: 'Moscow'     },
    { range: [159,159], lng: 37.6,  lat: 55.7,  country: 'RU', city: 'Moscow'     },
    { range: [162,163], lng: 4.9,   lat: 52.4,  country: 'NL', city: 'Amsterdam'  },
    { range: [176,176], lng: 37.6,  lat: 55.7,  country: 'RU', city: 'Moscow'     },
    { range: [178,179], lng: 37.6,  lat: 55.7,  country: 'RU', city: 'Moscow'     },
    { range: [180,180], lng: 37.6,  lat: 55.7,  country: 'RU', city: 'Moscow'     },
    { range: [181,181], lng: -46.6, lat: -23.5, country: 'BR', city: 'São Paulo'  },
    { range: [182,183], lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [185,185], lng: 4.9,   lat: 52.4,  country: 'NL', city: 'Amsterdam'  },
    { range: [186,191], lng: -46.6, lat: -23.5, country: 'BR', city: 'São Paulo'  },
    { range: [193,195], lng: 4.9,   lat: 52.4,  country: 'NL', city: 'Amsterdam'  },
    { range: [196,197], lng: 28.0,  lat: -26.2, country: 'ZA', city: 'Jo\'burg'  },
    { range: [200,201], lng: -46.6, lat: -23.5, country: 'BR', city: 'São Paulo'  },
    { range: [202,203], lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [210,211], lng: 116.4, lat: 39.9,  country: 'CN', city: 'Beijing'    },
    { range: [213,213], lng: 51.4,  lat: 35.7,  country: 'IR', city: 'Tehran'     },
    { range: [216,216], lng: -77.0, lat: 38.9,  country: 'US', city: 'Virginia'   },
    { range: [217,217], lng: 30.5,  lat: 50.5,  country: 'UA', city: 'Kyiv'       },
  ];
  const match = GEO_TABLE.find(e => first >= e.range[0] && first <= e.range[1]);
  return match || { lng: (first * 137.5) % 360 - 180, lat: (first * 79.3) % 140 - 70, country: `X${first}`, city: 'Unknown' };
}

function countToSev(count, max) {
  const pct = count / (max || 1);
  if (pct > 0.5) return 'critical';
  if (pct > 0.3) return 'high';
  if (pct > 0.15) return 'medium';
  return 'low';
}

const MAP_TARGETS_DEFAULT = [
  { lng: 36.3,   lat: 33.5, label: 'HQ · SOC DC'       },
  { lng: 4.9,    lat: 52.4, label: 'EU edge · Amsterdam' },
  { lng: -122.4, lat: 37.8, label: 'US edge · SF'        },
];

const SEV_COLOR = {
  critical: 'oklch(0.68 0.20 22)',
  high: 'oklch(0.78 0.16 50)',
  medium: 'oklch(0.85 0.16 90)',
  low: 'oklch(0.78 0.14 150)',
};

function PageMap() {
  const wrapRef = useMR(null);
  const [dims, setDims]           = useM_({ w: 1200, h: 600 });
  const [world, setWorld]         = useM_(null);
  const [loadErr, setLoadErr]     = useM_(null);
  const [tick, setTick]           = useM_(0);
  const [playing, setPlaying]     = useM_(true);
  const [feed, setFeed]           = useM_([]);
  const [highlight, setHighlight] = useM_(null);
  const [origins, setOrigins]     = useM_(MAP_TARGETS_DEFAULT.map((t,i) => ({
    lng: t.lng + 10, lat: t.lat + 5, count: 5, country: '??', city: 'Loading…', sev: 'low',
  })));
  const [dataLoaded, setDataLoaded] = useM_(false);

  // Load real top-IPs from API
  useME(() => {
    window.SOC_API.get('/api/stats/top-ips').then(data => {
      if (!data || data.error || !Array.isArray(data) || data.length === 0) return;
      const maxCount = Math.max(...data.map(d => d.count));
      const mapped = data.map(d => {
        const geo = geoHeuristic(d.ip);
        // Deterministic jitter from IP so overlapping countries don't stack
        // and dots don't twitch on re-render
        const parts = (d.ip || '').split('.');
        const h1 = ((parseInt(parts[2]) || 0) % 100) / 100 - 0.5;
        const h2 = ((parseInt(parts[3]) || 0) % 100) / 100 - 0.5;
        return {
          ...geo,
          lng: geo.lng + h1 * 4,
          lat: geo.lat + h2 * 4,
          count: d.count,
          ip: d.ip,
          sev: countToSev(d.count, maxCount),
        };
      });
      setOrigins(mapped);
      setDataLoaded(true);
      // seed ticker with real data
      setFeed(mapped.map((o, i) => ({
        id: 'WZ-' + (9280000 + i),
        time: new Date(Date.now() - i * 45000),
        origin: o,
        msg: `Attack from ${o.ip} · ${o.count} hits`,
      })));
    });
  }, []);

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

  // Stream real new alerts every 10s — short-poll the live alerts API
  // and dedupe by alert id. New alerts get a geo origin and join the feed.
  const seenIdsRef = useMR(new Set());
  useME(() => {
    if (!playing) return;
    let stopped = false;
    async function pollAlerts() {
      const data = await window.SOC_API.get('/api/alerts?hours=1&page_size=20');
      if (stopped || !data || data.error) return;
      const items = data.items || data.alerts || [];
      const fresh = [];
      for (const a of items) {
        const id = a.id || a.alertId || a.alert_id;
        if (!id || seenIdsRef.current.has(id)) continue;
        seenIdsRef.current.add(id);
        const ip = a.srcip || a.src_ip || a.source_ip || '';
        const geo = ip ? geoHeuristic(ip) : { country: '??', city: 'Unknown', lng: 0, lat: 0 };
        fresh.push({
          id: typeof id === 'string' ? id.slice(0, 12) : id,
          time: a.timestamp ? new Date(a.timestamp) : new Date(),
          origin: { ...geo, ip, count: 1, sev: a.severity || 'low' },
          msg: (a.description || a.rule || `Alert ${id}`).slice(0, 80),
        });
      }
      if (fresh.length) setFeed(f => [...fresh, ...f].slice(0, 30));
    }
    pollAlerts();
    const t = setInterval(pollAlerts, 10_000);
    return () => { stopped = true; clearInterval(t); };
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
  const totalHits  = origins.reduce((a, b) => a + b.count, 0);
  const critHits   = origins.filter(o => o.sev === 'critical').reduce((a,b)=>a+b.count, 0);
  const topByCount = [...origins].sort((a,b) => b.count - a.count).slice(0, 6);

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
                origins={origins}
                targets={MAP_TARGETS_DEFAULT}
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
                <div className="hud-num">{origins.length}</div>
                <div className="hud-lbl mono">COUNTRIES</div>
              </div>
              <div className="hud-block">
                <div className="hud-num">{MAP_TARGETS_DEFAULT.length}</div>
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
                {MAP_TARGETS_DEFAULT.map((t, i) => (
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

      {/* Origin pulses — log-scaled so high-volume counts don't blow up the
          map. With count=10 → r≈8, count=1000 → r≈15, count=10000 → r≈18 */}
      {oPts.map(o => {
        const r = Math.max(3, Math.min(18, 3 + Math.log2((o.count || 1) + 1) * 1.5));
        const sevColor = SEV_COLOR[o.sev];
        const isHi = highlight === o.country;
        return (
          <g key={o.country}
             onMouseEnter={() => onHover(o.country)}
             onMouseLeave={() => onHover(null)}
             style={{cursor: 'pointer'}}>
            <circle cx={o.p[0]} cy={o.p[1]} r={r * 1.8}
              fill={sevColor} opacity={isHi ? 0.22 : 0.12}>
              <animate attributeName="r" values={`${r * 1.2};${r * 2.4};${r * 1.2}`} dur="2.6s" repeatCount="indefinite"/>
              <animate attributeName="opacity" values="0.28;0;0.28" dur="2.6s" repeatCount="indefinite"/>
            </circle>
            <circle cx={o.p[0]} cy={o.p[1]} r={r} fill={sevColor} filter="url(#glow)"/>
            <circle cx={o.p[0]} cy={o.p[1]} r={Math.max(1, r * 0.45)} fill="#fff" opacity="0.9"/>
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

Object.assign(window, { PageMap });
