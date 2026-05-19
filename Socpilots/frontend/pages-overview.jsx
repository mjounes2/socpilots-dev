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
// ─── Real-world topology cache (fetched once, shared across all mounts) ──
window._socWorldFc = window._socWorldFc || null;
window._socWorldLoading = window._socWorldLoading || null;
function _loadWorldGeometry() {
  if (window._socWorldFc) return Promise.resolve(window._socWorldFc);
  if (window._socWorldLoading) return window._socWorldLoading;
  window._socWorldLoading = (async () => {
    for (let i = 0; i < 60 && (!window.topojson || !window.d3); i++) {
      await new Promise(r => setTimeout(r, 50));
    }
    if (!window.topojson || !window.d3) throw new Error('topojson/d3 missing');
    const r = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json');
    if (!r.ok) throw new Error('world-atlas fetch failed');
    const topo = await r.json();
    const fc = window.topojson.feature(topo, topo.objects.countries);
    window._socWorldFc = fc;
    return fc;
  })();
  return window._socWorldLoading;
}

// ─── Kaspersky-style rotating globe ───────────────────────────
// Real world-atlas country geometry, multi-layer atmospheric glow,
// pulsing attack origins with rising light beams, animated geodesic
// attack arcs toward a fixed HQ.
function DashWorldMap({ ips }) {
  const cvRef   = useRef1(null);
  const wrapRef = useRef1(null);
  const [world, setWorld] = useState1(window._socWorldFc);

  useEffect1(() => {
    if (world) return;
    let cancelled = false;
    _loadWorldGeometry().then(fc => { if (!cancelled) setWorld(fc); }).catch(() => {});
    return () => { cancelled = true; };
  }, [world]);

  useEffect1(() => {
    const cv   = cvRef.current;
    const wrap = wrapRef.current;
    if (!cv || !wrap || !window.d3) return;
    const d3 = window.d3;

    const dpr = window.devicePixelRatio || 1;
    const W = wrap.clientWidth || 400;
    const H = 260;
    cv.width  = W * dpr;
    cv.height = H * dpr;
    cv.style.width  = W + 'px';
    cv.style.height = H + 'px';
    const ctx = cv.getContext('2d');
    ctx.scale(dpr, dpr);

    // Star field — two layers (background tiny + foreground bigger)
    const stars = [];
    const rng = (() => { let s = 9301; return () => { s = (s * 9301 + 49297) % 233280; return s / 233280; }; })();
    for (let i = 0; i < 160; i++) {
      stars.push({
        x: rng() * W, y: rng() * H,
        r: rng() < 0.92 ? 0.4 : 1.0,
        twinkle: rng() * Math.PI * 2,
        alpha: 0.25 + rng() * 0.55,
        hue: rng() < 0.85 ? '220,230,255' : '180,210,240',
      });
    }

    // Globe geometry — center sphere in widget
    const cx = W * 0.55, cy = H / 2, radius = Math.min(H * 0.5, W * 0.4) * 0.95;
    const proj = d3.geoOrthographic()
      .scale(radius)
      .translate([cx, cy])
      .clipAngle(90);
    const pathFn = d3.geoPath(proj, ctx);

    const HQ = { lat: 33.5, lon: 36.3 };
    const origins = (ips || []).slice(0, 30).map(({ ip, count }) => {
      const g = dashGeoH(ip);
      return {
        ip, count,
        lat: g.lat, lon: g.lon,
        sev: count > 20 ? 'critical' : count > 10 ? 'high' : 'medium',
      };
    });

    const arcs = [];
    let nextArcAt = 0;
    let lambda = 30, raf = 0;
    let last = performance.now();

    const toRad = d => d * Math.PI / 180;
    function greatArcPoints(a, b, steps = 32) {
      const v = (lat, lon) => {
        const φ = toRad(lat), λ = toRad(lon);
        return [Math.cos(φ) * Math.cos(λ), Math.cos(φ) * Math.sin(λ), Math.sin(φ)];
      };
      const v1 = v(a.lat, a.lon), v2 = v(b.lat, b.lon);
      const dot = Math.max(-1, Math.min(1, v1[0]*v2[0] + v1[1]*v2[1] + v1[2]*v2[2]));
      const Ω = Math.acos(dot);
      if (Ω < 0.0001) return [[a.lon, a.lat], [b.lon, b.lat]];
      const sinΩ = Math.sin(Ω);
      const out = [];
      for (let i = 0; i <= steps; i++) {
        const t = i / steps;
        const A = Math.sin((1 - t) * Ω) / sinΩ;
        const B = Math.sin(t * Ω) / sinΩ;
        const x = A * v1[0] + B * v2[0];
        const y = A * v1[1] + B * v2[1];
        const z = A * v1[2] + B * v2[2];
        out.push([Math.atan2(y, x) * 180 / Math.PI, Math.asin(z) * 180 / Math.PI]);
      }
      return out;
    }

    function frame(now) {
      const dt = now - last;
      last = now;
      // Slower rotation: ~6°/sec for cinematic feel
      lambda = (lambda + dt * 0.006) % 360;
      proj.rotate([lambda, -12]);

      // Deep-space backdrop
      ctx.clearRect(0, 0, W, H);
      const bg = ctx.createRadialGradient(cx, cy, radius * 0.2, cx, cy, radius * 2.4);
      bg.addColorStop(0, '#0a1830');
      bg.addColorStop(0.6, '#040a1a');
      bg.addColorStop(1, '#01030a');
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, W, H);

      // Stars
      stars.forEach(s => {
        const tw = 0.55 + 0.45 * Math.sin((now / 1000) * 1.4 + s.twinkle);
        ctx.fillStyle = `rgba(${s.hue},${(s.alpha * tw).toFixed(3)})`;
        ctx.beginPath(); ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2); ctx.fill();
      });

      // Atmospheric glow — 3 stacked halos for depth
      const halos = [
        { r: radius * 1.50, c1: 'rgba(0,150,200,0.0)',  c2: 'rgba(0,150,200,0.10)' },
        { r: radius * 1.22, c1: 'rgba(0,180,220,0.0)',  c2: 'rgba(0,180,220,0.18)' },
        { r: radius * 1.06, c1: 'rgba(0,229,255,0.0)',  c2: 'rgba(0,229,255,0.30)' },
      ];
      halos.forEach(h => {
        const g = ctx.createRadialGradient(cx, cy, radius * 0.92, cx, cy, h.r);
        g.addColorStop(0, h.c2);
        g.addColorStop(1, h.c1);
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(cx, cy, h.r, 0, Math.PI * 2); ctx.fill();
      });

      // Sphere body (clipped)
      ctx.save();
      ctx.beginPath(); ctx.arc(cx, cy, radius, 0, Math.PI * 2); ctx.clip();

      // Inner sphere — slight specular highlight upper-left
      const sphereBg = ctx.createRadialGradient(
        cx - radius * 0.35, cy - radius * 0.35, radius * 0.05,
        cx, cy, radius);
      sphereBg.addColorStop(0,    '#13345e');
      sphereBg.addColorStop(0.55, '#0a1f3e');
      sphereBg.addColorStop(1,    '#020812');
      ctx.fillStyle = sphereBg;
      ctx.fillRect(cx - radius, cy - radius, radius * 2, radius * 2);

      // Graticule
      ctx.strokeStyle = 'rgba(0,200,230,0.07)';
      ctx.lineWidth = 0.5;
      const grat = d3.geoGraticule().step([15, 15])();
      ctx.beginPath();
      d3.geoPath(proj, ctx)(grat);
      ctx.stroke();

      // Real continents (or fallback to hand-drawn while world loads)
      if (world && world.features) {
        ctx.beginPath();
        pathFn({ type: 'FeatureCollection', features: world.features });
        ctx.fillStyle = 'rgba(30,80,140,0.85)';
        ctx.fill();
        ctx.strokeStyle = 'rgba(0,229,255,0.38)';
        ctx.lineWidth = 0.6;
        ctx.stroke();
      } else {
        DASH_CONTINENTS.forEach(pts => {
          ctx.beginPath();
          pathFn({ type: 'Feature', geometry: { type: 'Polygon', coordinates: [pts] } });
          ctx.fillStyle = 'rgba(20,60,110,0.8)';
          ctx.fill();
          ctx.strokeStyle = 'rgba(0,229,255,0.3)';
          ctx.lineWidth = 0.7;
          ctx.stroke();
        });
      }
      ctx.restore();

      // Sphere edge ring
      ctx.beginPath(); ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0,229,255,0.55)';
      ctx.lineWidth = 1.2;
      ctx.stroke();

      // Visibility test
      const center = proj.invert([cx, cy]);
      const visible = (lat, lon) =>
        d3.geoDistance([center[0], center[1]], [lon, lat]) < Math.PI / 2;

      // Spawn arcs toward HQ
      if (now > nextArcAt && origins.length) {
        const vis = origins.filter(o => visible(o.lat, o.lon));
        const pool = vis.length ? vis : origins;
        const src = pool[Math.floor(Math.random() * pool.length)];
        arcs.push({
          points: greatArcPoints(src, HQ, 36),
          t0: now, life: 2400, sev: src.sev,
        });
        nextArcAt = now + 500 + Math.random() * 600;
      }

      // Draw arcs (animated glowing trail)
      for (let i = arcs.length - 1; i >= 0; i--) {
        const a = arcs[i];
        const t = (now - a.t0) / a.life;
        if (t > 1.15) { arcs.splice(i, 1); continue; }
        const tipIdx = Math.min(a.points.length - 1, Math.floor(t * a.points.length));
        const trailLen = 14;
        const startIdx = Math.max(0, tipIdx - trailLen);
        const color = a.sev === 'critical' ? '#ff1744'
                    : a.sev === 'high'     ? '#ff8a00'
                    :                        '#00e5ff';
        ctx.lineCap = 'round';
        for (let k = startIdx; k < tipIdx; k++) {
          const seg = (k - startIdx) / trailLen;
          const p1 = proj(a.points[k]);
          const p2 = proj(a.points[k + 1]);
          if (!p1 || !p2) continue;
          ctx.globalAlpha = seg * (1 - Math.max(0, t - 1));
          ctx.strokeStyle = color;
          ctx.shadowColor = color; ctx.shadowBlur = 6;
          ctx.lineWidth = 1.1 + seg * 1.6;
          ctx.beginPath(); ctx.moveTo(p1[0], p1[1]); ctx.lineTo(p2[0], p2[1]); ctx.stroke();
        }
        ctx.globalAlpha = 1; ctx.shadowBlur = 0;
      }

      // Attack origins — rising light beams + pulsing dot
      origins.forEach((o, i) => {
        if (!visible(o.lat, o.lon)) return;
        const p = proj([o.lon, o.lat]);
        if (!p) return;
        const pulse = 0.5 + 0.5 * Math.sin((now / 1000) * 2 + i * 0.6);
        const baseR = Math.min(1.8 + Math.log2((o.count || 1) + 1) * 0.6, 4);
        const color = o.sev === 'critical' ? '#ff1744'
                    : o.sev === 'high'     ? '#ff8a00'
                    :                        '#ffd54f';

        // Vertical light beam rising from the surface (Kaspersky-style)
        const beamH = 14 + Math.log2((o.count || 1) + 1) * 3 + pulse * 4;
        const beamGrad = ctx.createLinearGradient(p[0], p[1] - beamH, p[0], p[1]);
        beamGrad.addColorStop(0, `rgba(255,255,255,0)`);
        beamGrad.addColorStop(0.4, color + '88');
        beamGrad.addColorStop(1, color);
        ctx.strokeStyle = beamGrad;
        ctx.lineWidth = 1.6;
        ctx.shadowColor = color; ctx.shadowBlur = 6;
        ctx.beginPath();
        ctx.moveTo(p[0], p[1]);
        ctx.lineTo(p[0], p[1] - beamH);
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Outer ripple ring
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.10 + 0.18 * (1 - pulse);
        ctx.beginPath(); ctx.arc(p[0], p[1], baseR + 4 + pulse * 6, 0, Math.PI * 2); ctx.fill();

        // Solid dot
        ctx.globalAlpha = 1;
        ctx.shadowColor = color; ctx.shadowBlur = 9;
        ctx.beginPath(); ctx.arc(p[0], p[1], baseR, 0, Math.PI * 2); ctx.fill();
        ctx.shadowBlur = 0;
      });

      // HQ bullseye
      if (visible(HQ.lat, HQ.lon)) {
        const p = proj([HQ.lon, HQ.lat]);
        // Outer pulsing ring
        const hqPulse = 0.5 + 0.5 * Math.sin(now / 350);
        ctx.strokeStyle = `rgba(0,229,255,${0.4 + hqPulse * 0.4})`;
        ctx.lineWidth = 1.2;
        ctx.beginPath(); ctx.arc(p[0], p[1], 6 + hqPulse * 4, 0, Math.PI * 2); ctx.stroke();
        // Inner
        ctx.fillStyle = '#00e5ff';
        ctx.shadowColor = '#00e5ff'; ctx.shadowBlur = 8;
        ctx.beginPath(); ctx.arc(p[0], p[1], 2.2, 0, Math.PI * 2); ctx.fill();
        ctx.shadowBlur = 0;
      }

      raf = requestAnimationFrame(frame);
    }

    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, [ips, world]);

  return (
    <div ref={wrapRef} style={{
      position: 'relative',
      background: 'radial-gradient(ellipse at center, #0a1830 0%, #01030a 100%)',
      borderRadius: 4,
      overflow: 'hidden',
    }}>
      <canvas ref={cvRef} style={{ display: 'block', width: '100%' }} />
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

// ─── Stacked-bar timeline (SVG + hover tooltip) ─────────────
// Vertical bars per hour bucket, stacked by severity (Critical at bottom,
// then High, Medium, Low). Centered legend above; per-bar tooltip on hover.
const TIMELINE_FONT_DISPLAY = "'IBM Plex Sans','Exo 2',system-ui,sans-serif";
const TIMELINE_FONT_MONO    = "'IBM Plex Mono','Share Tech Mono',monospace";

function AlertTimeline({ data }) {
  const [hover, setHover] = useState1(null); // { idx, px, py }
  const wrapRef = useRef1(null);

  if (!data || data.length < 1) return <EmptyState icon="📊" text="Insufficient timeline data" />;

  const w = 800, h = 260;
  const pad = { l: 64, r: 18, t: 44, b: 32 };
  const innerW = w - pad.l - pad.r;
  const innerH = h - pad.t - pad.b;

  // Order from bottom of stack → top
  const layers      = ['critical', 'high', 'medium', 'low'];
  const layerLabel  = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  const layerColor  = { critical: '#ff1744', high: '#ff9800', medium: '#ffc107', low: '#26c6da' };

  const totals = data.map(d => layers.reduce((s, L) => s + (d[L] || 0), 0));
  const rawMax = Math.max(...totals, 1);
  const niceMax = (() => {
    const pow = Math.pow(10, Math.floor(Math.log10(rawMax)));
    const m = rawMax / pow;
    const nice = m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10;
    return nice * pow;
  })();
  const tickStep = niceMax / 6;
  const yTicks   = Array.from({ length: 7 }, (_, i) => Math.round(i * tickStep));
  const fmtTick  = v => v.toLocaleString('en-US');

  const colW = innerW / data.length;
  const barW = colW * 0.7;
  const x = i => pad.l + colW * i + (colW - barW) / 2;
  const y = v => pad.t + innerH - (v / niceMax) * innerH;
  const ySpan = v => (v / niceMax) * innerH;

  const handleMove = (e) => {
    const rect = wrapRef.current?.getBoundingClientRect();
    if (!rect) return;
    const px = e.clientX - rect.left;
    const py = e.clientY - rect.top;
    const svgX = (px / rect.width) * w;
    if (svgX < pad.l || svgX > w - pad.r) { setHover(null); return; }
    const idx = Math.floor((svgX - pad.l) / colW);
    if (idx < 0 || idx >= data.length) { setHover(null); return; }
    setHover({ idx, px, py, rectW: rect.width });
  };

  const tooltipFor = hover ? data[hover.idx] : null;

  // Position tooltip — keep inside container by clamping to edges
  let tipLeft = hover ? hover.px + 14 : 0;
  let tipTop  = hover ? hover.py - 8  : 0;
  if (hover) {
    const TIP_W = 170, TIP_H = 142, M = 8;
    if (tipLeft + TIP_W > hover.rectW - M) tipLeft = hover.px - TIP_W - 14;
    if (tipTop < M) tipTop = M;
  }

  return (
    <div ref={wrapRef}
      style={{ position: 'relative', width: '100%' }}
      onMouseMove={handleMove}
      onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} className="chart"
        style={{ display: 'block' }}>
        {/* Legend (centered above chart area) */}
        <g transform={`translate(${pad.l + innerW / 2},${14})`}>
          {(() => {
            const items = ['critical', 'high', 'medium', 'low'];
            const widths = items.map(L => 12 + 6 + layerLabel[L].length * 8 + 22);
            const total = widths.reduce((a, b) => a + b, 0);
            let cursor = -total / 2;
            return items.map((L, i) => {
              const tx = cursor;
              cursor += widths[i];
              return (
                <g key={L} transform={`translate(${tx},0)`}>
                  <rect width="12" height="12" y="0" rx="2" fill={layerColor[L]} />
                  <text x="20" y="11" style={{
                    fontSize: 13, fill: 'var(--fg-1, #e8f4fd)',
                    fontFamily: TIMELINE_FONT_DISPLAY, fontWeight: 500,
                  }}>{layerLabel[L]}</text>
                </g>
              );
            });
          })()}
        </g>

        {/* Y gridlines + tick labels */}
        {yTicks.slice().reverse().map((t, i) => (
          <g key={i}>
            <line x1={pad.l} x2={w - pad.r} y1={y(t)} y2={y(t)}
              stroke="var(--ln, #1a2f4a)" strokeOpacity="0.55" />
            <text x={pad.l - 12} y={y(t) + 4} textAnchor="end"
              style={{ fontSize: 12, fill: 'var(--fg-2, #8ab0d0)', fontFamily: TIMELINE_FONT_MONO }}>
              {fmtTick(t)}
            </text>
          </g>
        ))}

        {/* Hovered column highlight */}
        {hover && (
          <rect
            x={pad.l + colW * hover.idx} y={pad.t}
            width={colW} height={innerH}
            fill="rgba(255,255,255,0.04)"
            pointerEvents="none"/>
        )}

        {/* Stacked bars */}
        {data.map((d, i) => {
          let acc = 0;
          return (
            <g key={i}>
              {layers.map(L => {
                const v = d[L] || 0;
                if (v <= 0) return null;
                const segH = ySpan(v);
                const segY = y(acc + v);
                acc += v;
                return (
                  <rect key={L}
                    x={x(i)} y={segY}
                    width={barW} height={Math.max(0, segH)}
                    fill={layerColor[L]} />
                );
              })}
            </g>
          );
        })}

        {/* X-axis labels (HH:00) */}
        {data.map((d, i) => {
          const stride = Math.max(1, Math.floor(data.length / 8));
          if (i % stride !== 0 && i !== data.length - 1) return null;
          return (
            <text key={i}
              x={x(i) + barW / 2}
              y={h - 10}
              textAnchor="middle"
              style={{ fontSize: 12, fill: 'var(--fg-2, #8ab0d0)', fontFamily: TIMELINE_FONT_MONO }}>
              {String(d.hour).padStart(2, '0')}:00
            </text>
          );
        })}
      </svg>

      {/* Tooltip */}
      {hover && tooltipFor && (
        <div style={{
          position: 'absolute',
          left: tipLeft, top: tipTop,
          minWidth: 158,
          padding: '10px 12px 12px',
          background: 'rgba(8,18,34,0.97)',
          border: '1px solid rgba(0,229,255,0.35)',
          borderRadius: 6,
          boxShadow: '0 8px 24px rgba(0,0,0,0.5), 0 0 0 1px rgba(0,229,255,0.08)',
          pointerEvents: 'none',
          fontFamily: TIMELINE_FONT_DISPLAY,
          color: 'var(--fg-1, #e8f4fd)',
          zIndex: 20,
        }}>
          <div style={{
            fontWeight: 600, fontSize: 13, marginBottom: 8,
            paddingBottom: 6, borderBottom: '1px solid rgba(0,229,255,0.18)',
          }}>
            Hour: {String(tooltipFor.hour).padStart(2, '0')}:00
          </div>
          {layers.slice().reverse().map(L => (
            <div key={L} style={{
              display: 'flex', alignItems: 'center', gap: 8,
              fontSize: 12.5, lineHeight: '20px',
              fontFamily: TIMELINE_FONT_MONO,
            }}>
              <span style={{
                width: 10, height: 10, borderRadius: 2,
                background: layerColor[L], flexShrink: 0,
              }} />
              <span style={{ color: layerColor[L], fontWeight: 500 }}>{layerLabel[L]}:</span>
              <span style={{ color: 'var(--fg-1, #e8f4fd)', marginLeft: 'auto' }}>
                {(tooltipFor[L] || 0).toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
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

    // Closed cases — non-blocking; use total not page-limited .length
    Promise.all([
      API.get('/api/cases?status=TruePositive&page_size=1'),
      API.get('/api/cases?status=FalsePositive&page_size=1'),
      API.get('/api/cases?status=Duplicate&page_size=1'),
    ]).then(([tp, fp, dup]) => {
      setClosedCases((tp?.total || 0) + (fp?.total || 0) + (dup?.total || 0));
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
    shortId: a.short_id || a.shortId || '',
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
                        <th>ALERT ID</th>
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
                          <td className="mono" style={{ fontSize: 10, color: 'var(--acc)', letterSpacing: '.04em', whiteSpace: 'nowrap' }}
                            title={`Full ID: ${a.id}`}>{a.shortId || '—'}</td>
                          <td className="mono dim">{relTime(a.time)}</td>
                          <td className="mono">{a.ruleId || '—'}</td>
                          <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
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

  const [copied, setCopied] = useState1(false);
  function copyAlertId() {
    if (!alert.shortId) return;
    navigator.clipboard.writeText(alert.shortId).then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <div className="detail">
      {/* Alert ID badge — primary reference for analysts */}
      {alert.shortId && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, padding: '6px 10px',
                      background: 'var(--acc-bg)', border: '1px solid rgba(0,229,255,.25)', borderRadius: 5 }}>
          <span style={{ fontSize: 9, color: 'var(--acc)', letterSpacing: '.1em', fontWeight: 700 }}>ALERT ID</span>
          <span className="mono" style={{ fontSize: 13, color: 'var(--acc)', fontWeight: 700, letterSpacing: '.06em', flex: 1 }}>{alert.shortId}</span>
          <button onClick={copyAlertId} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2,
                  color: copied ? 'var(--low)' : 'var(--fg-3)', fontSize: 11, fontFamily: 'var(--mono)' }}>
            {copied ? '✓ copied' : '⎘ copy'}
          </button>
        </div>
      )}
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
