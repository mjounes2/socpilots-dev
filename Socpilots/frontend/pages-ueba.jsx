// UEBA — Behavioral Intelligence Command Center
const {
  useState:   useUStateU,
  useEffect:  useUEffectU,
  useMemo:    useUMemoU,
  useCallback: useUCBU,
  useRef:     useURefU,
} = React;

// ── Anomaly metadata: severity, weight, label, MITRE mapping ────
const ANOMALY_META = {
  lateral_movement:      { label: 'Lateral Movement',     weight: 85, sev: 'high',     mitre: ['T1021'],          tactic: 'Lateral Movement'    },
  impossible_travel:     { label: 'Impossible Travel',    weight: 95, sev: 'critical', mitre: ['T1078.004'],      tactic: 'Initial Access'      },
  privilege_escalation:  { label: 'Privilege Escalation', weight: 80, sev: 'high',     mitre: ['T1068'],          tactic: 'Privilege Escalation'},
  after_hours_access:    { label: 'After-Hours Access',   weight: 55, sev: 'medium',   mitre: ['T1078'],          tactic: 'Defense Evasion'     },
  high_frequency_logins: { label: 'High-Freq Logins',     weight: 50, sev: 'medium',   mitre: ['T1110'],          tactic: 'Credential Access'   },
  rare_processes:        { label: 'Rare Processes',       weight: 70, sev: 'high',     mitre: ['T1059'],          tactic: 'Execution'           },
  new_connections:       { label: 'New Connections',      weight: 60, sev: 'medium',   mitre: ['T1071'],          tactic: 'Command and Control' },
  multi_stage_attacks:   { label: 'Multi-Stage Attacks',  weight: 90, sev: 'critical', mitre: ['T1486','T1021'],  tactic: 'Impact'              },
  shared_credentials:    { label: 'Shared Credentials',   weight: 65, sev: 'high',     mitre: ['T1078'],          tactic: 'Credential Access'   },
};
const ANOMALY_ORDER = [
  'multi_stage_attacks','impossible_travel','lateral_movement',
  'privilege_escalation','rare_processes','shared_credentials',
  'high_frequency_logins','after_hours_access','new_connections',
];

// ── Tiny SVG sparkline ──────────────────────────────────────────
function UebaSpark({ data = [], width = 110, height = 26, stroke = 'var(--acc)', fill = 'rgba(0,229,255,.1)' }) {
  if (!data.length) return <svg width={width} height={height}/>;
  const max = Math.max(1, ...data);
  const stepX = width / Math.max(1, data.length - 1);
  const pts = data.map((v, i) => [i * stepX, height - (v / max) * (height - 3) - 1.5]);
  const path = pts.map(([x, y], i) => (i === 0 ? `M${x},${y}` : `L${x},${y}`)).join(' ');
  const fillPath = `${path} L${width},${height} L0,${height} Z`;
  return (
    <svg width={width} height={height} style={{ display: 'block', overflow: 'visible' }}>
      <path d={fillPath} fill={fill} stroke="none"/>
      <path d={path} fill="none" stroke={stroke} strokeWidth="1.4" strokeLinejoin="round" strokeLinecap="round"/>
      {pts.length > 0 && (
        <circle cx={pts[pts.length-1][0]} cy={pts[pts.length-1][1]} r="2" fill={stroke}/>
      )}
    </svg>
  );
}

// ── KPI delta arrow ────────────────────────────────────────────
function Delta({ value }) {
  if (value == null || value === 0) return <span style={{ fontSize: 10, color: 'var(--fg-3)' }}>—</span>;
  const positive = value > 0;
  return (
    <span className="mono" style={{
      fontSize: 10, fontWeight: 600,
      color: positive ? 'var(--crit)' : 'var(--low)',
    }}>{positive ? '▲' : '▼'} {Math.abs(value)}</span>
  );
}

// ── ML Score Badge (compact) ───────────────────────────────────
function MlBadge({ score, size = 'sm' }) {
  if (score == null || score === 0) return null;
  const pct = Math.round(score);
  const tone = pct >= 80 ? 'crit' : pct >= 50 ? 'high' : 'med';
  const color = tone === 'crit' ? 'var(--crit)' : tone === 'high' ? 'var(--high)' : 'var(--med)';
  const w = size === 'sm' ? 44 : 64;
  return (
    <div title={`ML composite score: ${pct}`} style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '2px 7px', borderRadius: 4,
      background: 'rgba(180,80,200,.13)',
      border: `1px solid ${color}`,
    }}>
      <span className="mono" style={{ fontSize: 8.5, color: 'var(--fg-3)', fontWeight: 600, letterSpacing: 1 }}>ML</span>
      <span className="mono" style={{ fontSize: size === 'sm' ? 11 : 13, color, fontWeight: 600 }}>{pct}</span>
    </div>
  );
}

// ── Mini risk gauge (used in watchlist cards) ──────────────────
function RiskGauge({ risk }) {
  const pct = Math.min(100, Math.max(0, risk));
  const color = pct >= 70 ? 'var(--crit)' : pct >= 40 ? 'var(--high)' : pct >= 20 ? 'var(--med)' : 'var(--low)';
  const r = 26, c = 2 * Math.PI * r;
  return (
    <svg width="64" height="64" style={{ display: 'block' }}>
      <circle cx="32" cy="32" r={r} fill="none" stroke="var(--bg-3)" strokeWidth="4"/>
      <circle
        cx="32" cy="32" r={r} fill="none" stroke={color} strokeWidth="4"
        strokeDasharray={c} strokeDashoffset={c * (1 - pct/100)}
        strokeLinecap="round" transform="rotate(-90 32 32)"
        style={{ transition: 'stroke-dashoffset .5s' }}
      />
      <text x="32" y="36" textAnchor="middle" fontFamily="ui-monospace, monospace"
            fontWeight="600" fontSize="14" fill={color}>{pct}</text>
    </svg>
  );
}

// ── Critical Watchlist Card ────────────────────────────────────
function WatchlistCard({ entity, onProfile, onInvestigate, onDisable, investigating }) {
  const r = entity.risk_score ?? 0;
  const flags = entity.flag_breakdown || {};
  const topFlags = Object.entries(flags).sort((a, b) => b[1] - a[1]).slice(0, 3);
  const sev = r >= 70 ? 'critical' : r >= 40 ? 'high' : 'medium';
  const borderColor = r >= 70 ? 'var(--crit)' : r >= 40 ? 'var(--high)' : 'var(--med)';

  return (
    <div style={{
      background: 'linear-gradient(135deg, var(--bg-2) 0%, var(--bg-1) 100%)',
      border: `1px solid ${borderColor}`,
      borderRadius: 8, padding: 14,
      display: 'flex', flexDirection: 'column', gap: 10,
      boxShadow: r >= 70 ? '0 0 14px rgba(255,23,68,.18)' : 'none',
      position: 'relative', overflow: 'hidden',
    }}>
      {/* Severity ribbon */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 3,
        background: borderColor, opacity: 0.85,
      }}/>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 4 }}>
        <RiskGauge risk={r}/>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="mono" style={{
            fontSize: 13, color: 'var(--fg-0)', fontWeight: 600,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>{entity.entity}</div>
          <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: 1 }}>
            {entity.entity_type} · {entity.anomaly_count} anomalies
          </div>
          <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 3 }}>
            {entity.last_anomaly ? `last anomaly: ${entity.last_anomaly.slice(0,16).replace('T',' ')}` : 'no recent anomalies'}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 5 }}>
          <SevChip sev={sev}/>
          {entity.ml_score > 0 && <MlBadge score={entity.ml_score} size="sm"/>}
        </div>
      </div>

      {/* Flag chips */}
      {topFlags.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {topFlags.map(([flag, count]) => (
            <span key={flag} className="mono" style={{
              fontSize: 9.5, padding: '2px 7px',
              background: 'var(--bg-3)', border: '1px solid var(--ln)',
              borderRadius: 10, color: 'var(--fg-1)',
            }}>{flag.replace(/_/g, ' ')}·{count}</span>
          ))}
        </div>
      )}

      {/* Recent hosts */}
      {(entity.hosts || []).length > 0 && (
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          <span style={{ color: 'var(--fg-3)' }}>→ </span>
          {entity.hosts.slice(0, 3).join(' · ')}
          {entity.hosts.length > 3 && <span style={{ color: 'var(--fg-3)' }}> +{entity.hosts.length - 3}</span>}
        </div>
      )}

      {/* Action buttons */}
      <div style={{ display: 'flex', gap: 6, marginTop: 'auto' }}>
        <button className="btn btn-ghost btn-sm" style={{ flex: 1, fontSize: 11 }} onClick={() => onProfile(entity.entity)}>
          Profile
        </button>
        <button className="btn btn-primary btn-sm" style={{ flex: 1, fontSize: 11 }} onClick={() => onInvestigate(entity)}
                disabled={investigating}>
          {investigating ? <><Spinner size={10}/> …</> : 'Investigate'}
        </button>
        {onDisable && (
          <button className="btn btn-danger btn-sm" style={{ fontSize: 11, padding: '4px 8px' }}
                  onClick={() => onDisable(entity)}
                  title="Queue account disable for approval">
            Disable
          </button>
        )}
      </div>
    </div>
  );
}

// ── MITRE Behavior Heatmap Strip ──────────────────────────────
function MITREStrip({ anomalyCounts, active, onToggle }) {
  // Aggregate counts by technique
  const techCounts = useUMemoU(() => {
    const acc = {};
    for (const [kind, meta] of Object.entries(ANOMALY_META)) {
      const count = anomalyCounts[kind] || 0;
      for (const tech of meta.mitre) {
        acc[tech] = (acc[tech] || 0) + count;
      }
    }
    return acc;
  }, [anomalyCounts]);

  const sortedTechs = Object.entries(techCounts)
    .filter(([, count]) => count > 0)
    .sort((a, b) => b[1] - a[1]);

  if (sortedTechs.length === 0) {
    return (
      <Card title="MITRE ATT&CK Behavior Mapping" sub="UEBA anomalies → ATT&CK techniques">
        <div className="empty mono">No anomalies detected in this window</div>
      </Card>
    );
  }

  return (
    <Card title="MITRE ATT&CK Behavior Mapping" sub={`${sortedTechs.length} techniques evidenced by UEBA anomalies`}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {sortedTechs.map(([tech, count]) => {
          // Find which anomaly kinds map to this technique
          const kinds = Object.entries(ANOMALY_META).filter(([, m]) => m.mitre.includes(tech));
          const maxSev = kinds.reduce((m, [, k]) => {
            const sevRank = { critical:4, high:3, medium:2, low:1 };
            return Math.max(m, sevRank[k.sev] || 0);
          }, 0);
          const bg = maxSev >= 4 ? 'rgba(255,23,68,.16)'
                    : maxSev >= 3 ? 'rgba(255,140,0,.16)'
                    : 'rgba(255,193,7,.13)';
          const fg = maxSev >= 4 ? 'var(--crit)'
                    : maxSev >= 3 ? 'var(--high)'
                    : 'var(--med)';
          const isActive = active === tech;
          return (
            <button key={tech} onClick={() => onToggle && onToggle(tech)}
              className="mono"
              style={{
                padding: '6px 10px',
                background: isActive ? fg : bg,
                color: isActive ? '#0a1628' : fg,
                border: `1px solid ${isActive ? fg : 'var(--ln)'}`,
                borderRadius: 4, fontSize: 11, cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 6,
              }}>
              <span style={{ fontWeight: 600 }}>{tech}</span>
              <span style={{ opacity: .85 }}>·</span>
              <span>{kinds[0]?.[1].tactic || ''}</span>
              <span style={{
                background: isActive ? 'rgba(0,0,0,.2)' : 'var(--bg-2)',
                padding: '1px 6px', borderRadius: 8, fontWeight: 600,
              }}>{count}</span>
            </button>
          );
        })}
      </div>
    </Card>
  );
}

// ── Compact anomaly tile (used in 3x3 grid) ────────────────────
function AnomalyTile({ kind, items, isExpanded, onToggle, onItemClick }) {
  const meta = ANOMALY_META[kind];
  if (!meta) return null;
  const count = items?.length || 0;
  const sevColor = meta.sev === 'critical' ? 'var(--crit)' : meta.sev === 'high' ? 'var(--high)' : 'var(--med)';

  const top = (items || []).slice(0, 5);

  return (
    <div style={{
      background: 'var(--bg-2)',
      border: `1px solid ${count > 0 ? sevColor : 'var(--ln)'}`,
      borderLeftWidth: 3,
      borderRadius: 6,
      padding: 11,
      display: 'flex', flexDirection: 'column', gap: 8,
      opacity: count === 0 ? 0.55 : 1,
      transition: 'opacity .2s',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div className="mono" style={{ fontSize: 12, color: 'var(--fg-0)', fontWeight: 600 }}>{meta.label}</div>
          <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-3)', marginTop: 1 }}>
            {meta.mitre.join(' · ')} · weight {meta.weight}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="mono" style={{ fontSize: 18, fontWeight: 600, color: sevColor }}>{count}</span>
          {count > 0 && (
            <button className="btn btn-ghost btn-sm" style={{ fontSize: 9, padding: '2px 6px' }}
                    onClick={() => onToggle(kind)}>
              {isExpanded ? '▲' : '▼'}
            </button>
          )}
        </div>
      </div>

      {/* Top entity preview when collapsed */}
      {!isExpanded && top[0] && (
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          <span style={{ color: 'var(--fg-3)' }}>top: </span>
          {top[0].user || top[0].entity || top[0].process || '—'}
          {top[0].host && <span style={{ color: 'var(--fg-3)' }}> @ {top[0].host}</span>}
        </div>
      )}

      {/* Expanded event list */}
      {isExpanded && top.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 200, overflowY: 'auto' }}>
          {top.map((item, i) => {
            const entity = item.user || item.entity || item.process || '—';
            const detail = item.host
              ? `→ ${item.host}`
              : item.src_hosts
                ? `${(item.src_hosts || []).slice(0,2).join(',')} → ${(item.dst_hosts || []).slice(0,2).join(',')}`
                : item.ip1
                  ? `${item.ip1} → ${item.ip2}`
                  : item.hosts
                    ? (item.hosts || []).slice(0,3).join(',')
                    : '';
            return (
              <div key={i}
                onClick={() => onItemClick && onItemClick(entity)}
                style={{
                  padding: '5px 8px', background: 'var(--bg-1)', borderRadius: 4,
                  border: '1px solid var(--ln)', cursor: 'pointer',
                  display: 'flex', justifyContent: 'space-between', gap: 8,
                  alignItems: 'center', fontSize: 10.5,
                }}>
                <span className="mono" style={{ color: 'var(--acc)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {entity}
                </span>
                <span className="mono" style={{ color: 'var(--fg-2)', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                  {detail}
                </span>
                {item.deviation != null && (
                  <span className="mono" style={{
                    fontSize: 9, padding: '1px 5px', borderRadius: 8,
                    background: 'var(--bg-3)', color: sevColor, flexShrink: 0,
                  }}>{item.deviation}</span>
                )}
              </div>
            );
          })}
          {(items.length > 5) && (
            <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-3)', textAlign: 'center', padding: 2 }}>
              +{items.length - 5} more
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Entity Deep Dive Modal ────────────────────────────────────
function EntityModal({ entity, onClose, onInvestigate, onAction, investigating }) {
  const API = window.SOC_API;
  const [tab, setTab] = useUStateU('overview');
  const [profile, setProfile] = useUStateU(null);
  const [baseline, setBaseline] = useUStateU(null);
  const [timeline, setTimeline] = useUStateU([]);
  const [graph, setGraph] = useUStateU(null);
  const [mlData, setMlData] = useUStateU(null);
  const [mlPeers, setMlPeers] = useUStateU(null);
  const [loadingProfile, setLP] = useUStateU(true);

  useUEffectU(() => {
    if (!entity) return;
    let cancelled = false;
    setLP(true);
    Promise.all([
      API.get(`/api/ueba/profile/${encodeURIComponent(entity)}`),
      API.get(`/api/ueba/baseline/${encodeURIComponent(entity)}`),
      API.get(`/api/ueba/entity/${encodeURIComponent(entity)}/timeline?hours=24`),
      API.get(`/api/ueba/graph-nodes/${encodeURIComponent(entity)}`),
      API.get(`/api/ueba/ml/explain/${encodeURIComponent(entity)}`).catch(() => null),
      API.get(`/api/ueba/ml/peers/${encodeURIComponent(entity)}`).catch(() => null),
    ]).then(([prof, base, tl, g, ml, peers]) => {
      if (cancelled) return;
      setProfile(prof && !prof.error ? (prof.profile || prof) : null);
      setBaseline(base && !base.error ? base : null);
      setTimeline(tl && !tl.error ? (tl.buckets || []).map(b => b.count) : []);
      setGraph(g && !g.error ? g : null);
      setMlData(ml && !ml.error ? ml : null);
      setMlPeers(peers && !peers.error ? peers : null);
      setLP(false);
    });
    return () => { cancelled = true; };
  }, [entity]);

  if (!entity) return null;

  const r = profile?.risk_score ?? 0;
  const sevColor = r >= 70 ? 'var(--crit)' : r >= 40 ? 'var(--high)' : r >= 20 ? 'var(--med)' : 'var(--low)';

  return (
    <div onClick={onClose} style={{
      position: 'fixed', inset: 0, background: 'rgba(5,10,20,.78)',
      zIndex: 1000, display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
      padding: '40px 20px', backdropFilter: 'blur(4px)',
    }}>
      <div onClick={e => e.stopPropagation()} style={{
        background: 'var(--bg-1)', border: '1px solid var(--ln)', borderRadius: 8,
        maxWidth: 900, width: '100%', maxHeight: 'calc(100vh - 80px)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
        boxShadow: '0 24px 48px rgba(0,0,0,.6)',
      }}>
        {/* Header */}
        <div style={{
          padding: '14px 20px', background: 'var(--bg-2)',
          borderBottom: '1px solid var(--ln)',
          display: 'flex', alignItems: 'center', gap: 14,
        }}>
          <RiskGauge risk={r}/>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <div className="mono" style={{ fontSize: 18, color: 'var(--fg-0)', fontWeight: 600 }}>{entity}</div>
              <Chip mono tone={profile?.entity_type === 'host' ? 'warn' : 'default'}>
                {profile?.entity_type || 'entity'}
              </Chip>
              {r >= 70 && <SevChip sev="critical"/>}
              {mlData?.ml_score > 0 && <MlBadge score={mlData.ml_score}/>}
            </div>
            <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', marginTop: 2 }}>
              {profile?.anomaly_count ?? 0} anomalies · {profile?.total_events ?? 0} events · last seen {profile?.last_seen ? profile.last_seen.slice(0,16).replace('T',' ') : '—'}
            </div>
          </div>
          <button className="btn btn-ghost" onClick={onClose}>✕</button>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 0, padding: '0 20px', borderBottom: '1px solid var(--ln)', background: 'var(--bg-2)' }}>
          {['overview', 'anomalies', 'ml', 'connections', 'actions'].map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              background: 'transparent', border: 'none',
              borderBottom: tab === t ? '2px solid var(--acc)' : '2px solid transparent',
              padding: '10px 14px', cursor: 'pointer',
              color: tab === t ? 'var(--acc)' : 'var(--fg-2)',
              fontFamily: 'var(--mono)', fontSize: 12, textTransform: 'uppercase', letterSpacing: 1,
            }}>{t}</button>
          ))}
        </div>

        {/* Body */}
        <div style={{ padding: 20, overflowY: 'auto', flex: 1 }}>
          {loadingProfile ? (
            <div className="loading"><Spinner size={20}/> Loading profile…</div>
          ) : tab === 'overview' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {/* Risk timeline sparkline */}
              <div style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 6, padding: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: 1 }}>
                    24h Anomaly Activity
                  </div>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>
                    {timeline.reduce((a, b) => a + b, 0)} total · peak {Math.max(0, ...timeline)}
                  </div>
                </div>
                <UebaSpark data={timeline} width={840} height={40} stroke={sevColor} fill="rgba(255,140,0,.13)"/>
              </div>

              {/* KPI grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
                {[
                  ['Risk Score',    r,                                  sevColor],
                  ['Anomalies',     profile?.anomaly_count ?? 0,        r >= 40 ? 'var(--high)' : 'var(--fg-1)'],
                  ['Total Events',  profile?.total_events ?? 0,         'var(--fg-1)'],
                  ['Hosts',         (profile?.all_hosts || []).length,  'var(--fg-1)'],
                ].map(([k, v, c], i) => (
                  <div key={i} style={{
                    background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 6, padding: 10,
                  }}>
                    <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: 1 }}>{k}</div>
                    <div className="mono" style={{ fontSize: 20, fontWeight: 600, color: c, marginTop: 4 }}>{v}</div>
                  </div>
                ))}
              </div>

              {/* Baseline vs current */}
              {baseline?.has_baseline ? (
                <div style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 6, padding: 14 }}>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
                    Behavioral Baseline (30 days)
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    <div>
                      <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>typical hosts</div>
                      <div className="mono" style={{ fontSize: 11, color: 'var(--fg-1)', marginTop: 4 }}>
                        {(baseline.typical_hosts || []).length > 0
                          ? baseline.typical_hosts.slice(0, 6).join(' · ')
                          : '—'}
                      </div>
                    </div>
                    <div>
                      <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>typical hours</div>
                      <div className="mono" style={{ fontSize: 11, color: 'var(--fg-1)', marginTop: 4 }}>
                        {(baseline.typical_hours || []).slice(0, 6).map(h => h.hour + 'h').join(' · ') || '—'}
                      </div>
                    </div>
                  </div>
                  {baseline.fp_assessment?.assessable && (
                    <div className="mono" style={{ fontSize: 10.5, color: 'var(--fg-2)', marginTop: 10, padding: 8, background: 'var(--bg-1)', borderRadius: 4 }}>
                      FP assessment: <span style={{ color: baseline.fp_assessment.within_baseline ? 'var(--low)' : 'var(--high)' }}>
                        {baseline.fp_assessment.fp_score}% within baseline
                      </span> ({baseline.fp_assessment.events_assessed} events)
                    </div>
                  )}
                </div>
              ) : (
                <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', padding: 12, background: 'var(--bg-2)', borderRadius: 6 }}>
                  No 30-day baseline yet — needs more historical events
                </div>
              )}
            </div>
          ) : tab === 'anomalies' ? (
            <div>
              {(profile?.recent_logins || []).length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {profile.recent_logins.slice(0, 30).map((l, i) => (
                    <div key={i} style={{
                      padding: '7px 10px', background: 'var(--bg-2)', border: '1px solid var(--ln)',
                      borderRadius: 4, display: 'grid', gridTemplateColumns: '1fr 1fr auto auto', gap: 10,
                      alignItems: 'center', fontSize: 11,
                    }}>
                      <span className="mono" style={{ color: 'var(--fg-1)' }}>{l.host || '—'}</span>
                      <span className="mono" style={{ color: 'var(--fg-3)', fontSize: 10 }}>
                        {l.src_ip || ''}{l.flags?.length ? ` · ${l.flags.join(',')}` : ''}
                      </span>
                      <span className="mono" style={{ color: 'var(--fg-3)', fontSize: 10 }}>
                        {l.time ? l.time.slice(0, 16).replace('T', ' ') : ''}
                      </span>
                      {l.deviation > 0 && (
                        <span className="mono" style={{
                          fontSize: 10, padding: '2px 7px', borderRadius: 10,
                          background: l.deviation >= 70 ? 'rgba(255,23,68,.16)' : l.deviation >= 40 ? 'rgba(255,140,0,.16)' : 'var(--bg-3)',
                          color: l.deviation >= 70 ? 'var(--crit)' : l.deviation >= 40 ? 'var(--high)' : 'var(--fg-2)',
                        }}>dev:{l.deviation}</span>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty mono">No recent anomalous events recorded</div>
              )}
            </div>
          ) : tab === 'ml' ? (
            !mlData ? (
              <div className="empty mono" style={{ padding: 14 }}>
                No ML score yet for this entity. Re-run scoring from the ML Insights card.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {/* Composite score breakdown */}
                <div style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 6, padding: 14 }}>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                    Composite ML Score Breakdown
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 12 }}>
                    <div className="mono" style={{ fontSize: 36, fontWeight: 700, color: mlData.ml_score >= 80 ? 'var(--crit)' : mlData.ml_score >= 50 ? 'var(--high)' : 'var(--med)' }}>
                      {Math.round(mlData.ml_score)}
                    </div>
                    <div style={{ flex: 1, fontSize: 12, color: 'var(--fg-1)', lineHeight: 1.5 }}>
                      {mlData.interpretation}
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
                    {[
                      ['Isolation Forest', mlData.components?.isolation_forest, 'global outlier'],
                      ['Z-Score',          mlData.components?.z_score,          'vs own baseline'],
                      ['Peer Distance',    mlData.components?.peer_distance,    'vs cluster'],
                    ].map(([label, value, hint], i) => (
                      <div key={i} style={{ background: 'var(--bg-1)', border: '1px solid var(--ln)', borderRadius: 4, padding: 10 }}>
                        <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-3)', letterSpacing: 1, textTransform: 'uppercase' }}>{label}</div>
                        <div className="mono" style={{ fontSize: 22, fontWeight: 600, color: 'var(--fg-0)', margin: '4px 0' }}>{Math.round(value || 0)}</div>
                        <div className="mono" style={{ fontSize: 9, color: 'var(--fg-3)' }}>{hint}</div>
                        <div style={{ marginTop: 6, height: 3, background: 'var(--bg-3)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: (value || 0) + '%', height: 3, background: (value || 0) >= 70 ? 'var(--crit)' : 'var(--acc)' }}/>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Top contributing features (bar chart) */}
                <div style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 6, padding: 14 }}>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                    Top Contributing Features
                  </div>
                  {(mlData.top_features || []).length === 0 ? (
                    <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>No features exceeded the z-score threshold</div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {mlData.top_features.map((f, i) => {
                        const maxZ = Math.max(...mlData.top_features.map(x => x.z), 5);
                        const pct = (f.z / maxZ) * 100;
                        return (
                          <div key={i}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                              <span className="mono" style={{ fontSize: 11, color: 'var(--fg-0)' }}>
                                {f.feature.replace(/_/g, ' ')}
                              </span>
                              <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
                                value <span style={{ color: 'var(--fg-0)' }}>{f.value}</span> · z-score <span style={{ color: f.z >= 3 ? 'var(--crit)' : 'var(--high)', fontWeight: 600 }}>{f.z}</span>
                              </span>
                            </div>
                            <div style={{ height: 5, background: 'var(--bg-1)', borderRadius: 3, overflow: 'hidden' }}>
                              <div style={{
                                width: pct + '%', height: 5,
                                background: f.z >= 3 ? 'var(--crit)' : f.z >= 2 ? 'var(--high)' : 'var(--acc)',
                                transition: 'width .4s',
                              }}/>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Peer group */}
                <div style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 6, padding: 14 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: 1 }}>
                      Peer Group (DBSCAN cluster {mlData.peer_group})
                    </div>
                    <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>
                      {mlData.peer_group === -1 ? 'noise — no peer cluster' : `${mlPeers?.peer_count || 0} peers`}
                    </span>
                  </div>
                  {mlPeers && mlPeers.peers && mlPeers.peers.length > 0 ? (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                      {mlPeers.peers.slice(0, 12).map(p => (
                        <span key={p.name} onClick={() => { setTab('overview'); onClose(); setTimeout(() => window.location.hash = '#peer-' + p.name, 50); }}
                              title={`ML score ${p.ml_score}`}
                              className="mono" style={{
                                fontSize: 10.5, padding: '3px 8px',
                                background: 'var(--bg-1)', border: '1px solid var(--ln)',
                                borderRadius: 4, color: 'var(--acc)', cursor: 'pointer',
                              }}>
                          {p.name} <span style={{ color: 'var(--fg-3)' }}>·{Math.round(p.ml_score)}</span>
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
                      {mlData.peer_group === -1
                        ? "This entity's behavior doesn't match any peer cluster — strong outlier signal."
                        : 'No peers found.'}
                    </div>
                  )}
                </div>
              </div>
            )
          ) : tab === 'connections' ? (
            graph && graph.nodes?.length > 0 ? (
              <UEBAForceGraph data={graph} height={420} selectedId={entity}/>
            ) : (
              <div className="empty mono">No graph connections for this entity</div>
            )
          ) : (
            // Actions tab
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
                Autonomous response actions wired to the Dark SOC engine. Destructive actions queue for human approval.
              </div>
              <button className="btn btn-primary" disabled={investigating}
                      onClick={() => onInvestigate({ entity: entity, entity_type: profile?.entity_type, risk_score: r })}>
                <Icon.brain width="14" height="14"/>
                {investigating ? ' Investigating…' : ' Run Autonomous Investigation'}
              </button>
              <button className="btn btn-danger"
                      onClick={() => onAction('disable_user', entity)}
                      disabled={profile?.entity_type !== 'user'}>
                Disable User Account (→ approval queue)
              </button>
              <button className="btn btn-danger"
                      onClick={() => onAction('isolate_host', entity)}
                      disabled={profile?.entity_type !== 'host'}>
                Isolate Host (→ approval queue)
              </button>
              <button className="btn btn-ghost"
                      onClick={() => window.open(`/?p=copilot&q=${encodeURIComponent('Investigate entity ' + entity)}`, '_blank')}>
                Open AI Copilot Chat
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── ML Insights Card ────────────────────────────────────────
// Surfaces "unknown unknowns" — entities flagged by ML that the rule
// engine missed (or scored low). These are the highest-value finds.
function MlInsightsCard({ topMl, mlStats, onProfile, onRecalc, recalcing }) {
  // Sort: surface entities with high ML but low rule-based — the genuine novel finds
  const novel = [...(topMl || [])]
    .filter(e => e.ml_score >= 60)
    .sort((a, b) => (b.ml_score - (b.risk_score || 0) * 0.5) - (a.ml_score - (a.risk_score || 0) * 0.5));

  const lastRun = mlStats?.at ? new Date(mlStats.at) : null;
  const ageMin = lastRun ? Math.round((Date.now() - lastRun.getTime()) / 60_000) : null;
  const offline = !mlStats || mlStats.errors?.length > 0;

  return (
    <Card
      title="ML Anomaly Insights"
      sub={lastRun
        ? `${mlStats.users_scored || 0} entities scored · ${ageMin}min ago · IsolationForest + z-score + DBSCAN`
        : 'ML pipeline not yet run'}
      actions={<>
        <Chip mono tone={offline ? 'crit' : 'ok'}>
          {offline ? 'offline' : `${mlStats.high_anomaly_count || 0} high`}
        </Chip>
        <button className="btn btn-ghost btn-sm" onClick={onRecalc} disabled={recalcing}>
          <Icon.refresh width="12" height="12"/>
          {recalcing ? ' Scoring…' : ' Re-score'}
        </button>
      </>}
    >
      {novel.length === 0 ? (
        <div className="empty mono" style={{ padding: 12 }}>
          {offline
            ? 'ueba-ml service unreachable — check docker compose ps ueba-ml'
            : 'No high-ML anomalies in this window. ML acts as a second-opinion signal.'}
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 10 }}>
          {novel.slice(0, 6).map(e => {
            const isNovel = (e.ml_score || 0) - (e.risk_score || 0) >= 30;
            return (
              <div key={e.entity || e.name}
                onClick={() => onProfile(e.entity || e.name)}
                style={{
                  background: 'var(--bg-2)', border: '1px solid var(--ln)',
                  borderLeft: '3px solid ' + (isNovel ? 'var(--acc)' : 'var(--high)'),
                  borderRadius: 5, padding: 11, cursor: 'pointer',
                  display: 'flex', flexDirection: 'column', gap: 6,
                }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <span className="mono" style={{ fontSize: 12, color: 'var(--fg-0)', fontWeight: 600,
                                                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                    {e.entity || e.name}
                  </span>
                  <MlBadge score={e.ml_score}/>
                </div>
                <div style={{ display: 'flex', gap: 8, fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--fg-3)' }}>
                  <span>rule: <span style={{ color: (e.risk_score || 0) >= 60 ? 'var(--high)' : 'var(--fg-2)' }}>{e.risk_score || 0}</span></span>
                  <span>iF:{Math.round(e.ml_iforest_score || 0)}</span>
                  <span>z:{Math.round(e.ml_zscore || 0)}</span>
                  <span>peer:{Math.round(e.ml_peer_distance || 0)}</span>
                </div>
                {isNovel && (
                  <div className="mono" style={{
                    fontSize: 9, color: 'var(--acc)', padding: '2px 6px',
                    background: 'rgba(0,229,255,.1)', borderRadius: 8,
                    border: '1px solid var(--acc)', display: 'inline-block', width: 'fit-content',
                  }}>
                    💡 ML-only finding (rules missed this)
                  </div>
                )}
                {(e.ml_top_features || []).length > 0 && (
                  <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-2)' }}>
                    top: {(e.ml_top_features || []).slice(0, 2).map(f => `${f.feature.replace(/_/g, ' ')}·z${f.z}`).join(' · ')}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}

// ── MAIN PAGE ─────────────────────────────────────────────────
function PageUEBA() {
  const API  = window.SOC_API;

  const [tf,          setTf]          = useUStateU('24h');
  const [refreshKey,  setRefreshKey]  = useUStateU(0);
  const [loading,     setLoading]     = useUStateU(false);

  const [stats,       setStats]       = useUStateU(null);
  const [watchlist,   setWatchlist]   = useUStateU([]);
  const [anomalies,   setAnomalies]   = useUStateU({});
  const [anomalyCounts, setAnomalyCounts] = useUStateU({});
  const [topMl,       setTopMl]       = useUStateU([]);
  const [mlStats,     setMlStats]     = useUStateU(null);
  const [mlRecalcing, setMlRecalcing] = useUStateU(false);

  const [graphData,   setGraphData]   = useUStateU(null);
  const [graphLoading, setGraphLoading] = useUStateU(false);

  // Anomaly expansion state — which tile is open
  const [expandedKind, setExpandedKind] = useUStateU(null);
  const [mitreFilter,  setMitreFilter]  = useUStateU(null);

  // Entity lookup
  const [entityInput,   setEntityInput]   = useUStateU('');
  const [pathFrom,    setPathFrom]    = useUStateU('');
  const [pathTo,      setPathTo]      = useUStateU('');
  const [pathResult,  setPathResult]  = useUStateU(null);
  const [pathLoading, setPathLoading] = useUStateU(false);

  // Modal
  const [modalEntity, setModalEntity] = useUStateU(null);
  const [investigatingId, setInvestigatingId] = useUStateU(null);

  // AI digest
  const [digest,        setDigest]        = useUStateU(null);
  const [digestLoading, setDigestLoading] = useUStateU(false);

  const hours = tf === '7d' ? 168 : tf === '30d' ? 720 : 24;

  // ── Initial fetch ───────────────────────────────────────────
  useUEffectU(() => {
    let cancelled = false;
    setLoading(true);

    async function fetchAll() {
      try {
        const [overview, anomRes, topMlRes, mlStatsRes] = await Promise.all([
          API.get(`/api/ueba/overview?hours=${hours}`),
          API.get(`/api/ueba/anomalies?hours=${hours}`),
          API.get(`/api/ueba/ml/top-anomalies?min_score=50&limit=20`).catch(() => null),
          API.get(`/api/ueba/ml/stats`).catch(() => null),
        ]);
        if (cancelled) return;

        if (overview && !overview.error) {
          setStats(overview.stats || null);
          setWatchlist(overview.watchlist || []);
          setAnomalyCounts(overview.anomaly_counts || {});
        }
        if (anomRes && !anomRes.error) setAnomalies(anomRes);
        if (topMlRes && !topMlRes.error) setTopMl(topMlRes.items || []);
        if (mlStatsRes && !mlStatsRes.error) setMlStats(mlStatsRes);
      } catch {/* leave existing */}
      finally { if (!cancelled) setLoading(false); }
    }

    fetchAll();
    API.get('/api/ueba/digest/latest').then(r => {
      if (!cancelled && r && !r.error && r.text) setDigest(r.text);
    }).catch(() => {});

    return () => { cancelled = true; };
  }, [tf, refreshKey]);

  // ── Auto-load graph for top-risk entity ─────────────────────
  useUEffectU(() => {
    const top = watchlist[0];
    if (!top || graphData) return;
    let cancelled = false;
    setGraphLoading(true);
    API.get(`/api/ueba/graph-nodes/${encodeURIComponent(top.entity)}`).then(r => {
      if (cancelled) return;
      setGraphData(r && !r.error && r.nodes?.length ? r : null);
      setGraphLoading(false);
    });
    return () => { cancelled = true; };
  }, [watchlist]);

  // ── Action handlers ─────────────────────────────────────────
  const openEntity = useUCBU(name => { setModalEntity(name); }, []);

  const investigate = useUCBU(async (entityObj) => {
    const name = typeof entityObj === 'string' ? entityObj : entityObj.entity;
    setInvestigatingId(name);
    try {
      const alert = {
        ruleId:      'UEBA-MANUAL',
        rule_id:     'UEBA-MANUAL',
        level:       Math.min(15, Math.round((entityObj.risk_score || 50) / 7)),
        description: `UEBA-triggered investigation for ${name} (risk ${entityObj.risk_score || 0})`,
        agent:       name,
        timestamp:   new Date().toISOString(),
        source:      'ueba',
        full_log:    `Entity ${name} flagged by UEBA. Type: ${entityObj.entity_type || 'unknown'}. Recent anomalies tracked in graph.`,
      };
      const r = await API.post('/api/autonomous/investigate', { alert, force: false });
      if (r && r.investigation_id) {
        window.socToast?.({ title: `Investigation #${r.investigation_id} queued`, sub: name, tone: 'ok' });
      } else if (r && r.engine_enabled === false) {
        window.socToast?.({ title: 'Autonomous engine disabled', sub: 'Enable it from the AI Investigation page', tone: 'crit' });
      } else if (r && r.error) {
        window.socToast?.({ title: 'Investigation failed', sub: r.error, tone: 'crit' });
      }
    } catch (e) {
      window.socToast?.({ title: 'Investigation error', sub: e.message, tone: 'crit' });
    } finally {
      setInvestigatingId(null);
    }
  }, []);

  const queueAction = useUCBU(async (actionType, target) => {
    try {
      const summary = `UEBA: AI recommends ${actionType} on ${target}`;
      const r = await API.post('/api/autonomous/approval/create', {
        action_type: actionType, target, reason: 'UEBA high-risk entity',
        confidence: 0.75, fp_probability: 25, summary,
        alert: { agent: target, source: 'ueba_manual' },
      });
      if (r && r.approval_id) {
        window.socToast?.({ title: `Approval #${r.approval_id} queued`, sub: `${actionType} on ${target} — awaiting human review`, tone: 'info' });
      } else {
        window.socToast?.({ title: 'Approval queue failed', sub: r?.error || 'unknown', tone: 'crit' });
      }
    } catch (e) {
      window.socToast?.({ title: 'Action error', sub: e.message, tone: 'crit' });
    }
  }, []);

  const findPath = useUCBU(async () => {
    if (!pathFrom.trim() || !pathTo.trim()) return;
    setPathLoading(true);
    setPathResult(null);
    const r = await API.get(`/api/ueba/path?from=${encodeURIComponent(pathFrom.trim())}&to=${encodeURIComponent(pathTo.trim())}`);
    setPathResult(r && !r.error ? r : { error: r?.error || 'No path found' });
    setPathLoading(false);
  }, [pathFrom, pathTo]);

  const generateDigest = useUCBU(async () => {
    setDigestLoading(true);
    const r = await API.post('/api/ueba/digest/generate', { timeframe: tf });
    if (r && !r.error) {
      setTimeout(async () => {
        const d = await API.get('/api/ueba/digest/latest');
        if (d && !d.error && d.text) setDigest(d.text);
        setDigestLoading(false);
      }, 3000);
    } else {
      setDigestLoading(false);
    }
  }, [tf]);

  const recalcRisk = useUCBU(async () => {
    if (!confirm('Recompute risk scores for all entities? This may take a minute.')) return;
    const r = await API.post('/api/ueba/recalc', {});
    if (r && r.ok) {
      window.socToast?.({ title: 'Risk recalculated', sub: `${r.updated || 0} entities updated`, tone: 'ok' });
      setRefreshKey(k => k + 1);
    }
  }, []);

  const recalcMl = useUCBU(async () => {
    setMlRecalcing(true);
    const r = await API.post('/api/ueba/ml/recalc', {});
    setMlRecalcing(false);
    if (r && r.ok) {
      window.socToast?.({ title: 'ML scoring complete', sub: `${r.users_scored || 0} entities scored in ${r.duration_sec || 0}s`, tone: 'ok' });
      setRefreshKey(k => k + 1);
    } else {
      window.socToast?.({ title: 'ML re-score failed', sub: r?.error || 'service unavailable', tone: 'crit' });
    }
  }, []);

  const loadGraphFor = useUCBU(async (entityName) => {
    setGraphLoading(true);
    const r = await API.get(`/api/ueba/graph-nodes/${encodeURIComponent(entityName)}`);
    setGraphData(r && !r.error && r.nodes?.length ? r : null);
    setGraphLoading(false);
  }, []);

  // ── Stats values ────────────────────────────────────────────
  const s = stats || {};
  const users     = s.users     ?? 0;
  const hosts     = s.hosts     ?? 0;
  const processes = s.processes ?? 0;
  const edges     = s.relationships ?? s.edges ?? 0;
  const avgRisk   = s.avg_risk  ?? s.avgRisk  ?? 0;
  const highRisk  = s.high_risk_users ?? s.highRisk ?? 0;

  // Filter anomalies by MITRE if active
  const visibleAnomalies = useUMemoU(() => {
    if (!mitreFilter) return anomalies;
    const out = {};
    for (const [kind, meta] of Object.entries(ANOMALY_META)) {
      if (meta.mitre.includes(mitreFilter)) out[kind] = anomalies[kind] || [];
    }
    return out;
  }, [anomalies, mitreFilter]);

  return (
    <div className="page" data-screen-label="UEBA">
      <Topbar
        title="UEBA"
        sub="Behavioral Intelligence · Neo4j graph"
        actions={<>
          {['24h', '7d', '30d'].map(t => (
            <button key={t} className={tf === t ? 'btn btn-primary' : 'btn btn-ghost'} onClick={() => setTf(t)}>{t}</button>
          ))}
          <button className="btn btn-ghost" onClick={recalcRisk} title="Recompute all risk scores">
            <Icon.refresh width="13" height="13"/> Recalc
          </button>
          <button className="btn btn-ghost" onClick={() => setRefreshKey(k => k + 1)} disabled={loading}>
            <Icon.refresh width="13" height="13"/> {loading ? 'Loading…' : 'Refresh'}
          </button>
        </>}
      />

      <div className="page-body">

        {/* ── KPI Strip ───────────────────────────────── */}
        <div className="kpi-grid">
          <div className="kpi">
            <div className="kpi-label">Users Tracked</div>
            <div className="kpi-value">{users.toLocaleString()}</div>
            <div className="kpi-foot"><span className="kpi-sub">in graph</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Hosts</div>
            <div className="kpi-value">{hosts.toLocaleString()}</div>
            <div className="kpi-foot"><span className="kpi-sub">monitored</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Processes</div>
            <div className="kpi-value">{processes.toLocaleString()}</div>
            <div className="kpi-foot"><span className="kpi-sub">unique observed</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Graph Edges</div>
            <div className="kpi-value">{edges.toLocaleString()}</div>
            <div className="kpi-foot"><span className="kpi-sub">relationships</span></div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Avg Risk</div>
            <div className="kpi-value">{avgRisk}</div>
            <div className="kpi-foot"><span className="kpi-sub">across entities</span></div>
          </div>
          <div className="kpi" data-sev={highRisk > 0 ? 'critical' : undefined}>
            <div className="kpi-label">High Risk (≥70)</div>
            <div className="kpi-value mono" style={{ color: highRisk > 0 ? 'var(--crit)' : undefined }}>{highRisk}</div>
            <div className="kpi-foot"><span className="kpi-sub">need review</span></div>
          </div>
        </div>

        {/* ── Critical Watchlist (HERO) ───────────────── */}
        <Card
          title="Critical Watchlist"
          sub={`top ${watchlist.length} highest-risk entities · ${tf}`}
          actions={<Chip mono tone={watchlist.length > 0 ? 'crit' : 'default'}>
            {watchlist.length > 0 ? '🔥 action needed' : 'all clear'}
          </Chip>}
        >
          {loading && watchlist.length === 0 ? (
            <div className="loading"><Spinner size={22}/> Scanning entities…</div>
          ) : watchlist.length === 0 ? (
            <div className="empty mono" style={{ padding: 20 }}>
              No high-risk entities (≥40) in this window. Run "Recalc" if you've recently ingested data.
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
              {watchlist.map(e => (
                <WatchlistCard
                  key={e.entity}
                  entity={e}
                  onProfile={openEntity}
                  onInvestigate={investigate}
                  onDisable={e.entity_type === 'user' ? (ent => queueAction('disable_user', ent.entity)) : null}
                  investigating={investigatingId === e.entity}
                />
              ))}
            </div>
          )}
        </Card>

        {/* ── MITRE Behavior Strip ───────────────────── */}
        <MITREStrip
          anomalyCounts={anomalyCounts}
          active={mitreFilter}
          onToggle={tech => setMitreFilter(t => t === tech ? null : tech)}
        />

        {/* ── ML Anomaly Insights ───────────────────── */}
        <MlInsightsCard
          topMl={topMl}
          mlStats={mlStats}
          onProfile={openEntity}
          onRecalc={recalcMl}
          recalcing={mlRecalcing}
        />

        {/* ── Anomaly Map (3x3 grid) ─────────────────── */}
        <Card
          title="Anomaly Detection Map"
          sub={`${Object.values(anomalyCounts).reduce((a, b) => a + b, 0)} anomalies · 9 detection types${mitreFilter ? ` · filtered: ${mitreFilter}` : ''}`}
          actions={mitreFilter && <button className="btn btn-ghost btn-sm" onClick={() => setMitreFilter(null)}>Clear filter</button>}
        >
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
            {ANOMALY_ORDER.map(kind => {
              // Hide if MITRE filter doesn't match
              if (mitreFilter && !ANOMALY_META[kind].mitre.includes(mitreFilter)) return null;
              return (
                <AnomalyTile
                  key={kind}
                  kind={kind}
                  items={visibleAnomalies[kind] || []}
                  isExpanded={expandedKind === kind}
                  onToggle={k => setExpandedKind(e => e === k ? null : k)}
                  onItemClick={openEntity}
                />
              );
            })}
          </div>
        </Card>

        {/* ── Behavior Graph (REAL data) ─────────────── */}
        <Card
          title="Behavior Graph"
          sub={graphData ? `centered on ${graphData.nodes?.[0]?.id || watchlist[0]?.entity || 'top entity'} · dbl-click to expand` : 'live Neo4j entity graph'}
          actions={watchlist.length > 0 && (
            <div className="seg">
              {watchlist.slice(0, 4).map(w => (
                <button key={w.entity} className="seg-btn"
                        onClick={() => loadGraphFor(w.entity)}
                        title={`Load ${w.entity}'s neighborhood`}
                        style={{ fontSize: 10.5 }}>
                  {w.entity.length > 12 ? w.entity.slice(0, 12) + '…' : w.entity}
                </button>
              ))}
            </div>
          )}
        >
          {graphData ? (
            <UEBAForceGraph
              data={graphData}
              height={460}
              loading={graphLoading}
              onNodeClick={n => openEntity(n.id)}
              onExpand={id => loadGraphFor(id)}
            />
          ) : graphLoading ? (
            <div className="loading"><Spinner size={20}/> Loading graph…</div>
          ) : (
            <div className="empty mono">No entities to graph yet — ingest events to populate</div>
          )}
        </Card>

        {/* ── Compact Lookup + Path side-by-side ─────── */}
        <div className="grid-12">
          <Card title="Entity Lookup" sub="profile + risk + connections" span={6}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
              <input
                className="mono"
                style={{ flex: 1, background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 4, padding: '6px 10px', fontSize: 12, color: 'var(--fg-0)' }}
                placeholder="Username, hostname, or IP…"
                value={entityInput}
                onChange={e => setEntityInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && entityInput.trim() && openEntity(entityInput.trim())}
              />
              <button className="btn btn-primary" onClick={() => entityInput.trim() && openEntity(entityInput.trim())}>
                Open
              </button>
            </div>
            <div className="mono" style={{ fontSize: 10.5, color: 'var(--fg-3)' }}>
              Press Enter or click Open to launch full Entity Deep Dive (overview, anomalies, connections, actions).
            </div>
          </Card>

          <Card title="Attack Path Finder" sub="shortest lateral-movement path" span={6}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ display: 'flex', gap: 8 }}>
                <input className="mono"
                  style={{ flex: 1, background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 4, padding: '6px 10px', fontSize: 12, color: 'var(--fg-0)' }}
                  placeholder="From…" value={pathFrom} onChange={e => setPathFrom(e.target.value)}/>
                <input className="mono"
                  style={{ flex: 1, background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 4, padding: '6px 10px', fontSize: 12, color: 'var(--fg-0)' }}
                  placeholder="To…" value={pathTo} onChange={e => setPathTo(e.target.value)}/>
                <button className="btn btn-primary" onClick={findPath} disabled={pathLoading || !pathFrom.trim() || !pathTo.trim()}>
                  {pathLoading ? '…' : 'Find'}
                </button>
              </div>
              {pathResult && (
                pathResult.error ? (
                  <div className="mono" style={{ color: 'var(--fg-2)', fontSize: 11, padding: '6px 0' }}>{pathResult.error}</div>
                ) : !pathResult.found ? (
                  <div className="mono" style={{ color: 'var(--fg-3)', fontSize: 11, padding: '6px 0' }}>No path found between these entities.</div>
                ) : (
                  <div style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 6, padding: 10 }}>
                    {Array.isArray(pathResult.nodes) && (
                      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 5 }}>
                        {pathResult.nodes.map((node, i) => (
                          <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                            <span className="mono" onClick={() => openEntity(node.name || node.address)} style={{
                              fontSize: 11, padding: '2px 8px',
                              background: 'var(--bg-3)', border: '1px solid var(--ln)',
                              borderRadius: 4, color: 'var(--acc)', cursor: 'pointer',
                            }}>{node.name || node.address || node}</span>
                            {i < pathResult.nodes.length - 1 && (
                              <span style={{ color: 'var(--fg-3)', fontSize: 11 }}>→</span>
                            )}
                          </span>
                        ))}
                      </div>
                    )}
                    <div className="mono dim" style={{ fontSize: 10, marginTop: 6 }}>
                      {pathResult.hops != null ? `${pathResult.hops} hop${pathResult.hops !== 1 ? 's' : ''}` : ''}
                      {pathResult.maxDeviation != null ? ` · max deviation ${pathResult.maxDeviation}` : ''}
                    </div>
                  </div>
                )
              )}
            </div>
          </Card>
        </div>

        {/* ── AI Behavior Digest ─────────────────────── */}
        <Card
          title="AI Behavior Digest"
          sub="LangChain analysis of UEBA patterns"
          actions={
            <button className="btn btn-primary" onClick={generateDigest} disabled={digestLoading}>
              <Icon.brain width="13" height="13"/>
              {digestLoading ? ' Generating…' : ' Generate Digest'}
            </button>
          }
        >
          {digest ? (
            <div style={{
              background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 6, padding: 16,
              fontSize: 13, lineHeight: 1.65, color: 'var(--fg-1)', whiteSpace: 'pre-wrap',
            }}>{digest}</div>
          ) : (
            <div className="empty mono">No digest yet — click Generate Digest</div>
          )}
        </Card>
      </div>

      {/* ── Entity Deep Dive Modal ───────────────────── */}
      <EntityModal
        entity={modalEntity}
        onClose={() => setModalEntity(null)}
        onInvestigate={investigate}
        onAction={queueAction}
        investigating={investigatingId === modalEntity}
      />
    </div>
  );
}

Object.assign(window, { PageUEBA });
