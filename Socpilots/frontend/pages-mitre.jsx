// MITRE ATT&CK Coverage page
const { useState: useStateMT, useEffect: useEffectMT, useMemo: useMemoMT } = React;

// ── Static data ──────────────────────────────────────────────────────────────

const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance',        short: 'RECON'    },
  { id: 'TA0042', name: 'Resource Development',  short: 'RES-DEV'  },
  { id: 'TA0001', name: 'Initial Access',        short: 'INIT-ACC' },
  { id: 'TA0002', name: 'Execution',             short: 'EXEC'     },
  { id: 'TA0003', name: 'Persistence',           short: 'PERSIST'  },
  { id: 'TA0004', name: 'Privilege Escalation',  short: 'PRIV-ESC' },
  { id: 'TA0005', name: 'Defense Evasion',       short: 'DEF-EV'   },
  { id: 'TA0006', name: 'Credential Access',     short: 'CRED-ACC' },
  { id: 'TA0007', name: 'Discovery',             short: 'DISC'     },
  { id: 'TA0008', name: 'Lateral Movement',      short: 'LAT-MOV'  },
  { id: 'TA0009', name: 'Collection',            short: 'COLLECT'  },
  { id: 'TA0011', name: 'Command and Control',   short: 'C2'       },
  { id: 'TA0010', name: 'Exfiltration',          short: 'EXFIL'    },
  { id: 'TA0040', name: 'Impact',                short: 'IMPACT'   },
];

// [id, name, [tactic_ids...]]
const MITRE_TECHS = [
  ['T1595', 'Active Scanning',                     ['TA0043']],
  ['T1589', 'Gather Victim Identity Info',          ['TA0043']],
  ['T1590', 'Gather Victim Network Info',           ['TA0043']],
  ['T1583', 'Acquire Infrastructure',              ['TA0042']],
  ['T1586', 'Compromise Accounts',                 ['TA0042']],
  ['T1190', 'Exploit Public-Facing Application',   ['TA0001']],
  ['T1133', 'External Remote Services',            ['TA0001']],
  ['T1078', 'Valid Accounts',                      ['TA0001','TA0003','TA0004','TA0005']],
  ['T1566', 'Phishing',                            ['TA0001']],
  ['T1059', 'Command and Scripting Interpreter',   ['TA0002']],
  ['T1203', 'Exploitation for Client Execution',   ['TA0002']],
  ['T1106', 'Native API',                          ['TA0002']],
  ['T1053', 'Scheduled Task/Job',                  ['TA0002','TA0003','TA0004']],
  ['T1204', 'User Execution',                      ['TA0002']],
  ['T1547', 'Boot or Logon Autostart Execution',   ['TA0003','TA0004']],
  ['T1543', 'Create or Modify System Process',     ['TA0003','TA0004']],
  ['T1136', 'Create Account',                      ['TA0003']],
  ['T1505', 'Server Software Component',           ['TA0003']],
  ['T1548', 'Abuse Elevation Control Mechanism',   ['TA0004','TA0005']],
  ['T1134', 'Access Token Manipulation',           ['TA0004','TA0005']],
  ['T1068', 'Exploitation for Privilege Escalation',['TA0004']],
  ['T1055', 'Process Injection',                   ['TA0004','TA0005']],
  ['T1140', 'Deobfuscate/Decode Files or Info',    ['TA0005']],
  ['T1070', 'Indicator Removal',                   ['TA0005']],
  ['T1036', 'Masquerading',                        ['TA0005']],
  ['T1027', 'Obfuscated Files or Information',     ['TA0005']],
  ['T1110', 'Brute Force',                         ['TA0006']],
  ['T1555', 'Credentials from Password Stores',    ['TA0006']],
  ['T1003', 'OS Credential Dumping',               ['TA0006']],
  ['T1558', 'Steal or Forge Kerberos Tickets',     ['TA0006']],
  ['T1552', 'Unsecured Credentials',               ['TA0006']],
  ['T1087', 'Account Discovery',                   ['TA0007']],
  ['T1083', 'File and Directory Discovery',        ['TA0007']],
  ['T1046', 'Network Service Discovery',           ['TA0007']],
  ['T1057', 'Process Discovery',                   ['TA0007']],
  ['T1018', 'Remote System Discovery',             ['TA0007']],
  ['T1021', 'Remote Services',                     ['TA0008']],
  ['T1091', 'Replication Through Removable Media', ['TA0008']],
  ['T1550', 'Use Alternate Authentication Material',['TA0008']],
  ['T1560', 'Archive Collected Data',              ['TA0009']],
  ['T1005', 'Data from Local System',              ['TA0009']],
  ['T1039', 'Data from Network Shared Drive',      ['TA0009']],
  ['T1071', 'Application Layer Protocol',          ['TA0011']],
  ['T1573', 'Encrypted Channel',                   ['TA0011']],
  ['T1572', 'Protocol Tunneling',                  ['TA0011']],
  ['T1041', 'Exfiltration Over C2 Channel',        ['TA0010']],
  ['T1048', 'Exfiltration Over Alternative Protocol',['TA0010']],
  ['T1485', 'Data Destruction',                    ['TA0040']],
  ['T1486', 'Data Encrypted for Impact',           ['TA0040']],
  ['T1490', 'Inhibit System Recovery',             ['TA0040']],
  ['T1498', 'Network Denial of Service',           ['TA0040']],
  ['T1529', 'System Shutdown/Reboot',              ['TA0040']],
];

const FALLBACK_COVERAGE = {
  'T1110': { count: 847, max_level: 10, rules: ['5710','5711'], agents: ['web-prod-01'], last_seen: new Date().toISOString() },
  'T1059': { count: 412, max_level: 12, rules: ['92653'],       agents: ['web-prod-01','win-dc-01'], last_seen: new Date().toISOString() },
  'T1078': { count: 198, max_level: 8,  rules: ['5501'],        agents: ['win-dc-01'], last_seen: new Date().toISOString() },
  'T1003': { count: 87,  max_level: 14, rules: ['60106'],       agents: ['win-dc-01'], last_seen: new Date().toISOString() },
  'T1021': { count: 45,  max_level: 10, rules: ['11302'],       agents: ['jump-host'], last_seen: new Date().toISOString() },
  'T1046': { count: 23,  max_level: 7,  rules: ['1002'],        agents: ['web-prod-01'], last_seen: new Date().toISOString() },
  'T1053': { count: 8,   max_level: 9,  rules: ['92000'],       agents: ['db-primary'], last_seen: new Date().toISOString() },
  'T1566': { count: 3,   max_level: 6,  rules: ['99001'],       agents: ['mail-gw-01'], last_seen: new Date().toISOString() },
  'T1070': { count: 2,   max_level: 8,  rules: ['554'],         agents: ['win-dc-01'], last_seen: new Date().toISOString() },
  'T1486': { count: 1,   max_level: 15, rules: ['87105'],       agents: ['db-primary'], last_seen: new Date().toISOString() },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function covColor(d) {
  if (!d || d.count === 0) return 'rgba(255,255,255,0.04)';
  if (d.count >= 10) return '#00c853';
  if (d.count >= 3)  return '#ff9800';
  return '#29b6f6';
}

function covLevel(d) {
  if (!d || d.count === 0) return 'none';
  if (d.count >= 10) return 'high';
  if (d.count >= 3)  return 'medium';
  return 'low';
}

function fmtTs(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  } catch { return iso; }
}

function exportNavigator(covData) {
  const techniques = Object.entries(covData).map(([tid, d]) => ({
    techniqueID: tid,
    tactic: null,
    color: d.count >= 10 ? '#00c853' : d.count >= 3 ? '#ff9800' : '#29b6f6',
    comment: `${d.count} alerts, max level ${d.max_level}`,
    enabled: true,
    metadata: [],
    showSubtechniques: false,
    score: d.count,
  }));
  const nav = {
    name: 'SOCPilots Coverage',
    versions: { attack: '14', navigator: '4.9', layer: '4.5' },
    domain: 'enterprise-attack',
    description: `Generated by SOCPilots on ${new Date().toISOString()}`,
    techniques,
    gradient: { colors: ['#ff6666','#ffe766','#8ec843'], minValue: 0, maxValue: 100 },
    legendItems: [],
    metadata: [],
    showTacticRowBackground: false,
    tacticRowBackground: '#dddddd',
    selectTechniquesAcrossTactics: false,
    selectSubtechniquesWithParent: false,
  };
  const blob = new Blob([JSON.stringify(nav, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'socpilots-mitre-coverage.json'; a.click();
  URL.revokeObjectURL(url);
}

// ── Main page component ───────────────────────────────────────────────────────

function PageMitre() {
  const [tf, setTf]             = useStateMT('7d');
  const [covData, setCovData]   = useStateMT(FALLBACK_COVERAGE);
  const [loading, setLoading]   = useStateMT(true);
  const [tacticFilt, setTacticFilt] = useStateMT('all');
  const [levelFilt, setLevelFilt]   = useStateMT('all');
  const [selected, setSelected] = useStateMT(null);   // { id, name }
  const [detail, setDetail]     = useStateMT(null);   // fetched drill-down data
  const [detailLoad, setDetailLoad] = useStateMT(false);

  // Load coverage on timeframe change
  useEffectMT(() => {
    setLoading(true);
    window.SOC_API.get(`/api/mitre/coverage?timeframe=${tf}`).then(resp => {
      const cov = (resp && resp.coverage) ? resp.coverage : FALLBACK_COVERAGE;
      setCovData(cov);
      setLoading(false);
    }).catch(() => {
      setCovData(FALLBACK_COVERAGE);
      setLoading(false);
    });
  }, [tf]);

  // Load drill-down when technique is selected
  useEffectMT(() => {
    if (!selected) { setDetail(null); return; }
    setDetailLoad(true);
    window.SOC_API.get(`/api/mitre/technique/${selected.id}?timeframe=${tf}`).then(resp => {
      setDetail(resp || null);
      setDetailLoad(false);
    }).catch(() => {
      setDetail(null);
      setDetailLoad(false);
    });
  }, [selected, tf]);

  // Stat computations
  const stats = useMemoMT(() => {
    const covered  = Object.values(covData).filter(d => d.count > 0).length;
    const total    = MITRE_TECHS.length;
    const pct      = total > 0 ? Math.round(covered / total * 100) : 0;
    const critical = Object.values(covData).filter(d => d.max_level >= 12).length;
    return { covered, total, pct, critical };
  }, [covData]);

  // Visible tactics after tactic filter
  const visibleTactics = useMemoMT(() => {
    return tacticFilt === 'all'
      ? MITRE_TACTICS
      : MITRE_TACTICS.filter(t => t.id === tacticFilt);
  }, [tacticFilt]);

  function openTechDetail(id, name) {
    setSelected({ id, name });
  }

  function closeDetail() {
    setSelected(null);
    setDetail(null);
  }

  const TF_OPTS = ['24h', '7d', '30d', '90d'];
  const LEVEL_OPTS = ['all', 'high', 'medium', 'low', 'none'];

  return (
    <div className="page" data-screen-label="MITRE ATT&CK Coverage">
      <Topbar
        title="ATT&CK Coverage"
        sub={`MITRE Enterprise · ${stats.covered} / ${stats.total} techniques · ${tf}`}
        actions={<>
          <div className="seg">
            {TF_OPTS.map(t => (
              <button key={t} className={`seg-btn ${tf === t ? 'on' : ''}`} onClick={() => setTf(t)}>{t}</button>
            ))}
          </div>
          <button className="btn btn-ghost" onClick={() => exportNavigator(covData)}>
            <Icon.file width="13" height="13" /> Export Navigator
          </button>
        </>}
      />

      <div className="page-body">

        {/* Coverage stat cards */}
        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
          <StatCard label="Techniques Covered" value={stats.covered} color="var(--acc)" />
          <StatCard label="Total Techniques"   value={stats.total}   color="var(--fg-2)" />
          <StatCard label="Coverage"           value={`${stats.pct}%`} color={stats.pct >= 50 ? 'var(--ok)' : stats.pct >= 25 ? 'var(--warn)' : 'var(--crit)'} />
          <StatCard label="Critical Covered"   value={stats.critical} color="var(--crit)" sub="max_level ≥ 12" />
        </div>

        {/* Heatmap card */}
        <Card title="ATT&CK COVERAGE MATRIX" sub={loading ? 'Loading…' : `${stats.covered} techniques detected across ${MITRE_TACTICS.length} tactics`}
          actions={<>
            <select
              className="chip chip-mono"
              value={tacticFilt}
              onChange={e => setTacticFilt(e.target.value)}
              style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', color: 'var(--fg)', borderRadius: 4, padding: '2px 6px', fontSize: 11 }}
            >
              <option value="all">All tactics</option>
              {MITRE_TACTICS.map(t => <option key={t.id} value={t.id}>{t.short}</option>)}
            </select>
            <div className="seg" style={{ marginLeft: 8 }}>
              {LEVEL_OPTS.map(l => (
                <button key={l} className={`seg-btn ${levelFilt === l ? 'on' : ''}`} style={{ fontSize: 10, padding: '2px 8px' }}
                  onClick={() => setLevelFilt(l)}>
                  {l}
                </button>
              ))}
            </div>
          </>}
        >
          {loading ? (
            <div className="loading mono" style={{ padding: '2rem', textAlign: 'center' }}>Loading coverage data…</div>
          ) : (
            <div style={{ overflowX: 'auto', paddingBottom: 8 }}>
              <div style={{ display: 'flex', gap: 6, minWidth: visibleTactics.length * 110 }}>
                {visibleTactics.map(tactic => {
                  const techs = MITRE_TECHS.filter(t => t[2].includes(tactic.id));
                  const visible = levelFilt === 'all'
                    ? techs
                    : techs.filter(t => covLevel(covData[t[0]]) === levelFilt);
                  return (
                    <div key={tactic.id} style={{ flex: '0 0 108px' }}>
                      {/* Tactic header */}
                      <div style={{
                        background: 'rgba(0,229,255,0.08)',
                        border: '1px solid rgba(0,229,255,0.2)',
                        borderRadius: 4,
                        padding: '4px 6px',
                        marginBottom: 5,
                        fontSize: 10,
                        fontFamily: 'var(--mono)',
                        color: 'var(--acc)',
                        textAlign: 'center',
                        letterSpacing: '0.04em',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }} title={tactic.name}>
                        {tactic.short}
                      </div>
                      {/* Technique cells */}
                      {visible.length === 0 && (
                        <div style={{ fontSize: 9, color: 'var(--fg-3)', textAlign: 'center', padding: '4px 0' }}>—</div>
                      )}
                      {visible.map(tech => {
                        const d   = covData[tech[0]];
                        const bg  = covColor(d);
                        const isNone = !d || d.count === 0;
                        const isSelected = selected?.id === tech[0];
                        return (
                          <div
                            key={tech[0]}
                            onClick={() => openTechDetail(tech[0], tech[1])}
                            title={`${tech[0]}: ${tech[1]}${d ? ' · ' + d.count + ' alerts' : ''}`}
                            style={{
                              background: bg,
                              border: isSelected
                                ? '1px solid var(--acc)'
                                : '1px solid rgba(255,255,255,0.08)',
                              borderRadius: 3,
                              padding: '3px 6px',
                              fontSize: 10,
                              cursor: 'pointer',
                              marginBottom: 2,
                              color: isNone ? 'var(--fg-3)' : '#fff',
                              fontFamily: 'var(--mono)',
                              boxShadow: isSelected ? '0 0 6px rgba(0,229,255,0.4)' : 'none',
                              transition: 'box-shadow 0.15s',
                            }}
                          >
                            {tech[0]}
                          </div>
                        );
                      })}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Legend */}
          <div style={{ display: 'flex', gap: 16, marginTop: 12, fontSize: 11, fontFamily: 'var(--mono)' }}>
            {[
              { color: '#00c853', label: 'High (≥10 alerts)' },
              { color: '#ff9800', label: 'Medium (3–9)' },
              { color: '#29b6f6', label: 'Low (1–2)' },
              { color: 'rgba(255,255,255,0.10)', label: 'Not detected', dim: true },
            ].map(l => (
              <span key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 10, height: 10, borderRadius: 2, background: l.color, border: '1px solid rgba(255,255,255,0.15)', flexShrink: 0 }} />
                <span style={{ color: l.dim ? 'var(--fg-3)' : 'var(--fg-2)' }}>{l.label}</span>
              </span>
            ))}
          </div>
        </Card>

        {/* Drill-down detail panel */}
        {selected && (
          <TechDetail
            id={selected.id}
            name={selected.name}
            covEntry={covData[selected.id] || null}
            apiDetail={detail}
            loading={detailLoad}
            onClose={closeDetail}
          />
        )}
      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({ label, value, color, sub }) {
  return (
    <div className="kpi">
      <div className="kpi-label">{label}</div>
      <div className="kpi-value mono" style={{ color }}>{value}</div>
      {sub && <div className="kpi-foot"><span className="kpi-sub">{sub}</span></div>}
    </div>
  );
}

function TechDetail({ id, name, covEntry, apiDetail, loading, onClose }) {
  // Merge: prefer API detail, fall back to covEntry fields
  const count     = apiDetail?.count     ?? covEntry?.count     ?? 0;
  const lastSeen  = apiDetail?.last_seen ?? covEntry?.last_seen ?? null;
  const maxLevel  = apiDetail?.max_level ?? covEntry?.max_level ?? '—';
  const rules     = apiDetail?.rules     ?? covEntry?.rules     ?? [];
  const agents    = apiDetail?.agents    ?? covEntry?.agents    ?? [];
  const alerts    = apiDetail?.recent_alerts ?? [];

  const sev = maxLevel >= 12 ? 'critical' : maxLevel >= 8 ? 'high' : maxLevel >= 5 ? 'medium' : 'low';

  return (
    <Card
      title={<><span className="mono" style={{ color: 'var(--acc)' }}>{id}</span> · {name}</>}
      sub="Technique drill-down"
      actions={
        <button className="btn-icon" onClick={onClose} title="Close">
          <Icon.x width="14" height="14" />
        </button>
      }
    >
      {loading ? (
        <div className="loading mono" style={{ padding: '1rem', textAlign: 'center' }}>Loading technique detail…</div>
      ) : (
        <div>
          {/* Summary row */}
          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', marginBottom: 16 }}>
            <DetailCell label="Total Alerts" value={count.toLocaleString()} mono accent={count > 0} />
            <DetailCell label="Max Rule Level" value={maxLevel} mono />
            <DetailCell label="Severity" value={<SevChip sev={sev} />} />
            <DetailCell label="Last Seen" value={fmtTs(lastSeen)} mono />
            <DetailCell label="Rules Triggered" value={rules.length || '—'} mono />
            <DetailCell label="Agents Affected" value={agents.length || '—'} mono />
          </div>

          {/* Rules + Agents */}
          <div style={{ display: 'flex', gap: 24, marginBottom: 16, flexWrap: 'wrap' }}>
            {rules.length > 0 && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 5 }}>RULES</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {rules.map(r => <Chip key={r} mono>{r}</Chip>)}
                </div>
              </div>
            )}
            {agents.length > 0 && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 5 }}>AGENTS</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {agents.map(a => <Chip key={a} mono tone="dim">{a}</Chip>)}
                </div>
              </div>
            )}
          </div>

          {/* Recent alerts */}
          {alerts.length > 0 && (
            <div>
              <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 6 }}>RECENT ALERTS (last 5)</div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>TIME</th>
                    <th>AGENT</th>
                    <th>RULE</th>
                    <th>SEV</th>
                    <th>DESCRIPTION</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.slice(0, 5).map((a, i) => (
                    <tr key={i}>
                      <td className="mono dim">{a.timestamp ? a.timestamp.slice(0, 16).replace('T', ' ') : '—'}</td>
                      <td className="mono">{a.agent || '—'}</td>
                      <td className="mono">{a.ruleId || '—'}</td>
                      <td><SevChip sev={a.severity || 'low'} /></td>
                      <td>{a.description || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {alerts.length === 0 && count > 0 && (
            <div className="empty mono" style={{ fontSize: 11 }}>
              {count} alert{count !== 1 ? 's' : ''} detected — no per-alert detail available from API.
            </div>
          )}

          {count === 0 && (
            <div className="empty mono" style={{ fontSize: 11 }}>No alerts detected for this technique in the selected timeframe.</div>
          )}
        </div>
      )}
    </Card>
  );
}

function DetailCell({ label, value, mono, accent }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 2 }}>{label}</div>
      <div className={mono ? 'mono' : ''} style={{ fontSize: 14, color: accent ? 'var(--acc)' : 'var(--fg)' }}>{value}</div>
    </div>
  );
}

// ── Export ────────────────────────────────────────────────────────────────────

Object.assign(window, { PageMitre });
