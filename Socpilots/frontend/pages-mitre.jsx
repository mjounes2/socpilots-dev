// MITRE ATT&CK Coverage page
const { useState: useStateMT, useEffect: useEffectMT, useMemo: useMemoMT, useCallback: useCallbackMT } = React;

// ── Static data ───────────────────────────────────────────────────────────────

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

// Full Enterprise ATT&CK v14 — synced with server.js _MITRE_TECHS_LIST
const MITRE_TECHS = [
  // Reconnaissance
  ['T1595','Active Scanning',                        ['TA0043']],
  ['T1592','Gather Victim Host Info',                ['TA0043']],
  ['T1589','Gather Victim Identity Info',            ['TA0043']],
  ['T1590','Gather Victim Network Info',             ['TA0043']],
  ['T1591','Gather Victim Org Info',                 ['TA0043']],
  ['T1598','Phishing for Info',                      ['TA0043']],
  ['T1597','Search Closed Sources',                  ['TA0043']],
  ['T1596','Search Open Tech Databases',             ['TA0043']],
  ['T1593','Search Open Websites',                   ['TA0043']],
  ['T1594','Search Victim Website',                  ['TA0043']],
  // Resource Development
  ['T1583','Acquire Infrastructure',                 ['TA0042']],
  ['T1584','Compromise Infrastructure',              ['TA0042']],
  ['T1586','Compromise Accounts',                    ['TA0042']],
  ['T1587','Develop Capabilities',                   ['TA0042']],
  ['T1588','Obtain Capabilities',                    ['TA0042']],
  ['T1585','Establish Accounts',                     ['TA0042']],
  ['T1608','Stage Capabilities',                     ['TA0042']],
  // Initial Access
  ['T1189','Drive-by Compromise',                    ['TA0001']],
  ['T1190','Exploit Public-Facing Application',      ['TA0001']],
  ['T1133','External Remote Services',               ['TA0001','TA0003']],
  ['T1200','Hardware Additions',                     ['TA0001']],
  ['T1566','Phishing',                               ['TA0001']],
  ['T1091','Replication via Removable Media',        ['TA0001','TA0008']],
  ['T1195','Supply Chain Compromise',                ['TA0001']],
  ['T1199','Trusted Relationship',                   ['TA0001']],
  ['T1078','Valid Accounts',                         ['TA0001','TA0003','TA0004','TA0005']],
  ['T1659','Content Injection',                      ['TA0001']],
  // Execution
  ['T1059','Command and Scripting Interpreter',      ['TA0002']],
  ['T1203','Exploitation for Client Execution',      ['TA0002']],
  ['T1559','Inter-Process Communication',            ['TA0002']],
  ['T1106','Native API',                             ['TA0002']],
  ['T1053','Scheduled Task/Job',                     ['TA0002','TA0003','TA0004']],
  ['T1129','Shared Modules',                         ['TA0002']],
  ['T1569','System Services',                        ['TA0002','TA0003']],
  ['T1204','User Execution',                         ['TA0002']],
  ['T1047','Windows Management Instrumentation',     ['TA0002']],
  ['T1072','Software Deployment Tools',              ['TA0002','TA0008']],
  // Persistence
  ['T1098','Account Manipulation',                   ['TA0003','TA0004']],
  ['T1197','BITS Jobs',                              ['TA0003','TA0005']],
  ['T1547','Boot or Logon Autostart',                ['TA0003','TA0004']],
  ['T1176','Browser Extensions',                     ['TA0003']],
  ['T1554','Compromise Host Software Binary',        ['TA0003']],
  ['T1136','Create Account',                         ['TA0003']],
  ['T1543','Create or Modify System Process',        ['TA0003','TA0004']],
  ['T1546','Event Triggered Execution',              ['TA0003','TA0004']],
  ['T1574','Hijack Execution Flow',                  ['TA0003','TA0004','TA0005']],
  ['T1137','Office Application Startup',             ['TA0003']],
  ['T1542','Pre-OS Boot',                            ['TA0003','TA0005']],
  ['T1505','Server Software Component',              ['TA0003']],
  // Privilege Escalation
  ['T1548','Abuse Elevation Control Mechanism',      ['TA0004','TA0005']],
  ['T1134','Access Token Manipulation',              ['TA0004','TA0005']],
  ['T1484','Domain or Tenant Policy Modification',   ['TA0004','TA0005']],
  ['T1068','Exploitation for Privilege Escalation',  ['TA0004']],
  ['T1055','Process Injection',                      ['TA0004','TA0005']],
  ['T1611','Escape to Host',                         ['TA0004']],
  // Defense Evasion
  ['T1140','Deobfuscate/Decode Files',               ['TA0005']],
  ['T1006','Direct Volume Access',                   ['TA0005']],
  ['T1480','Execution Guardrails',                   ['TA0005']],
  ['T1211','Exploitation for Defense Evasion',       ['TA0005']],
  ['T1222','File and Directory Permissions Mod',     ['TA0005']],
  ['T1564','Hide Artifacts',                         ['TA0005']],
  ['T1562','Impair Defenses',                        ['TA0005']],
  ['T1070','Indicator Removal',                      ['TA0005']],
  ['T1202','Indirect Command Execution',             ['TA0005']],
  ['T1036','Masquerading',                           ['TA0005']],
  ['T1112','Modify Registry',                        ['TA0005']],
  ['T1027','Obfuscated Files or Information',        ['TA0005']],
  ['T1647','Plist File Modification',                ['TA0005']],
  ['T1620','Reflective Code Loading',                ['TA0005']],
  ['T1553','Subvert Trust Controls',                 ['TA0005']],
  ['T1218','System Binary Proxy Execution',          ['TA0005']],
  ['T1216','System Script Proxy Execution',          ['TA0005']],
  ['T1127','Trusted Developer Utilities Proxy',      ['TA0005']],
  ['T1497','Virtualization/Sandbox Evasion',         ['TA0005']],
  ['T1600','Weaken Encryption',                      ['TA0005']],
  // Credential Access
  ['T1557','Adversary-in-the-Middle',                ['TA0006','TA0009']],
  ['T1110','Brute Force',                            ['TA0006']],
  ['T1555','Credentials from Password Stores',       ['TA0006']],
  ['T1212','Exploitation for Credential Access',     ['TA0006']],
  ['T1187','Forced Authentication',                  ['TA0006']],
  ['T1606','Forge Web Credentials',                  ['TA0006']],
  ['T1056','Input Capture',                          ['TA0006','TA0009']],
  ['T1040','Network Sniffing',                       ['TA0006','TA0007']],
  ['T1003','OS Credential Dumping',                  ['TA0006']],
  ['T1528','Steal Application Access Token',         ['TA0006']],
  ['T1558','Steal or Forge Kerberos Tickets',        ['TA0006']],
  ['T1539','Steal Web Session Cookie',               ['TA0006']],
  ['T1552','Unsecured Credentials',                  ['TA0006']],
  // Discovery
  ['T1087','Account Discovery',                      ['TA0007']],
  ['T1010','Application Window Discovery',           ['TA0007']],
  ['T1217','Browser Information Discovery',          ['TA0007']],
  ['T1580','Cloud Infrastructure Discovery',         ['TA0007']],
  ['T1538','Cloud Service Dashboard',                ['TA0007']],
  ['T1526','Cloud Service Discovery',                ['TA0007']],
  ['T1613','Container and Resource Discovery',       ['TA0007']],
  ['T1482','Domain Trust Discovery',                 ['TA0007']],
  ['T1083','File and Directory Discovery',           ['TA0007']],
  ['T1615','Group Policy Discovery',                 ['TA0007']],
  ['T1046','Network Service Discovery',              ['TA0007']],
  ['T1135','Network Share Discovery',                ['TA0007']],
  ['T1201','Password Policy Discovery',              ['TA0007']],
  ['T1120','Peripheral Device Discovery',            ['TA0007']],
  ['T1069','Permission Groups Discovery',            ['TA0007']],
  ['T1057','Process Discovery',                      ['TA0007']],
  ['T1012','Query Registry',                         ['TA0007']],
  ['T1018','Remote System Discovery',                ['TA0007']],
  ['T1518','Software Discovery',                     ['TA0007']],
  ['T1082','System Information Discovery',           ['TA0007']],
  ['T1016','System Network Configuration Discovery', ['TA0007']],
  ['T1049','System Network Connections Discovery',   ['TA0007']],
  ['T1033','System Owner/User Discovery',            ['TA0007']],
  ['T1007','System Service Discovery',               ['TA0007']],
  ['T1124','System Time Discovery',                  ['TA0007']],
  // Lateral Movement
  ['T1210','Exploitation of Remote Services',        ['TA0008']],
  ['T1534','Internal Spearphishing',                 ['TA0008']],
  ['T1570','Lateral Tool Transfer',                  ['TA0008']],
  ['T1563','Remote Service Session Hijacking',       ['TA0008']],
  ['T1021','Remote Services',                        ['TA0008']],
  ['T1080','Taint Shared Content',                   ['TA0008']],
  ['T1550','Use Alternate Authentication Material',  ['TA0005','TA0008']],
  // Collection
  ['T1560','Archive Collected Data',                 ['TA0009']],
  ['T1123','Audio Capture',                          ['TA0009']],
  ['T1119','Automated Collection',                   ['TA0009']],
  ['T1185','Browser Session Hijacking',              ['TA0009']],
  ['T1115','Clipboard Data',                         ['TA0009']],
  ['T1530','Data from Cloud Storage',                ['TA0009']],
  ['T1213','Data from Information Repositories',     ['TA0009']],
  ['T1005','Data from Local System',                 ['TA0009']],
  ['T1039','Data from Network Shared Drive',         ['TA0009']],
  ['T1025','Data from Removable Media',              ['TA0009']],
  ['T1074','Data Staged',                            ['TA0009']],
  ['T1114','Email Collection',                       ['TA0009']],
  ['T1602','Data from Configuration Repository',     ['TA0009']],
  ['T1113','Screen Capture',                         ['TA0009']],
  ['T1125','Video Capture',                          ['TA0009']],
  // Exfiltration
  ['T1020','Automated Exfiltration',                 ['TA0010']],
  ['T1030','Data Transfer Size Limits',              ['TA0010']],
  ['T1048','Exfiltration Over Alt Protocol',         ['TA0010']],
  ['T1041','Exfiltration Over C2 Channel',           ['TA0010']],
  ['T1011','Exfiltration Over Other Network',        ['TA0010']],
  ['T1052','Exfiltration Over Physical Medium',      ['TA0010']],
  ['T1567','Exfiltration Over Web Service',          ['TA0010']],
  ['T1537','Transfer Data to Cloud Account',         ['TA0010']],
  ['T1029','Scheduled Transfer',                     ['TA0010']],
  // Command and Control
  ['T1071','Application Layer Protocol',             ['TA0011']],
  ['T1092','Communication via Removable Media',      ['TA0011']],
  ['T1132','Data Encoding',                          ['TA0011']],
  ['T1001','Data Obfuscation',                       ['TA0011']],
  ['T1568','Dynamic Resolution',                     ['TA0011']],
  ['T1573','Encrypted Channel',                      ['TA0011']],
  ['T1008','Fallback Channels',                      ['TA0011']],
  ['T1105','Ingress Tool Transfer',                  ['TA0011']],
  ['T1104','Multi-Stage Channels',                   ['TA0011']],
  ['T1095','Non-Application Layer Protocol',         ['TA0011']],
  ['T1571','Non-Standard Port',                      ['TA0011']],
  ['T1572','Protocol Tunneling',                     ['TA0011']],
  ['T1090','Proxy',                                  ['TA0011']],
  ['T1219','Remote Access Software',                 ['TA0011']],
  ['T1205','Traffic Signaling',                      ['TA0011','TA0003']],
  ['T1102','Web Service',                            ['TA0011']],
  // Impact
  ['T1531','Account Access Removal',                 ['TA0040']],
  ['T1485','Data Destruction',                       ['TA0040']],
  ['T1486','Data Encrypted for Impact',              ['TA0040']],
  ['T1565','Data Manipulation',                      ['TA0040']],
  ['T1491','Defacement',                             ['TA0040']],
  ['T1561','Disk Wipe',                              ['TA0040']],
  ['T1499','Endpoint Denial of Service',             ['TA0040']],
  ['T1495','Firmware Corruption',                    ['TA0040']],
  ['T1490','Inhibit System Recovery',                ['TA0040']],
  ['T1498','Network Denial of Service',              ['TA0040']],
  ['T1496','Resource Hijacking',                     ['TA0040']],
  ['T1489','Service Stop',                           ['TA0040']],
  ['T1529','System Shutdown/Reboot',                 ['TA0040']],
  ['T1657','Financial Theft',                        ['TA0040']],
];

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
  try { return new Date(iso).toISOString().slice(0, 16).replace('T', ' ') + ' UTC'; }
  catch { return iso; }
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
  const [tf, setTf]                     = useStateMT('7d');
  const [covData, setCovData]           = useStateMT({});
  const [allAgents, setAllAgents]       = useStateMT([]);
  const [loading, setLoading]           = useStateMT(true);
  const [tacticFilt, setTacticFilt]     = useStateMT('all');
  const [levelFilt, setLevelFilt]       = useStateMT('all');
  const [selected, setSelected]         = useStateMT(null);
  const [detail, setDetail]             = useStateMT(null);
  const [detailLoad, setDetailLoad]     = useStateMT(false);
  const [showAnalysis, setShowAnalysis] = useStateMT(false);

  useEffectMT(() => {
    setLoading(true);
    window.SOC_API.get(`/api/mitre/coverage?timeframe=${tf}`).then(resp => {
      if (resp && resp.coverage) {
        // Roll up subtechnique hits (e.g. T1110.001) into their parent (T1110)
        const raw = resp.coverage;
        const merged = { ...raw };
        for (const [tid, data] of Object.entries(raw)) {
          if (!tid.includes('.')) continue;
          const parent = tid.split('.')[0];
          if (!merged[parent]) {
            merged[parent] = {
              ...data,
              rules:    [...(data.rules   || [])],
              agents:   [...(data.agents  || [])],
              decoders: [...(data.decoders|| [])],
            };
          } else {
            const p = merged[parent];
            merged[parent] = {
              ...p,
              count:          p.count + data.count,
              max_level:      Math.max(p.max_level || 0, data.max_level || 0),
              rules:          [...new Set([...(p.rules   || []), ...(data.rules   || [])])],
              agents:         [...new Set([...(p.agents  || []), ...(data.agents  || [])])],
              decoders:       [...new Set([...(p.decoders|| []), ...(data.decoders|| [])])],
              coverage_score: Math.max(p.coverage_score || 0, data.coverage_score || 0),
              last_seen:      Math.max(p.last_seen || 0, data.last_seen || 0) || null,
            };
          }
        }
        setCovData(merged);
        setAllAgents(resp.all_agents || []);
      }
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [tf]);

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

  const stats = useMemoMT(() => {
    const covered  = Object.values(covData).filter(d => d.count > 0).length;
    const total    = MITRE_TECHS.length;
    const pct      = total > 0 ? Math.round(covered / total * 100) : 0;
    const critical = Object.values(covData).filter(d => d.max_level >= 12).length;
    const allAlerts = Object.values(covData).reduce((s, d) => s + (d.count || 0), 0);
    return { covered, total, pct, critical, allAlerts };
  }, [covData]);

  const visibleTactics = useMemoMT(() =>
    tacticFilt === 'all' ? MITRE_TACTICS : MITRE_TACTICS.filter(t => t.id === tacticFilt)
  , [tacticFilt]);

  const TF_OPTS    = ['24h','7d','30d','90d'];
  const LEVEL_OPTS = ['all','high','medium','low','none'];

  return (
    <div className="page" data-screen-label="MITRE ATT&CK Coverage">
      <Topbar
        title="ATT&CK Coverage"
        sub={`MITRE Enterprise v14 · ${stats.covered} / ${stats.total} techniques · ${tf}`}
        actions={<>
          <div className="seg">
            {TF_OPTS.map(t => (
              <button key={t} className={`seg-btn ${tf === t ? 'on' : ''}`} onClick={() => setTf(t)}>{t}</button>
            ))}
          </div>
          <button className="btn btn-ghost" onClick={() => setShowAnalysis(v => !v)}>
            <Icon.cpu width="13" height="13" /> {showAnalysis ? 'Hide Analysis' : 'AI Analysis'}
          </button>
          <button className="btn btn-ghost" onClick={() => exportNavigator(covData)}>
            <Icon.file width="13" height="13" /> Export Navigator
          </button>
        </>}
      />

      <div className="page-body">

        {/* KPI row */}
        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
          <StatCard label="Techniques Covered" value={stats.covered}            color="var(--acc)" />
          <StatCard label="Total Techniques"   value={stats.total}              color="var(--fg-2)" />
          <StatCard label="Coverage"           value={`${stats.pct}%`}
            color={stats.pct >= 50 ? 'var(--ok)' : stats.pct >= 25 ? 'var(--warn)' : 'var(--crit)'} />
          <StatCard label="Critical Rules Hit" value={stats.critical}           color="var(--crit)" sub="max_level ≥ 12" />
          <StatCard label="Total MITRE Alerts" value={stats.allAlerts.toLocaleString()} color="var(--acc)" sub={tf} />
        </div>

        {/* Heatmap */}
        <Card
          title="ATT&CK COVERAGE MATRIX"
          sub={loading ? 'Loading…' : `${stats.covered} techniques detected · ${MITRE_TACTICS.length} tactics`}
          actions={<>
            <select
              className="chip chip-mono"
              value={tacticFilt}
              onChange={e => setTacticFilt(e.target.value)}
              style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', color: 'var(--fg)', borderRadius: 4, padding: '2px 6px', fontSize: 11 }}
            >
              <option value="all">All tactics</option>
              {MITRE_TACTICS.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
            <div className="seg" style={{ marginLeft: 8 }}>
              {LEVEL_OPTS.map(l => (
                <button key={l} className={`seg-btn ${levelFilt === l ? 'on' : ''}`}
                  style={{ fontSize: 10, padding: '2px 8px' }} onClick={() => setLevelFilt(l)}>
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
                      <div style={{
                        background: 'rgba(0,229,255,0.08)', border: '1px solid rgba(0,229,255,0.2)',
                        borderRadius: 4, padding: '4px 6px', marginBottom: 5, fontSize: 10,
                        fontFamily: 'var(--mono)', color: 'var(--acc)', textAlign: 'center',
                        letterSpacing: '0.04em', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                      }} title={tactic.name}>{tactic.short}</div>
                      {visible.length === 0 && (
                        <div style={{ fontSize: 9, color: 'var(--fg-3)', textAlign: 'center', padding: '4px 0' }}>—</div>
                      )}
                      {visible.map(tech => {
                        const d = covData[tech[0]];
                        const isSelected = selected?.id === tech[0];
                        return (
                          <div key={tech[0]}
                            onClick={() => setSelected(s => s?.id === tech[0] ? null : { id: tech[0], name: tech[1] })}
                            title={`${tech[0]}: ${tech[1]}${d ? ' · ' + d.count + ' alerts' : ' · no coverage'}`}
                            style={{
                              background: covColor(d),
                              border: isSelected ? '1px solid var(--acc)' : '1px solid rgba(255,255,255,0.08)',
                              borderRadius: 3, padding: '3px 6px', fontSize: 10, cursor: 'pointer',
                              marginBottom: 2, color: (!d || d.count === 0) ? 'var(--fg-3)' : '#fff',
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

        {/* Technique drill-down */}
        {selected && (
          <TechDetail
            id={selected.id}
            name={selected.name}
            covEntry={covData[selected.id] || null}
            apiDetail={detail}
            loading={detailLoad}
            onClose={() => { setSelected(null); setDetail(null); }}
          />
        )}

        {/* AI Gap Analysis panel */}
        {showAnalysis && (
          <AnalysisPanel covData={covData} allAgents={allAgents} tf={tf} />
        )}
      </div>
    </div>
  );
}

// ── Technique drill-down ──────────────────────────────────────────────────────

function TechDetail({ id, name, covEntry, apiDetail, loading, onClose }) {
  const count    = apiDetail?.count    ?? apiDetail?.total  ?? covEntry?.count    ?? 0;
  const lastSeen = apiDetail?.last_seen ?? covEntry?.last_seen ?? null;
  const maxLevel = apiDetail?.max_level ?? covEntry?.max_level ?? 0;
  const rules    = apiDetail?.rules    ?? covEntry?.rules    ?? [];
  const agents   = apiDetail?.agents   ?? covEntry?.agents   ?? [];
  const decoders = apiDetail?.decoders ?? covEntry?.decoders ?? [];
  const alerts   = apiDetail?.recent_alerts ?? [];
  const timeline = apiDetail?.timeline ?? [];

  const sev = maxLevel >= 12 ? 'critical' : maxLevel >= 8 ? 'high' : maxLevel >= 5 ? 'medium' : 'low';

  return (
    <Card
      title={<><span className="mono" style={{ color: 'var(--acc)' }}>{id}</span> · {name}</>}
      sub="Technique drill-down"
      actions={<button className="btn-icon" onClick={onClose} title="Close"><Icon.x width="14" height="14" /></button>}
    >
      {loading ? (
        <div className="loading mono" style={{ padding: '1rem', textAlign: 'center' }}>Loading technique detail…</div>
      ) : (
        <div>
          {/* Summary */}
          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', marginBottom: 16 }}>
            <DetailCell label="Total Alerts"   value={count.toLocaleString()} mono accent={count > 0} />
            <DetailCell label="Max Rule Level" value={maxLevel || '—'} mono />
            <DetailCell label="Severity"       value={<SevChip sev={sev} />} />
            <DetailCell label="Last Seen"      value={fmtTs(lastSeen)} mono />
            <DetailCell label="Rules Matched"  value={rules.length || '—'} mono />
            <DetailCell label="Agents Hit"     value={agents.length || '—'} mono />
          </div>

          {/* Rules */}
          {rules.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 6 }}>MATCHING WAZUH RULES</div>
              <table className="data-table" style={{ fontSize: 11 }}>
                <thead><tr><th>RULE ID</th><th>LEVEL</th><th>SEV</th><th>ALERTS</th><th>DESCRIPTION</th></tr></thead>
                <tbody>
                  {rules.map(r => {
                    const rId   = typeof r === 'object' ? r.id : r;
                    const rDesc = typeof r === 'object' ? r.description : '—';
                    const rLvl  = typeof r === 'object' ? r.level : 0;
                    const rCnt  = typeof r === 'object' ? r.count : 0;
                    const rSev  = rLvl >= 12 ? 'critical' : rLvl >= 8 ? 'high' : rLvl >= 5 ? 'medium' : 'low';
                    return (
                      <tr key={rId}>
                        <td className="mono" style={{ color: 'var(--acc)' }}>{rId}</td>
                        <td className="mono">{rLvl || '—'}</td>
                        <td><SevChip sev={rSev} /></td>
                        <td className="mono">{rCnt.toLocaleString()}</td>
                        <td style={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rDesc}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Agents + Log Sources */}
          <div style={{ display: 'flex', gap: 24, marginBottom: 14, flexWrap: 'wrap' }}>
            {agents.length > 0 && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 5 }}>AGENTS AFFECTED</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {agents.map(a => {
                    const n = typeof a === 'object' ? a.name : a;
                    const c = typeof a === 'object' ? a.count : null;
                    return <Chip key={n} mono tone="dim">{n}{c ? ` (${c})` : ''}</Chip>;
                  })}
                </div>
              </div>
            )}
            {decoders.length > 0 && (
              <div>
                <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 5 }}>LOG SOURCES</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {decoders.map(d => <Chip key={d} mono>{d}</Chip>)}
                </div>
              </div>
            )}
          </div>

          {/* Daily timeline */}
          {timeline.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 6 }}>DAILY ALERT TIMELINE</div>
              <MiniBar data={timeline} />
            </div>
          )}

          {/* Recent alerts */}
          {alerts.length > 0 && (
            <div>
              <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 6 }}>RECENT ALERTS (last 5)</div>
              <table className="data-table" style={{ fontSize: 11 }}>
                <thead><tr><th>TIME</th><th>AGENT</th><th>RULE</th><th>SEV</th><th>DESCRIPTION</th></tr></thead>
                <tbody>
                  {alerts.slice(0, 5).map((a, i) => (
                    <tr key={i}>
                      <td className="mono dim">{a.timestamp ? a.timestamp.slice(0, 16).replace('T', ' ') : '—'}</td>
                      <td className="mono">{a.agent || '—'}</td>
                      <td className="mono">{a.ruleId || a.rule || '—'}</td>
                      <td><SevChip sev={a.severity || 'low'} /></td>
                      <td style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.description || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {alerts.length === 0 && count > 0 && (
            <div className="empty mono" style={{ fontSize: 11 }}>
              {count.toLocaleString()} alert{count !== 1 ? 's' : ''} detected — no per-alert detail available from API.
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

// ── AI Gap Analysis & Recommendations panel ───────────────────────────────────

function AnalysisPanel({ covData, allAgents, tf }) {
  const [tab, setTab]           = useStateMT('tactic');
  const [analysis, setAnalysis] = useStateMT(null);
  const [auditData, setAuditData] = useStateMT(null);
  const [running, setRunning]   = useStateMT(false);
  const [auditLoad, setAuditLoad] = useStateMT(true);
  const [lastRun, setLastRun]   = useStateMT(null);

  useEffectMT(() => {
    // Load cached AI analysis
    window.SOC_API.get('/api/mitre/analysis').then(r => {
      if (r && r.available && r.result) {
        setAnalysis(r.result);
        setLastRun(r.last_analyzed_at);
      }
    }).catch(() => {});
    // Load unmapped rules audit
    setAuditLoad(true);
    window.SOC_API.get(`/api/mitre/coverage-audit?timeframe=${tf}`).then(r => {
      if (r && !r.error) setAuditData(r);
      setAuditLoad(false);
    }).catch(() => setAuditLoad(false));
  }, [tf]);

  const { covered, gaps, logSources } = useMemoMT(() => {
    const covered = MITRE_TECHS
      .filter(t => covData[t[0]] && covData[t[0]].count > 0)
      .map(t => ({
        id: t[0], name: t[1],
        count: covData[t[0]].count,
        score: covData[t[0]].coverage_score || 0,
        rule_count: (covData[t[0]].rules || []).length,
        tactics: t[2],
      }));
    const gaps = MITRE_TECHS
      .filter(t => !covData[t[0]] || covData[t[0]].count === 0)
      .map(t => ({ id: t[0], name: t[1], tactics: t[2] }));
    const logSources = [...new Set(
      Object.values(covData).flatMap(d => d.decoders || [])
    )].filter(Boolean).slice(0, 20);
    return { covered, gaps, logSources };
  }, [covData]);

  function runAnalysis() {
    setRunning(true);
    window.SOC_API.post('/api/mitre/analyze', {
      covered,
      gaps,
      log_sources: logSources,
      agents: allAgents,
      summary: {
        total_techniques: MITRE_TECHS.length,
        covered_count:    covered.length,
        gap_count:        gaps.length,
        coverage_pct:     Math.round(covered.length / MITRE_TECHS.length * 100),
        timeframe:        tf,
      },
    }).then(r => {
      if (r && !r.error) { setAnalysis(r); setLastRun(Date.now()); }
      setRunning(false);
    }).catch(() => setRunning(false));
  }

  // Per-tactic breakdown derived from covData
  const tacticBreakdown = useMemoMT(() => {
    const counts = {};
    MITRE_TACTICS.forEach(t => { counts[t.id] = { name: t.name, covered: 0, total: 0 }; });
    MITRE_TECHS.forEach(([id, , tactics]) => {
      tactics.forEach(ta => {
        if (counts[ta]) {
          counts[ta].total++;
          if (covData[id] && covData[id].count > 0) counts[ta].covered++;
        }
      });
    });
    return Object.entries(counts)
      .map(([id, v]) => ({ id, ...v, pct: v.total ? Math.round(v.covered / v.total * 100) : 0 }))
      .sort((a, b) => b.pct - a.pct);
  }, [covData]);

  const TABS = [
    { id: 'tactic',    label: 'Tactic Breakdown' },
    { id: 'gaps',      label: `Coverage Gaps (${gaps.length})` },
    { id: 'recs',      label: 'Recommendations' },
    { id: 'unmapped',  label: `Unmapped Rules${auditData ? ' (' + auditData.top_rules?.length + ')' : ''}` },
  ];

  const EFFORT_COLOR = { quick_win: '#00c853', medium_effort: '#ff9800', strategic: '#7c4dff' };
  const EFFORT_LABEL = { quick_win: 'Quick Win', medium_effort: 'Medium Effort', strategic: 'Strategic' };

  return (
    <Card
      title="AI COVERAGE ANALYSIS"
      sub={lastRun ? `Last analyzed: ${fmtTs(new Date(lastRun).toISOString())}` : 'Run AI analysis to get gap recommendations'}
      actions={
        <button className="btn btn-primary" onClick={runAnalysis} disabled={running} style={{ fontSize: 11 }}>
          {running ? 'Analyzing…' : analysis ? 'Re-run Analysis' : 'Run AI Analysis'}
        </button>
      }
    >
      {running && (
        <div className="loading mono" style={{ padding: '0.75rem', textAlign: 'center', marginBottom: 12 }}>
          AI is analyzing {gaps.length} coverage gaps using available log sources…
        </div>
      )}

      {/* Log sources summary */}
      {logSources.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 6 }}>ACTIVE LOG SOURCES (from MITRE-mapped alerts)</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {logSources.map(s => <Chip key={s} mono>{s}</Chip>)}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="seg" style={{ marginBottom: 16 }}>
        {TABS.map(t => (
          <button key={t.id} className={`seg-btn ${tab === t.id ? 'on' : ''}`}
            style={{ fontSize: 11 }} onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {/* Tactic breakdown */}
      {tab === 'tactic' && (
        <div>
          {tacticBreakdown.map(t => (
            <div key={t.id} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                <span style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--fg)' }}>{t.name}</span>
                <span style={{ fontSize: 11, fontFamily: 'var(--mono)', color: t.pct >= 50 ? 'var(--ok)' : t.pct >= 25 ? 'var(--warn)' : 'var(--crit)' }}>
                  {t.covered}/{t.total} ({t.pct}%)
                </span>
              </div>
              <div style={{ height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 3,
                  width: `${t.pct}%`,
                  background: t.pct >= 50 ? 'var(--ok)' : t.pct >= 25 ? 'var(--warn)' : 'var(--crit)',
                  transition: 'width 0.5s ease',
                }} />
              </div>
              {/* From AI analysis if available */}
              {analysis?.tactic_breakdown && (() => {
                const norm = t.name.toLowerCase().replace(/\s+/g, '_').replace(/-/g, '_');
                const ai   = analysis.tactic_breakdown.find(x => x.tactic === norm);
                return ai ? (
                  <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', marginTop: 2 }}>
                    AI: {ai.covered} covered · {ai.gaps} gaps
                  </div>
                ) : null;
              })()}
            </div>
          ))}
        </div>
      )}

      {/* Coverage gaps with AI analysis */}
      {tab === 'gaps' && (
        <div>
          {!analysis && (
            <div style={{ marginBottom: 12, padding: '10px 14px', background: 'rgba(0,229,255,0.06)', border: '1px solid rgba(0,229,255,0.15)', borderRadius: 6, fontSize: 12, color: 'var(--fg-2)' }}>
              Run AI Analysis to get why these gaps exist and what detection opportunities are available.
            </div>
          )}
          <table className="data-table" style={{ fontSize: 11 }}>
            <thead>
              <tr>
                <th>TECHNIQUE</th>
                <th>TACTIC(S)</th>
                {analysis?.gap_analysis?.length > 0 && <>
                  <th>WHY MISSING</th>
                  <th>DETECTION OPPORTUNITY</th>
                </>}
              </tr>
            </thead>
            <tbody>
              {gaps.slice(0, 50).map(g => {
                const ai = analysis?.gap_analysis?.find(x => x.id === g.id);
                return (
                  <tr key={g.id}>
                    <td>
                      <span className="mono" style={{ color: 'var(--crit)', marginRight: 6 }}>{g.id}</span>
                      <span style={{ color: 'var(--fg-2)' }}>{g.name}</span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {g.tactics.map(ta => {
                          const t = MITRE_TACTICS.find(x => x.id === ta);
                          return <Chip key={ta} mono tone="dim" style={{ fontSize: 9 }}>{t?.short || ta}</Chip>;
                        })}
                      </div>
                    </td>
                    {analysis?.gap_analysis?.length > 0 && <>
                      <td style={{ maxWidth: 220, fontSize: 10, color: 'var(--fg-3)' }}>{ai?.why_missing || '—'}</td>
                      <td style={{ maxWidth: 240, fontSize: 10, color: 'var(--ok)' }}>{ai?.detection_opportunity || '—'}</td>
                    </>}
                  </tr>
                );
              })}
            </tbody>
          </table>
          {gaps.length > 50 && (
            <div style={{ fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--mono)', marginTop: 8, textAlign: 'center' }}>
              Showing top 50 of {gaps.length} uncovered techniques
            </div>
          )}
        </div>
      )}

      {/* Recommendations */}
      {tab === 'recs' && (
        <div>
          {!analysis?.recommendations?.length ? (
            <div className="empty mono" style={{ fontSize: 12 }}>
              {running ? 'Generating recommendations…' : 'Run AI Analysis to generate actionable detection recommendations.'}
            </div>
          ) : (
            <div>
              {['quick_win', 'medium_effort', 'strategic'].map(effort => {
                const recs = analysis.recommendations.filter(r => r.effort === effort);
                if (!recs.length) return null;
                return (
                  <div key={effort} style={{ marginBottom: 20 }}>
                    <div style={{
                      fontSize: 11, fontFamily: 'var(--mono)', letterSpacing: '0.06em',
                      color: EFFORT_COLOR[effort], marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8,
                    }}>
                      <span style={{ width: 8, height: 8, borderRadius: 2, background: EFFORT_COLOR[effort], display: 'inline-block' }} />
                      {EFFORT_LABEL[effort]} ({recs.length})
                    </div>
                    {recs.map((r, i) => (
                      <div key={i} style={{
                        background: 'var(--bg-2)', border: `1px solid ${EFFORT_COLOR[effort]}33`,
                        borderLeft: `3px solid ${EFFORT_COLOR[effort]}`,
                        borderRadius: 6, padding: '10px 14px', marginBottom: 8,
                      }}>
                        <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--fg)', marginBottom: 4 }}>{r.title}</div>
                        <div style={{ fontSize: 11, color: 'var(--ok)', marginBottom: 6 }}>{r.impact}</div>
                        <div style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 8 }}>{r.steps}</div>
                        {r.techniques_covered?.length > 0 && (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                            {r.techniques_covered.map(t => (
                              <Chip key={t} mono style={{ fontSize: 9 }}>{t}</Chip>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                );
              })}
              {analysis.models_used && (
                <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', marginTop: 8 }}>
                  Models: gap prioritization={analysis.models_used.gap_prioritization} · recommendations={analysis.models_used.recommendations}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Unmapped rules (no MITRE tag) */}
      {tab === 'unmapped' && (
        <div>
          {auditLoad ? (
            <div className="loading mono" style={{ padding: '1rem', textAlign: 'center' }}>Loading unmapped rules audit…</div>
          ) : !auditData ? (
            <div className="empty mono">Could not load audit data.</div>
          ) : (
            <div>
              <div style={{ marginBottom: 14, display: 'flex', gap: 24 }}>
                <DetailCell label="Alerts Without MITRE Tag" value={auditData.total_unmapped?.toLocaleString() || '0'} mono accent />
                <DetailCell label="Log Sources with Gaps"    value={auditData.by_decoder?.length || '0'} mono />
                <DetailCell label="Unmapped Rule IDs"        value={auditData.top_rules?.length || '0'} mono />
              </div>

              {auditData.by_decoder?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 8 }}>
                    UNMAPPED RULES BY LOG SOURCE
                  </div>
                  {auditData.by_decoder.map(d => (
                    <div key={d.decoder} style={{ marginBottom: 10, padding: '10px 14px', background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 6 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <span className="mono" style={{ color: 'var(--acc)', fontSize: 12 }}>{d.decoder}</span>
                        <span className="mono" style={{ color: 'var(--fg-3)', fontSize: 11 }}>{d.count.toLocaleString()} alerts</span>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                        {d.top_rules?.map(r => (
                          <div key={r.id} style={{ display: 'flex', gap: 12, fontSize: 11, alignItems: 'center' }}>
                            <span className="mono" style={{ color: 'var(--warn)', minWidth: 60 }}>{r.id}</span>
                            <SevChip sev={r.severity} />
                            <span className="mono" style={{ color: 'var(--fg-3)', fontSize: 10, minWidth: 50 }}>{r.count.toLocaleString()} hits</span>
                            <span style={{ color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div>
                <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 8 }}>
                  TOP UNMAPPED RULES (candidate for MITRE mapping)
                </div>
                <table className="data-table" style={{ fontSize: 11 }}>
                  <thead><tr><th>RULE ID</th><th>LEVEL</th><th>SEV</th><th>LOG SOURCE</th><th>ALERTS</th><th>DESCRIPTION</th></tr></thead>
                  <tbody>
                    {auditData.top_rules?.map(r => (
                      <tr key={r.id}>
                        <td className="mono" style={{ color: 'var(--warn)' }}>{r.id}</td>
                        <td className="mono">{r.level}</td>
                        <td><SevChip sev={r.severity} /></td>
                        <td className="mono" style={{ color: 'var(--acc)' }}>{r.decoder}</td>
                        <td className="mono">{r.count.toLocaleString()}</td>
                        <td style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div style={{ marginTop: 12, padding: '10px 14px', background: 'rgba(255,152,0,0.06)', border: '1px solid rgba(255,152,0,0.2)', borderRadius: 6, fontSize: 11, color: 'var(--fg-2)' }}>
                  These rules are firing but have no <span className="mono" style={{ color: 'var(--warn)' }}>rule.mitre.id</span> tag.
                  Map them in your Wazuh ruleset to improve ATT&CK coverage accuracy.
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

// ── Small helper components ───────────────────────────────────────────────────

function StatCard({ label, value, color, sub }) {
  return (
    <div className="kpi">
      <div className="kpi-label">{label}</div>
      <div className="kpi-value mono" style={{ color }}>{value}</div>
      {sub && <div className="kpi-foot"><span className="kpi-sub">{sub}</span></div>}
    </div>
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

function MiniBar({ data }) {
  const max = Math.max(...data.map(d => d.count), 1);
  return (
    <div style={{ display: 'flex', gap: 2, alignItems: 'flex-end', height: 40 }}>
      {data.map((d, i) => (
        <div key={i} title={`${d.date}: ${d.count}`} style={{
          flex: 1,
          height: `${Math.max(2, Math.round((d.count / max) * 40))}px`,
          background: d.count > 0 ? 'var(--acc)' : 'rgba(255,255,255,0.06)',
          borderRadius: 2, opacity: 0.8,
        }} />
      ))}
    </div>
  );
}

// ── Export ────────────────────────────────────────────────────────────────────

Object.assign(window, { PageMitre });
