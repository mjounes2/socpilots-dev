// Agents · Detection Rules · Vulnerabilities · Reports
const { useState: useStateS, useMemo: useMemoS } = React;

// ============= AGENTS =============
const AGENTS = [
  { id: '003', name: 'web-prod-01',  os: 'Ubuntu 22.04', ver: '4.7.5', ip: '10.0.4.122', last: '2s',   alerts: 412, status: 'active',   group: 'web',     cpu: 32, mem: 68 },
  { id: '004', name: 'web-prod-02',  os: 'Ubuntu 22.04', ver: '4.7.5', ip: '10.0.4.123', last: '4s',   alerts: 87,  status: 'active',   group: 'web',     cpu: 24, mem: 51 },
  { id: '007', name: 'db-primary',   os: 'Debian 12',    ver: '4.7.5', ip: '10.0.4.18',  last: '12s',  alerts: 287, status: 'active',   group: 'data',    cpu: 71, mem: 84 },
  { id: '008', name: 'db-replica',   os: 'Debian 12',    ver: '4.7.4', ip: '10.0.4.19',  last: '8s',   alerts: 4,   status: 'active',   group: 'data',    cpu: 48, mem: 62 },
  { id: '011', name: 'win-dc-01',    os: 'Win Srv 2022', ver: '4.7.5', ip: '10.0.4.45',  last: '4s',   alerts: 198, status: 'active',   group: 'identity',cpu: 38, mem: 71 },
  { id: '012', name: 'win-dc-02',    os: 'Win Srv 2022', ver: '4.7.5', ip: '10.0.4.46',  last: '6s',   alerts: 12,  status: 'active',   group: 'identity',cpu: 22, mem: 48 },
  { id: '015', name: 'mail-gw-01',   os: 'Rocky 9',      ver: '4.7.5', ip: '10.0.4.7',   last: '1m',   alerts: 154, status: 'active',   group: 'edge',    cpu: 41, mem: 56 },
  { id: '022', name: 'jump-host',    os: 'Ubuntu 22.04', ver: '4.7.5', ip: '10.0.4.99',  last: '3s',   alerts: 89,  status: 'active',   group: 'access',  cpu: 18, mem: 34 },
  { id: '023', name: 'jump-host-2',  os: 'Ubuntu 22.04', ver: '4.7.3', ip: '10.0.4.100', last: '11s',  alerts: 3,   status: 'active',   group: 'access',  cpu: 12, mem: 28 },
  { id: '028', name: 'k8s-worker-3', os: 'Talos 1.6',    ver: '4.7.5', ip: '10.0.5.13',  last: '4h',   alerts: 0,   status: 'offline',  group: 'platform',cpu: 0,  mem: 0  },
  { id: '029', name: 'k8s-worker-1', os: 'Talos 1.6',    ver: '4.7.5', ip: '10.0.5.11',  last: '3s',   alerts: 18,  status: 'active',   group: 'platform',cpu: 67, mem: 79 },
  { id: '030', name: 'k8s-worker-2', os: 'Talos 1.6',    ver: '4.7.5', ip: '10.0.5.12',  last: '5s',   alerts: 7,   status: 'active',   group: 'platform',cpu: 58, mem: 72 },
  { id: '034', name: 'macbook-yj',   os: 'macOS 14.4',   ver: '4.7.4', ip: '10.0.8.41',  last: '2m',   alerts: 2,   status: 'active',   group: 'endpoint',cpu: 8,  mem: 41 },
  { id: '041', name: 'lab-vm-01',    os: 'Kali 2024.2',  ver: '4.7.2', ip: '10.0.9.5',   last: '1d',   alerts: 0,   status: 'offline',  group: 'lab',     cpu: 0,  mem: 0  },
];

function PageAgents() {
  const [filter, setFilter] = useStateS('all');
  const [group, setGroup] = useStateS('all');
  const groups = ['all', ...Array.from(new Set(AGENTS.map(a => a.group)))];
  const filtered = AGENTS.filter(a => (filter === 'all' || a.status === filter) && (group === 'all' || a.group === group));
  const active = AGENTS.filter(a => a.status === 'active').length;
  const offline = AGENTS.filter(a => a.status === 'offline').length;
  const outdated = AGENTS.filter(a => a.ver !== '4.7.5').length;

  return (
    <div className="page" data-screen-label="08 Agents">
      <Topbar
        title="Agents"
        sub="Wazuh monitored endpoints"
        actions={<>
          <button className="btn btn-ghost"><Icon.refresh width="13" height="13"/> Sync</button>
          <button className="btn btn-ghost">Export CSV</button>
          <button className="btn btn-primary"><Icon.plus width="13" height="13"/> Enroll agent</button>
        </>}
      />
      <div className="page-body">
        <div className="kpi-grid" style={{gridTemplateColumns:'repeat(4,1fr)'}}>
          <KpiCard label="Total agents" value={AGENTS.length} sub="across 7 groups"/>
          <KpiCard label="Active" value={active} sub="last seen ≤ 1m" />
          <KpiCard label="Offline" value={offline} sub="> 6h silent" sev={offline > 0 ? 'critical' : undefined} />
          <KpiCard label="Outdated" value={outdated} sub="needs update to 4.7.5" />
        </div>

        <Card title="Endpoints" sub={`${filtered.length} of ${AGENTS.length}`}
          actions={<>
            <div className="seg">
              {['all','active','offline'].map(s => (
                <button key={s} className={`seg-btn ${filter===s?'on':''}`} onClick={()=>setFilter(s)}>
                  {s !== 'all' && <SevDot sev={s==='active'?'low':'offline'} size={6}/>}
                  {s}
                </button>
              ))}
            </div>
            <select className="select-mini mono" value={group} onChange={e=>setGroup(e.target.value)}>
              {groups.map(g => <option key={g} value={g}>group: {g}</option>)}
            </select>
          </>}>
          <table className="data-table">
            <thead><tr>
              <th style={{width:8}}></th>
              <th style={{width:50}}>ID</th>
              <th>NAME</th>
              <th>OS</th>
              <th>VERSION</th>
              <th>IP</th>
              <th>LAST SEEN</th>
              <th>CPU</th>
              <th>MEM</th>
              <th>ALERTS 24H</th>
              <th></th>
            </tr></thead>
            <tbody>
              {filtered.map(a => (
                <tr key={a.id}>
                  <td><span className="sev-bar" data-sev={a.status==='active'?'low':'offline'} style={{height:18}}/></td>
                  <td className="mono dim">#{a.id}</td>
                  <td className="mono">{a.name}</td>
                  <td>{a.os}</td>
                  <td className="mono dim">{a.ver}{a.ver!=='4.7.5' && <span className="ver-warn">↑</span>}</td>
                  <td className="mono">{a.ip}</td>
                  <td className="mono dim">{a.last}</td>
                  <td><MiniGauge value={a.cpu}/></td>
                  <td><MiniGauge value={a.mem}/></td>
                  <td className="mono">{a.alerts}</td>
                  <td><button className="btn-icon" onClick={() => window.socToast?.({title:'Agent action', sub:a.name+' · isolated', tone:'crit'})}><Icon.chevron width="12" height="12"/></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
}

function MiniGauge({ value }) {
  if (value === 0) return <span className="mono dim">—</span>;
  const tone = value > 80 ? 'critical' : value > 60 ? 'high' : value > 40 ? 'medium' : 'low';
  return (
    <div className="mini-gauge">
      <div className="mg-track"><div className="mg-fill" data-sev={tone} style={{width:`${value}%`}}/></div>
      <span className="mono">{value}%</span>
    </div>
  );
}

// ============= DETECTION RULES =============
const RULES = [
  { id: '92653', level: 13, name: 'Suspicious PowerShell execution',          tactic: 'Execution',         technique: 'T1059.001', triggered: 156, enabled: true,  category: 'windows', custom: false },
  { id: '5710',  level: 10, name: 'Multiple authentication failures',          tactic: 'Credential Access',technique: 'T1110',     triggered: 284, enabled: true,  category: 'auth',    custom: false },
  { id: '31151', level: 12, name: 'Web exploit attempt — SQL injection',       tactic: 'Initial Access',    technique: 'T1190',     triggered: 142, enabled: true,  category: 'web',     custom: false },
  { id: '40111', level: 14, name: 'Process injection detected',                tactic: 'Defense Evasion',   technique: 'T1055',     triggered: 76,  enabled: true,  category: 'edr',     custom: false },
  { id: '60106', level: 12, name: 'Windows audit log cleared',                 tactic: 'Defense Evasion',   technique: 'T1070.001', triggered: 41,  enabled: true,  category: 'windows', custom: false },
  { id: '11302', level: 8,  name: 'Remote Desktop session opened',             tactic: 'Lateral Movement',  technique: 'T1021.001', triggered: 38,  enabled: true,  category: 'auth',    custom: false },
  { id: '92900', level: 12, name: 'Kerberoasting attempt',                     tactic: 'Credential Access',technique: 'T1558.003', triggered: 8,   enabled: true,  category: 'ad',      custom: true  },
  { id: '60103', level: 11, name: 'Credential dumping (LSASS access)',         tactic: 'Credential Access',technique: 'T1003.001', triggered: 12,  enabled: true,  category: 'edr',     custom: false },
  { id: '92805', level: 13, name: 'Cobalt Strike beacon hash match',           tactic: 'Command & Control', technique: 'T1071',     triggered: 4,   enabled: true,  category: 'threat',  custom: true  },
  { id: '5503',  level: 3,  name: 'PAM: user login session opened',            tactic: 'Initial Access',    technique: 'T1078',     triggered: 98,  enabled: false, category: 'auth',    custom: false },
  { id: '92107', level: 9,  name: 'Outbound to Tor exit node',                 tactic: 'Command & Control', technique: 'T1090.003', triggered: 31,  enabled: true,  category: 'net',     custom: true  },
  { id: '92450', level: 11, name: 'Scheduled task created — suspicious path',  tactic: 'Persistence',       technique: 'T1053.005', triggered: 14,  enabled: true,  category: 'windows', custom: false },
];
const TACTICS = ['all','Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion','Credential Access','Discovery','Lateral Movement','Command & Control','Exfiltration'];

function PageRules() {
  const [tactic, setTactic] = useStateS('all');
  const [search, setSearch] = useStateS('');
  const [enabled, setEnabled] = useStateS(RULES.reduce((a,r) => ({...a, [r.id]: r.enabled}), {}));
  const filtered = RULES.filter(r =>
    (tactic === 'all' || r.tactic === tactic) &&
    (!search || (r.name + r.technique + r.id).toLowerCase().includes(search.toLowerCase()))
  );
  const totalEnabled = Object.values(enabled).filter(Boolean).length;
  const custom = RULES.filter(r => r.custom).length;

  return (
    <div className="page" data-screen-label="09 Detection Rules">
      <Topbar
        title="Detection Rules"
        sub="Active ruleset · MITRE ATT&CK mapped"
        actions={<>
          <button className="btn btn-ghost">Import</button>
          <button className="btn btn-ghost">Export</button>
          <button className="btn btn-primary"><Icon.plus width="13" height="13"/> New rule</button>
        </>}
      />
      <div className="page-body">
        <div className="kpi-grid" style={{gridTemplateColumns:'repeat(4,1fr)'}}>
          <KpiCard label="Total rules" value={RULES.length} sub="loaded from ruleset" />
          <KpiCard label="Enabled" value={totalEnabled} sub={`${RULES.length - totalEnabled} disabled`} />
          <KpiCard label="Custom" value={custom} sub="tuned for this env" />
          <KpiCard label="Triggered (24h)" value={RULES.reduce((a,r)=>a+r.triggered,0).toLocaleString()} sub="across all rules" />
        </div>

        <Card title="Ruleset" sub={`${filtered.length} of ${RULES.length} rules`}
          actions={<>
            <div className="tb-search rules-search">
              <Icon.search width="13" height="13"/>
              <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="search id, name, MITRE…"/>
            </div>
          </>}>
          <div className="tactic-pills">
            {TACTICS.map(tc => (
              <button key={tc} className={`tactic-pill ${tactic===tc?'on':''}`} onClick={()=>setTactic(tc)}>
                {tc === 'all' ? 'all tactics' : tc}
                {tactic === tc && <span className="tp-count mono">{filtered.length}</span>}
              </button>
            ))}
          </div>
          <table className="data-table">
            <thead><tr>
              <th style={{width:60}}>ID</th>
              <th style={{width:60}}>LEVEL</th>
              <th>NAME</th>
              <th>TACTIC</th>
              <th>TECHNIQUE</th>
              <th style={{width:120}}>TRIGGERED 24H</th>
              <th style={{width:80}}>STATUS</th>
            </tr></thead>
            <tbody>
              {filtered.map(r => (
                <tr key={r.id}>
                  <td className="mono dim">{r.id}{r.custom && <span className="custom-badge mono">⊕</span>}</td>
                  <td><LevelChip level={r.level}/></td>
                  <td>{r.name}</td>
                  <td className="dim">{r.tactic}</td>
                  <td className="mono"><a href="#" className="link">{r.technique}</a></td>
                  <td><div className="bar-wrap"><div className="bar" data-sev={r.level>=12?'critical':r.level>=10?'high':r.level>=7?'medium':'low'} style={{width:`${Math.min(100,r.triggered/3)}%`}}/><span className="bar-val mono">{r.triggered}</span></div></td>
                  <td>
                    <button
                      className={`toggle ${enabled[r.id]?'on':''}`}
                      onClick={() => { setEnabled(e => ({...e, [r.id]: !e[r.id]})); window.socToast?.({title: enabled[r.id] ? 'Rule disabled' : 'Rule enabled', sub: r.id + ' · ' + r.name, tone: enabled[r.id]?'default':'ok'}); }}
                    >
                      <span className="toggle-thumb"/>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
}

function LevelChip({ level }) {
  const sev = level >= 12 ? 'critical' : level >= 10 ? 'high' : level >= 7 ? 'medium' : 'low';
  return <span className="level-chip mono" data-sev={sev}>L{level}</span>;
}

// ============= VULNERABILITIES =============
const VULNS = [
  { cve: 'CVE-2026-1142', cvss: 9.8, sev: 'critical', pkg: 'openssh-server', ver: '8.9p1-3', fix: '8.9p1-5', hosts: 12, status: 'open',     age: '4d', published: '2026-05-09' },
  { cve: 'CVE-2026-0934', cvss: 9.1, sev: 'critical', pkg: 'log4j',          ver: '2.17.0',  fix: '2.22.1',  hosts: 3,  status: 'open',     age: '6d', published: '2026-05-07' },
  { cve: 'CVE-2025-9847', cvss: 8.4, sev: 'high',     pkg: 'nginx',          ver: '1.24.0',  fix: '1.26.2',  hosts: 8,  status: 'in-progress', age: '11d', published: '2025-05-02' },
  { cve: 'CVE-2026-0815', cvss: 8.1, sev: 'high',     pkg: 'curl',           ver: '7.88.1',  fix: '8.7.1',   hosts: 28, status: 'open',     age: '7d', published: '2026-05-06' },
  { cve: 'CVE-2026-0719', cvss: 7.5, sev: 'high',     pkg: 'glibc',          ver: '2.36-1',  fix: '2.36-3',  hosts: 32, status: 'open',     age: '9d', published: '2026-05-04' },
  { cve: 'CVE-2026-0623', cvss: 7.2, sev: 'high',     pkg: 'postgresql',     ver: '15.4',    fix: '15.7',    hosts: 4,  status: 'in-progress', age: '12d', published: '2026-05-01' },
  { cve: 'CVE-2025-9712', cvss: 6.8, sev: 'medium',   pkg: 'redis',          ver: '7.0.11',  fix: '7.2.4',   hosts: 6,  status: 'open',     age: '15d', published: '2025-04-28' },
  { cve: 'CVE-2025-9645', cvss: 6.1, sev: 'medium',   pkg: 'nodejs',         ver: '18.19.0', fix: '18.20.2', hosts: 18, status: 'in-progress', age: '18d', published: '2025-04-25' },
  { cve: 'CVE-2025-9512', cvss: 5.3, sev: 'medium',   pkg: 'samba',          ver: '4.17.7',  fix: '4.19.5',  hosts: 2,  status: 'patched',  age: '22d', published: '2025-04-21' },
  { cve: 'CVE-2025-9201', cvss: 3.7, sev: 'low',      pkg: 'sudo',           ver: '1.9.13',  fix: '1.9.15',  hosts: 4,  status: 'wont-fix', age: '28d', published: '2025-04-15' },
];

function PageVulns() {
  const [sev, setSev] = useStateS('all');
  const filtered = sev === 'all' ? VULNS : VULNS.filter(v => v.sev === sev);
  const crit = VULNS.filter(v => v.sev === 'critical').length;
  const high = VULNS.filter(v => v.sev === 'high').length;
  const patched = VULNS.filter(v => v.status === 'patched').length;
  const patchedPct = Math.round(patched / VULNS.length * 100);

  return (
    <div className="page" data-screen-label="10 Vulnerabilities">
      <Topbar
        title="Vulnerabilities"
        sub="CVE feed · SOCPilots AI enriched"
        actions={<>
          <button className="btn btn-ghost"><Icon.refresh width="13" height="13"/> Re-scan</button>
          <button className="btn btn-ghost">Export SBOM</button>
          <button className="btn btn-primary">Patch plan</button>
        </>}
      />
      <div className="page-body">
        <div className="kpi-grid" style={{gridTemplateColumns:'repeat(4,1fr)'}}>
          <KpiCard label="Open CVEs" value={VULNS.filter(v=>v.status==='open').length} sub="across 156 agents" />
          <KpiCard label="Critical" value={crit} sub="CVSS ≥ 9.0" sev="critical" />
          <KpiCard label="High" value={high} sub="CVSS 7.0–8.9" />
          <KpiCard label="Patched (30d)" value={`${patchedPct}%`} sub={`${patched} of ${VULNS.length}`} />
        </div>

        <Card title="CVE feed" sub={`${filtered.length} vulnerabilities`}
          actions={<>
            <div className="seg">
              {['all','critical','high','medium','low'].map(s => (
                <button key={s} className={`seg-btn ${sev===s?'on':''}`} onClick={()=>setSev(s)}>
                  {s !== 'all' && <SevDot sev={s} size={6}/>}
                  {s}
                </button>
              ))}
            </div>
          </>}>
          <table className="data-table">
            <thead><tr>
              <th>CVE</th>
              <th style={{width:70}}>CVSS</th>
              <th style={{width:80}}>SEVERITY</th>
              <th>PACKAGE</th>
              <th>INSTALLED</th>
              <th>FIX</th>
              <th style={{width:110}}>HOSTS</th>
              <th style={{width:100}}>STATUS</th>
              <th style={{width:60}}>AGE</th>
            </tr></thead>
            <tbody>
              {filtered.map(v => (
                <tr key={v.cve}>
                  <td className="mono"><a href="#" className="link">{v.cve}</a></td>
                  <td><CvssChip score={v.cvss}/></td>
                  <td><SevChip sev={v.sev}/></td>
                  <td className="mono">{v.pkg}</td>
                  <td className="mono dim">{v.ver}</td>
                  <td className="mono">{v.fix}</td>
                  <td><div className="bar-wrap"><div className="bar" data-sev={v.sev} style={{width:`${Math.min(100,v.hosts*3)}%`}}/><span className="bar-val mono">{v.hosts}</span></div></td>
                  <td><StatusChip status={v.status}/></td>
                  <td className="mono dim">{v.age}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
}

function CvssChip({ score }) {
  const sev = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
  return <span className="cvss-chip mono" data-sev={sev}>{score.toFixed(1)}</span>;
}
function StatusChip({ status }) {
  const tone = status === 'open' ? 'crit' : status === 'in-progress' ? 'warn' : status === 'patched' ? 'ok' : 'dim';
  return <Chip mono tone={tone}>{status}</Chip>;
}

// ============= REPORTS =============
const REPORTS = [
  { id: 'RPT-2026-019', title: 'Executive · Week 19', range: 'May 6 – May 13', author: 'AI · younes', status: 'draft', pages: 6, when: 'now' },
  { id: 'RPT-2026-018', title: 'Executive · Week 18', range: 'Apr 29 – May 6', author: 'AI · younes', status: 'sent', pages: 6, when: '7d ago' },
  { id: 'RPT-2026-017', title: 'Compliance · ISO 27001', range: 'Apr 1 – Apr 30', author: 'AI · sara', status: 'sent', pages: 14, when: '13d ago' },
  { id: 'RPT-2026-016', title: 'Incident · CASE-4438 retro', range: 'Apr 22', author: 'younes', status: 'sent', pages: 9, when: '21d ago' },
];

function PageReports() {
  const [selectedId, setSelectedId] = useStateS('RPT-2026-019');
  const selected = REPORTS.find(r => r.id === selectedId);

  return (
    <div className="page" data-screen-label="11 Reports">
      <Topbar
        title="Reports"
        sub="AI-drafted exec summaries · compliance · incident retros"
        actions={<>
          <button className="btn btn-ghost">Templates</button>
          <button className="btn btn-ghost">Schedule</button>
          <button className="btn btn-primary" onClick={() => window.socToast?.({title:'Generating report', sub:'AI draft · 6 pages · ~30s', tone:'info'})}><Icon.brain width="13" height="13"/> Generate</button>
        </>}
      />
      <div className="page-body">
        <div className="reports-layout">
          <aside className="reports-side">
            <Card title="Reports" sub={`${REPORTS.length} total`} padded={true}>
              <ul className="report-list">
                {REPORTS.map(r => (
                  <li key={r.id}>
                    <button className={`report-item ${selectedId===r.id?'on':''}`} onClick={()=>setSelectedId(r.id)}>
                      <div className="ri-head">
                        <span className="ri-id mono">{r.id}</span>
                        <Chip mono tone={r.status === 'sent' ? 'ok' : 'warn'}>{r.status}</Chip>
                      </div>
                      <div className="ri-title">{r.title}</div>
                      <div className="ri-meta mono">{r.range} · {r.pages}pp · {r.when}</div>
                    </button>
                  </li>
                ))}
              </ul>
            </Card>

            <Card title="Distribution" sub="auto-deliver">
              <div className="dist-row">
                <Icon.inbox width="14" height="14"/>
                <span>ciso@socpilots.com</span>
              </div>
              <div className="dist-row">
                <Icon.inbox width="14" height="14"/>
                <span>soc-leads@socpilots.com</span>
              </div>
              <div className="dist-row">
                <Icon.share width="14" height="14"/>
                <span>Slack #soc-execs</span>
              </div>
              <button className="btn btn-ghost btn-sm" style={{marginTop:10}}><Icon.plus width="11" height="11"/> Add recipient</button>
            </Card>
          </aside>

          <main className="reports-main">
            {selected && <ReportPreview r={selected} />}
          </main>
        </div>
      </div>
    </div>
  );
}

function ReportPreview({ r }) {
  return (
    <Card title={r.title} sub={r.range + ' · ' + r.author}
      actions={<>
        <Chip mono tone={r.status === 'sent' ? 'ok' : 'warn'}>{r.status}</Chip>
        <button className="btn btn-ghost btn-sm">Edit</button>
        <button className="btn btn-ghost btn-sm">PDF</button>
        <button className="btn btn-primary btn-sm" onClick={() => window.socToast?.({title:'Report sent', sub: 'delivered to 3 recipients', tone:'ok'})}>Send</button>
      </>}>
      <div className="report-doc">
        <div className="rd-header">
          <div className="rd-brand">
            <div className="rd-mark">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
                <path d="M12 2L20 7V17L12 22L4 17V7Z"/><circle cx="12" cy="12" r="3" fill="currentColor"/>
              </svg>
            </div>
            <div>
              <div className="rd-brand-name">SOC<span>PILOTS</span></div>
              <div className="rd-brand-sub mono">{r.id} · CONFIDENTIAL</div>
            </div>
          </div>
          <div className="rd-meta mono">
            <div>Period · {r.range}</div>
            <div>Author · {r.author}</div>
            <div>Pages · {r.pages}</div>
          </div>
        </div>

        <section className="rd-section">
          <h3 className="rd-h3"><span className="rd-num">01</span> Executive summary</h3>
          <p>This week the SOC processed <strong>1,847 alerts</strong> across <strong>156 endpoints</strong>, opening <strong>23 cases</strong> of which 7 remain active. Mean time to detect improved 18% week-over-week to <strong>4m 12s</strong>; mean time to respond held at <strong>38m</strong>. The single most significant event was an <strong>active intrusion on web-prod-01</strong> (CASE-4471) traced to Tor exit <span className="mono">185.220.101.42</span>; contained in 12 minutes with no data exfiltration confirmed.</p>
        </section>

        <section className="rd-section">
          <h3 className="rd-h3"><span className="rd-num">02</span> Top threats</h3>
          <ol className="rd-list">
            <li><strong>PowerShell-based intrusions</strong> — 4 incidents, all from Tor or known-bad IPs. T1059.001 dominant.</li>
            <li><strong>Credential brute-force</strong> — 284 rule-5710 hits, mostly noise but 1 promoted to case.</li>
            <li><strong>Kerberoasting probing</strong> — first time observed in 30d. Likely targeted reconnaissance.</li>
          </ol>
        </section>

        <section className="rd-section rd-grid">
          <div>
            <div className="rd-stat-label">Alerts this week</div>
            <div className="rd-stat-value">12,847</div>
            <div className="rd-stat-trend up">↑ 8.4% vs last week</div>
          </div>
          <div>
            <div className="rd-stat-label">Cases opened</div>
            <div className="rd-stat-value">23</div>
            <div className="rd-stat-trend down">↓ 12% vs last week</div>
          </div>
          <div>
            <div className="rd-stat-label">MTTD</div>
            <div className="rd-stat-value">4m 12s</div>
            <div className="rd-stat-trend down">↓ 18% (improving)</div>
          </div>
          <div>
            <div className="rd-stat-label">MTTR</div>
            <div className="rd-stat-value">38m 04s</div>
            <div className="rd-stat-trend flat">stable</div>
          </div>
        </section>

        <section className="rd-section">
          <h3 className="rd-h3"><span className="rd-num">03</span> Recommendations</h3>
          <ul className="rd-list">
            <li>Prioritize patching CVE-2026-1142 (openssh) — affects 12 hosts, including web-prod-01.</li>
            <li>Tighten egress filtering at the perimeter; 31 outbound Tor connections this week.</li>
            <li>Add detection for service-account → PowerShell launches; currently relies on level-13 fallback.</li>
            <li>Schedule quarterly purple-team exercise focused on lateral movement (T1021).</li>
          </ul>
        </section>

        <footer className="rd-foot mono">SOC Pilots · {r.id} · Generated {r.when} · AI-drafted, human-approved</footer>
      </div>
    </Card>
  );
}

Object.assign(window, { PageAgents, PageRules, PageVulns, PageReports });
