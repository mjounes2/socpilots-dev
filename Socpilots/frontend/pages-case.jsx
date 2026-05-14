// SP-CM Case detail — full incident record view
const { useState: useStateC, useMemo: useMemoC } = React;

const CASE_TIMELINE = [
  { t: '14:22:47', who: 'system',  type: 'create',  txt: 'Case opened from alert WZ-9281047', tone: 'crit' },
  { t: '14:22:51', who: 'AI',      type: 'analyze', txt: 'Severity classified as P1 / critical · confidence 96%', tone: 'info' },
  { t: '14:23:02', who: 'system',  type: 'auto',    txt: 'IR runbook auto-attached · template "PowerShell intrusion"', tone: 'default' },
  { t: '14:23:18', who: 'younes',  type: 'assign',  txt: 'Self-assigned · taking lead', tone: 'default' },
  { t: '14:24:02', who: 'AI',      type: 'enrich',  txt: 'IOC enrichment complete · 185.220.101.42 flagged by 4 sources', tone: 'info' },
  { t: '14:25:11', who: 'younes',  type: 'action',  txt: 'Step 1 marked complete · Verified true positive', tone: 'ok' },
  { t: '14:27:42', who: 'younes',  type: 'action',  txt: 'Initiated isolation of web-prod-01', tone: 'crit' },
  { t: '14:27:46', who: 'system',  type: 'auto',    txt: 'web-prod-01 cordoned via Wazuh active-response', tone: 'crit' },
  { t: '14:28:11', who: 'younes',  type: 'comment', txt: 'Confirmed payload is Cobalt Strike loader. Checking lateral movement.', tone: 'default' },
  { t: '14:31:04', who: 'system',  type: 'auto',    txt: 'Firewall block rule deployed · 185.220.101.42', tone: 'crit' },
  { t: '14:34:22', who: 'AI',      type: 'hunt',    txt: 'Cross-fleet hunt for hash a4f8b2c… → 0 additional matches', tone: 'ok' },
];

const CASE_OBSERVABLES = [
  { type: 'ip',     value: '185.220.101.42',           tags: ['tor-exit', 'c2'],     intel: { vt: 18, abuse: 100 }, sighted: 4, ioc: true },
  { type: 'host',   value: 'web-prod-01',              tags: ['affected'],            intel: null, sighted: 47, ioc: false },
  { type: 'user',   value: 'svc_backup',               tags: ['suspended'],           intel: null, sighted: 8,  ioc: false },
  { type: 'hash',   value: 'a4f8b2c91d3e0775fa2b8c…',  tags: ['cobalt-strike'],       intel: { vt: 62 },         sighted: 1, ioc: true },
  { type: 'domain', value: 'malicious-c2.xyz',         tags: ['c2', 'dns-sinkhole'], intel: { vt: 24 },         sighted: 2, ioc: true },
  { type: 'url',    value: 'http://185.220.101.42/payload.bin', tags: ['payload'],   intel: { vt: 24 },         sighted: 1, ioc: true },
];

const CASE_TASKS = [
  { id: 't1', title: 'Verify true positive',           status: 'done',     assignee: 'younes', due: 'completed' },
  { id: 't2', title: 'Isolate web-prod-01',            status: 'done',     assignee: 'younes', due: 'completed' },
  { id: 't3', title: 'Block 185.220.101.42 at edge',   status: 'done',     assignee: 'system', due: 'completed' },
  { id: 't4', title: 'Suspend svc_backup credential',  status: 'in-progress', assignee: 'younes', due: 'in 22m' },
  { id: 't5', title: 'Memory image of web-prod-01',     status: 'todo',     assignee: 'amir',   due: 'in 1h' },
  { id: 't6', title: 'Hunt persistence on fleet',       status: 'todo',     assignee: 'sara',   due: 'in 4h' },
  { id: 't7', title: 'Re-image + restore web-prod-01', status: 'todo',     assignee: null,     due: 'today' },
  { id: 't8', title: 'Post-incident report',           status: 'todo',     assignee: null,     due: 'in 48h' },
];

const CASE_COMMENTS = [
  { who: 'younes', when: '4m ago', text: 'Confirmed payload is Cobalt Strike loader matching the same family from CASE-4438 (3d ago). Same C2 IP. Likely the same actor returning.' },
  { who: 'sara',   when: '2m ago', text: 'Pulled memory + sent to lab. Initial strings suggest the loader was staged from `%APPDATA%\\Microsoft\\Windows`. Will share full triage in 30min.' },
  { who: 'AI',     when: '1m ago', text: 'I cross-referenced the hash against the fleet — no additional matches on the other 155 agents. Containment appears successful. Recommend continuing eradication phase.' },
];

const CASE_LINKED_ALERTS = [
  { id: 'WZ-9281047', rule: 'Suspicious PowerShell execution', mitre: 'T1059.001', sev: 'critical', when: '14:22 UTC' },
  { id: 'WZ-9281024', rule: 'Process injection detected',     mitre: 'T1055',      sev: 'critical', when: '14:21 UTC' },
  { id: 'WZ-9281007', rule: 'Outbound to known C2',            mitre: 'T1071',      sev: 'critical', when: '14:18 UTC' },
];

function CaseDetailSheet({ openCase, onClose, onOpenRunbook }) {
  const [tab, setTab] = useStateC('overview');

  React.useEffect(() => {
    const h = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);

  if (!openCase) return null;

  const tabs = [
    { id: 'overview',   label: 'Overview' },
    { id: 'timeline',   label: 'Timeline',     count: CASE_TIMELINE.length },
    { id: 'observables',label: 'Observables',  count: CASE_OBSERVABLES.length },
    { id: 'tasks',      label: 'Tasks',        count: CASE_TASKS.filter(t=>t.status!=='done').length + '/' + CASE_TASKS.length },
    { id: 'comments',   label: 'Comments',     count: CASE_COMMENTS.length },
    { id: 'alerts',     label: 'Linked alerts',count: CASE_LINKED_ALERTS.length },
  ];

  return (
    <div className="case-overlay" onClick={onClose}>
      <div className="case-sheet" onClick={e => e.stopPropagation()}>
        <header className="case-head">
          <div className="case-head-l">
            <div className="case-eyebrow mono">
              <SevDot sev={openCase.sev}/> {openCase.id} · OPEN {openCase.age} AGO
            </div>
            <h2 className="case-title">{openCase.title}</h2>
            <div className="case-meta">
              <SevChip sev={openCase.sev}/>
              <Chip mono>P1 · critical</Chip>
              <Chip mono><Icon.bell width="10" height="10"/> {openCase.alerts} alerts</Chip>
              {openCase.assignee ? (
                <span className="cc-assignee" style={{fontSize:11}}>
                  <span className="cc-avatar">{openCase.assignee[0].toUpperCase()}</span>{openCase.assignee}
                </span>
              ) : <Chip mono>unassigned</Chip>}
              {openCase.tags.map(t => <Chip key={t} mono>{t}</Chip>)}
            </div>
          </div>
          <div className="case-head-r">
            <button className="btn btn-primary" onClick={() => onOpenRunbook(openCase)}>
              <Icon.brain width="13" height="13"/> Run IR runbook
            </button>
            <button className="btn btn-ghost btn-sm">Share</button>
            <button className="btn-icon" onClick={onClose}><Icon.x width="16" height="16"/></button>
          </div>
        </header>

        <div className="case-tabs">
          {tabs.map(t => (
            <button key={t.id} className={`case-tab ${tab===t.id?'on':''}`} onClick={()=>setTab(t.id)}>
              {t.label}
              {t.count != null && <span className="case-tab-count mono">{t.count}</span>}
            </button>
          ))}
        </div>

        <div className="case-body">
          {tab === 'overview' && <CaseOverview c={openCase}/>}
          {tab === 'timeline' && <CaseTimeline/>}
          {tab === 'observables' && <CaseObservables/>}
          {tab === 'tasks' && <CaseTasks/>}
          {tab === 'comments' && <CaseComments/>}
          {tab === 'alerts' && <CaseLinkedAlerts/>}
        </div>
      </div>
    </div>
  );
}

// --- Overview tab ---
function CaseOverview({ c }) {
  return (
    <div className="case-overview">
      <div className="case-overview-main">
        <section className="case-section">
          <h3 className="cs-h3">Summary</h3>
          <p className="cs-p">
            Active intrusion detected on <span className="mono">web-prod-01</span> at 14:22 UTC. A base64-encoded PowerShell payload was executed by the <span className="mono">svc_backup</span> service account, attempting outbound communication to <span className="mono">185.220.101.42</span> — a known Tor exit node previously seen in CASE-4438. Forensic analysis confirms the payload is a Cobalt Strike loader.
          </p>
        </section>

        <section className="case-section">
          <h3 className="cs-h3">Status</h3>
          <div className="case-status-grid">
            <div className="css-cell">
              <div className="css-lbl mono">PHASE</div>
              <div className="css-val">CONTAIN</div>
              <div className="css-sub mono">3 of 8 tasks complete</div>
            </div>
            <div className="css-cell">
              <div className="css-lbl mono">CONTAINMENT</div>
              <div className="css-val css-ok">ACHIEVED</div>
              <div className="css-sub mono">host isolated · IP blocked</div>
            </div>
            <div className="css-cell">
              <div className="css-lbl mono">IMPACT</div>
              <div className="css-val">1 host</div>
              <div className="css-sub mono">no data exfil confirmed</div>
            </div>
            <div className="css-cell">
              <div className="css-lbl mono">TIME TO CONTAIN</div>
              <div className="css-val mono">12m 04s</div>
              <div className="css-sub mono">↓ 38% vs. SLA</div>
            </div>
          </div>
        </section>

        <section className="case-section">
          <h3 className="cs-h3">AI assessment <span className="ds-tag">SOCPilots AI</span></h3>
          <div className="ai-verdict">
            <span className="av-pill">active intrusion · 96% confidence</span>
            <p>This case represents a hands-on-keyboard adversary leveraging a stolen or compromised service-account credential. The attack chain (PowerShell loader → C2 beacon → planned lateral movement) is consistent with FIN7-style operations. Recommend: continue eradication, rotate all credentials that touched the host, and add a detection rule for service-account → PowerShell launches.</p>
          </div>
        </section>
      </div>

      <aside className="case-overview-rail">
        <section className="case-rail-section">
          <div className="crs-h">Metadata</div>
          <ul className="crs-list">
            <li><span>Created</span><span className="mono">14:22 UTC</span></li>
            <li><span>Reporter</span><span className="mono">system</span></li>
            <li><span>Lead</span><span className="mono">younes</span></li>
            <li><span>Responders</span><span className="mono">3</span></li>
            <li><span>TLP</span><span className="mono">AMBER</span></li>
            <li><span>PAP</span><span className="mono">AMBER</span></li>
          </ul>
        </section>

        <section className="case-rail-section">
          <div className="crs-h">Related</div>
          <ul className="crs-related">
            <li>
              <SevDot sev="critical" size={5}/>
              <span className="mono dim">CASE-4438</span>
              <span>Contained: ransomware staging</span>
            </li>
            <li>
              <SevDot sev="high" size={5}/>
              <span className="mono dim">CASE-4470</span>
              <span>Brute force surge — SSH</span>
            </li>
          </ul>
        </section>

        <section className="case-rail-section">
          <div className="crs-h">Quick actions</div>
          <div className="crs-actions">
            <button className="btn btn-ghost btn-sm">Pin to dashboard</button>
            <button className="btn btn-ghost btn-sm">Notify on-call</button>
            <button className="btn btn-ghost btn-sm">Export STIX</button>
            <button className="btn btn-ghost btn-sm">Close case…</button>
          </div>
        </section>
      </aside>
    </div>
  );
}

// --- Timeline tab ---
function CaseTimeline() {
  return (
    <div className="case-timeline">
      {CASE_TIMELINE.map((e, i) => (
        <div key={i} className="ct-row" data-tone={e.tone}>
          <div className="ct-time mono">{e.t}</div>
          <div className="ct-line"><span className="ct-dot"/></div>
          <div className="ct-body">
            <div className="ct-head">
              <span className="ct-who mono">{e.who}</span>
              <Chip mono>{e.type}</Chip>
            </div>
            <div className="ct-txt">{e.txt}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

// --- Observables tab ---
function CaseObservables() {
  return (
    <table className="data-table">
      <thead><tr>
        <th style={{width:70}}>TYPE</th>
        <th>VALUE</th>
        <th style={{width:170}}>TAGS</th>
        <th style={{width:120}}>INTEL</th>
        <th style={{width:80}}>SIGHTED</th>
        <th style={{width:60}}>IOC</th>
        <th style={{width:50}}></th>
      </tr></thead>
      <tbody>
        {CASE_OBSERVABLES.map(o => (
          <tr key={o.value}>
            <td><Chip mono>{o.type}</Chip></td>
            <td className="mono">{o.value}</td>
            <td><div className="obs-tags">{o.tags.map(t => <Chip key={t} mono>{t}</Chip>)}</div></td>
            <td>
              {o.intel ? (
                <div className="obs-intel mono">
                  {o.intel.vt != null && <span className={o.intel.vt > 30 ? 'crit' : 'warn'}>VT {o.intel.vt}/94</span>}
                  {o.intel.abuse != null && <span className="crit">{o.intel.abuse}%</span>}
                </div>
              ) : <span className="mono dim">—</span>}
            </td>
            <td className="mono">{o.sighted}×</td>
            <td>{o.ioc ? <Chip mono tone="crit">IOC</Chip> : <span className="mono dim">—</span>}</td>
            <td><button className="btn-icon"><Icon.chevron width="11" height="11"/></button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// --- Tasks tab ---
function CaseTasks() {
  return (
    <ul className="case-tasks">
      {CASE_TASKS.map((t,i) => (
        <li key={t.id} className={`case-task ${t.status}`}>
          <div className="case-task-check" data-status={t.status}>
            {t.status === 'done' && <Icon.check width="12" height="12"/>}
            {t.status === 'in-progress' && <span className="dot-pulse"/>}
          </div>
          <div className="case-task-body">
            <div className="case-task-row">
              <span className="case-task-num mono">{String(i+1).padStart(2,'0')}</span>
              <span className="case-task-title">{t.title}</span>
            </div>
            <div className="case-task-row2 mono">
              <span>due · {t.due}</span>
              {t.assignee
                ? <span className="case-task-assignee"><span className="sb-avatar" style={{width:16,height:16,fontSize:8}}>{t.assignee[0].toUpperCase()}</span>{t.assignee}</span>
                : <span className="dim">unassigned</span>}
            </div>
          </div>
          <button className="btn btn-ghost btn-sm">Open</button>
        </li>
      ))}
    </ul>
  );
}

// --- Comments tab ---
function CaseComments() {
  const [draft, setDraft] = useStateC('');
  return (
    <div className="case-comments">
      <ul className="cc-list">
        {CASE_COMMENTS.map((c,i) => (
          <li key={i} className={`cc-msg ${c.who === 'AI' ? 'ai' : ''}`}>
            <span className="sb-avatar" style={{width:28,height:28,fontSize:11}}>{c.who === 'AI' ? <Icon.brain width="13" height="13"/> : c.who[0].toUpperCase()}</span>
            <div className="cc-msg-body">
              <div className="cc-msg-head">
                <span className="cc-msg-who mono">{c.who}</span>
                <span className="cc-msg-when mono dim">{c.when}</span>
              </div>
              <p>{c.text}</p>
            </div>
          </li>
        ))}
      </ul>
      <div className="cc-composer">
        <textarea
          value={draft}
          onChange={e=>setDraft(e.target.value)}
          placeholder="Leave a comment… (@mention to notify, /ai to ask SOCPilots AI)"
          rows="2"
        />
        <div className="cc-composer-foot">
          <span className="mono dim">supports markdown · @mentions notify by email</span>
          <button className="btn btn-primary btn-sm" onClick={() => { if (draft.trim()) { window.socToast?.({title:'Comment posted', tone:'ok'}); setDraft(''); } }}>
            <Icon.send width="11" height="11"/> Post
          </button>
        </div>
      </div>
    </div>
  );
}

// --- Linked alerts tab ---
function CaseLinkedAlerts() {
  return (
    <table className="data-table">
      <thead><tr>
        <th style={{width:8}}></th>
        <th>ALERT ID</th>
        <th>RULE</th>
        <th>MITRE</th>
        <th>SEVERITY</th>
        <th>WHEN</th>
        <th></th>
      </tr></thead>
      <tbody>
        {CASE_LINKED_ALERTS.map(a => (
          <tr key={a.id}>
            <td><span className="sev-bar" data-sev={a.sev} style={{height:18}}/></td>
            <td className="mono"><a href="#" className="link">{a.id}</a></td>
            <td>{a.rule}</td>
            <td className="mono"><a className="link" href="#">{a.mitre}</a></td>
            <td><SevChip sev={a.sev}/></td>
            <td className="mono dim">{a.when}</td>
            <td><button className="btn-icon"><Icon.chevron width="12" height="12"/></button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

Object.assign(window, { CaseDetailSheet });
