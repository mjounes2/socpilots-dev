// SP-CM Case detail — full incident record view (real TheHive data)
const { useState: useStateC, useEffect: useEffectC, useCallback: useCallbackC } = React;

// ─── helpers ──────────────────────────────────────────────────
function caseRelAgo(ts) {
  if (!ts) return '—';
  const s = Math.round((Date.now() - (typeof ts === 'number' ? ts : new Date(ts).getTime())) / 1000);
  if (s < 60)   return `${s}s ago`;
  if (s < 3600) return `${Math.round(s/60)}m ago`;
  if (s < 86400)return `${Math.round(s/3600)}h ago`;
  return `${Math.round(s/86400)}d ago`;
}
function caseTimeStr(ts) {
  if (!ts) return '—';
  return new Date(typeof ts === 'number' ? ts : new Date(ts).getTime())
    .toISOString().slice(11,19) + ' UTC';
}
function caseDateStr(ts) {
  if (!ts) return '—';
  return new Date(typeof ts === 'number' ? ts : new Date(ts).getTime())
    .toISOString().slice(0,16).replace('T',' ') + ' UTC';
}

// Extract IPs/hosts from description markdown
function parseDescIPs(desc) {
  if (!desc) return [];
  const ipRe = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
  return [...new Set((desc.match(ipRe) || []).filter(ip => !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('172.') && !ip.startsWith('127.')))].slice(0, 3);
}
function parseDescAgent(desc) {
  const m = (desc || '').match(/\*\*Agent Name\*\*\s*\|\s*([^\n|]+)/i);
  return m ? m[1].trim() : null;
}
function parseRuleId(desc) {
  const m = (desc || '').match(/\*\*Rule ID\*\*\s*\|\s*(\d+)/i);
  return m ? m[1] : null;
}

// Map audit type to timeline chip tone
const TIMELINE_TONE = {
  create:      'crit',
  link:        'info',
  assign:      'default',
  status:      'ok',
  observable:  'info',
  update:      'default',
};

// AI assessment derived from real case data
function buildAIAssessment(c) {
  const sev   = (c.severity || c.sev || 'low').toLowerCase();
  const ips   = parseDescIPs(c.description);
  const agent = parseDescAgent(c.description);
  const ruleId = parseRuleId(c.description);
  const conf   = sev === 'critical' ? 96 : sev === 'high' ? 88 : sev === 'medium' ? 73 : 55;
  const verdicts = {
    critical: 'active intrusion',
    high:     'high-severity indicator',
    medium:   'medium-confidence signal',
    low:      'low-priority activity',
  };
  const recs = {
    critical: `This alert strongly indicates active adversarial activity${agent ? ` on ${agent}` : ''}${ips.length ? ` with external communication to ${ips[0]}` : ''}. Recommend immediate containment, credential rotation, and host forensics.`,
    high:     `High-severity event detected${agent ? ` on ${agent}` : ''}${ruleId ? ` (rule ${ruleId})` : ''}. Recommend promotion to P1 case with analyst assignment. Correlate with UEBA behavior data and IOC feeds before escalating.`,
    medium:   `Medium-confidence indicator requiring analyst review${agent ? ` on ${agent}` : ''}. Verify against baseline and similar alerts. Check for pattern recurrence before closing.`,
    low:      `Low-priority signal. Likely benign. Monitor for recurrence or correlation with other events before taking action.`,
  };
  return {
    verdict: verdicts[sev] || verdicts.low,
    conf,
    text: recs[sev] || recs.low,
  };
}

// ─── Main case detail sheet ────────────────────────────────────
function CaseDetailSheet({ openCase, onClose, onOpenRunbook }) {
  const [tab, setTab]           = useStateC('overview');
  const [timeline, setTimeline] = useStateC(null);
  const [observables, setObs]   = useStateC(null);
  const [tasks, setTasks]       = useStateC(null);
  const [comments, setComments] = useStateC(null);
  const [alerts, setAlerts]     = useStateC(null);

  // ESC to close
  useEffectC(() => {
    const h = e => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);

  // Reset + load when case changes
  useEffectC(() => {
    const caseId = openCase?.hiveId || openCase?.id;
    if (!caseId) return;
    setTab('overview');
    setTimeline(null); setObs(null); setTasks(null); setComments(null); setAlerts(null);
    const API = window.SOC_API;
    API.get(`/api/cases/${caseId}/timeline`).then(d => setTimeline(d?.events || []));
    API.get(`/api/cases/${caseId}/observables`).then(d => setObs(d?.observables || []));
    API.get(`/api/cases/${caseId}/tasks`).then(d => setTasks(d?.tasks || []));
    API.get(`/api/cases/${caseId}/comments`).then(d => setComments(d?.comments || []));
    API.get(`/api/cases/${caseId}/alerts`).then(d => setAlerts(d?.alerts || []));
  }, [openCase?.hiveId, openCase?.id]);

  if (!openCase) return null;

  const doneTasks = (tasks || []).filter(t => t.status === 'Completed' || t.status === 'done').length;
  const totalTasks = (tasks || []).length;

  const tabs = [
    { id: 'overview',    label: 'Overview' },
    { id: 'timeline',    label: 'Timeline',      count: timeline?.length ?? '…' },
    { id: 'observables', label: 'Observables',   count: observables?.length ?? '…' },
    { id: 'tasks',       label: 'Tasks',         count: totalTasks > 0 ? `${doneTasks}/${totalTasks}` : (tasks === null ? '…' : 0) },
    { id: 'comments',    label: 'Comments',      count: comments?.length ?? '…' },
    { id: 'alerts',      label: 'Linked alerts', count: alerts?.length ?? '…' },
  ];

  const sev = (openCase.sev || openCase.severity || 'low').toLowerCase();

  return (
    <div className="case-overlay" onClick={onClose}>
      <div className="case-sheet" onClick={e => e.stopPropagation()}>
        <header className="case-head">
          <div className="case-head-l">
            <div className="case-eyebrow mono">
              <SevDot sev={sev}/> #{openCase.number || (openCase.hiveId || openCase.id || '').slice(0,8)} · {openCase.status?.toUpperCase() || 'OPEN'} · {openCase.age || caseRelAgo(openCase.created)}
            </div>
            <h2 className="case-title">{openCase.title}</h2>
            <div className="case-meta">
              <SevChip sev={sev}/>
              <Chip mono>P1 · {sev}</Chip>
              {(alerts?.length ?? 0) > 0 && (
                <Chip mono><Icon.bell width="10" height="10"/> {alerts.length} alerts</Chip>
              )}
              {openCase.assignee
                ? <span className="cc-assignee" style={{ fontSize: 11 }}>
                    <span className="cc-avatar">{openCase.assignee[0].toUpperCase()}</span>
                    {openCase.assignee.replace(/@.*/, '')}
                  </span>
                : <Chip mono>unassigned</Chip>}
              {(openCase.tags || []).slice(0, 4).map(t => <Chip key={t} mono>{t}</Chip>)}
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
            <button key={t.id} className={`case-tab ${tab === t.id ? 'on' : ''}`} onClick={() => setTab(t.id)}>
              {t.label}
              {t.count != null && <span className="case-tab-count mono">{t.count}</span>}
            </button>
          ))}
        </div>

        <div className="case-body">
          {tab === 'overview'    && <CaseOverview c={openCase} obs={observables} tasks={tasks} />}
          {tab === 'timeline'    && <CaseTimeline events={timeline} />}
          {tab === 'observables' && <CaseObservables items={observables} />}
          {tab === 'tasks'       && <CaseTasks items={tasks} />}
          {tab === 'comments'    && <CaseComments items={comments} caseId={openCase.hiveId || openCase.id} />}
          {tab === 'alerts'      && <CaseLinkedAlerts items={alerts} />}
        </div>
      </div>
    </div>
  );
}

// ─── Overview tab ──────────────────────────────────────────────
function CaseOverview({ c, obs, tasks }) {
  const ips     = parseDescIPs(c.description);
  const agent   = parseDescAgent(c.description);
  const ruleId  = parseRuleId(c.description);
  const ai      = buildAIAssessment(c);
  const sev     = (c.sev || c.severity || 'low').toLowerCase();
  const doneTasks  = (tasks || []).filter(t => t.status === 'Completed' || t.status === 'done').length;
  const totalTasks = (tasks || []).length;

  // Phase derived from task completion
  const phase = totalTasks === 0 ? 'TRIAGE' :
                doneTasks === 0  ? 'CONTAIN' :
                doneTasks < totalTasks ? 'ERADICATE' : 'CLOSED';

  return (
    <div className="case-overview">
      <div className="case-overview-main">
        {/* Summary */}
        <section className="case-section">
          <h3 className="cs-h3">Summary</h3>
          <p className="cs-p">
            {c.description
              ? c.description
                  .replace(/#+\s*/g, '')
                  .replace(/\*\*([^*]+)\*\*/g, '$1')
                  .replace(/\|[^\n]+\n/g, '')
                  .replace(/`{3}[^`]+`{3}/gs, '')
                  .trim()
                  .slice(0, 350) + (c.description.length > 350 ? '…' : '')
              : 'No summary available.'}
          </p>
          {(ips.length > 0 || agent || ruleId) && (
            <div style={{ marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {ips.map(ip    => <Chip key={ip}     mono>{ip}</Chip>)}
              {agent         && <Chip mono>host: {agent}</Chip>}
              {ruleId        && <Chip mono>rule {ruleId}</Chip>}
            </div>
          )}
        </section>

        {/* Status grid */}
        <section className="case-section">
          <h3 className="cs-h3">Status</h3>
          <div className="case-status-grid">
            <div className="css-cell">
              <div className="css-lbl mono">PHASE</div>
              <div className="css-val">{phase}</div>
              <div className="css-sub mono">{totalTasks > 0 ? `${doneTasks} of ${totalTasks} tasks complete` : 'No tasks yet'}</div>
            </div>
            <div className="css-cell">
              <div className="css-lbl mono">STATUS</div>
              <div className={`css-val ${c.isClosed ? 'css-ok' : 'css-warn'}`}>{c.status || 'New'}</div>
              <div className="css-sub mono">{c.statusLabel || c.status}</div>
            </div>
            <div className="css-cell">
              <div className="css-lbl mono">SEVERITY</div>
              <div className="css-val">{(c.severity || c.sev || 'LOW').toUpperCase()}</div>
              <div className="css-sub mono">{obs !== null ? `${(obs || []).length} observables` : 'loading…'}</div>
            </div>
            <div className="css-cell">
              <div className="css-lbl mono">OPENED</div>
              <div className="css-val mono" style={{ fontSize: 13 }}>{caseDateStr(c.created)}</div>
              <div className="css-sub mono">TLP: {c.tlp || 'AMBER'}</div>
            </div>
          </div>
        </section>

        {/* AI assessment */}
        <section className="case-section">
          <h3 className="cs-h3">AI assessment <span className="ds-tag">SOCPilots AI</span></h3>
          <div className="ai-verdict">
            <span className="av-pill">{ai.verdict} · {ai.conf}% confidence</span>
            <p>{ai.text}</p>
          </div>
        </section>
      </div>

      {/* Right rail */}
      <aside className="case-overview-rail">
        <section className="case-rail-section">
          <div className="crs-h">Metadata</div>
          <ul className="crs-list">
            <li><span>Created</span>  <span className="mono">{caseDateStr(c.created)}</span></li>
            <li><span>Lead</span>     <span className="mono">{(c.assignee || '—').replace(/@.*/, '')}</span></li>
            <li><span>TLP</span>      <span className="mono">{c.tlp || 'AMBER'}</span></li>
            <li><span>Severity</span> <span className="mono">{(c.severity || c.sev || '—').toUpperCase()}</span></li>
            <li><span>Status</span>   <span className="mono">{c.status || '—'}</span></li>
            {c.number && <li><span>Case #</span><span className="mono">{c.number}</span></li>}
          </ul>
        </section>

        {(obs && obs.length > 0) && (
          <section className="case-rail-section">
            <div className="crs-h">Observables ({obs.length})</div>
            <ul className="crs-related">
              {obs.slice(0, 4).map(o => (
                <li key={o.id}>
                  <Chip mono>{o.type}</Chip>
                  <span className="mono dim" style={{ fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 160 }}>{o.value}</span>
                  {o.ioc && <Chip mono tone="error">IOC</Chip>}
                </li>
              ))}
            </ul>
          </section>
        )}

        <section className="case-rail-section">
          <div className="crs-h">Quick actions</div>
          <div className="crs-actions">
            <button className="btn btn-ghost btn-sm">Notify on-call</button>
            <button className="btn btn-ghost btn-sm">Export STIX</button>
            <button className="btn btn-ghost btn-sm">Close case…</button>
          </div>
        </section>
      </aside>
    </div>
  );
}

// ─── Timeline tab ──────────────────────────────────────────────
function CaseTimeline({ events }) {
  if (!events) return <div className="loading mono" style={{ padding: 40 }}>Loading timeline…</div>;
  if (events.length === 0) return <div className="empty mono" style={{ padding: 40 }}>No timeline events</div>;
  return (
    <div className="case-timeline">
      {events.map((e, i) => (
        <div key={i} className="ct-row" data-tone={TIMELINE_TONE[e.type] || 'default'}>
          <div className="ct-time mono">{caseTimeStr(e.ts)}</div>
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

// ─── Observables tab ───────────────────────────────────────────
function CaseObservables({ items }) {
  if (!items) return <div className="loading mono" style={{ padding: 40 }}>Loading observables…</div>;
  if (items.length === 0) return <div className="empty mono" style={{ padding: 40 }}>No observables</div>;
  return (
    <table className="data-table">
      <thead><tr>
        <th style={{ width: 70 }}>TYPE</th>
        <th>VALUE</th>
        <th style={{ width: 140 }}>TAGS</th>
        <th style={{ width: 70 }}>TLP</th>
        <th style={{ width: 60 }}>IOC</th>
      </tr></thead>
      <tbody>
        {items.map(o => (
          <tr key={o.id}>
            <td><Chip mono>{o.type}</Chip></td>
            <td className="mono" style={{ wordBreak: 'break-all', fontSize: 11 }}>{o.value}</td>
            <td><div className="obs-tags">{(o.tags || []).map(t => <Chip key={t} mono>{t}</Chip>)}</div></td>
            <td className="mono dim" style={{ fontSize: 10 }}>{o.tlp}</td>
            <td>{o.ioc ? <Chip mono tone="error">IOC</Chip> : <span className="mono dim">—</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ─── Tasks tab ─────────────────────────────────────────────────
function CaseTasks({ items }) {
  if (!items) return <div className="loading mono" style={{ padding: 40 }}>Loading tasks…</div>;
  if (items.length === 0) return <div className="empty mono" style={{ padding: 40 }}>No tasks — tasks can be added in TheHive</div>;
  return (
    <ul className="case-tasks">
      {items.map((t, i) => {
        const done = t.status === 'Completed' || t.status === 'done';
        const wip  = t.status === 'InProgress' || t.status === 'in-progress';
        return (
          <li key={t.id} className={`case-task ${done ? 'done' : wip ? 'in-progress' : 'todo'}`}>
            <div className="case-task-check" data-status={done ? 'done' : wip ? 'in-progress' : 'todo'}>
              {done && <Icon.check width="12" height="12"/>}
              {wip  && <span className="dot-pulse"/>}
            </div>
            <div className="case-task-body">
              <div className="case-task-row">
                <span className="case-task-num mono">{String(i+1).padStart(2,'0')}</span>
                <span className="case-task-title">{t.title}</span>
              </div>
              <div className="case-task-row2 mono">
                <span>{t.status}</span>
                {t.assignee
                  ? <span className="case-task-assignee"><span className="sb-avatar" style={{ width:16,height:16,fontSize:8 }}>{t.assignee[0].toUpperCase()}</span>{t.assignee}</span>
                  : <span className="dim">unassigned</span>}
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

// ─── Comments tab ──────────────────────────────────────────────
function CaseComments({ items, caseId }) {
  const [draft, setDraft] = useStateC('');
  const [posting, setPosting] = useStateC(false);

  if (!items) return <div className="loading mono" style={{ padding: 40 }}>Loading comments…</div>;

  async function postComment() {
    if (!draft.trim() || !caseId) return;
    setPosting(true);
    const r = await window.SOC_API.post(`/api/cases/${caseId}/comments`, { message: draft.trim() });
    setPosting(false);
    if (r && !r.error) {
      window.socToast?.({ title: 'Comment posted', tone: 'ok' });
      setDraft('');
    } else {
      window.socToast?.({ title: 'Post failed', sub: r?.error || 'Check TheHive', tone: 'error' });
    }
  }

  return (
    <div className="case-comments">
      <ul className="cc-list">
        {items.length === 0 && <li className="empty mono" style={{ padding: 24 }}>No comments yet</li>}
        {items.map((c, i) => (
          <li key={c.id || i} className="cc-msg">
            <span className="sb-avatar" style={{ width:28,height:28,fontSize:11 }}>{c.who[0].toUpperCase()}</span>
            <div className="cc-msg-body">
              <div className="cc-msg-head">
                <span className="cc-msg-who mono">{c.who}</span>
                <span className="cc-msg-when mono dim">{caseRelAgo(c.when)}</span>
              </div>
              <p>{c.message}</p>
            </div>
          </li>
        ))}
      </ul>
      <div className="cc-composer">
        <textarea
          value={draft}
          onChange={e => setDraft(e.target.value)}
          placeholder="Leave a comment… (@mention to notify, /ai to ask SOCPilots AI)"
          rows="2"
        />
        <div className="cc-composer-foot">
          <span className="mono dim">supports markdown · @mentions notify by email</span>
          <button className="btn btn-primary btn-sm" disabled={posting} onClick={postComment}>
            <Icon.send width="11" height="11"/> {posting ? 'Posting…' : 'Post'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Linked alerts tab ─────────────────────────────────────────
function CaseLinkedAlerts({ items }) {
  if (!items) return <div className="loading mono" style={{ padding: 40 }}>Loading linked alerts…</div>;
  if (items.length === 0) return <div className="empty mono" style={{ padding: 40 }}>No linked alerts</div>;
  return (
    <table className="data-table">
      <thead><tr>
        <th style={{ width: 8 }}></th>
        <th>ALERT REF</th>
        <th>TITLE</th>
        <th>SOURCE</th>
        <th>SEVERITY</th>
        <th>WHEN</th>
      </tr></thead>
      <tbody>
        {items.map(a => (
          <tr key={a.id}>
            <td><span className="sev-bar" data-sev={a.sev?.toLowerCase()} style={{ height: 18 }}/></td>
            <td className="mono dim" style={{ fontSize: 10 }}>{a.ref}</td>
            <td style={{ fontSize: 11 }}>{a.title}</td>
            <td className="mono dim" style={{ fontSize: 10 }}>{a.source}</td>
            <td><SevChip sev={a.sev?.toLowerCase()}/></td>
            <td className="mono dim" style={{ fontSize: 10 }}>{caseDateStr(a.when)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

Object.assign(window, { CaseDetailSheet });
