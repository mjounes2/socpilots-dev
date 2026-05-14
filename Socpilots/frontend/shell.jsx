// Global shell: Command palette + Toasts + IR Runbook modal
const { useState: useS, useEffect: useE, useRef: useR, useMemo: useM, useCallback: useC } = React;

// ============= TOAST MANAGER (global) =============
let _toastId = 0;
const _toastListeners = new Set();
let _toastState = [];
function toast(opts) {
  const t = { id: ++_toastId, ts: Date.now(), title: opts.title || '', sub: opts.sub || '', tone: opts.tone || 'default', icon: opts.icon };
  _toastState = [..._toastState, t];
  _toastListeners.forEach(l => l(_toastState));
  setTimeout(() => {
    _toastState = _toastState.filter(x => x.id !== t.id);
    _toastListeners.forEach(l => l(_toastState));
  }, opts.duration || 4200);
}
window.socToast = toast;

function ToastHost() {
  const [items, setItems] = useS([]);
  useE(() => {
    _toastListeners.add(setItems);
    return () => _toastListeners.delete(setItems);
  }, []);
  return (
    <div className="toast-host">
      {items.map(t => (
        <div key={t.id} className="toast" data-tone={t.tone}>
          <div className="toast-icon">
            {t.tone === 'ok'   && <Icon.check width="14" height="14"/>}
            {t.tone === 'crit' && <Icon.alert width="14" height="14"/>}
            {t.tone === 'info' && <Icon.brain width="14" height="14"/>}
            {(!['ok','crit','info'].includes(t.tone)) && <Icon.dot width="14" height="14"/>}
          </div>
          <div className="toast-body">
            <div className="toast-title">{t.title}</div>
            {t.sub && <div className="toast-sub mono">{t.sub}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

// ============= COMMAND PALETTE =============
function CommandPalette({ onNav, page }) {
  const [open, setOpen] = useS(false);
  const [q, setQ] = useS('');
  const [idx, setIdx] = useS(0);
  const inputRef = useR(null);

  useE(() => {
    const h = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen(o => !o);
      } else if (e.key === 'Escape') {
        setOpen(false);
      }
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);

  useE(() => {
    if (open) { setQ(''); setIdx(0); setTimeout(() => inputRef.current?.focus(), 50); }
  }, [open]);

  const all = useM(() => [
    { type: 'nav', label: 'Go to Dashboard',    key: 'dashboard',  hint: '⌘D', sub: 'KPIs · timeline · attack map' },
    { type: 'nav', label: 'Go to Alerts',       key: 'alerts',     hint: '⌘A', sub: 'live alert feed · triage' },
    { type: 'nav', label: 'Go to SOCPilots AI', key: 'copilot',    hint: '⌘I', sub: 'chat with the AI co-analyst' },
    { type: 'nav', label: 'Go to SP-CM Cases',  key: 'cases',      hint: '⌘C', sub: 'kanban · 4 lanes' },
    { type: 'nav', label: 'Go to Correlation',  key: 'correlation',hint: '⌘L', sub: 'entity link graph' },
    { type: 'nav', label: 'Go to Threat Hunt',  key: 'hunt',       hint: '⌘H', sub: 'SIEM search · AI co-analyst' },
    { type: 'nav', label: 'Go to IOC Enrichment', key: 'ioc',      hint: '⌘E', sub: 'IP · domain · URL · hash' },
    { type: 'action', label: 'New case',        key: 'new-case',   hint: '',   sub: 'create a SP-CM case from scratch',
      do: () => toast({ title: 'New case', sub: 'CASE-4472 created · assigned to younes', tone: 'ok' }) },
    { type: 'action', label: 'Isolate agent · web-prod-01', key: 'isolate', hint: '', sub: 'cuts network · keeps Wazuh agent',
      do: () => toast({ title: 'Isolation queued', sub: 'web-prod-01 · cordoned in 2.4s', tone: 'crit' }) },
    { type: 'action', label: 'Block IP at perimeter',       key: 'block',   hint: '', sub: 'pushes to firewall via n8n',
      do: () => toast({ title: 'Block rule deployed', sub: '185.220.101.42 · denied at edge', tone: 'ok' }) },
    { type: 'action', label: 'Generate exec report',         key: 'report',  hint: '', sub: 'AI-drafted 24h summary',
      do: () => toast({ title: 'Report drafted', sub: '6 pages · awaiting your review', tone: 'info' }) },
    { type: 'action', label: 'Run hunt · lateral movement',  key: 'hunt-lat',hint: '', sub: 'MITRE T1021 · last 24h',
      do: () => { onNav('hunt'); toast({ title: 'Hunt running', sub: '6 events found across 4 hosts', tone: 'info' }); } },
    { type: 'entity', label: 'WZ-9281047',    key: 'a1', hint: 'alert', sub: 'PowerShell C2 · web-prod-01 · critical' },
    { type: 'entity', label: 'CASE-4471',     key: 'c1', hint: 'case',  sub: 'Active intrusion · web-prod-01' },
    { type: 'entity', label: '185.220.101.42', key: 'i1', hint: 'IP',    sub: 'Tor exit · VT 18/94 · AbuseIPDB 100%' },
    { type: 'entity', label: 'web-prod-01',   key: 'g1', hint: 'agent', sub: 'Ubuntu 22.04 · 412 alerts/24h' },
  ], []);

  const filtered = useM(() => {
    if (!q.trim()) return all;
    const ql = q.toLowerCase();
    return all.filter(it => (it.label + ' ' + (it.sub||'') + ' ' + (it.hint||'')).toLowerCase().includes(ql));
  }, [q, all]);

  useE(() => { setIdx(0); }, [q]);

  function activate(it) {
    setOpen(false);
    if (it.type === 'nav') {
      onNav(it.key);
    } else if (it.type === 'action' && it.do) {
      it.do();
    } else if (it.type === 'entity') {
      toast({ title: `Opening ${it.label}`, sub: it.sub, tone: 'info' });
      // Naive routing for demo
      if (it.hint === 'alert') onNav('alerts');
      if (it.hint === 'case') onNav('cases');
      if (it.hint === 'IP') onNav('ioc');
      if (it.hint === 'agent') onNav('agents');
    }
  }

  function onKey(e) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx(i => Math.min(filtered.length - 1, i + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setIdx(i => Math.max(0, i - 1)); }
    else if (e.key === 'Enter') { e.preventDefault(); if (filtered[idx]) activate(filtered[idx]); }
  }

  if (!open) return null;
  return (
    <div className="cmd-overlay" onClick={() => setOpen(false)}>
      <div className="cmd-palette" onClick={e => e.stopPropagation()}>
        <div className="cmd-input-row">
          <Icon.search width="16" height="16"/>
          <input
            ref={inputRef}
            className="cmd-input"
            placeholder="Search commands, alerts, cases, IPs, hosts…"
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={onKey}
          />
          <Kbd>esc</Kbd>
        </div>
        <div className="cmd-list">
          {filtered.length === 0 && (
            <div className="cmd-empty mono">no matches for "{q}"</div>
          )}
          {groupBy(filtered, 'type').map(([type, items]) => (
            <div key={type} className="cmd-group">
              <div className="cmd-group-label mono">
                {type === 'nav' ? 'NAVIGATE' : type === 'action' ? 'ACTIONS' : 'ENTITIES'}
              </div>
              {items.map((it) => {
                const i = filtered.indexOf(it);
                return (
                  <button
                    key={it.key}
                    className={`cmd-item ${i === idx ? 'on' : ''}`}
                    onMouseEnter={() => setIdx(i)}
                    onClick={() => activate(it)}
                  >
                    <div className="cmd-icon">
                      {it.type === 'nav' && <Icon.chevron width="13" height="13"/>}
                      {it.type === 'action' && <Icon.spark width="13" height="13"/>}
                      {it.type === 'entity' && <Icon.target width="13" height="13"/>}
                    </div>
                    <div className="cmd-text">
                      <div className="cmd-label">{it.label}</div>
                      {it.sub && <div className="cmd-sub mono">{it.sub}</div>}
                    </div>
                    {it.hint && <span className="cmd-hint mono">{it.hint}</span>}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
        <div className="cmd-foot mono">
          <span><Kbd>↑↓</Kbd> navigate</span>
          <span><Kbd>↵</Kbd> select</span>
          <span><Kbd>esc</Kbd> close</span>
          <span style={{marginLeft:'auto'}}>{filtered.length} results</span>
        </div>
      </div>
    </div>
  );
}

function groupBy(arr, key) {
  const m = new Map();
  arr.forEach(x => { if (!m.has(x[key])) m.set(x[key], []); m.get(x[key]).push(x); });
  return Array.from(m.entries());
}

// ============= IR RUNBOOK MODAL =============
const RUNBOOK_STEPS = [
  {
    id: 'verify', phase: 'TRIAGE', title: 'Verify alert is not a false positive',
    detail: 'Confirm process tree, parent process, command-line args. Cross-reference with known-good baselines.',
    actions: [
      { label: 'Pull process tree', kind: 'auto', value: 'web-prod-01 · last 5m' },
      { label: 'Compare to baseline', kind: 'auto', value: 'svc_backup · 14-day window' },
    ],
    aiNote: 'cmd.exe → powershell.exe -enc … never seen before for svc_backup on this host. Highly anomalous (z=4.2).',
    aiVerdict: 'true-positive', confidence: 96,
  },
  {
    id: 'contain', phase: 'CONTAIN', title: 'Isolate the affected endpoint',
    detail: 'Cut network access at the host level while preserving the Wazuh agent for visibility. Snapshot memory for forensics.',
    actions: [
      { label: 'Isolate web-prod-01', kind: 'manual', value: 'Wazuh active response · isolate-firewalld' },
      { label: 'Capture memory image', kind: 'manual', value: 'avml → s3://soc-forensics/' },
      { label: 'Suspend svc_backup credential', kind: 'manual', value: 'AD: disable + force logoff' },
    ],
    aiNote: 'Account svc_backup is currently authenticated on 3 hosts. Suspend immediately to prevent lateral movement.',
  },
  {
    id: 'block', phase: 'CONTAIN', title: 'Block C2 infrastructure at perimeter',
    detail: 'Push deny rules for the malicious IP and any related infrastructure to your edge firewall.',
    actions: [
      { label: 'Block 185.220.101.42', kind: 'auto', value: 'n8n → firewall · 2.4s' },
      { label: 'Block /24 subnet', kind: 'manual', value: '185.220.101.0/24 · 24h' },
      { label: 'Block C2 domain', kind: 'auto', value: 'malicious-c2.xyz → DNS sinkhole' },
    ],
  },
  {
    id: 'eradicate', phase: 'ERADICATE', title: 'Remove persistence + remediate',
    detail: 'Hunt for and remove any persistence mechanisms (scheduled tasks, services, run keys, WMI subscriptions).',
    actions: [
      { label: 'Scan for scheduled tasks', kind: 'auto', value: 'AT/Schtasks · created last 7d' },
      { label: 'Inspect Run keys', kind: 'auto', value: 'HKLM\\…\\Run · HKCU\\…\\Run' },
      { label: 'Hunt across fleet for hash a4f8b2c…', kind: 'auto', value: '156 agents · 0 additional matches' },
    ],
    aiNote: 'Cobalt Strike loader rarely deploys without persistence. Recommend a 7-day registry/scheduled-task audit on the affected host.',
  },
  {
    id: 'recover', phase: 'RECOVER', title: 'Restore & verify',
    detail: 'Re-image or restore host from a known-good backup. Rotate all credentials that touched the host.',
    actions: [
      { label: 'Re-image web-prod-01', kind: 'manual', value: 'gold image · ~14 min' },
      { label: 'Rotate credentials', kind: 'manual', value: 'svc_backup, deploy_key, db_ro · 3 secrets' },
      { label: 'Re-enroll Wazuh agent', kind: 'auto', value: 'after re-image' },
    ],
  },
  {
    id: 'lessons', phase: 'LEARN', title: 'Post-incident report',
    detail: 'Generate AI-drafted timeline, write up lessons learned, propose detection-rule tuning.',
    actions: [
      { label: 'Draft exec timeline', kind: 'auto', value: 'AI · ~1 page' },
      { label: 'Propose rule additions', kind: 'auto', value: 'svc_backup → powershell · alert always' },
    ],
  },
];

function RunbookModal({ openCase, onClose }) {
  const [done, setDone] = useS(() => new Set(['verify']));
  const [activeIdx, setActiveIdx] = useS(1);

  useE(() => {
    const h = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);

  if (!openCase) return null;

  const complete = (id) => {
    setDone(d => new Set([...d, id]));
    const nextIdx = RUNBOOK_STEPS.findIndex(s => !done.has(s.id) && s.id !== id);
    if (nextIdx >= 0) setActiveIdx(nextIdx);
    toast({ title: 'Step completed', sub: id + ' · auto-attached to ' + openCase.id, tone: 'ok' });
  };
  const runAction = (label, kind) => {
    if (kind === 'auto') toast({ title: 'Action queued', sub: label + ' · executing…', tone: 'info' });
    else toast({ title: 'Manual step', sub: label + ' · requires operator approval', tone: 'default' });
  };

  const progress = done.size / RUNBOOK_STEPS.length;
  const phases = ['TRIAGE','CONTAIN','ERADICATE','RECOVER','LEARN'];

  return (
    <div className="rb-overlay" onClick={onClose}>
      <div className="rb-modal" onClick={e => e.stopPropagation()}>
        <header className="rb-head">
          <div className="rb-head-l">
            <div className="rb-eyebrow mono">
              <Icon.brain width="11" height="11"/>
              AI-DRAFTED RUNBOOK · APPROVED BY @younes
            </div>
            <h2 className="rb-title">Incident response · {openCase.title}</h2>
            <div className="rb-meta">
              <SevChip sev={openCase.sev}/>
              <Chip mono>{openCase.id}</Chip>
              <Chip mono>{openCase.alerts} alerts</Chip>
              <Chip mono>opened {openCase.age} ago</Chip>
            </div>
          </div>
          <button className="btn-icon rb-close" onClick={onClose}><Icon.x width="16" height="16"/></button>
        </header>

        <div className="rb-progress-bar">
          <div className="rb-progress-fill" style={{ width: `${progress * 100}%` }}/>
          <div className="rb-progress-text mono">{done.size} / {RUNBOOK_STEPS.length} steps complete</div>
        </div>

        <div className="rb-phases">
          {phases.map((p, i) => {
            const stepsInPhase = RUNBOOK_STEPS.filter(s => s.phase === p);
            const doneInPhase  = stepsInPhase.filter(s => done.has(s.id)).length;
            const allDone      = doneInPhase === stepsInPhase.length;
            const someDone     = doneInPhase > 0;
            return (
              <div key={p} className="rb-phase" data-state={allDone ? 'done' : someDone ? 'active' : 'todo'}>
                <div className="rb-phase-dot">{allDone ? <Icon.check width="10" height="10"/> : i+1}</div>
                <div className="rb-phase-label mono">{p}</div>
                <div className="rb-phase-count mono">{doneInPhase}/{stepsInPhase.length}</div>
              </div>
            );
          })}
        </div>

        <div className="rb-body">
          {RUNBOOK_STEPS.map((s, i) => {
            const isDone = done.has(s.id);
            const isActive = i === activeIdx;
            return (
              <div key={s.id} className={`rb-step ${isDone ? 'done' : ''} ${isActive ? 'active' : ''}`}
                   onClick={() => setActiveIdx(i)}>
                <div className="rb-step-marker">
                  {isDone ? <Icon.check width="13" height="13"/> : <span className="mono">{i+1}</span>}
                </div>
                <div className="rb-step-body">
                  <div className="rb-step-head">
                    <span className="rb-step-phase mono">{s.phase}</span>
                    <span className="rb-step-title">{s.title}</span>
                    {isDone && <Chip mono tone="ok">complete</Chip>}
                  </div>
                  {isActive && (
                    <div className="rb-step-detail">
                      <p>{s.detail}</p>
                      <div className="rb-actions">
                        {s.actions.map((a, j) => (
                          <button key={j} className={`rb-action ${a.kind}`} onClick={(e) => { e.stopPropagation(); runAction(a.label, a.kind); }}>
                            <span className="rb-action-kind mono">{a.kind}</span>
                            <span className="rb-action-label">{a.label}</span>
                            <span className="rb-action-val mono">{a.value}</span>
                          </button>
                        ))}
                      </div>
                      {s.aiNote && (
                        <div className="rb-ai-note">
                          <Icon.brain width="12" height="12"/>
                          <div>
                            <div className="rb-ai-label mono">AI INSIGHT{s.aiVerdict ? ` · ${s.aiVerdict.toUpperCase()} (${s.confidence}%)` : ''}</div>
                            <div className="rb-ai-text">{s.aiNote}</div>
                          </div>
                        </div>
                      )}
                      {!isDone && (
                        <div className="rb-step-foot">
                          <button className="btn btn-primary btn-sm" onClick={(e) => { e.stopPropagation(); complete(s.id); }}>
                            <Icon.check width="12" height="12"/> Mark complete
                          </button>
                          <button className="btn btn-ghost btn-sm" onClick={e => e.stopPropagation()}>Skip</button>
                          <button className="btn btn-ghost btn-sm" onClick={e => e.stopPropagation()}>Snooze</button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        <footer className="rb-foot">
          <span className="mono dim">Last edit: AI · 4m ago · v1.3</span>
          <div className="rb-foot-actions">
            <button className="btn btn-ghost btn-sm">Export PDF</button>
            <button className="btn btn-ghost btn-sm">Share</button>
            <button className="btn btn-primary btn-sm" onClick={onClose}>Save & close</button>
          </div>
        </footer>
      </div>
    </div>
  );
}

Object.assign(window, { ToastHost, CommandPalette, RunbookModal });
