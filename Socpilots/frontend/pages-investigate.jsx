// AI Copilot + Cases + Correlation pages
const { useState: useStateI, useEffect: useEffectI, useRef: useRefI, useMemo: useMemoI } = React;

// ============= AI COPILOT =============
function PageCopilot() {
  const D = window.SOC_DATA;
  const [msgs, setMsgs] = useStateI(D.COPILOT_CONVO);
  const [draft, setDraft] = useStateI('');
  const [thinking, setThinking] = useStateI(false);
  const endRef = useRefI(null);

  useEffectI(() => {
    endRef.current?.parentElement?.scrollTo({ top: 999999, behavior: 'smooth' });
  }, [msgs, thinking]);

  function send(text) {
    if (!text.trim()) return;
    setMsgs(m => [...m, { role: 'user', text }]);
    setDraft('');
    setThinking(true);
    setTimeout(() => {
      setThinking(false);
      setMsgs(m => [...m, {
        role: 'ai',
        text: 'Containment plan generated. (1) Isolate `web-prod-01` via Wazuh active response. (2) Block `185.220.101.42` at perimeter firewall. (3) Quarantine the suspicious process and capture full memory image. (4) Open case CASE-4471 → P1 and assign to incident-response. Shall I execute steps 1–2 now?',
        evidence: [
          { type: 'action', label: 'Auto-actions ready', value: '4 steps · est. 2m 14s' },
          { type: 'query', label: 'Wazuh API call', value: 'POST /active-response/isolate { agent_id: "003" }' },
        ],
      }]);
    }, 1400);
  }

  return (
    <div className="page page-copilot" data-screen-label="03 SOCPilots AI">
      <Topbar
        title="SOCPilots AI"
        sub="Connected to SIEM · SP-CM · MCP · gpt-4o"
        actions={<>
          <Chip mono tone="ok"><span className="pip pip-ok"/> n8n online</Chip>
          <Chip mono>session · 12 turns</Chip>
          <button className="btn btn-ghost">New session</button>
        </>}
      />

      <div className="copilot-layout">
        <aside className="copilot-sessions">
          <div className="cs-section">
            <div className="cs-label">SESSIONS</div>
            <button className="cs-item active">
              <SevDot sev="critical" size={6}/>
              <div>
                <div className="cs-title">PowerShell intrusion · web-prod-01</div>
                <div className="cs-sub mono">12 turns · 3m ago</div>
              </div>
            </button>
            <button className="cs-item">
              <SevDot sev="high" size={6}/>
              <div>
                <div className="cs-title">Kerberoasting on win-dc-01</div>
                <div className="cs-sub mono">8 turns · 2h ago</div>
              </div>
            </button>
            <button className="cs-item">
              <SevDot sev="medium" size={6}/>
              <div>
                <div className="cs-title">Phishing wave — finance dept.</div>
                <div className="cs-sub mono">24 turns · 5h ago</div>
              </div>
            </button>
            <button className="cs-item">
              <SevDot sev="low" size={6}/>
              <div>
                <div className="cs-title">Weekly exec summary draft</div>
                <div className="cs-sub mono">3 turns · 1d ago</div>
              </div>
            </button>
          </div>

          <div className="cs-section">
            <div className="cs-label">QUICK PROMPTS</div>
            {[
              'Summarize last 24h activity',
              'What changed since last shift?',
              'Show me unresolved P1 cases',
              'Run hunt: lateral movement',
              'Generate exec report',
            ].map(p => (
              <button key={p} className="cs-prompt" onClick={()=>send(p)}>
                <Icon.spark width="11" height="11" /> {p}
              </button>
            ))}
          </div>
        </aside>

        <main className="copilot-main">
          <div className="chat">
            {msgs.map((m, i) => <ChatMessage key={i} msg={m} />)}
            {thinking && <ChatThinking />}
            <div ref={endRef} />
          </div>

          <div className="composer">
            <div className="composer-context">
              <Chip mono icon={<Icon.target width="11" height="11"/>}>WZ-9281047</Chip>
              <Chip mono>web-prod-01</Chip>
              <Chip mono>last 1h</Chip>
              <button className="btn-icon"><Icon.plus width="12" height="12"/></button>
            </div>
            <div className="composer-input">
              <textarea
                value={draft}
                onChange={e=>setDraft(e.target.value)}
                onKeyDown={e=>{ if(e.key==='Enter' && !e.shiftKey){ e.preventDefault(); send(draft); }}}
                placeholder="Ask SOCPilots AI…   try: 'pivot on src.ip', 'show all related events', 'draft IR runbook'"
                rows="2"
              />
              <button className="btn btn-primary" onClick={()=>send(draft)}>
                <Icon.send width="14" height="14"/> Send <Kbd>↵</Kbd>
              </button>
            </div>
            <div className="composer-foot mono">
              connected · SIEM ✓ SP-CM ✓ MCP ✓ · model gpt-4o · response avg 2.1s
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

function ChatMessage({ msg }) {
  return (
    <div className={`msg msg-${msg.role}`}>
      <div className="msg-avatar">
        {msg.role === 'ai' ? <Icon.brain width="14" height="14"/> : 'YJ'}
      </div>
      <div className="msg-body">
        <div className="msg-name">
          {msg.role === 'ai' ? 'SOCPilots AI' : 'younes'}
          {msg.role === 'ai' && <span className="msg-tag">gpt-4o</span>}
        </div>
        <div className="msg-text" dangerouslySetInnerHTML={{ __html: highlight(msg.text) }} />
        {msg.evidence && (
          <div className="evidence">
            {msg.evidence.map((e, i) => (
              <div key={i} className="ev-row" data-type={e.type}>
                <div className="ev-type mono">{e.type}</div>
                <div className="ev-pair">
                  <div className="ev-label">{e.label}</div>
                  <div className="ev-value mono">{e.value}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ChatThinking() {
  return (
    <div className="msg msg-ai">
      <div className="msg-avatar"><Icon.brain width="14" height="14"/></div>
      <div className="msg-body">
        <div className="msg-name">SOCPilots AI <span className="msg-tag">thinking</span></div>
        <div className="thinking">
          <span/> <span/> <span/>
          <span className="th-text mono">running SIEM query · enriching IOCs · drafting plan…</span>
        </div>
      </div>
    </div>
  );
}

function highlight(t) {
  return t
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>');
}

// ============= CASES KANBAN =============
function PageCases({ onOpenCase }) {
  const D = window.SOC_DATA;
  const lanes = [
    { key: 'new',        label: 'NEW',         sev: 'critical', items: D.CASES.new },
    { key: 'inProgress', label: 'IN PROGRESS', sev: 'high',     items: D.CASES.inProgress },
    { key: 'resolved',   label: 'RESOLVED',    sev: 'medium',   items: D.CASES.resolved },
    { key: 'closed',     label: 'CLOSED',      sev: 'low',      items: D.CASES.closed },
  ];
  const [selected, setSelected] = useStateI(D.CASES.new[0]);

  return (
    <div className="page" data-screen-label="04 SP-CM Cases">
      <Topbar
        title="SP-CM Cases"
        sub="Case Management · TheHive"
        actions={<>
          <button className="btn btn-ghost"><Icon.filter width="13" height="13"/> Filter</button>
          <button className="btn btn-ghost">All assignees <Icon.chevron width="12" height="12"/></button>
          <button className="btn btn-primary" onClick={() => window.socToast?.({title:'New case', sub:'CASE-4472 created', tone:'ok'})}><Icon.plus width="13" height="13"/> New case</button>
        </>}
      />

      <div className="page-body">
        <div className="kanban">
          {lanes.map(lane => (
            <div key={lane.key} className="lane">
              <header className="lane-head" data-sev={lane.sev}>
                <span className="lane-bar" />
                <span className="lane-label">{lane.label}</span>
                <span className="lane-count mono">{lane.items.length}</span>
                <button className="btn-icon lane-add"><Icon.plus width="12" height="12"/></button>
              </header>
              <div className="lane-body">
                {lane.items.map(c => (
                  <button
                    key={c.id}
                    className={`case-card ${selected?.id === c.id ? 'sel' : ''}`}
                    onClick={() => { setSelected(c); onOpenCase?.(c); }}
                  >
                    <div className="cc-top">
                      <SevDot sev={c.sev}/>
                      <span className="cc-id mono">{c.id}</span>
                      <span className="cc-age mono">{c.age}</span>
                    </div>
                    <div className="cc-title">{c.title}</div>
                    <div className="cc-tags">
                      {c.tags.map(t => <Chip key={t} mono>{t}</Chip>)}
                    </div>
                    <div className="cc-foot">
                      <span className="cc-alerts mono"><Icon.bell width="10" height="10"/> {c.alerts}</span>
                      {c.assignee ? (
                        <span className="cc-assignee"><span className="cc-avatar">{c.assignee[0].toUpperCase()}</span>{c.assignee}</span>
                      ) : (
                        <span className="cc-unassigned">unassigned</span>
                      )}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="cases-hint mono">
          <Icon.brain width="12" height="12"/>
          tip · click any case to open its AI-drafted incident-response runbook
        </div>
      </div>
    </div>
  );
}

// ============= CORRELATION GRAPH =============
function PageCorrelation() {
  const D = window.SOC_DATA;
  const [selected, setSelected] = useStateI('a1');
  const W = 760, H = 480;

  const nodes = D.CORRELATION_NODES.map(n => ({ ...n, px: n.x * W, py: n.y * H }));
  const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
  const edges = D.CORRELATION_EDGES;

  const typeStyle = {
    ip:    { icon: <Icon.globe width="14" height="14"/>, lbl: 'IP' },
    agent: { icon: <Icon.cpu width="14" height="14"/>, lbl: 'AGENT' },
    rule:  { icon: <Icon.file width="14" height="14"/>, lbl: 'RULE' },
    case:  { icon: <Icon.folder width="14" height="14"/>, lbl: 'CASE' },
    user:  { icon: <Icon.user width="14" height="14"/>, lbl: 'USER' },
    hash:  { icon: <Icon.target width="14" height="14"/>, lbl: 'HASH' },
  };
  const sel = nodeById[selected];

  return (
    <div className="page" data-screen-label="05 Correlation">
      <Topbar
        title="Correlation"
        sub="Cross-source link analysis · SIEM + SP-CM + AI"
        actions={<>
          <button className="btn btn-ghost">Layout: force <Icon.chevron width="12" height="12"/></button>
          <button className="btn btn-ghost">Depth: 2</button>
          <button className="btn btn-primary"><Icon.brain width="13" height="13"/> AI report</button>
        </>}
      />
      <div className="page-body">
        <div className="corr-layout">
          <Card title="Link graph" sub="entities related to alert WZ-9281047" padded={false}
            actions={<><Chip mono>{nodes.length} nodes</Chip><Chip mono>{edges.length} edges</Chip></>}>
            <div className="graph-wrap">
              <svg viewBox={`0 0 ${W} ${H}`} className="graph">
                <defs>
                  <pattern id="dotgrid" x="0" y="0" width="24" height="24" patternUnits="userSpaceOnUse">
                    <circle cx="1" cy="1" r="1" fill="var(--ln)"/>
                  </pattern>
                </defs>
                <rect width={W} height={H} fill="url(#dotgrid)" opacity=".4"/>
                {/* Edges */}
                {edges.map(([a,b], i) => {
                  const A = nodeById[a], B = nodeById[b];
                  if (!A || !B) return null;
                  const isOnPath = (selected === a || selected === b);
                  return (
                    <g key={i}>
                      <line x1={A.px} y1={A.py} x2={B.px} y2={B.py}
                        stroke={isOnPath ? 'var(--acc)' : 'var(--ln)'}
                        strokeWidth={isOnPath ? 1.5 : 1}
                        opacity={isOnPath ? 0.9 : 0.45}
                      />
                    </g>
                  );
                })}
                {/* Nodes */}
                {nodes.map(n => {
                  const isSel = selected === n.id;
                  const sevColor = `var(--${n.sev === 'critical' ? 'crit' : n.sev === 'high' ? 'high' : n.sev === 'medium' ? 'med' : 'low'})`;
                  return (
                    <g key={n.id} transform={`translate(${n.px},${n.py})`}
                       onClick={()=>setSelected(n.id)} style={{cursor:'pointer'}}>
                      {isSel && <circle r="38" fill="none" stroke="var(--acc)" strokeWidth="1" opacity=".5" />}
                      <circle r="26" fill="var(--bg-2)" stroke={sevColor} strokeWidth={isSel ? 2 : 1.2}/>
                      <foreignObject x="-10" y="-10" width="20" height="20">
                        <div style={{color: sevColor, display:'flex', alignItems:'center', justifyContent:'center', height:'100%'}}>
                          {typeStyle[n.type].icon}
                        </div>
                      </foreignObject>
                      <text y="42" textAnchor="middle" className="graph-label">{n.label}</text>
                      <text y="55" textAnchor="middle" className="graph-type">{typeStyle[n.type].lbl}</text>
                    </g>
                  );
                })}
              </svg>
            </div>
          </Card>

          <aside className="corr-side">
            <Card title="Entity" sub={sel ? typeStyle[sel.type].lbl : ''}>
              {sel && (
                <div className="entity">
                  <div className="entity-icon" style={{color: `var(--${sel.sev === 'critical' ? 'crit' : sel.sev === 'high' ? 'high' : 'med'})`}}>
                    {typeStyle[sel.type].icon}
                  </div>
                  <div className="entity-name mono">{sel.label}</div>
                  <div className="entity-sev"><SevChip sev={sel.sev}/></div>
                  <ul className="entity-meta">
                    <li><span>first seen</span><span className="mono">12 min ago</span></li>
                    <li><span>last seen</span><span className="mono">8s ago</span></li>
                    <li><span>related alerts</span><span className="mono">14</span></li>
                    <li><span>connections</span><span className="mono">{edges.filter(e => e[0] === sel.id || e[1] === sel.id).length}</span></li>
                  </ul>
                  <div className="entity-actions">
                    <button className="btn btn-ghost btn-sm">Pivot</button>
                    <button className="btn btn-ghost btn-sm">Enrich</button>
                  </div>
                </div>
              )}
            </Card>

            <Card title="AI report" sub="auto-generated" icon={<Icon.brain width="14" height="14"/>}>
              <div className="ai-report">
                <p>This cluster represents an <strong>active intrusion</strong> originating from <span className="mono">185.220.101.42</span> (Tor exit) that has touched <strong>2 agents</strong> via <strong>2 detection rules</strong>.</p>
                <p>The path <span className="mono">ip1 → a1 → r1 → c1</span> is the highest-confidence attack chain (T1059.001 → T1071 C2). Hash <span className="mono">a4f8b2c…</span> matches a known Cobalt Strike loader.</p>
                <div className="ai-report-actions">
                  <button className="btn btn-primary btn-sm">Open IR runbook</button>
                  <button className="btn btn-ghost btn-sm">Export PDF</button>
                </div>
              </div>
            </Card>
          </aside>
        </div>
      </div>
    </div>
  );
}

// ============= PLACEHOLDER PAGE (for unbuilt routes) =============
function PagePlaceholder({ title, sub }) {
  return (
    <div className="page" data-screen-label={`${title}`}>
      <Topbar title={title} sub={sub} actions={<button className="btn btn-ghost">Help</button>} />
      <div className="page-body">
        <div className="placeholder">
          <div className="ph-mark">
            <Icon.cog width="32" height="32"/>
          </div>
          <h2 className="ph-title">{title}</h2>
          <p className="ph-sub">This page exists in the live SOC Pilots app — included here as a navigation stub. The prototype focuses on the highest-value flows: Dashboard, Alerts, AI Copilot, Cases, and Correlation.</p>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { PageCopilot, PageCases, PageCorrelation, PagePlaceholder });
