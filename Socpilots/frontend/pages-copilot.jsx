// SOCPilots AI v2 — with tool-call visualization
// Overrides the original PageCopilot defined in pages-investigate.jsx.
const { useState: useC2S, useEffect: useC2E, useRef: useC2R, useMemo: useC2M } = React;

// Each AI message carries an array of `toolCalls` showing the reasoning chain.
const COPILOT_CHAIN_V2 = [
  {
    role: 'user',
    text: 'Investigate alert WZ-9281047 — PowerShell on web-prod-01.',
  },
  {
    role: 'ai',
    toolCalls: [
      {
        id: 'tc1', tool: 'siem.search',
        args: { index: 'wazuh-alerts-*', query: '_id:"WZ-9281047"', fields: ['process.*', 'data.*', 'rule.*'] },
        status: 'complete', duration: 142,
        result: {
          hits: 1,
          summary: '1 alert · 14:22:11 UTC · rule 92653 · level 13 · agent.id=003',
        },
      },
      {
        id: 'tc2', tool: 'siem.get_process_tree',
        args: { agent_id: '003', timestamp: '2026-05-13T14:22:11Z', depth: 4 },
        status: 'complete', duration: 287,
        result: {
          hits: 3,
          summary: 'systemd(1) → sshd(4127) → bash(8201) → cmd.exe(8442) → powershell.exe(8443)',
          notable: 'powershell.exe spawned with -enc flag; decoded args fetch http://185.220.101.42/payload.bin',
        },
      },
      {
        id: 'tc3', tool: 'mcp.enrich_ip',
        args: { ip: '185.220.101.42', sources: ['virustotal', 'abuseipdb', 'alienvault'] },
        status: 'complete', duration: 612,
        result: {
          hits: 3,
          summary: 'malicious · 4 sources agree',
          notable: 'VT 18/94 · AbuseIPDB 100% · AlienVault: Tor exit · GreyNoise: scanner',
        },
      },
      {
        id: 'tc4', tool: 'spcm.find_related',
        args: { ioc: '185.220.101.42', lookback_days: 30 },
        status: 'complete', duration: 89,
        result: {
          hits: 1,
          summary: '1 prior case · CASE-4438 (3d ago)',
          notable: 'Same IP touched web-prod-01 in CASE-4438 (contained · ransomware staging)',
        },
      },
      {
        id: 'tc5', tool: 'mcp.hash_lookup',
        args: { hash: 'a4f8b2c91d3e0775fa2b8c91d3e0775', kind: 'sha256' },
        status: 'complete', duration: 198,
        result: {
          hits: 1,
          summary: 'Cobalt Strike loader · YARA family CS_loader_v4',
          notable: 'VT 62/94 · first seen 2024-08-12',
        },
      },
      {
        id: 'tc6', tool: 'reason',
        args: { task: 'synthesize verdict + confidence + recommended actions' },
        status: 'complete', duration: 1840,
        result: { hits: 1, summary: 'synthesis complete' },
      },
    ],
    verdict: { label: 'true-positive · active intrusion', confidence: 96, tone: 'crit' },
    text: 'This is an **active intrusion**, not a false positive. A base64-encoded PowerShell payload spawned by `cmd.exe` at 15:42:11 UTC attempted to download a Cobalt Strike loader (hash matches the same family from CASE-4438 three days ago) from `185.220.101.42` — a known Tor exit. **MITRE: T1059.001 + T1071.** Recommend immediate containment of `web-prod-01`, perimeter block on the source IP, and rotation of `svc_backup` credentials. Containment runbook is ready when you are.',
  },
  {
    role: 'user',
    text: 'Recommend containment.',
  },
];

// Replacement PageCopilot
function PageCopilot() {
  const [msgs, setMsgs] = useC2S([]);
  const [draft, setDraft] = useC2S('');
  const [thinking, setThinking] = useC2S(false);
  const [thinkingChain, setThinkingChain] = useC2S([]); // tool calls being streamed
  const [thinkingFinalDraft, setThinkingFinalDraft] = useC2S('');
  const scrollRef = useC2R(null);

  const socUser = sessionStorage.getItem('soc_user') || 'analyst';
  const userAvatar = socUser.slice(0, 2).toUpperCase();

  useC2E(() => {
    scrollRef.current?.scrollTo({ top: 999999, behavior: 'smooth' });
  }, [msgs, thinking, thinkingChain]);

  async function send(text) {
    if (!text.trim()) return;
    const history = msgs.slice(-6).map(m => ({ role: m.role === 'ai' ? 'assistant' : 'user', content: m.text }));
    setMsgs(m => [...m, { role: 'user', text }]);
    setDraft('');
    setThinking(true);
    // Push streaming placeholder
    setMsgs(m => [...m, { role: 'ai', text: '', streaming: true }]);
    await window.SOC_API.stream(
      '/api/ai/chat/stream',
      { message: text, history, session_id: `soc_${socUser}` },
      (partial) => {
        setMsgs(m => {
          const copy = [...m];
          const last = copy[copy.length - 1];
          if (last?.streaming) copy[copy.length - 1] = { ...last, text: partial };
          return copy;
        });
      },
      (full) => {
        setThinking(false);
        setMsgs(m => {
          const copy = [...m];
          const last = copy[copy.length - 1];
          if (last?.streaming) copy[copy.length - 1] = { role: 'ai', text: full || 'No response from AI.' };
          return copy;
        });
      }
    );
  }

  return (
    <div className="page page-copilot" data-screen-label="03 SOCPilots AI">
      <Topbar
        title="SOCPilots AI"
        sub="Connected to SIEM · SP-CM · MCP · gpt-4o"
        actions={<>
          <Chip mono tone="ok"><span className="pip pip-ok"/> n8n online</Chip>
          <Chip mono>session · {msgs.length} turns</Chip>
          <button className="btn btn-ghost" onClick={() => setMsgs([])}>New session</button>
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
              'Recommend containment',
              'Summarize last 24h activity',
              'What changed since last shift?',
              'Show me unresolved P1 cases',
              'Generate exec report',
            ].map(p => (
              <button key={p} className="cs-prompt" onClick={()=>send(p)}>
                <Icon.spark width="11" height="11" /> {p}
              </button>
            ))}
          </div>

          <div className="cs-section">
            <div className="cs-label">CONNECTED TOOLS</div>
            <div className="tool-pip-list">
              <ToolPip name="siem.search" status="ok"/>
              <ToolPip name="siem.get_process_tree" status="ok"/>
              <ToolPip name="mcp.enrich_ip" status="ok"/>
              <ToolPip name="mcp.hash_lookup" status="ok"/>
              <ToolPip name="spcm.find_related" status="ok"/>
              <ToolPip name="spcm.update_case" status="ok"/>
              <ToolPip name="wazuh.active_response" status="ok"/>
              <ToolPip name="firewall.block" status="ok"/>
              <ToolPip name="ad.suspend_account" status="warn"/>
              <ToolPip name="virustotal.lookup" status="warn"/>
            </div>
          </div>
        </aside>

        <main className="copilot-main">
          <div className="chat" ref={scrollRef}>
            {msgs.length === 0 && !thinking && (
              <div className="chat-empty">
                <Icon.brain width="32" height="32" style={{opacity: 0.3}}/>
                <div className="mono dim" style={{marginTop: 12}}>Start a conversation</div>
                <div className="mono dim" style={{fontSize: '0.78rem', marginTop: 4}}>Ask SOCPilots AI to investigate, triage, or summarize</div>
              </div>
            )}
            {msgs.map((m, i) => <ChatMessageV2 key={i} msg={m} userAvatar={userAvatar} socUser={socUser} />)}
            {thinking && (
              <ChatStreamingV2 chain={thinkingChain} text={thinkingFinalDraft}/>
            )}
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
                placeholder="Ask SOCPilots AI…   try: 'recommend containment', 'pivot on src.ip', 'draft IR runbook'"
                rows="2"
              />
              <button className="btn btn-primary" onClick={()=>send(draft || 'Recommend containment')}>
                <Icon.send width="14" height="14"/> Send <Kbd>↵</Kbd>
              </button>
            </div>
            <div className="composer-foot mono">
              connected · SIEM ✓ SP-CM ✓ MCP ✓ · model gpt-4o · response avg 2.1s · 10 tools
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

function ChatMessageV2({ msg, userAvatar, socUser }) {
  if (msg.role === 'user') {
    return (
      <div className="msg msg-user">
        <div className="msg-avatar">{userAvatar || 'AN'}</div>
        <div className="msg-body">
          <div className="msg-name">{socUser || 'analyst'}</div>
          <div className="msg-text">{msg.text}</div>
        </div>
      </div>
    );
  }
  return (
    <div className="msg msg-ai">
      <div className="msg-avatar"><Icon.brain width="14" height="14"/></div>
      <div className="msg-body">
        <div className="msg-name">
          SOCPilots AI <span className="msg-tag">gpt-4o</span>
          {msg.toolCalls && (
            <span className="msg-tag msg-tag-soft">
              {msg.toolCalls.length} tools · {(msg.toolCalls.reduce((a,b)=>a+b.duration,0)/1000).toFixed(1)}s
            </span>
          )}
        </div>
        {msg.toolCalls && (
          <ToolChain chain={msg.toolCalls} collapsed/>
        )}
        {msg.verdict && (
          <div className="ai-verdict-v2" data-tone={msg.verdict.tone}>
            <div className="avv-pill">
              <SevDot sev={msg.verdict.tone === 'crit' ? 'critical' : msg.verdict.tone === 'info' ? 'info' : 'low'} size={6}/>
              {msg.verdict.label}
              <span className="avv-conf mono">{msg.verdict.confidence}%</span>
            </div>
          </div>
        )}
        {msg.streaming ? (
          <div className="msg-text msg-streaming">
            {msg.text ? <span dangerouslySetInnerHTML={{ __html: renderMd(msg.text) + '<span class="cursor"></span>' }} /> : <span className="mono dim">…</span>}
          </div>
        ) : (
          <div className="msg-text" dangerouslySetInnerHTML={{ __html: renderMd(msg.text) }} />
        )}
      </div>
    </div>
  );
}

function ChatStreamingV2({ chain, text }) {
  return (
    <div className="msg msg-ai">
      <div className="msg-avatar"><Icon.brain width="14" height="14"/></div>
      <div className="msg-body">
        <div className="msg-name">
          SOCPilots AI
          <span className="msg-tag thinking-tag">
            <span className="th-dots"><i/><i/><i/></span>
            {text ? 'writing' : `running tools (${chain.filter(c=>c.status==='complete').length}/${chain.length})`}
          </span>
        </div>
        {chain.length > 0 && <ToolChain chain={chain}/>}
        {text && <div className="msg-text" dangerouslySetInnerHTML={{ __html: renderMd(text) + '<span class="cursor"></span>' }} />}
      </div>
    </div>
  );
}

function ToolChain({ chain, collapsed }) {
  const [open, setOpen] = useC2S(collapsed ? false : true);
  const [expandedCallId, setExpandedCallId] = useC2S(null);

  const totalMs = chain.reduce((a,b) => a + (b.duration || 0), 0);
  const visible = open;

  return (
    <div className="tool-chain">
      <button className="tool-chain-head" onClick={() => setOpen(o => !o)}>
        <Icon.chevron width="11" height="11" style={{transform: visible ? 'rotate(90deg)' : 'none', transition: 'transform .12s'}}/>
        <span className="mono">reasoning chain · {chain.length} tool calls · {(totalMs/1000).toFixed(2)}s</span>
      </button>
      {visible && (
        <ol className="tool-chain-list">
          {chain.map((c, i) => (
            <ToolCallRow
              key={c.id}
              call={c}
              expanded={expandedCallId === c.id}
              onToggle={() => setExpandedCallId(id => id === c.id ? null : c.id)}
              isLast={i === chain.length - 1}
            />
          ))}
        </ol>
      )}
    </div>
  );
}

function ToolCallRow({ call, expanded, onToggle, isLast }) {
  return (
    <li className={`tool-call tc-${call.status}`}>
      <div className="tc-rail">
        <div className={`tc-bullet status-${call.status}`}>
          {call.status === 'complete' && <Icon.check width="9" height="9"/>}
          {call.status === 'running' && <span className="tc-spin"/>}
          {call.status === 'failed' && <Icon.x width="9" height="9"/>}
        </div>
        {!isLast && <div className="tc-line"/>}
      </div>
      <button className="tc-body" onClick={onToggle}>
        <div className="tc-head">
          <span className="tc-tool mono">{call.tool}</span>
          <span className="tc-args mono">{compactArgs(call.args)}</span>
          {call.status === 'complete' && call.duration && (
            <span className="tc-duration mono">{call.duration}ms</span>
          )}
        </div>
        {call.status === 'complete' && call.result && (
          <div className="tc-result-line mono">
            <span className="tc-arrow">→</span>
            <span className="tc-result-summary">{call.result.summary}</span>
            {call.result.hits != null && <span className="tc-result-hits">· {call.result.hits} hit{call.result.hits === 1 ? '' : 's'}</span>}
          </div>
        )}
        {expanded && call.status === 'complete' && (
          <div className="tc-expanded">
            <div className="tc-expand-row">
              <span className="tc-expand-key mono">args</span>
              <pre className="tc-expand-val mono">{JSON.stringify(call.args, null, 2)}</pre>
            </div>
            <div className="tc-expand-row">
              <span className="tc-expand-key mono">result</span>
              <pre className="tc-expand-val mono">{JSON.stringify(call.result, null, 2)}</pre>
            </div>
            {(call.notable || call.result.notable) && (
              <div className="tc-notable mono">
                <Icon.alert width="10" height="10"/> {call.notable || call.result.notable}
              </div>
            )}
          </div>
        )}
      </button>
    </li>
  );
}

function compactArgs(args) {
  if (!args) return '';
  const parts = Object.entries(args).slice(0, 3).map(([k, v]) => {
    const sv = typeof v === 'string' ? `"${v.length > 28 ? v.slice(0, 28) + '…' : v}"` : Array.isArray(v) ? `[${v.length}]` : typeof v === 'object' ? '{…}' : String(v);
    return `${k}: ${sv}`;
  });
  return '(' + parts.join(', ') + (Object.keys(args).length > 3 ? ', …' : '') + ')';
}

function ToolPip({ name, status }) {
  return (
    <div className="tool-pip">
      <SevDot sev={status === 'ok' ? 'low' : status === 'warn' ? 'medium' : 'critical'} size={5}/>
      <span className="mono">{name}</span>
    </div>
  );
}

function renderMd(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .split('\n\n').map(p => {
      if (/^\s*\d\./.test(p)) {
        const items = p.split(/\n/).filter(l => /^\s*\d\./.test(l));
        return '<ol>' + items.map(l => '<li>' + l.replace(/^\s*\d\.\s*/, '') + '</li>').join('') + '</ol>';
      }
      return '<p>' + p.replace(/\n/g, '<br/>') + '</p>';
    }).join('');
}

// Override the old export
Object.assign(window, { PageCopilot });
