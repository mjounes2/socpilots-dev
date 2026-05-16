// SOCPilots AI Copilot — wired to real LangChain ReAct agent
// Overrides the stub PageCopilot from pages-investigate.jsx
const { useState: useC2S, useEffect: useC2E, useRef: useC2R } = React;

const WELCOME_MSG = {
  role: 'ai',
  text: 'Connected to SIEM, SP-CM, and threat intelligence feeds. I can investigate alerts, enrich IOCs, pivot on IPs/hashes, review cases, and draft incident response runbooks.\n\nTry: **"Summarize last 24h threats"**, **"What are the top attacking IPs today?"**, or paste an alert ID to investigate.',
  duration_ms: null,
  steps: null,
};

function PageCopilot() {
  const API = window.SOC_API;
  const user = sessionStorage.getItem('soc_user') || 'analyst';
  const [msgs, setMsgs] = useC2S([WELCOME_MSG]);
  const [draft, setDraft] = useC2S('');
  const [thinking, setThinking] = useC2S(false);
  const [sessions, setSessions] = useC2S([]);
  const scrollRef = useC2R(null);
  const taRef = useC2R(null);

  useC2E(() => {
    scrollRef.current?.scrollTo({ top: 999999, behavior: 'smooth' });
  }, [msgs, thinking]);

  const send = async (text) => {
    const q = text.trim();
    if (!q || thinking) return;
    setDraft('');
    setMsgs(m => [...m, { role: 'user', text: q }]);
    setThinking(true);

    const t0 = Date.now();
    const res = await API.post('/api/langchain/investigate', { message: q });
    const elapsed = Date.now() - t0;

    setThinking(false);

    if (!res || res.error) {
      setMsgs(m => [...m, {
        role: 'ai',
        text: `Error: ${res?.error || 'LangChain agent unavailable. Ensure the langchain-agent service is running.'}`,
        isError: true,
      }]);
      return;
    }

    setMsgs(m => [...m, {
      role: 'ai',
      text: res.report || '(No response)',
      steps: res.steps,
      duration_ms: res.duration_ms || elapsed,
      model: res.model || 'gpt-4',
      structured: res.structured || null,
    }]);

    // Keep a simple session log
    setSessions(s => {
      const entry = { text: q.slice(0, 60), ts: new Date().toISOString() };
      return [entry, ...s.slice(0, 9)];
    });
  };

  const onKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(draft); }
  };

  const quickPrompts = [
    'Summarize last 24h threats',
    'What are the top attacking IPs today?',
    'Show me critical alerts from the last hour',
    'Are there signs of lateral movement?',
    'What MITRE techniques are active?',
    'Draft an executive summary',
  ];

  return (
    <div className="page page-copilot" data-screen-label="03 SOCPilots AI">
      <Topbar
        title="SOCPilots AI"
        sub="ReAct agent · SIEM · SP-CM · TI feeds"
        actions={<>
          <button className="btn btn-ghost" onClick={() => { setMsgs([WELCOME_MSG]); setSessions([]); }}>
            New session
          </button>
        </>}
      />

      <div className="copilot-layout">
        <aside className="copilot-sessions">
          <div className="cs-section">
            <div className="cs-label">QUICK PROMPTS</div>
            {quickPrompts.map(p => (
              <button key={p} className="cs-prompt" onClick={() => send(p)} disabled={thinking}>
                <Icon.spark width="11" height="11" /> {p}
              </button>
            ))}
          </div>

          {sessions.length > 0 && (
            <div className="cs-section">
              <div className="cs-label">THIS SESSION</div>
              {sessions.map((s, i) => (
                <button key={i} className="cs-item" onClick={() => send(s.text)}>
                  <SevDot sev="low" size={6}/>
                  <div>
                    <div className="cs-title">{s.text}</div>
                    <div className="cs-sub mono">{new Date(s.ts).toLocaleTimeString()}</div>
                  </div>
                </button>
              ))}
            </div>
          )}

          <div className="cs-section">
            <div className="cs-label">CONNECTED TOOLS</div>
            <div className="tool-pip-list">
              <ToolPip name="search_alerts" />
              <ToolPip name="enrich_ip" />
              <ToolPip name="check_cases" />
              <ToolPip name="query_ueba" />
              <ToolPip name="query_assets" />
              <ToolPip name="query_shodan" />
            </div>
          </div>
        </aside>

        <main className="copilot-main">
          <div className="chat" ref={scrollRef}>
            {msgs.map((m, i) => <ChatMsg key={i} msg={m} user={user} />)}
            {thinking && <ChatThinking />}
          </div>

          <div className="composer">
            <div className="composer-input">
              <textarea
                ref={taRef}
                value={draft}
                onChange={e => setDraft(e.target.value)}
                onKeyDown={onKey}
                placeholder="Ask SOCPilots AI… investigate alert, pivot on IP, summarize threats"
                rows="2"
                disabled={thinking}
              />
              <button className="btn btn-primary" onClick={() => send(draft)} disabled={thinking || !draft.trim()}>
                <Icon.send width="14" height="14" /> Send <Kbd>↵</Kbd>
              </button>
            </div>
            <div className="composer-foot mono">
              {thinking
                ? 'ReAct agent running… this may take 30–120s'
                : 'SIEM ✓  SP-CM ✓  MCP ✓  TI ✓  · model: gpt-4  · Enter to send'}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

function ChatMsg({ msg, user }) {
  if (msg.role === 'user') {
    return (
      <div className="msg msg-user">
        <div className="msg-avatar">{(user[0] || 'A').toUpperCase()}</div>
        <div className="msg-body">
          <div className="msg-name">{user}</div>
          <div className="msg-text">{msg.text}</div>
        </div>
      </div>
    );
  }
  return (
    <div className={`msg msg-ai ${msg.isError ? 'msg-error' : ''}`}>
      <div className="msg-avatar"><Icon.brain width="14" height="14"/></div>
      <div className="msg-body">
        <div className="msg-name">
          SOCPilots AI
          {msg.model && <span className="msg-tag">{msg.model}</span>}
          {msg.steps > 0 && <span className="msg-tag msg-tag-soft">{msg.steps} reasoning steps</span>}
          {msg.duration_ms > 0 && <span className="msg-tag msg-tag-soft">{(msg.duration_ms/1000).toFixed(1)}s</span>}
        </div>
        <div className="msg-text" dangerouslySetInnerHTML={{ __html: renderMd(msg.text) }} />
        {msg.structured && <StructuredResult data={msg.structured} />}
      </div>
    </div>
  );
}

function StructuredResult({ data }) {
  if (!data) return null;
  return (
    <div className="ai-structured">
      {data.verdict && (
        <div className="ai-verdict-v2" data-tone={data.verdict === 'true_positive' ? 'crit' : 'info'}>
          <div className="avv-pill">
            <SevDot sev={data.verdict === 'true_positive' ? 'critical' : 'low'} size={6}/>
            {data.verdict.replace('_', ' ')}
            {data.confidence != null && <span className="avv-conf mono">{data.confidence}%</span>}
          </div>
        </div>
      )}
      {data.mitre_techniques?.length > 0 && (
        <div style={{marginTop:6,fontSize:11,color:'var(--txt-2)'}}>
          MITRE: {data.mitre_techniques.map(t => <span key={t} className="mono" style={{marginRight:6,color:'var(--acc)'}}>{t}</span>)}
        </div>
      )}
      {data.recommended_actions?.length > 0 && (
        <div style={{marginTop:8}}>
          <div className="ds-title">Recommended actions</div>
          <ol style={{margin:'4px 0 0 16px',fontSize:12,color:'var(--txt-2)'}}>
            {data.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}
          </ol>
        </div>
      )}
    </div>
  );
}

function ChatThinking() {
  return (
    <div className="msg msg-ai">
      <div className="msg-avatar"><Icon.brain width="14" height="14"/></div>
      <div className="msg-body">
        <div className="msg-name">SOCPilots AI <span className="msg-tag thinking-tag">running agent</span></div>
        <div className="thinking">
          <span/><span/><span/>
          <span className="th-text mono">querying SIEM · enriching IOCs · building verdict…</span>
        </div>
      </div>
    </div>
  );
}

function ToolPip({ name }) {
  return (
    <div className="tool-pip">
      <SevDot sev="low" size={5}/>
      <span className="mono">{name}</span>
    </div>
  );
}

function renderMd(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .split('\n\n').map(p => {
      if (/^\s*[-*]\s/.test(p)) {
        return '<ul>' + p.split('\n').filter(l => /^\s*[-*]\s/.test(l))
          .map(l => '<li>' + l.replace(/^\s*[-*]\s/, '') + '</li>').join('') + '</ul>';
      }
      if (/^\s*\d+\.\s/.test(p)) {
        return '<ol>' + p.split('\n').filter(l => /^\s*\d+\.\s/.test(l))
          .map(l => '<li>' + l.replace(/^\s*\d+\.\s*/, '') + '</li>').join('') + '</ol>';
      }
      return '<p>' + p.replace(/\n/g, '<br/>') + '</p>';
    }).join('');
}

Object.assign(window, { PageCopilot });
