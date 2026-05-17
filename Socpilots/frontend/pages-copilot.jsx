// SOCPilots AI Copilot — chat history, timestamps, copy & reload
const {
  useState: useC2S, useEffect: useC2E, useRef: useC2R,
  useCallback: useC2CB, useMemo: useC2M,
} = React;

// ── helpers ─────────────────────────────────────────────────────────
function fmtMsgTime(ts) {
  if (!ts) return '';
  const d   = new Date(ts);
  const now = new Date();
  const sod = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const mod = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const diffDays = Math.round((sod - mod) / 86400000);
  const hhmm = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  if (diffDays === 0) return hhmm;
  if (diffDays === 1) return `Yesterday · ${hhmm}`;
  if (diffDays <  7) return `${d.toLocaleDateString('en-GB',{weekday:'short'})} · ${hhmm}`;
  return `${d.toLocaleDateString('en-GB',{day:'2-digit',month:'short'})} · ${hhmm}`;
}

function dayLabel(ts) {
  if (!ts) return null;
  const d    = new Date(ts);
  const now  = new Date();
  const diff = Math.round((now - d) / 86400000);
  if (diff < 1) return 'Today';
  if (diff < 2) return 'Yesterday';
  return d.toLocaleDateString('en-GB', { weekday:'long', day:'numeric', month:'long', year:'numeric' });
}

function newSid() { return `soc_${Date.now()}_${Math.random().toString(36).slice(2,7)}`; }

// ── welcome message ──────────────────────────────────────────────────
const WELCOME_MSG = {
  role: 'ai', isWelcome: true,
  text: 'Connected to SIEM, SP-CM, and threat intelligence feeds. I can investigate alerts, enrich IOCs, pivot on IPs/hashes, review cases, and draft incident response runbooks.\n\nTry: **"Summarize last 24h threats"**, **"What are the top attacking IPs today?"**, or paste an alert ID to investigate.',
};

// ── quick prompts ────────────────────────────────────────────────────
const QUICK_PROMPTS = [
  'Summarize last 24h threats',
  'What are the top attacking IPs today?',
  'Show me critical alerts from the last hour',
  'Are there signs of lateral movement?',
  'What MITRE techniques are active?',
  'Draft an executive summary',
];

// ── main component ───────────────────────────────────────────────────
function PageCopilot() {
  const API  = window.SOC_API;
  const user = sessionStorage.getItem('soc_user') || 'analyst';

  const [sessionId,      setSessionId]      = useC2S(() => newSid());
  const [msgs,           setMsgs]           = useC2S([WELCOME_MSG]);
  const [draft,          setDraft]          = useC2S('');
  const [thinking,       setThinking]       = useC2S(false);
  const [pastSessions,   setPastSessions]   = useC2S([]);
  const [loadingHistory, setLoadingHistory] = useC2S(false);
  const [activeSession,  setActiveSession]  = useC2S(null);

  const scrollRef = useC2R(null);
  const taRef     = useC2R(null);

  // Auto-scroll to bottom on new messages
  useC2E(() => {
    scrollRef.current?.scrollTo({ top: 999999, behavior: 'smooth' });
  }, [msgs, thinking]);

  // Load session list on mount
  useC2E(() => { fetchSessions(); }, []);

  const fetchSessions = useC2CB(async () => {
    const data = await API.get('/api/chat/sessions?limit=20');
    setPastSessions(data?.sessions || []);
  }, []);

  const restoreSession = useC2CB(async (sid) => {
    setLoadingHistory(true);
    setActiveSession(sid);
    const data = await API.get(`/api/chat/sessions/${sid}?limit=100`);
    const messages = (data?.messages || []).map(m => ({
      role: m.role === 'assistant' ? 'ai' : 'user',
      text: m.content,
      ts:   m.created_at,
    }));
    setMsgs(messages.length > 0 ? messages : [WELCOME_MSG]);
    setSessionId(sid);
    setLoadingHistory(false);
  }, []);

  const deleteSession = useC2CB(async (sid, e) => {
    e.stopPropagation();
    await API.del(`/api/chat/sessions/${sid}`);
    setPastSessions(s => s.filter(x => x.session_id !== sid));
    if (sid === sessionId) startNewSession();
  }, [sessionId]);

  const startNewSession = useC2CB(() => {
    const sid = newSid();
    setSessionId(sid);
    setActiveSession(null);
    setMsgs([WELCOME_MSG]);
    fetchSessions();
  }, []);

  const buildHistory = (messages) =>
    messages
      .filter(m => !m.isWelcome && !m.isError)
      .slice(-8)
      .map(m => ({ role: m.role === 'ai' ? 'assistant' : 'user', content: m.text }));

  const send = useC2CB(async (text) => {
    const q = (text || '').trim();
    if (!q || thinking) return;
    setDraft('');
    const userMsg = { role: 'user', text: q, ts: new Date().toISOString() };
    setMsgs(m => [...m, userMsg]);
    setThinking(true);

    const history = buildHistory(msgs);
    const t0 = Date.now();

    const res = await API.post('/api/ai/chat', {
      message:    q,
      history,
      session_id: sessionId,
    });

    const elapsed = Date.now() - t0;
    setThinking(false);

    if (!res || res.error) {
      setMsgs(m => [...m, {
        role: 'ai', isError: true,
        text: `Error: ${res?.error || 'SOCPilots AI unavailable. Ensure the langchain-agent service is running.'}`,
        ts: new Date().toISOString(),
      }]);
      return;
    }

    setMsgs(m => [...m, {
      role:        'ai',
      text:        res.response || '(No response)',
      tools_used:  res.tools_used,
      duration_ms: res.duration_ms || elapsed,
      model:       res.model || null,
      ts:          new Date().toISOString(),
    }]);

    fetchSessions();
  }, [thinking, msgs, sessionId]);

  const onKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(draft); }
  };

  // Group messages by day for dividers
  const msgGroups = useC2M(() => {
    const result = [];
    let lastDay = null;
    for (const m of msgs) {
      const day = m.ts ? dayLabel(m.ts) : null;
      if (day && day !== lastDay) {
        result.push({ type: 'divider', label: day });
        lastDay = day;
      }
      result.push({ type: 'msg', msg: m });
    }
    return result;
  }, [msgs]);

  return (
    <div className="page page-copilot" data-screen-label="03 SOCPilots AI">
      <Topbar
        title="SOCPilots AI"
        sub="ReAct agent · SIEM · SP-CM · TI feeds"
        actions={<>
          <button className="btn btn-ghost" onClick={startNewSession}>
            <Icon.plus width="12" height="12"/> New session
          </button>
        </>}
      />

      <div className="copilot-layout">

        {/* ── LEFT SIDEBAR ── */}
        <aside className="copilot-sessions">

          {/* Chat history from DB */}
          <div className="cs-section">
            <div className="cs-label" style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
              CHAT HISTORY
              <button style={{fontSize:9,opacity:.5,background:'none',border:'none',cursor:'pointer',color:'var(--fg-2)'}}
                onClick={fetchSessions}>↻</button>
            </div>
            {loadingHistory ? (
              <div style={{padding:'8px 0',textAlign:'center'}}><Spinner size={14}/></div>
            ) : pastSessions.length === 0 ? (
              <div style={{fontSize:11,color:'var(--fg-3)',padding:'6px 0'}}>No history yet</div>
            ) : pastSessions.map(s => {
              const isActive = s.session_id === (activeSession || sessionId);
              const preview  = (s.last_content || '').slice(0, 52) + ((s.last_content || '').length > 52 ? '…' : '');
              const timeStr  = s.last_message ? fmtMsgTime(s.last_message) : '';
              return (
                <div key={s.session_id}
                  className={`cs-item ${isActive ? 'cs-item-active' : ''}`}
                  onClick={() => restoreSession(s.session_id)}
                  style={{cursor:'pointer',paddingRight:4}}
                >
                  <SevDot sev={isActive ? 'low' : 'medium'} size={5}/>
                  <div style={{flex:1,minWidth:0}}>
                    <div className="cs-title" style={{
                      overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',
                      color: isActive ? 'var(--acc)' : 'var(--fg-1)',
                    }}>{preview || 'Session'}</div>
                    <div className="cs-sub mono" style={{display:'flex',gap:6}}>
                      <span>{timeStr}</span>
                      <span style={{opacity:.5}}>· {s.count} msg</span>
                    </div>
                  </div>
                  <button
                    onClick={(e) => deleteSession(s.session_id, e)}
                    style={{
                      background:'none',border:'none',cursor:'pointer',opacity:.35,
                      color:'var(--fg-2)',padding:'2px 4px',flexShrink:0,
                      fontSize:13,lineHeight:1,
                    }}
                    title="Delete session"
                  >×</button>
                </div>
              );
            })}
          </div>

          {/* Quick prompts */}
          <div className="cs-section">
            <div className="cs-label">QUICK PROMPTS</div>
            {QUICK_PROMPTS.map(p => (
              <button key={p} className="cs-prompt" onClick={() => send(p)} disabled={thinking}>
                <Icon.spark width="11" height="11"/> {p}
              </button>
            ))}
          </div>

          {/* Connected tools */}
          <div className="cs-section">
            <div className="cs-label">CONNECTED TOOLS</div>
            <div className="tool-pip-list">
              {['search_alerts','enrich_ip','check_cases','query_ueba','query_assets','query_shodan'].map(n => (
                <div key={n} className="tool-pip">
                  <SevDot sev="low" size={5}/>
                  <span className="mono">{n}</span>
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* ── CHAT MAIN ── */}
        <main className="copilot-main">
          <div className="chat" ref={scrollRef}>
            {msgGroups.map((item, i) =>
              item.type === 'divider' ? (
                <div key={`d-${i}`} style={{
                  display:'flex',alignItems:'center',gap:10,
                  margin:'12px 0 6px',padding:'0 4px',
                }}>
                  <div style={{flex:1,height:1,background:'var(--ln)'}}/>
                  <span style={{fontSize:10,color:'var(--fg-3)',fontFamily:'var(--mono)',whiteSpace:'nowrap'}}>
                    {item.label}
                  </span>
                  <div style={{flex:1,height:1,background:'var(--ln)'}}/>
                </div>
              ) : (
                <ChatMsg key={i} msg={item.msg} user={user} onReload={send} />
              )
            )}
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
              <button className="btn btn-primary" onClick={() => send(draft)}
                disabled={thinking || !draft.trim()}>
                <Icon.send width="14" height="14"/> Send <Kbd>↵</Kbd>
              </button>
            </div>
            <div className="composer-foot mono">
              {thinking
                ? 'ReAct agent running… this may take 30–120s'
                : 'SIEM ✓  SP-CM ✓  MCP ✓  TI ✓  · Enter to send · Shift+Enter for newline'}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

// ── Chat message bubble ──────────────────────────────────────────────
function ChatMsg({ msg, user, onReload }) {
  const [hovered, setHovered] = useC2S(false);
  const [copied,  setCopied]  = useC2S(false);

  const copyText = () => {
    navigator.clipboard?.writeText(msg.text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  };

  const tsStr = msg.ts ? fmtMsgTime(msg.ts) : null;

  const actionBtn = (label, icon, onClick, title) => (
    <button onClick={onClick} title={title} style={{
      display:'inline-flex',alignItems:'center',gap:3,
      background:'none',border:'1px solid var(--ln)',borderRadius:4,
      padding:'2px 7px',fontSize:10,color:'var(--fg-3)',cursor:'pointer',
      transition:'color .15s, border-color .15s',
    }}
      onMouseEnter={e => { e.currentTarget.style.color='var(--fg-1)'; e.currentTarget.style.borderColor='var(--ln-2)'; }}
      onMouseLeave={e => { e.currentTarget.style.color='var(--fg-3)'; e.currentTarget.style.borderColor='var(--ln)'; }}
    >{icon} {label}</button>
  );

  if (msg.role === 'user') {
    return (
      <div className="msg msg-user"
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
      >
        <div className="msg-avatar">{(user[0] || 'A').toUpperCase()}</div>
        <div className="msg-body">
          <div className="msg-name" style={{display:'flex',alignItems:'center',gap:8}}>
            {user}
            {tsStr && (
              <span style={{fontSize:10,color:'var(--fg-3)',fontFamily:'var(--mono)',fontWeight:400}}>
                {tsStr}
              </span>
            )}
          </div>
          <div className="msg-text">{msg.text}</div>
          {hovered && (
            <div style={{display:'flex',gap:5,marginTop:6}}>
              {actionBtn(copied ? 'Copied!' : 'Copy', <Icon.check width="9" height="9"/>, copyText, 'Copy prompt')}
              {actionBtn('Reload', <Icon.refresh width="9" height="9"/>, () => onReload(msg.text), 'Re-send this prompt')}
            </div>
          )}
        </div>
      </div>
    );
  }

  // AI message
  return (
    <div className={`msg msg-ai ${msg.isError ? 'msg-error' : ''}`}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div className="msg-avatar"><Icon.brain width="14" height="14"/></div>
      <div className="msg-body">
        <div className="msg-name" style={{display:'flex',alignItems:'center',gap:6,flexWrap:'wrap'}}>
          SOCPilots AI
          {msg.model       && <span className="msg-tag">{msg.model}</span>}
          {msg.duration_ms > 0 && <span className="msg-tag msg-tag-soft">{(msg.duration_ms/1000).toFixed(1)}s</span>}
          {tsStr && (
            <span style={{fontSize:10,color:'var(--fg-3)',fontFamily:'var(--mono)',fontWeight:400,marginLeft:'auto'}}>
              {tsStr}
            </span>
          )}
        </div>
        {msg.isWelcome ? (
          <div className="msg-text" dangerouslySetInnerHTML={{ __html: renderMd(msg.text) }} />
        ) : (
          <div className="msg-text" dangerouslySetInnerHTML={{ __html: renderMd(msg.text) }} />
        )}
        {msg.structured && <StructuredResult data={msg.structured} />}
        {hovered && !msg.isWelcome && !msg.isError && (
          <div style={{display:'flex',gap:5,marginTop:6}}>
            {actionBtn(copied ? 'Copied!' : 'Copy response', <Icon.check width="9" height="9"/>, copyText, 'Copy AI response')}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Structured verdict block ─────────────────────────────────────────
function StructuredResult({ data }) {
  if (!data) return null;
  return (
    <div className="ai-structured">
      {data.verdict && (
        <div className="ai-verdict-v2" data-tone={data.verdict === 'true_positive' ? 'crit' : 'info'}>
          <div className="avv-pill">
            <SevDot sev={data.verdict === 'true_positive' ? 'critical' : 'low'} size={6}/>
            {data.verdict.replace('_',' ')}
            {data.confidence != null && <span className="avv-conf mono">{data.confidence}%</span>}
          </div>
        </div>
      )}
      {data.mitre_techniques?.length > 0 && (
        <div style={{marginTop:6,fontSize:11,color:'var(--fg-2)'}}>
          MITRE: {data.mitre_techniques.map(t =>
            <span key={t} className="mono" style={{marginRight:6,color:'var(--acc)'}}>{t}</span>
          )}
        </div>
      )}
      {data.recommended_actions?.length > 0 && (
        <div style={{marginTop:8}}>
          <div className="ds-title">Recommended actions</div>
          <ol style={{margin:'4px 0 0 16px',fontSize:12,color:'var(--fg-2)'}}>
            {data.recommended_actions.map((a,i) => <li key={i}>{a}</li>)}
          </ol>
        </div>
      )}
    </div>
  );
}

// ── Thinking indicator ───────────────────────────────────────────────
function ChatThinking() {
  return (
    <div className="msg msg-ai">
      <div className="msg-avatar"><Icon.brain width="14" height="14"/></div>
      <div className="msg-body">
        <div className="msg-name">
          SOCPilots AI <span className="msg-tag thinking-tag">running agent</span>
        </div>
        <div className="thinking">
          <span/><span/><span/>
          <span className="th-text mono">querying SIEM · enriching IOCs · building verdict…</span>
        </div>
      </div>
    </div>
  );
}

// ── Markdown renderer ────────────────────────────────────────────────
function renderMd(text) {
  if (!text) return '';
  return text
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/`([^`]+)`/g,'<code>$1</code>')
    .split('\n\n').map(p => {
      if (/^\s*[-*]\s/.test(p))
        return '<ul>' + p.split('\n').filter(l=>/^\s*[-*]\s/.test(l))
          .map(l=>'<li>'+l.replace(/^\s*[-*]\s/,'')+' </li>').join('') + '</ul>';
      if (/^\s*\d+\.\s/.test(p))
        return '<ol>' + p.split('\n').filter(l=>/^\s*\d+\.\s/.test(l))
          .map(l=>'<li>'+l.replace(/^\s*\d+\.\s*/,'')+' </li>').join('') + '</ol>';
      return '<p>' + p.replace(/\n/g,'<br/>') + '</p>';
    }).join('');
}

Object.assign(window, { PageCopilot });
