// Create Detection Rules — Form Builder + AI Chat + Deploy via MCP
const { useState: useStateCR, useEffect: useEffectCR, useRef: useRefCR } = React;

const RULE_TEMPLATES = {
  ssh_bruteforce: { name: 'SSH Brute Force Detection', level: '10', group: 'sshd', desc: 'Multiple failed SSH login attempts detected from same source IP', pattern: 'PAM authentication failure\nFailed password for\nInvalid user\nConnection closed by invalid user', mitre: 'T1110', freq: '5', action: 'alert_and_case', context: 'Threshold: 5+ failures in 60 seconds from same IP' },
  web_scan:       { name: 'Web Application Scanner Detection', level: '8', group: 'web', desc: 'HTTP 404 flood — potential web vulnerability scanner detected', pattern: 'HTTP 404\nnot found\nGET /admin\nGET /.env\nsqlmap\nnmap', mitre: 'T1190', freq: '20', action: 'alert_and_block', context: 'Common scanner signatures: sqlmap, nmap, nikto, dirbuster' },
  priv_escalation:{ name: 'Privilege Escalation Attempt', level: '12', group: 'authentication', desc: 'Suspicious sudo or su usage indicating privilege escalation attempt', pattern: 'sudo: .* COMMAND\nsu: pam_unix\nsu: authentication failure\nsudo: pam_unix', mitre: 'T1068', freq: '3', action: 'full_response', context: 'Unusual sudo commands especially to root from non-privileged users' },
  malware_drop:   { name: 'Malware Dropper Execution', level: '13', group: 'malware', desc: 'Suspicious file execution pattern consistent with malware dropper', pattern: 'chmod +x\nwget .sh\ncurl bash\npython -c\n/tmp/ exec', mitre: 'T1204', freq: '1', action: 'full_response', context: 'Files executed from /tmp, /dev/shm or downloaded and executed' },
};

const AI_TEMPLATES = [
  { label: '🔐 SSH Brute Force',       prompt: 'Detect SSH brute force attack: 5 or more failed authentication attempts within 60 seconds from the same source IP address. Level 10, MITRE T1110.' },
  { label: '⚡ Privilege Escalation',   prompt: 'Detect privilege escalation: any sudo or su command executed by a non-admin user, especially attempts to run commands as root. Level 12, MITRE T1068.' },
  { label: '🌐 Web App Scanner',        prompt: 'Detect web application scanning: 20+ HTTP 404 errors from the same IP within 1 minute, or requests containing sqlmap, nikto, nmap user-agent strings. Level 8, MITRE T1190.' },
  { label: '🦠 Malware Dropper',        prompt: 'Detect malware dropper: execution of scripts downloaded from internet (wget/curl piped to bash), or execution of files from /tmp or /dev/shm directories. Level 13, MITRE T1204.' },
  { label: '🔀 Lateral Movement',       prompt: 'Detect lateral movement: SMB or RDP authentication attempts to multiple hosts from a single source within a short time window. Level 12, MITRE T1021.' },
  { label: '📤 Data Exfiltration',      prompt: 'Detect data exfiltration: large outbound data transfers to external IPs, or connections to cloud storage services outside business hours. Level 12, MITRE T1041.' },
  { label: '📁 Critical File Change',   prompt: 'Detect critical file modification: any changes to /etc/passwd, /etc/shadow, /etc/sudoers, or SSH authorized_keys files. Level 12, MITRE T1098.' },
];

function xmlEsc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function buildRuleXml(d, ruleId) {
  const groupName = (d.group || 'custom').toLowerCase().replace(/[^a-z0-9_]/g, '_').replace(/_+$/, '') || 'custom';
  const mitreIds  = (d.mitre || '').split(/[,\s]+/).filter(Boolean);
  const mitreXml  = mitreIds.length ? `\n    <mitre>\n${mitreIds.map(id => `      <id>${id}</id>`).join('\n')}\n    </mitre>` : '';
  return `<group name="${xmlEsc(groupName)}">
  <rule id="${ruleId}" level="${d.level || '10'}">
    <decoded_as>json</decoded_as>
    <match>${xmlEsc(d.pattern || 'PATTERN_HERE')}</match>
    <description>${xmlEsc(d.desc)}</description>
    <group>${xmlEsc(d.group || 'custom')}</group>${mitreXml}
  </rule>
</group>`;
}

// ============= PAGE CREATE RULES =============
function PageCreateRules() {
  const API    = window.SOC_API;
  const user   = API.user?.();
  const isL2   = ['l2', 'l3', 'admin'].includes(user?.role);

  const [mode, setMode] = useStateCR('form');

  // Form fields
  const [name,    setName]    = useStateCR('');
  const [ruleId,  setRuleId]  = useStateCR('');
  const [level,   setLevel]   = useStateCR('10');
  const [group,   setGroup]   = useStateCR('sshd');
  const [desc,    setDesc]    = useStateCR('');
  const [pattern, setPattern] = useStateCR('');
  const [mitre,   setMitre]   = useStateCR('T1110');
  const [freq,    setFreq]    = useStateCR('5');
  const [action,  setAction]  = useStateCR('alert');
  const [context, setContext] = useStateCR('');

  // Preview / status
  const [previewXml, setPreviewXml] = useStateCR('');
  const [status,     setStatus]     = useStateCR(null);
  const [testing,    setTesting]    = useStateCR(false);
  const [deploying,  setDeploying]  = useStateCR(false);

  // AI chat
  const [chatMsgs,  setChatMsgs]  = useStateCR([
    { role: 'ai', content: 'Hello! I\'m your Rule Generation Assistant.\n\nDescribe the security threat or behavior you want to detect and I\'ll generate a complete Wazuh rule XML.\n\n**Examples:**\n• "Detect SSH brute force — 5+ failures in 60 seconds"\n• "Alert when /etc/passwd is modified"\n• "Detect port scanning from external IPs"\n• "Monitor failed sudo attempts by non-admin users"\n\nI\'ll also show the generated XML so you can copy and import it into the form builder.' }
  ]);
  const [chatInput,  setChatInput]  = useStateCR('');
  const [chatLoading,setChatLoad]   = useStateCR(false);
  const [chatXml,    setChatXml]    = useStateCR('');
  const [sysCtx,     setSysCtx]     = useStateCR('');
  const [showSys,    setShowSys]    = useStateCR(false);
  const chatRef = useRefCR(null);

  // Deployed custom rules
  const [customRules, setCustomRules] = useStateCR(null);
  const [rulesLoading,setRulesLoad]   = useStateCR(false);

  useEffectCR(() => { loadCustomRules(); }, []);

  async function loadCustomRules() {
    setRulesLoad(true);
    const d = await API.get('/api/rules');
    setRulesLoad(false);
    if (!d || d.error) { setCustomRules([]); return; }
    const all = d.rules || [];
    const custom = all.filter(r => parseInt(r.id) >= 200000 && parseInt(r.id) < 300000);
    setCustomRules(custom.length > 0 ? custom : all.slice(0, 15));
  }

  function fillTemplate(key) {
    const t = RULE_TEMPLATES[key];
    if (!t) return;
    setName(t.name); setLevel(t.level); setGroup(t.group);
    setDesc(t.desc); setPattern(t.pattern); setMitre(t.mitre);
    setFreq(t.freq); setAction(t.action); setContext(t.context);
    setPreviewXml(''); setStatus(null);
    window.socToast?.({ title: 'Template loaded', sub: t.name, tone: 'info' });
  }

  function getNewRuleId() {
    const manual = parseInt(ruleId);
    return (manual >= 200000 && manual <= 299999) ? manual : 200000 + Math.floor(Math.random() * 9000);
  }

  function handlePreview() {
    if (!name.trim() || !desc.trim()) {
      window.socToast?.({ title: 'Name and description required', tone: 'warn' }); return;
    }
    const id  = getNewRuleId();
    const xml = buildRuleXml({ group, level, desc, pattern, mitre }, id);
    setPreviewXml(xml);
    window.socToast?.({ title: `Preview ready · Rule ${id}`, tone: 'ok' });
  }

  async function handleTest() {
    if (!name.trim() || !desc.trim() || !pattern.trim()) {
      window.socToast?.({ title: 'Name, description and pattern required', tone: 'warn' }); return;
    }
    setTesting(true); setStatus({ type: 'loading', text: '🧪 Testing rule (dry-run, no deployment)…' });
    const id      = getNewRuleId();
    const safeName = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 30) || 'custom_rule';
    const filename = `${safeName}_${id}.xml`;
    const xml      = buildRuleXml({ group, level, desc, pattern, mitre }, id);

    const testPrompt = `Test this Wazuh rule WITHOUT deploying it. Do NOT call the add_wazuh_rule tool.

Proposed file: ${filename}
Rule XML:
${xml}

Tasks:
1. Validate the XML syntax (well-formed, properly nested tags)
2. Generate 3 sample log entries that WOULD match this rule
3. Generate 2 sample log entries that should NOT match (false positive check)
4. Assessment: false positive risk, performance, recommendations

Format response with: ## XML Validation / ## Matching Logs / ## Non-Matching Logs / ## Assessment

Do NOT call add_wazuh_rule. This is validation only.`;

    const r = await API.post('/api/ai/chat', { message: testPrompt, session_id: `rule-test-${id}` });
    setTesting(false);
    const reply = r?.response || r?.output || r?.text || 'No response';
    setStatus({ type: 'test', filename, id, xml, reply });
    window.socToast?.({ title: 'Rule tested', sub: 'Review before deploying', tone: 'ok' });
  }

  async function handleDeploy() {
    if (!name.trim() || !desc.trim() || !pattern.trim()) {
      window.socToast?.({ title: 'Name, description and pattern required', tone: 'warn' }); return;
    }
    if (!isL2) { window.socToast?.({ title: 'Analyst role required', tone: 'crit' }); return; }

    const id      = getNewRuleId();
    const safeName = name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 30) || 'custom_rule';
    const filename = `${safeName}_${id}.xml`;

    if (!window.confirm(`Deploy rule via add_wazuh_rule MCP tool?\n\n📁 ${filename}\n🆔 Rule ID: ${id}\n📊 Level: ${level}\n🎯 Group: ${group}\n\nContinue?`)) return;

    setDeploying(true);
    setStatus({ type: 'loading', text: '🚀 Calling add_wazuh_rule MCP tool…' });

    const r = await API.post('/api/rules/deploy-custom', { name, level, group, description: desc, pattern, mitre, freq, action, context });
    setDeploying(false);

    if (r && !r.error) {
      setStatus({ type: 'success', id: r.ruleId || id, filename, reply: r.message || 'Deployed successfully' });
      window.socToast?.({ title: `Rule ${r.ruleId || id} deployed`, tone: 'ok' });
      setTimeout(() => loadCustomRules(), 2500);
    } else {
      setStatus({ type: 'error', id, filename, reply: r?.error || 'Deployment failed' });
      window.socToast?.({ title: 'Deployment failed', sub: r?.error || 'Check server logs', tone: 'error' });
    }
  }

  // ── AI Chat ────────────────────────────────────────────────────
  async function sendChat() {
    const msg = chatInput.trim();
    if (!msg || chatLoading) return;
    setChatInput('');

    const userMsg = { role: 'user', content: msg };
    setChatMsgs(prev => [...prev, userMsg]);
    setChatLoad(true);

    const systemContext = `You are a Wazuh detection rule expert. The user wants to create a Wazuh OSSEC XML detection rule.
${sysCtx ? 'Additional context: ' + sysCtx : ''}

When generating a rule:
1. Generate a complete valid Wazuh rule XML with proper attributes
2. Use rule ID in range 200000-299999 (custom rules range)
3. Include: <rule id="..."> <match> or <regex>, <description>, <group>, <level>, and MITRE tags if applicable
4. After the XML, provide a brief explanation of what it detects
5. Format the XML in a proper code block

Generate the rule now.`;

    const fullMsg = `${systemContext}\n\nUser request: ${msg}`;
    const r = await API.post('/api/ai/chat', { message: fullMsg, session_id: 'soc-rule-chat' });
    setChatLoad(false);

    const reply = r?.response || r?.output || r?.text || r?.message || 'SOCPilots AI unavailable';
    setChatMsgs(prev => [...prev, { role: 'ai', content: reply }]);

    // Auto-extract XML from reply
    let xml = '';
    const codeIdx = reply.indexOf('```xml');
    if (codeIdx >= 0) {
      const start = codeIdx + 6;
      const end = reply.indexOf('```', start);
      xml = (end >= 0 ? reply.slice(start, end) : reply.slice(start)).trim();
    } else {
      const ruleIdx = reply.indexOf('<rule');
      if (ruleIdx >= 0) {
        const endIdx = reply.lastIndexOf('</rule>');
        if (endIdx >= 0) xml = reply.slice(ruleIdx, endIdx + 7).trim();
      }
    }
    if (xml) setChatXml(xml);

    setTimeout(() => { if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight; }, 50);
  }

  function importXmlToForm() {
    if (!chatXml) { window.socToast?.({ title: 'No XML generated yet', tone: 'warn' }); return; }
    const getAttrRule = attr => { const m = chatXml.match(new RegExp(`<rule[^>]*${attr}="([^"]*)"`)); return m ? m[1] : ''; };
    const getTag = tag => { const m = chatXml.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`)); return m ? m[1].trim() : ''; };
    const foundLevel = getAttrRule('level'); if (foundLevel) setLevel(foundLevel);
    const foundDesc  = getTag('description'); if (foundDesc) { setDesc(foundDesc); if (!name) setName(foundDesc.slice(0, 60)); }
    const foundGrp   = getTag('group'); if (foundGrp) setGroup(foundGrp.split(',')[0].trim() || 'custom');
    const foundMatch = getTag('match') || getTag('regex'); if (foundMatch) setPattern(foundMatch);
    const foundMitre = getTag('id'); if (foundMitre && foundMitre.startsWith('T')) setMitre(foundMitre);
    setPreviewXml(chatXml); setMode('form');
    window.socToast?.({ title: 'Rule imported from AI', sub: 'Review and adjust, then deploy', tone: 'ok' });
  }

  // ── Status render ───────────────────────────────────────────────
  function StatusBlock() {
    if (!status) return <div style={{ padding: 16, color: 'var(--fg-3)', fontFamily: 'var(--fm)', fontSize: 11 }}>Rule not yet deployed</div>;
    if (status.type === 'loading') return <div style={{ padding: 16, color: 'var(--acc)', fontFamily: 'var(--fm)', fontSize: 12 }}>{status.text}</div>;

    const tone = status.type === 'success' ? 'var(--low)' : status.type === 'error' ? 'var(--crit)' : 'var(--med)';
    const label = status.type === 'success' ? `✓ Rule deployed (ID ${status.id})` : status.type === 'error' ? `⚠ Deployment failed` : `🧪 Test complete`;

    return (
      <div>
        <div style={{ padding: '6px 10px', borderRadius: 4, background: status.type === 'success' ? 'rgba(0,230,118,.1)' : status.type === 'error' ? 'rgba(255,23,68,.1)' : 'rgba(0,229,255,.08)', border: `1px solid ${tone}44`, color: tone, fontFamily: 'var(--fm)', fontSize: 12, fontWeight: 700, marginBottom: 8 }}>{label}</div>
        {status.filename && <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--fm)', marginBottom: 8 }}>file: {status.filename} · ID: {status.id}</div>}
        {status.xml && (
          <details style={{ marginBottom: 8 }}>
            <summary style={{ cursor: 'pointer', color: 'var(--acc)', fontFamily: 'var(--fm)', fontSize: 11 }}>View rule XML</summary>
            <pre style={{ background: 'var(--bg-0)', border: '1px solid var(--ln)', borderRadius: 4, padding: 10, fontSize: 10, color: 'var(--low)', whiteSpace: 'pre-wrap', wordBreak: 'break-word', marginTop: 6 }}>{status.xml}</pre>
          </details>
        )}
        {status.reply && <div style={{ fontSize: 11, color: 'var(--fg-2)', whiteSpace: 'pre-wrap', lineHeight: 1.6, maxHeight: '40vh', overflowY: 'auto' }}>{status.reply}</div>}
      </div>
    );
  }

  // ── Chat message renderer ────────────────────────────────────────
  function ChatMsg({ msg }) {
    const isAI = msg.role === 'ai';
    return (
      <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
        <div style={{ width: 28, height: 28, borderRadius: '50%', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 700, fontFamily: 'var(--fm)', background: isAI ? 'rgba(0,229,255,.15)' : 'rgba(255,255,255,.08)', color: isAI ? 'var(--acc)' : 'var(--fg-1)', border: `1px solid ${isAI ? 'rgba(0,229,255,.3)' : 'rgba(255,255,255,.1)'}` }}>
          {isAI ? 'SP' : (user?.username?.[0] || 'U').toUpperCase()}
        </div>
        <div style={{ flex: 1, background: isAI ? 'var(--bg-3)' : 'rgba(255,255,255,.04)', border: '1px solid var(--ln)', borderRadius: 6, padding: '8px 12px', fontSize: 12, color: 'var(--fg-1)', lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
          {msg.content}
        </div>
      </div>
    );
  }

  const sevColor = l => parseInt(l) >= 12 ? 'var(--crit)' : parseInt(l) >= 10 ? 'var(--high)' : parseInt(l) >= 7 ? 'var(--med)' : 'var(--low)';

  return (
    <div className="page" data-screen-label="Create Rules">
      <Topbar
        title="Create Detection Rules"
        sub="Build and deploy Wazuh detection rules via MCP · custom rule range 200000–299999"
        actions={<>
          <div style={{ display: 'flex', background: 'var(--bg-3)', border: '1px solid var(--ln)', borderRadius: 4, padding: 2, gap: 2 }}>
            <button className={`btn btn-sm ${mode === 'form' ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setMode('form')} style={{ fontSize: 11 }}>
              <Icon.file width="11" height="11"/> Form Builder
            </button>
            <button className={`btn btn-sm ${mode === 'ai' ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setMode('ai')} style={{ fontSize: 11 }}>
              <Icon.brain width="11" height="11"/> AI Chat Mode
            </button>
          </div>
        </>}
      />

      <div className="page-body">

        {/* ── FORM BUILDER MODE ──────────────────────────────────── */}
        {mode === 'form' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>

              {/* Left: form */}
              <Card title="RULE BUILDER">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 10 }}>
                    <div>
                      <div className="mono dim" style={{ fontSize: 10, marginBottom: 4 }}>Rule Name *</div>
                      <input className="mono" placeholder="e.g. SSH Brute Force Detection" value={name} onChange={e => setName(e.target.value)} style={{ width: '100%' }} />
                    </div>
                    <div>
                      <div className="mono dim" style={{ fontSize: 10, marginBottom: 4 }}>Rule ID (200000–299999)</div>
                      <input className="mono" type="number" min="200000" max="299999" placeholder="Auto" value={ruleId} onChange={e => setRuleId(e.target.value)} style={{ width: '100%' }} />
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                    <div>
                      <div className="mono dim" style={{ fontSize: 10, marginBottom: 4 }}>Severity Level (1–15)</div>
                      <select className="select-mini mono" value={level} onChange={e => setLevel(e.target.value)} style={{ width: '100%' }}>
                        <option value="5">5 — Low</option>
                        <option value="7">7 — Medium</option>
                        <option value="10">10 — High</option>
                        <option value="12">12 — Critical</option>
                        <option value="15">15 — Maximum</option>
                      </select>
                    </div>
                    <div>
                      <div className="mono dim" style={{ fontSize: 10, marginBottom: 4 }}>Category / Group</div>
                      <select className="select-mini mono" value={group} onChange={e => setGroup(e.target.value)} style={{ width: '100%' }}>
                        {['syslog','sshd','web','authentication','intrusion_detection','malware','custom'].map(g => <option key={g} value={g}>{g}</option>)}
                      </select>
                    </div>
                  </div>

                  <div>
                    <div className="mono dim" style={{ fontSize: 10, marginBottom: 4 }}>Rule Description *</div>
                    <input className="mono" placeholder="e.g. Multiple failed SSH login attempts from same IP" value={desc} onChange={e => setDesc(e.target.value)} style={{ width: '100%' }} />
                  </div>

                  <div>
                    <div className="mono dim" style={{ fontSize: 10, marginBottom: 4 }}>Log Pattern / Condition to Match</div>
                    <textarea className="mono" placeholder={'e.g. PAM authentication failure\nFailed password for\nsshd: Failed'} value={pattern} onChange={e => setPattern(e.target.value)} style={{ width: '100%', minHeight: 72, background: 'var(--bg-3)', border: '1px solid var(--ln)', borderRadius: 4, padding: '8px 10px', color: 'var(--fg-1)', fontSize: 12, resize: 'vertical' }} />
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                    <div>
                      <div className="mono dim" style={{ fontSize: 10, marginBottom: 4 }}>MITRE ATT&amp;CK Technique</div>
                      <select className="select-mini mono" value={mitre} onChange={e => setMitre(e.target.value)} style={{ width: '100%' }}>
                        <option value="">None</option>
                        <option value="T1110">T1110 — Brute Force</option>
                        <option value="T1078">T1078 — Valid Accounts</option>
                        <option value="T1059">T1059 — Command Execution</option>
                        <option value="T1055">T1055 — Process Injection</option>
                        <option value="T1190">T1190 — Exploit Public App</option>
                        <option value="T1071">T1071 — App Layer Protocol</option>
                        <option value="T1486">T1486 — Data Encrypted</option>
                        <option value="T1040">T1040 — Network Sniffing</option>
                        <option value="T1068">T1068 — Privilege Escalation</option>
                        <option value="T1204">T1204 — User Execution</option>
                        <option value="T1021">T1021 — Lateral Movement</option>
                        <option value="T1041">T1041 — Exfiltration over C2</option>
                        <option value="T1098">T1098 — Account Manipulation</option>
                      </select>
                    </div>
                    <div>
                      <div className="mono dim" style={{ fontSize: 10, marginBottom: 4 }}>Fires per Minute Threshold</div>
                      <input className="mono" type="number" value={freq} min="1" onChange={e => setFreq(e.target.value)} style={{ width: '100%' }} />
                    </div>
                  </div>

                  <div>
                    <div className="mono dim" style={{ fontSize: 10, marginBottom: 4 }}>Response Action</div>
                    <select className="select-mini mono" value={action} onChange={e => setAction(e.target.value)} style={{ width: '100%' }}>
                      <option value="alert">Alert only</option>
                      <option value="alert_and_block">Alert + Block IP</option>
                      <option value="alert_and_case">Alert + Create Case</option>
                      <option value="full_response">Alert + Block + Case</option>
                    </select>
                  </div>

                  <div>
                    <div className="mono dim" style={{ fontSize: 10, marginBottom: 4 }}>Additional Context (optional)</div>
                    <textarea className="mono" placeholder="Any additional context, examples, or specific conditions..." value={context} onChange={e => setContext(e.target.value)} style={{ width: '100%', minHeight: 48, background: 'var(--bg-3)', border: '1px solid var(--ln)', borderRadius: 4, padding: '8px 10px', color: 'var(--fg-1)', fontSize: 12, resize: 'vertical' }} />
                  </div>

                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn btn-ghost" style={{ flex: 1, justifyContent: 'center' }} onClick={handlePreview}>
                      <Icon.search width="12" height="12"/> Preview
                    </button>
                    <button className="btn btn-ghost" style={{ flex: 1, justifyContent: 'center', color: 'var(--acc)', borderColor: 'var(--acc)' }} onClick={handleTest} disabled={testing}>
                      <Icon.check width="12" height="12"/> {testing ? 'Testing…' : 'Test Rule'}
                    </button>
                    <button className="btn btn-primary" style={{ flex: 1, justifyContent: 'center' }} onClick={handleDeploy} disabled={deploying || !isL2}>
                      <Icon.check width="12" height="12"/> {deploying ? 'Deploying…' : 'Deploy to Wazuh'}
                    </button>
                  </div>
                </div>
              </Card>

              {/* Right: preview + status */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <Card title="GENERATED RULE XML" actions={previewXml ? <button className="btn btn-ghost btn-sm" onClick={() => navigator.clipboard.writeText(previewXml).then(() => window.socToast?.({ title: 'Copied!', tone: 'ok' }))}>Copy XML</button> : null}>
                  {previewXml ? (
                    <pre style={{ background: 'var(--bg-0)', border: '1px solid var(--ln)', borderRadius: 4, padding: 12, fontSize: 11, fontFamily: 'var(--fm)', color: 'var(--low)', whiteSpace: 'pre-wrap', wordBreak: 'break-word', lineHeight: 1.6, margin: 0 }}>{previewXml}</pre>
                  ) : (
                    <div className="empty mono">Click "Preview" to generate rule XML</div>
                  )}
                </Card>
                <Card title="DEPLOYMENT STATUS">
                  <StatusBlock />
                </Card>
              </div>
            </div>

            {/* Quick Templates */}
            <Card title="QUICK TEMPLATES" sub="Click to auto-fill the form">
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 8 }}>
                {[
                  { key: 'ssh_bruteforce', icon: '🔐', label: 'SSH Brute Force',      meta: 'Level 10 · T1110 · Auth failure threshold' },
                  { key: 'web_scan',       icon: '🌐', label: 'Web Scanning',         meta: 'Level 8 · T1190 · HTTP 404 flood detection' },
                  { key: 'priv_escalation',icon: '⚡', label: 'Privilege Escalation', meta: 'Level 12 · T1068 · sudo/su anomaly' },
                  { key: 'malware_drop',   icon: '🦠', label: 'Malware Dropper',      meta: 'Level 13 · T1204 · Suspicious file exec' },
                ].map(t => (
                  <div key={t.key} onClick={() => fillTemplate(t.key)} style={{ padding: '10px 12px', background: 'var(--bg-3)', border: '1px solid var(--ln)', borderRadius: 6, cursor: 'pointer', transition: 'border-color .15s' }}
                    onMouseOver={e => e.currentTarget.style.borderColor = 'var(--acc)'}
                    onMouseOut={e => e.currentTarget.style.borderColor = 'var(--ln)'}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-0)', marginBottom: 4 }}>{t.icon} {t.label}</div>
                    <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{t.meta}</div>
                  </div>
                ))}
              </div>
            </Card>
          </>
        )}

        {/* ── AI CHAT MODE ────────────────────────────────────────── */}
        {mode === 'ai' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 16, height: 'calc(100vh - 200px)', minHeight: 520 }}>

            {/* Chat window */}
            <Card title="SOCPilots AI — Rule Generator" sub="Describe a threat → AI generates Wazuh XML">
              <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: 0 }}>
                <div ref={chatRef} style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 12 }}>
                  {chatMsgs.map((m, i) => <ChatMsg key={i} msg={m} />)}
                  {chatLoading && (
                    <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                      <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'rgba(0,229,255,.15)', border: '1px solid rgba(0,229,255,.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 700, fontFamily: 'var(--fm)', color: 'var(--acc)' }}>SP</div>
                      <div style={{ color: 'var(--fg-3)', fontFamily: 'var(--fm)', fontSize: 12 }}>Generating rule…</div>
                    </div>
                  )}
                </div>

                {showSys && (
                  <textarea className="mono" placeholder="Add context: your OS, log format, specific conditions…" value={sysCtx} onChange={e => setSysCtx(e.target.value)} style={{ width: '100%', height: 48, background: 'var(--bg-3)', border: '1px solid var(--ln)', borderRadius: 4, padding: '6px 10px', color: 'var(--fg-2)', fontSize: 11, resize: 'none', marginBottom: 8 }} />
                )}

                <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 6 }}>
                  <span className="mono" style={{ fontSize: 9, color: 'var(--fg-3)', letterSpacing: 1 }}>SYSTEM CONTEXT</span>
                  <button className="btn btn-ghost btn-sm" style={{ fontSize: 9, padding: '1px 6px' }} onClick={() => setShowSys(s => !s)}>{showSys ? 'Hide' : 'Show'}</button>
                </div>

                <div style={{ display: 'flex', gap: 8 }}>
                  <textarea className="mono" placeholder="Describe the threat to detect…" value={chatInput} onChange={e => setChatInput(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); } }} style={{ flex: 1, height: 44, background: 'var(--bg-3)', border: '1px solid var(--ln)', borderRadius: 4, padding: '8px 10px', color: 'var(--fg-1)', fontSize: 12, resize: 'none' }} />
                  <button className="btn btn-primary" onClick={sendChat} disabled={chatLoading} style={{ alignSelf: 'stretch' }}>
                    <Icon.check width="12" height="12"/> Generate
                  </button>
                </div>
              </div>
            </Card>

            {/* Right: templates + generated XML */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <Card title="QUICK PROMPTS" sub="Click to fill input">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {AI_TEMPLATES.map(t => (
                    <button key={t.label} className="btn btn-ghost btn-sm" style={{ justifyContent: 'flex-start', fontSize: 10, textAlign: 'left', height: 'auto', padding: '5px 8px', whiteSpace: 'normal', lineHeight: 1.3 }}
                      onClick={() => setChatInput(t.prompt)}>
                      {t.label}
                    </button>
                  ))}
                </div>
              </Card>

              <Card title="GENERATED XML" sub={chatXml ? 'Ready to import' : 'Will appear after AI response'} actions={chatXml ? (
                <div style={{ display: 'flex', gap: 4 }}>
                  <button className="btn btn-ghost btn-sm" onClick={() => navigator.clipboard.writeText(chatXml).then(() => window.socToast?.({ title: 'Copied', tone: 'ok' }))}>Copy</button>
                  <button className="btn btn-primary btn-sm" onClick={importXmlToForm}>Import →</button>
                </div>
              ) : null}>
                {chatXml ? (
                  <pre style={{ background: 'var(--bg-0)', border: '1px solid var(--ln)', borderRadius: 4, padding: 10, fontSize: 10, fontFamily: 'var(--fm)', color: 'var(--low)', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 200, overflowY: 'auto', margin: 0 }}>{chatXml}</pre>
                ) : (
                  <div className="empty mono" style={{ padding: 12, fontSize: 10 }}>XML will appear here after AI generates a rule</div>
                )}
              </Card>
            </div>
          </div>
        )}

        {/* ── DEPLOYED CUSTOM RULES ───────────────────────────────── */}
        <Card title="DEPLOYED CUSTOM RULES" sub="Rule IDs 200000–299999 (your range)" actions={
          <button className="btn btn-ghost btn-sm" onClick={loadCustomRules} disabled={rulesLoading}>
            <Icon.refresh width="11" height="11"/> {rulesLoading ? 'Loading…' : 'Refresh'}
          </button>
        }>
          {rulesLoading ? (
            <div className="loading mono">Loading from SIEM…</div>
          ) : !customRules || customRules.length === 0 ? (
            <div className="empty mono">No custom rules deployed yet. Use the form or AI chat above to create your first rule.</div>
          ) : (
            <table className="data-table">
              <thead><tr>
                <th style={{ width: 90 }}>RULE ID</th>
                <th style={{ width: 60 }}>LEVEL</th>
                <th>DESCRIPTION</th>
                <th style={{ width: 120 }}>GROUPS</th>
                <th style={{ width: 80 }}>MITRE</th>
                <th style={{ width: 80 }}>FIRES 24h</th>
              </tr></thead>
              <tbody>
                {customRules.map(r => {
                  const id = parseInt(r.id);
                  const isCustom = id >= 200000;
                  return (
                    <tr key={r.id} style={{ background: isCustom ? 'rgba(0,229,255,.03)' : undefined }}>
                      <td className="mono" style={{ color: isCustom ? 'var(--acc)' : 'var(--fg-2)', fontWeight: isCustom ? 700 : 400 }}>{r.id}</td>
                      <td><span className="mono" style={{ color: sevColor(r.level), fontWeight: 700 }}>{r.level}</span></td>
                      <td style={{ fontSize: 12 }}>{r.description || '—'}</td>
                      <td className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>
                        {(Array.isArray(r.groups) ? r.groups : [r.groups]).filter(Boolean).slice(0, 2).join(', ')}
                      </td>
                      <td className="mono" style={{ fontSize: 10, color: 'var(--med)' }}>
                        {(Array.isArray(r.mitre) ? r.mitre : [r.mitre]).filter(Boolean).slice(0, 2).join(', ') || '—'}
                      </td>
                      <td className="mono" style={{ fontWeight: 700, color: (r.count || 0) > 0 ? 'var(--high)' : 'var(--fg-3)' }}>{r.count || 0}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </div>
  );
}

Object.assign(window, { PageCreateRules });
