// Threat Hunt + IOC Enrichment pages — wired to real APIs
const { useState: useStateX, useMemo: useMemoX, useEffect: useEffectX, useCallback: useCallbackX } = React;

// ============= THREAT HUNT =============
const HUNT_PRESETS = [
  { id: 'lateral',  label: 'Lateral movement',
    q: 'rule.mitre.tactic:"Lateral Movement" AND data.win.eventdata.targetUserName:* | last 24h',
    hours: 24 },
  { id: 'c2',       label: 'C2 beacon patterns',
    q: 'dst.port:(443 OR 8080) AND network.bytes_out > 1000 | groupby data.srcip | last 24h',
    hours: 24 },
  { id: 'pshell',   label: 'Suspicious PowerShell',
    q: 'process.name:powershell.exe AND process.args:*-enc* OR process.args:*bypass* | last 24h',
    hours: 24 },
  { id: 'kerb',     label: 'Kerberoasting',
    q: 'event.code:4769 AND ticket.encryption:0x17 | groupby user.name | last 24h',
    hours: 24 },
  { id: 'creds',    label: 'Credential dumping',
    q: 'process.parent.name:(lsass.exe) OR rule.id:(60103 OR 60106) | last 24h',
    hours: 24 },
  { id: 'persist',  label: 'New persistence',
    q: 'registry.path:*\\Run\\* OR scheduled_task.created:* | last 7d',
    hours: 168 },
];

// Extract keyword from DSL-style query (strip directives like | last 24h | groupby X)
function dslToKeyword(q) {
  return q.replace(/\|\s*last\s+\S+/gi, '').replace(/\|\s*groupby\s+\S+/gi, '').replace(/\|\s*limit\s+\d+/gi, '').trim();
}
// Extract hours from | last Nh directive
function dslToHours(q) {
  const m = q.match(/\|\s*last\s+(\d+)([hd])/i);
  if (!m) return 24;
  return m[2].toLowerCase() === 'd' ? parseInt(m[1]) * 24 : parseInt(m[1]);
}

function PageHunt() {
  const API = window.SOC_API;
  const [preset, setPreset]   = useStateX('lateral');
  const [query, setQuery]     = useStateX(HUNT_PRESETS[0].q);
  const [limit, setLimit]     = useStateX(500);
  const [running, setRunning] = useStateX(false);
  const [results, setResults] = useStateX([]);
  const [total, setTotal]     = useStateX(0);
  const [aiVerdict, setAiVerdict] = useStateX(null);
  const [aiLoading, setAiLoading] = useStateX(false);
  const [hasRun, setHasRun]   = useStateX(false);
  const taRef = useStateX(null)[0]; // for ref — use useRef

  // Scheduled hunts state
  const [schedules, setSchedules]       = useStateX([]);
  const [schedLoading, setSchedLoading] = useStateX(false);
  const [showNewSched, setShowNewSched] = useStateX(false);
  const [newSchedName, setNewSchedName] = useStateX('');
  const [newSchedCron, setNewSchedCron] = useStateX('0 * * * *');
  const [newSchedQuery, setNewSchedQuery] = useStateX('');
  const [schedSaving, setSchedSaving]   = useStateX(false);

  const loadSchedules = useCallbackX(async () => {
    setSchedLoading(true);
    const d = await API.get('/api/hunt/schedules?page_size=50');
    setSchedules(d?.items || []);
    setSchedLoading(false);
  }, []);

  useEffectX(() => { loadSchedules(); }, [loadSchedules]);

  async function toggleSchedule(id, enabled) {
    await API.patch(`/api/hunt/schedules/${id}`, { enabled: !enabled });
    setSchedules(prev => prev.map(s => s.id === id ? { ...s, enabled: !enabled } : s));
  }

  async function runScheduleNow(id) {
    window.socToast?.({ title: 'Hunt triggered', sub: 'Running in background…', tone: 'info' });
    await API.post(`/api/hunt/schedules/${id}/run`, {});
  }

  async function deleteSchedule(id) {
    await API.delete(`/api/hunt/schedules/${id}`);
    setSchedules(prev => prev.filter(s => s.id !== id));
  }

  async function createSchedule() {
    if (!newSchedName.trim() || !newSchedQuery.trim()) return;
    setSchedSaving(true);
    const d = await API.post('/api/hunt/schedules', {
      name: newSchedName.trim(),
      query: newSchedQuery.trim(),
      cron_expr: newSchedCron.trim() || '0 * * * *',
    });
    setSchedSaving(false);
    if (d && !d.error) {
      await loadSchedules();
      setShowNewSched(false);
      setNewSchedName(''); setNewSchedQuery(''); setNewSchedCron('0 * * * *');
      window.socToast?.({ title: 'Schedule created', sub: d.name || newSchedName, tone: 'ok' });
    } else {
      window.socToast?.({ title: 'Failed to create', sub: d?.error || 'API error', tone: 'error' });
    }
  }

  const taRefR = React.useRef(null);

  function selectPreset(id) {
    setPreset(id);
    const p = HUNT_PRESETS.find(h => h.id === id);
    if (p) setQuery(p.q);
  }

  const hours = dslToHours(query);

  // Count lines for gutter
  const lineCount = Math.max(2, (query.match(/\n/g) || []).length + 1);

  const runHunt = async () => {
    const q = query.trim();
    if (!q) return;
    setRunning(true); setAiVerdict(null); setHasRun(false);

    const keyword = dslToKeyword(q);
    const h       = dslToHours(q);
    const params  = new URLSearchParams({ hours: h, page_size: Math.min(limit, 500) });
    if (keyword) params.set('q', keyword);

    const data  = await API.get(`/api/alerts?${params}`);
    const items = (data?.items || data?.alerts || []).map(a => ({
      time:  a.timestamp ? a.timestamp.slice(0, 19).replace('T', ' ') : '—',
      agent: a.agent || '—',
      rule:  a.ruleId || '—',
      desc:  (a.description || '').slice(0, 80),
      mitre: Array.isArray(a.mitre) ? (a.mitre[0] || '—') : (a.mitre || '—'),
      sev:   a.severity || 'low',
      score: a.level ? Math.min(100, Math.round(a.level * 7)) : 30,
    }));
    setResults(items);
    setTotal(data?.total || items.length);
    setRunning(false);
    setHasRun(true);

    if (items.length > 0) {
      setAiLoading(true);
      const ctx = `Threat hunt query: "${q}" (last ${h}h, limit ${limit}). Found ${data?.total || items.length} total alerts. Top results: ${items.slice(0, 5).map(a => `[${a.sev}] rule ${a.rule} — ${a.desc.slice(0, 50)}`).join('; ')}. Provide: risk assessment, MITRE technique mapping, attack chain analysis, and recommended next steps.`;
      const res = await API.post('/api/langchain/investigate', { message: ctx });
      setAiLoading(false);
      if (res && !res.error) setAiVerdict(res.report || res.result || res.answer);
    }
  };

  return (
    <div className="page" data-screen-label="06 Threat Hunt">
      <Topbar title="Threat Hunt" sub="SIEM search · AI co-analyst" />
      <div className="page-body">

        {/* Hunt presets */}
        <Card title="Hunt presets" sub="MITRE-aligned starting points">
          <div className="hunt-presets">
            {HUNT_PRESETS.map(p => (
              <button key={p.id} className={`hunt-preset ${preset === p.id ? 'on' : ''}`}
                onClick={() => selectPreset(p.id)}>
                <div className="hp-label">{p.label}</div>
                <div className="hp-q mono">{p.q.slice(0, 60)}{p.q.length > 60 ? '…' : ''}</div>
              </button>
            ))}
          </div>
        </Card>

        {/* Query editor */}
        <Card title="Query" sub="OpenSearch DSL · time-bounded · grouped"
          actions={<>
            <button className="btn btn-ghost btn-sm mono" onClick={() => {
              const h = dslToHours(query);
              setQuery(q => q.replace(/\|\s*last\s+\S+/i, `| last ${h === 24 ? '7d' : '24h'}`));
            }}>last {hours}h</button>
            <button className="btn btn-ghost btn-sm mono" onClick={() => setLimit(l => l === 500 ? 100 : 500)}>limit {limit}</button>
            <button className="btn btn-primary" onClick={runHunt} disabled={running}>
              {running ? 'Running…' : 'Run hunt'}
            </button>
          </>}>
          <div className="query-box">
            <div className="query-gutter">
              {Array.from({ length: lineCount }, (_, i) => (
                <div key={i}>{i + 1}</div>
              ))}
            </div>
            <textarea
              ref={taRefR}
              className="query-input mono"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => {
                if ((e.key === 'Enter' && e.ctrlKey) || (e.key === 'Enter' && e.metaKey)) { e.preventDefault(); runHunt(); }
              }}
              placeholder="rule.mitre.tactic:&quot;Lateral Movement&quot; AND data.win.eventdata.targetUserName:* | last 24h"
              spellCheck="false"
              rows={Math.max(2, lineCount)}
            />
          </div>
          <div className="query-foot">
            <span className="mono dim">Ctrl+Enter to run · ⌘+S to save · /docs for syntax</span>
          </div>
        </Card>

        {/* AI co-analyst verdict */}
        {(aiLoading || aiVerdict) && (
          <Card title="AI co-analyst verdict" icon={<Icon.brain width="14" height="14"/>}
            actions={aiLoading
              ? <Chip mono tone="warn">analyzing…</Chip>
              : <Chip mono tone="ok"><span className="pip pip-ok"/> analysis ready</Chip>}>
            {aiLoading ? (
              <div className="hunt-running">
                <div className="hunt-progress"><div /></div>
                <div className="mono dim">ReAct agent analyzing hunt results…</div>
              </div>
            ) : (
              <div className="ai-verdict">
                <div dangerouslySetInnerHTML={{ __html: (aiVerdict || '')
                  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                  .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
                  .replace(/`([^`]+)`/g,'<code>$1</code>')
                  .replace(/\n\n/g,'</p><p>').replace(/\n/g,'<br/>')
                  .replace(/^/,'<p>').replace(/$/,'</p>')
                }} />
                <div className="verdict-actions">
                  <button className="btn btn-primary btn-sm" onClick={async () => {
                    const res = await API.post('/api/cases/create', {
                      title: `Hunt: ${dslToKeyword(query).slice(0, 60)}`,
                      description: `Threat hunt found ${total} alerts.\n\nQuery:\n${query}\n\nAI analysis:\n${aiVerdict}`,
                    });
                    if (res && !res.error) window.socToast?.({ title: 'Case created', sub: res.caseId || 'New case', tone: 'ok' });
                  }}>
                    <Icon.folder width="11" height="11"/> Promote to case
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={runHunt}>Re-run</button>
                </div>
              </div>
            )}
          </Card>
        )}

        {/* Results */}
        {hasRun && (
          <Card title="Results"
            sub={running ? 'streaming…' : `${total.toLocaleString()} events · last ${hours}h`}
            actions={<Chip mono>{results.length} shown</Chip>}>
            {running ? (
              <div className="hunt-running">
                <div className="hunt-progress"><div /></div>
                <div className="mono dim">querying SIEM…</div>
              </div>
            ) : results.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--fg-3)', fontSize: 12 }}>
                No results for this query in the last {hours}h. Try broadening search terms or the time range.
              </div>
            ) : (
              <table className="data-table hunt-results">
                <thead><tr>
                  <th>TIME</th>
                  <th>SEV</th>
                  <th>RULE</th>
                  <th>DESCRIPTION</th>
                  <th>AGENT</th>
                  <th>MITRE</th>
                  <th style={{ width: 120 }}>SCORE</th>
                </tr></thead>
                <tbody>
                  {results.map((r, i) => (
                    <tr key={i}>
                      <td className="mono dim" style={{ fontSize: 10 }}>{r.time}</td>
                      <td><SevChip sev={r.sev}/></td>
                      <td className="mono dim">{r.rule}</td>
                      <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.desc}>{r.desc}</td>
                      <td className="mono">{r.agent}</td>
                      <td className="mono">{r.mitre !== '—' ? <span className="link">{r.mitre}</span> : <span className="dim">—</span>}</td>
                      <td>
                        <div className="score-bar">
                          <div className="sb-fill" data-sev={r.score >= 80 ? 'critical' : r.score >= 60 ? 'high' : r.score >= 40 ? 'medium' : 'low'}
                            style={{ width: `${r.score}%` }}/>
                          <span className="sb-num mono">{r.score}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        )}
        {/* Scheduled Hunts */}
        <Card title="Scheduled Hunts" sub="Automated recurring threat hunts"
          actions={<button className="btn btn-primary btn-sm" onClick={() => setShowNewSched(true)}>+ New schedule</button>}>

          {showNewSched && (
            <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 8, padding: '16px', marginBottom: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>NAME</span>
                  <input className="mono" placeholder="My hunt name" value={newSchedName}
                    onChange={e => setNewSchedName(e.target.value)} style={{ fontSize: 13 }}/>
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>CRON EXPRESSION</span>
                  <input className="mono" placeholder="0 * * * *" value={newSchedCron}
                    onChange={e => setNewSchedCron(e.target.value)} style={{ fontSize: 13 }}/>
                </label>
              </div>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 10 }}>
                <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>QUERY (DSL)</span>
                <input className="mono" placeholder="rule.mitre.tactic:&quot;Lateral Movement&quot; | last 24h"
                  value={newSchedQuery} onChange={e => setNewSchedQuery(e.target.value)} style={{ fontSize: 12 }}/>
              </label>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button className="btn btn-ghost btn-sm" onClick={() => setShowNewSched(false)}>Cancel</button>
                <button className="btn btn-primary btn-sm" onClick={createSchedule} disabled={schedSaving}>
                  {schedSaving ? 'Saving…' : 'Create'}
                </button>
              </div>
            </div>
          )}

          {schedLoading ? (
            <div className="mono dim" style={{ padding: '12px 0', fontSize: 12 }}>Loading schedules…</div>
          ) : schedules.length === 0 ? (
            <div style={{ padding: '16px 0', textAlign: 'center', color: 'var(--fg-3)', fontSize: 12 }}>
              No scheduled hunts. Click <strong>+ New schedule</strong> to create one.
            </div>
          ) : (
            <table className="data-table">
              <thead><tr>
                <th>NAME</th>
                <th>CRON</th>
                <th>QUERY</th>
                <th>ENABLED</th>
                <th>LAST RUN</th>
                <th style={{ width: 120 }}>ACTIONS</th>
              </tr></thead>
              <tbody>
                {schedules.map(s => (
                  <tr key={s.id}>
                    <td style={{ fontWeight: 600 }}>{s.name}</td>
                    <td className="mono dim" style={{ fontSize: 11 }}>{s.cron_expr}</td>
                    <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 11 }} title={s.query}>{s.query || '—'}</td>
                    <td>
                      <button className={`btn btn-sm ${s.enabled ? 'btn-primary' : 'btn-ghost'}`}
                        onClick={() => toggleSchedule(s.id, s.enabled)} style={{ minWidth: 60 }}>
                        {s.enabled ? 'ON' : 'OFF'}
                      </button>
                    </td>
                    <td className="mono dim" style={{ fontSize: 11 }}>
                      {s.last_run ? new Date(s.last_run).toLocaleString() : '—'}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn btn-ghost btn-sm" title="Run now" onClick={() => runScheduleNow(s.id)}>▶</button>
                        <button className="btn btn-ghost btn-sm" title="Delete"
                          style={{ color: 'var(--red)' }} onClick={() => deleteSchedule(s.id)}>✕</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

      </div>
    </div>
  );
}

// ============= IOC ENRICHMENT =============
const IOC_TYPES = [
  { id: 'ip',     label: 'IP',     ph: 'e.g. 185.220.101.42' },
  { id: 'domain', label: 'Domain', ph: 'e.g. malicious-c2.xyz' },
  { id: 'url',    label: 'URL',    ph: 'e.g. http://evil.example.com/payload' },
  { id: 'hash',   label: 'Hash',   ph: 'e.g. a4f8b2c91d3e0775fa2b8c91d3e0775' },
];

function PageIOC() {
  const API = window.SOC_API;
  const [type, setType] = useStateX('ip');
  const [input, setInput] = useStateX('');
  const [loading, setLoading] = useStateX(false);
  const [result, setResult] = useStateX(null);
  const [error, setError] = useStateX(null);

  const enrich = async () => {
    const indicator = input.trim();
    if (!indicator) return;
    setLoading(true);
    setResult(null);
    setError(null);
    const data = await API.post('/api/langchain/enrich', { indicator, type });
    setLoading(false);
    if (!data || data.error) {
      setError(data?.error || 'Enrichment failed. Ensure LangChain agent is running and API keys are configured.');
      return;
    }
    setResult(data);
  };

  const verdict = result ? (() => {
    const vt = result.vt;
    const ab = result.abuse;
    if (vt?.malicious > 5 || ab?.abuseConfidenceScore > 50) return 'malicious';
    if (vt?.malicious > 0 || ab?.abuseConfidenceScore > 20) return 'suspicious';
    return 'clean';
  })() : null;

  const confidence = result ? (() => {
    const vt = result.vt;
    const ab = result.abuse;
    const vtScore = vt?.malicious ? Math.round((vt.malicious / (vt.malicious + vt.harmless + vt.undetected + 1)) * 100) : 0;
    const abScore = ab?.abuseConfidenceScore || 0;
    return Math.max(vtScore, abScore);
  })() : 0;

  return (
    <div className="page" data-screen-label="07 IOC Enrichment">
      <Topbar
        title="IOC Enrichment"
        sub="IP · Domain · URL · Hash · real TI feeds"
        actions={<>
          <Chip mono>VT · AbuseIPDB · Shodan · OTX</Chip>
        </>}
      />
      <div className="page-body">
        <Card title="Indicator" sub="paste an IOC to enrich across threat-intel sources">
          <div className="ioc-input-row">
            <div className="seg">
              {IOC_TYPES.map(t => (
                <button key={t.id} className={`seg-btn ${type===t.id?'on':''}`}
                  onClick={() => setType(t.id)}>{t.label}</button>
              ))}
            </div>
            <div className="ioc-field">
              <input value={input} onChange={e=>setInput(e.target.value)}
                onKeyDown={e=>{ if(e.key==='Enter') enrich(); }}
                className="mono"
                placeholder={IOC_TYPES.find(t=>t.id===type)?.ph || ''}/>
            </div>
            <button className="btn btn-primary" onClick={enrich} disabled={loading || !input.trim()}>
              <Icon.search width="13" height="13"/> {loading ? 'Enriching…' : 'Enrich'}
            </button>
          </div>
          {loading && (
            <div className="hunt-running" style={{marginTop:12}}>
              <div className="hunt-progress"><div /></div>
              <div className="mono dim">querying VT · AbuseIPDB · Shodan · OTX…</div>
            </div>
          )}
          {error && (
            <div style={{marginTop:12,padding:'8px 12px',background:'rgba(255,30,60,.08)',
              border:'1px solid var(--crit)',borderRadius:4,fontSize:12,color:'var(--crit)'}}>
              {error}
            </div>
          )}
        </Card>

        {result && (
          <>
            <div className="grid-12">
              <Card span={5} title="Verdict" sub={`${result.indicator}`}>
                <div className="verdict-block">
                  <div className={`verdict-pill mono ${verdict === 'malicious' ? 'verdict-mal' : verdict === 'suspicious' ? 'verdict-sus' : 'verdict-ok'}`}>
                    {verdict}
                  </div>
                  <div className="verdict-ioc mono">{result.indicator}</div>
                  {confidence > 0 && (
                    <div className="verdict-conf">
                      <div className="conf-track">
                        <div className="conf-fill" data-sev={confidence > 70 ? 'critical' : confidence > 30 ? 'high' : 'medium'}
                          style={{width: `${confidence}%`}}/>
                      </div>
                      <span className="mono">{confidence}% confidence</span>
                    </div>
                  )}
                  <ul className="verdict-meta">
                    {result.abuse?.countryCode && <li><span>country</span><span className="mono">{result.abuse.countryCode}</span></li>}
                    {result.abuse?.isp && <li><span>ISP</span><span className="mono">{result.abuse.isp}</span></li>}
                    {result.vt?.owner && <li><span>owner</span><span className="mono">{result.vt.owner}</span></li>}
                    {result.abuse?.usageType && <li><span>usage</span><span className="mono">{result.abuse.usageType}</span></li>}
                    {result.cached && <li><span>source</span><span className="mono dim">Redis cache hit</span></li>}
                  </ul>
                  {result.vt?.tags?.length > 0 && (
                    <div className="ioc-tags">
                      {result.vt.tags.slice(0,5).map(t => <Chip key={t} mono tone="warn">{t}</Chip>)}
                    </div>
                  )}
                </div>
              </Card>

              <Card span={7} title="Threat intel sources">
                <div className="intel-grid">
                  {result.vt && !result.vt.error && (
                    <div className="intel-card" data-tone={result.vt.malicious > 0 ? 'crit' : 'ok'}>
                      <div className="ic-source">VirusTotal</div>
                      <div className="ic-verdict">{result.vt.malicious > 0 ? 'malicious' : 'clean'}</div>
                      <div className="ic-detail mono">{result.vt.malicious}/{result.vt.malicious + result.vt.harmless + result.vt.undetected + result.vt.suspicious} engines</div>
                    </div>
                  )}
                  {result.vt?.error && (
                    <div className="intel-card" data-tone="dim">
                      <div className="ic-source">VirusTotal</div>
                      <div className="ic-verdict dim">unavailable</div>
                      <div className="ic-detail mono dim">{result.vt.error}</div>
                    </div>
                  )}
                  {result.abuse && !result.abuse.error && (
                    <div className="intel-card" data-tone={result.abuse.abuseConfidenceScore > 50 ? 'crit' : result.abuse.abuseConfidenceScore > 20 ? 'warn' : 'ok'}>
                      <div className="ic-source">AbuseIPDB</div>
                      <div className="ic-verdict">{result.abuse.abuseConfidenceScore > 50 ? 'abusive' : result.abuse.abuseConfidenceScore > 0 ? 'suspicious' : 'clean'}</div>
                      <div className="ic-detail mono">{result.abuse.abuseConfidenceScore}% confidence</div>
                    </div>
                  )}
                  {result.shodan && !result.shodan.error && (
                    <div className="intel-card" data-tone="warn">
                      <div className="ic-source">Shodan</div>
                      <div className="ic-verdict">exposed</div>
                      <div className="ic-detail mono">{(result.shodan.ports || []).length} open ports</div>
                    </div>
                  )}
                  {result.otx && !result.otx.error && (
                    <div className="intel-card" data-tone={result.otx.pulse_count > 0 ? 'warn' : 'ok'}>
                      <div className="ic-source">OTX AlienVault</div>
                      <div className="ic-verdict">{result.otx.pulse_count > 0 ? 'in feeds' : 'not found'}</div>
                      <div className="ic-detail mono">{result.otx.pulse_count || 0} pulses</div>
                    </div>
                  )}
                </div>
              </Card>
            </div>

            {result.shodan && !result.shodan.error && (result.shodan.ports || []).length > 0 && (
              <Card title="Open ports" sub="Shodan scan">
                <div className="ports-grid">
                  {(result.shodan.ports || []).map(p => (
                    <div key={p} className="port-cell">
                      <div className="port-num mono">{p}</div>
                      <div className="port-svc mono">{{21:'ftp',22:'ssh',25:'smtp',53:'dns',80:'http',443:'https',3306:'mysql',3389:'rdp',6379:'redis',8080:'http-alt',9001:'tor'}[p] || '?'}</div>
                    </div>
                  ))}
                </div>
              </Card>
            )}

            {result.otx?.malware_families?.length > 0 && (
              <Card title="OTX threat context" sub="malware families + campaigns">
                <div className="ioc-tags">
                  {result.otx.malware_families.map(f => <Chip key={f} mono tone="crit">{f}</Chip>)}
                </div>
              </Card>
            )}

            <div style={{marginTop:12,display:'flex',gap:8}}>
              <button className="btn btn-primary" onClick={async () => {
                const res = await API.post('/api/cases/create', {
                  title: `IOC investigation: ${result.indicator}`,
                  description: `IOC: ${result.indicator} (${type})\nVerdict: ${verdict} (${confidence}%)\nVT: ${result.vt?.malicious || 0} detections\nAbuseIPDB: ${result.abuse?.abuseConfidenceScore || 0}%`,
                });
                if (res && !res.error) window.socToast?.({title:'Case created', sub: res.caseId || 'New case', tone:'ok'});
              }}>
                <Icon.folder width="13" height="13"/> Open case
              </button>
              <button className="btn btn-ghost" onClick={() => { setResult(null); setError(null); setInput(''); }}>
                Clear
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

Object.assign(window, { PageHunt, PageIOC });
