// Threat Hunt + IOC Enrichment pages — wired to real APIs
const { useState: useStateX, useMemo: useMemoX, useEffect: useEffectX, useCallback: useCallbackX } = React;

// ============= THREAT HUNT =============
const HUNT_PRESETS = [
  { id: 'lateral',  label: 'Lateral movement',      q: 'lateral movement', hours: 24 },
  { id: 'pshell',   label: 'Suspicious PowerShell', q: 'powershell', hours: 6 },
  { id: 'kerb',     label: 'Kerberoasting',          q: 'kerberos', hours: 24 },
  { id: 'creds',    label: 'Credential dumping',     q: 'credential', hours: 24 },
  { id: 'brute',    label: 'Brute force',            q: 'authentication failure', hours: 6 },
  { id: 'persist',  label: 'New persistence',        q: 'persistence', hours: 168 },
];

function PageHunt() {
  const API = window.SOC_API;
  const [preset, setPreset] = useStateX('lateral');
  const [query, setQuery]   = useStateX('');
  const [hours, setHours]   = useStateX(24);
  const [running, setRunning] = useStateX(false);
  const [results, setResults] = useStateX([]);
  const [total, setTotal]   = useStateX(0);
  const [aiVerdict, setAiVerdict] = useStateX(null);
  const [aiLoading, setAiLoading] = useStateX(false);
  const [hasRun, setHasRun] = useStateX(false);

  function selectPreset(id) {
    setPreset(id);
    const p = HUNT_PRESETS.find(h => h.id === id);
    if (p) { setQuery(p.q); setHours(p.hours); }
  }

  const runHunt = async () => {
    const q = query.trim();
    if (!q) return;
    setRunning(true);
    setAiVerdict(null);
    setHasRun(false);

    const params = new URLSearchParams({ hours, page_size: 50 });
    if (q) params.set('q', q);
    const data = await API.get(`/api/alerts?${params}`);
    const items = (data?.items || data?.alerts || []).map(a => ({
      time: a.timestamp ? a.timestamp.slice(11, 19) : '—',
      agent: a.agent || '—',
      rule: a.ruleId || '—',
      desc: (a.description || '').slice(0, 60),
      mitre: Array.isArray(a.mitre) ? (a.mitre[0] || '—') : (a.mitre || '—'),
      sev: a.severity || window.SOC_API.sevFromLevel(a.level),
      score: a.level ? Math.min(100, Math.round(a.level * 7)) : 30,
    }));
    setResults(items);
    setTotal(data?.total || items.length);
    setRunning(false);
    setHasRun(true);

    // AI analysis in background
    if (items.length > 0) {
      setAiLoading(true);
      const ctx = `Threat hunt results for query: "${q}" (last ${hours}h). Found ${data?.total || items.length} alerts. Top alerts: ${items.slice(0,5).map(a => `${a.sev} - ${a.desc} (rule ${a.rule})`).join('; ')}. Analyze this pattern, assess severity, and recommend next steps.`;
      const res = await API.post('/api/langchain/investigate', { message: ctx });
      setAiLoading(false);
      if (res && !res.error) setAiVerdict(res.report);
    }
  };

  return (
    <div className="page" data-screen-label="06 Threat Hunt">
      <Topbar
        title="Threat Hunt"
        sub="SIEM search · AI co-analyst"
        actions={<>
          <select className="btn btn-ghost" style={{background:'transparent',border:'none',color:'var(--txt)',cursor:'pointer'}}
            value={hours} onChange={e => setHours(Number(e.target.value))}>
            <option value={1}>Last 1h</option>
            <option value={6}>Last 6h</option>
            <option value={24}>Last 24h</option>
            <option value={168}>Last 7d</option>
          </select>
          <button className="btn btn-primary" onClick={runHunt} disabled={running}>
            <Icon.search width="13" height="13"/> {running ? 'Running…' : 'Run hunt'}
          </button>
        </>}
      />
      <div className="page-body">
        <Card title="Hunt presets" sub="MITRE-aligned starting points">
          <div className="hunt-presets">
            {HUNT_PRESETS.map(p => (
              <button key={p.id} className={`hunt-preset ${preset===p.id?'on':''}`}
                onClick={() => selectPreset(p.id)}>
                <div className="hp-label">{p.label}</div>
                <div className="hp-q mono">{p.q}</div>
              </button>
            ))}
          </div>
        </Card>

        <Card title="Query" sub="SIEM keyword search · time-bounded"
          actions={<>
            <Chip mono>{hours}h window</Chip>
            <button className="btn btn-primary" onClick={runHunt} disabled={running}>
              {running ? 'Running…' : 'Run hunt'}
            </button>
          </>}>
          <div className="query-box">
            <textarea className="query-input mono" value={query}
              onChange={e=>setQuery(e.target.value)}
              onKeyDown={e=>{ if(e.key==='Enter'&&e.ctrlKey){ e.preventDefault(); runHunt(); }}}
              placeholder="Search keywords: e.g. 'powershell', 'lateral movement', 'authentication failure'"
              spellCheck="false" rows="2"/>
          </div>
          <div className="query-foot">
            <span className="mono dim">Ctrl+Enter to run · searches SIEM rule descriptions and alert text</span>
          </div>
        </Card>

        {aiLoading && (
          <Card title="AI co-analyst" icon={<Icon.brain width="14" height="14"/>}
            actions={<Chip mono tone="warn">analyzing…</Chip>}>
            <div className="hunt-running">
              <div className="hunt-progress"><div /></div>
              <div className="mono dim">ReAct agent analyzing hunt results…</div>
            </div>
          </Card>
        )}

        {aiVerdict && (
          <Card title="AI co-analyst verdict" icon={<Icon.brain width="14" height="14"/>}
            actions={<Chip mono tone="ok"><span className="pip pip-ok"/> analysis ready</Chip>}>
            <div className="ai-verdict">
              <div dangerouslySetInnerHTML={{ __html: aiVerdict
                .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
                .replace(/`([^`]+)`/g,'<code>$1</code>')
                .replace(/\n\n/g,'</p><p>').replace(/\n/g,'<br/>')
                .replace(/^/,'<p>').replace(/$/,'</p>')
              }} />
              <div className="verdict-actions">
                <button className="btn btn-primary btn-sm" onClick={async () => {
                  const res = await API.post('/api/cases/create', {
                    title: `Hunt result: ${query}`,
                    description: `Threat hunt for "${query}" found ${total} alerts.\n\nAI analysis:\n${aiVerdict}`,
                  });
                  if (res && !res.error) window.socToast?.({title:'Case created', sub: res.caseId || 'New case', tone:'ok'});
                }}>
                  <Icon.folder width="11" height="11"/> Promote to case
                </button>
                <button className="btn btn-ghost btn-sm" onClick={runHunt}>Re-run</button>
              </div>
            </div>
          </Card>
        )}

        {hasRun && (
          <Card title="Results" sub={running ? 'streaming…' : `${total.toLocaleString()} events · last ${hours}h`}
            actions={<><Chip mono>{results.length} shown</Chip></>}>
            {running ? (
              <div className="hunt-running">
                <div className="hunt-progress"><div /></div>
                <div className="mono dim">querying SIEM…</div>
              </div>
            ) : results.length === 0 ? (
              <div style={{padding:'24px',textAlign:'center',color:'var(--txt-3)'}}>
                No results for "{query}" in the last {hours}h. Try broadening the search terms or time range.
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
                  <th style={{width:120}}>SCORE</th>
                </tr></thead>
                <tbody>
                  {results.map((r,i) => (
                    <tr key={i}>
                      <td className="mono dim">{r.time}</td>
                      <td><SevChip sev={r.sev} /></td>
                      <td className="mono dim">{r.rule}</td>
                      <td style={{maxWidth:220,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}
                        title={r.desc}>{r.desc}</td>
                      <td className="mono">{r.agent}</td>
                      <td className="mono">{r.mitre !== '—' ? <span className="link">{r.mitre}</span> : <span className="dim">—</span>}</td>
                      <td>
                        <div className="score-bar">
                          <div className="sb-fill" data-sev={r.score >= 80 ? 'critical' : r.score >= 60 ? 'high' : r.score >= 40 ? 'medium' : 'low'}
                            style={{width: `${r.score}%`}}/>
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
