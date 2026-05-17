// Agents · Detection Rules · Vulnerabilities · Reports
const { useState: useStateS, useMemo: useMemoS, useEffect: useEffectS, useRef: useRefS } = React;

// ============= AGENTS =============
function fmtLastSeen(ts) {
  if (!ts) return '—';
  const s = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60)  return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60)  return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24)  return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function PageAgents() {
  const [agents, setAgents]   = useStateS([]);
  const [loading, setLoading] = useStateS(true);
  const [error, setError]     = useStateS(null);
  const [filter, setFilter]   = useStateS('all');
  const [search, setSearch]   = useStateS('');

  useEffectS(() => { load(); }, []);

  async function load() {
    setLoading(true);
    const d = await window.SOC_API.get('/api/agents');
    if (!d || d.error) { setError(d?.error || 'SIEM unavailable'); setLoading(false); return; }
    setAgents(d.agents || []);
    setLoading(false);
  }

  const groups = ['all', ...Array.from(new Set(agents.map(a => a.group || 'default').filter(Boolean)))];
  const [group, setGroup] = useStateS('all');

  const filtered = agents.filter(a => {
    if (filter !== 'all' && a.status !== filter) return false;
    if (group !== 'all' && (a.group || 'default') !== group) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!(a.name || '').toLowerCase().includes(q) && !(a.ip || '').includes(q)) return false;
    }
    return true;
  });

  const active   = agents.filter(a => a.status === 'active').length;
  const offline  = agents.filter(a => a.status !== 'active').length;
  const outdated = agents.filter(a => a.version && a.version !== agents[0]?.version).length;

  return (
    <div className="page" data-screen-label="08 Agents">
      <Topbar
        title="Agents"
        sub="Wazuh monitored endpoints"
        actions={<>
          <button className="btn btn-ghost" onClick={load}><Icon.refresh width="13" height="13"/> Sync</button>
          <button className="btn btn-ghost">Export CSV</button>
        </>}
      />
      <div className="page-body">
        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
          <KpiCard label="Total agents"  value={agents.length} sub="enrolled in SIEM"/>
          <KpiCard label="Active"        value={active}        sub="reporting now"/>
          <KpiCard label="Offline"       value={offline}       sub="silent > threshold" sev={offline > 0 ? 'critical' : undefined}/>
          <KpiCard label="Outdated"      value={outdated}      sub="version mismatch"/>
        </div>

        <Card title="Endpoints" sub={`${filtered.length} of ${agents.length}`}
          actions={<>
            <input className="mono" placeholder="Search name or IP…" value={search}
              onChange={e => setSearch(e.target.value)} style={{ width: 180, fontSize: 11 }}/>
            <div className="seg">
              {['all','active','disconnected'].map(s => (
                <button key={s} className={`seg-btn ${filter===s?'on':''}`} onClick={() => setFilter(s)}>
                  {s !== 'all' && <SevDot sev={s==='active'?'low':'critical'} size={6}/>}
                  {s}
                </button>
              ))}
            </div>
            <select className="select-mini mono" value={group} onChange={e => setGroup(e.target.value)}>
              {groups.map(g => <option key={g} value={g}>group: {g}</option>)}
            </select>
          </>}>
          {loading && <div className="empty mono">Loading from SIEM…</div>}
          {error   && <div className="empty mono" style={{ color: 'var(--red)' }}>{error}</div>}
          {!loading && !error && (
            <table className="data-table">
              <thead><tr>
                <th style={{ width: 8 }}></th>
                <th style={{ width: 50 }}>ID</th>
                <th>NAME</th>
                <th>OS</th>
                <th>VERSION</th>
                <th>IP</th>
                <th>LAST SEEN</th>
                <th>ALERTS 24H</th>
                <th></th>
              </tr></thead>
              <tbody>
                {filtered.length === 0 && (
                  <tr><td colSpan="9" className="empty mono">No agents match</td></tr>
                )}
                {filtered.map(a => (
                  <tr key={a.id}>
                    <td><span className="sev-bar" data-sev={a.status==='active'?'low':'critical'} style={{ height: 18 }}/></td>
                    <td className="mono dim">#{a.id}</td>
                    <td className="mono">{a.name}</td>
                    <td className="dim">{a.os || '—'}</td>
                    <td className="mono dim">{a.version || '—'}</td>
                    <td className="mono">{a.ip || '—'}</td>
                    <td className="mono dim">{fmtLastSeen(a.lastSeen)}</td>
                    <td className="mono">{(a.alertCount || 0).toLocaleString()}</td>
                    <td>
                      <button className="btn-icon" onClick={() => window.socToast?.({ title: 'Agent detail', sub: a.name, tone: 'default' })}>
                        <Icon.chevron width="12" height="12"/>
                      </button>
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

function MiniGauge({ value }) {
  if (value === 0) return <span className="mono dim">—</span>;
  const tone = value > 80 ? 'critical' : value > 60 ? 'high' : value > 40 ? 'medium' : 'low';
  return (
    <div className="mini-gauge">
      <div className="mg-track"><div className="mg-fill" data-sev={tone} style={{width:`${value}%`}}/></div>
      <span className="mono">{value}%</span>
    </div>
  );
}

// ============= DETECTION RULES =============
function sevFromLevel(l) {
  if (l >= 12) return 'critical';
  if (l >= 10) return 'high';
  if (l >= 7)  return 'medium';
  return 'low';
}

function actBadge(lastSeen) {
  if (!lastSeen) return null;
  const d = Date.now() - lastSeen;
  if (d < 86400000)  return { label: '24h',    tone: 'ok' };
  if (d < 604800000) return { label: '7d',     tone: 'warn' };
  return                    { label: 'DORMANT', tone: 'dim' };
}

function PageRules() {
  const [rules, setRules]       = useStateS([]);
  const [filtered, setFiltered] = useStateS([]);
  const [loading, setLoading]   = useStateS(true);
  const [error, setError]       = useStateS(null);
  const [page, setPage]         = useStateS(1);
  const [search, setSearch]     = useStateS('');
  const [fSev, setFSev]         = useStateS('');
  const [fAct, setFAct]         = useStateS('');
  const [fMitre, setFMitre]     = useStateS('');
  const [fDecoder, setFDecoder] = useStateS('');
  const [sortBy, setSortBy]     = useStateS('count_desc');
  const searchTimer             = useRefS(null);
  const PAGE_SIZE = 50;

  useEffectS(() => { load(); }, []);
  useEffectS(() => { applyFilters(); }, [rules, search, fSev, fAct, fMitre, fDecoder, sortBy]);

  async function load() {
    setLoading(true);
    const d = await window.SOC_API.get('/api/rules');
    if (!d || d.error) { setError(d?.error || 'SIEM unavailable'); setLoading(false); return; }
    setRules(d.rules || []);
    setLoading(false);
  }

  function applyFilters() {
    const now = Date.now();
    const q = search.toLowerCase().trim();
    let out = rules.filter(r => {
      if (q && !`${r.id} ${r.description} ${(r.groups||[]).join(' ')} ${(r.mitre||[]).join(' ')} ${r.decoder||''}`.toLowerCase().includes(q)) return false;
      if (fSev && r.severity !== fSev) return false;
      if (fMitre && !(r.mitre||[]).includes(fMitre)) return false;
      if (fDecoder && r.decoder !== fDecoder) return false;
      if (fAct) {
        const ls = r.last_seen || 0;
        if (fAct === '24h'    && now - ls >= 86400000)  return false;
        if (fAct === '7d'     && now - ls >= 604800000) return false;
        if (fAct === 'dormant'&& now - ls < 604800000)  return false;
      }
      return true;
    });
    if (sortBy === 'count_asc')      out.sort((a,b) => a.count - b.count);
    else if (sortBy === 'sev_desc')  out.sort((a,b) => b.level - a.level);
    else if (sortBy === 'sev_asc')   out.sort((a,b) => a.level - b.level);
    else if (sortBy === 'alpha')     out.sort((a,b) => (a.description||'').localeCompare(b.description||''));
    else if (sortBy === 'recent')    out.sort((a,b) => (b.last_seen||0) - (a.last_seen||0));
    else                             out.sort((a,b) => b.count - a.count);
    setFiltered(out);
    setPage(1);
  }

  const mitreSet   = useMemoS(() => [...new Set(rules.flatMap(r => r.mitre||[]))].sort(), [rules]);
  const decoderSet = useMemoS(() => [...new Set(rules.map(r => r.decoder).filter(Boolean))].sort(), [rules]);

  const crit    = rules.filter(r => r.severity === 'critical').length;
  const high    = rules.filter(r => r.severity === 'high').length;
  const now2    = Date.now();
  const active24= rules.filter(r => r.last_seen && now2 - r.last_seen < 86400000).length;
  const mitreMapped = rules.filter(r => (r.mitre||[]).length > 0).length;

  const pageSlice = filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);

  return (
    <div className="page" data-screen-label="09 Detection Rules">
      <Topbar
        title="Detection Rules"
        sub="Active ruleset · MITRE ATT&CK mapped"
        actions={<>
          <button className="btn btn-ghost" onClick={load}><Icon.refresh width="13" height="13"/> Refresh</button>
        </>}
      />
      <div className="page-body">
        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(5,1fr)' }}>
          <KpiCard label="Total rules"   value={rules.length}   sub="from SIEM ruleset"/>
          <KpiCard label="Critical"      value={crit}           sub="level ≥ 12" sev="critical"/>
          <KpiCard label="High"          value={high}           sub="level 10–11"/>
          <KpiCard label="Active (24h)"  value={active24}       sub="fired in last 24h"/>
          <KpiCard label="MITRE mapped"  value={mitreMapped}    sub="ATT&CK technique"/>
        </div>

        <Card title="Ruleset" sub={`${filtered.length} of ${rules.length} rules`}
          actions={<>
            <input className="mono" placeholder="Search ID, name, MITRE…" value={search}
              onChange={e => { setSearch(e.target.value); clearTimeout(searchTimer.current); searchTimer.current = setTimeout(() => {}, 250); }}
              style={{ width: 220, fontSize: 11 }}/>
            <select className="select-mini mono" value={fSev} onChange={e => setFSev(e.target.value)}>
              <option value="">All severity</option>
              {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <select className="select-mini mono" value={fAct} onChange={e => setFAct(e.target.value)}>
              <option value="">All activity</option>
              <option value="24h">Active 24h</option>
              <option value="7d">Active 7d</option>
              <option value="dormant">Dormant</option>
            </select>
            <select className="select-mini mono" value={fMitre} onChange={e => setFMitre(e.target.value)}>
              <option value="">All MITRE</option>
              {mitreSet.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
            <select className="select-mini mono" value={fDecoder} onChange={e => setFDecoder(e.target.value)}>
              <option value="">All decoders</option>
              {decoderSet.map(d => <option key={d} value={d}>{d}</option>)}
            </select>
            <select className="select-mini mono" value={sortBy} onChange={e => setSortBy(e.target.value)}>
              <option value="count_desc">Sort: Most fires</option>
              <option value="count_asc">Sort: Least fires</option>
              <option value="sev_desc">Sort: Severity ↓</option>
              <option value="sev_asc">Sort: Severity ↑</option>
              <option value="recent">Sort: Recently seen</option>
              <option value="alpha">Sort: A–Z</option>
            </select>
          </>}>
          {loading && <div className="empty mono">Loading from SIEM…</div>}
          {error   && <div className="empty mono" style={{ color: 'var(--red)' }}>{error}</div>}
          {!loading && !error && (
            <>
              <table className="data-table">
                <thead><tr>
                  <th style={{ width: 70 }}>ID</th>
                  <th style={{ width: 60 }}>LEVEL</th>
                  <th>DESCRIPTION</th>
                  <th>GROUPS</th>
                  <th>MITRE</th>
                  <th>DECODER</th>
                  <th style={{ width: 70 }}>ACTIVITY</th>
                  <th style={{ width: 80 }}>FIRES</th>
                </tr></thead>
                <tbody>
                  {pageSlice.length === 0 && <tr><td colSpan="8" className="empty mono">No rules match filters</td></tr>}
                  {pageSlice.map(r => {
                    const act = actBadge(r.last_seen);
                    return (
                      <tr key={r.id}>
                        <td className="mono" style={{ color: 'var(--acc)' }}>{r.id}</td>
                        <td><LevelChip level={r.level}/></td>
                        <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.description}>{r.description}</td>
                        <td style={{ maxWidth: 160 }}>
                          {(Array.isArray(r.groups) ? r.groups : [r.groups]).filter(Boolean).slice(0,3).map(g => (
                            <span key={g} className="mono dim" style={{ fontSize: 9, background: 'var(--b1)', padding: '1px 5px', borderRadius: 3, marginRight: 2 }}>{g}</span>
                          ))}
                        </td>
                        <td>
                          {(Array.isArray(r.mitre) ? r.mitre : [r.mitre]).filter(Boolean).slice(0,2).map(m => (
                            <Chip key={m} mono>{m}</Chip>
                          ))}
                        </td>
                        <td className="mono dim">{r.decoder || '—'}</td>
                        <td>{act ? <Chip mono tone={act.tone}>{act.label}</Chip> : <span className="mono dim">—</span>}</td>
                        <td className="mono" style={{ color: 'var(--acc)' }}>{(r.count || 0).toLocaleString()}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {filtered.length > PAGE_SIZE && (
                <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 12 }}>
                  <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => setPage(p => p-1)}>← Prev</button>
                  <span className="mono dim" style={{ lineHeight: '28px' }}>Page {page} / {Math.ceil(filtered.length / PAGE_SIZE)}</span>
                  <button className="btn btn-ghost btn-sm" disabled={page * PAGE_SIZE >= filtered.length} onClick={() => setPage(p => p+1)}>Next →</button>
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </div>
  );
}

function LevelChip({ level }) {
  const sev = level >= 12 ? 'critical' : level >= 10 ? 'high' : level >= 7 ? 'medium' : 'low';
  return <span className="level-chip mono" data-sev={sev}>L{level}</span>;
}

// ============= VULNERABILITIES =============
function PageVulns() {
  const [vulns, setVulns]   = useStateS([]);
  const [sev, setSev]       = useStateS('all');
  const [loading, setLoad]  = useStateS(false);

  useEffectS(() => {
    setLoad(true);
    window.SOC_API.get('/api/vulns').then(d => {
      const arr = d?.items || d?.vulns || (Array.isArray(d) ? d : null);
      if (arr) setVulns(arr);
      setLoad(false);
    }).catch(() => setLoad(false));
  }, []);

  const filtered = sev === 'all' ? vulns : vulns.filter(v => v.sev === sev);
  const crit    = vulns.filter(v => v.sev === 'critical').length;
  const high    = vulns.filter(v => v.sev === 'high').length;
  const patched = vulns.filter(v => v.status === 'patched').length;
  const patchedPct = vulns.length > 0 ? Math.round(patched / vulns.length * 100) : 0;

  return (
    <div className="page" data-screen-label="10 Vulnerabilities">
      <Topbar
        title="Vulnerabilities"
        sub="CVE feed · SOCPilots AI enriched"
        actions={<>
          <button className="btn btn-ghost" onClick={() => { setLoad(true); window.SOC_API.get('/api/vulns').then(d => { const a = d?.items || d?.vulns || (Array.isArray(d) ? d : null); if (a) setVulns(a); setLoad(false); }); }}><Icon.refresh width="13" height="13"/> Re-scan</button>
          <button className="btn btn-ghost">Export SBOM</button>
          <button className="btn btn-primary">Patch plan</button>
        </>}
      />
      <div className="page-body">
        <div className="kpi-grid" style={{gridTemplateColumns:'repeat(4,1fr)'}}>
          <KpiCard label="Open CVEs" value={vulns.filter(v=>v.status==='open').length} sub="across all agents" />
          <KpiCard label="Critical" value={crit} sub="CVSS ≥ 9.0" sev="critical" />
          <KpiCard label="High" value={high} sub="CVSS 7.0–8.9" />
          <KpiCard label="Patched (30d)" value={`${patchedPct}%`} sub={`${patched} of ${vulns.length}`} />
        </div>

        <Card title="CVE feed" sub={loading ? 'Loading…' : `${filtered.length} vulnerabilities`}
          actions={<>
            <div className="seg">
              {['all','critical','high','medium','low'].map(s => (
                <button key={s} className={`seg-btn ${sev===s?'on':''}`} onClick={()=>setSev(s)}>
                  {s !== 'all' && <SevDot sev={s} size={6}/>}
                  {s}
                </button>
              ))}
            </div>
          </>}>
          {loading ? (
            <div className="loading mono">Loading vulnerability data…</div>
          ) : vulns.length === 0 ? (
            <div className="empty mono">No vulnerability data available. Configure the vulnerability scanner to populate this feed.</div>
          ) : (
            <table className="data-table">
              <thead><tr>
                <th>CVE</th>
                <th style={{width:70}}>CVSS</th>
                <th style={{width:80}}>SEVERITY</th>
                <th>PACKAGE</th>
                <th>INSTALLED</th>
                <th>FIX</th>
                <th style={{width:110}}>HOSTS</th>
                <th style={{width:100}}>STATUS</th>
                <th style={{width:60}}>AGE</th>
              </tr></thead>
              <tbody>
                {filtered.map(v => (
                  <tr key={v.cve}>
                    <td className="mono"><a href="#" className="link">{v.cve}</a></td>
                    <td><CvssChip score={v.cvss}/></td>
                    <td><SevChip sev={v.sev}/></td>
                    <td className="mono">{v.pkg}</td>
                    <td className="mono dim">{v.ver}</td>
                    <td className="mono">{v.fix}</td>
                    <td><div className="bar-wrap"><div className="bar" data-sev={v.sev} style={{width:`${Math.min(100,v.hosts*3)}%`}}/><span className="bar-val mono">{v.hosts}</span></div></td>
                    <td><StatusChip status={v.status}/></td>
                    <td className="mono dim">{v.age}</td>
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

function CvssChip({ score }) {
  const sev = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
  return <span className="cvss-chip mono" data-sev={sev}>{score.toFixed(1)}</span>;
}
function StatusChip({ status }) {
  const tone = status === 'open' ? 'crit' : status === 'in-progress' ? 'warn' : status === 'patched' ? 'ok' : 'dim';
  return <Chip mono tone={tone}>{status}</Chip>;
}

// ============= REPORTS =============
function PageReports() {
  const [reports, setReports]   = useStateS([]);
  const [selectedId, setSelectedId] = useStateS(null);
  const [loading, setLoad]      = useStateS(false);
  const [generating, setGen]    = useStateS(false);

  useEffectS(() => {
    setLoad(true);
    window.SOC_API.get('/api/reports').then(d => {
      const arr = d?.items || d?.reports || (Array.isArray(d) ? d : null);
      if (arr) {
        setReports(arr);
        if (arr.length > 0 && !selectedId) setSelectedId(arr[0].id);
      }
      setLoad(false);
    }).catch(() => setLoad(false));
  }, []);

  async function generateReport() {
    setGen(true);
    window.socToast?.({ title: 'Generating report', sub: 'AI draft · ~30s', tone: 'info' });
    const r = await window.SOC_API.get('/api/reports/summary');
    setGen(false);
    if (r && r.text) {
      const newRpt = {
        id: 'RPT-' + Date.now(),
        title: 'Executive Summary',
        range: new Date().toLocaleDateString('en-GB'),
        author: 'AI',
        status: 'draft',
        pages: 1,
        when: 'now',
        content: r.text,
      };
      setReports(prev => [newRpt, ...prev]);
      setSelectedId(newRpt.id);
      window.socToast?.({ title: 'Report generated', sub: newRpt.id, tone: 'ok' });
    } else {
      window.socToast?.({ title: 'Generation failed', sub: r?.error || 'AI engine unavailable', tone: 'error' });
    }
  }

  const selected = reports.find(r => r.id === selectedId);

  return (
    <div className="page" data-screen-label="11 Reports">
      <Topbar
        title="Reports"
        sub="AI-drafted exec summaries · compliance · incident retros"
        actions={<>
          <button className="btn btn-ghost">Templates</button>
          <button className="btn btn-ghost">Schedule</button>
          <button className="btn btn-primary" onClick={generateReport} disabled={generating}>
            <Icon.brain width="13" height="13"/> {generating ? 'Generating…' : 'Generate'}
          </button>
        </>}
      />
      <div className="page-body">
        {loading ? (
          <div className="loading mono">Loading reports…</div>
        ) : reports.length === 0 ? (
          <div className="empty mono" style={{ marginTop: 40, textAlign: 'center' }}>
            <Icon.folder width="32" height="32" /><br />
            No reports yet. Click <strong>Generate</strong> to create an AI executive summary.
          </div>
        ) : (
          <div className="reports-layout">
            <aside className="reports-side">
              <Card title="Reports" sub={`${reports.length} total`} padded={true}>
                <ul className="report-list">
                  {reports.map(r => (
                    <li key={r.id}>
                      <button className={`report-item ${selectedId===r.id?'on':''}`} onClick={()=>setSelectedId(r.id)}>
                        <div className="ri-head">
                          <span className="ri-id mono">{r.id}</span>
                          <Chip mono tone={r.status === 'sent' ? 'ok' : 'warn'}>{r.status}</Chip>
                        </div>
                        <div className="ri-title">{r.title}</div>
                        <div className="ri-meta mono">{r.range} · {r.pages ? r.pages + 'pp · ' : ''}{r.when || ''}</div>
                      </button>
                    </li>
                  ))}
                </ul>
              </Card>

              <Card title="Distribution" sub="auto-deliver">
                <div className="dist-row"><Icon.inbox width="14" height="14"/><span>ciso@socpilots.com</span></div>
                <div className="dist-row"><Icon.inbox width="14" height="14"/><span>soc-leads@socpilots.com</span></div>
                <div className="dist-row"><Icon.share width="14" height="14"/><span>Slack #soc-execs</span></div>
                <button className="btn btn-ghost btn-sm" style={{marginTop:10}}><Icon.plus width="11" height="11"/> Add recipient</button>
              </Card>
            </aside>

            <main className="reports-main">
              {selected && <ReportPreview r={selected} />}
            </main>
          </div>
        )}
      </div>
    </div>
  );
}

function ReportPreview({ r }) {
  return (
    <Card title={r.title} sub={r.range + ' · ' + r.author}
      actions={<>
        <Chip mono tone={r.status === 'sent' ? 'ok' : 'warn'}>{r.status}</Chip>
        <button className="btn btn-ghost btn-sm">Edit</button>
        <button className="btn btn-ghost btn-sm">PDF</button>
        <button className="btn btn-primary btn-sm" onClick={() => window.socToast?.({title:'Report sent', sub: 'delivered to 3 recipients', tone:'ok'})}>Send</button>
      </>}>
      <div className="report-doc">
        <div className="rd-header">
          <div className="rd-brand">
            <div className="rd-mark">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
                <path d="M12 2L20 7V17L12 22L4 17V7Z"/><circle cx="12" cy="12" r="3" fill="currentColor"/>
              </svg>
            </div>
            <div>
              <div className="rd-brand-name">SOC<span>PILOTS</span></div>
              <div className="rd-brand-sub mono">{r.id} · CONFIDENTIAL</div>
            </div>
          </div>
          <div className="rd-meta mono">
            <div>Period · {r.range}</div>
            <div>Author · {r.author}</div>
            <div>Pages · {r.pages}</div>
          </div>
        </div>

        {r.content ? (
          <section className="rd-section">
            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'var(--fm)', fontSize: '0.82rem', color: 'var(--fg-1)', margin: 0 }}>{r.content}</pre>
          </section>
        ) : (
          <div className="empty mono" style={{ padding: '40px 24px', textAlign: 'center' }}>
            Report content not available. Click <strong>Generate</strong> to produce an AI-drafted summary.
          </div>
        )}

        <footer className="rd-foot mono">SOC Pilots · {r.id} · Generated {r.when || 'unknown'} · AI-drafted, human-approved</footer>
      </div>
    </Card>
  );
}

Object.assign(window, { PageAgents, PageRules, PageVulns, PageReports });
