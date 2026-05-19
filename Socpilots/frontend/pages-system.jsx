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
const REPORT_TEMPLATES = [
  { id: 'exec',       label: 'Executive Summary',      desc: 'High-level weekly brief for CxO audience',                   icon: '📊' },
  { id: 'threat',     label: 'Threat Intelligence',    desc: 'IOC analysis, MITRE coverage, threat actors',                icon: '🎯' },
  { id: 'compliance', label: 'Compliance Report',      desc: 'SOC 2 / ISO 27001 / NIST framework alignment',               icon: '✅' },
  { id: 'incident',   label: 'Incident Retrospective', desc: 'Post-incident timeline, root cause, lessons learned',         icon: '🔍' },
  { id: 'coverage',   label: 'ATT&CK Coverage Report', desc: 'Full MITRE gap analysis with detection recommendations',     icon: '🛡️' },
];
const SCHED_FREQS = ['Daily', 'Weekly', 'Bi-weekly', 'Monthly'];
const SCHED_DAYS  = ['Monday','Tuesday','Wednesday','Thursday','Friday'];

function PageReports() {
  const [reports, setReports]         = useStateS([]);
  const [selectedId, setSelectedId]   = useStateS(null);
  const [loading, setLoad]            = useStateS(false);
  const [generating, setGen]          = useStateS(false);
  const [mitreCov, setMitreCov]       = useStateS(null);
  const [recipients, setRecipients]   = useStateS([
    { id: 1, type: 'email', addr: 'ciso@socpilots.com'      },
    { id: 2, type: 'email', addr: 'soc-leads@socpilots.com' },
    { id: 3, type: 'slack', addr: 'Slack #soc-execs'        },
  ]);
  const [addingRecip, setAddingRecip] = useStateS(false);
  const [newAddr, setNewAddr]         = useStateS('');
  const [newType, setNewType]         = useStateS('email');
  const [showTmpl, setShowTmpl]       = useStateS(false);
  const [showSched, setShowSched]     = useStateS(false);
  const [schedFreq, setSchedFreq]     = useStateS('Weekly');
  const [schedDay, setSchedDay]       = useStateS('Monday');
  const [schedTime, setSchedTime]     = useStateS('08:00');
  const [editMode, setEditMode]       = useStateS(false);
  const [editContent, setEditContent] = useStateS('');

  useEffectS(() => {
    setLoad(true);
    window.SOC_API.get('/api/reports').then(d => {
      const arr = d?.items || d?.reports || (Array.isArray(d) ? d : null);
      if (arr && arr.length > 0) { setReports(arr); setSelectedId(arr[0].id); }
      setLoad(false);
    }).catch(() => setLoad(false));
    // Pre-load MITRE coverage data for the report sections
    window.SOC_API.get('/api/reports/coverage').then(d => {
      if (d && d.available) setMitreCov(d);
    }).catch(() => {});
  }, []);

  async function generate(type = 'exec') {
    setGen(true);
    const tmpl = REPORT_TEMPLATES.find(t => t.id === type) || REPORT_TEMPLATES[0];
    window.socToast?.({ title: `Generating ${tmpl.label}`, sub: 'AI draft · ~30–60 s', tone: 'info' });

    // Refresh MITRE coverage data so the report gets fresh context
    const [r, covData] = await Promise.all([
      window.SOC_API.get(`/api/reports/summary?type=${type}`),
      window.SOC_API.get('/api/reports/coverage').catch(() => null),
    ]);
    if (covData && covData.available) setMitreCov(covData);
    setGen(false);

    if (r && r.text) {
      const rpt = {
        id:       'RPT-' + Date.now(),
        title:    tmpl.label,
        range:    new Date().toLocaleDateString('en-GB'),
        author:   'AI',
        status:   'draft',
        pages:    1,
        when:     'now',
        type,
        content:  r.text,
        has_mitre: r.has_mitre_context || false,
      };
      setReports(prev => [rpt, ...prev]);
      setSelectedId(rpt.id);
      setEditMode(false);
      window.socToast?.({ title: 'Report ready', sub: rpt.id, tone: 'ok' });
    } else {
      window.socToast?.({ title: 'Generation failed', sub: r?.error || 'AI engine unavailable', tone: 'error' });
    }
  }

  function deleteReport(id) {
    setReports(prev => {
      const next = prev.filter(r => r.id !== id);
      if (selectedId === id) setSelectedId(next[0]?.id || null);
      return next;
    });
  }

  function addRecipient() {
    if (!newAddr.trim()) return;
    setRecipients(prev => [...prev, { id: Date.now(), type: newType, addr: newAddr.trim() }]);
    setNewAddr('');
    setAddingRecip(false);
  }

  function sendReport(sel) {
    if (!sel) return;
    setReports(prev => prev.map(r => r.id === sel.id ? { ...r, status: 'sent', when: 'now' } : r));
    window.socToast?.({ title: 'Report sent', sub: `Delivered to ${recipients.length} recipient${recipients.length !== 1 ? 's' : ''}`, tone: 'ok' });
  }

  function exportPDF(sel) {
    if (!sel) return;
    const win = window.open('', '_blank');
    // Build MITRE section HTML for PDF
    let mitreSectionHtml = '';
    if (mitreCov) {
      const effortColor = { quick_win: '#15803d', medium_effort: '#b45309', strategic: '#6d28d9' };
      const effortLabel = { quick_win: 'Quick Win', medium_effort: 'Medium Effort', strategic: 'Strategic' };
      const tacticRows = (mitreCov.tactic_breakdown || []).map(t =>
        `<tr><td>${t.name}</td><td>${t.covered}/${t.total}</td>
         <td><div style="width:100%;background:#e5e7eb;border-radius:3px;height:8px"><div style="width:${t.pct}%;background:${t.pct>=50?'#16a34a':t.pct>=25?'#d97706':'#dc2626'};height:8px;border-radius:3px"></div></div></td>
         <td>${t.pct}%</td></tr>`
      ).join('');
      const recCards = (mitreCov.ai_analysis?.recommendations || []).map(r =>
        `<div style="margin-bottom:10px;padding:10px 14px;border-left:4px solid ${effortColor[r.effort]||'#6b7280'};background:#f9fafb">
          <div style="font-weight:700;font-size:13px">[${effortLabel[r.effort]||r.effort}] ${r.title}</div>
          <div style="color:#16a34a;font-size:12px;margin:3px 0">${r.impact}</div>
          <div style="color:#6b7280;font-size:12px">${r.steps || ''}</div>
          ${(r.techniques_covered||[]).length?`<div style="font-size:11px;color:#374151;margin-top:4px">Covers: ${r.techniques_covered.join(', ')}</div>`:''}
        </div>`
      ).join('');
      const gapRows = (mitreCov.ai_analysis?.gap_analysis || []).slice(0, 15).map(g =>
        `<tr><td style="font-family:monospace;color:#b45309">${g.id}</td><td>${g.name}</td>
         <td>${g.why_missing||'—'}</td><td style="color:#15803d">${g.detection_opportunity||'—'}</td></tr>`
      ).join('');
      mitreSectionHtml = `
        <div style="margin-top:40px;padding-top:24px;border-top:2px solid #111">
          <h2 style="font-size:18px;letter-spacing:1px;margin-bottom:4px">MITRE ATT&CK Coverage Analysis</h2>
          <p style="color:#666;font-size:12px;margin-bottom:20px">Timeframe: ${mitreCov.timeframe} · ${mitreCov.covered}/${mitreCov.total} techniques (${mitreCov.pct}% coverage) · Log sources: ${(mitreCov.log_sources||[]).join(', ')||'N/A'}</p>

          <h3 style="font-size:14px;margin:16px 0 8px">Tactic Coverage Breakdown</h3>
          <table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:20px">
            <thead><tr style="background:#f3f4f6"><th style="text-align:left;padding:6px">Tactic</th><th>Techniques</th><th style="width:120px">Coverage</th><th>%</th></tr></thead>
            <tbody>${tacticRows}</tbody>
          </table>

          ${gapRows ? `<h3 style="font-size:14px;margin:16px 0 8px">Priority Coverage Gaps</h3>
          <table style="width:100%;border-collapse:collapse;font-size:11px;margin-bottom:20px">
            <thead><tr style="background:#f3f4f6"><th>ID</th><th>Technique</th><th>Why Missing</th><th>Detection Opportunity</th></tr></thead>
            <tbody>${gapRows}</tbody>
          </table>` : ''}

          ${recCards ? `<h3 style="font-size:14px;margin:16px 0 8px">Detection Recommendations</h3>${recCards}` : ''}

          ${mitreCov.unmapped_audit ? `<div style="margin-top:16px;padding:10px 14px;background:#fefce8;border:1px solid #fde047;font-size:12px">
            <strong>Unmapped Rules:</strong> ${mitreCov.unmapped_audit.total_unmapped?.toLocaleString()} alerts without MITRE tags — ${(mitreCov.unmapped_audit.top_decoders||[]).map(d=>d.decoder+'('+d.count.toLocaleString()+')').join(', ')}
          </div>` : ''}
        </div>`;
    }

    win.document.write(`<!DOCTYPE html><html><head><title>${sel.title}</title><style>
      body{font-family:sans-serif;max-width:800px;margin:48px auto;color:#111;line-height:1.6}
      .hdr{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #111;padding-bottom:14px;margin-bottom:28px}
      .logo{font-size:22px;font-weight:800;letter-spacing:3px}.sub{font-size:11px;color:#666;margin-top:2px}
      .meta{font-size:12px;color:#555;text-align:right;line-height:1.8}
      pre{white-space:pre-wrap;word-break:break-word;font-size:13px;font-family:inherit}
      table{border-collapse:collapse;width:100%} th,td{padding:5px 8px;border:1px solid #e5e7eb;text-align:left}
      .ft{margin-top:48px;border-top:1px solid #ccc;padding-top:8px;font-size:11px;color:#999;text-align:center}
      @media print{body{margin:24px}}
    </style></head><body>
      <div class="hdr">
        <div><div class="logo">SOC<span style="color:#0077cc">PILOTS</span></div>
          <div class="sub">${sel.id} · CONFIDENTIAL</div></div>
        <div class="meta">Period: ${sel.range}<br>Author: ${sel.author}<br>Pages: ${sel.pages}</div>
      </div>
      <pre>${(sel.content || 'No content').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
      ${mitreSectionHtml}
      <div class="ft">SOC Pilots · ${sel.id} · Generated ${sel.when || ''} · AI-drafted, human-approved</div>
    </body></html>`);
    win.document.close();
    setTimeout(() => win.print(), 400);
  }

  function startEdit(sel) {
    setEditContent(sel?.content || '');
    setEditMode(true);
  }

  function saveEdit() {
    setReports(prev => prev.map(r => r.id === selectedId ? { ...r, content: editContent } : r));
    setEditMode(false);
    window.socToast?.({ title: 'Report saved', sub: 'Content updated', tone: 'ok' });
  }

  const selected = reports.find(r => r.id === selectedId) || null;

  return (
    <div className="page">
      <Topbar
        title="Reports"
        sub="AI-drafted exec summaries · compliance · incident retros"
        actions={<>
          <button className="btn btn-ghost" onClick={() => setShowTmpl(true)}>Templates</button>
          <button className="btn btn-ghost" onClick={() => setShowSched(true)}>Schedule</button>
          <button className="btn btn-primary" onClick={() => generate('exec')} disabled={generating}>
            <Icon.brain width="13" height="13"/> {generating ? 'Generating…' : 'Generate'}
          </button>
        </>}
      />

      {/* Templates modal */}
      {showTmpl && (
        <div className="modal-overlay" onClick={() => setShowTmpl(false)}>
          <div className="modal" style={{ maxWidth: 480 }} onClick={e => e.stopPropagation()}>
            <div className="modal-hd">
              <span>Report Templates</span>
              <button className="btn-icon" onClick={() => setShowTmpl(false)}><Icon.x width="14" height="14"/></button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: '16px 0' }}>
              {REPORT_TEMPLATES.map(t => (
                <button key={t.id} className="btn btn-ghost" style={{ justifyContent: 'flex-start', gap: 12, padding: '12px 16px', textAlign: 'left' }}
                  onClick={() => { setShowTmpl(false); generate(t.id); }}>
                  <span style={{ fontSize: 22 }}>{t.icon}</span>
                  <div>
                    <div style={{ fontWeight: 600, marginBottom: 2 }}>{t.label}</div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--fg-3)' }}>{t.desc}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Schedule modal */}
      {showSched && (
        <div className="modal-overlay" onClick={() => setShowSched(false)}>
          <div className="modal" style={{ maxWidth: 400 }} onClick={e => e.stopPropagation()}>
            <div className="modal-hd">
              <span>Schedule Reports</span>
              <button className="btn-icon" onClick={() => setShowSched(false)}><Icon.x width="14" height="14"/></button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, padding: '16px 0' }}>
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span className="card-sub">Frequency</span>
                <select className="select-mini" value={schedFreq} onChange={e => setSchedFreq(e.target.value)}>
                  {SCHED_FREQS.map(f => <option key={f}>{f}</option>)}
                </select>
              </label>
              {(schedFreq === 'Weekly' || schedFreq === 'Bi-weekly') && (
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span className="card-sub">Day</span>
                  <select className="select-mini" value={schedDay} onChange={e => setSchedDay(e.target.value)}>
                    {SCHED_DAYS.map(d => <option key={d}>{d}</option>)}
                  </select>
                </label>
              )}
              <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <span className="card-sub">Time (UTC)</span>
                <input type="time" className="mono" value={schedTime} onChange={e => setSchedTime(e.target.value)} style={{ width: 120 }}/>
              </label>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 8 }}>
                <button className="btn btn-ghost" onClick={() => setShowSched(false)}>Cancel</button>
                <button className="btn btn-primary" onClick={() => {
                  setShowSched(false);
                  window.socToast?.({ title: 'Schedule saved', sub: `${schedFreq} · ${schedDay || ''} ${schedTime} UTC`, tone: 'ok' });
                }}>Save Schedule</button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="page-body">
        {loading ? (
          <div className="loading mono">Loading reports…</div>
        ) : reports.length === 0 ? (
          <div className="empty mono" style={{ marginTop: 60, textAlign: 'center' }}>
            <Icon.folder width="36" height="36"/><br/><br/>
            No reports yet.<br/>Click <strong>Generate</strong> or pick a <strong>Template</strong>.
          </div>
        ) : (
          <div className="reports-layout">
            <aside className="reports-side">
              <Card title="Reports" sub={`${reports.length} total`} padded>
                <ul className="report-list">
                  {reports.map(r => (
                    <li key={r.id} style={{ position: 'relative' }}>
                      <button className={`report-item ${selectedId === r.id ? 'on' : ''}`} onClick={() => { setSelectedId(r.id); setEditMode(false); }}>
                        <div className="ri-head">
                          <span className="ri-id mono">{r.id}</span>
                          <Chip mono tone={r.status === 'sent' ? 'ok' : 'warn'}>{r.status}</Chip>
                        </div>
                        <div className="ri-title">{r.title}</div>
                        <div className="ri-meta mono">{r.range} · {r.pages ? r.pages + 'pp · ' : ''}{r.when || ''}</div>
                      </button>
                      <button className="btn-icon" title="Delete report"
                        style={{ position: 'absolute', top: 6, right: 4, opacity: .45 }}
                        onClick={e => { e.stopPropagation(); deleteReport(r.id); }}>
                        <Icon.x width="11" height="11"/>
                      </button>
                    </li>
                  ))}
                </ul>
              </Card>

              <Card title="Distribution" sub="auto-deliver" padded>
                {recipients.map(rec => (
                  <div key={rec.id} className="dist-row" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    {rec.type === 'slack'
                      ? <Icon.share width="13" height="13" style={{ flexShrink: 0 }}/>
                      : <Icon.inbox width="13" height="13" style={{ flexShrink: 0 }}/>}
                    <span style={{ flex: 1, fontSize: '0.82rem' }}>{rec.addr}</span>
                    <button className="btn-icon" title="Remove" style={{ opacity: .4 }}
                      onClick={() => setRecipients(prev => prev.filter(r => r.id !== rec.id))}>
                      <Icon.x width="11" height="11"/>
                    </button>
                  </div>
                ))}

                {addingRecip ? (
                  <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
                    <select className="select-mini" value={newType} onChange={e => setNewType(e.target.value)}>
                      <option value="email">Email</option>
                      <option value="slack">Slack</option>
                    </select>
                    <input placeholder={newType === 'email' ? 'name@company.com' : '#channel-name'}
                      value={newAddr} onChange={e => setNewAddr(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') addRecipient(); if (e.key === 'Escape') setAddingRecip(false); }}
                      style={{ fontSize: '0.82rem' }} autoFocus/>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button className="btn btn-primary btn-sm" onClick={addRecipient}>Add</button>
                      <button className="btn btn-ghost btn-sm" onClick={() => setAddingRecip(false)}>Cancel</button>
                    </div>
                  </div>
                ) : (
                  <button className="btn btn-ghost btn-sm" style={{ marginTop: 10 }}
                    onClick={() => setAddingRecip(true)}>
                    <Icon.plus width="11" height="11"/> Add recipient
                  </button>
                )}
              </Card>
            </aside>

            <main className="reports-main">
              {selected && (
                <Card title={selected.title} sub={selected.range + ' · ' + selected.author}
                  actions={<>
                    <Chip mono tone={selected.status === 'sent' ? 'ok' : 'warn'}>{selected.status}</Chip>
                    {editMode
                      ? <>
                          <button className="btn btn-primary btn-sm" onClick={saveEdit}>Save</button>
                          <button className="btn btn-ghost btn-sm" onClick={() => setEditMode(false)}>Cancel</button>
                        </>
                      : <>
                          <button className="btn btn-ghost btn-sm" onClick={() => startEdit(selected)}>Edit</button>
                          <button className="btn btn-ghost btn-sm" onClick={() => exportPDF(selected)}>PDF</button>
                          <button className="btn btn-primary btn-sm"
                            onClick={() => sendReport(selected)}
                            disabled={selected.status === 'sent'}>
                            {selected.status === 'sent' ? 'Sent' : 'Send'}
                          </button>
                        </>
                    }
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
                          <div className="rd-brand-sub mono">{selected.id} · CONFIDENTIAL</div>
                        </div>
                      </div>
                      <div className="rd-meta mono">
                        <div>Period · {selected.range}</div>
                        <div>Author · {selected.author}</div>
                        <div>Pages · {selected.pages}</div>
                      </div>
                    </div>

                    {editMode ? (
                      <textarea
                        value={editContent}
                        onChange={e => setEditContent(e.target.value)}
                        style={{ width: '100%', minHeight: 340, background: 'var(--bg-2)', border: '1px solid var(--ln)',
                          borderRadius: 6, padding: 12, color: 'var(--fg-0)', fontFamily: 'var(--fm)',
                          fontSize: '0.82rem', lineHeight: 1.6, resize: 'vertical' }}
                      />
                    ) : selected.content ? (
                      <>
                        <section className="rd-section">
                          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'var(--fm)', fontSize: '0.82rem', color: 'var(--fg-1)', margin: 0, lineHeight: 1.65 }}>{selected.content}</pre>
                        </section>
                        {mitreCov && <ReportMitreSection cov={mitreCov} />}
                      </>
                    ) : (
                      <div className="empty mono" style={{ padding: '40px 24px', textAlign: 'center' }}>
                        Click <strong>Generate</strong> or choose a <strong>Template</strong> to create a report.
                      </div>
                    )}

                    <footer className="rd-foot mono">SOC Pilots · {selected.id} · Generated {selected.when || 'unknown'} · AI-drafted, human-approved</footer>
                  </div>
                </Card>
              )}
            </main>
          </div>
        )}
      </div>
    </div>
  );
}

// ── MITRE ATT&CK section rendered inside the report viewer ───────────────────
function ReportMitreSection({ cov }) {
  const [tab, setTab] = useStateS('tactic');
  if (!cov) return null;

  const EFFORT_COLOR = { quick_win: 'var(--ok)', medium_effort: 'var(--warn)', strategic: '#9c6cf7' };
  const EFFORT_LABEL = { quick_win: 'Quick Win', medium_effort: 'Medium Effort', strategic: 'Strategic' };
  const ai           = cov.ai_analysis;
  const hasTabs      = !!(ai?.gap_analysis?.length || ai?.recommendations?.length);

  return (
    <section className="rd-section" style={{ borderTop: '1px solid var(--ln)', paddingTop: 20, marginTop: 20 }}>
      {/* Section header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--fg)', letterSpacing: '0.04em', marginBottom: 4 }}>
            MITRE ATT&CK COVERAGE ANALYSIS
          </div>
          <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>
            Timeframe: {cov.timeframe} · {cov.covered}/{cov.total} techniques ({cov.pct}% coverage)
            {cov.ai_analyzed_at && ` · AI analyzed ${new Date(cov.ai_analyzed_at).toLocaleString()}`}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 16, textAlign: 'right' }}>
          <div>
            <div className="mono" style={{ fontSize: 18, color: cov.pct >= 50 ? 'var(--ok)' : cov.pct >= 25 ? 'var(--warn)' : 'var(--crit)', fontWeight: 700 }}>{cov.pct}%</div>
            <div style={{ fontSize: 10, color: 'var(--fg-3)' }}>Coverage</div>
          </div>
          <div>
            <div className="mono" style={{ fontSize: 18, color: 'var(--acc)', fontWeight: 700 }}>{cov.covered}</div>
            <div style={{ fontSize: 10, color: 'var(--fg-3)' }}>Detected</div>
          </div>
        </div>
      </div>

      {/* Log sources */}
      {cov.log_sources?.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--mono)', letterSpacing: '0.06em', marginBottom: 6 }}>ACTIVE LOG SOURCES</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {cov.log_sources.map(s => (
              <span key={s} className="chip chip-mono" style={{ fontSize: 10, padding: '2px 8px', background: 'rgba(0,229,255,0.08)', border: '1px solid rgba(0,229,255,0.2)', borderRadius: 3, color: 'var(--acc)' }}>{s}</span>
            ))}
          </div>
        </div>
      )}

      {/* Tab navigation */}
      {hasTabs && (
        <div className="seg" style={{ marginBottom: 14 }}>
          <button className={`seg-btn ${tab === 'tactic' ? 'on' : ''}`} style={{ fontSize: 10 }} onClick={() => setTab('tactic')}>Tactic Breakdown</button>
          {ai?.gap_analysis?.length > 0 && (
            <button className={`seg-btn ${tab === 'gaps' ? 'on' : ''}`} style={{ fontSize: 10 }} onClick={() => setTab('gaps')}>Top Gaps ({ai.gap_analysis.length})</button>
          )}
          {ai?.recommendations?.length > 0 && (
            <button className={`seg-btn ${tab === 'recs' ? 'on' : ''}`} style={{ fontSize: 10 }} onClick={() => setTab('recs')}>Recommendations ({ai.recommendations.length})</button>
          )}
          {cov.unmapped_audit && (
            <button className={`seg-btn ${tab === 'unmapped' ? 'on' : ''}`} style={{ fontSize: 10 }} onClick={() => setTab('unmapped')}>
              Unmapped Rules ({cov.unmapped_audit.total_unmapped?.toLocaleString()})
            </button>
          )}
        </div>
      )}

      {/* Tactic breakdown (always shown if no AI yet) */}
      {(tab === 'tactic' || !hasTabs) && (
        <div>
          {(cov.tactic_breakdown || []).map(t => (
            <div key={t.id} style={{ marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                <span style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--fg)' }}>{t.name}</span>
                <span className="mono" style={{ fontSize: 11, color: t.pct >= 50 ? 'var(--ok)' : t.pct >= 25 ? 'var(--warn)' : 'var(--crit)' }}>
                  {t.covered}/{t.total} · {t.pct}%
                </span>
              </div>
              <div style={{ height: 5, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 3, width: `${t.pct}%`,
                  background: t.pct >= 50 ? 'var(--ok)' : t.pct >= 25 ? 'var(--warn)' : 'var(--crit)',
                  transition: 'width 0.4s ease',
                }} />
              </div>
            </div>
          ))}
          {!hasTabs && (
            <div style={{ marginTop: 12, padding: '10px 14px', background: 'rgba(0,229,255,0.05)', border: '1px solid rgba(0,229,255,0.15)', borderRadius: 6, fontSize: 11, color: 'var(--fg-2)' }}>
              Go to <strong>ATT&CK Coverage</strong> page and run <strong>AI Analysis</strong> to get gap explanations and detection recommendations.
            </div>
          )}
        </div>
      )}

      {/* Priority gaps */}
      {tab === 'gaps' && ai?.gap_analysis?.length > 0 && (
        <table className="data-table" style={{ fontSize: 11 }}>
          <thead><tr><th>TECHNIQUE</th><th>WHY MISSING</th><th>DETECTION OPPORTUNITY</th></tr></thead>
          <tbody>
            {ai.gap_analysis.map(g => (
              <tr key={g.id}>
                <td>
                  <span className="mono" style={{ color: 'var(--crit)', marginRight: 6 }}>{g.id}</span>
                  <span style={{ color: 'var(--fg-2)' }}>{g.name}</span>
                </td>
                <td style={{ fontSize: 10, color: 'var(--fg-3)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{g.why_missing || '—'}</td>
                <td style={{ fontSize: 10, color: 'var(--ok)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{g.detection_opportunity || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* Recommendations */}
      {tab === 'recs' && ai?.recommendations?.length > 0 && (
        <div>
          {['quick_win', 'medium_effort', 'strategic'].map(effort => {
            const recs = ai.recommendations.filter(r => r.effort === effort);
            if (!recs.length) return null;
            return (
              <div key={effort} style={{ marginBottom: 16 }}>
                <div className="mono" style={{ fontSize: 10, color: EFFORT_COLOR[effort], letterSpacing: '0.06em', marginBottom: 8 }}>
                  {EFFORT_LABEL[effort]} ({recs.length})
                </div>
                {recs.map((r, i) => (
                  <div key={i} style={{
                    marginBottom: 8, padding: '10px 14px',
                    background: 'var(--bg-2)',
                    borderLeft: `3px solid ${EFFORT_COLOR[effort]}`,
                    borderRadius: 4,
                  }}>
                    <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--fg)', marginBottom: 3 }}>{r.title}</div>
                    <div style={{ fontSize: 11, color: 'var(--ok)', marginBottom: 4 }}>{r.impact}</div>
                    <div style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: r.techniques_covered?.length ? 6 : 0 }}>{r.steps}</div>
                    {r.techniques_covered?.length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {r.techniques_covered.map(t => (
                          <span key={t} className="mono" style={{ fontSize: 9, padding: '1px 5px', background: 'rgba(0,229,255,0.06)', border: '1px solid rgba(0,229,255,0.15)', borderRadius: 2, color: 'var(--acc)' }}>{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      )}

      {/* Unmapped rules */}
      {tab === 'unmapped' && cov.unmapped_audit && (
        <div>
          <div style={{ marginBottom: 12, padding: '8px 12px', background: 'rgba(255,152,0,0.06)', border: '1px solid rgba(255,152,0,0.2)', borderRadius: 6, fontSize: 11, color: 'var(--fg-2)' }}>
            <span className="mono" style={{ color: 'var(--warn)' }}>{cov.unmapped_audit.total_unmapped?.toLocaleString()}</span> alerts have no <span className="mono" style={{ color: 'var(--warn)' }}>rule.mitre.id</span> tag.
            These rules need MITRE mapping in your Wazuh ruleset to improve real coverage.
          </div>
          <table className="data-table" style={{ fontSize: 11 }}>
            <thead><tr><th>RULE ID</th><th>LEVEL</th><th>SEV</th><th>LOG SOURCE</th><th>ALERTS</th><th>DESCRIPTION</th></tr></thead>
            <tbody>
              {(cov.unmapped_audit.top_rules || []).map(r => (
                <tr key={r.id}>
                  <td className="mono" style={{ color: 'var(--warn)' }}>{r.id}</td>
                  <td className="mono">{r.level}</td>
                  <td><SevChip sev={r.severity} /></td>
                  <td className="mono" style={{ color: 'var(--acc)' }}>{r.decoder}</td>
                  <td className="mono">{r.count?.toLocaleString()}</td>
                  <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

Object.assign(window, { PageAgents, PageRules, PageVulns, PageReports });
