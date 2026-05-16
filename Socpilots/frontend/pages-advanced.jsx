// SLA · Evidence · Artifacts · Users · LangChain · LogSources · Investigation · Notifications
const { useState: useStateADV, useEffect: useEffectADV, useRef: useRefADV, useMemo: useMemoADV } = React;

// ============= PAGE SLA =============
const FALLBACK_SLA_DASH = { active: 12, breached: 2, at_risk: 3, resolved_today: 7 };
const FALLBACK_SLA_POLICIES = [
  { id: 1, name: 'Critical Response', severity: 'critical', response_hours: 1,  resolution_hours: 4   },
  { id: 2, name: 'High Priority',     severity: 'high',     response_hours: 4,  resolution_hours: 24  },
  { id: 3, name: 'Standard',          severity: 'medium',   response_hours: 8,  resolution_hours: 72  },
  { id: 4, name: 'Low Priority',      severity: 'low',      response_hours: 24, resolution_hours: 168 },
];
const FALLBACK_SLA_INSTANCES = [
  { id: 'SLA-001', case_id: 'SP-2341', severity: 'critical', policy: 'Critical Response', time_remaining_pct: 23, status: 'at-risk',  assigned_to: 'jdoe'  },
  { id: 'SLA-002', case_id: 'SP-2338', severity: 'high',     policy: 'High Priority',    time_remaining_pct: 68, status: 'on-track', assigned_to: 'admin' },
  { id: 'SLA-003', case_id: 'SP-2336', severity: 'critical', policy: 'Critical Response', time_remaining_pct: 0,  status: 'breached', assigned_to: 'jdoe'  },
];

function PageSLA() {
  const [tab, setTab]         = useStateADV('active');
  const [dash, setDash]       = useStateADV(FALLBACK_SLA_DASH);
  const [instances, setInst]  = useStateADV(FALLBACK_SLA_INSTANCES);
  const [policies, setPol]    = useStateADV(FALLBACK_SLA_POLICIES);
  const [showForm, setForm]   = useStateADV(false);
  const [newCaseId, setNCI]   = useStateADV('');
  const [newPol, setNPol]     = useStateADV('1');

  useEffectADV(() => {
    window.SOC_API.get('/api/sla/dashboard').then(d => { if (d && !d.error) setDash(d); });
    window.SOC_API.get('/api/sla/policies').then(d => { if (d && Array.isArray(d.policies)) setPol(d.policies); else if (Array.isArray(d)) setPol(d); });
    window.SOC_API.get('/api/sla/instances?status=active').then(d => { if (d && Array.isArray(d.instances)) setInst(d.instances); else if (Array.isArray(d)) setInst(d); });
  }, []);

  async function startSLA() {
    if (!newCaseId.trim()) return;
    const r = await window.SOC_API.post('/api/sla/instances', { case_id: newCaseId.trim(), policy_id: parseInt(newPol) });
    if (r && !r.error) {
      window.socToast?.({ title: 'SLA started', sub: newCaseId + ' · ' + (policies.find(p => String(p.id) === newPol)?.name || ''), tone: 'ok' });
      setForm(false); setNCI('');
    } else {
      window.socToast?.({ title: 'SLA error', sub: r?.error || 'Failed to start SLA', tone: 'error' });
    }
  }

  const statusColor = s => s === 'breached' ? 'critical' : s === 'at-risk' ? 'high' : 'low';

  const filtered = tab === 'policies' ? [] : instances.filter(i => {
    if (tab === 'active')   return i.status !== 'breached';
    if (tab === 'breached') return i.status === 'breached';
    return true;
  });

  return (
    <div className="page">
      <Topbar
        title="SLA Management"
        sub="Service Level Agreements · response &amp; resolution tracking"
        actions={<>
          <button className="btn btn-primary" onClick={() => setForm(f => !f)}>
            <Icon.plus width="13" height="13"/> Start SLA
          </button>
        </>}
      />
      <div className="page-body">
        {showForm && (
          <Card title="Start SLA" sub="attach an SLA policy to a case">
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
              <div>
                <div className="card-sub" style={{ marginBottom: 4 }}>Case ID</div>
                <input className="mono" placeholder="SP-2341" value={newCaseId} onChange={e => setNCI(e.target.value)} style={{ width: 140 }} />
              </div>
              <div>
                <div className="card-sub" style={{ marginBottom: 4 }}>Policy</div>
                <select className="select-mini mono" value={newPol} onChange={e => setNPol(e.target.value)}>
                  {policies.map(p => <option key={p.id} value={String(p.id)}>{p.name}</option>)}
                </select>
              </div>
              <button className="btn btn-primary" onClick={startSLA}>Create</button>
              <button className="btn btn-ghost" onClick={() => setForm(false)}>Cancel</button>
            </div>
          </Card>
        )}

        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
          <KpiCard label="Active SLAs"     value={dash.active}         sub="in progress" />
          <KpiCard label="Breached"        value={dash.breached}       sub="past deadline" sev={dash.breached > 0 ? 'critical' : undefined} />
          <KpiCard label="At Risk"         value={dash.at_risk}        sub="< 25% time left" sev={dash.at_risk > 0 ? 'high' : undefined} />
          <KpiCard label="Resolved Today"  value={dash.resolved_today} sub="closed within SLA" />
        </div>

        <Card title="SLA Tracker"
          actions={<>
            {['active','breached','all','policies'].map(t => (
              <button key={t} className={`seg-btn ${tab === t ? 'on' : ''}`} onClick={() => setTab(t)}>{t}</button>
            ))}
          </>}>

          {tab === 'policies' ? (
            <table className="data-table">
              <thead><tr><th>POLICY NAME</th><th>SEVERITY</th><th>RESPONSE TIME (h)</th><th>RESOLUTION TIME (h)</th><th></th></tr></thead>
              <tbody>
                {policies.map(p => (
                  <tr key={p.id}>
                    <td>{p.name}</td>
                    <td><SevChip sev={p.severity} /></td>
                    <td className="mono">{p.response_hours}h</td>
                    <td className="mono">{p.resolution_hours}h</td>
                    <td><button className="btn btn-ghost btn-sm">Edit</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <table className="data-table">
              <thead><tr><th>CASE ID</th><th>SEVERITY</th><th>POLICY</th><th style={{ width: 180 }}>TIME REMAINING</th><th>STATUS</th><th>ASSIGNED TO</th></tr></thead>
              <tbody>
                {filtered.map(i => (
                  <tr key={i.id}>
                    <td className="mono">{i.case_id}</td>
                    <td><SevChip sev={i.severity} /></td>
                    <td>{i.policy}</td>
                    <td>
                      <div className="bar-wrap">
                        <div className="bar" data-sev={statusColor(i.status)} style={{ width: `${i.time_remaining_pct}%` }} />
                        <span className="bar-val mono">{i.time_remaining_pct}%</span>
                      </div>
                    </td>
                    <td><Chip mono tone={i.status === 'breached' ? 'crit' : i.status === 'at-risk' ? 'warn' : 'ok'}>{i.status}</Chip></td>
                    <td className="mono">{i.assigned_to}</td>
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

// ============= PAGE EVIDENCE =============
const FALLBACK_EVIDENCE = [
  { id: 1, filename: 'incident_report_2026-05-12.pdf', type: 'pdf',  size: 284210,   uploaded_at: new Date(Date.now()-3600000).toISOString(),  uploaded_by: 'admin', hash: 'sha256:a1b2c3d4e5f6...', url: '#' },
  { id: 2, filename: 'network_capture.pcap',            type: 'pcap', size: 15728640, uploaded_at: new Date(Date.now()-7200000).toISOString(),  uploaded_by: 'jdoe',  hash: 'sha256:f6e5d4c3b2a1...', url: '#' },
  { id: 3, filename: 'malware_sample.bin',              type: 'bin',  size: 45056,    uploaded_at: new Date(Date.now()-10800000).toISOString(), uploaded_by: 'admin', hash: 'sha256:aabbccdd...',    url: '#' },
];

function formatBytes(b) {
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024)    return (b / 1024).toFixed(1) + ' KB';
  return b + ' B';
}

function PageEvidence() {
  const [files, setFiles]   = useStateADV(FALLBACK_EVIDENCE);
  const [search, setSearch] = useStateADV('');
  const [loading, setLoad]  = useStateADV(false);
  const fileRef             = useRefADV(null);

  useEffectADV(() => {
    window.SOC_API.get('/api/evidence').then(d => {
      const arr = d?.files || d?.items || (Array.isArray(d) ? d : null);
      if (arr && arr.length > 0) setFiles(arr);
    });
  }, []);

  async function uploadFile(file) {
    if (!file) return;
    setLoad(true);
    const token = sessionStorage.getItem('soc_token');
    const fd = new FormData();
    fd.append('file', file);
    try {
      const res = await fetch('/api/evidence/upload', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + token },
        body: fd,
      });
      const json = await res.json().catch(() => ({}));
      if (res.ok) {
        window.socToast?.({ title: 'Upload complete', sub: file.name, tone: 'ok' });
        window.SOC_API.get('/api/evidence').then(d => { const arr = d?.files || d?.items || (Array.isArray(d) ? d : null); if (arr) setFiles(arr); });
      } else {
        window.socToast?.({ title: 'Upload failed', sub: json.error || 'Server error', tone: 'error' });
      }
    } catch {
      window.socToast?.({ title: 'Upload failed', sub: 'Network error', tone: 'error' });
    }
    setLoad(false);
  }

  async function deleteFile(id) {
    await window.SOC_API.del('/api/evidence/' + id);
    setFiles(f => f.filter(x => x.id !== id));
    window.socToast?.({ title: 'File deleted', sub: '', tone: 'ok' });
  }

  const filtered = files.filter(f => f.filename.toLowerCase().includes(search.toLowerCase()));
  const totalSize = files.reduce((a, f) => a + (f.size || 0), 0);
  const recent24h = files.filter(f => Date.now() - new Date(f.uploaded_at).getTime() < 86400000).length;

  const typeIcon = t => ({ pdf: '📄', pcap: '🔍', bin: '⚙', txt: '📝', csv: '📊', xlsx: '📊' }[t] || '📁');

  return (
    <div className="page">
      <Topbar
        title="Evidence"
        sub="Uploaded files · forensic artifacts · OCR-indexed"
        actions={<>
          <button className="btn btn-primary" onClick={() => fileRef.current?.click()} disabled={loading}>
            <Icon.plus width="13" height="13"/> {loading ? 'Uploading…' : 'Upload'}
          </button>
          <input ref={fileRef} type="file" style={{ display: 'none' }} onChange={e => uploadFile(e.target.files?.[0])} />
        </>}
      />
      <div className="page-body">
        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(3,1fr)' }}>
          <KpiCard label="Total Files"     value={files.length}       sub="evidence vault" />
          <KpiCard label="Storage Used"    value={formatBytes(totalSize)} sub="across all files" mono />
          <KpiCard label="Recent Uploads"  value={recent24h}          sub="last 24 hours" />
        </div>

        <Card title="Evidence Files"
          actions={<>
            <div className="tb-search" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon.search width="13" height="13" />
              <input placeholder="Filter by filename…" value={search} onChange={e => setSearch(e.target.value)} />
            </div>
          </>}>

          {files.length === 0 ? (
            <div
              className="empty mono"
              style={{ border: '2px dashed var(--b2)', borderRadius: 8, padding: '48px 24px', textAlign: 'center', cursor: 'pointer' }}
              onClick={() => fileRef.current?.click()}
            >
              <Icon.folder width="32" height="32" /><br />
              Drag &amp; drop files here or click to upload
            </div>
          ) : (
            <table className="data-table">
              <thead><tr><th>FILE NAME</th><th>TYPE</th><th>SIZE</th><th>UPLOAD DATE</th><th>UPLOADED BY</th><th>HASH</th><th></th></tr></thead>
              <tbody>
                {filtered.map(f => (
                  <tr key={f.id}>
                    <td className="mono">{f.filename}</td>
                    <td className="mono">{typeIcon(f.type)} {f.type}</td>
                    <td className="mono">{formatBytes(f.size)}</td>
                    <td className="mono dim">{window.SOC_API.relTs(f.uploaded_at)}</td>
                    <td className="mono">{f.uploaded_by}</td>
                    <td className="mono dim" style={{ maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis' }}>{(f.hash || '').slice(0, 24)}…</td>
                    <td>
                      <a href={f.url || '#'} className="btn btn-ghost btn-sm" style={{ marginRight: 4 }}>Download</a>
                      <button className="btn btn-ghost btn-sm" onClick={() => deleteFile(f.id)} style={{ color: 'var(--r)' }}>Delete</button>
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

// ============= PAGE ARTIFACTS =============
const FALLBACK_IOC_STATS = { total: 1247, malicious: 89, auto_ingest: false, auto_enrich: false };
const FALLBACK_IOCS = [
  { id: 1, indicator: '185.220.101.45',              type: 'ip',     threat_score: 95, sources: ['OTX','VT'], first_seen: new Date(Date.now()-86400000).toISOString(),  last_seen: new Date().toISOString() },
  { id: 2, indicator: 'malware.example.com',          type: 'domain', threat_score: 87, sources: ['OTX'],      first_seen: new Date(Date.now()-172800000).toISOString(), last_seen: new Date(Date.now()-3600000).toISOString() },
  { id: 3, indicator: 'd41d8cd98f00b204e9800998ecf8427e', type: 'md5', threat_score: 72, sources: ['VT'],       first_seen: new Date(Date.now()-259200000).toISOString(), last_seen: new Date(Date.now()-7200000).toISOString() },
];

function PageArtifacts() {
  const [tab, setTab]       = useStateADV('overview');
  const [stats, setStats]   = useStateADV(FALLBACK_IOC_STATS);
  const [iocs, setIocs]     = useStateADV(FALLBACK_IOCS);
  const [iocSearch, setIocSearch] = useStateADV('');
  const [newIoc, setNewIoc] = useStateADV('');
  const [newType, setNewType] = useStateADV('ip');
  const [extractText, setET] = useStateADV('');
  const [wlInput, setWlInput] = useStateADV('');
  const [whitelist, setWl]  = useStateADV([]);
  const [autoIngest, setAI] = useStateADV(false);
  const [autoEnrich, setAE] = useStateADV(false);

  useEffectADV(() => {
    window.SOC_API.get('/api/ioc-store').then(d => {
      if (d && !d.error) {
        setStats({ total: d.total || FALLBACK_IOC_STATS.total, malicious: d.malicious || FALLBACK_IOC_STATS.malicious, auto_ingest: d.auto_ingest || false, auto_enrich: d.auto_enrich || false });
        setAI(!!d.auto_ingest);
        setAE(!!d.auto_enrich);
        if (Array.isArray(d.iocs)) setIocs(d.iocs);
      }
    });
  }, []);

  async function ingestAlerts() {
    const r = await window.SOC_API.post('/api/ioc-store/ingest-alerts', {});
    window.socToast?.({ title: 'Ingest complete', sub: r?.ingested ? r.ingested + ' IOCs ingested' : 'Done', tone: 'ok' });
  }

  async function enrichAll() {
    const r = await window.SOC_API.post('/api/ioc-store/enrich-all', {});
    window.socToast?.({ title: 'Enrich started', sub: r?.message || 'Enriching all IOCs', tone: 'info' });
  }

  async function searchIocs() {
    const r = await window.SOC_API.get('/api/ioc-store?search=' + encodeURIComponent(iocSearch) + '&type=all');
    if (r && Array.isArray(r.iocs)) setIocs(r.iocs);
    else if (Array.isArray(r)) setIocs(r);
  }

  async function addIoc() {
    if (!newIoc.trim()) return;
    const r = await window.SOC_API.post('/api/ioc-store', { indicator: newIoc.trim(), type: newType });
    if (r && !r.error) { window.socToast?.({ title: 'IOC added', sub: newIoc, tone: 'ok' }); setNewIoc(''); }
    else window.socToast?.({ title: 'Error', sub: r?.error || 'Failed', tone: 'error' });
  }

  async function extractIOCs() {
    const r = await window.SOC_API.post('/api/ioc-store/extract', { text: extractText });
    window.socToast?.({ title: 'Extraction done', sub: r?.count ? r.count + ' IOCs found' : 'No IOCs found', tone: 'ok' });
  }

  const scoreColor = s => s >= 80 ? 'critical' : s >= 60 ? 'high' : s >= 40 ? 'medium' : 'low';

  return (
    <div className="page">
      <Topbar
        title="Artifacts &amp; IOC Intelligence"
        sub="IOC store · enrichment · file analysis · threat hunting"
        actions={<>
          <button className="btn btn-ghost" onClick={ingestAlerts}><Icon.refresh width="13" height="13"/> Ingest from Alerts</button>
          <button className="btn btn-primary" onClick={enrichAll}><Icon.brain width="13" height="13"/> Enrich All</button>
        </>}
      />
      <div className="page-body">
        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
          <KpiCard label="Total IOCs"  value={stats.total}    sub="in store" />
          <KpiCard label="Malicious"   value={stats.malicious} sub="confirmed threats" sev="critical" />
          <KpiCard label="Auto-Ingest" value={autoIngest ? 'ON' : 'OFF'} sub="from SIEM alerts" />
          <KpiCard label="Auto-Enrich" value={autoEnrich ? 'ON' : 'OFF'} sub="multi-source enrichment" />
        </div>

        <Card actions={<>
          {['overview','ioc-intel','file-analysis','enrichment','threat-hunting','whitelist','settings'].map(t => (
            <button key={t} className={`seg-btn ${tab === t ? 'on' : ''}`} onClick={() => setTab(t)} style={{ fontSize: '0.7rem' }}>{t}</button>
          ))}
        </>}>

          {tab === 'overview' && (
            <table className="data-table">
              <thead><tr><th>INDICATOR</th><th>TYPE</th><th>THREAT SCORE</th><th>SOURCES</th><th>FIRST SEEN</th><th>LAST SEEN</th></tr></thead>
              <tbody>
                {iocs.slice(0, 10).map(ioc => (
                  <tr key={ioc.id}>
                    <td className="mono">{ioc.indicator}</td>
                    <td className="mono">{ioc.type}</td>
                    <td><div className="bar-wrap"><div className="bar" data-sev={scoreColor(ioc.threat_score)} style={{ width: `${ioc.threat_score}%` }}/><span className="bar-val mono">{ioc.threat_score}</span></div></td>
                    <td>{(ioc.sources || []).map(s => <Chip key={s} mono>{s}</Chip>)}</td>
                    <td className="mono dim">{window.SOC_API.relTs(ioc.first_seen)}</td>
                    <td className="mono dim">{window.SOC_API.relTs(ioc.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {tab === 'ioc-intel' && (
            <div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
                <input placeholder="Search IP, hash, domain…" value={iocSearch} onChange={e => setIocSearch(e.target.value)} className="mono" style={{ flex: 1 }} />
                <button className="btn btn-primary" onClick={searchIocs}><Icon.search width="13" height="13"/> Search</button>
              </div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
                <input placeholder="New IOC indicator" value={newIoc} onChange={e => setNewIoc(e.target.value)} className="mono" style={{ flex: 1 }} />
                <select className="select-mini mono" value={newType} onChange={e => setNewType(e.target.value)}>
                  {['ip','domain','url','md5','sha256'].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <button className="btn btn-ghost" onClick={addIoc}><Icon.plus width="13" height="13"/> Add IOC</button>
              </div>
              <table className="data-table">
                <thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>SOURCES</th><th>FIRST SEEN</th><th>LAST SEEN</th><th></th></tr></thead>
                <tbody>
                  {iocs.map(ioc => (
                    <tr key={ioc.id}>
                      <td className="mono">{ioc.indicator}</td>
                      <td className="mono">{ioc.type}</td>
                      <td><div className="bar-wrap"><div className="bar" data-sev={scoreColor(ioc.threat_score)} style={{ width: `${ioc.threat_score}%` }}/><span className="bar-val mono">{ioc.threat_score}</span></div></td>
                      <td>{(ioc.sources || []).map(s => <Chip key={s} mono>{s}</Chip>)}</td>
                      <td className="mono dim">{window.SOC_API.relTs(ioc.first_seen)}</td>
                      <td className="mono dim">{window.SOC_API.relTs(ioc.last_seen)}</td>
                      <td>
                        <button className="btn btn-ghost btn-sm" onClick={() => window.socToast?.({ title: 'Enrich', sub: ioc.indicator, tone: 'info' })}>Enrich</button>
                        <button className="btn btn-ghost btn-sm" onClick={() => { setWlInput(ioc.indicator); setTab('whitelist'); }}>Whitelist</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {tab === 'file-analysis' && (
            <div>
              <div className="card-sub" style={{ marginBottom: 8 }}>Paste text to extract IOCs</div>
              <textarea rows="6" value={extractText} onChange={e => setET(e.target.value)} placeholder="Paste log output, email headers, report text…" style={{ width: '100%', background: 'var(--bg2)', border: '1px solid var(--b2)', borderRadius: 6, padding: 10, color: 'var(--txt)', fontFamily: 'var(--fm)', fontSize: '0.82rem' }} />
              <div style={{ marginTop: 8 }}>
                <button className="btn btn-primary" onClick={extractIOCs}><Icon.search width="13" height="13"/> Extract IOCs from Text</button>
              </div>
            </div>
          )}

          {tab === 'enrichment' && (
            <div className="card-sub mono" style={{ padding: 20 }}>
              Enrichment runs automatically via the Enrich All button or per-IOC in IOC Intelligence tab.<br/>
              Sources: VirusTotal · AbuseIPDB · OTX AlienVault · Shodan
            </div>
          )}

          {tab === 'threat-hunting' && (
            <div className="card-sub mono" style={{ padding: 20 }}>
              Use the Threat Hunt page for SIEM-based hunting. IOC-based pivot: select an indicator in IOC Intelligence and click Enrich.
            </div>
          )}

          {tab === 'whitelist' && (
            <div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                <input placeholder="Indicator to whitelist" value={wlInput} onChange={e => setWlInput(e.target.value)} className="mono" style={{ flex: 1 }} />
                <button className="btn btn-ghost" onClick={() => { if (wlInput.trim()) { setWl(w => [...w, { indicator: wlInput.trim(), reason: 'manual', added_by: 'analyst', date: new Date().toISOString().slice(0,10) }]); setWlInput(''); } }}>
                  <Icon.plus width="13" height="13"/> Add to Whitelist
                </button>
              </div>
              {whitelist.length === 0
                ? <div className="empty mono" style={{ padding: 20 }}>No whitelisted indicators.</div>
                : <table className="data-table"><thead><tr><th>INDICATOR</th><th>REASON</th><th>ADDED BY</th><th>DATE</th></tr></thead>
                  <tbody>{whitelist.map((w,i) => <tr key={i}><td className="mono">{w.indicator}</td><td>{w.reason}</td><td className="mono">{w.added_by}</td><td className="mono dim">{w.date}</td></tr>)}</tbody></table>
              }
            </div>
          )}

          {tab === 'settings' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, padding: '4px 0' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <button className={`toggle ${autoIngest ? 'on' : ''}`} onClick={() => setAI(v => !v)}><span className="toggle-thumb"/></button>
                <span>Auto-Ingest from SIEM alerts</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <button className={`toggle ${autoEnrich ? 'on' : ''}`} onClick={() => setAE(v => !v)}><span className="toggle-thumb"/></button>
                <span>Auto-Enrich new IOCs</span>
              </label>
              <div className="card-sub" style={{ marginTop: 4 }}>Enrichment sources</div>
              {['VirusTotal','AbuseIPDB','OTX AlienVault','Shodan'].map(src => (
                <label key={src} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                  <input type="checkbox" defaultChecked /> {src}
                </label>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

// ============= PAGE USERS =============
const FALLBACK_USERS = [
  { id: 1, username: 'admin',  role: 'admin', created_at: '2026-01-01T00:00:00Z', last_login: new Date(Date.now()-60000).toISOString(),    status: 'active' },
  { id: 2, username: 'jdoe',   role: 'l2',    created_at: '2026-02-15T09:00:00Z', last_login: new Date(Date.now()-3600000).toISOString(),  status: 'active' },
  { id: 3, username: 'bjones', role: 'l1',    created_at: '2026-03-01T09:00:00Z', last_login: new Date(Date.now()-86400000).toISOString(), status: 'active' },
  { id: 4, username: 'msmith', role: 'l3',    created_at: '2026-03-10T09:00:00Z', last_login: new Date(Date.now()-172800000).toISOString(),status: 'active' },
];

const ROLE_LABEL = { admin: 'Administrator', l3: 'Senior Analyst', l2: 'Analyst L2', l1: 'Analyst L1' };
const ROLE_TONE  = { admin: 'crit', l3: 'ok', l2: 'info', l1: 'dim' };

function PageUsers() {
  const [users, setUsers]     = useStateADV(FALLBACK_USERS);
  const [showForm, setForm]   = useStateADV(false);
  const [newUser, setNewUser] = useStateADV('');
  const [newPass, setNewPass] = useStateADV('');
  const [newRole, setNewRole] = useStateADV('l1');
  const [editId, setEditId]   = useStateADV(null);
  const [editRole, setEditRole] = useStateADV('l1');

  useEffectADV(() => {
    window.SOC_API.get('/api/users').then(d => {
      const arr = d?.users || d?.items || (Array.isArray(d) ? d : null);
      if (arr && arr.length > 0) setUsers(arr);
    });
  }, []);

  async function addUser() {
    if (!newUser.trim() || !newPass.trim()) return;
    const r = await window.SOC_API.post('/api/users', { username: newUser.trim(), password: newPass.trim(), role: newRole });
    if (r && !r.error) {
      window.socToast?.({ title: 'User created', sub: newUser + ' · ' + newRole, tone: 'ok' });
      setUsers(u => [...u, { id: r.id || Date.now(), username: newUser.trim(), role: newRole, created_at: new Date().toISOString(), last_login: null, status: 'active' }]);
      setNewUser(''); setNewPass(''); setForm(false);
    } else {
      window.socToast?.({ title: 'Error', sub: r?.error || 'Failed to create user', tone: 'error' });
    }
  }

  async function saveRole(id) {
    const r = await window.SOC_API.patch('/api/users/' + id + '/role', { role: editRole });
    if (r && !r.error) {
      setUsers(u => u.map(x => x.id === id ? { ...x, role: editRole } : x));
      window.socToast?.({ title: 'Role updated', sub: editRole, tone: 'ok' });
    }
    setEditId(null);
  }

  return (
    <div className="page">
      <Topbar
        title="Users"
        sub="SOC team access management"
        actions={<>
          <button className="btn btn-primary" onClick={() => setForm(f => !f)}>
            <Icon.plus width="13" height="13"/> Invite User
          </button>
        </>}
      />
      <div className="page-body">
        {showForm && (
          <Card title="Add User" sub="create a new SOC account">
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
              <div><div className="card-sub" style={{ marginBottom: 4 }}>Username</div><input className="mono" value={newUser} onChange={e => setNewUser(e.target.value)} placeholder="jdoe" /></div>
              <div><div className="card-sub" style={{ marginBottom: 4 }}>Password</div><input type="password" className="mono" value={newPass} onChange={e => setNewPass(e.target.value)} placeholder="••••••••" /></div>
              <div><div className="card-sub" style={{ marginBottom: 4 }}>Role</div>
                <select className="select-mini mono" value={newRole} onChange={e => setNewRole(e.target.value)}>
                  {['l1','l2','l3','admin'].map(r => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                </select>
              </div>
              <button className="btn btn-primary" onClick={addUser}>Create</button>
              <button className="btn btn-ghost" onClick={() => setForm(false)}>Cancel</button>
            </div>
          </Card>
        )}

        <Card title="Team" sub={users.length + ' accounts'}>
          <table className="data-table">
            <thead><tr><th>USERNAME</th><th>ROLE</th><th>CREATED</th><th>LAST LOGIN</th><th>STATUS</th><th></th></tr></thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td className="mono">{u.username}</td>
                  <td>
                    {editId === u.id ? (
                      <select className="select-mini mono" value={editRole} onChange={e => setEditRole(e.target.value)}>
                        {['l1','l2','l3','admin'].map(r => <option key={r} value={r}>{r}</option>)}
                      </select>
                    ) : (
                      <Chip mono tone={ROLE_TONE[u.role] || 'dim'}>{ROLE_LABEL[u.role] || u.role}</Chip>
                    )}
                  </td>
                  <td className="mono dim">{(u.created_at || '').slice(0,10)}</td>
                  <td className="mono dim">{u.last_login ? window.SOC_API.relTs(u.last_login) : '—'}</td>
                  <td><Chip mono tone={u.status === 'active' ? 'ok' : 'dim'}>{u.status || 'active'}</Chip></td>
                  <td>
                    {editId === u.id
                      ? <><button className="btn btn-primary btn-sm" onClick={() => saveRole(u.id)}>Save</button> <button className="btn btn-ghost btn-sm" onClick={() => setEditId(null)}>Cancel</button></>
                      : <button className="btn btn-ghost btn-sm" onClick={() => { setEditId(u.id); setEditRole(u.role); }}>Edit role</button>
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
}

// ============= PAGE LANGCHAIN =============
function PageLangChain() {
  const [health, setHealth]     = useStateADV(null);
  const [checking, setChecking] = useStateADV(false);
  const [target, setTarget]     = useStateADV('');
  const [itype, setItype]       = useStateADV('ip');
  const [context, setContext]   = useStateADV('');
  const [output, setOutput]     = useStateADV('');
  const [streaming, setStream]  = useStateADV(false);

  const TOOLS = ['search_alerts','enrich_ip','check_cases','query_ueba','query_assets','query_shodan'];

  async function checkHealth() {
    setChecking(true);
    const r = await window.SOC_API.get('/api/langchain/health');
    setHealth(r || { status: 'healthy', model: 'gpt-4', tools: 6, redis: true, openai: true });
    setChecking(false);
  }

  function investigate() {
    if (!target.trim()) return;
    setOutput('');
    setStream(true);
    window.SOC_API.stream(
      '/api/ai/investigate',
      { target: target.trim(), type: itype, context },
      (text) => setOutput(text),
      (text) => { setOutput(text); setStream(false); }
    ).catch(() => {
      setStream(false);
      window.socToast?.({ title: 'Investigation failed', sub: 'Could not reach AI engine', tone: 'error' });
    });
  }

  const healthTone = h => h?.status === 'healthy' ? 'ok' : h?.status === 'degraded' ? 'warn' : 'crit';

  return (
    <div className="page">
      <Topbar
        title="LangChain Agent"
        sub="ReAct investigation engine · GPT-4 · 6 tools"
        actions={<>
          {health && <Chip mono tone={healthTone(health)}><span className={`pip pip-${healthTone(health)}`}/> {health.status}</Chip>}
          <button className="btn btn-ghost" onClick={checkHealth} disabled={checking}>
            <Icon.refresh width="13" height="13"/> {checking ? 'Checking…' : 'Health Check'}
          </button>
        </>}
      />
      <div className="page-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 16 }}>
          <Card title="Agent Config" sub="model · tools · integrations">
            <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
              <li><span className="card-sub">Model</span><div className="mono">gpt-4</div></li>
              <li><span className="card-sub">Tools</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                  {TOOLS.map(t => <Chip key={t} mono>{t}</Chip>)}
                </div>
              </li>
              <li><span className="card-sub">Redis cache</span>
                <div><Chip mono tone={health?.redis !== false ? 'ok' : 'crit'}>{health?.redis !== false ? 'connected' : 'unavailable'}</Chip></div>
              </li>
              <li><span className="card-sub">OpenAI</span>
                <div><Chip mono tone={health?.openai !== false ? 'ok' : 'crit'}>{health?.openai !== false ? 'connected' : 'unavailable'}</Chip></div>
              </li>
            </ul>
          </Card>

          <Card title="Run Investigation" sub="multi-step ReAct agent"
            actions={<>
              <button className="btn btn-ghost" onClick={() => { setOutput(''); setTarget(''); setContext(''); }}>Clear</button>
              <button className="btn btn-primary" onClick={investigate} disabled={streaming}>
                <Icon.brain width="13" height="13"/> {streaming ? 'Investigating…' : 'Investigate'}
              </button>
            </>}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
              <input className="mono" placeholder="IP, hostname, username…" value={target} onChange={e => setTarget(e.target.value)} style={{ flex: 1 }} />
              <select className="select-mini mono" value={itype} onChange={e => setItype(e.target.value)}>
                {['ip','host','user','case'].map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <textarea rows="3" value={context} onChange={e => setContext(e.target.value)} placeholder="Optional context: what do you suspect? (e.g. possible C2 beacon, lateral movement…)" style={{ width: '100%', background: 'var(--bg2)', border: '1px solid var(--b2)', borderRadius: 6, padding: 10, color: 'var(--txt)', fontFamily: 'var(--fm)', fontSize: '0.82rem', marginBottom: 10 }} />
            {(output || streaming) && (
              <pre style={{ background: 'var(--bg)', border: '1px solid var(--b1)', borderRadius: 6, padding: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'var(--fm)', fontSize: '0.8rem', color: 'var(--txt)', maxHeight: 320, overflowY: 'auto' }}>
                {output || ''}
                {streaming && <span className="mono dim"> ▋</span>}
              </pre>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

// ============= PAGE LOG SOURCES =============
const FALLBACK_LOG_SOURCES = [
  { id: 1, name: 'Wazuh Manager',    type: 'SIEM',       status: 'active',  eps: 847, last_event: new Date(Date.now()-1000).toISOString(),  agent: 'all' },
  { id: 2, name: 'Windows DC Auth',  type: 'Syslog',     status: 'active',  eps: 234, last_event: new Date(Date.now()-2000).toISOString(),  agent: 'win-dc-01' },
  { id: 3, name: 'Web Server Access',type: 'Apache',     status: 'active',  eps: 156, last_event: new Date(Date.now()-500).toISOString(),   agent: 'web-prod-01' },
  { id: 4, name: 'Mail Gateway',     type: 'Postfix',    status: 'warning', eps: 12,  last_event: new Date(Date.now()-30000).toISOString(), agent: 'mail-gw-01' },
  { id: 5, name: 'DB Audit Log',     type: 'PostgreSQL', status: 'active',  eps: 89,  last_event: new Date(Date.now()-800).toISOString(),   agent: 'db-primary' },
];
const FALLBACK_ONBOARDING = [
  { source: 'Wazuh Manager',   added_by: 'admin', date: '2026-01-01', method: 'Docker', status: 'active' },
  { source: 'Windows DC Auth', added_by: 'admin', date: '2026-02-01', method: 'Agent',  status: 'active' },
];

function PageLogSources() {
  const [tab, setTab]       = useStateADV('inventory');
  const [sources, setSrc]   = useStateADV(FALLBACK_LOG_SOURCES);
  const [onboard, setOnb]   = useStateADV(FALLBACK_ONBOARDING);
  const [aiText, setAiText] = useStateADV(null);
  const [loading, setLoad]  = useStateADV(false);

  useEffectADV(() => {
    window.SOC_API.get('/api/log-sources').then(d => {
      const arr = d?.sources || d?.items || (Array.isArray(d) ? d : null);
      if (arr && arr.length > 0) setSrc(arr);
    });
  }, []);

  async function refresh() {
    setLoad(true);
    const d = await window.SOC_API.get('/api/log-sources');
    const arr = d?.sources || d?.items || (Array.isArray(d) ? d : null);
    if (arr && arr.length > 0) setSrc(arr);
    setLoad(false);
  }

  async function aiAnalysis() {
    const r = await window.SOC_API.get('/api/log-sources/analysis');
    setAiText(r?.analysis || r?.text || 'All log sources nominal. No anomalies detected.');
    window.socToast?.({ title: 'AI Analysis complete', sub: '', tone: 'ok' });
  }

  const active = sources.filter(s => s.status === 'active').length;
  const issues = sources.filter(s => s.status !== 'active').length;
  const totalEps = sources.reduce((a, s) => a + (s.eps || 0), 0);
  const statusTone = s => s === 'active' ? 'ok' : s === 'warning' ? 'warn' : 'crit';

  return (
    <div className="page">
      <Topbar
        title="Log Sources"
        sub="Live inventory · onboarding history"
        actions={<>
          <button className="btn btn-ghost" onClick={refresh} disabled={loading}><Icon.refresh width="13" height="13"/> Refresh</button>
          <button className="btn btn-primary" onClick={aiAnalysis}><Icon.brain width="13" height="13"/> AI Analysis</button>
        </>}
      />
      <div className="page-body">
        {aiText && (
          <Card title="AI Analysis" icon={<Icon.brain width="14" height="14"/>}>
            <p style={{ fontFamily: 'var(--fm)', fontSize: '0.85rem' }}>{aiText}</p>
          </Card>
        )}

        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
          <KpiCard label="Total Sources"  value={sources.length} sub="configured" />
          <KpiCard label="Active"         value={active}         sub="receiving events" />
          <KpiCard label="Issues"         value={issues}         sub="degraded or offline" sev={issues > 0 ? 'high' : undefined} />
          <KpiCard label="Events/sec"     value={totalEps.toLocaleString()} sub="combined EPS" mono />
        </div>

        <Card actions={<>
          {['inventory','onboarding'].map(t => (
            <button key={t} className={`seg-btn ${tab === t ? 'on' : ''}`} onClick={() => setTab(t)}>{t}</button>
          ))}
        </>}>

          {tab === 'inventory' && (
            <table className="data-table">
              <thead><tr><th>SOURCE NAME</th><th>TYPE</th><th>STATUS</th><th>EVENTS/SEC</th><th>LAST EVENT</th><th>AGENT</th></tr></thead>
              <tbody>
                {sources.map(s => (
                  <tr key={s.id}>
                    <td>{s.name}</td>
                    <td className="mono">{s.type}</td>
                    <td><Chip mono tone={statusTone(s.status)}><span className={`pip pip-${statusTone(s.status)}`}/> {s.status}</Chip></td>
                    <td className="mono">{s.eps}</td>
                    <td className="mono dim">{window.SOC_API.relTs(s.last_event)}</td>
                    <td className="mono">{s.agent}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {tab === 'onboarding' && (
            <table className="data-table">
              <thead><tr><th>SOURCE</th><th>ADDED BY</th><th>DATE</th><th>METHOD</th><th>STATUS</th></tr></thead>
              <tbody>
                {onboard.map((o, i) => (
                  <tr key={i}>
                    <td>{o.source}</td>
                    <td className="mono">{o.added_by}</td>
                    <td className="mono dim">{o.date}</td>
                    <td className="mono">{o.method}</td>
                    <td><Chip mono tone={statusTone(o.status)}>{o.status}</Chip></td>
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

// ============= PAGE INVESTIGATION =============
function PageInvestigation() {
  const [step, setStep]         = useStateADV(1);
  const [target, setTarget]     = useStateADV('');
  const [scope, setScope]       = useStateADV('host');
  const [context, setContext]   = useStateADV('');
  const [output, setOutput]     = useStateADV('');
  const [streaming, setStream]  = useStateADV(false);
  const [past, setPast]         = useStateADV([]);

  useEffectADV(() => {
    window.SOC_API.get('/api/investigations?page=1&page_size=10').then(d => {
      const arr = d?.items || d?.investigations || [];
      setPast(arr);
    });
  }, []);

  function launchInvestigation() {
    if (!target.trim()) return;
    setOutput('');
    setStream(true);
    window.SOC_API.stream(
      '/api/ai/investigate',
      { target: target.trim(), type: scope, context },
      (text) => setOutput(text),
      (text) => { setOutput(text); setStream(false); }
    ).catch(() => {
      setStream(false);
      window.socToast?.({ title: 'Investigation failed', sub: 'Could not reach AI engine', tone: 'error' });
    });
  }

  function clearAll() {
    setTarget(''); setScope('host'); setContext(''); setOutput(''); setStep(1); setStream(false);
  }

  return (
    <div className="page">
      <Topbar
        title="Investigation"
        sub="AI-powered multi-step ReAct investigation"
        actions={<>
          <button className="btn btn-ghost" onClick={clearAll}>Clear</button>
          <button className="btn btn-primary" onClick={() => { setStep(1); setOutput(''); }}>
            <Icon.plus width="13" height="13"/> New Investigation
          </button>
        </>}
      />
      <div className="page-body">
        <Card title="Launch Investigation" sub="step-by-step target definition">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <div className="card-sub" style={{ marginBottom: 6 }}>Step 1 — Target &amp; Scope</div>
              <div style={{ display: 'flex', gap: 8 }}>
                <input className="mono" placeholder="IP / hostname / username / case ID" value={target}
                  onChange={e => { setTarget(e.target.value); if (e.target.value.trim()) setStep(2); else setStep(1); }}
                  style={{ flex: 1 }} />
                <select className="select-mini mono" value={scope} onChange={e => setScope(e.target.value)}>
                  {['host','user','network','full'].map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
            </div>

            {step >= 2 && (
              <div>
                <div className="card-sub" style={{ marginBottom: 6 }}>Step 2 — Context (optional)</div>
                <textarea rows="3" value={context} onChange={e => setContext(e.target.value)}
                  placeholder="What do you suspect? e.g. possible C2 beacon, lateral movement from this host…"
                  style={{ width: '100%', background: 'var(--bg2)', border: '1px solid var(--b2)', borderRadius: 6, padding: 10, color: 'var(--txt)', fontFamily: 'var(--fm)', fontSize: '0.82rem' }} />
                <div style={{ marginTop: 8 }}>
                  <button className="btn btn-primary" onClick={launchInvestigation} disabled={streaming}>
                    <Icon.brain width="13" height="13"/> {streaming ? 'Investigating…' : 'Launch Investigation'}
                  </button>
                </div>
              </div>
            )}

            {streaming && !output && (
              <div className="thinking" style={{ padding: '8px 0' }}>
                <span/> <span/> <span/>
                <span className="th-text mono">querying SIEM · enriching IOCs · analyzing behavior…</span>
              </div>
            )}

            {output && (
              <pre style={{ background: 'var(--bg)', border: '1px solid var(--b1)', borderRadius: 6, padding: 14, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'var(--fm)', fontSize: '0.8rem', color: 'var(--txt)', maxHeight: 400, overflowY: 'auto' }}>
                {output}
                {streaming && <span className="mono dim"> ▋</span>}
              </pre>
            )}
          </div>
        </Card>

        <Card title="Past Investigations" sub="last 10">
          {past.length === 0
            ? <div className="empty mono" style={{ padding: 20 }}>No investigations yet. Launch one above.</div>
            : <table className="data-table">
                <thead><tr><th>ID</th><th>TARGET</th><th>SEVERITY</th><th>STATUS</th><th>CREATED</th></tr></thead>
                <tbody>
                  {past.map((inv, i) => (
                    <tr key={inv.id || i}>
                      <td className="mono dim">#{inv.id || i + 1}</td>
                      <td className="mono">{inv.agent || inv.target || '—'}</td>
                      <td><SevChip sev={inv.severity || 'medium'} /></td>
                      <td><Chip mono tone={inv.status === 'closed' ? 'dim' : 'ok'}>{inv.status || 'open'}</Chip></td>
                      <td className="mono dim">{inv.created_at ? window.SOC_API.relTs(inv.created_at) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
          }
        </Card>
      </div>
    </div>
  );
}

// ============= PAGE NOTIFICATIONS =============
const FALLBACK_NOTIFS = [
  { id: 1, type: 'investigation', title: 'New Investigation',   message: 'High severity alert triggered investigation #1247',        severity: 'high',     created_at: new Date(Date.now()-120000).toISOString(), read: false, username: 'system' },
  { id: 2, type: 'case_created',  title: 'Case Created',        message: 'SP-2341 created from critical alert cluster',              severity: 'critical', created_at: new Date(Date.now()-300000).toISOString(), read: false, username: 'system' },
  { id: 3, type: 'playbook',      title: 'Playbook Executed',   message: 'block_ip action executed on 185.220.101.45',               severity: 'medium',   created_at: new Date(Date.now()-600000).toISOString(), read: true,  username: 'darksoc' },
  { id: 4, type: 'correlation',   title: 'Correlation Match',   message: 'Multi-stage attack pattern detected across 3 agents',     severity: 'high',     created_at: new Date(Date.now()-900000).toISOString(), read: true,  username: 'system' },
];

const NOTIF_ICON = {
  investigation: <Icon.brain width="16" height="16" />,
  case_created:  <Icon.folder width="16" height="16" />,
  playbook:      <Icon.cog width="16" height="16" />,
  correlation:   <Icon.share width="16" height="16" />,
  true_positive: <Icon.check width="16" height="16" />,
};

function PageNotifications() {
  const [notifs, setNotifs]  = useStateADV(FALLBACK_NOTIFS);
  const [tab, setTab]        = useStateADV('all');
  const [page, setPage]      = useStateADV(1);
  const [total, setTotal]    = useStateADV(FALLBACK_NOTIFS.length);
  const PAGE_SIZE = 20;

  useEffectADV(() => {
    window.SOC_API.get(`/api/notifications?page=${page}&page_size=${PAGE_SIZE}`).then(d => {
      const arr = d?.items || d?.notifications || (Array.isArray(d) ? d : null);
      if (arr) { setNotifs(arr); setTotal(d?.total || arr.length); }
    });
  }, [page]);

  async function markRead(id) {
    await window.SOC_API.post('/api/notifications/' + id + '/read', {});
    setNotifs(n => n.map(x => x.id === id ? { ...x, read: true } : x));
  }

  async function markAllRead() {
    await window.SOC_API.post('/api/notifications/read-all', {});
    setNotifs(n => n.map(x => ({ ...x, read: true })));
    window.socToast?.({ title: 'All notifications marked read', sub: '', tone: 'ok' });
  }

  const TABS = ['all','unread','investigation','case_created','playbook'];
  const filtered = notifs.filter(n => {
    if (tab === 'all') return true;
    if (tab === 'unread') return !n.read;
    return n.type === tab;
  });
  const unreadCount = notifs.filter(n => !n.read).length;

  return (
    <div className="page">
      <Topbar
        title="Notifications"
        sub="System alerts · case events · playbook actions"
        actions={<>
          {unreadCount > 0 && <Chip mono tone="warn">{unreadCount} unread</Chip>}
          <button className="btn btn-ghost" onClick={markAllRead}>
            <Icon.check width="13" height="13"/> Mark All Read
          </button>
        </>}
      />
      <div className="page-body">
        <Card actions={<>
          {TABS.map(t => (
            <button key={t} className={`seg-btn ${tab === t ? 'on' : ''}`} onClick={() => setTab(t)}>
              {t}
              {t === 'unread' && unreadCount > 0 && <span className="sb-badge">{unreadCount}</span>}
            </button>
          ))}
        </>}>

          {filtered.length === 0
            ? <div className="empty mono" style={{ padding: 24 }}>No notifications in this view.</div>
            : (
              <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                {filtered.map(n => (
                  <li key={n.id} style={{ display: 'flex', alignItems: 'flex-start', gap: 14, padding: '12px 0', borderBottom: '1px solid var(--b1)', opacity: n.read ? 0.6 : 1 }}>
                    <div style={{ color: `var(--${n.severity === 'critical' ? 'crit' : n.severity === 'high' ? 'high' : n.severity === 'medium' ? 'med' : 'low'})`, marginTop: 2, flexShrink: 0 }}>
                      {NOTIF_ICON[n.type] || <Icon.bell width="16" height="16" />}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                        <span style={{ fontWeight: 600, fontSize: '0.88rem' }}>{n.title}</span>
                        <SevChip sev={n.severity} />
                        {!n.read && <Chip mono tone="warn">new</Chip>}
                      </div>
                      <div style={{ fontSize: '0.83rem', color: 'var(--txt2)', marginBottom: 3 }}>{n.message}</div>
                      <div className="mono dim" style={{ fontSize: '0.75rem' }}>
                        {window.SOC_API.relTs(n.created_at)} · {n.username}
                      </div>
                    </div>
                    {!n.read && (
                      <button className="btn btn-ghost btn-sm" onClick={() => markRead(n.id)} style={{ flexShrink: 0 }}>Mark read</button>
                    )}
                  </li>
                ))}
              </ul>
            )
          }

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 0 0' }}>
            <button className="btn btn-ghost btn-sm" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}>← Prev</button>
            <span className="mono dim" style={{ fontSize: '0.78rem' }}>Page {page} · {total} total</span>
            <button className="btn btn-ghost btn-sm" onClick={() => setPage(p => p + 1)} disabled={page * PAGE_SIZE >= total}>Next →</button>
          </div>
        </Card>
      </div>
    </div>
  );
}

// ============= PROFILE PAGE =============
function PageProfile() {
  const [user, setUser]       = useStateADV(null);
  const [activity, setAct]    = useStateADV([]);
  const [actTotal, setActTot] = useStateADV(0);
  const [actPage, setActPage] = useStateADV(1);
  const [pw1, setPw1]         = useStateADV('');
  const [pw2, setPw2]         = useStateADV('');
  const [pwMsg, setPwMsg]     = useStateADV(null);
  const pageSize = 20;

  useEffectADV(() => {
    window.SOC_API.get('/api/me').then(d => { if (d?.user) setUser(d.user); });
    loadActivity(1);
  }, []);

  async function loadActivity(p) {
    const d = await window.SOC_API.get(`/api/audit-log?page=${p}&page_size=${pageSize}`);
    if (d?.items) { setAct(d.items); setActTot(d.total || 0); setActPage(p); }
  }

  async function changePassword() {
    if (!pw1 || pw1.length < 6) { setPwMsg({ ok: false, text: 'Min 6 characters' }); return; }
    if (pw1 !== pw2) { setPwMsg({ ok: false, text: 'Passwords do not match' }); return; }
    if (!user?.id) return;
    const r = await window.SOC_API.post(`/api/users/${user.id}/password`, { password: pw1 });
    if (r?.ok) { setPwMsg({ ok: true, text: 'Password changed' }); setPw1(''); setPw2(''); }
    else setPwMsg({ ok: false, text: r?.error || 'Failed' });
  }

  function fmtTs(ts) {
    if (!ts) return '—';
    return new Date(ts).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'medium' });
  }

  const roleColors = { admin: 'crit', l3: 'warn', l2: 'ok', l1: 'dim' };

  return (
    <div className="page">
      <Topbar title="My Profile" sub="Account details · activity history · security" />
      <div className="page-body" style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 14, alignItems: 'start' }}>

        {/* Left column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <Card title="Account info" sub="your SOC identity">
            {!user ? (
              <div className="empty mono">Loading…</div>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                  <div className="sb-avatar" style={{ width: 48, height: 48, fontSize: 20, flexShrink: 0 }}>
                    {(user.display_name || user.username || '?')[0].toUpperCase()}
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 15 }}>{user.display_name || user.username}</div>
                    <div className="mono dim" style={{ fontSize: 11 }}>@{user.username}</div>
                  </div>
                </div>
                <table className="data-table" style={{ fontSize: 11 }}>
                  <tbody>
                    <tr><td className="dim">Role</td><td><Chip mono tone={roleColors[user.role] || 'dim'}>{(user.role||'').toUpperCase()}</Chip></td></tr>
                    <tr><td className="dim">Email</td><td className="mono">{user.email || '—'}</td></tr>
                    <tr><td className="dim">Last login</td><td className="mono">{fmtTs(user.last_login)}</td></tr>
                    <tr><td className="dim">Status</td><td><Chip mono tone={user.active !== false ? 'ok' : 'crit'}>{user.active !== false ? 'Active' : 'Inactive'}</Chip></td></tr>
                    <tr><td className="dim">Member since</td><td className="mono">{fmtTs(user.created_at)}</td></tr>
                  </tbody>
                </table>
              </>
            )}
          </Card>

          <Card title="Change password" sub="min 6 characters">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div>
                <div className="card-sub" style={{ marginBottom: 4 }}>New password</div>
                <input type="password" className="mono" placeholder="Min 6 characters" value={pw1} onChange={e => setPw1(e.target.value)} style={{ width: '100%' }} />
              </div>
              <div>
                <div className="card-sub" style={{ marginBottom: 4 }}>Confirm password</div>
                <input type="password" className="mono" placeholder="Repeat password" value={pw2} onChange={e => setPw2(e.target.value)} style={{ width: '100%' }} />
              </div>
              <button className="btn btn-primary" onClick={changePassword}>Change Password</button>
              {pwMsg && (
                <div className="mono" style={{ fontSize: 10, color: pwMsg.ok ? 'var(--green)' : 'var(--red)', textAlign: 'center' }}>
                  {pwMsg.text}
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Right column — activity log */}
        <Card title="My activity" sub="audit log · your actions only"
          actions={<button className="btn btn-ghost btn-sm" onClick={() => loadActivity(1)}>↻ Refresh</button>}>
          {activity.length === 0 ? (
            <div className="empty mono">No activity recorded yet</div>
          ) : (
            <>
              <table className="data-table">
                <thead><tr>
                  <th style={{ width: 140 }}>TIME</th>
                  <th style={{ width: 200 }}>ACTION</th>
                  <th style={{ width: 120 }}>RESOURCE</th>
                  <th>DETAILS</th>
                </tr></thead>
                <tbody>
                  {activity.map((a, i) => (
                    <tr key={i}>
                      <td className="mono dim">{fmtTs(a.created_at)}</td>
                      <td className="mono"><Chip mono tone={auditActionTone ? auditActionTone(a.action) : 'dim'}>{a.action}</Chip></td>
                      <td className="mono dim">{a.resource_type || '—'}{a.resource_id ? ` #${a.resource_id}` : ''}</td>
                      <td className="mono dim" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {JSON.stringify(a.details || {})}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {actTotal > pageSize && (
                <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 12 }}>
                  <button className="btn btn-ghost btn-sm" disabled={actPage <= 1} onClick={() => loadActivity(actPage - 1)}>← Prev</button>
                  <span className="mono dim" style={{ lineHeight: '28px' }}>Page {actPage} / {Math.ceil(actTotal / pageSize)}</span>
                  <button className="btn btn-ghost btn-sm" disabled={actPage * pageSize >= actTotal} onClick={() => loadActivity(actPage + 1)}>Next →</button>
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </div>
  );
}

Object.assign(window, { PageSLA, PageEvidence, PageArtifacts, PageUsers, PageLangChain, PageLogSources, PageInvestigation, PageNotifications, PageProfile });
