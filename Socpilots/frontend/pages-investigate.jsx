// Cases Kanban + Correlation pages (Copilot is in pages-copilot.jsx)
const { useState: useStateI, useEffect: useEffectI, useRef: useRefI, useMemo: useMemoI, useCallback: useCallbackI } = React;

// ============= AI COPILOT stub (overridden by pages-copilot.jsx) =============
function PageCopilot() {
  return (
    <div className="page page-copilot" data-screen-label="03 SOCPilots AI">
      <Topbar title="SOCPilots AI" sub="Loading copilot…" />
      <div className="page-body" style={{display:'flex',alignItems:'center',justifyContent:'center',height:300}}>
        <Spinner />
      </div>
    </div>
  );
}

// ============= CASES INBOX =============
function caseAge(ts) {
  if (!ts) return '—';
  const ms = typeof ts === 'number' ? ts : new Date(ts).getTime();
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 3600)  return `${Math.round(s/60)}m`;
  if (s < 86400) return `${Math.round(s/3600)}h`;
  return `${Math.round(s/86400)}d`;
}

const CASE_TABS = [
  { id: 'all',           label: 'All',            status: '',              statKey: 'total'          },
  { id: 'new',           label: 'New',            status: 'New',           statKey: 'new'            },
  { id: 'inprogress',    label: 'In Progress',    status: 'InProgress',    statKey: 'in_progress'    },
  { id: 'truepositive',  label: 'True Positive',  status: 'TruePositive',  statKey: 'true_positive'  },
  { id: 'falsepositive', label: 'False Positive', status: 'FalsePositive', statKey: 'false_positive' },
  { id: 'duplicate',     label: 'Duplicate',      status: 'Duplicate',     statKey: null             },
  { id: 'resolved',      label: 'Resolved',       status: 'Resolved',      statKey: null             },
  { id: 'archive',       label: 'Archive',        status: '_archive',      statKey: 'closed'         },
];

const CASE_STATUS_COLOR = {
  New:          '#ff3b3b',
  InProgress:   '#ff8c00',
  TruePositive: '#00e676',
  FalsePositive:'#607d8b',
  Duplicate:    '#9e9e9e',
  Resolved:     '#00bcd4',
  Other:        '#757575',
};

function PageCases({ onOpenCase }) {
  const API = window.SOC_API;
  const PAGE_SIZE = 50;

  const [tab,           setTab]           = useStateI('new');
  const [cases,         setCases]         = useStateI([]);
  const [stats,         setStats]         = useStateI(null);
  const [total,         setTotal]         = useStateI(0);
  const [page,          setPage]          = useStateI(1);
  const [loading,       setLoading]       = useStateI(true);
  const [q,             setQ]             = useStateI('');
  const [sevFilter,     setSevFilter]     = useStateI('');
  const [timeRange,     setTimeRange]     = useStateI('all');
  const [showNew,       setShowNew]       = useStateI(false);
  const [newForm,       setNewForm]       = useStateI({ title:'', description:'', severity:'medium', tags:'' });
  const [creating,      setCreating]      = useStateI(false);
  const [deletingStale, setDeletingStale] = useStateI(false);
  const searchTimer = useRefI(null);

  const buildParams = (p, tabId, qVal, sevVal, trVal) => {
    const cfg = CASE_TABS.find(t => t.id === tabId) || CASE_TABS[0];
    let params = `page=${p}&page_size=${PAGE_SIZE}`;
    if (cfg.status && cfg.status !== '_archive') params += `&status=${cfg.status}`;
    if (sevVal)    params += `&severity=${sevVal}`;
    if (qVal?.trim()) params += `&q=${encodeURIComponent(qVal.trim())}`;
    if (trVal && trVal !== 'all') {
      const hours = { '24h':24, '7d':168, '30d':720 }[trVal];
      if (hours) params += `&time_from=${encodeURIComponent(new Date(Date.now()-hours*3600000).toISOString())}`;
    }
    return { params, cfg };
  };

  const loadCases = useCallbackI(async (p, tabId, qVal, sevVal, trVal) => {
    setLoading(true);
    const { params, cfg } = buildParams(p, tabId, qVal, sevVal, trVal);

    if (cfg.status === '_archive') {
      const extra = sevVal ? `&severity=${sevVal}` : '';
      const qExtra = qVal?.trim() ? `&q=${encodeURIComponent(qVal.trim())}` : '';
      const [tp, fp, dup, res] = await Promise.all([
        API.get(`/api/cases?status=TruePositive&page=${p}&page_size=${PAGE_SIZE}${extra}${qExtra}`),
        API.get(`/api/cases?status=FalsePositive&page=${p}&page_size=${PAGE_SIZE}${extra}${qExtra}`),
        API.get(`/api/cases?status=Duplicate&page=${p}&page_size=${PAGE_SIZE}${extra}${qExtra}`),
        API.get(`/api/cases?status=Resolved&page=${p}&page_size=${PAGE_SIZE}${extra}${qExtra}`),
      ]);
      const merged = [
        ...(tp?.cases || []), ...(fp?.cases || []),
        ...(dup?.cases || []), ...(res?.cases || []),
      ].sort((a, b) => new Date(b.created) - new Date(a.created));
      setCases(merged);
      setTotal((tp?.total||0)+(fp?.total||0)+(dup?.total||0)+(res?.total||0));
    } else {
      const data = await API.get(`/api/cases?${params}`);
      setCases(data?.cases || []);
      setTotal(data?.total || 0);
    }
    setLoading(false);
  }, []);

  const loadStats = useCallbackI(async () => {
    const s = await API.get('/api/cases/stats');
    if (s && !s.error) setStats(s);
  }, []);

  useEffectI(() => {
    loadStats();
    loadCases(1, 'new', '', '', 'all');
  }, []);

  const switchTab = (tabId) => {
    setTab(tabId);
    setPage(1);
    loadCases(1, tabId, q, sevFilter, timeRange);
  };

  const onSearchChange = (v) => {
    setQ(v);
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => {
      setPage(1);
      loadCases(1, tab, v, sevFilter, timeRange);
    }, 300);
  };

  const onSevChange = (v) => {
    setSevFilter(v);
    setPage(1);
    loadCases(1, tab, q, v, timeRange);
  };

  const onTimeChange = (v) => {
    setTimeRange(v);
    setPage(1);
    loadCases(1, tab, q, sevFilter, v);
  };

  const goPage = (p) => {
    setPage(p);
    loadCases(p, tab, q, sevFilter, timeRange);
  };

  const createCase = async () => {
    if (!newForm.title.trim()) return;
    setCreating(true);
    const tags = newForm.tags.split(',').map(t => t.trim()).filter(Boolean);
    const res = await API.post('/api/cases/create', {
      title:       newForm.title,
      description: newForm.description,
      severity:    newForm.severity,
      tags:        tags.length ? tags : ['soc-pilots'],
    });
    setCreating(false);
    if (res && !res.error) {
      window.socToast?.({ title: 'Case created', sub: newForm.title, tone: 'ok' });
      setShowNew(false);
      setNewForm({ title:'', description:'', severity:'medium', tags:'' });
      loadStats();
      loadCases(1, tab, q, sevFilter, timeRange);
    } else {
      window.socToast?.({ title: 'Failed', sub: res?.error || 'Error creating case', tone: 'crit' });
    }
  };

  const deleteStale = async () => {
    if (!window.confirm('Delete all open (New / In Progress) cases older than 90 days? This cannot be undone.')) return;
    setDeletingStale(true);
    const res = await API.del('/api/cases/stale');
    setDeletingStale(false);
    if (res && !res.error) {
      const tone = res.errors > 0 ? 'warn' : 'ok';
      window.socToast?.({ title: `Deleted ${res.deleted} stale cases`, sub: res.errors > 0 ? `${res.errors} errors` : 'Done', tone });
      loadStats();
      loadCases(1, tab, q, sevFilter, timeRange);
    } else {
      window.socToast?.({ title: 'Failed', sub: res?.error || 'Error', tone: 'crit' });
    }
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  const KPI_COLS = [
    { label:'Total',        key:'total',          color:'var(--acc)'  },
    { label:'New',          key:'new',             color:'#ff3b3b'     },
    { label:'In Progress',  key:'in_progress',     color:'#ff8c00'     },
    { label:'True Positive',key:'true_positive',   color:'#00e676'     },
    { label:'False Positive',key:'false_positive', color:'#607d8b'     },
    { label:'Critical',     key:'critical',        color:'#ff3b3b'     },
    { label:'High',         key:'high',            color:'#ff8c00'     },
    { label:'Closed',       key:'closed',          color:'var(--fg-2)' },
  ];

  return (
    <div className="page" data-screen-label="04 SP-CM Cases">
      <Topbar
        title="SP-CM Cases"
        sub="Case Management · TheHive"
        actions={<>
          <button className="btn btn-ghost" onClick={() => { loadStats(); loadCases(page, tab, q, sevFilter, timeRange); }}>
            <Icon.refresh width="13" height="13"/> Refresh
          </button>
          <button
            className="btn btn-ghost"
            style={{color:'#ff3b3b'}}
            onClick={deleteStale}
            disabled={deletingStale}
            title="Delete open cases older than 90 days"
          >
            <Icon.trash width="13" height="13"/> {deletingStale ? 'Deleting…' : 'Delete Stale'}
          </button>
          <button className="btn btn-primary" onClick={() => setShowNew(true)}>
            <Icon.plus width="13" height="13"/> New Case
          </button>
        </>}
      />

      <div className="page-body">

        {/* KPI row */}
        {stats && (
          <div style={{display:'grid',gridTemplateColumns:'repeat(8,1fr)',gap:8,marginBottom:16}}>
            {KPI_COLS.map(({ label, key, color }) => (
              <div key={key} style={{background:'var(--bg-2)',border:'1px solid var(--ln)',borderRadius:6,padding:'8px 12px'}}>
                <div style={{fontSize:10,color:'var(--fg-2)',marginBottom:2,whiteSpace:'nowrap'}}>{label}</div>
                <div style={{fontSize:20,fontWeight:700,color,fontFamily:'var(--font-mono)'}}>{(stats[key] ?? 0).toLocaleString()}</div>
              </div>
            ))}
          </div>
        )}

        {/* Status tabs */}
        <div style={{display:'flex',gap:0,borderBottom:'1px solid var(--ln)',marginBottom:12,overflowX:'auto'}}>
          {CASE_TABS.map(t => {
            const count = t.statKey && stats ? stats[t.statKey] : null;
            return (
              <button key={t.id} onClick={() => switchTab(t.id)} style={{
                padding:'8px 14px',fontSize:12,fontWeight:500,border:'none',background:'none',
                cursor:'pointer',whiteSpace:'nowrap',
                color: tab===t.id ? 'var(--acc)' : 'var(--fg-2)',
                borderBottom: tab===t.id ? '2px solid var(--acc)' : '2px solid transparent',
              }}>
                {t.label}
                {count != null && (
                  <span style={{marginLeft:5,fontSize:10,opacity:.65,fontFamily:'var(--font-mono)'}}>
                    {count.toLocaleString()}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Filter bar */}
        <div style={{display:'flex',gap:8,marginBottom:12,alignItems:'center',flexWrap:'wrap'}}>
          <div style={{position:'relative',flex:'1 1 220px',maxWidth:320}}>
            <input
              value={q}
              onChange={e => onSearchChange(e.target.value)}
              placeholder="Search cases…"
              style={{width:'100%',padding:'6px 10px 6px 30px',background:'var(--bg-2)',border:'1px solid var(--ln)',borderRadius:4,color:'var(--fg-0)',fontSize:12,boxSizing:'border-box'}}
            />
            <span style={{position:'absolute',left:9,top:'50%',transform:'translateY(-50%)',opacity:.4,pointerEvents:'none'}}>
              <Icon.search width="12" height="12"/>
            </span>
          </div>
          <select value={sevFilter} onChange={e => onSevChange(e.target.value)}
            style={{padding:'6px 10px',background:'var(--bg-2)',border:'1px solid var(--ln)',borderRadius:4,color:'var(--fg-0)',fontSize:12}}>
            <option value="">All Severities</option>
            <option value="4">Critical</option>
            <option value="3">High</option>
            <option value="2">Medium</option>
            <option value="1">Low</option>
          </select>
          <select value={timeRange} onChange={e => onTimeChange(e.target.value)}
            style={{padding:'6px 10px',background:'var(--bg-2)',border:'1px solid var(--ln)',borderRadius:4,color:'var(--fg-0)',fontSize:12}}>
            <option value="all">All Time</option>
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7d</option>
            <option value="30d">Last 30d</option>
          </select>
          <span style={{marginLeft:'auto',fontSize:11,color:'var(--fg-2)',whiteSpace:'nowrap'}}>
            {total.toLocaleString()} case{total !== 1 ? 's' : ''}
          </span>
        </div>

        {/* Table */}
        {loading ? (
          <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:220}}>
            <Spinner />
          </div>
        ) : cases.length === 0 ? (
          <div style={{padding:'48px 0',textAlign:'center',color:'var(--fg-2)',fontSize:13}}>
            No cases found for this view
          </div>
        ) : (
          <div style={{overflowX:'auto',borderRadius:6,border:'1px solid var(--ln)'}}>
            <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
              <thead>
                <tr style={{background:'var(--bg-2)'}}>
                  {['SEV','#','TITLE','STATUS','ASSIGNEE','TAGS','CREATED','AGE',''].map((h,i) => (
                    <th key={i} style={{
                      padding:'8px 10px',textAlign:'left',fontSize:10,color:'var(--fg-2)',
                      fontWeight:600,whiteSpace:'nowrap',borderBottom:'1px solid var(--ln)'
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cases.map((c, ri) => {
                  const sc = CASE_STATUS_COLOR[c.status] || '#888';
                  return (
                    <tr
                      key={c.id || ri}
                      style={{borderBottom:'1px solid rgba(255,255,255,.04)',cursor:'pointer',transition:'background .1s'}}
                      onClick={() => { if (onOpenCase) onOpenCase(c); }}
                      onMouseEnter={e => e.currentTarget.style.background='rgba(255,255,255,.04)'}
                      onMouseLeave={e => e.currentTarget.style.background=''}
                    >
                      <td style={{padding:'9px 10px'}}>
                        <SevDot sev={c.severity} />
                      </td>
                      <td style={{padding:'9px 10px',fontFamily:'var(--font-mono)',color:'var(--fg-2)',whiteSpace:'nowrap',fontSize:11}}>
                        #{c.number || c.id?.slice(0,8)}
                      </td>
                      <td style={{padding:'9px 10px',maxWidth:300}}>
                        <div style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',fontWeight:500}}>{c.title}</div>
                        {c.mitre?.length > 0 && (
                          <div style={{fontSize:10,color:'var(--fg-3)',marginTop:2,fontFamily:'var(--font-mono)'}}>
                            {c.mitre.slice(0,3).join(' · ')}
                          </div>
                        )}
                      </td>
                      <td style={{padding:'9px 10px',whiteSpace:'nowrap'}}>
                        <span style={{
                          padding:'2px 8px',borderRadius:10,fontSize:10,fontWeight:600,
                          background:`${sc}22`,color:sc,
                        }}>{c.statusLabel || c.status}</span>
                      </td>
                      <td style={{padding:'9px 10px',whiteSpace:'nowrap',maxWidth:120}}>
                        {c.assignee ? (
                          <span style={{display:'inline-flex',alignItems:'center',gap:5,color:'var(--fg-1)'}}>
                            <span style={{
                              width:20,height:20,borderRadius:'50%',background:'var(--acc)',
                              color:'#000',display:'inline-flex',alignItems:'center',justifyContent:'center',
                              fontSize:9,fontWeight:700,flexShrink:0,
                            }}>{(c.assignee[0]||'?').toUpperCase()}</span>
                            <span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',maxWidth:80,fontSize:11}}>{c.assignee}</span>
                          </span>
                        ) : <span style={{color:'var(--fg-3)',fontSize:11}}>—</span>}
                      </td>
                      <td style={{padding:'9px 10px',maxWidth:140}}>
                        <div style={{display:'flex',gap:3,flexWrap:'wrap',alignItems:'center'}}>
                          {(c.tags||[]).slice(0,2).map(t => (
                            <span key={t} style={{
                              padding:'1px 6px',borderRadius:3,fontSize:9,
                              background:'rgba(255,255,255,.07)',color:'var(--fg-2)',
                              fontFamily:'var(--font-mono)',whiteSpace:'nowrap',
                            }}>{t}</span>
                          ))}
                          {(c.tags||[]).length > 2 && (
                            <span style={{fontSize:10,color:'var(--fg-3)'}}>+{c.tags.length-2}</span>
                          )}
                        </div>
                      </td>
                      <td style={{padding:'9px 10px',fontFamily:'var(--font-mono)',fontSize:11,color:'var(--fg-2)',whiteSpace:'nowrap'}}>
                        {c.created ? new Date(c.created).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'}) : '—'}
                      </td>
                      <td style={{padding:'9px 10px',fontFamily:'var(--font-mono)',fontSize:11,whiteSpace:'nowrap',color:
                        c.created && (Date.now()-new Date(c.created).getTime())>90*86400000 && !c.isClosed ? '#ff3b3b' : 'var(--fg-2)'
                      }}>
                        {caseAge(c.created)}
                      </td>
                      <td style={{padding:'9px 10px'}} onClick={e => e.stopPropagation()}>
                        <button className="btn btn-ghost" style={{fontSize:10,padding:'3px 8px',whiteSpace:'nowrap'}}
                          onClick={() => { if (onOpenCase) onOpenCase(c); }}>
                          View
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{display:'flex',gap:6,alignItems:'center',justifyContent:'center',marginTop:14}}>
            <button className="btn btn-ghost" style={{fontSize:11}} disabled={page<=1} onClick={() => goPage(page-1)}>
              ← Prev
            </button>
            <span style={{fontSize:11,color:'var(--fg-2)',fontFamily:'var(--font-mono)'}}>
              {page} / {totalPages}
            </span>
            <button className="btn btn-ghost" style={{fontSize:11}} disabled={page>=totalPages} onClick={() => goPage(page+1)}>
              Next →
            </button>
          </div>
        )}
      </div>

      {/* New Case Modal */}
      {showNew && (
        <div style={{
          position:'fixed',inset:0,background:'rgba(0,0,0,.65)',
          display:'flex',alignItems:'center',justifyContent:'center',zIndex:1000,
        }} onClick={e => { if(e.target===e.currentTarget) setShowNew(false); }}>
          <div style={{
            background:'var(--bg-1)',border:'1px solid var(--ln)',borderRadius:8,
            width:500,maxWidth:'90vw',padding:24,
          }}>
            <h3 style={{margin:'0 0 18px',fontSize:16,fontWeight:600}}>New Case</h3>
            <label style={{display:'block',marginBottom:12}}>
              <div style={{fontSize:11,color:'var(--fg-2)',marginBottom:4}}>Title *</div>
              <input
                value={newForm.title}
                onChange={e => setNewForm(f => ({...f, title:e.target.value}))}
                placeholder="Case title"
                autoFocus
                style={{width:'100%',padding:'8px 10px',background:'var(--bg-2)',border:'1px solid var(--ln)',borderRadius:4,color:'var(--fg-0)',fontSize:13,boxSizing:'border-box'}}
              />
            </label>
            <label style={{display:'block',marginBottom:12}}>
              <div style={{fontSize:11,color:'var(--fg-2)',marginBottom:4}}>Description</div>
              <textarea
                value={newForm.description}
                onChange={e => setNewForm(f => ({...f, description:e.target.value}))}
                rows={3} placeholder="Brief description…"
                style={{width:'100%',padding:'8px 10px',background:'var(--bg-2)',border:'1px solid var(--ln)',borderRadius:4,color:'var(--fg-0)',fontSize:13,resize:'vertical',boxSizing:'border-box'}}
              />
            </label>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:18}}>
              <label>
                <div style={{fontSize:11,color:'var(--fg-2)',marginBottom:4}}>Severity</div>
                <select value={newForm.severity} onChange={e => setNewForm(f => ({...f, severity:e.target.value}))}
                  style={{width:'100%',padding:'8px 10px',background:'var(--bg-2)',border:'1px solid var(--ln)',borderRadius:4,color:'var(--fg-0)',fontSize:13}}>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </label>
              <label>
                <div style={{fontSize:11,color:'var(--fg-2)',marginBottom:4}}>Tags</div>
                <input
                  value={newForm.tags}
                  onChange={e => setNewForm(f => ({...f, tags:e.target.value}))}
                  placeholder="apt, phishing, …"
                  style={{width:'100%',padding:'8px 10px',background:'var(--bg-2)',border:'1px solid var(--ln)',borderRadius:4,color:'var(--fg-0)',fontSize:13,boxSizing:'border-box'}}
                />
              </label>
            </div>
            <div style={{display:'flex',gap:8,justifyContent:'flex-end'}}>
              <button className="btn btn-ghost" onClick={() => setShowNew(false)}>Cancel</button>
              <button className="btn btn-primary" disabled={creating || !newForm.title.trim()} onClick={createCase}>
                {creating ? 'Creating…' : 'Create Case'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ============= CORRELATION / ALERT GROUPS =============
function PageCorrelation() {
  const API = window.SOC_API;
  const [groups, setGroups] = useStateI([]);
  const [total, setTotal] = useStateI(0);
  const [loading, setLoading] = useStateI(true);
  const [page, setPage] = useStateI(1);
  const [selected, setSelected] = useStateI(null);
  const PAGE_SIZE = 20;

  const load = useCallbackI(async (p) => {
    setLoading(true);
    const data = await API.get(`/api/alert-groups?page=${p}&page_size=${PAGE_SIZE}`);
    const rows = data?.groups || [];
    setGroups(rows);
    setTotal(data?.total || rows.length);
    if (!selected && rows.length > 0) setSelected(rows[0]);
    setLoading(false);
  }, []);

  useEffectI(() => { load(1); }, []);

  const totalPages = Math.ceil(total / PAGE_SIZE);
  const sevFor = (count) => count > 100 ? 'critical' : count > 20 ? 'high' : count > 5 ? 'medium' : 'low';

  const timeRange = (g) => {
    const diff = new Date(g.last_seen) - new Date(g.first_seen);
    if (diff < 60000) return `${Math.round(diff/1000)}s window`;
    if (diff < 3600000) return `${Math.round(diff/60000)}m window`;
    return `${Math.round(diff/3600000)}h window`;
  };

  return (
    <div className="page" data-screen-label="05 Correlation">
      <Topbar
        title="Correlation"
        sub="Grouped alert clusters · SIEM"
        actions={<>
          <button className="btn btn-ghost" onClick={() => load(page)}>
            <Icon.refresh width="13" height="13" /> Refresh
          </button>
        </>}
      />
      <div className="page-body">
        {loading ? (
          <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:300}}>
            <Spinner />
          </div>
        ) : groups.length === 0 ? (
          <div style={{padding:48,textAlign:'center',color:'var(--txt-3)'}}>
            <div style={{fontSize:32,marginBottom:12}}>🔗</div>
            <div style={{fontWeight:500,marginBottom:4}}>No correlated alert groups</div>
            <div style={{fontSize:12}}>Alert groups appear when the same rule fires repeatedly from the same source. Check back after SIEM receives more events.</div>
          </div>
        ) : (
          <div className="corr-layout">
            <Card title="Alert groups" sub={`${total.toLocaleString()} clusters · sorted by recency`} padded={false}
              actions={<>
                {page > 1 && <button className="btn btn-ghost" style={{padding:'2px 8px'}} onClick={()=>{const p=page-1;setPage(p);load(p);}}>← Prev</button>}
                {page < totalPages && <button className="btn btn-ghost" style={{padding:'2px 8px'}} onClick={()=>{const p=page+1;setPage(p);load(p);}}>Next →</button>}
                <Chip mono>{page}/{totalPages}</Chip>
              </>}>
              <table className="data-table">
                <thead><tr>
                  <th>SEV</th>
                  <th>RULE ID</th>
                  <th>SOURCE IP</th>
                  <th>AGENT</th>
                  <th style={{width:70}}>COUNT</th>
                  <th>WINDOW</th>
                  <th>LAST SEEN</th>
                </tr></thead>
                <tbody>
                  {groups.map(g => {
                    const sev = sevFor(g.count);
                    return (
                      <tr key={g.id}
                        className={selected?.id === g.id ? 'sel' : ''}
                        onClick={() => setSelected(g)}
                        style={{cursor:'pointer'}}>
                        <td><SevChip sev={sev} /></td>
                        <td className="mono">{g.rule_id || '—'}</td>
                        <td className="mono">{g.src_ip || '—'}</td>
                        <td className="mono">{g.agent || '—'}</td>
                        <td className="mono">{g.count}</td>
                        <td className="dim" style={{fontSize:11}}>{timeRange(g)}</td>
                        <td className="mono dim" style={{fontSize:11}}>
                          {g.last_seen ? new Date(g.last_seen).toISOString().slice(0,16).replace('T',' ') : '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Card>

            {selected && (
              <aside className="corr-side">
                <Card title="Group detail" sub={`ID ${selected.id}`}>
                  <div className="entity">
                    <div style={{display:'flex',gap:8,alignItems:'center',marginBottom:12}}>
                      <SevChip sev={sevFor(selected.count)} />
                      <span className="mono" style={{fontSize:11}}>{selected.count} alerts</span>
                    </div>
                    <ul className="entity-meta">
                      <li><span>rule</span><span className="mono">{selected.rule_id || '—'}</span></li>
                      <li><span>source IP</span><span className="mono">{selected.src_ip || '—'}</span></li>
                      <li><span>agent</span><span className="mono">{selected.agent || '—'}</span></li>
                      <li><span>first seen</span><span className="mono">{selected.first_seen ? new Date(selected.first_seen).toISOString().slice(0,16).replace('T',' ') : '—'}</span></li>
                      <li><span>last seen</span><span className="mono">{selected.last_seen ? new Date(selected.last_seen).toISOString().slice(0,16).replace('T',' ') : '—'}</span></li>
                      <li><span>alert count</span><span className="mono">{selected.count}</span></li>
                      {selected.investigation_count > 0 && (
                        <li><span>investigations</span><span className="mono">{selected.investigation_count}</span></li>
                      )}
                    </ul>
                    <div className="entity-actions" style={{marginTop:12}}>
                      <button className="btn btn-primary btn-sm"
                        onClick={async () => {
                          const res = await window.SOC_API.post('/api/cases/create', {
                            title: `Correlated: rule ${selected.rule_id} from ${selected.src_ip} (${selected.count} alerts)`,
                            severity: sevFor(selected.count),
                            description: `Alert group ${selected.id}: ${selected.count} alerts from ${selected.src_ip || 'unknown'} via rule ${selected.rule_id || 'unknown'} on agent ${selected.agent || 'unknown'}.`,
                          });
                          if (res && !res.error) {
                            window.socToast?.({ title: 'Case created', sub: res.caseId || 'New case', tone: 'ok' });
                          }
                        }}>
                        Create case
                      </button>
                      {selected.src_ip && (
                        <button className="btn btn-ghost btn-sm"
                          onClick={() => {
                            const url = `/api/langchain/enrich?ip=${encodeURIComponent(selected.src_ip)}`;
                            window.SOC_API.get(url).then(d => {
                              window.socToast?.({ title: 'Enrichment complete', sub: `${selected.src_ip} · check console`, tone: 'ok' });
                              console.log('[enrich]', d);
                            });
                          }}>
                          Enrich IP
                        </button>
                      )}
                    </div>
                  </div>
                </Card>
              </aside>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ============= PLACEHOLDER PAGE =============
function PagePlaceholder({ title, sub }) {
  return (
    <div className="page" data-screen-label={title}>
      <Topbar title={title} sub={sub} actions={<button className="btn btn-ghost">Help</button>} />
      <div className="page-body">
        <div className="placeholder">
          <div className="ph-mark"><Icon.cog width="32" height="32"/></div>
          <h2 className="ph-title">{title}</h2>
          <p className="ph-sub">This page is available in the live SOCPilots app.</p>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { PageCopilot, PageCases, PageCorrelation, PagePlaceholder });
