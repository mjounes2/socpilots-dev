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

// ============= CASES KANBAN =============
function caseAge(ts) {
  if (!ts) return '—';
  const ms = typeof ts === 'number' ? ts : new Date(ts).getTime();
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 3600) return `${Math.round(s/60)}m`;
  if (s < 86400) return `${Math.round(s/3600)}h`;
  return `${Math.round(s/86400)}d`;
}

function caseToCard(c) {
  return {
    id: c.number ? `#${c.number}` : c.id?.slice(0, 8),
    hiveId: c.id,
    title: c.title || '(no title)',
    sev: c.severity || 'low',
    status: c.status,
    tags: (c.tags || []).slice(0, 3),
    assignee: c.assignee || null,
    age: caseAge(c.created),
    mitre: c.mitre || [],
  };
}

function PageCases({ onOpenCase }) {
  const API = window.SOC_API;
  const [lanes, setLanes] = useStateI({ new: [], inProgress: [], truePositive: [], closed: [] });
  const [totals, setTotals] = useStateI({ new: 0, inProgress: 0, truePositive: 0, closed: 0 });
  const [loading, setLoading] = useStateI(true);
  const [selected, setSelected] = useStateI(null);
  const [creating, setCreating] = useStateI(false);
  const [newTitle, setNewTitle] = useStateI('');

  const load = useCallbackI(async () => {
    setLoading(true);
    const [nRes, ipRes, tpRes, fpRes, resolvedRes] = await Promise.all([
      API.get('/api/cases?status=New&page_size=20'),
      API.get('/api/cases?status=InProgress&page_size=20'),
      API.get('/api/cases?status=TruePositive&page_size=20'),
      API.get('/api/cases?status=FalsePositive&page_size=10'),
      API.get('/api/cases?status=Resolved&page_size=10'),
    ]);
    const nCases     = (nRes?.cases        || []).map(caseToCard);
    const ipCases    = (ipRes?.cases       || []).map(caseToCard);
    const tpCases    = (tpRes?.cases       || []).map(caseToCard);
    const closedArr  = [
      ...(fpRes?.cases      || []),
      ...(resolvedRes?.cases || []),
    ].map(caseToCard);

    setLanes({ new: nCases, inProgress: ipCases, truePositive: tpCases, closed: closedArr });
    setTotals({
      new:          nRes?.total  || nCases.length,
      inProgress:   ipRes?.total || ipCases.length,
      truePositive: tpRes?.total || tpCases.length,
      closed:       (fpRes?.total || 0) + (resolvedRes?.total || 0) || closedArr.length,
    });
    if (!selected && nCases.length > 0) setSelected(nCases[0]);
    setLoading(false);
  }, []);

  useEffectI(() => { load(); }, []);

  const createCase = async () => {
    if (!newTitle.trim()) return;
    setCreating(true);
    const res = await API.post('/api/cases/create', { title: newTitle, severity: 'medium' });
    setCreating(false);
    setNewTitle('');
    if (res && !res.error) {
      window.socToast?.({ title: 'Case created', sub: res.caseId || 'New case', tone: 'ok' });
      load();
    } else {
      window.socToast?.({ title: 'Failed', sub: res?.error || 'Unknown error', tone: 'crit' });
    }
  };

  const laneConfig = [
    { key: 'new',          label: 'NEW',           sev: 'critical' },
    { key: 'inProgress',   label: 'IN PROGRESS',   sev: 'high'     },
    { key: 'truePositive', label: 'TRUE POSITIVE',  sev: 'medium'   },
    { key: 'closed',       label: 'CLOSED / FP',   sev: 'low'      },
  ];

  return (
    <div className="page" data-screen-label="04 SP-CM Cases">
      <Topbar
        title="SP-CM Cases"
        sub="Case Management · TheHive"
        actions={<>
          <button className="btn btn-ghost" onClick={load}>
            <Icon.refresh width="13" height="13"/> Refresh
          </button>
          <button className="btn btn-primary" onClick={() => {
            const t = prompt('Case title:');
            if (t) { setNewTitle(t); setTimeout(createCase, 50); }
          }}>
            <Icon.plus width="13" height="13"/> New case
          </button>
        </>}
      />

      <div className="page-body">
        {loading ? (
          <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:300}}>
            <Spinner />
          </div>
        ) : (
          <div className="kanban">
            {laneConfig.map(({ key, label, sev }) => {
              const items = lanes[key] || [];
              const total = totals[key] || items.length;
              return (
                <div key={key} className="lane">
                  <header className="lane-head" data-sev={sev}>
                    <span className="lane-bar" />
                    <span className="lane-label">{label}</span>
                    <span className="lane-count mono">{total}</span>
                  </header>
                  <div className="lane-body">
                    {items.length === 0 ? (
                      <div style={{padding:'12px 8px',fontSize:11,color:'var(--txt-3)',textAlign:'center'}}>
                        No cases
                      </div>
                    ) : items.map(c => (
                      <button
                        key={c.hiveId || c.id}
                        className={`case-card ${selected?.hiveId === c.hiveId ? 'sel' : ''}`}
                        onClick={() => { setSelected(c); if (onOpenCase) onOpenCase(c); }}
                      >
                        <div className="cc-top">
                          <SevDot sev={c.sev} />
                          <span className="cc-id mono">{c.id}</span>
                          <span className="cc-age mono">{c.age}</span>
                        </div>
                        <div className="cc-title">{c.title}</div>
                        {c.tags.length > 0 && (
                          <div className="cc-tags">
                            {c.tags.map(t => <Chip key={t} mono>{t}</Chip>)}
                          </div>
                        )}
                        <div className="cc-foot">
                          <SevChip sev={c.sev} />
                          {c.assignee ? (
                            <span className="cc-assignee">
                              <span className="cc-avatar">{c.assignee[0].toUpperCase()}</span>
                              {c.assignee}
                            </span>
                          ) : (
                            <span className="cc-unassigned">unassigned</span>
                          )}
                        </div>
                      </button>
                    ))}
                    {total > items.length && (
                      <div style={{padding:'6px 8px',fontSize:11,color:'var(--txt-3)',textAlign:'center'}}>
                        +{total - items.length} more
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
        {selected && (
          <div style={{
            marginTop:12, padding:'12px 16px', background:'var(--bg-2)',
            border:'1px solid var(--ln)', borderRadius:6, fontSize:12
          }}>
            <div style={{display:'flex',gap:12,alignItems:'center',marginBottom:8}}>
              <SevChip sev={selected.sev} />
              <span className="mono dim">{selected.id}</span>
              <span style={{flex:1,fontWeight:500}}>{selected.title}</span>
              <span className="mono dim">{selected.age} ago</span>
            </div>
            {selected.mitre.length > 0 && (
              <div style={{fontSize:11,color:'var(--txt-2)'}}>
                MITRE: <span className="mono">{selected.mitre.join(', ')}</span>
              </div>
            )}
          </div>
        )}
      </div>
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
