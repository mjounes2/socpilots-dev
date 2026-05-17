// Dark SOC — Autonomous Response Engine (production-parity rewrite)
const { useState: useStateDK, useEffect: useEffectDK, useCallback: useCallbackDK } = React;

// ── helpers ──────────────────────────────────────────────────────
function typeIcon(t) {
  const m = { auth:'🔐', alert:'🔍', case:'📋', playbook:'⚡', hunt:'🎯', scan:'🖥', settings:'⚙️' };
  return m[t] || '•';
}
function statusCls(s) {
  if (s === 'ok' || s === 'executed') return 'ok';
  if (s === 'skip' || s === 'skipped') return 'skip';
  return 'fail';
}
function relTs(ts) {
  if (!ts) return '—';
  return window.SOC_API.relTs ? window.SOC_API.relTs(ts) : new Date(ts).toLocaleString();
}
function fmtTs(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'medium' });
}

// ── main page ─────────────────────────────────────────────────────
function PageDarkSOC() {
  const API    = window.SOC_API;
  const user   = API.user?.();
  const isL2   = ['l2', 'l3', 'admin'].includes(user?.role);
  const isAdmin = user?.role === 'admin';

  // settings toggles
  const [mainOn,    setMainOn]    = useStateDK(false);
  const [huntOn,    setHuntOn]    = useStateDK(false);
  const [latOn,     setLatOn]     = useStateDK(false);
  const [saving,    setSaving]    = useStateDK(false);

  // section data
  const [execStats, setExecStats] = useStateDK(null);
  const [pbCount,   setPbCount]   = useStateDK(0);
  const [activity,  setActivity]  = useStateDK(null);
  const [queue,     setQueue]     = useStateDK(null);
  const [audit,     setAudit]     = useStateDK([]);
  const [auditFilter, setAuditFilter] = useStateDK('');
  const [fpStats,   setFpStats]   = useStateDK(null);
  const [approvals, setApprovals] = useStateDK([]);
  const [draftRules,setDraftRules]= useStateDK(null);
  const [playbooks, setPlaybooks] = useStateDK([]);
  const [suppressions, setSuppressions] = useStateDK(null);
  const [protected_,   setProtected]    = useStateDK([]);
  const [isoApprovals, setIsoApprovals] = useStateDK([]);
  const [expandedDraft, setExpandedDraft] = useStateDK(null);

  // add-suppression form
  const [showAddSupp, setShowAddSupp] = useStateDK(false);
  const [suppRuleId, setSuppRuleId]   = useStateDK('');
  const [suppAgent,  setSuppAgent]    = useStateDK('*');
  const [suppReason, setSuppReason]   = useStateDK('');

  // add-protected form
  const [showAddProt, setShowAddProt] = useStateDK(false);
  const [protHost,  setProtHost]      = useStateDK('');
  const [protTier,  setProtTier]      = useStateDK('protected');
  const [protReason,setProtReason]    = useStateDK('');

  const [loading, setLoading] = useStateDK(true);

  // ── data loaders ────────────────────────────────────────────────
  const loadStatus = useCallbackDK(async () => {
    const d = await API.get('/api/darksoc/status');
    if (d && !d.error) {
      setMainOn(!!d.darksoc_enabled);
      setHuntOn(!!d.hunt_enabled);
      setLatOn(!!d.lateral_monitor_enabled);
      setExecStats(d.execution_stats || null);
      setPbCount(d.active_playbooks || 0);
    }
  }, []);

  const loadAudit = useCallbackDK(async (filter) => {
    const f   = filter ?? auditFilter;
    const url = `/api/system-events?limit=50${f ? '&type=' + encodeURIComponent(f) : ''}`;
    const d   = await API.get(url);
    if (d && !d.error) {
      setAudit(d.events || []);
      if (d.activity_today) setActivity(d.activity_today);
    }
  }, [auditFilter]);

  const loadAll = useCallbackDK(async () => {
    setLoading(true);
    await loadStatus();
    await loadAudit(auditFilter);
    const [qd, fpd, apd, drd, pbd, supd, pad, iad] = await Promise.all([
      API.get('/api/triage-queue/stats'),
      API.get('/api/fp-stats'),
      API.get('/api/action-approvals'),
      API.get('/api/draft-rules?page_size=20'),
      API.get('/api/playbooks'),
      API.get('/api/suppressions'),
      API.get('/api/protected-assets'),
      API.get('/api/isolation-approvals'),
    ]);
    if (qd  && !qd.error)   setQueue(qd);
    if (fpd && !fpd.error)  setFpStats(fpd);
    if (apd && !apd.error)  setApprovals(apd.items || []);
    if (drd && !drd.error)  setDraftRules(drd);
    if (pbd && !pbd.error)  setPlaybooks(pbd.playbooks || pbd || []);
    if (supd && !supd.error) setSuppressions(supd);
    if (pad) {
      const arr = pad.assets || (Array.isArray(pad) ? pad : []);
      setProtected(arr);
    }
    if (iad) {
      const arr = iad.approvals || (Array.isArray(iad) ? iad : []);
      setIsoApprovals(arr);
    }
    setLoading(false);
  }, [auditFilter]);

  useEffectDK(() => { loadAll(); }, []);

  // ── settings save ────────────────────────────────────────────────
  async function saveSettings(next_main, next_hunt, next_lat) {
    setSaving(true);
    const m = next_main ?? mainOn;
    const h = next_hunt ?? huntOn;
    const l = next_lat  ?? latOn;
    const r = await API.post('/api/settings', {
      darksoc_enabled:                 String(m),
      darksoc_hunt_enabled:            String(h),
      darksoc_lateral_monitor_enabled: String(l),
      auto_triage_enabled:             String(m),
    });
    setSaving(false);
    if (r && !r.error) {
      setMainOn(m); setHuntOn(h); setLatOn(l);
      window.socToast?.({ title: 'Settings saved', sub: `Dark SOC: ${m ? 'ON' : 'OFF'}`, tone: m ? 'ok' : 'warn' });
    }
  }

  // ── action approval ──────────────────────────────────────────────
  async function approveAction(id) {
    const r = await API.post(`/api/action-approvals/${id}/approve`, {});
    if (r && !r.error) { window.socToast?.({ title: 'Approved', sub: 'Playbooks executing…', tone: 'ok' }); loadAll(); }
    else window.socToast?.({ title: 'Failed', sub: r?.error || 'Unknown error', tone: 'crit' });
  }
  async function rejectAction(id) {
    const r = await API.post(`/api/action-approvals/${id}/reject`, {});
    if (r && !r.error) { window.socToast?.({ title: 'Rejected', sub: 'Action cancelled', tone: 'warn' }); loadAll(); }
    else window.socToast?.({ title: 'Failed', sub: r?.error || 'Unknown error', tone: 'crit' });
  }

  // ── approval actions for isolation ──────────────────────────────
  async function approveIsolation(id) {
    const r = await API.post(`/api/isolation-approvals/${id}/approve`, {});
    if (r && !r.error) { window.socToast?.({ title: 'Isolation approved', tone: 'ok' }); loadAll(); }
  }
  async function rejectIsolation(id) {
    const r = await API.post(`/api/isolation-approvals/${id}/reject`, {});
    if (r && !r.error) { window.socToast?.({ title: 'Isolation rejected', tone: 'warn' }); loadAll(); }
  }

  // ── draft rule status update ─────────────────────────────────────
  async function setDraftStatus(id, status) {
    const r = await API.put(`/api/draft-rules/${id}/status`, { status });
    if (r && !r.error) { window.socToast?.({ title: `Rule ${status}`, tone: status === 'approved' ? 'ok' : 'warn' }); loadAll(); }
  }

  // ── add suppression ──────────────────────────────────────────────
  async function saveSuppression() {
    if (!suppRuleId.trim()) { alert('Rule ID required'); return; }
    const r = await API.post('/api/suppressions', {
      rule_id:       suppRuleId.trim(),
      agent_pattern: suppAgent.trim() || '*',
      reason:        suppReason.trim(),
    });
    if (r && !r.error) {
      window.socToast?.({ title: 'Suppression added', sub: suppRuleId, tone: 'ok' });
      setShowAddSupp(false); setSuppRuleId(''); setSuppAgent('*'); setSuppReason('');
      loadAll();
    } else {
      window.socToast?.({ title: 'Failed', sub: r?.error, tone: 'crit' });
    }
  }

  async function deleteSuppression(id) {
    if (!confirm('Delete this suppression rule?')) return;
    const r = await API.del(`/api/suppressions/${id}`);
    if (r && !r.error) { window.socToast?.({ title: 'Suppression removed', tone: 'warn' }); loadAll(); }
  }

  // ── add protected asset ──────────────────────────────────────────
  async function saveProtected() {
    if (!protHost.trim()) { alert('Hostname required'); return; }
    const r = await API.post('/api/protected-assets', {
      hostname: protHost.trim(), tier: protTier, reason: protReason.trim(),
    });
    if (r && !r.error) {
      window.socToast?.({ title: 'Asset protected', sub: protHost, tone: 'ok' });
      setShowAddProt(false); setProtHost(''); setProtReason('');
      loadAll();
    } else {
      window.socToast?.({ title: 'Failed', sub: r?.error, tone: 'crit' });
    }
  }

  async function deleteProtected(id, hostname) {
    if (!confirm(`Remove protection for ${hostname}?`)) return;
    const r = await API.del(`/api/protected-assets/${id}`);
    if (r && !r.error) { window.socToast?.({ title: 'Protection removed', sub: hostname, tone: 'warn' }); loadAll(); }
  }

  // ── playbook toggle ──────────────────────────────────────────────
  async function togglePlaybook(pb) {
    const r = await API.put(`/api/playbooks/${pb.id}`, { enabled: !pb.enabled });
    if (r && !r.error) {
      window.socToast?.({ title: pb.enabled ? 'Playbook paused' : 'Playbook activated', sub: pb.name, tone: pb.enabled ? 'warn' : 'ok' });
      loadAll();
    }
  }

  const anyOn = mainOn || huntOn || latOn;

  // ── render ───────────────────────────────────────────────────────
  return (
    <div className="page" data-screen-label="12 Dark SOC">

      {/* Add suppression modal */}
      {showAddSupp && (
        <div style={{ position:'fixed',inset:0,background:'rgba(0,0,0,.65)',zIndex:1000,display:'flex',alignItems:'center',justifyContent:'center' }}
             onClick={() => setShowAddSupp(false)}>
          <div style={{ background:'var(--bg-2)',border:'1px solid var(--ln)',borderRadius:8,width:'90%',maxWidth:460 }}
               onClick={e => e.stopPropagation()}>
            <div style={{ display:'flex',alignItems:'center',justifyContent:'space-between',padding:'16px 20px',borderBottom:'1px solid var(--ln)' }}>
              <span style={{ fontWeight:700 }}>Add Suppression Rule</span>
              <button className="btn btn-ghost btn-sm" onClick={() => setShowAddSupp(false)}>✕</button>
            </div>
            <div style={{ padding:20,display:'flex',flexDirection:'column',gap:12 }}>
              <div>
                <div className="mono dim" style={{ fontSize:11,marginBottom:4 }}>Rule ID *</div>
                <input className="mono" placeholder="e.g. 5710" value={suppRuleId} onChange={e => setSuppRuleId(e.target.value)} style={{ width:'100%' }} />
              </div>
              <div>
                <div className="mono dim" style={{ fontSize:11,marginBottom:4 }}>Agent Pattern</div>
                <input className="mono" placeholder="* = all agents" value={suppAgent} onChange={e => setSuppAgent(e.target.value)} style={{ width:'100%' }} />
              </div>
              <div>
                <div className="mono dim" style={{ fontSize:11,marginBottom:4 }}>Reason</div>
                <input className="mono" placeholder="Why are we suppressing this rule?" value={suppReason} onChange={e => setSuppReason(e.target.value)} style={{ width:'100%' }} />
              </div>
            </div>
            <div style={{ display:'flex',gap:8,padding:'12px 20px',borderTop:'1px solid var(--ln)' }}>
              <button className="btn btn-ghost" onClick={() => setShowAddSupp(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={saveSuppression}>Add Suppression</button>
            </div>
          </div>
        </div>
      )}

      {/* Add protected asset modal */}
      {showAddProt && (
        <div style={{ position:'fixed',inset:0,background:'rgba(0,0,0,.65)',zIndex:1000,display:'flex',alignItems:'center',justifyContent:'center' }}
             onClick={() => setShowAddProt(false)}>
          <div style={{ background:'var(--bg-2)',border:'1px solid var(--ln)',borderRadius:8,width:'90%',maxWidth:460 }}
               onClick={e => e.stopPropagation()}>
            <div style={{ display:'flex',alignItems:'center',justifyContent:'space-between',padding:'16px 20px',borderBottom:'1px solid var(--ln)' }}>
              <span style={{ fontWeight:700 }}>Protect Host</span>
              <button className="btn btn-ghost btn-sm" onClick={() => setShowAddProt(false)}>✕</button>
            </div>
            <div style={{ padding:20,display:'flex',flexDirection:'column',gap:12 }}>
              <div>
                <div className="mono dim" style={{ fontSize:11,marginBottom:4 }}>Hostname *</div>
                <input className="mono" placeholder="e.g. win-dc-01" value={protHost} onChange={e => setProtHost(e.target.value)} style={{ width:'100%' }} />
              </div>
              <div>
                <div className="mono dim" style={{ fontSize:11,marginBottom:4 }}>Protection Tier</div>
                <select className="select-mini mono" value={protTier} onChange={e => setProtTier(e.target.value)} style={{ width:'100%' }}>
                  <option value="critical">CRITICAL — isolation always blocked, IP blocked + escalation</option>
                  <option value="protected">PROTECTED — requires analyst approval (30 min TTL)</option>
                </select>
              </div>
              <div>
                <div className="mono dim" style={{ fontSize:11,marginBottom:4 }}>Reason</div>
                <input className="mono" placeholder="e.g. Domain Controller — never auto-isolate" value={protReason} onChange={e => setProtReason(e.target.value)} style={{ width:'100%' }} />
              </div>
            </div>
            <div style={{ display:'flex',gap:8,padding:'12px 20px',borderTop:'1px solid var(--ln)' }}>
              <button className="btn btn-ghost" onClick={() => setShowAddProt(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={saveProtected}>Protect Host</button>
            </div>
          </div>
        </div>
      )}

      <Topbar
        title="Dark SOC"
        sub="Autonomous AI response engine — playbooks, isolation, blocking, suppression"
        actions={<>
          <span className={`mono`} style={{ fontSize:11,padding:'4px 12px',borderRadius:3,fontWeight:700,letterSpacing:2,
            background: anyOn ? 'rgba(0,230,118,.1)' : 'rgba(255,23,68,.08)',
            color: anyOn ? 'var(--low)' : 'var(--crit)',
            border: `1px solid ${anyOn ? 'rgba(0,230,118,.3)' : 'rgba(255,23,68,.3)'}`,
          }}>{anyOn ? 'ACTIVE' : 'INACTIVE'}</span>
          <button className="btn btn-ghost" onClick={loadAll} disabled={loading}>
            <Icon.refresh width="13" height="13"/> Refresh
          </button>
        </>}
      />

      <div className="page-body">

        {/* ── 1. STATUS + SETTINGS ───────────────────────────────── */}
        <div className="grid-12" style={{ marginBottom:0 }}>
          {/* Status ring + 3 toggles */}
          <Card span={4} title="DARK SOC CONTROL">
            <div style={{ textAlign:'center',paddingBottom:16 }}>
              <div style={{
                width:110,height:110,borderRadius:'50%',margin:'0 auto 16px',display:'flex',alignItems:'center',
                justifyContent:'center',flexDirection:'column',border:'3px solid',transition:'all .3s',
                borderColor:   anyOn ? 'var(--low)' : 'var(--crit)',
                boxShadow:     anyOn ? '0 0 28px rgba(0,230,118,.2)' : '0 0 20px rgba(255,23,68,.1)',
                background:    anyOn ? 'rgba(0,230,118,.05)' : 'rgba(255,23,68,.03)',
              }}>
                <div style={{ fontFamily:'var(--fw)',fontSize:26,fontWeight:700,color: anyOn ? 'var(--low)' : 'var(--crit)' }}>
                  {anyOn ? 'ON' : 'OFF'}
                </div>
                <div style={{ fontSize:9,color:'var(--fg-3)',fontFamily:'var(--fm)',marginTop:2 }}>AUTONOMOUS</div>
              </div>
            </div>
            <div style={{ display:'flex',flexDirection:'column',gap:6 }}>
              {[
                { label:'Auto-Response Engine', val:mainOn, set:v => saveSettings(v, huntOn, latOn), color:'var(--crit)' },
                { label:'Threat Hunt Automation', val:huntOn, set:v => saveSettings(mainOn, v, latOn), color:'var(--med)' },
                { label:'Lateral Movement Monitor', val:latOn, set:v => saveSettings(mainOn, huntOn, v), color:'var(--med)' },
              ].map(({ label, val, set, color }) => (
                <label key={label} style={{ display:'flex',alignItems:'center',justifyContent:'space-between',fontSize:11,
                  fontFamily:'var(--fm)',color:'var(--fg-2)',padding:'6px 10px',background:'var(--bg-3)',borderRadius:4,cursor:'pointer' }}>
                  <span>{label}</span>
                  <input type="checkbox" checked={val} onChange={e => set(e.target.checked)}
                    disabled={saving} style={{ accentColor:color, width:14, height:14 }} />
                </label>
              ))}
            </div>
          </Card>

          {/* Execution stats */}
          <Card span={8} title="EXECUTION STATS" sub="Dark SOC playbooks only">
            <div style={{ display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:10,marginBottom:16 }}>
              {[
                { label:'Total Runs',    val: execStats?.total              ?? '—' },
                { label:'Executed',      val: execStats?.executed           ?? '—', color:'var(--low)'  },
                { label:'Skipped',       val: execStats?.skipped            ?? '—', color:'var(--med)'  },
                { label:'Pending Approvals', val: execStats?.pending_approvals ?? '—', color: (execStats?.pending_approvals ?? 0) > 0 ? 'var(--high)' : undefined },
              ].map(k => (
                <div key={k.label} style={{ background:'var(--bg-3)',borderRadius:6,padding:'12px 14px' }}>
                  <div style={{ fontSize:9,color:'var(--fg-3)',fontFamily:'var(--fm)',textTransform:'uppercase',letterSpacing:1,marginBottom:6 }}>{k.label}</div>
                  <div className="mono" style={{ fontSize:22,fontWeight:700,color:k.color||'var(--acc)' }}>{loading ? '…' : k.val}</div>
                </div>
              ))}
            </div>
            <div style={{ display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10 }}>
              {[
                { label:'Investigations Today', val:activity?.investigations ?? '—', color:'var(--low)' },
                { label:'Hunts Completed',       val:activity?.hunts          ?? '—', color:'var(--med)' },
                { label:'Logins Today',          val:activity?.logins         ?? '—', color:'var(--acc)' },
              ].map(k => (
                <div key={k.label} style={{ background:'var(--bg-3)',borderRadius:6,padding:'10px 14px' }}>
                  <div style={{ fontSize:9,color:'var(--fg-3)',fontFamily:'var(--fm)',textTransform:'uppercase',letterSpacing:1,marginBottom:4 }}>{k.label}</div>
                  <div className="mono" style={{ fontSize:18,fontWeight:700,color:k.color }}>{loading ? '…' : k.val}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* ── 2. TRIAGE QUEUE ────────────────────────────────────── */}
        <Card title="TRIAGE QUEUE" sub={queue ? `${(queue.queued_1h||0)} queued last 1h · ${(queue.queued_24h||0)} last 24h` : 'Loading…'}
          actions={<button className="btn btn-ghost btn-sm" onClick={() => API.get('/api/triage-queue/stats').then(d => { if(d&&!d.error) setQueue(d); })}>
            <Icon.refresh width="11" height="11"/>
          </button>}
          style={{ borderLeft:'3px solid var(--acc)' }}>
          {queue ? (
            <>
              <div style={{ display:'grid',gridTemplateColumns:'repeat(5,1fr)',gap:10,marginBottom:10 }}>
                {[
                  { label:'Pending',    val:queue.pending,    color:'var(--crit)' },
                  { label:'Processing', val:queue.processing, color:'var(--high)' },
                  { label:'Done',       val:queue.done,       color:'var(--low)'  },
                  { label:'Suppressed', val:queue.suppressed, color:'var(--med)'  },
                  { label:'Failed',     val:queue.failed,     color:'var(--acc)'  },
                ].map(k => (
                  <div key={k.label} style={{ background:'var(--bg-3)',borderRadius:6,padding:'10px 12px' }}>
                    <div style={{ fontSize:9,color:'var(--fg-3)',fontFamily:'var(--fm)',textTransform:'uppercase',letterSpacing:1,marginBottom:4 }}>{k.label}</div>
                    <div className="mono" style={{ fontSize:20,fontWeight:700,color:k.color }}>{k.val ?? '—'}</div>
                  </div>
                ))}
              </div>
              <div style={{ display:'flex',gap:6,flexWrap:'wrap',alignItems:'center' }}>
                <span style={{ fontSize:9,fontFamily:'var(--fm)',color:'var(--fg-3)' }}>Pending by tier:</span>
                {[
                  { count:queue.pending_critical, label:'CRITICAL', cls:'critical' },
                  { count:queue.pending_high,     label:'HIGH',     cls:'high'     },
                  { count:queue.pending_medium,   label:'MEDIUM',   cls:'medium'   },
                  { count:queue.pending_low,      label:'LOW',      cls:'low'      },
                ].filter(b => b.count > 0).map(b => (
                  <span key={b.cls} className={`badge ${b.cls}`} style={{ fontSize:9 }}>{b.count} {b.label}</span>
                ))}
                {!queue.pending && !queue.pending_critical && !queue.pending_high && !queue.pending_medium && (
                  <span style={{ fontSize:9,fontFamily:'var(--fm)',color:'var(--low)' }}>Queue clear</span>
                )}
              </div>
            </>
          ) : <div className="empty mono" style={{ padding:20 }}>{loading ? 'Loading…' : 'Triage queue unavailable'}</div>}
        </Card>

        {/* ── 3. AUDIT LOG ───────────────────────────────────────── */}
        <Card title="AUDIT LOG — RECENT ACTIONS"
          actions={<>
            <select className="select-mini mono" value={auditFilter}
              onChange={e => { setAuditFilter(e.target.value); loadAudit(e.target.value); }}
              style={{ marginRight:6 }}>
              <option value="">All events</option>
              <option value="auth">🔐 Auth</option>
              <option value="alert">🔍 Investigations</option>
              <option value="case">📋 Cases</option>
              <option value="playbook">⚡ Playbooks</option>
              <option value="hunt">🎯 Hunts</option>
              <option value="scan">🖥 Scans</option>
              <option value="settings">⚙️ Settings</option>
            </select>
            <button className="btn btn-ghost btn-sm" onClick={() => loadAudit(auditFilter)}>
              <Icon.refresh width="11" height="11"/>
            </button>
          </>}>
          {loading
            ? <div className="empty mono" style={{ padding:20 }}>Loading…</div>
            : audit.length === 0
              ? <div className="empty mono" style={{ padding:20 }}>No events recorded yet</div>
              : <div style={{ maxHeight:380,overflowY:'auto',display:'flex',flexDirection:'column',gap:4 }}>
                  {audit.map((ev, i) => {
                    const sc = statusCls(ev.status);
                    const scColor = sc === 'ok' ? 'var(--low)' : sc === 'skip' ? 'var(--med)' : 'var(--crit)';
                    const scLabel = sc === 'ok' ? 'OK' : sc === 'skip' ? 'SKIP' : 'FAIL';
                    return (
                      <div key={ev.id || i} style={{ display:'flex',gap:10,alignItems:'baseline',fontSize:11,
                        padding:'6px 10px',background:'var(--bg-3)',borderRadius:4 }}>
                        <span className="mono" style={{ color:'var(--fg-3)',whiteSpace:'nowrap',flexShrink:0,fontSize:10 }}>
                          {fmtTs(ev.created_at)}
                        </span>
                        <span style={{ flex:1,color:'var(--fg-1)' }}>
                          {typeIcon(ev.event_type)} {ev.title || ev.description || '—'}
                          {ev.actor && <span style={{ color:'var(--fg-3)',marginLeft:6 }}>[{ev.actor}]</span>}
                        </span>
                        <span className="mono" style={{ fontSize:10,fontWeight:700,color:scColor,whiteSpace:'nowrap' }}>{scLabel}</span>
                      </div>
                    );
                  })}
                </div>
          }
        </Card>

        {/* ── 4. FP RATE LEARNING ────────────────────────────────── */}
        <Card title="FP RATE LEARNING — PER-RULE GROUND TRUTH"
          sub={fpStats?.cache_age_min != null ? `cache ${fpStats.cache_age_min}m old` : undefined}
          style={{ borderLeft:'3px solid var(--med)' }}
          actions={<button className="btn btn-ghost btn-sm" onClick={() => API.get('/api/fp-stats').then(d => { if(d&&!d.error) setFpStats(d); })}>
            <Icon.refresh width="11" height="11"/>
          </button>}>
          <div style={{ fontSize:10,color:'var(--fg-3)',fontFamily:'var(--fm)',marginBottom:10,lineHeight:1.5 }}>
            Analyst TP/FP labels feed Beta-smoothed per-rule rates. Blended with LangChain AI using a linear ramp (0→70% historical weight as samples grow 0→30).
          </div>
          {!fpStats
            ? <div className="empty mono" style={{ padding:20 }}>{loading ? 'Loading…' : 'No labelled investigations yet — mark investigations as TP/FP to build ground truth'}</div>
            : fpStats.items?.length === 0
              ? <div className="empty mono" style={{ padding:20 }}>No labelled investigations yet — mark investigations as TP/FP to build ground truth</div>
              : <div style={{ overflowX:'auto' }}>
                  <table className="data-table">
                    <thead><tr>
                      <th>RULE ID</th><th style={{width:80}}>LABELLED</th><th style={{width:70}}>FP</th><th style={{width:70}}>TP</th>
                      <th style={{width:90}}>RAW FP%</th><th style={{width:110}}>ADJUSTED FP%</th><th>HIST. WEIGHT</th>
                    </tr></thead>
                    <tbody>
                      {(fpStats.items || []).slice(0,20).map(r => {
                        const fpCol = r.fp_rate_raw >= 70 ? 'var(--crit)' : r.fp_rate_raw >= 40 ? 'var(--high)' : 'var(--low)';
                        const adjCol = r.fp_rate_adjusted >= 70 ? 'var(--crit)' : r.fp_rate_adjusted >= 40 ? 'var(--high)' : 'var(--low)';
                        return (
                          <tr key={r.rule_id}>
                            <td className="mono" style={{ color:'var(--acc)' }}>{r.rule_id}</td>
                            <td className="mono" style={{ textAlign:'center' }}>{r.total_labelled}</td>
                            <td className="mono" style={{ textAlign:'center',color:'var(--crit)' }}>{r.fp_count}</td>
                            <td className="mono" style={{ textAlign:'center',color:'var(--low)' }}>{r.tp_count}</td>
                            <td className="mono" style={{ fontWeight:700,color:fpCol }}>{r.fp_rate_raw}%</td>
                            <td className="mono" style={{ fontWeight:700,color:adjCol }}>{r.fp_rate_adjusted}%</td>
                            <td>
                              <div style={{ display:'flex',alignItems:'center',gap:6 }}>
                                <div style={{ flex:1,height:4,background:'var(--ln)',borderRadius:2,minWidth:60 }}>
                                  <div style={{ width:`${r.hist_weight_pct}%`,height:'100%',background:'var(--acc)',borderRadius:2 }}/>
                                </div>
                                <span className="mono" style={{ fontSize:10,color:'var(--fg-3)' }}>{r.hist_weight_pct}%</span>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  {(fpStats.items?.length || 0) > 20 && (
                    <div style={{ fontSize:9,color:'var(--fg-3)',fontFamily:'var(--fm)',padding:'6px 8px' }}>
                      Showing top 20 of {fpStats.items.length} rules
                    </div>
                  )}
                </div>
          }
        </Card>

        {/* ── 5. PENDING ACTION APPROVALS ────────────────────────── */}
        <Card title="PENDING ACTION APPROVALS"
          style={{ borderLeft:`3px solid var(--high)` }}
          sub="L2+ required to approve · 30-min TTL"
          actions={<>
            {approvals.length > 0 && (
              <span style={{ fontSize:9,padding:'2px 8px',borderRadius:8,background:'rgba(255,152,0,.15)',color:'var(--high)',
                border:'1px solid rgba(255,152,0,.3)',fontFamily:'var(--fm)',fontWeight:700 }}>{approvals.length}</span>
            )}
            <button className="btn btn-ghost btn-sm" onClick={() => API.get('/api/action-approvals').then(d => { if(d&&!d.error) setApprovals(d.items||[]); })}>
              <Icon.refresh width="11" height="11"/>
            </button>
          </>}>
          {approvals.length === 0
            ? <div className="empty mono" style={{ padding:20,color:'var(--low)' }}>✓ No pending approvals</div>
            : <div style={{ overflowX:'auto' }}>
                <table className="data-table">
                  <thead><tr>
                    <th>RULE</th><th>AGENT</th><th>VERDICT</th><th style={{width:90}}>CONFIDENCE</th>
                    <th style={{width:90}}>FP RISK</th><th>ACTIONS REQUESTED</th><th>SUMMARY</th>
                    <th style={{width:70}}>AGE</th><th style={{width:60}}>EXPIRES</th><th style={{width:140}}></th>
                  </tr></thead>
                  <tbody>
                    {approvals.map(a => {
                      const ageMins = Math.round((Date.now() - new Date(a.created_at).getTime()) / 60000);
                      const expMins = Math.max(0, Math.round((new Date(a.expires_at).getTime() - Date.now()) / 60000));
                      const vSev    = a.verdict === 'true_positive' ? 'critical' : a.verdict === 'false_positive' ? 'ok' : 'medium';
                      let fpDisplay = `${a.fp_probability}%`;
                      try {
                        const iv = typeof a.investigation_verdict === 'string' ? JSON.parse(a.investigation_verdict) : a.investigation_verdict;
                        const b  = iv?.fp_blend_info;
                        if (b && b.sample_count > 0) fpDisplay = `${b.adjusted_fp}% (${b.sample_count} labels)`;
                      } catch(_) {}
                      return (
                        <tr key={a.id}>
                          <td>
                            <span className="mono" style={{ fontSize:10,color:'var(--acc)' }}>{a.rule_id || '—'}</span>
                            <br/><span style={{ fontSize:9,color:'var(--fg-3)' }}>{a.severity}</span>
                          </td>
                          <td className="mono" style={{ fontSize:10 }}>{a.agent || '—'}</td>
                          <td><SevChip sev={vSev} label={(a.verdict || '').replace('_', ' ')} /></td>
                          <td className="mono" style={{ fontWeight:700,color:'var(--acc)' }}>{a.confidence}%</td>
                          <td className="mono" style={{ fontSize:11 }}>{fpDisplay}</td>
                          <td style={{ fontSize:10,color:'var(--high)' }}>{(a.recommended_actions || []).join(', ') || '—'}</td>
                          <td style={{ fontSize:10,maxWidth:180,whiteSpace:'normal',lineHeight:1.4,color:'var(--fg-2)' }}>
                            {(a.summary || '').slice(0, 90)}
                          </td>
                          <td className="mono" style={{ fontSize:10,color:'var(--fg-3)' }}>{ageMins}m</td>
                          <td className="mono" style={{ fontSize:10,color:expMins < 5 ? 'var(--crit)' : 'var(--fg-3)' }}>{expMins}m</td>
                          <td>
                            <div style={{ display:'flex',gap:4 }}>
                              <button className="btn btn-ghost btn-sm" style={{ color:'var(--low)',borderColor:'var(--low)' }}
                                onClick={() => approveAction(a.id)}>Approve</button>
                              <button className="btn btn-ghost btn-sm" style={{ color:'var(--crit)',borderColor:'var(--crit)' }}
                                onClick={() => rejectAction(a.id)}>Reject</button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
          }
        </Card>

        {/* ── 6. DRAFT DETECTION RULES ───────────────────────────── */}
        <Card title="DRAFT DETECTION RULES"
          style={{ borderLeft:'3px solid rgba(0,230,118,.5)' }}
          sub={draftRules ? `${draftRules.stats?.pending || 0} pending · ${draftRules.total || 0} total` : 'Auto-generated after each confirmed true positive'}
          actions={<button className="btn btn-ghost btn-sm" onClick={() => API.get('/api/draft-rules?page_size=20').then(d => { if(d&&!d.error) setDraftRules(d); })}>
            <Icon.refresh width="11" height="11"/>
          </button>}>
          <div style={{ fontSize:10,color:'var(--fg-3)',fontFamily:'var(--fm)',marginBottom:10,lineHeight:1.6 }}>
            AI drafts a Wazuh XML rule + Sigma rule after each confirmed true positive. Review, approve, and deploy.
          </div>
          {!draftRules || !draftRules.rules?.length
            ? <div className="empty mono" style={{ padding:20 }}>{loading ? 'Loading…' : 'No draft rules — confirm true positives to generate rules automatically'}</div>
            : <div style={{ display:'flex',flexDirection:'column',gap:6 }}>
                {draftRules.rules.map(r => (
                  <div key={r.id} style={{ border:'1px solid var(--ln)',borderRadius:6,overflow:'hidden' }}>
                    <div style={{ display:'flex',gap:10,alignItems:'center',padding:'8px 12px',background:'var(--bg-3)',cursor:'pointer' }}
                         onClick={() => setExpandedDraft(expandedDraft === r.id ? null : r.id)}>
                      <span className="mono" style={{ fontSize:10,color:'var(--acc)',fontWeight:700 }}>Rule {r.rule_id || '—'}</span>
                      <span className={`badge ${r.status === 'pending_review' ? 'high' : r.status === 'approved' ? 'ok' : 'low'}`} style={{ fontSize:9 }}>
                        {r.status?.replace('_',' ') || 'pending'}
                      </span>
                      <span style={{ flex:1,fontSize:11,color:'var(--fg-2)' }}>inv #{r.investigation_id}</span>
                      <span className="mono" style={{ fontSize:10,color:'var(--fg-3)' }}>{relTs(r.created_at)}</span>
                      {isL2 && r.status === 'pending_review' && (
                        <div style={{ display:'flex',gap:4 }} onClick={e => e.stopPropagation()}>
                          <button className="btn btn-ghost btn-sm" style={{ color:'var(--low)' }} onClick={() => setDraftStatus(r.id,'approved')}>Approve</button>
                          <button className="btn btn-ghost btn-sm" style={{ color:'var(--fg-3)' }} onClick={() => setDraftStatus(r.id,'dismissed')}>Dismiss</button>
                        </div>
                      )}
                    </div>
                    {expandedDraft === r.id && (
                      <div style={{ padding:12,display:'flex',flexDirection:'column',gap:8 }}>
                        {r.wazuh_xml && (
                          <div>
                            <div style={{ fontSize:9,color:'var(--acc)',fontFamily:'var(--fm)',marginBottom:4,letterSpacing:1 }}>WAZUH XML</div>
                            <pre style={{ background:'var(--bg)',border:'1px solid var(--ln)',borderRadius:4,padding:10,fontSize:10,
                              whiteSpace:'pre-wrap',wordBreak:'break-word',maxHeight:160,overflowY:'auto',color:'var(--fg-1)' }}>
                              {r.wazuh_xml}
                            </pre>
                          </div>
                        )}
                        {r.sigma_rule && (
                          <div>
                            <div style={{ fontSize:9,color:'var(--med)',fontFamily:'var(--fm)',marginBottom:4,letterSpacing:1 }}>SIGMA RULE</div>
                            <pre style={{ background:'var(--bg)',border:'1px solid var(--ln)',borderRadius:4,padding:10,fontSize:10,
                              whiteSpace:'pre-wrap',wordBreak:'break-word',maxHeight:160,overflowY:'auto',color:'var(--fg-1)' }}>
                              {r.sigma_rule}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
          }
        </Card>

        {/* ── 7. RESPONSE PLAYBOOKS ──────────────────────────────── */}
        <Card title="RESPONSE PLAYBOOKS"
          sub="Executed automatically by Dark SOC engine"
          actions={<>
            <span style={{ fontSize:9,fontFamily:'var(--fm)',color:'var(--fg-3)',marginRight:8 }}>
              Stored in PostgreSQL · not via n8n
            </span>
            {isAdmin && <button className="btn btn-ghost btn-sm" onClick={() => window.socToast?.({ title:'New Playbook', sub:'Coming soon', tone:'info' })}>
              <Icon.plus width="11" height="11"/> New Playbook
            </button>}
          </>}>
          <div style={{ fontSize:10,color:'var(--fg-3)',fontFamily:'var(--fm)',marginBottom:10 }}>
            Each playbook matches alerts by severity level and MITRE technique, then fires response actions automatically.
          </div>
          {loading
            ? <div className="empty mono" style={{ padding:20 }}>Loading…</div>
            : playbooks.length === 0
              ? <div className="empty mono" style={{ padding:20 }}>No playbooks configured yet</div>
              : <table className="data-table">
                  <thead><tr>
                    <th>NAME</th><th>TRIGGER SEVERITY</th><th>MITRE</th>
                    <th>ACTIONS</th><th style={{width:80}}>STATUS</th>
                    <th style={{width:100}}>LAST RUN</th><th style={{width:80}}>RUNS</th><th style={{width:90}}></th>
                  </tr></thead>
                  <tbody>
                    {playbooks.map(pb => {
                      const lvl = pb.min_rule_level || 0;
                      const sev = pb.trigger_severity || (lvl >= 12 ? 'critical' : lvl >= 10 ? 'high' : lvl >= 7 ? 'medium' : 'low');
                      const mitre = pb.mitre_techniques || pb.trigger_mitre || [];
                      const actions = (pb.actions || []).map(a => typeof a === 'string' ? a : a.type || JSON.stringify(a));
                      const isOn = pb.enabled || pb.status === 'active';
                      return (
                        <tr key={pb.id}>
                          <td style={{ fontWeight:600 }}>{pb.name}</td>
                          <td><SevChip sev={sev} /></td>
                          <td className="mono" style={{ fontSize:10,color:'var(--fg-2)' }}>
                            {mitre.slice(0,3).join(', ') || '—'}{mitre.length > 3 ? ` +${mitre.length-3}` : ''}
                          </td>
                          <td>
                            <div style={{ display:'flex',gap:4,flexWrap:'wrap' }}>
                              {actions.map(a => <Chip key={a} mono tone="default">{a}</Chip>)}
                            </div>
                          </td>
                          <td>
                            <Chip mono tone={isOn ? 'ok' : 'default'}>
                              {isOn ? 'active' : 'paused'}
                            </Chip>
                          </td>
                          <td className="mono" style={{ fontSize:10,color:'var(--fg-3)' }}>
                            {pb.last_run ? relTs(pb.last_run) : '—'}
                          </td>
                          <td className="mono">{pb.run_count ?? 0}</td>
                          <td>
                            <button className="btn btn-ghost btn-sm" onClick={() => togglePlaybook(pb)}>
                              {isOn ? 'Pause' : 'Enable'}
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
          }
        </Card>

        {/* ── 8. SUPPRESSIONS + PROTECTED ASSETS (2-col) ─────────── */}
        <div className="grid-12">
          <Card span={6} title="ALERT SUPPRESSIONS"
            style={{ borderLeft:'3px solid rgba(0,229,255,.5)' }}
            sub={suppressions ? `${suppressions.total || 0} rules · ${suppressions.stats?.hits_24h || 0} hits today` : undefined}
            actions={<>
              {isL2 && <button className="btn btn-ghost btn-sm" onClick={() => setShowAddSupp(true)}>
                <Icon.plus width="11" height="11"/> Add Rule
              </button>}
            </>}>
            <div style={{ fontSize:10,color:'var(--fg-3)',fontFamily:'var(--fm)',marginBottom:10,lineHeight:1.5 }}>
              Drop alerts matching these rules before they enter the triage queue. Hit counts confirm what each rule is actually suppressing.
            </div>
            {loading
              ? <div className="empty mono" style={{ padding:20 }}>Loading…</div>
              : !suppressions?.suppressions?.length
                ? <div className="empty mono" style={{ padding:16 }}>No suppression rules configured</div>
                : <table className="data-table">
                    <thead><tr>
                      <th style={{width:90}}>RULE ID</th><th>AGENT</th>
                      <th style={{width:70}}>HITS</th><th>REASON</th>
                      {isL2 && <th style={{width:50}}></th>}
                    </tr></thead>
                    <tbody>
                      {suppressions.suppressions.map(s => (
                        <tr key={s.id}>
                          <td className="mono" style={{ color:'var(--acc)' }}>{s.rule_id}</td>
                          <td className="mono" style={{ fontSize:10 }}>{s.agent_pattern || '*'}</td>
                          <td className="mono" style={{ fontWeight:700,color:'var(--med)' }}>{s.hit_count ?? 0}</td>
                          <td className="dim" style={{ fontSize:11 }}>{s.reason || '—'}</td>
                          {isL2 && <td>
                            <button className="btn btn-ghost btn-sm" style={{ color:'var(--crit)' }} onClick={() => deleteSuppression(s.id)}>Del</button>
                          </td>}
                        </tr>
                      ))}
                    </tbody>
                  </table>
            }
          </Card>

          <Card span={6} title="PROTECTED ASSETS"
            style={{ borderLeft:'3px solid var(--med)' }}
            actions={<>
              {isAdmin && <button className="btn btn-ghost btn-sm" onClick={() => setShowAddProt(true)}>
                <Icon.plus width="11" height="11"/> Protect Host
              </button>}
            </>}>
            <div style={{ fontSize:10,color:'var(--fg-3)',fontFamily:'var(--fm)',marginBottom:10,lineHeight:1.5 }}>
              <span style={{ color:'var(--crit)',fontWeight:700 }}>CRITICAL</span> — isolation always blocked; attacker IP blocked + escalation case created.<br/>
              <span style={{ color:'var(--med)',fontWeight:700 }}>PROTECTED</span> — requires analyst approval (30-min window before auto-reject).
            </div>
            {loading
              ? <div className="empty mono" style={{ padding:20 }}>Loading…</div>
              : protected_.length === 0
                ? <div className="empty mono" style={{ padding:16 }}>No protected assets configured</div>
                : <table className="data-table">
                    <thead><tr>
                      <th>HOST</th><th style={{width:90}}>TIER</th><th>REASON</th>
                      <th style={{width:70}}>ADDED BY</th>
                      {isAdmin && <th style={{width:50}}></th>}
                    </tr></thead>
                    <tbody>
                      {protected_.map(p => (
                        <tr key={p.id}>
                          <td className="mono">{p.hostname || p.ip_address || '—'}</td>
                          <td>
                            <span className="mono" style={{ fontSize:10,fontWeight:700,
                              color: p.tier === 'critical' ? 'var(--crit)' : 'var(--med)' }}>
                              {(p.tier || 'protected').toUpperCase()}
                            </span>
                          </td>
                          <td className="dim" style={{ fontSize:11 }}>{p.reason || '—'}</td>
                          <td className="mono dim" style={{ fontSize:10 }}>{p.added_by || '—'}</td>
                          {isAdmin && <td>
                            <button className="btn btn-ghost btn-sm" style={{ color:'var(--crit)' }}
                              onClick={() => deleteProtected(p.id, p.hostname)}>Del</button>
                          </td>}
                        </tr>
                      ))}
                    </tbody>
                  </table>
            }
          </Card>
        </div>

        {/* ── 9. ISOLATION APPROVALS ─────────────────────────────── */}
        <Card title="PENDING ISOLATION APPROVALS"
          style={{ borderLeft:'3px solid var(--acc)' }}
          actions={<button className="btn btn-ghost btn-sm" onClick={() => API.get('/api/isolation-approvals').then(d => {
            const arr = d?.approvals || (Array.isArray(d) ? d : []);
            setIsoApprovals(arr);
          })}><Icon.refresh width="11" height="11"/></button>}>
          <div style={{ fontSize:10,color:'var(--fg-3)',fontFamily:'var(--fm)',marginBottom:10,lineHeight:1.5 }}>
            When Dark SOC wants to isolate a PROTECTED host, it waits here. Approve → immediate isolation. Reject → no action. Auto-expires after timeout.
          </div>
          {isoApprovals.length === 0
            ? <div style={{ fontSize:11,color:'var(--fg-3)',fontFamily:'var(--fm)',padding:16 }}>No pending isolation approvals.</div>
            : <table className="data-table">
                <thead><tr>
                  <th>HOST</th><th>IP</th><th>REQUESTED BY</th>
                  <th style={{width:100}}>EXPIRES</th><th>REASON</th><th style={{width:140}}></th>
                </tr></thead>
                <tbody>
                  {isoApprovals.map(ap => (
                    <tr key={ap.id}>
                      <td className="mono">{ap.hostname || ap.host || '—'}</td>
                      <td className="mono" style={{ fontSize:10,color:'var(--fg-3)' }}>{ap.ip_address || '—'}</td>
                      <td className="mono dim">{ap.requested_by || ap.user || '—'}</td>
                      <td className="mono dim">{ap.expires_at ? relTs(ap.expires_at) : '—'}</td>
                      <td className="dim" style={{ fontSize:11 }}>{ap.reason || '—'}</td>
                      <td>
                        <div style={{ display:'flex',gap:4 }}>
                          <button className="btn btn-ghost btn-sm" style={{ color:'var(--low)',borderColor:'var(--low)' }}
                            onClick={() => approveIsolation(ap.id)}>Approve</button>
                          <button className="btn btn-ghost btn-sm" style={{ color:'var(--crit)',borderColor:'var(--crit)' }}
                            onClick={() => rejectIsolation(ap.id)}>Reject</button>
                        </div>
                      </td>
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

Object.assign(window, { PageDarkSOC });
