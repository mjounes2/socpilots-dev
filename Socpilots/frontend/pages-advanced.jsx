// SLA · Evidence · Artifacts · Users · LangChain · LogSources · Investigation · Notifications
const { useState: useStateADV, useEffect: useEffectADV, useRef: useRefADV, useMemo: useMemoADV } = React;

// ============= PAGE SLA =============
function PageSLA() {
  const [tab, setTab]               = useStateADV('alerts');
  const [dash, setDash]             = useStateADV(null);
  const [policyMap, setPolicyMap]   = useStateADV(null);

  // Tab data
  const [alertHrs, setAlertHrs]     = useStateADV('24');
  const [alertData, setAlertData]   = useStateADV(null);
  const [alertLoading, setAL]       = useStateADV(false);
  const [alertErr, setAlertErr]     = useStateADV(null);

  const [activeData, setActiveData] = useStateADV(null);
  const [activePage, setActivePage] = useStateADV(1);
  const [activeLoading, setActL]    = useStateADV(false);

  const [breachedData, setBData]    = useStateADV(null);
  const [breachedPage, setBPage]    = useStateADV(1);
  const [breachLoading, setBL]      = useStateADV(false);

  const [allData, setAllData]       = useStateADV(null);
  const [allPage, setAllPage]       = useStateADV(1);
  const [allStatus, setAllStatus]   = useStateADV('');
  const [allType, setAllType]       = useStateADV('');
  const [allLoading, setAllL]       = useStateADV(false);

  const [polData, setPolData]       = useStateADV(null);
  const [polLoading, setPolL]       = useStateADV(false);

  // SIEM Alerts tab — search / filter / sort
  const [alertQ, setAlertQ]               = useStateADV('');
  const [alertSevF, setAlertSevF]         = useStateADV('');
  const [alertSortCol, setAlertSortCol]   = useStateADV('ts');
  const [alertSortDir, setAlertSortDir]   = useStateADV('desc');

  // Detail modal
  const [showDetail, setShowDetail] = useStateADV(false);
  const [detailInst, setDetailInst] = useStateADV(null);
  const [detailEvts, setDetailEvts] = useStateADV([]);
  const [detailLoad, setDetailLoad] = useStateADV(false);

  // Start SLA modal
  const [showStart, setShowStart]   = useStateADV(false);
  const [startType, setStartType]   = useStateADV('alert');
  const [startId, setStartId]       = useStateADV('');
  const [startLabel, setStartLabel] = useStateADV('');
  const [startSev, setStartSev]     = useStateADV('high');

  // Policy modal
  const [showPolModal, setShowPol]  = useStateADV(false);
  const [polEditId, setPolEditId]   = useStateADV(null);
  const [polName, setPolName]       = useStateADV('');
  const [polDesc, setPolDesc]       = useStateADV('');
  const [polEntity, setPolEntity]   = useStateADV('all');
  const [polSev, setPolSev]         = useStateADV('all');
  const [polResp, setPolResp]       = useStateADV('60');
  const [polResol, setPolResol]     = useStateADV('480');

  const user = window.SOC_API.user();
  const isAdmin = user?.role === 'admin';

  function fmtTs(ts) {
    if (!ts) return '—';
    return new Date(ts).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'medium' });
  }

  // ── Helpers ──────────────────────────────────────────────────────
  function slaIcon(elapsedMs, responseMinutes, status) {
    if (status === 'completed') return '✅';
    if (status === 'cancelled') return '⊘';
    const pct = (elapsedMs / (responseMinutes * 60000)) * 100;
    if (status === 'breached' || pct >= 100) return '🔴';
    if (pct >= 70) return '⚠️';
    return '✅';
  }

  function RiskBar({ pct, status }) {
    let color = 'var(--low)';
    if (status === 'breached' || pct >= 100) color = 'var(--crit)';
    else if (pct >= 90) color = 'var(--high)';
    else if (pct >= 70) color = 'var(--med)';
    const w = Math.min(pct, 100);
    return (
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
        <div style={{ background: 'var(--ln)', borderRadius: 3, height: 7, width: 80, overflow: 'hidden', flexShrink: 0 }}>
          <div style={{ background: color, height: '100%', width: `${w}%` }} />
        </div>
        <span className="mono" style={{ fontSize: 11, color }}>{pct}%</span>
      </div>
    );
  }

  function StatusBadge({ status }) {
    const map = { running: 'var(--acc)', paused: 'var(--med)', breached: 'var(--crit)', completed: 'var(--low)', cancelled: 'var(--fg-3)' };
    return <span className="mono" style={{ color: map[status] || 'var(--fg-3)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>{status}</span>;
  }

  function EntityLabel({ inst }) {
    const icons = { investigation: '🔍', case: '📁', alert: '⚡' };
    const icon  = icons[inst.entity_type] || '•';
    const label = inst.entity_label || inst.entity_id;
    return <span title={`${inst.entity_type}: ${inst.entity_id}`}>{icon} {label}</span>;
  }

  // ── Data loaders ─────────────────────────────────────────────────
  async function loadDash() {
    const d = await window.SOC_API.get('/api/sla/dashboard');
    if (d && !d.error) setDash(d);
  }

  async function loadPolicyMapOnce() {
    if (policyMap) return policyMap;
    const d = await window.SOC_API.get('/api/sla/policy-map');
    if (d && !d.error) { setPolicyMap(d); return d; }
    return null;
  }

  async function loadAlerts(hrs) {
    const h = hrs ?? alertHrs;
    setAL(true); setAlertErr(null);
    const d = await window.SOC_API.get(`/api/sla/alerts?hours=${h}`);
    setAL(false);
    if (!d || d.error) { setAlertErr(d?.error || 'Failed to load SLA alerts'); return; }
    setAlertData(d);
  }

  async function loadActive(page) {
    const p = page ?? activePage;
    setActivePage(p); setActL(true);
    const d = await window.SOC_API.get(`/api/sla/active?page=${p}&page_size=50`);
    setActL(false); setActiveData(d);
  }

  async function loadBreached(page) {
    const p = page ?? breachedPage;
    setBPage(p); setBL(true);
    const d = await window.SOC_API.get(`/api/sla/breached?page=${p}&page_size=50`);
    setBL(false); setBData(d);
  }

  async function loadAll(page, status, etype) {
    const p  = page   ?? allPage;
    const st = status ?? allStatus;
    const et = etype  ?? allType;
    setAllPage(p); setAllL(true);
    const params = new URLSearchParams({ page: p, page_size: 50 });
    if (st) params.set('status', st);
    if (et) params.set('entity_type', et);
    const d = await window.SOC_API.get(`/api/sla/instances?${params}`);
    setAllL(false); setAllData(d);
  }

  async function loadPolicies() {
    setPolL(true);
    const d = await window.SOC_API.get('/api/sla/policies');
    setPolL(false);
    if (d && !d.error) setPolData(d);
  }

  function refresh() {
    loadDash();
    if (tab === 'alerts')        loadAlerts();
    else if (tab === 'active')   loadActive();
    else if (tab === 'breached') loadBreached();
    else if (tab === 'all')      loadAll();
    else if (tab === 'policies') loadPolicies();
  }

  // Initial load
  useEffectADV(() => {
    loadDash();
    loadPolicyMapOnce();
    loadAlerts();
  }, []);

  // Tab switch loads
  useEffectADV(() => {
    if (tab === 'alerts')        loadAlerts();
    else if (tab === 'active')   loadActive(1);
    else if (tab === 'breached') loadBreached(1);
    else if (tab === 'all')      loadAll(1);
    else if (tab === 'policies') loadPolicies();
  }, [tab]);

  // ── Actions ──────────────────────────────────────────────────────
  async function openDetail(id) {
    setDetailInst(null); setDetailEvts([]);
    setDetailLoad(true); setShowDetail(true);
    const [inst, evtData] = await Promise.all([
      window.SOC_API.get(`/api/sla/instances/${id}`),
      window.SOC_API.get(`/api/sla/instances/${id}/events`),
    ]);
    setDetailLoad(false);
    if (inst && !inst.error) setDetailInst(inst);
    if (evtData?.events) setDetailEvts(evtData.events);
  }

  async function doPause(id, fromDetail) {
    const r = await window.SOC_API.post(`/api/sla/instances/${id}/pause`, { reason: 'Manual pause' });
    if (!r || r.error) { alert(r?.error || 'Failed to pause'); return; }
    if (fromDetail) setShowDetail(false);
    refresh();
  }

  async function doResume(id, fromDetail) {
    const r = await window.SOC_API.post(`/api/sla/instances/${id}/resume`, { reason: 'Manual resume' });
    if (!r || r.error) { alert(r?.error || 'Failed to resume'); return; }
    if (fromDetail) setShowDetail(false);
    refresh();
  }

  async function doStop(id, fromDetail) {
    const r = await window.SOC_API.post(`/api/sla/instances/${id}/stop`, { reason: 'Resolved by analyst' });
    if (!r || r.error) { alert(r?.error || 'Failed to complete SLA'); return; }
    if (fromDetail) setShowDetail(false);
    refresh();
  }

  async function doCancel(id, fromDetail) {
    if (!confirm('Cancel this SLA timer?')) return;
    const r = await window.SOC_API.post(`/api/sla/instances/${id}/cancel`, { reason: 'Cancelled by analyst' });
    if (!r || r.error) { alert(r?.error || 'Failed to cancel SLA'); return; }
    if (fromDetail) setShowDetail(false);
    refresh();
  }

  async function doStartManual() {
    if (!startId.trim()) { alert('Entity ID is required'); return; }
    const r = await window.SOC_API.post('/api/sla/start', {
      entity_type: startType, entity_id: startId.trim(),
      entity_label: startLabel.trim() || null, severity: startSev,
    });
    if (!r || r.error) { alert(r?.error || 'Failed to start SLA'); return; }
    setShowStart(false); setStartId(''); setStartLabel('');
    window.socToast?.({ title: 'SLA started', sub: startId, tone: 'ok' });
    refresh();
  }

  async function doSavePolicy() {
    const body = {
      name: polName.trim(), description: polDesc.trim(),
      entity_type: polEntity, severity: polSev,
      response_minutes: parseInt(polResp), resolution_minutes: parseInt(polResol),
      escalation_chain: [], active: true,
    };
    if (!body.name || !body.response_minutes || !body.resolution_minutes) {
      alert('Name, Response Minutes, and Resolution Minutes are required'); return;
    }
    const r = polEditId
      ? await window.SOC_API.put(`/api/sla/policies/${polEditId}`, body)
      : await window.SOC_API.post('/api/sla/policies', body);
    if (!r || r.error) { alert(r?.error || 'Failed to save policy'); return; }
    setShowPol(false); loadPolicies();
  }

  async function doDeletePolicy(id) {
    if (!confirm('Delete this SLA policy? Active SLA instances will keep their current timers.')) return;
    const r = await window.SOC_API.del(`/api/sla/policies/${id}`);
    if (!r || r.error) { alert(r?.error || 'Failed to delete policy'); return; }
    loadPolicies();
  }

  function openNewPolicy() {
    setPolEditId(null); setPolName(''); setPolDesc('');
    setPolEntity('all'); setPolSev('all'); setPolResp('60'); setPolResol('480');
    setShowPol(true);
  }

  function openEditPolicy(p) {
    setPolEditId(p.id); setPolName(p.name); setPolDesc(p.description || '');
    setPolEntity(p.entity_type); setPolSev(p.severity);
    setPolResp(String(p.response_minutes)); setPolResol(String(p.resolution_minutes));
    setShowPol(true);
  }

  // ── Tab content renderers ────────────────────────────────────────
  const TABS = ['alerts', 'active', 'breached', 'all', 'policies'];
  const TAB_LABELS = { alerts: '⚡ SIEM Alerts', active: 'Active', breached: 'Breached', all: 'All SLAs', policies: 'Policies' };

  function TabAlerts() {
    if (alertLoading) return <div className="empty mono" style={{ padding: 32 }}>Loading SIEM alerts &amp; syncing SLA timers…</div>;
    if (alertErr)     return <div className="empty mono" style={{ color: 'var(--crit)', padding: 20 }}>{alertErr}</div>;
    if (!alertData)   return null;

    const allAlerts = alertData.alerts || [];

    // Severity helper
    const sevOf = (alert, sla) => {
      if (sla?.severity) return sla.severity;
      const l = parseInt(alert?.rule?.level || 0);
      return l >= 12 ? 'critical' : l >= 8 ? 'high' : 'medium';
    };

    // Client-side filter
    const q = alertQ.trim().toLowerCase();
    let filtered = allAlerts.filter(({ alert, sla }) => {
      if (alertSevF && sevOf(alert, sla) !== alertSevF) return false;
      if (q) {
        const sid  = (alert?.short_id || '').toLowerCase();
        const rid  = String(alert?.rule?.id || '').toLowerCase();
        const desc = (alert?.rule?.description || '').toLowerCase();
        const agt  = (alert?.agent?.name || '').toLowerCase();
        const src  = (alert?.data?.srcip || '').toLowerCase();
        if (!sid.includes(q) && !rid.includes(q) && !desc.includes(q) && !agt.includes(q) && !src.includes(q)) return false;
      }
      return true;
    });

    // Client-side sort
    const dir = alertSortDir === 'asc' ? 1 : -1;
    filtered = [...filtered].sort((a, b) => {
      const aa = a.alert, ab = b.alert, sa = a.sla, sb = b.sla;
      switch (alertSortCol) {
        case 'short_id': return dir * (aa?.short_id || '').localeCompare(ab?.short_id || '');
        case 'sev':      return dir * ((parseInt(aa?.rule?.level) || 0) - (parseInt(ab?.rule?.level) || 0));
        case 'rule':     return dir * String(aa?.rule?.id || '').localeCompare(String(ab?.rule?.id || ''));
        case 'agent':    return dir * (aa?.agent?.name || '').localeCompare(ab?.agent?.name || '');
        case 'ts':       return dir * (new Date(aa?.['@timestamp'] || 0) - new Date(ab?.['@timestamp'] || 0));
        case 'elapsed':  return dir * ((sa?.elapsed_ms || 0) - (sb?.elapsed_ms || 0));
        case 'risk':     return dir * ((sa?.breach_pct || 0) - (sb?.breach_pct || 0));
        default:         return 0;
      }
    });

    // Sortable column header
    function SortTh({ col, label, style: s }) {
      const active = alertSortCol === col;
      const arrow  = active ? (alertSortDir === 'asc' ? ' ↑' : ' ↓') : '';
      return (
        <th style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap', ...(s || {}) }}
            onClick={() => {
              if (alertSortCol === col) setAlertSortDir(d => d === 'asc' ? 'desc' : 'asc');
              else { setAlertSortCol(col); setAlertSortDir('desc'); }
            }}>
          <span style={{ color: active ? 'var(--acc)' : undefined }}>{label}{arrow}</span>
        </th>
      );
    }

    return (
      <>
        {/* Filter / search bar */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '8px 0 12px', flexWrap: 'wrap' }}>
          <input
            placeholder="Search alert ID (SOC-…), rule ID, description, agent, IP…"
            value={alertQ}
            onChange={e => setAlertQ(e.target.value)}
            style={{ flex: 1, minWidth: 240, fontSize: 12 }}
          />
          <select className="select-mini mono" value={alertSevF} onChange={e => setAlertSevF(e.target.value)}>
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
          {(alertQ || alertSevF) && (
            <button className="btn btn-ghost btn-sm" onClick={() => { setAlertQ(''); setAlertSevF(''); }}>Clear</button>
          )}
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', whiteSpace: 'nowrap' }}>
            {filtered.length !== allAlerts.length ? `${filtered.length} / ${allAlerts.length}` : allAlerts.length} alerts
          </span>
        </div>

        <div style={{ fontSize: 10, color: 'var(--fg-3)', paddingBottom: 8, display: 'flex', gap: 16 }}>
          <span>🔴 = SLA Breached &nbsp;⚠️ = At Risk (&gt;70%) &nbsp;✅ = On Track</span>
          <span style={{ marginLeft: 'auto' }}>SLA timers auto-started from alert detection time · click column headers to sort</span>
        </div>

        {filtered.length === 0 ? (
          <div className="empty mono">No alerts match current filters</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead><tr>
                <th style={{ textAlign: 'center' }}>SLA</th>
                <SortTh col="sev"      label="SEVERITY" />
                <th>ALERT</th>
                <SortTh col="rule"     label="RULE" />
                <SortTh col="agent"    label="AGENT" />
                <th>SRC IP</th>
                <SortTh col="ts"       label="DETECTED" />
                <SortTh col="short_id" label="ALERT ID" s={{ color: 'var(--acc)' }} />
                <SortTh col="elapsed"  label="ELAPSED" />
                <th>REMAINING</th>
                <SortTh col="risk"     label="RISK" />
                <th>ACTIONS</th>
              </tr></thead>
              <tbody>
                {filtered.map(({ alert, sla }, idx) => {
                  const sev      = sevOf(alert, sla);
                  const status   = sla?.status || 'running';
                  const pct      = sla?.breach_pct ?? 0;
                  const icon     = sla ? slaIcon(sla.elapsed_ms || 0, sla.response_minutes, status) : '—';
                  const rule     = alert?.rule || {};
                  const desc     = (rule.description || '').slice(0, 65);
                  const agent    = alert?.agent?.name || '—';
                  const srcIp    = alert?.data?.srcip || '—';
                  const ts       = alert?.['@timestamp'] || '';
                  const shortId  = alert?.short_id || '—';
                  const activeSla = sla && ['running','paused','breached'].includes(status);
                  return (
                    <tr key={alert?._id || idx}>
                      <td style={{ textAlign: 'center', fontSize: 15 }}>{icon}</td>
                      <td><SevChip sev={sev} /></td>
                      <td className="mono" style={{ fontSize: 11, maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={rule.description}>{desc || '—'}</td>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--acc)' }}>{rule.id || '—'}</td>
                      <td style={{ fontSize: 11, color: 'var(--fg-2)' }}>{agent}</td>
                      <td className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{srcIp}</td>
                      <td className="mono" style={{ fontSize: 10, whiteSpace: 'nowrap' }}>{fmtTs(ts)}</td>
                      <td className="mono" style={{ fontSize: 10, color: 'var(--acc)', letterSpacing: '.05em', fontWeight: 700, whiteSpace: 'nowrap' }}>{shortId}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{sla?.elapsed_human || '—'}</td>
                      <td className="mono" style={{ fontSize: 11, color: pct >= 90 ? 'var(--crit)' : pct >= 70 ? 'var(--med)' : 'var(--fg-0)' }}>{sla?.remaining_human || '—'}</td>
                      <td>{sla ? <RiskBar pct={pct} status={status} /> : <span style={{ color: 'var(--fg-3)', fontSize: 10 }}>No policy</span>}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        {activeSla && <button className="btn btn-ghost btn-sm" style={{ color: 'var(--low)', marginRight: 4 }} onClick={() => doStop(sla.id)}>✓ Resolve</button>}
                        {sla && <button className="btn btn-ghost btn-sm" onClick={() => openDetail(sla.id)}>Detail</button>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </>
    );
  }

  function TabActive() {
    if (activeLoading) return <div className="empty mono" style={{ padding: 32 }}>Loading…</div>;
    const items = activeData?.items;
    if (!items) return null;
    if (!items.length) return <div className="empty mono">No active SLAs running</div>;
    return (
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead><tr>
            <th>Entity</th><th>Type</th><th>Severity</th><th>Policy</th>
            <th>Elapsed</th><th>Remaining</th><th>Risk</th><th>Owner</th><th>Actions</th>
          </tr></thead>
          <tbody>
            {items.map(i => (
              <tr key={i.id} style={{ cursor: 'pointer' }} onClick={() => openDetail(i.id)}>
                <td><EntityLabel inst={i} /></td>
                <td style={{ fontSize: 12, color: 'var(--fg-2)' }}>{i.entity_type}</td>
                <td><SevChip sev={i.severity} /></td>
                <td style={{ fontSize: 12, color: 'var(--acc)' }}>{i.policy_name || '—'}</td>
                <td className="mono" style={{ fontSize: 12 }}>{i.elapsed_human}</td>
                <td className="mono" style={{ fontSize: 12, color: i.breach_pct >= 90 ? 'var(--crit)' : i.breach_pct >= 70 ? 'var(--med)' : 'var(--fg-0)' }}>{i.remaining_human}</td>
                <td onClick={e => e.stopPropagation()}><RiskBar pct={i.breach_pct} status={i.status} /></td>
                <td style={{ fontSize: 12, color: 'var(--fg-2)' }}>{i.owner || '—'}</td>
                <td onClick={e => e.stopPropagation()} style={{ whiteSpace: 'nowrap' }}>
                  {i.status === 'running'
                    ? <button className="btn btn-ghost btn-sm" style={{ marginRight: 4 }} onClick={() => doPause(i.id)}>Pause</button>
                    : <button className="btn btn-ghost btn-sm" style={{ marginRight: 4 }} onClick={() => doResume(i.id)}>Resume</button>}
                  <button className="btn btn-ghost btn-sm" style={{ color: 'var(--low)' }} onClick={() => doStop(i.id)}>Done</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {activeData?.total > 50 && (
          <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 12 }}>
            <button className="btn btn-ghost btn-sm" disabled={activePage <= 1} onClick={() => loadActive(activePage - 1)}>← Prev</button>
            <span className="mono dim" style={{ lineHeight: '28px', fontSize: 11 }}>Page {activePage}</span>
            <button className="btn btn-ghost btn-sm" disabled={activePage * 50 >= activeData.total} onClick={() => loadActive(activePage + 1)}>Next →</button>
          </div>
        )}
      </div>
    );
  }

  function TabBreached() {
    if (breachLoading) return <div className="empty mono" style={{ padding: 32 }}>Loading…</div>;
    const items = breachedData?.items;
    if (!items) return null;
    if (!items.length) return <div className="empty mono" style={{ color: 'var(--low)' }}>No breached SLAs — compliance is on track!</div>;
    return (
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead><tr>
            <th>Entity</th><th>Type</th><th>Severity</th><th>Policy</th>
            <th>Elapsed</th><th>Over SLA By</th><th>Owner</th><th>Actions</th>
          </tr></thead>
          <tbody>
            {items.map(i => {
              const overMins = Math.round(Math.max(0, (i.elapsed_ms || 0) - i.response_minutes * 60000) / 60000);
              return (
                <tr key={i.id} style={{ cursor: 'pointer' }} onClick={() => openDetail(i.id)}>
                  <td><EntityLabel inst={i} /></td>
                  <td style={{ fontSize: 12, color: 'var(--fg-2)' }}>{i.entity_type}</td>
                  <td><SevChip sev={i.severity} /></td>
                  <td style={{ fontSize: 12, color: 'var(--acc)' }}>{i.policy_name || '—'}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{i.elapsed_human}</td>
                  <td className="mono" style={{ fontSize: 12, color: 'var(--crit)', fontWeight: 600 }}>+{overMins}m</td>
                  <td style={{ fontSize: 12, color: 'var(--fg-2)' }}>{i.owner || '—'}</td>
                  <td onClick={e => e.stopPropagation()}>
                    <button className="btn btn-ghost btn-sm" style={{ color: 'var(--low)' }} onClick={() => doStop(i.id)}>Resolve</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {breachedData?.total > 50 && (
          <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 12 }}>
            <button className="btn btn-ghost btn-sm" disabled={breachedPage <= 1} onClick={() => loadBreached(breachedPage - 1)}>← Prev</button>
            <span className="mono dim" style={{ lineHeight: '28px', fontSize: 11 }}>Page {breachedPage}</span>
            <button className="btn btn-ghost btn-sm" disabled={breachedPage * 50 >= breachedData.total} onClick={() => loadBreached(breachedPage + 1)}>Next →</button>
          </div>
        )}
      </div>
    );
  }

  function TabAll() {
    if (allLoading) return <div className="empty mono" style={{ padding: 32 }}>Loading…</div>;
    const items = allData?.items;
    if (!items) return null;
    if (!items.length) return <div className="empty mono">No SLAs found</div>;
    return (
      <div style={{ overflowX: 'auto' }}>
        <table className="data-table">
          <thead><tr>
            <th>Entity</th><th>Type</th><th>Severity</th><th>Policy</th>
            <th>Status</th><th>Elapsed</th><th>Risk</th><th>Owner</th><th>Started</th>
          </tr></thead>
          <tbody>
            {items.map(i => (
              <tr key={i.id} style={{ cursor: 'pointer' }} onClick={() => openDetail(i.id)}>
                <td><EntityLabel inst={i} /></td>
                <td style={{ fontSize: 12, color: 'var(--fg-2)' }}>{i.entity_type}</td>
                <td><SevChip sev={i.severity} /></td>
                <td style={{ fontSize: 12, color: 'var(--acc)' }}>{i.policy_name || '—'}</td>
                <td><StatusBadge status={i.status} /></td>
                <td className="mono" style={{ fontSize: 12 }}>{i.elapsed_human}</td>
                <td>{['running','paused','breached'].includes(i.status) ? <RiskBar pct={i.breach_pct} status={i.status} /> : <span style={{ color: 'var(--fg-3)' }}>—</span>}</td>
                <td style={{ fontSize: 12, color: 'var(--fg-2)' }}>{i.owner || '—'}</td>
                <td className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>{fmtTs(i.started_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {allData?.total > 50 && (
          <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 12 }}>
            <button className="btn btn-ghost btn-sm" disabled={allPage <= 1} onClick={() => loadAll(allPage - 1)}>← Prev</button>
            <span className="mono dim" style={{ lineHeight: '28px', fontSize: 11 }}>Page {allPage} · {allData.total} total</span>
            <button className="btn btn-ghost btn-sm" disabled={allPage * 50 >= allData.total} onClick={() => loadAll(allPage + 1)}>Next →</button>
          </div>
        )}
      </div>
    );
  }

  function TabPolicies() {
    if (polLoading) return <div className="empty mono" style={{ padding: 32 }}>Loading…</div>;
    const policies = polData?.policies || [];
    return (
      <>
        {isAdmin && (
          <div style={{ marginBottom: 14 }}>
            <button className="btn btn-primary btn-sm" onClick={openNewPolicy}>+ New Policy</button>
          </div>
        )}
        <table className="data-table">
          <thead><tr>
            <th>Name</th><th>Entity Type</th><th>Severity</th>
            <th>Response</th><th>Resolution</th><th>Escalation Chain</th><th>Status</th>
            {isAdmin && <th></th>}
          </tr></thead>
          <tbody>
            {policies.map(p => {
              const chain = Array.isArray(p.escalation_chain) ? p.escalation_chain : [];
              const chainStr = chain.map(e => `${e.at_pct}% → ${e.action}`).join(', ') || '—';
              return (
                <tr key={p.id}>
                  <td style={{ fontWeight: 600, color: 'var(--acc)' }}>{p.name}</td>
                  <td style={{ fontSize: 12, color: 'var(--fg-2)' }}>{p.entity_type}</td>
                  <td>{p.severity !== 'all' ? <SevChip sev={p.severity} /> : <span style={{ color: 'var(--fg-3)' }}>all</span>}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{p.response_minutes}m</td>
                  <td className="mono" style={{ fontSize: 12 }}>{p.resolution_minutes >= 60 ? Math.round(p.resolution_minutes / 60) + 'h' : p.resolution_minutes + 'm'}</td>
                  <td style={{ fontSize: 11, color: 'var(--fg-2)' }}>{chainStr}</td>
                  <td>{p.active ? <span style={{ color: 'var(--low)', fontSize: 11, fontWeight: 700 }}>ACTIVE</span> : <span style={{ color: 'var(--fg-3)', fontSize: 11 }}>OFF</span>}</td>
                  {isAdmin && (
                    <td style={{ whiteSpace: 'nowrap' }}>
                      <button className="btn btn-ghost btn-sm" style={{ marginRight: 4 }} onClick={() => openEditPolicy(p)}>Edit</button>
                      <button className="btn btn-ghost btn-sm" style={{ color: 'var(--crit)' }} onClick={() => doDeletePolicy(p.id)}>Del</button>
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </>
    );
  }

  // ── Detail modal content ─────────────────────────────────────────
  function DetailModal() {
    if (!showDetail) return null;
    const inst = detailInst;
    const isActive = inst && ['running','paused','breached'].includes(inst.status);
    return (
      <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
           onClick={() => setShowDetail(false)}>
        <div style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 8, width: '90%', maxWidth: 680, maxHeight: '85vh', display: 'flex', flexDirection: 'column' }}
             onClick={e => e.stopPropagation()}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--ln)' }}>
            <span style={{ fontWeight: 700, fontSize: 15 }}>SLA Detail &amp; Audit Log</span>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowDetail(false)}>✕</button>
          </div>
          <div style={{ overflowY: 'auto', padding: 20, flex: 1 }}>
            {detailLoad && <div className="empty mono">Loading…</div>}
            {!detailLoad && !inst && <div className="empty mono" style={{ color: 'var(--crit)' }}>Failed to load SLA instance</div>}
            {inst && (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20, paddingBottom: 16, borderBottom: '1px solid var(--ln)' }}>
                  {[
                    ['Entity', <span style={{ color: 'var(--acc)' }}>
                      {inst.entity_type}:{' '}
                      {inst.entity_type === 'alert' && inst.entity_short_id
                        ? <span className="mono" style={{ fontWeight: 700, letterSpacing: '.05em' }}>{inst.entity_short_id}</span>
                        : <span className="mono">{inst.entity_id}</span>}
                      {inst.entity_label && <span style={{ color: 'var(--fg-2)', fontSize: 12, display: 'block', marginTop: 2 }}>{inst.entity_label}</span>}
                    </span>],
                    ['Policy',           inst.policy_name || 'Custom'],
                    ['Status',           <StatusBadge status={inst.status} />],
                    ['Severity',         <SevChip sev={inst.severity} />],
                    ['Elapsed / Window', <span className="mono">{inst.elapsed_human} / {inst.response_minutes}m</span>],
                    ['Remaining',        <span className="mono">{isActive ? inst.remaining_human : '—'}</span>],
                    ['Breach Risk',      (isActive || inst.status === 'breached') ? <RiskBar pct={inst.breach_pct} status={inst.status} /> : <span style={{ color: 'var(--fg-3)' }}>—</span>],
                    ['Owner',            <span style={{ color: 'var(--fg-2)' }}>{inst.owner || '—'}</span>],
                  ].map(([label, val]) => (
                    <div key={label}>
                      <div style={{ color: 'var(--fg-3)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 3 }}>{label}</div>
                      <div>{val}</div>
                    </div>
                  ))}
                </div>
                {isActive && (
                  <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
                    {inst.status === 'running' && <button className="btn btn-ghost btn-sm" onClick={() => doPause(inst.id, true)}>Pause Timer</button>}
                    {inst.status === 'paused'  && <button className="btn btn-ghost btn-sm" onClick={() => doResume(inst.id, true)}>Resume Timer</button>}
                    <button className="btn btn-ghost btn-sm" style={{ color: 'var(--low)' }} onClick={() => doStop(inst.id, true)}>Mark Resolved</button>
                    <button className="btn btn-ghost btn-sm" style={{ color: 'var(--crit)' }} onClick={() => doCancel(inst.id, true)}>Cancel SLA</button>
                  </div>
                )}
                <div style={{ color: 'var(--fg-3)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 10 }}>Audit Log</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {detailEvts.length === 0
                    ? <div className="mono dim" style={{ fontSize: 12 }}>No events recorded yet</div>
                    : detailEvts.map((e, i) => (
                      <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'baseline', fontSize: 12, padding: '6px 10px', background: 'var(--bg-3)', borderRadius: 4, borderLeft: `2px solid ${e.event_type.includes('breach') ? 'var(--crit)' : e.event_type.includes('thresh') ? 'var(--med)' : 'var(--ln)'}` }}>
                        <span className="mono dim" style={{ whiteSpace: 'nowrap', flexShrink: 0 }}>{fmtTs(e.created_at)}</span>
                        <span className="mono" style={{ color: 'var(--acc)', fontWeight: 700, textTransform: 'uppercase', fontSize: 10, whiteSpace: 'nowrap' }}>{e.event_type}</span>
                        {e.actor  && <span style={{ color: 'var(--fg-2)' }}>{e.actor}</span>}
                        {e.reason && <span style={{ color: 'var(--fg-3)' }}>{e.reason}</span>}
                      </div>
                    ))
                  }
                </div>
              </>
            )}
          </div>
          <div style={{ padding: '12px 20px', borderTop: '1px solid var(--ln)' }}>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowDetail(false)}>Close</button>
          </div>
        </div>
      </div>
    );
  }

  function StartModal() {
    if (!showStart) return null;
    return (
      <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
           onClick={() => setShowStart(false)}>
        <div style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 8, width: '90%', maxWidth: 480 }}
             onClick={e => e.stopPropagation()}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--ln)' }}>
            <span style={{ fontWeight: 700 }}>Start SLA Timer</span>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowStart(false)}>✕</button>
          </div>
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>Entity Type</div>
              <select className="select-mini mono" value={startType} onChange={e => setStartType(e.target.value)} style={{ width: '100%' }}>
                <option value="alert">SIEM Alert</option>
                <option value="investigation">Investigation</option>
                <option value="case">Case</option>
              </select>
            </div>
            <div>
              <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>Entity ID</div>
              <input className="mono" placeholder="e.g. 42, case-1234, or OpenSearch alert ID" value={startId} onChange={e => setStartId(e.target.value)} style={{ width: '100%' }} />
            </div>
            <div>
              <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>Label (optional)</div>
              <input className="mono" placeholder="e.g. Brute force attack on DC01" value={startLabel} onChange={e => setStartLabel(e.target.value)} style={{ width: '100%' }} />
            </div>
            <div>
              <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>Severity</div>
              <select className="select-mini mono" value={startSev} onChange={e => setStartSev(e.target.value)} style={{ width: '100%' }}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, padding: '12px 20px', borderTop: '1px solid var(--ln)' }}>
            <button className="btn btn-ghost" onClick={() => setShowStart(false)}>Cancel</button>
            <button className="btn btn-primary" onClick={doStartManual}>Start SLA</button>
          </div>
        </div>
      </div>
    );
  }

  function PolicyModal() {
    if (!showPolModal) return null;
    return (
      <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.65)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
           onClick={() => setShowPol(false)}>
        <div style={{ background: 'var(--bg-2)', border: '1px solid var(--ln)', borderRadius: 8, width: '90%', maxWidth: 520 }}
             onClick={e => e.stopPropagation()}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--ln)' }}>
            <span style={{ fontWeight: 700 }}>{polEditId ? 'Edit SLA Policy' : 'New SLA Policy'}</span>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowPol(false)}>✕</button>
          </div>
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>Policy Name *</div>
              <input className="mono" placeholder="e.g. Critical Incident SLA" value={polName} onChange={e => setPolName(e.target.value)} style={{ width: '100%' }} />
            </div>
            <div>
              <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>Description</div>
              <input className="mono" placeholder="Optional description" value={polDesc} onChange={e => setPolDesc(e.target.value)} style={{ width: '100%' }} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>Entity Type</div>
                <select className="select-mini mono" value={polEntity} onChange={e => setPolEntity(e.target.value)} style={{ width: '100%' }}>
                  <option value="all">All</option>
                  <option value="alert">Alert</option>
                  <option value="investigation">Investigation</option>
                  <option value="case">Case</option>
                </select>
              </div>
              <div>
                <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>Severity</div>
                <select className="select-mini mono" value={polSev} onChange={e => setPolSev(e.target.value)} style={{ width: '100%' }}>
                  <option value="all">All</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>Response Window (minutes) *</div>
                <input type="number" min="1" className="mono" value={polResp} onChange={e => setPolResp(e.target.value)} style={{ width: '100%' }} />
              </div>
              <div>
                <div className="mono dim" style={{ fontSize: 11, marginBottom: 4 }}>Resolution Window (minutes) *</div>
                <input type="number" min="1" className="mono" value={polResol} onChange={e => setPolResol(e.target.value)} style={{ width: '100%' }} />
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, padding: '12px 20px', borderTop: '1px solid var(--ln)' }}>
            <button className="btn btn-ghost" onClick={() => setShowPol(false)}>Cancel</button>
            <button className="btn btn-primary" onClick={doSavePolicy}>Save Policy</button>
          </div>
        </div>
      </div>
    );
  }

  // ── Render ───────────────────────────────────────────────────────
  const mttrStr  = dash?.mttr_minutes != null ? dash.mttr_minutes + 'm' : '—';
  const complStr = dash?.compliance_rate != null ? dash.compliance_rate + '%' : '—';

  return (
    <div className="page">
      <DetailModal />
      <StartModal />
      <PolicyModal />
      <Topbar
        title="SLA Management"
        sub="Track response &amp; resolution SLAs across investigations, cases, and SIEM alerts"
        actions={<>
          <button className="btn btn-ghost btn-sm" onClick={refresh}><Icon.refresh width="13" height="13" /></button>
          <button className="btn btn-primary" onClick={() => setShowStart(true)}>
            <Icon.plus width="13" height="13" /> Start SLA
          </button>
        </>}
      />
      <div className="page-body">
        {/* KPI strip */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12, marginBottom: 16 }}>
          {[
            { label: 'Active SLAs',      value: dash?.active ?? '…',   sub: 'running timers',        sev: undefined },
            { label: 'Breached',         value: dash?.breached ?? '…', sub: 'past deadline',          sev: dash?.breached > 0 ? 'critical' : undefined },
            { label: 'Paused',           value: dash?.paused ?? '…',   sub: 'suspended timers',       sev: undefined },
            { label: 'Compliance (30d)', value: complStr,               sub: '% resolved on time',    sev: undefined },
            { label: 'Avg MTTR (30d)',   value: mttrStr,                sub: 'mean time to resolve',  sev: undefined },
          ].map(k => <KpiCard key={k.label} label={k.label} value={k.value} sub={k.sub} sev={k.sev} />)}
        </div>

        {/* Tabs */}
        <Card
          title="SLA Tracker"
          actions={<>
            {tab === 'alerts' && (
              <select className="select-mini mono" value={alertHrs} onChange={e => { setAlertHrs(e.target.value); loadAlerts(e.target.value); }}
                style={{ marginRight: 8 }}>
                <option value="1">Last 1h</option>
                <option value="6">Last 6h</option>
                <option value="24">Last 24h</option>
                <option value="48">Last 48h</option>
                <option value="168">Last 7d</option>
              </select>
            )}
            {tab === 'all' && (
              <>
                <select className="select-mini mono" value={allStatus} onChange={e => { setAllStatus(e.target.value); loadAll(1, e.target.value); }} style={{ marginRight: 6 }}>
                  <option value="">All statuses</option>
                  <option value="running">Running</option>
                  <option value="paused">Paused</option>
                  <option value="breached">Breached</option>
                  <option value="completed">Completed</option>
                  <option value="cancelled">Cancelled</option>
                </select>
                <select className="select-mini mono" value={allType} onChange={e => { setAllType(e.target.value); loadAll(1, allStatus, e.target.value); }} style={{ marginRight: 8 }}>
                  <option value="">All types</option>
                  <option value="alert">Alert</option>
                  <option value="investigation">Investigation</option>
                  <option value="case">Case</option>
                </select>
              </>
            )}
            {TABS.map(t => (
              <button key={t} className={`seg-btn ${tab === t ? 'on' : ''}`} onClick={() => setTab(t)}>{TAB_LABELS[t]}</button>
            ))}
          </>}
        >
          {tab === 'alerts'   && <TabAlerts />}
          {tab === 'active'   && <TabActive />}
          {tab === 'breached' && <TabBreached />}
          {tab === 'all'      && <TabAll />}
          {tab === 'policies' && <TabPolicies />}
        </Card>
      </div>
    </div>
  );
}

// ============= PAGE EVIDENCE =============
function formatBytes(b) {
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024)    return (b / 1024).toFixed(1) + ' KB';
  return b + ' B';
}

function PageEvidence() {
  const [files, setFiles]   = useStateADV([]);
  const [search, setSearch] = useStateADV('');
  const [loading, setLoad]  = useStateADV(false);
  const fileRef             = useRefADV(null);

  useEffectADV(() => {
    window.SOC_API.get('/api/evidence').then(d => {
      const arr = d?.files || d?.items || (Array.isArray(d) ? d : null);
      if (arr) setFiles(arr);
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
function PageArtifacts() {
  const [tab,        setTab]    = useStateADV('overview');
  const [stats,      setStats]  = useStateADV({ total: 0, malicious: 0, suspicious: 0, enriched: 0, byType: [], sources: [] });
  const [jobStatus,  setJobs]   = useStateADV({ ingest: {}, enrich: {} });
  const [iocs,       setIocs]   = useStateADV([]);
  const [iocTotal,   setIocTotal] = useStateADV(0);
  const [iocPage,    setIocPage]  = useStateADV(1);
  const [q,          setQ]      = useStateADV('');
  const [typeFilter, setTypeFilter] = useStateADV('');
  const [loading,    setLoading]  = useStateADV(false);
  const [newIoc,     setNewIoc]   = useStateADV('');
  const [newType,    setNewType]  = useStateADV('ip');
  const [extractText, setET]    = useStateADV('');
  const [extracted,  setExtracted] = useStateADV([]);
  const [whitelist,  setWl]     = useStateADV([]);
  const [wlInput,    setWlInput] = useStateADV('');
  const [wlType,     setWlType] = useStateADV('ip');
  const [wlCat,      setWlCat]  = useStateADV('internal');
  const [wlReason,   setWlReason] = useStateADV('');
  const [enriching,  setEnriching] = useStateADV({});

  function loadStats() {
    window.SOC_API.get('/api/ioc-store/stats').then(d => {
      if (!d || d.error) return;
      const s = d.summary || {};
      setStats({
        total:     parseInt(s.total || 0),
        malicious: parseInt(s.malicious || 0),
        suspicious: parseInt(s.suspicious || 0),
        enriched:  parseInt(s.enriched || 0),
        byType:    d.by_type || [],
        sources:   d.enrichment_sources || [],
      });
      setJobs({ ingest: d.ingest || {}, enrich: d.enrich || {} });
    });
  }

  async function loadIOCs(pg = 1, search = q, tf = typeFilter) {
    setLoading(true);
    const p = new URLSearchParams({ page: pg, page_size: 50 });
    if (search) p.set('q', search);
    if (tf)     p.set('ioc_type', tf);
    const d = await window.SOC_API.get('/api/ioc-store?' + p);
    setLoading(false);
    if (d && !d.error) { setIocs(d.items || []); setIocTotal(d.total || 0); setIocPage(pg); }
  }

  function loadWhitelist() {
    window.SOC_API.get('/api/ioc-whitelist?page_size=100').then(d => {
      if (d?.items) setWl(d.items);
    });
  }

  useEffectADV(() => { loadStats(); loadIOCs(1); loadWhitelist(); }, []);

  async function ingestAlerts() {
    const r = await window.SOC_API.post('/api/ioc-store/ingest-alerts', {});
    window.socToast?.({ title: 'Ingest started', sub: r?.status === 'already_running' ? 'Already running' : 'Ingesting IOCs from SIEM alerts…', tone: 'ok' });
    setTimeout(loadStats, 4000);
  }

  async function enrichAll() {
    const r = await window.SOC_API.post('/api/ioc-store/enrich-all', {});
    window.socToast?.({ title: 'Enrich started', sub: r?.status === 'already_running' ? 'Already running' : `Running enrichment (batch: ${r?.batch_size || 10})`, tone: 'info' });
    setTimeout(loadStats, 4000);
  }

  async function addIoc() {
    if (!newIoc.trim()) return;
    const r = await window.SOC_API.post('/api/ioc-store', { indicator: newIoc.trim(), ioc_type: newType });
    if (r && !r.error) {
      window.socToast?.({ title: 'IOC added', sub: newIoc.trim(), tone: 'ok' });
      setNewIoc('');
      loadIOCs(iocPage); loadStats();
    } else {
      window.socToast?.({ title: 'Error', sub: r?.error || 'Failed to add IOC', tone: 'error' });
    }
  }

  async function enrichIoc(ioc) {
    setEnriching(e => ({ ...e, [ioc.id]: true }));
    const r = await window.SOC_API.post(`/api/ioc-store/${ioc.id}/enrich`, {});
    setEnriching(e => ({ ...e, [ioc.id]: false }));
    if (r && !r.error) {
      window.socToast?.({ title: 'Enriched', sub: ioc.indicator, tone: 'ok' });
      loadIOCs(iocPage);
    } else {
      window.socToast?.({ title: 'Enrich failed', sub: r?.error || 'Check TI API keys in Settings', tone: 'error' });
    }
  }

  async function deleteIoc(ioc) {
    const r = await window.SOC_API.del(`/api/ioc-store/${ioc.id}`);
    if (r !== null) {
      window.socToast?.({ title: 'IOC deleted', sub: ioc.indicator, tone: 'ok' });
      loadIOCs(iocPage); loadStats();
    }
  }

  async function extractIOCs() {
    if (!extractText.trim()) return;
    const r = await window.SOC_API.post('/api/ioc-store/extract', { text: extractText });
    if (r) {
      setExtracted(r.extracted || []);
      window.socToast?.({ title: 'Extraction done', sub: `${r.count || 0} IOC${r.count !== 1 ? 's' : ''} found`, tone: r.count > 0 ? 'ok' : 'info' });
    }
  }

  async function saveExtractedIoc(ioc) {
    const r = await window.SOC_API.post('/api/ioc-store', { indicator: ioc.indicator, ioc_type: ioc.ioc_type });
    if (r && !r.error) { window.socToast?.({ title: 'Saved', sub: ioc.indicator, tone: 'ok' }); loadStats(); }
    else window.socToast?.({ title: 'Error', sub: r?.error || 'Failed', tone: 'error' });
  }

  async function addWhitelist() {
    if (!wlInput.trim()) return;
    const r = await window.SOC_API.post('/api/ioc-whitelist', {
      indicator: wlInput.trim(), ioc_type: wlType, category: wlCat, reason: wlReason,
    });
    if (r && !r.error) {
      window.socToast?.({ title: 'Whitelisted', sub: wlInput.trim(), tone: 'ok' });
      setWlInput(''); setWlReason('');
      loadWhitelist();
      if (r.risk_warning) window.socToast?.({ title: 'Risk warning', sub: r.risk_warning, tone: 'warn' });
    } else {
      window.socToast?.({ title: 'Error', sub: r?.error || 'Failed', tone: 'error' });
    }
  }

  const repTone  = r => ({ malicious: 'crit', suspicious: 'warn', trusted: 'ok' })[r] || 'dim';
  const scoreCol = s => s >= 80 ? 'critical' : s >= 60 ? 'high' : s >= 40 ? 'medium' : 'low';

  const IocTable = ({ rows, actions = true }) => (
    <table className="data-table">
      <thead><tr>
        <th>INDICATOR</th><th>TYPE</th><th>REPUTATION</th><th>RISK</th><th>SOURCE</th><th>ENRICHED</th><th>LAST SEEN</th>
        {actions && <th></th>}
      </tr></thead>
      <tbody>
        {rows.length === 0
          ? <tr><td colSpan={actions ? 8 : 7} className="empty mono" style={{ textAlign: 'center', padding: 20 }}>No IOCs found.</td></tr>
          : rows.map(ioc => (
            <tr key={ioc.id}>
              <td className="mono" style={{ color: 'var(--acc)', fontSize: 12 }}>{ioc.indicator}</td>
              <td><Chip mono>{ioc.ioc_type}</Chip></td>
              <td><Chip mono tone={repTone(ioc.reputation)}>{ioc.reputation || 'unknown'}</Chip></td>
              <td>
                <div className="bar-wrap">
                  <div className="bar" data-sev={scoreCol(ioc.risk_score)} style={{ width: `${ioc.risk_score}%` }}/>
                  <span className="bar-val mono">{ioc.risk_score}</span>
                </div>
              </td>
              <td className="mono dim" style={{ fontSize: 11 }}>{ioc.source || '—'}</td>
              <td className="mono dim" style={{ fontSize: 11 }}>{ioc.enriched_at ? window.SOC_API.relTs(ioc.enriched_at) : '—'}</td>
              <td className="mono dim" style={{ fontSize: 11 }}>{window.SOC_API.relTs(ioc.last_seen)}</td>
              {actions && (
                <td style={{ whiteSpace: 'nowrap' }}>
                  <button className="btn btn-ghost btn-sm" disabled={enriching[ioc.id]}
                    onClick={() => enrichIoc(ioc)}>
                    {enriching[ioc.id] ? '…' : 'Enrich'}
                  </button>
                  <button className="btn btn-ghost btn-sm"
                    onClick={() => { setWlInput(ioc.indicator); setWlType(ioc.ioc_type); setTab('whitelist'); }}>
                    WL
                  </button>
                  <button className="btn btn-ghost btn-sm"
                    style={{ color: 'var(--crit)', opacity: .7 }}
                    onClick={() => deleteIoc(ioc)}>
                    ✕
                  </button>
                </td>
              )}
            </tr>
          ))
        }
      </tbody>
    </table>
  );

  return (
    <div className="page">
      <Topbar
        title="Artifacts &amp; IOC Intelligence"
        sub="IOC store · enrichment · file analysis · threat hunting"
        actions={<>
          <button className="btn btn-ghost" onClick={ingestAlerts}>
            <Icon.refresh width="13" height="13"/>
            {jobStatus.ingest?.running ? ' Ingesting…' : ' Ingest from Alerts'}
          </button>
          <button className="btn btn-primary" onClick={enrichAll}>
            <Icon.brain width="13" height="13"/>
            {jobStatus.enrich?.running ? ' Enriching…' : ' Enrich All'}
          </button>
        </>}
      />
      <div className="page-body">
        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
          <KpiCard label="Total IOCs"   value={stats.total}     sub="in store" />
          <KpiCard label="Malicious"    value={stats.malicious} sub="confirmed threats" sev="critical" />
          <KpiCard label="Suspicious"   value={stats.suspicious} sub="needs review" sev="high" />
          <KpiCard label="Enriched"     value={stats.enriched}  sub="TI lookups done" />
        </div>

        <Card actions={<>
          {['overview','ioc-intel','file-analysis','enrichment','whitelist'].map(t => (
            <button key={t} className={`seg-btn ${tab === t ? 'on' : ''}`} onClick={() => setTab(t)}
              style={{ fontSize: '0.7rem' }}>{t}</button>
          ))}
        </>}>

          {tab === 'overview' && (
            <div>
              {loading
                ? <div className="loading mono" style={{ padding: 20 }}>Loading IOCs…</div>
                : <IocTable rows={iocs.slice(0, 15)} actions={false} />
              }
              {stats.byType.length > 0 && (
                <div style={{ marginTop: 14, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {stats.byType.map(bt => (
                    <Chip key={bt.ioc_type} mono>{bt.ioc_type}: {bt.cnt}</Chip>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === 'ioc-intel' && (
            <div>
              {/* Search + filter bar */}
              <div style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'center' }}>
                <input placeholder="Search indicator, notes…" value={q}
                  onChange={e => setQ(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && loadIOCs(1, q, typeFilter)}
                  className="mono" style={{ flex: 1 }} />
                <select className="select-mini mono" value={typeFilter}
                  onChange={e => { setTypeFilter(e.target.value); loadIOCs(1, q, e.target.value); }}>
                  <option value="">All types</option>
                  {['ip','domain','url','md5','sha256','sha1'].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <button className="btn btn-primary" onClick={() => loadIOCs(1, q, typeFilter)}>
                  <Icon.search width="13" height="13"/> Search
                </button>
              </div>
              {/* Add IOC bar */}
              <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
                <input placeholder="New IOC indicator (IP, domain, hash…)" value={newIoc}
                  onChange={e => setNewIoc(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addIoc()}
                  className="mono" style={{ flex: 1 }} />
                <select className="select-mini mono" value={newType} onChange={e => setNewType(e.target.value)}>
                  {['ip','domain','url','md5','sha256','sha1'].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <button className="btn btn-ghost" onClick={addIoc}>
                  <Icon.plus width="13" height="13"/> Add IOC
                </button>
              </div>
              {loading
                ? <div className="loading mono" style={{ padding: 20 }}>Loading…</div>
                : <IocTable rows={iocs} actions={true} />
              }
              {/* Pagination */}
              {iocTotal > 50 && (
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 10 }}>
                  <button className="btn btn-ghost btn-sm" disabled={iocPage <= 1}
                    onClick={() => loadIOCs(iocPage - 1)}>← Prev</button>
                  <span className="mono dim" style={{ fontSize: 11 }}>
                    Page {iocPage} · {iocTotal} total
                  </span>
                  <button className="btn btn-ghost btn-sm" disabled={iocPage * 50 >= iocTotal}
                    onClick={() => loadIOCs(iocPage + 1)}>Next →</button>
                </div>
              )}
            </div>
          )}

          {tab === 'file-analysis' && (
            <div>
              <div className="card-sub" style={{ marginBottom: 8 }}>Paste log output, email headers, or report text to extract IOCs automatically</div>
              <textarea rows="7" value={extractText} onChange={e => setET(e.target.value)}
                placeholder="Paste log output, email headers, report text, threat intel report…"
                style={{ width: '100%', background: 'var(--bg2)', border: '1px solid var(--b2)', borderRadius: 6, padding: 10, color: 'var(--txt)', fontFamily: 'var(--fm)', fontSize: '0.82rem' }} />
              <div style={{ marginTop: 8 }}>
                <button className="btn btn-primary" onClick={extractIOCs} disabled={!extractText.trim()}>
                  <Icon.search width="13" height="13"/> Extract IOCs
                </button>
              </div>
              {extracted.length > 0 && (
                <div style={{ marginTop: 14 }}>
                  <div className="card-sub" style={{ marginBottom: 6 }}>{extracted.length} IOCs extracted — click Save to add to store</div>
                  <table className="data-table">
                    <thead><tr><th>INDICATOR</th><th>TYPE</th><th></th></tr></thead>
                    <tbody>
                      {extracted.map((ioc, i) => (
                        <tr key={i}>
                          <td className="mono" style={{ color: 'var(--acc)' }}>{ioc.indicator}</td>
                          <td><Chip mono>{ioc.ioc_type}</Chip></td>
                          <td>
                            <button className="btn btn-ghost btn-sm" onClick={() => saveExtractedIoc(ioc)}>Save</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {tab === 'enrichment' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', gap: 10 }}>
                <div style={{ flex: 1, background: 'var(--bg2)', border: '1px solid var(--b1)', borderRadius: 6, padding: 12 }}>
                  <div className="card-sub">Ingest job</div>
                  <div className="mono" style={{ fontSize: 11, marginTop: 4 }}>
                    Status: <span style={{ color: jobStatus.ingest?.running ? 'var(--acc)' : 'var(--fg-3)' }}>
                      {jobStatus.ingest?.running ? 'running' : 'idle'}
                    </span>
                    {jobStatus.ingest?.last_run && <><br/>Last run: {window.SOC_API.relTs(jobStatus.ingest.last_run)}</>}
                    {jobStatus.ingest?.last_new != null && <><br/>Last ingested: {jobStatus.ingest.last_new} new IOCs</>}
                  </div>
                </div>
                <div style={{ flex: 1, background: 'var(--bg2)', border: '1px solid var(--b1)', borderRadius: 6, padding: 12 }}>
                  <div className="card-sub">Enrich job</div>
                  <div className="mono" style={{ fontSize: 11, marginTop: 4 }}>
                    Status: <span style={{ color: jobStatus.enrich?.running ? 'var(--acc)' : 'var(--fg-3)' }}>
                      {jobStatus.enrich?.running ? 'running' : 'idle'}
                    </span>
                    {jobStatus.enrich?.last_run && <><br/>Last run: {window.SOC_API.relTs(jobStatus.enrich.last_run)}</>}
                    {jobStatus.enrich?.queue != null && <><br/>Queue: {jobStatus.enrich.queue} pending</>}
                  </div>
                </div>
              </div>
              <div className="card-sub">Configured TI sources</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {stats.sources.map(src => (
                  <Chip key={src.name} mono tone={src.configured ? 'ok' : 'dim'}>
                    <span className={`pip pip-${src.configured ? 'ok' : 'dim'}`}/> {src.name}
                  </Chip>
                ))}
              </div>
            </div>
          )}

          {tab === 'whitelist' && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto auto', gap: 8, marginBottom: 12 }}>
                <input placeholder="Indicator to whitelist" value={wlInput}
                  onChange={e => setWlInput(e.target.value)} className="mono" />
                <select className="select-mini mono" value={wlType} onChange={e => setWlType(e.target.value)}>
                  {['ip','domain','url','md5','sha256'].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <select className="select-mini mono" value={wlCat} onChange={e => setWlCat(e.target.value)}>
                  {['internal','scanner','trusted_vendor','false_positive','other'].map(c => <option key={c} value={c}>{c}</option>)}
                </select>
                <button className="btn btn-ghost" onClick={addWhitelist} disabled={!wlInput.trim()}>
                  <Icon.plus width="13" height="13"/> Whitelist
                </button>
              </div>
              {wlInput && (
                <input placeholder="Reason (optional)" value={wlReason}
                  onChange={e => setWlReason(e.target.value)}
                  style={{ width: '100%', marginBottom: 12, background: 'var(--bg2)', border: '1px solid var(--b1)', borderRadius: 4, padding: '6px 10px', color: 'var(--txt)', fontFamily: 'var(--fm)', fontSize: '0.82rem' }} />
              )}
              {whitelist.length === 0
                ? <div className="empty mono" style={{ padding: 20 }}>No whitelisted indicators.</div>
                : <table className="data-table">
                    <thead><tr><th>INDICATOR</th><th>TYPE</th><th>CATEGORY</th><th>REASON</th><th>ADDED BY</th><th>CREATED</th></tr></thead>
                    <tbody>
                      {whitelist.map(w => (
                        <tr key={w.id}>
                          <td className="mono" style={{ color: 'var(--acc)' }}>{w.indicator}</td>
                          <td><Chip mono>{w.ioc_type}</Chip></td>
                          <td className="mono dim">{w.category}</td>
                          <td style={{ fontSize: 12 }}>{w.reason || '—'}</td>
                          <td className="mono dim">{w.added_by}</td>
                          <td className="mono dim">{window.SOC_API.relTs(w.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
              }
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

// ============= PAGE USERS =============
const ROLE_LABEL = { admin: 'Administrator', l3: 'Senior Analyst', l2: 'Analyst L2', l1: 'Analyst L1' };
const ROLE_TONE  = { admin: 'crit', l3: 'ok', l2: 'info', l1: 'dim' };

function PageUsers() {
  const [users, setUsers]     = useStateADV([]);
  const [showForm, setForm]   = useStateADV(false);
  const [newUser, setNewUser] = useStateADV('');
  const [newPass, setNewPass] = useStateADV('');
  const [newRole, setNewRole] = useStateADV('l1');
  const [editId, setEditId]   = useStateADV(null);
  const [editRole, setEditRole] = useStateADV('l1');

  useEffectADV(() => {
    window.SOC_API.get('/api/users').then(d => {
      const arr = d?.users || d?.items || (Array.isArray(d) ? d : null);
      if (arr) setUsers(arr);
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
    setHealth(r || { status: 'healthy', tools: 6, redis: true, openai: true });
    setChecking(false);
  }

  async function investigate() {
    const tgt = target.trim();
    const ctx = context.trim();
    if (!tgt && !ctx) {
      window.socToast?.({ title: 'Nothing to investigate', sub: 'Enter a target (IP / host / username) or describe the query in the context box', tone: 'error' });
      return;
    }
    setOutput('');
    setStream(true);
    const prompt = tgt
      ? `Investigate ${itype}: ${tgt}${ctx ? '\n\nContext: ' + ctx : ''}`
      : ctx;
    const r = await window.SOC_API.post('/api/ai/investigate', { prompt });
    setStream(false);
    if (!r || r.error) {
      window.socToast?.({ title: 'Investigation failed', sub: r?.error || 'Could not reach AI engine', tone: 'error' });
      return;
    }
    setOutput(r.response || r.output || r.text || '(No response)');
  }

  const healthTone = h => h?.status === 'healthy' ? 'ok' : h?.status === 'degraded' ? 'warn' : 'crit';

  return (
    <div className="page">
      <Topbar
        title="LangChain Agent"
        sub="ReAct investigation engine · LLM Engine · 6 tools"
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
              <li><span className="card-sub">Model</span><div className="mono">LLM</div></li>
              <li><span className="card-sub">Tools</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                  {TOOLS.map(t => <Chip key={t} mono>{t}</Chip>)}
                </div>
              </li>
              <li><span className="card-sub">Redis cache</span>
                <div><Chip mono tone={health?.redis !== false ? 'ok' : 'crit'}>{health?.redis !== false ? 'connected' : 'unavailable'}</Chip></div>
              </li>
              <li><span className="card-sub">LLM Engine</span>
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
            <textarea rows="3" value={context} onChange={e => setContext(e.target.value)} placeholder="Context or full query — e.g. 'search alerts containing admin', 'possible C2 beacon from this host', 'any lateral movement in last 24h?'" style={{ width: '100%', background: 'var(--bg2)', border: '1px solid var(--b2)', borderRadius: 6, padding: 10, color: 'var(--txt)', fontFamily: 'var(--fm)', fontSize: '0.82rem', marginBottom: 10 }} />
            {streaming && !output && (
              <div style={{ padding: '18px 12px', display: 'flex', alignItems: 'center', gap: 10, color: 'var(--fg-2)', fontFamily: 'var(--fm)', fontSize: '0.82rem', background: 'var(--bg)', border: '1px solid var(--b1)', borderRadius: 6 }}>
                <span style={{ animation: 'spin 1s linear infinite', display: 'inline-block' }}>⟳</span>
                Running ReAct agent — this may take up to 60 s…
              </div>
            )}
            {output && (
              <div className="inv-output">
                <div dangerouslySetInnerHTML={{ __html: window.renderMd ? window.renderMd(output) : output }} />
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

// ============= PAGE LOG SOURCES =============
function srcStatus(s) {
  if (!s.last_seen) return 'inactive';
  const ageMin = (Date.now() - new Date(s.last_seen).getTime()) / 60000;
  // Cloud API sources (CloudTrail, Office 365, Azure, etc.) are event-driven —
  // gaps of many hours are normal when there's no cloud activity.
  // Use much wider thresholds so a quiet period doesn't falsely flag them.
  const isCloud = s.type === 'cloud_api' || s.protocol === 'api' || s.source_ip === 'cloud';
  const warnMin    = isCloud ? 1440 : 60;   // cloud: 24h  agent: 1h
  const inactiveMin= isCloud ? 4320 : 1440; // cloud: 3d   agent: 24h
  if (ageMin < warnMin)     return 'active';
  if (ageMin < inactiveMin) return 'warning';
  return 'inactive';
}
function srcTone(s) {
  const st = typeof s === 'string' ? s : srcStatus(s);
  return st === 'active' ? 'ok' : st === 'warning' ? 'warn' : 'crit';
}

function PageLogSources() {
  const [tab, setTab]         = useStateADV('inventory');
  const [sources, setSrc]     = useStateADV([]);
  const [summary, setSummary] = useStateADV(null);
  const [insights, setInsights] = useStateADV([]);
  const [onboard, setOnb]     = useStateADV([]);
  const [aiResult, setAiResult] = useStateADV(null);
  const [loading, setLoad]    = useStateADV(false);
  const [analyzing, setAna]   = useStateADV(false);
  const [pending, setPending] = useStateADV(false);

  useEffectADV(() => { loadSources(); }, []);

  async function loadSources() {
    setLoad(true);
    const d = await window.SOC_API.get('/api/log-sources');
    setLoad(false);
    if (!d || d.error) return;
    if (d.pending) { setPending(true); setTimeout(loadSources, 5000); return; }
    setPending(false);
    setSrc(d.sources || []);
    setSummary(d.summary || null);
    setInsights(d.insights || []);
  }

  async function loadHistory() {
    const d = await window.SOC_API.get('/api/log-sources/history?page_size=100');
    if (d?.items) setOnb(d.items);
  }

  useEffectADV(() => { if (tab === 'onboarding') loadHistory(); }, [tab]);

  async function runAiAnalysis() {
    if (!sources.length) { window.socToast?.({ title: 'No sources loaded', sub: 'Refresh first', tone: 'warn' }); return; }
    setAna(true);
    window.socToast?.({ title: 'AI Analysis running', sub: 'Analysing ' + sources.length + ' sources…', tone: 'info' });
    const r = await window.SOC_API.post('/api/log-sources/analyze', { sources });
    setAna(false);
    if (!r || r.error) { window.socToast?.({ title: 'Analysis failed', sub: r?.error || 'AI engine unavailable', tone: 'error' }); return; }
    setAiResult(r);
    window.socToast?.({ title: 'AI Analysis complete', sub: (r.sources_analyzed || sources.length) + ' sources reviewed', tone: 'ok' });
  }

  const active   = sources.filter(s => srcStatus(s) === 'active').length;
  const warnings = sources.filter(s => srcStatus(s) === 'warning').length;
  const inactive = sources.filter(s => srcStatus(s) === 'inactive').length;
  const totalEps = summary?.total_eps ?? sources.reduce((a, s) => a + (s.eps || 0), 0);

  return (
    <div className="page">
      <Topbar
        title="Log Sources"
        sub="Live inventory · onboarding history · AI analysis"
        actions={<>
          <button className="btn btn-ghost" onClick={loadSources} disabled={loading}>
            <Icon.refresh width="13" height="13"/> {loading ? 'Loading…' : 'Refresh'}
          </button>
          <button className="btn btn-primary" onClick={runAiAnalysis} disabled={analyzing || !sources.length}>
            <Icon.brain width="13" height="13"/> {analyzing ? 'Analysing…' : 'AI Analysis'}
          </button>
        </>}
      />
      <div className="page-body">

        {/* AI Investigation Report */}
        {aiResult && (
          <Card
            title="Log Source Intelligence Report"
            sub={`${aiResult.total_sources} sources analysed · ${new Date().toLocaleTimeString()}`}
            actions={<button className="btn-icon" title="Close" onClick={() => setAiResult(null)}><Icon.x width="13" height="13"/></button>}
          >
            {/* Full narrative */}
            {aiResult.full_report ? (
              <pre style={{
                whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                fontFamily: 'var(--fm)', fontSize: '0.82rem',
                color: 'var(--fg-1)', lineHeight: 1.7, margin: '0 0 16px',
                maxHeight: 540, overflowY: 'auto',
                background: 'var(--bg-1)', border: '1px solid var(--ln)',
                borderRadius: 6, padding: 16,
              }}>{aiResult.full_report}</pre>
            ) : (
              <div className="empty mono" style={{ padding: '20px 0', textAlign: 'center', marginBottom: 12 }}>
                Narrative report unavailable — LangChain agent unreachable.
              </div>
            )}

            {/* Flagged sources */}
            {aiResult.anomalies?.length > 0 && (
              <div style={{ marginBottom: 14 }}>
                <div className="card-sub" style={{ marginBottom: 6 }}>Flagged Sources ({aiResult.anomalies.length})</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {aiResult.anomalies.map((a, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 8px', background: 'var(--bg-1)', borderRadius: 5 }}>
                      <Chip mono tone="warn">{a.source_name}</Chip>
                      <span style={{ fontSize: '0.81rem', color: 'var(--fg-2)', flex: 1 }}>{a.reason}</span>
                      <Chip mono tone={srcTone(a.status || 'warning')}>{a.status || 'warning'}</Chip>
                      {a.eps > 0 && <span className="mono dim" style={{ fontSize: '0.78rem' }}>{a.eps} EPS</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Pipeline insights */}
            {aiResult.insights?.length > 0 && (
              <div>
                <div className="card-sub" style={{ marginBottom: 6 }}>Pipeline Insights</div>
                <ul style={{ paddingLeft: 18, margin: 0, fontSize: '0.82rem', lineHeight: 1.75, color: 'var(--fg-2)' }}>
                  {aiResult.insights.map((ins, i) => <li key={i}>{ins}</li>)}
                </ul>
              </div>
            )}
          </Card>
        )}

        {/* SIEM insights */}
        {insights.length > 0 && (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 2 }}>
            {insights.map((ins, i) => (
              <Chip key={i} mono tone={ins.includes('anomalous') || ins.includes('new') ? 'warn' : 'default'}>{ins}</Chip>
            ))}
          </div>
        )}

        {/* KPIs */}
        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(5,1fr)' }}>
          <KpiCard label="Total Sources"  value={sources.length}                           sub="discovered" />
          <KpiCard label="Active"         value={active}                                   sub="< 1h last event" />
          <KpiCard label="Degraded"       value={warnings}                                 sub="1h–24h gap" sev={warnings > 0 ? 'medium' : undefined} />
          <KpiCard label="Inactive"       value={inactive}                                 sub="> 24h silent"  sev={inactive > 0 ? 'high' : undefined} />
          <KpiCard label="Combined EPS"   value={totalEps.toLocaleString(undefined,{maximumFractionDigits:2})} sub="events per second" mono />
        </div>

        <Card actions={<>
          {['inventory','onboarding'].map(t => (
            <button key={t} className={`seg-btn ${tab === t ? 'on' : ''}`} onClick={() => setTab(t)}>{t}</button>
          ))}
        </>}>

          {pending && (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--fm)', fontSize: '0.83rem' }}>
              <Icon.refresh width="16" height="16"/> Connecting to SIEM… retrying automatically
            </div>
          )}

          {!pending && tab === 'inventory' && (
            sources.length === 0 && !loading ? (
              <div className="empty mono" style={{ padding: '32px', textAlign: 'center' }}>
                No log sources found in the last 7 days.
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>SOURCE</th><th>VENDOR</th><th>TYPE</th><th>PROTOCOL</th>
                    <th>STATUS</th><th>EPS</th><th>EVENTS/24H</th><th>LAST SEEN</th><th>IP</th>
                  </tr>
                </thead>
                <tbody>
                  {sources.map(s => {
                    const st = srcStatus(s);
                    return (
                      <tr key={s.source_id}>
                        <td style={{ fontWeight: 500 }}>
                          {s.source_name}
                          {s.anomaly && <Chip mono tone="warn" style={{ marginLeft: 6 }}>anomaly</Chip>}
                          {s.is_new   && <Chip mono tone="info" style={{ marginLeft: 6 }}>new</Chip>}
                        </td>
                        <td className="mono">{s.vendor || '—'}</td>
                        <td className="mono">{s.type || '—'}</td>
                        <td className="mono">{s.protocol || '—'}</td>
                        <td>
                          <Chip mono tone={srcTone(st)}>
                            <span className={`pip pip-${srcTone(st)}`}/> {st}
                          </Chip>
                        </td>
                        <td className="mono">{s.eps?.toFixed(3) ?? '—'}</td>
                        <td className="mono">{(s.event_count_24h || 0).toLocaleString()}</td>
                        <td className="mono dim">{window.SOC_API.relTs(s.last_seen)}</td>
                        <td className="mono dim">{s.source_ip === 'cloud' ? 'cloud' : s.source_ip || '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )
          )}

          {!pending && tab === 'onboarding' && (
            onboard.length === 0 ? (
              <div className="empty mono" style={{ padding: '32px', textAlign: 'center' }}>
                No onboarding history yet. Sources are recorded on first discovery.
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr><th>SOURCE</th><th>VENDOR</th><th>TYPE</th><th>PROTOCOL</th><th>FIRST SEEN</th></tr>
                </thead>
                <tbody>
                  {onboard.map((o, i) => (
                    <tr key={i}>
                      <td>{o.source_name}</td>
                      <td className="mono">{o.vendor || '—'}</td>
                      <td className="mono">{o.type || '—'}</td>
                      <td className="mono">{o.protocol || '—'}</td>
                      <td className="mono dim">{window.SOC_API.relTs(o.first_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
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
    const message = `Investigate ${scope}: ${target.trim()}${context ? '\n\nContext: ' + context : ''}`;
    window.SOC_API.stream(
      '/api/ai/chat/stream',
      { message, history: [], session_id: `inv_${Date.now()}` },
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
              <div className="inv-output">
                <div dangerouslySetInnerHTML={{ __html: window.renderMd ? window.renderMd(output) : output }} />
                {streaming && <span className="mono" style={{ color: 'var(--acc)', opacity: .7 }}> ▋</span>}
              </div>
            )}
          </div>
        </Card>

        <Card title="Past Investigations" sub="last 10">
          {past.length === 0
            ? <div className="empty mono" style={{ padding: 20 }}>No investigations yet. Launch one above.</div>
            : <table className="data-table">
                <thead><tr><th>ID</th><th>ALERT ID</th><th>TARGET</th><th>SEVERITY</th><th>STATUS</th><th>CREATED</th></tr></thead>
                <tbody>
                  {past.map((inv, i) => (
                    <tr key={inv.id || i}>
                      <td className="mono dim">#{inv.id || i + 1}</td>
                      <td className="mono" style={{ fontSize: 10, color: 'var(--acc)', letterSpacing: '.04em', whiteSpace: 'nowrap' }}>
                        {inv.alert_short_id || '—'}
                      </td>
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
const NOTIF_ICON = {
  investigation: <Icon.brain width="16" height="16" />,
  case_created:  <Icon.folder width="16" height="16" />,
  playbook:      <Icon.cog width="16" height="16" />,
  correlation:   <Icon.share width="16" height="16" />,
  true_positive: <Icon.check width="16" height="16" />,
};

function PageNotifications() {
  const [notifs, setNotifs]  = useStateADV([]);
  const [tab, setTab]        = useStateADV('all');
  const [page, setPage]      = useStateADV(1);
  const [total, setTotal]    = useStateADV(0);
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
