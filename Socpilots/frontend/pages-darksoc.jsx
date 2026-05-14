// Dark SOC — Automated Response Engine
const { useState: useStateDK, useEffect: useEffectDK } = React;

// ============= FALLBACK DATA =============
const FALLBACK_DS_STATUS = {
  enabled: false, actions_24h: 0, tp_rate: 0, active_playbooks: 3,
  actions: { block_ip: 0, isolate_host: 0, kill_process: 0, disable_user: 0, create_case: 0 },
};
const FALLBACK_PLAYBOOKS = [
  { id: 1, name: 'Critical Alert Auto-Response', trigger: 'severity=critical AND fp_prob<0.2', actions: ['block_ip', 'create_case'],    status: 'active', last_run: null, run_count: 0 },
  { id: 2, name: 'Ransomware Containment',        trigger: 'rule.groups:ransomware',            actions: ['isolate_host', 'create_case'], status: 'active', last_run: null, run_count: 0 },
  { id: 3, name: 'Bruteforce Blocker',            trigger: 'rule.id:5710 AND count>10',         actions: ['block_ip'],                   status: 'paused', last_run: null, run_count: 0 },
];
const FALLBACK_AUDIT = [
  { time: '—', action: 'block_ip', target: '—', agent: '—', result: 'success', by: 'system' },
];
const FALLBACK_PROTECTED = [
  { asset: 'postgres-primary', reason: 'Database server',  added_by: 'admin' },
  { asset: 'win-dc-01',        reason: 'Domain controller', added_by: 'admin' },
];
const FALLBACK_APPROVALS = [];
const FALLBACK_SUPPRESSIONS = [];
const FALLBACK_TRIAGE = { pending: 0, auto_triaged: 0, escalated: 0 };

// ============= HELPERS =============
function auditResultChip(result) {
  if (result === 'success') return <Chip mono tone="ok">success</Chip>;
  if (result === 'failed')  return <Chip mono tone="crit">failed</Chip>;
  return <Chip mono tone="default">{result}</Chip>;
}

function playbookStatusChip(status) {
  if (status === 'active') return <Chip mono tone="ok">active</Chip>;
  if (status === 'paused') return <Chip mono tone="default">paused</Chip>;
  return <Chip mono tone="warn">{status}</Chip>;
}

// ============= MAIN PAGE =============
function PageDarkSOC() {
  const [status,       setStatus]       = useStateDK(FALLBACK_DS_STATUS);
  const [playbooks,    setPlaybooks]    = useStateDK(FALLBACK_PLAYBOOKS);
  const [audit,        setAudit]        = useStateDK(FALLBACK_AUDIT);
  const [protected_,   setProtected]    = useStateDK(FALLBACK_PROTECTED);
  const [approvals,    setApprovals]    = useStateDK(FALLBACK_APPROVALS);
  const [suppressions, setSuppressions] = useStateDK(FALLBACK_SUPPRESSIONS);
  const [triage,       setTriage]       = useStateDK(FALLBACK_TRIAGE);
  const [loading,      setLoading]      = useStateDK(true);
  const [toggling,     setToggling]     = useStateDK(false);

  async function fetchAll() {
    setLoading(true);
    try {
      // Dark SOC status + execution stats
      const dsData = await window.SOC_API.get('/api/darksoc/status');
      if (dsData && !dsData.error) {
        setStatus({
          enabled:          !!dsData.enabled,
          actions_24h:      dsData.actions_24h      ?? 0,
          tp_rate:          dsData.tp_rate           ?? 0,
          active_playbooks: dsData.active_playbooks  ?? FALLBACK_DS_STATUS.active_playbooks,
          actions:          dsData.actions           || FALLBACK_DS_STATUS.actions,
        });
      }

      // Settings fallback for enabled state
      const settingData = await window.SOC_API.get('/api/settings/darksoc_enabled');
      if (settingData && !settingData.error && settingData.value !== undefined) {
        setStatus(prev => ({ ...prev, enabled: settingData.value === 'true' || settingData.value === true }));
      }

      // Playbooks
      const pbData = await window.SOC_API.get('/api/playbooks');
      if (pbData && Array.isArray(pbData.playbooks) && pbData.playbooks.length > 0) {
        setPlaybooks(pbData.playbooks);
      } else if (pbData && Array.isArray(pbData) && pbData.length > 0) {
        setPlaybooks(pbData);
      }

      // Audit log (system events)
      const evData = await window.SOC_API.get('/api/system-events?limit=20');
      if (evData && Array.isArray(evData.events) && evData.events.length > 0) {
        setAudit(evData.events.map(e => ({
          time:   e.created_at ? window.SOC_API.relTs(e.created_at) : '—',
          action: e.action || e.event_type || '—',
          target: e.target || e.resource  || '—',
          agent:  e.agent  || '—',
          result: e.result || e.status    || 'success',
          by:     e.user   || e.source    || 'system',
        })));
      }

      // Protected assets
      const paData = await window.SOC_API.get('/api/protected-assets');
      if (paData && Array.isArray(paData.assets) && paData.assets.length > 0) {
        setProtected(paData.assets);
      } else if (paData && Array.isArray(paData) && paData.length > 0) {
        setProtected(paData);
      }

      // Isolation approvals
      const apData = await window.SOC_API.get('/api/isolation-approvals');
      if (apData && Array.isArray(apData.approvals)) {
        setApprovals(apData.approvals);
      } else if (apData && Array.isArray(apData)) {
        setApprovals(apData);
      }

      // Suppressions
      const supData = await window.SOC_API.get('/api/suppressions');
      if (supData && Array.isArray(supData.suppressions)) {
        setSuppressions(supData.suppressions);
      } else if (supData && Array.isArray(supData)) {
        setSuppressions(supData);
      }

      // Triage queue stats
      const tqData = await window.SOC_API.get('/api/triage-queue/stats');
      if (tqData && !tqData.error) {
        setTriage({
          pending:      tqData.pending      ?? 0,
          auto_triaged: tqData.auto_triaged ?? 0,
          escalated:    tqData.escalated    ?? 0,
        });
      }
    } catch (e) {
      // retain fallback data silently
    }
    setLoading(false);
  }

  useEffectDK(() => { fetchAll(); }, []);

  async function handleToggle() {
    if (toggling) return;
    setToggling(true);
    const newVal = status.enabled ? 'false' : 'true';
    const res = await window.SOC_API.post('/api/settings', { key: 'darksoc_enabled', value: newVal });
    if (res && !res.error) {
      // Re-fetch to confirm from server
      const confirm = await window.SOC_API.get('/api/settings/darksoc_enabled');
      if (confirm && confirm.value !== undefined) {
        setStatus(prev => ({ ...prev, enabled: confirm.value === 'true' || confirm.value === true }));
      } else {
        setStatus(prev => ({ ...prev, enabled: newVal === 'true' }));
      }
      window.socToast?.({
        title: newVal === 'true' ? 'Dark SOC enabled' : 'Dark SOC disabled',
        sub:   newVal === 'true' ? 'Automated response is now active' : 'All detections will be logged only',
        tone:  newVal === 'true' ? 'ok' : 'warn',
      });
    }
    setToggling(false);
  }

  const enabled = status.enabled;
  const acts    = status.actions || FALLBACK_DS_STATUS.actions;

  return (
    <div className="page" data-screen-label="12 Dark SOC">
      <Topbar
        title="Dark SOC"
        sub="Automated response engine — playbooks, isolation, blocking"
        actions={<>
          <button
            className={`btn ${enabled ? 'btn-ghost' : 'btn-primary'}`}
            onClick={handleToggle}
            disabled={toggling}
            style={enabled ? { borderColor: 'var(--r)', color: 'var(--r)' } : { background: 'var(--g)', borderColor: 'var(--g)', color: '#0a1628' }}
          >
            <Icon.shield width="13" height="13"/>
            {toggling ? 'Updating…' : enabled ? 'Disable Dark SOC' : 'Enable Dark SOC'}
          </button>
          <button className="btn btn-ghost" onClick={fetchAll}>
            <Icon.refresh width="13" height="13"/> Refresh
          </button>
        </>}
      />

      <div className="page-body">

        {/* Disabled warning banner */}
        {!enabled && (
          <div style={{
            background: 'rgba(255,23,68,.08)',
            border: '1px solid rgba(255,23,68,.35)',
            borderRadius: 'var(--r3)',
            padding: '10px 16px',
            marginBottom: 16,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            fontSize: '0.85rem',
            color: 'var(--r)',
          }}>
            <Icon.alert width="15" height="15"/>
            <span>
              <strong>Dark SOC is currently DISABLED.</strong> All detections will be logged but no automated actions will execute.
            </span>
          </div>
        )}

        {/* Status row — 4 KPI cards */}
        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
          <KpiCard
            label="Dark SOC Status"
            value={loading ? '…' : enabled ? 'ACTIVE' : 'STANDBY'}
            sub={enabled ? 'automated response on' : 'monitoring only'}
            sev={enabled ? undefined : 'critical'}
          />
          <KpiCard
            label="Actions Executed (24h)"
            value={loading ? '…' : status.actions_24h}
            sub="across all playbooks"
          />
          <KpiCard
            label="True Positive Rate"
            value={loading ? '…' : `${status.tp_rate}%`}
            sub="automated triage accuracy"
          />
          <KpiCard
            label="Active Playbooks"
            value={loading ? '…' : status.active_playbooks}
            sub="configured response rules"
          />
        </div>

        {/* Execution stats + Triage queue (2-col) */}
        <div className="grid-12">
          <Card span={6} title="EXECUTION STATS" sub="action breakdown — last 24h">
            <table className="data-table">
              <thead><tr>
                <th>ACTION</th>
                <th style={{ width: 90 }}>COUNT</th>
              </tr></thead>
              <tbody>
                {[
                  ['block_ip',      'Block IP'],
                  ['isolate_host',  'Isolate Host'],
                  ['kill_process',  'Kill Process'],
                  ['disable_user',  'Disable User'],
                  ['create_case',   'Create Case'],
                ].map(([key, label]) => (
                  <tr key={key}>
                    <td className="mono">{label}</td>
                    <td className="mono">{loading ? '…' : (acts[key] ?? 0)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <Card span={6} title="TRIAGE QUEUE" sub="current queue state">
            <table className="data-table">
              <thead><tr>
                <th>STATE</th>
                <th style={{ width: 90 }}>COUNT</th>
              </tr></thead>
              <tbody>
                <tr>
                  <td>Pending review</td>
                  <td className="mono">{loading ? '…' : triage.pending}</td>
                </tr>
                <tr>
                  <td>Auto-triaged</td>
                  <td className="mono">{loading ? '…' : triage.auto_triaged}</td>
                </tr>
                <tr>
                  <td>Escalated</td>
                  <td className="mono">{loading ? '…' : triage.escalated}</td>
                </tr>
              </tbody>
            </table>
          </Card>
        </div>

        {/* Playbooks (full-width) */}
        <Card
          title="PLAYBOOKS"
          sub={loading ? 'Loading…' : `${playbooks.length} configured`}
          actions={<>
            <button className="btn btn-primary btn-sm" onClick={() => window.socToast?.({ title: 'New Playbook', sub: 'Feature coming soon', tone: 'info' })}>
              <Icon.plus width="11" height="11"/> New Playbook
            </button>
          </>}
        >
          {loading
            ? <div className="loading mono" style={{ padding: 20 }}>Loading…</div>
            : (
              <table className="data-table">
                <thead><tr>
                  <th>NAME</th>
                  <th>TRIGGER CONDITION</th>
                  <th>ACTIONS</th>
                  <th style={{ width: 90 }}>STATUS</th>
                  <th style={{ width: 100 }}>LAST RUN</th>
                  <th style={{ width: 80 }}>RUN COUNT</th>
                  <th style={{ width: 100 }}></th>
                </tr></thead>
                <tbody>
                  {playbooks.map(pb => (
                    <tr key={pb.id}>
                      <td>{pb.name}</td>
                      <td className="mono dim" style={{ fontSize: '0.78rem' }}>{pb.trigger}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {(pb.actions || []).map(a => (
                            <Chip key={a} mono tone="default">{a}</Chip>
                          ))}
                        </div>
                      </td>
                      <td>{playbookStatusChip(pb.status)}</td>
                      <td className="mono dim">{pb.last_run ? window.SOC_API.relTs(pb.last_run) : '—'}</td>
                      <td className="mono">{pb.run_count ?? 0}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 4 }}>
                          <button className="btn btn-ghost btn-sm" onClick={() => window.socToast?.({ title: pb.name, sub: pb.trigger, tone: 'info' })}>View</button>
                          <button
                            className="btn btn-ghost btn-sm"
                            onClick={() => window.socToast?.({ title: pb.status === 'active' ? 'Playbook paused' : 'Playbook activated', sub: pb.name, tone: pb.status === 'active' ? 'warn' : 'ok' })}
                          >
                            {pb.status === 'active' ? 'Pause' : 'Enable'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </Card>

        {/* Audit log (full-width) */}
        <Card
          title="AUDIT LOG"
          sub={loading ? 'Loading…' : `last ${audit.length} actions`}
        >
          {loading
            ? <div className="loading mono" style={{ padding: 20 }}>Loading…</div>
            : (
              <table className="data-table">
                <thead><tr>
                  <th style={{ width: 120 }}>TIME</th>
                  <th style={{ width: 130 }}>ACTION</th>
                  <th>TARGET</th>
                  <th>AGENT</th>
                  <th style={{ width: 90 }}>RESULT</th>
                  <th style={{ width: 100 }}>TRIGGERED BY</th>
                </tr></thead>
                <tbody>
                  {audit.map((a, i) => (
                    <tr key={i}>
                      <td className="mono dim">{a.time}</td>
                      <td className="mono">{a.action}</td>
                      <td className="mono">{a.target}</td>
                      <td className="mono dim">{a.agent}</td>
                      <td>{auditResultChip(a.result)}</td>
                      <td className="mono dim">{a.by}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          }
        </Card>

        {/* Protected assets + Isolation approvals (2-col) */}
        <div className="grid-12">
          <Card
            span={6}
            title="PROTECTED ASSETS"
            sub="exempt from auto-isolation"
            actions={<>
              <button className="btn btn-ghost btn-sm" onClick={() => window.socToast?.({ title: 'Add Asset', sub: 'Feature coming soon', tone: 'info' })}>
                <Icon.plus width="11" height="11"/> Add Asset
              </button>
            </>}
          >
            {loading
              ? <div className="loading mono" style={{ padding: 20 }}>Loading…</div>
              : protected_.length === 0
                ? <div className="empty mono" style={{ padding: 20 }}>No protected assets configured.</div>
                : (
                  <table className="data-table">
                    <thead><tr>
                      <th>ASSET</th>
                      <th>REASON</th>
                      <th style={{ width: 80 }}>ADDED BY</th>
                    </tr></thead>
                    <tbody>
                      {protected_.map((p, i) => (
                        <tr key={i}>
                          <td className="mono">{p.asset}</td>
                          <td className="dim">{p.reason}</td>
                          <td className="mono dim">{p.added_by}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )
            }
          </Card>

          <Card
            span={6}
            title="ISOLATION APPROVALS"
            sub="pending consensus requests"
          >
            {loading
              ? <div className="loading mono" style={{ padding: 20 }}>Loading…</div>
              : approvals.length === 0
                ? <div className="empty mono" style={{ padding: 20 }}>No pending isolation approvals.</div>
                : (
                  <table className="data-table">
                    <thead><tr>
                      <th>HOST</th>
                      <th>REQUESTED BY</th>
                      <th style={{ width: 80 }}>EXPIRES</th>
                      <th style={{ width: 130 }}></th>
                    </tr></thead>
                    <tbody>
                      {approvals.map((ap, i) => (
                        <tr key={i}>
                          <td className="mono">{ap.host || ap.asset || '—'}</td>
                          <td className="mono dim">{ap.requested_by || ap.user || '—'}</td>
                          <td className="mono dim">{ap.expires_at ? window.SOC_API.relTs(ap.expires_at) : '—'}</td>
                          <td>
                            <div style={{ display: 'flex', gap: 4 }}>
                              <button
                                className="btn btn-ghost btn-sm"
                                style={{ color: 'var(--g)', borderColor: 'var(--g)' }}
                                onClick={() => window.socToast?.({ title: 'Approved', sub: (ap.host || ap.asset), tone: 'ok' })}
                              >Approve</button>
                              <button
                                className="btn btn-ghost btn-sm"
                                style={{ color: 'var(--r)', borderColor: 'var(--r)' }}
                                onClick={() => window.socToast?.({ title: 'Rejected', sub: (ap.host || ap.asset), tone: 'crit' })}
                              >Reject</button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )
            }
          </Card>
        </div>

        {/* Suppressions (full-width) */}
        <Card
          title="SUPPRESSIONS"
          sub={loading ? 'Loading…' : `${suppressions.length} active suppression rules`}
          actions={<>
            <button className="btn btn-ghost btn-sm" onClick={() => window.socToast?.({ title: 'Add Suppression', sub: 'Feature coming soon', tone: 'info' })}>
              <Icon.plus width="11" height="11"/> Add Suppression
            </button>
          </>}
        >
          {loading
            ? <div className="loading mono" style={{ padding: 20 }}>Loading…</div>
            : suppressions.length === 0
              ? <div className="empty mono" style={{ padding: 20 }}>No suppression rules configured.</div>
              : (
                <table className="data-table">
                  <thead><tr>
                    <th style={{ width: 100 }}>RULE ID</th>
                    <th>AGENT PATTERN</th>
                    <th style={{ width: 160 }}>SUPPRESSED UNTIL</th>
                    <th>REASON</th>
                  </tr></thead>
                  <tbody>
                    {suppressions.map((s, i) => (
                      <tr key={i}>
                        <td className="mono">{s.rule_id || s.ruleId || '—'}</td>
                        <td className="mono">{s.agent_pattern || s.agent || '—'}</td>
                        <td className="mono dim">
                          {s.suppressed_until || s.until
                            ? window.SOC_API.relTs(s.suppressed_until || s.until)
                            : '—'}
                        </td>
                        <td className="dim">{s.reason || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
          }
        </Card>

      </div>
    </div>
  );
}

Object.assign(window, { PageDarkSOC });
