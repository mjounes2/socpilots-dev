// Settings — connection diagnostics, integrations, users, audit log
const { useState: useStateSet, useMemo: useMemoSet, useEffect: useEffectSet } = React;

// ── Map /api/health/deep check name → display label + icon + description ──
const HEALTH_META = {
  postgres:   { name: 'PostgreSQL',                icon: 'cpu',    desc: 'Persistent state · investigations · approvals' },
  neo4j:      { name: 'Neo4j · UEBA graph',        icon: 'share',  desc: 'User & entity behavior graph' },
  opensearch: { name: 'SIEM · OpenSearch',         icon: 'globe',  desc: 'Wazuh alerts · agents · rule index' },
  thehive:    { name: 'SP-CM · TheHive',           icon: 'folder', desc: 'Case management · alert inbox' },
  langchain:  { name: 'LangChain · ReAct agent',   icon: 'brain',  desc: 'AI investigation engine' },
  rag:        { name: 'RAG Retrieval',             icon: 'search', desc: 'Vector search · MITRE knowledge' },
  knowledge:  { name: 'Knowledge Ingestion',       icon: 'file',   desc: 'Evidence upload · embedding pipeline' },
  'ueba-ml':  { name: 'UEBA ML',                   icon: 'cpu',    desc: 'Isolation Forest · z-score · DBSCAN' },
  qdrant:     { name: 'Qdrant vector DB',          icon: 'target', desc: 'BGE embeddings · 384-dim cosine' },
};

// Settings keys that store API keys / passwords (never exposed)
const SECRET_KEY_PATTERNS = [
  /api_key/i, /password/i, /pass$/i, /_pass$/i, /secret/i, /token/i,
];

function PageSettings() {
  const [section, setSection] = useStateSet('integrations');
  const SECTIONS = [
    { id: 'integrations', label: 'Integrations',  icon: Icon.share },
    { id: 'users',        label: 'Users & roles', icon: Icon.user },
    { id: 'secrets',      label: 'Secrets',       icon: Icon.shield },
    { id: 'audit',        label: 'Audit log',     icon: Icon.file },
    { id: 'preferences',  label: 'Preferences',   icon: Icon.cog },
    { id: 'about',        label: 'About',         icon: Icon.dot },
  ];

  return (
    <div className="page" data-screen-label="14 Settings">
      <Topbar
        title="Settings"
        sub="System configuration · diagnostics · access control"
        actions={<>
          <Chip mono tone="ok"><span className="pip pip-ok"/> 6 of 8 integrations healthy</Chip>
          <button className="btn btn-ghost"><Icon.refresh width="13" height="13"/> Test all</button>
        </>}
      />
      <div className="page-body settings-body">
        <aside className="settings-side">
          <ul className="settings-nav">
            {SECTIONS.map(s => {
              const Ic = s.icon;
              return (
                <li key={s.id}>
                  <button className={`settings-nav-item ${section===s.id?'on':''}`} onClick={()=>setSection(s.id)}>
                    <Ic width="13" height="13"/>
                    <span>{s.label}</span>
                  </button>
                </li>
              );
            })}
          </ul>
          <div className="settings-version mono">
            <div className="sv-row"><span>build</span><span>3.0.42</span></div>
            <div className="sv-row"><span>commit</span><span>e8a57ac</span></div>
            <div className="sv-row"><span>licence</span><span>MIT</span></div>
          </div>
        </aside>

        <main className="settings-main">
          {section === 'integrations' && <SettingsIntegrations />}
          {section === 'users'        && <SettingsUsers />}
          {section === 'secrets'      && <SettingsSecrets />}
          {section === 'audit'        && <SettingsAudit />}
          {section === 'preferences'  && <SettingsPrefs />}
          {section === 'about'        && <SettingsAbout />}
        </main>
      </div>
    </div>
  );
}

// ============= INTEGRATIONS — wired to /api/health/deep ===========
function SettingsIntegrations() {
  const [health, setHealth] = useStateSet(null);
  const [loading, setLoading] = useStateSet(true);
  const [testing, setTesting] = useStateSet(null);

  async function load() {
    setLoading(true);
    const d = await window.SOC_API.get('/api/health/deep');
    if (d && !d.error) setHealth(d);
    setLoading(false);
  }
  useEffectSet(() => {
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, []);

  async function test(checkName) {
    setTesting(checkName);
    await load();
    setTesting(null);
    const check = health?.checks?.find(c => c.name === checkName);
    if (check) {
      window.socToast?.({
        title:  check.ok ? 'Connection OK' : 'Connection failed',
        sub:    `${checkName} · ${check.ok ? `${check.latency_ms}ms` : check.error}`,
        tone:   check.ok ? 'ok' : 'crit',
      });
    }
  }

  if (loading && !health) {
    return <Card title="External integrations"><div className="empty mono"><Spinner/> Probing dependencies…</div></Card>;
  }
  if (!health) {
    return <Card title="External integrations"><div className="empty mono">Health endpoint unavailable</div></Card>;
  }

  const checks = health.checks || [];
  const statusToLabel = ok => ok ? 'healthy' : 'offline';

  return (
    <>
      <Card title="External integrations"
        sub={`${health.ok_count}/${health.total} healthy · refreshed every 30s`}
        actions={<>
          <Chip mono tone={health.status === 'healthy' ? 'ok' : health.status === 'degraded' ? 'warn' : 'crit'}>
            {health.status?.toUpperCase()}
          </Chip>
          <button className="btn btn-ghost btn-sm" onClick={load}>
            <Icon.refresh width="11" height="11"/> Refresh
          </button>
        </>}>
        <ul className="integrations-list">
          {checks.map(c => {
            const meta = HEALTH_META[c.name] || { name: c.name, icon: 'dot', desc: 'internal service' };
            const Ic = Icon[meta.icon] || Icon.dot;
            const status = statusToLabel(c.ok);
            return (
              <li key={c.name} className={`integration ${status}`}>
                <div className="int-icon"><Ic width="16" height="16"/></div>
                <div className="int-info">
                  <div className="int-name">{meta.name}</div>
                  <div className="int-host mono">{c.detail || c.error || '—'}</div>
                  <div className="int-desc">{meta.desc}</div>
                </div>
                <div className="int-stats">
                  <div className="int-stat">
                    <div className="is-lbl mono">LATENCY</div>
                    <div className="is-val mono">{c.latency_ms != null ? c.latency_ms + 'ms' : '—'}</div>
                  </div>
                  <div className="int-stat">
                    <div className="is-lbl mono">STATUS</div>
                    <div className="is-val mono" style={{ color: c.ok ? 'var(--low)' : 'var(--crit)' }}>
                      {c.ok ? 'OK' : 'DOWN'}
                    </div>
                  </div>
                  {c.cluster && (
                    <div className="int-stat">
                      <div className="is-lbl mono">CLUSTER</div>
                      <div className="is-val mono">{c.cluster}</div>
                    </div>
                  )}
                  {c.last_run && (
                    <div className="int-stat">
                      <div className="is-lbl mono">LAST RUN</div>
                      <div className="is-val mono">{c.last_run.slice(11,16)}</div>
                    </div>
                  )}
                </div>
                <div className="int-status">
                  <StatusBadge status={status}/>
                </div>
                <div className="int-actions">
                  <button className="btn btn-ghost btn-sm" onClick={() => test(c.name)} disabled={testing === c.name}>
                    {testing === c.name ? <span className="test-spin"/> : <Icon.refresh width="11" height="11"/>}
                    Test
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      </Card>

      <Card title="Process info" sub="webapp container">
        <div className="mono" style={{ fontSize: 12, color: 'var(--fg-1)', padding: 8, display: 'flex', gap: 20 }}>
          <div>uptime: <span style={{ color: 'var(--fg-0)' }}>{Math.floor((health.uptime_sec || 0) / 60)}m</span></div>
          <div>last refresh: <span style={{ color: 'var(--fg-0)' }}>{health.timestamp?.slice(11,19)}</span></div>
        </div>
      </Card>
    </>
  );
}

function StatusBadge({ status, small }) {
  const labels = { healthy: 'HEALTHY', degraded: 'DEGRADED', offline: 'OFFLINE' };
  const sevMap = { healthy: 'low', degraded: 'medium', offline: 'critical' };
  return (
    <span className={`status-badge ${small ? 'sb-sm' : ''}`} data-status={status}>
      <SevDot sev={sevMap[status]} size={small ? 5 : 6}/>
      {labels[status]}
    </span>
  );
}

// ============= USERS — wired to /api/users (admin only) =============
function SettingsUsers() {
  const [users, setUsers] = useStateSet([]);
  const [loading, setLoading] = useStateSet(true);
  const [denied, setDenied] = useStateSet(false);

  async function load() {
    setLoading(true);
    const d = await window.SOC_API.get('/api/users');
    if (d?.error?.toLowerCase().includes('permission') || d?.error?.toLowerCase().includes('insufficient')) {
      setDenied(true);
    } else if (Array.isArray(d?.users)) {
      setUsers(d.users);
    } else if (Array.isArray(d)) {
      setUsers(d);
    }
    setLoading(false);
  }
  useEffectSet(() => { load(); }, []);

  if (denied) {
    return (
      <Card title="Users & roles" sub="admin permission required">
        <div className="mono" style={{ padding: 14, color: 'var(--fg-2)' }}>
          <Icon.shield width="13" height="13"/> Only administrators can view user accounts. Ask an admin to grant your role.
        </div>
      </Card>
    );
  }

  return (
    <Card title="Users & roles" sub={`${users.length} accounts`}
      actions={
        <button className="btn btn-ghost btn-sm" onClick={load}>
          <Icon.refresh width="11" height="11"/> Refresh
        </button>
      }>
      {loading ? <div className="empty mono"><Spinner/> Loading users…</div>
      : users.length === 0 ? <div className="empty mono">No users yet</div>
      : (
        <table className="data-table">
          <thead><tr>
            <th>USER</th>
            <th>ROLE</th>
            <th>CREATED</th>
            <th>LAST LOGIN</th>
            <th>OPEN CASES</th>
          </tr></thead>
          <tbody>
            {users.map(u => (
              <tr key={u.username || u.id}>
                <td>
                  <div className="user-cell">
                    <span className="sb-avatar" style={{width:24,height:24,fontSize:10}}>
                      {(u.username || '?')[0].toUpperCase()}
                    </span>
                    <span className="mono">{u.username || u.name}</span>
                  </div>
                </td>
                <td><RoleChip role={u.role}/></td>
                <td className="mono dim">{u.created_at ? u.created_at.slice(0, 10) : '—'}</td>
                <td className="mono dim">{u.last_login ? u.last_login.slice(0, 16).replace('T', ' ') : '—'}</td>
                <td className="mono">{u.open_cases ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

function RoleChip({ role }) {
  const map = { admin: 'crit', analyst: 'warn', viewer: 'dim' };
  return <Chip mono tone={map[role]}>{role}</Chip>;
}

// ============= SECRETS — show configuration status only (never values) =====
// Lists secret-looking env vars expected by the stack and shows whether each
// is configured. The webapp never reads back env values to the frontend —
// only "set" or "missing" is exposed.
function SettingsSecrets() {
  const [envStatus, setEnvStatus] = useStateSet(null);
  const [loading, setLoading] = useStateSet(true);

  async function load() {
    setLoading(true);
    const d = await window.SOC_API.get('/api/settings/env-status');
    if (d && !d.error) setEnvStatus(d);
    setLoading(false);
  }
  useEffectSet(() => { load(); }, []);

  return (
    <Card title="Environment & secrets" sub="configuration status · values never exposed"
      actions={<button className="btn btn-ghost btn-sm" onClick={load}>
        <Icon.refresh width="11" height="11"/> Refresh
      </button>}>
      <div className="secrets-warning mono">
        <Icon.shield width="13" height="13"/>
        Secret values live in the host <code>.env</code> file and are read by the container at boot.
        This UI shows only <strong>whether each key is set</strong> — values are never sent over the wire.
        Rotate secrets by editing <code>.env</code> and running <code>docker compose restart</code>.
      </div>
      {loading ? <div className="empty mono"><Spinner/> Checking environment…</div>
      : !envStatus ? <div className="empty mono">Unable to read env status</div>
      : (
        <table className="data-table secrets-table">
          <thead><tr>
            <th style={{width:300}}>KEY</th>
            <th style={{width:120}}>CATEGORY</th>
            <th>STATUS</th>
            <th style={{width:200}}>NOTES</th>
          </tr></thead>
          <tbody>
            {(envStatus.items || []).map(s => (
              <tr key={s.key}>
                <td className="mono">{s.key}</td>
                <td><Chip mono tone={s.required ? 'crit' : 'default'}>{s.category || 'misc'}</Chip></td>
                <td>
                  {s.set
                    ? <Chip mono tone="ok">SET · {s.preview}</Chip>
                    : s.required
                      ? <Chip mono tone="crit">MISSING (required)</Chip>
                      : <Chip mono>not set</Chip>}
                </td>
                <td className="mono dim" style={{ fontSize: 11 }}>{s.note || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

// ============= AUDIT LOG =============
function auditActionTone(action) {
  if (!action) return 'dim';
  if (action.includes('delete') || action.includes('reset')) return 'crit';
  if (action.includes('create') || action.includes('deploy')) return 'warn';
  if (action.includes('update') || action.includes('change')) return 'ok';
  return 'dim';
}

function SettingsAudit() {
  const [items, setItems]       = useStateSet([]);
  const [total, setTotal]       = useStateSet(0);
  const [page, setPage]         = useStateSet(1);
  const [actions, setActions]   = useStateSet([]);
  const [filterUser, setFUser]  = useStateSet('');
  const [filterAction, setFA]   = useStateSet('');
  const [filterRes, setFRes]    = useStateSet('');
  const [filterFrom, setFFrom]  = useStateSet('');
  const [filterTo, setFTo]      = useStateSet('');
  const [loading, setLoading]   = useStateSet(true);
  const pageSize = 50;

  useEffectSet(() => {
    window.SOC_API.get('/api/audit-log/actions').then(d => {
      if (d?.actions) setActions(d.actions);
    });
  }, []);

  useEffectSet(() => { load(1); }, [filterUser, filterAction, filterRes, filterFrom, filterTo]);

  async function load(p) {
    setLoading(true);
    const qs = new URLSearchParams({ page: p, page_size: pageSize });
    if (filterUser)   qs.set('username',      filterUser);
    if (filterAction) qs.set('action',         filterAction);
    if (filterRes)    qs.set('resource_type',  filterRes);
    if (filterFrom)   qs.set('date_from',      filterFrom);
    if (filterTo)     qs.set('date_to',        filterTo);
    const d = await window.SOC_API.get('/api/audit-log?' + qs.toString());
    if (d?.items) { setItems(d.items); setTotal(d.total || 0); setPage(p); }
    setLoading(false);
  }

  function fmtTs(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'medium' });
  }

  return (
    <>
      <Card title="Audit log filters" sub="admin view · all users">
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <input className="mono" placeholder="Filter by user…" value={filterUser} onChange={e => setFUser(e.target.value)} style={{ width: 150 }} />
          <select className="select-mini mono" value={filterAction} onChange={e => setFA(e.target.value)} style={{ width: 180 }}>
            <option value="">All actions</option>
            {actions.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
          <select className="select-mini mono" value={filterRes} onChange={e => setFRes(e.target.value)} style={{ width: 140 }}>
            <option value="">All resources</option>
            {['rule','user','playbook','investigation'].map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          <input type="date" className="mono" value={filterFrom} onChange={e => setFFrom(e.target.value)} style={{ width: 140 }} />
          <input type="date" className="mono" value={filterTo} onChange={e => setFTo(e.target.value)} style={{ width: 140 }} />
          <button className="btn btn-ghost btn-sm" onClick={() => { setFUser(''); setFA(''); setFRes(''); setFFrom(''); setFTo(''); }}>Clear</button>
        </div>
      </Card>
      <Card title="Audit log" sub={`${total.toLocaleString()} entries`}
        actions={<Chip mono>{total} total</Chip>}>
        {loading ? (
          <div className="empty mono">Loading…</div>
        ) : items.length === 0 ? (
          <div className="empty mono">No audit entries found</div>
        ) : (
          <>
            <table className="data-table audit-table">
              <thead><tr>
                <th style={{ width: 140 }}>TIME</th>
                <th style={{ width: 110 }}>USER</th>
                <th style={{ width: 200 }}>ACTION</th>
                <th style={{ width: 120 }}>RESOURCE</th>
                <th>DETAILS</th>
              </tr></thead>
              <tbody>
                {items.map((row, i) => (
                  <tr key={i}>
                    <td className="mono dim">{fmtTs(row.created_at)}</td>
                    <td className="mono">{row.username === 'system'
                      ? <Chip mono>system</Chip>
                      : <span className="user-cell-sm"><span className="sb-avatar" style={{ width: 18, height: 18, fontSize: 8 }}>{(row.username||'?')[0].toUpperCase()}</span>{row.username}</span>
                    }</td>
                    <td className="mono">
                      <Chip mono tone={auditActionTone(row.action)}>{row.action}</Chip>
                    </td>
                    <td className="mono dim">{row.resource_type || '—'}{row.resource_id ? ` #${row.resource_id}` : ''}</td>
                    <td className="mono dim" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {JSON.stringify(row.details || {})}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {total > pageSize && (
              <div style={{ display: 'flex', gap: 8, justifyContent: 'center', marginTop: 12 }}>
                <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => load(page - 1)}>← Prev</button>
                <span className="mono dim" style={{ lineHeight: '28px' }}>Page {page} / {Math.ceil(total / pageSize)}</span>
                <button className="btn btn-ghost btn-sm" disabled={page * pageSize >= total} onClick={() => load(page + 1)}>Next →</button>
              </div>
            )}
          </>
        )}
      </Card>
    </>
  );
}

// ============= PREFERENCES =============
function SettingsPrefs() {
  const [retention, setRetention] = useStateSet(90);
  const [autoAck, setAutoAck] = useStateSet(true);
  const [aiAuto, setAiAuto] = useStateSet(false);
  const [emailDigest, setEmailDigest] = useStateSet(true);
  return (
    <>
      <Card title="Workspace preferences" sub="apply to all users in this tenant">
        <div className="pref-list">
          <PrefRow label="Alert retention" sub="how long raw SIEM alerts are stored">
            <div className="pref-slider">
              <input type="range" min="7" max="365" step="1" value={retention} onChange={e => setRetention(+e.target.value)}/>
              <span className="mono">{retention} days</span>
            </div>
          </PrefRow>
          <PrefRow label="Auto-acknowledge low-severity" sub="dismiss level ≤3 alerts after 24h if untouched">
            <Toggle on={autoAck} onChange={setAutoAck}/>
          </PrefRow>
          <PrefRow label="AI auto-containment" sub="allow AI to execute response actions without approval" warn>
            <Toggle on={aiAuto} onChange={setAiAuto}/>
          </PrefRow>
          <PrefRow label="Daily email digest" sub="executive summary to ciso@socpilots.com at 09:00 UTC">
            <Toggle on={emailDigest} onChange={setEmailDigest}/>
          </PrefRow>
        </div>
      </Card>
      <Card title="Time zone & display" sub="per-user · saved on this browser">
        <div className="pref-list">
          <PrefRow label="Time zone" sub="affects all timestamps">
            <select className="select-mini mono"><option>UTC</option><option>Europe/Amsterdam</option><option>Asia/Damascus</option></select>
          </PrefRow>
          <PrefRow label="Time format" sub="">
            <select className="select-mini mono"><option>24h</option><option>12h</option></select>
          </PrefRow>
          <PrefRow label="Date format" sub="">
            <select className="select-mini mono"><option>ISO 8601</option><option>DD/MM/YYYY</option><option>MM/DD/YYYY</option></select>
          </PrefRow>
        </div>
      </Card>
    </>
  );
}
function PrefRow({ label, sub, warn, children }) {
  return (
    <div className={`pref-row ${warn ? 'warn' : ''}`}>
      <div className="pref-info">
        <div className="pref-label">{label}{warn && <span className="pref-warn">requires extra caution</span>}</div>
        <div className="pref-sub">{sub}</div>
      </div>
      <div className="pref-ctrl">{children}</div>
    </div>
  );
}
function Toggle({ on, onChange }) {
  return <button className={`toggle ${on?'on':''}`} onClick={() => onChange(!on)}><span className="toggle-thumb"/></button>;
}

// ============= ABOUT =============
function SettingsAbout() {
  return (
    <Card title="SOC Pilots" sub="version & licence">
      <div className="about">
        <div className="about-mark">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4">
            <path d="M12 2L20 7V17L12 22L4 17V7Z"/>
            <circle cx="12" cy="12" r="3" fill="currentColor"/>
          </svg>
        </div>
        <div className="about-name">SOC<span>PILOTS</span></div>
        <div className="about-version mono">version 3.0.42 · April 2026</div>
        <p className="about-desc">An open-source AI security operations center. Built by Younes / CyberTalents.</p>
        <ul className="about-links">
          <li><a className="link" href="#">github.com/younis2023/socpilots-dark-soc</a></li>
          <li><a className="link" href="#">documentation</a></li>
          <li><a className="link" href="#">changelog</a></li>
          <li><a className="link" href="#">licence · MIT</a></li>
        </ul>
      </div>
    </Card>
  );
}

Object.assign(window, { PageSettings });
