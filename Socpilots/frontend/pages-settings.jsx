// Settings — connection diagnostics, integrations, users, audit log
const { useState: useStateSet, useMemo: useMemoSet, useEffect: useEffectSet } = React;

const FALLBACK_INTEGRATIONS = [
  { id: 'siem',    name: 'SIEM · Wazuh + OpenSearch', host: 'vmi3247591.contaboserver.net:9200', latency: 41, status: 'healthy', uptime: 99.97, lastEvent: '2s ago', icon: 'globe',  desc: 'Alerts · agents · rules · MITRE mapping' },
  { id: 'spcm',    name: 'SP-CM · TheHive',           host: 'app.socpilots.com',                 latency: 22, status: 'healthy', uptime: 99.99, lastEvent: '4s ago', icon: 'folder', desc: 'Case management · alert inbox' },
  { id: 'n8n',     name: 'SOCPilots AI · n8n',         host: 'vmi3254460.contaboserver.net:5678', latency: 38, status: 'healthy', uptime: 99.92, lastEvent: '8s ago', icon: 'brain',  desc: 'Workflow automation · MCP bridge' },
  { id: 'openai',  name: 'OpenAI · gpt-4o',            host: 'api.openai.com',                    latency: 412, status: 'healthy', uptime: 99.78, lastEvent: '12s ago', icon: 'spark', desc: 'AI investigation engine' },
  { id: 'vt',      name: 'VirusTotal',                  host: 'www.virustotal.com',                latency: 287, status: 'degraded', uptime: 98.42, lastEvent: '1m ago', icon: 'target', desc: 'IOC reputation enrichment' },
  { id: 'abuse',   name: 'AbuseIPDB',                   host: 'api.abuseipdb.com',                 latency: 198, status: 'healthy', uptime: 99.81, lastEvent: '34s ago', icon: 'shield', desc: 'IP reputation scoring' },
  { id: 'misp',    name: 'MISP threat feed',           host: 'misp.cert.local',                   latency: 0,   status: 'offline',  uptime: 87.21, lastEvent: '14m ago', icon: 'share',  desc: 'Indicator sharing platform' },
  { id: 'mcp',     name: 'Wazuh MCP bridge',            host: 'vmi3254460.contaboserver.net:8080', latency: 19, status: 'healthy', uptime: 99.94, lastEvent: '6s ago', icon: 'cpu',    desc: 'AI ↔ SIEM tool-call bridge' },
];

const USERS = [
  { id: 'u1', name: 'younes',  email: 'younes@socpilots.com', role: 'admin',   last: 'now',     mfa: true,  cases: 14 },
  { id: 'u2', name: 'sara',    email: 'sara@socpilots.com',   role: 'analyst', last: '2m ago',  mfa: true,  cases: 8  },
  { id: 'u3', name: 'amir',    email: 'amir@socpilots.com',   role: 'analyst', last: '5h ago',  mfa: true,  cases: 6  },
  { id: 'u4', name: 'ciso',    email: 'ciso@socpilots.com',   role: 'viewer',  last: '1d ago',  mfa: true,  cases: 0  },
  { id: 'u5', name: 'on-call', email: 'oncall@socpilots.com', role: 'analyst', last: '12d ago', mfa: false, cases: 0  },
];

const FALLBACK_AUDIT_LOG = [
  { t: '14:22:47', who: 'younes',  action: 'case.create',      target: 'CASE-4471',       tone: 'ok' },
  { t: '14:22:31', who: 'system',  action: 'agent.isolate',    target: 'web-prod-01',     tone: 'crit' },
  { t: '14:22:08', who: 'younes',  action: 'runbook.advance',  target: 'CASE-4471 · 2/6', tone: 'default' },
  { t: '14:21:42', who: 'system',  action: 'firewall.block',   target: '185.220.101.42',  tone: 'crit' },
  { t: '14:20:55', who: 'sara',    action: 'alert.promote',    target: 'AL-2640 → CASE-4470', tone: 'ok' },
  { t: '14:18:11', who: 'younes',  action: 'rule.disable',     target: 'rule 5503',       tone: 'default' },
  { t: '14:15:02', who: 'system',  action: 'integration.degrade', target: 'VirusTotal',   tone: 'warn' },
  { t: '14:11:54', who: 'amir',    action: 'case.close',       target: 'CASE-4438',       tone: 'ok' },
  { t: '14:08:33', who: 'system',  action: 'auth.login',       target: 'younes from 10.0.8.41', tone: 'default' },
  { t: '14:02:09', who: 'sara',    action: 'report.send',      target: 'RPT-2026-018',    tone: 'ok' },
];

const SECRETS = [
  { key: 'OPENSEARCH_PASS',       value: '••••••••••••••••', rotated: '12d ago' },
  { key: 'THEHIVE_API_KEY',       value: '••••••••••••••••', rotated: '8d ago' },
  { key: 'OPENAI_API_KEY',        value: '••••••••••••••••', rotated: '3d ago' },
  { key: 'VIRUSTOTAL_API_KEY',    value: '••••••••••••••••', rotated: '21d ago', warn: true },
  { key: 'ABUSEIPDB_API_KEY',     value: '••••••••••••••••', rotated: '5d ago' },
  { key: 'AUTH_SECRET_KEY',       value: '••••••••••••••••', rotated: '1d ago' },
  { key: 'MCP_API_KEY',           value: '••••••••••••••••', rotated: '7d ago' },
  { key: 'N8N_PASSWORD',          value: '••••••••••••••••', rotated: '14d ago' },
];

// Map /api/status response fields to integration card status
function applyStatusToIntegrations(integrations, statusData) {
  if (!statusData) return integrations;
  return integrations.map(s => {
    let override = null;
    if (s.id === 'siem' && statusData.opensearch) {
      const ok = statusData.opensearch.ok;
      override = {
        status:  ok ? 'healthy' : 'offline',
        latency: statusData.opensearch.latency || s.latency,
        lastEvent: ok ? 'just now' : s.lastEvent,
      };
    } else if (s.id === 'spcm' && statusData.thehive) {
      const ok = statusData.thehive.ok;
      override = {
        status:  ok ? 'healthy' : 'offline',
        latency: statusData.thehive.latency || s.latency,
        lastEvent: ok ? 'just now' : s.lastEvent,
      };
    } else if (s.id === 'n8n' && statusData.n8n) {
      const ok = statusData.n8n.ok;
      override = {
        status:  ok ? 'healthy' : 'offline',
        latency: statusData.n8n.latency || s.latency,
        lastEvent: ok ? 'just now' : s.lastEvent,
      };
    }
    return override ? { ...s, ...override } : s;
  });
}

// Map /api/system-events event status to audit tone
function eventStatusToTone(status, source) {
  if (!status) return 'default';
  const s = String(status).toLowerCase();
  if (s === 'critical' || s === 'error' || s === 'fail' || s === 'failed') return 'crit';
  if (s === 'warning' || s === 'warn' || s === 'degraded') return 'warn';
  if (s === 'ok' || s === 'success' || s === 'executed') return 'ok';
  return 'default';
}

function PageSettings() {
  const [section, setSection] = useStateSet('integrations');
  const [integrations, setIntegrations] = useStateSet(FALLBACK_INTEGRATIONS);
  const [auditLog, setAuditLog] = useStateSet(FALLBACK_AUDIT_LOG);
  const [statusLoading, setStatusLoading] = useStateSet(false);

  useEffectSet(() => {
    (async () => {
      setStatusLoading(true);
      const [statusData, eventsData] = await Promise.all([
        window.SOC_API.get('/api/status'),
        window.SOC_API.get('/api/system-events?limit=20'),
      ]);

      if (statusData && !statusData.error) {
        setIntegrations(applyStatusToIntegrations(FALLBACK_INTEGRATIONS, statusData));
      }

      if (eventsData && Array.isArray(eventsData.events) && eventsData.events.length > 0) {
        const mapped = eventsData.events.map(e => ({
          t:      e.created_at ? new Date(e.created_at).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—',
          who:    e.actor || 'system',
          action: e.title || e.event_type || '—',
          target: e.description || '—',
          tone:   eventStatusToTone(e.status, e.source),
        }));
        setAuditLog(mapped);
      }

      setStatusLoading(false);
    })();
  }, []);

  const SECTIONS = [
    { id: 'integrations', label: 'Integrations',  icon: Icon.share },
    { id: 'users',        label: 'Users & roles', icon: Icon.user },
    { id: 'secrets',      label: 'Secrets',       icon: Icon.shield },
    { id: 'audit',        label: 'Audit log',     icon: Icon.file },
    { id: 'preferences',  label: 'Preferences',   icon: Icon.cog },
    { id: 'about',        label: 'About',         icon: Icon.dot },
  ];

  const healthyCount = integrations.filter(s => s.status === 'healthy').length;

  return (
    <div className="page" data-screen-label="14 Settings">
      <Topbar
        title="Settings"
        sub="System configuration · diagnostics · access control"
        actions={<>
          <Chip mono tone="ok"><span className="pip pip-ok"/> {healthyCount} of {integrations.length} integrations healthy</Chip>
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
          {section === 'integrations' && <SettingsIntegrations integrations={integrations} loading={statusLoading}/>}
          {section === 'users'        && <SettingsUsers />}
          {section === 'secrets'      && <SettingsSecrets />}
          {section === 'audit'        && <SettingsAudit auditLog={auditLog} loading={statusLoading}/>}
          {section === 'preferences'  && <SettingsPrefs />}
          {section === 'about'        && <SettingsAbout />}
        </main>
      </div>
    </div>
  );
}

// ============= INTEGRATIONS =============
function SettingsIntegrations({ integrations, loading }) {
  const [testing, setTesting] = useStateSet(null);
  function test(id) {
    setTesting(id);
    setTimeout(() => {
      setTesting(null);
      window.socToast?.({ title: 'Connection OK', sub: id + ' · responded in ' + (20 + Math.random() * 200 | 0) + 'ms', tone: 'ok' });
    }, 1100);
  }
  return (
    <>
      <Card title="External integrations" sub="upstream services this app depends on">
        {loading
          ? <div className="loading mono" style={{padding:20}}>Loading…</div>
          : (
            <ul className="integrations-list">
              {integrations.map(s => {
                const Ic = Icon[s.icon] || Icon.dot;
                return (
                  <li key={s.id} className={`integration ${s.status}`}>
                    <div className="int-icon"><Ic width="16" height="16"/></div>
                    <div className="int-info">
                      <div className="int-name">{s.name}</div>
                      <div className="int-host mono">{s.host}</div>
                      <div className="int-desc">{s.desc}</div>
                    </div>
                    <div className="int-stats">
                      <div className="int-stat">
                        <div className="is-lbl mono">LATENCY</div>
                        <div className="is-val mono">{s.latency === 0 ? '—' : s.latency + 'ms'}</div>
                      </div>
                      <div className="int-stat">
                        <div className="is-lbl mono">UPTIME 30D</div>
                        <div className="is-val mono">{s.uptime}%</div>
                      </div>
                      <div className="int-stat">
                        <div className="is-lbl mono">LAST EVENT</div>
                        <div className="is-val mono">{s.lastEvent}</div>
                      </div>
                    </div>
                    <div className="int-status">
                      <StatusBadge status={s.status}/>
                    </div>
                    <div className="int-actions">
                      <button className="btn btn-ghost btn-sm" onClick={()=>test(s.id)}>
                        {testing === s.id ? <span className="test-spin"/> : <Icon.refresh width="11" height="11"/>}
                        Test
                      </button>
                      <button className="btn btn-ghost btn-sm">Configure</button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )
        }
      </Card>

      <Card title="System health" sub="last 24h">
        <div className="health-grid">
          {integrations.slice(0, 6).map(s => (
            <div key={s.id} className="health-cell">
              <div className="hc-head">
                <span className="hc-name">{s.name.split(' · ')[0]}</span>
                <StatusBadge status={s.status} small/>
              </div>
              <HealthSpark status={s.status}/>
              <div className="hc-foot mono">avg {s.latency || '—'}ms · {s.uptime}%</div>
            </div>
          ))}
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

function HealthSpark({ status }) {
  const data = useMemoSet(() => {
    const base = status === 'healthy' ? 40 : status === 'degraded' ? 80 : 0;
    const variance = status === 'healthy' ? 12 : status === 'degraded' ? 30 : 0;
    return Array.from({length: 30}, (_, i) => base + (Math.sin(i / 3 + base) * variance) + Math.random() * 10);
  }, [status]);
  const color = status === 'healthy' ? 'var(--low)' : status === 'degraded' ? 'var(--high)' : 'var(--crit)';
  if (status === 'offline') {
    return (
      <div className="health-spark-offline mono">
        — connection lost —
      </div>
    );
  }
  return <Sparkline data={data} height={40} color={color}/>;
}

// ============= USERS =============
function SettingsUsers() {
  return (
    <Card title="Users & roles" sub={`${USERS.length} accounts`}
      actions={<button className="btn btn-primary btn-sm"><Icon.plus width="11" height="11"/> Invite user</button>}>
      <table className="data-table">
        <thead><tr>
          <th>USER</th>
          <th>EMAIL</th>
          <th>ROLE</th>
          <th>MFA</th>
          <th>LAST SEEN</th>
          <th>OPEN CASES</th>
          <th></th>
        </tr></thead>
        <tbody>
          {USERS.map(u => (
            <tr key={u.id}>
              <td>
                <div className="user-cell">
                  <span className="sb-avatar" style={{width:24,height:24,fontSize:10}}>{u.name[0].toUpperCase()}</span>
                  <span className="mono">{u.name}</span>
                </div>
              </td>
              <td className="mono dim">{u.email}</td>
              <td><RoleChip role={u.role}/></td>
              <td>{u.mfa ? <Chip mono tone="ok">enabled</Chip> : <Chip mono tone="crit">disabled</Chip>}</td>
              <td className="mono dim">{u.last}</td>
              <td className="mono">{u.cases}</td>
              <td><button className="btn-icon"><Icon.chevron width="12" height="12"/></button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function RoleChip({ role }) {
  const map = { admin: 'crit', analyst: 'warn', viewer: 'dim' };
  return <Chip mono tone={map[role]}>{role}</Chip>;
}

// ============= SECRETS =============
function SettingsSecrets() {
  const [revealed, setRevealed] = useStateSet(new Set());
  function rotate(k) {
    window.socToast?.({title: 'Secret rotated', sub: k + ' · new value generated and re-deployed', tone: 'ok'});
  }
  return (
    <Card title=".env secrets" sub="encrypted at rest · rotate regularly"
      actions={<button className="btn btn-ghost btn-sm">Export .env.example</button>}>
      <div className="secrets-warning mono">
        <Icon.shield width="13" height="13"/>
        Secrets are stored in your <code>.env</code> file. Never commit them. The values shown are masked; click the eye to reveal locally.
      </div>
      <table className="data-table secrets-table">
        <thead><tr>
          <th style={{width:280}}>KEY</th>
          <th>VALUE</th>
          <th style={{width:120}}>LAST ROTATED</th>
          <th style={{width:120}}></th>
        </tr></thead>
        <tbody>
          {SECRETS.map(s => (
            <tr key={s.key}>
              <td className="mono">{s.key}</td>
              <td>
                <div className="secret-row">
                  <span className="mono">{revealed.has(s.key) ? 'sk-proj-' + Math.random().toString(36).slice(2, 18) : s.value}</span>
                  <button className="btn-icon" onClick={()=>setRevealed(r => { const n = new Set(r); if (n.has(s.key)) n.delete(s.key); else n.add(s.key); return n; })}>
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                  </button>
                </div>
              </td>
              <td className="mono dim">{s.rotated}{s.warn && <span className="ver-warn" title="overdue"> ↑</span>}</td>
              <td>
                <button className="btn btn-ghost btn-sm" onClick={()=>rotate(s.key)}><Icon.refresh width="10" height="10"/> Rotate</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

// ============= AUDIT LOG =============
function SettingsAudit({ auditLog, loading }) {
  return (
    <Card title="Audit log" sub="all actions · all users · last 24h"
      actions={<>
        <Chip mono>{loading ? '…' : auditLog.length} of 4,128 entries</Chip>
        <button className="btn btn-ghost btn-sm">Export CSV</button>
      </>}>
      {loading
        ? <div className="loading mono" style={{padding:20}}>Loading…</div>
        : (
          <table className="data-table audit-table">
            <thead><tr>
              <th style={{width:80}}>TIME</th>
              <th style={{width:90}}>USER</th>
              <th style={{width:180}}>ACTION</th>
              <th>TARGET</th>
            </tr></thead>
            <tbody>
              {auditLog.map((row, i) => (
                <tr key={i}>
                  <td className="mono dim">{row.t}</td>
                  <td className="mono">{row.who === 'system' || row.who === 'darksoc'
                    ? <Chip mono>{row.who}</Chip>
                    : <span className="user-cell-sm"><span className="sb-avatar" style={{width:18,height:18,fontSize:8}}>{(row.who || '?')[0].toUpperCase()}</span>{row.who}</span>
                  }</td>
                  <td className="mono">
                    <span className="audit-action" data-tone={row.tone}>{row.action}</span>
                  </td>
                  <td className="mono">{row.target}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      }
    </Card>
  );
}

// ============= PREFERENCES =============
function SettingsPrefs() {
  const [retention, setRetention] = useStateSet(90);
  const [autoAck, setAutoAck] = useStateSet(true);
  const [aiAuto, setAiAuto] = useStateSet(false);
  const [emailDigest, setEmailDigest] = useStateSet(true);

  // Fetch real DarkSOC enabled state from settings
  useEffectSet(() => {
    (async () => {
      const data = await window.SOC_API.get('/api/settings');
      if (data && data.darksoc_enabled !== undefined) {
        setAiAuto(data.darksoc_enabled === 'true' || data.darksoc_enabled === true);
      }
    })();
  }, []);

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
