// SP-CM Alerts — TheHive inbox-style triage queue
const { useState: useSPA, useMemo: useSPM } = React;

// Pre-curated alerts (different shape from SIEM — these have titles, descriptions, observables)
const HIVE_ALERTS = [
  {
    id: 'AL-2641',
    title: 'PowerShell C2 beacon detected · web-prod-01',
    description: 'Encoded PowerShell payload spawned by cmd.exe on web-prod-01 attempting outbound connection to known Tor exit node. Behavior matches Cobalt Strike beacon pattern.',
    source: 'Wazuh · rule 92653',
    sev: 'critical', tlp: 'amber', pap: 'amber',
    status: 'new', read: false,
    when: ago(2),
    observables: { ip: 2, domain: 0, url: 1, hash: 1, host: 1 },
    tags: ['T1059.001', 'T1071', 'cobalt-strike', 'tor'],
    assignee: null,
    similar: 3,
  },
  {
    id: 'AL-2640',
    title: 'Brute force surge against SSH · 47 attempts',
    description: 'Authentication failures from 45.155.205.18 targeting db-primary over 12-minute window. Source IP appears in known credential-stuffing botnet feed.',
    source: 'Wazuh · rule 5710',
    sev: 'high', tlp: 'green', pap: 'green',
    status: 'new', read: false,
    when: ago(8),
    observables: { ip: 1, domain: 0, url: 0, hash: 0, host: 1 },
    tags: ['T1110', 'brute-force'],
    assignee: null,
    similar: 14,
  },
  {
    id: 'AL-2639',
    title: 'Outbound to known C2 · db-primary',
    description: 'Detected connection from db-primary (10.0.4.18) to 91.219.236.222 — flagged as active C2 infrastructure by AlienVault OTX and AbuseIPDB.',
    source: 'MISP · feed 12',
    sev: 'critical', tlp: 'red', pap: 'red',
    status: 'updated', read: true,
    when: ago(14),
    observables: { ip: 1, domain: 1, url: 0, hash: 0, host: 1 },
    tags: ['T1071', 'c2', 'alienvault'],
    assignee: 'younes',
    similar: 0,
  },
  {
    id: 'AL-2638',
    title: 'Phishing email cluster · 24 recipients · finance dept',
    description: 'Inbound emails with malicious link to credential-harvesting page. Subject line patterns match recent FIN7 campaign reported by CISA.',
    source: 'MS Defender · phish-feed',
    sev: 'medium', tlp: 'amber', pap: 'green',
    status: 'imported', read: true,
    when: ago(22),
    observables: { ip: 4, domain: 2, url: 6, hash: 0, host: 0 },
    tags: ['T1566.002', 'phishing', 'fin7'],
    assignee: 'sara',
    similar: 0,
  },
  {
    id: 'AL-2637',
    title: 'Container escape attempt · k8s-worker-1',
    description: 'Suspicious privileged operation in container namespace; container attempted to mount host filesystem. Wazuh rule 92710 with anomaly score 0.94.',
    source: 'Wazuh · rule 92710',
    sev: 'high', tlp: 'amber', pap: 'amber',
    status: 'new', read: false,
    when: ago(31),
    observables: { ip: 0, domain: 0, url: 0, hash: 1, host: 1 },
    tags: ['T1611', 'container'],
    assignee: null,
    similar: 0,
  },
  {
    id: 'AL-2636',
    title: 'Kerberoasting attempt against svc accounts',
    description: 'Multiple Kerberos AS-REQ tickets requested with weak encryption (RC4) for service accounts on win-dc-01. Indicative of offline password cracking attempt.',
    source: 'Wazuh · rule 92900',
    sev: 'high', tlp: 'amber', pap: 'amber',
    status: 'updated', read: true,
    when: ago(48),
    observables: { ip: 1, domain: 0, url: 0, hash: 0, host: 1 },
    tags: ['T1558.003', 'kerberoasting'],
    assignee: 'younes',
    similar: 2,
  },
  {
    id: 'AL-2635',
    title: 'Audit log tampering · win-dc-01',
    description: 'Windows Security event log was cleared at 14:21 UTC by a non-administrator session. No legitimate maintenance window scheduled.',
    source: 'Wazuh · rule 60106',
    sev: 'high', tlp: 'amber', pap: 'amber',
    status: 'new', read: false,
    when: ago(62),
    observables: { ip: 0, domain: 0, url: 0, hash: 0, host: 1 },
    tags: ['T1070.001', 'defense-evasion'],
    assignee: null,
    similar: 0,
  },
  {
    id: 'AL-2634',
    title: 'Tor exit node connection · web-prod-01',
    description: 'Outbound TCP/443 from web-prod-01 to 193.32.162.157, identified as Tor exit by dan.me.uk feed.',
    source: 'Wazuh · rule 92107',
    sev: 'medium', tlp: 'green', pap: 'green',
    status: 'imported', read: true,
    when: ago(95),
    observables: { ip: 1, domain: 0, url: 0, hash: 0, host: 1 },
    tags: ['T1090.003', 'tor'],
    assignee: null,
    similar: 5,
  },
  {
    id: 'AL-2633',
    title: 'Suspicious WMI subscription created',
    description: 'New permanent WMI event subscription created on win-dc-01 referencing PowerShell command — common persistence technique.',
    source: 'Wazuh · rule 92450',
    sev: 'high', tlp: 'amber', pap: 'amber',
    status: 'new', read: false,
    when: ago(124),
    observables: { ip: 0, domain: 0, url: 0, hash: 0, host: 1 },
    tags: ['T1546.003', 'persistence'],
    assignee: null,
    similar: 0,
  },
  {
    id: 'AL-2632',
    title: 'New scheduled task created · suspicious path',
    description: 'Scheduled task created from %APPDATA% location pointing to powershell.exe with encoded args. Path is not on any application allowlist.',
    source: 'Wazuh · rule 92451',
    sev: 'medium', tlp: 'green', pap: 'green',
    status: 'ignored', read: true,
    when: ago(180),
    observables: { ip: 0, domain: 0, url: 0, hash: 1, host: 1 },
    tags: ['T1053.005', 'persistence'],
    assignee: null,
    similar: 0,
  },
  {
    id: 'AL-2631',
    title: 'Unsigned driver loaded · win-dc-02',
    description: 'A driver without a Microsoft-trusted signature was loaded at boot. Possibly a legitimate vendor driver, but warrants verification against fleet baseline.',
    source: 'Wazuh · rule 92810',
    sev: 'medium', tlp: 'green', pap: 'green',
    status: 'imported', read: true,
    when: ago(240),
    observables: { ip: 0, domain: 0, url: 0, hash: 2, host: 1 },
    tags: ['T1014', 'rootkit-suspected'],
    assignee: null,
    similar: 0,
  },
  {
    id: 'AL-2630',
    title: 'Crypto miner signature · k8s-worker-2',
    description: 'Process matching XMRig hash a4f8b2c9… observed running with unusual CPU pattern. Confirmed match in VirusTotal (62/94 engines).',
    source: 'YARA · miner-rules',
    sev: 'high', tlp: 'amber', pap: 'green',
    status: 'updated', read: true,
    when: ago(310),
    observables: { ip: 1, domain: 1, url: 0, hash: 1, host: 1 },
    tags: ['T1496', 'crypto-mining'],
    assignee: 'sara',
    similar: 0,
  },
];

function ago(min) { return new Date(Date.now() - min * 60000); }

const TLP_INFO = {
  red:    { color: 'oklch(0.68 0.20 22)',  bg: 'oklch(0.30 0.08 22 / 0.22)',  label: 'TLP:RED' },
  amber:  { color: 'oklch(0.78 0.16 50)',  bg: 'oklch(0.30 0.08 50 / 0.22)',  label: 'TLP:AMBER' },
  green:  { color: 'oklch(0.78 0.14 150)', bg: 'oklch(0.30 0.08 150 / 0.22)', label: 'TLP:GREEN' },
  white:  { color: 'oklch(0.85 0.005 250)',bg: 'oklch(0.30 0.005 250 / 0.22)',label: 'TLP:WHITE' },
};

function PageSPAlerts() {
  const [filter, setFilter] = useSPA('all');
  const [sevFilter, setSevFilter] = useSPA('all');
  const [selectedId, setSelectedId] = useSPA(HIVE_ALERTS[0].id);
  const [selectedSet, setSelectedSet] = useSPA(new Set());

  const filtered = useSPM(() => HIVE_ALERTS.filter(a => {
    if (filter === 'unread' && a.read) return false;
    if (filter === 'imported' && a.status !== 'imported') return false;
    if (filter === 'updated' && a.status !== 'updated') return false;
    if (filter === 'new' && a.status !== 'new') return false;
    if (filter === 'assigned-me' && a.assignee !== 'younes') return false;
    if (filter === 'unassigned' && a.assignee !== null) return false;
    if (sevFilter !== 'all' && a.sev !== sevFilter) return false;
    return true;
  }), [filter, sevFilter]);

  const counts = {
    all:        HIVE_ALERTS.length,
    unread:     HIVE_ALERTS.filter(a => !a.read).length,
    new:        HIVE_ALERTS.filter(a => a.status === 'new').length,
    updated:    HIVE_ALERTS.filter(a => a.status === 'updated').length,
    imported:   HIVE_ALERTS.filter(a => a.status === 'imported').length,
    'assigned-me': HIVE_ALERTS.filter(a => a.assignee === 'younes').length,
    unassigned: HIVE_ALERTS.filter(a => a.assignee === null).length,
  };

  const selected = HIVE_ALERTS.find(a => a.id === selectedId);

  function toggleSelect(id, e) {
    e.stopPropagation();
    setSelectedSet(s => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function bulkPromote() {
    const n = selectedSet.size || 1;
    window.socToast?.({ title: `${n} alert${n>1?'s':''} promoted to case`, sub: 'CASE-447' + Math.floor(Math.random()*9) + ' created · linked', tone: 'ok' });
    setSelectedSet(new Set());
  }
  function bulkIgnore() {
    window.socToast?.({ title: `${selectedSet.size} alerts ignored`, sub: 'will not trigger again for 24h', tone: 'default' });
    setSelectedSet(new Set());
  }

  return (
    <div className="page" data-screen-label="13 SP-CM Alerts">
      <Topbar
        title="SP-CM Alerts"
        sub="Pre-case triage inbox · TheHive"
        actions={<>
          <Chip mono>{counts.unread} unread · {counts.new} new</Chip>
          <button className="btn btn-ghost"><Icon.refresh width="13" height="13"/> Refresh</button>
          <button className="btn btn-ghost"><Icon.filter width="13" height="13"/> Rules</button>
        </>}
      />
      <div className="page-body sp-alerts-body">
        <aside className="sp-side">
          <Card title="Folders" sub="filter inbox">
            <ul className="sp-folders">
              {[
                { id: 'all',         label: 'All alerts',        icon: Icon.inbox },
                { id: 'unread',      label: 'Unread',            icon: Icon.dot },
                { id: 'new',         label: 'New',               icon: Icon.bell },
                { id: 'updated',     label: 'Updated',           icon: Icon.refresh },
                { id: 'imported',    label: 'Imported',          icon: Icon.share },
                { id: 'assigned-me', label: 'Assigned to me',    icon: Icon.user },
                { id: 'unassigned',  label: 'Unassigned',        icon: Icon.target },
              ].map(f => {
                const Ic = f.icon;
                return (
                  <li key={f.id}>
                    <button className={`sp-folder ${filter===f.id?'on':''}`} onClick={()=>setFilter(f.id)}>
                      <Ic width="13" height="13"/>
                      <span>{f.label}</span>
                      <span className="sp-folder-count mono">{counts[f.id]}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </Card>

          <Card title="Severity">
            <ul className="sp-folders">
              {['all','critical','high','medium','low'].map(s => (
                <li key={s}>
                  <button className={`sp-folder ${sevFilter===s?'on':''}`} onClick={()=>setSevFilter(s)}>
                    {s === 'all'
                      ? <Icon.grid width="13" height="13"/>
                      : <SevDot sev={s}/>
                    }
                    <span style={{textTransform:'capitalize'}}>{s}</span>
                    <span className="sp-folder-count mono">
                      {s === 'all' ? HIVE_ALERTS.length : HIVE_ALERTS.filter(a => a.sev === s).length}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </Card>

          <Card title="Sources" sub="feed integrations">
            <ul className="sp-sources">
              <li><span className="ss-pip" style={{background:'var(--low)'}}/> Wazuh <span className="mono dim" style={{marginLeft:'auto'}}>9</span></li>
              <li><span className="ss-pip" style={{background:'var(--acc)'}}/> MISP <span className="mono dim" style={{marginLeft:'auto'}}>1</span></li>
              <li><span className="ss-pip" style={{background:'var(--high)'}}/> MS Defender <span className="mono dim" style={{marginLeft:'auto'}}>1</span></li>
              <li><span className="ss-pip" style={{background:'var(--med)'}}/> YARA <span className="mono dim" style={{marginLeft:'auto'}}>1</span></li>
            </ul>
          </Card>
        </aside>

        <main className="sp-inbox">
          <div className="sp-inbox-tb">
            <label className="sp-checkbox">
              <input type="checkbox"
                checked={selectedSet.size === filtered.length && filtered.length > 0}
                onChange={() => {
                  if (selectedSet.size === filtered.length) setSelectedSet(new Set());
                  else setSelectedSet(new Set(filtered.map(a => a.id)));
                }}
              />
              <span className="cb-mark"/>
            </label>
            <span className="sp-inbox-tb-label mono">
              {selectedSet.size > 0 ? `${selectedSet.size} selected` : `${filtered.length} alerts`}
            </span>
            {selectedSet.size > 0 && (
              <div className="sp-inbox-actions">
                <button className="btn btn-primary btn-sm" onClick={bulkPromote}>
                  <Icon.folder width="11" height="11"/> Promote to case
                </button>
                <button className="btn btn-ghost btn-sm" onClick={bulkIgnore}>Ignore</button>
                <button className="btn btn-ghost btn-sm">Assign</button>
                <button className="btn btn-ghost btn-sm">Merge</button>
              </div>
            )}
            <div className="sp-inbox-tb-right">
              <Chip mono>sort: newest</Chip>
            </div>
          </div>

          <ul className="sp-list">
            {filtered.map(a => (
              <li key={a.id}
                  className={`sp-item ${selectedId === a.id ? 'sel' : ''} ${!a.read ? 'unread' : ''} ${selectedSet.has(a.id) ? 'checked' : ''}`}
                  onClick={() => setSelectedId(a.id)}>
                <label className="sp-checkbox" onClick={e => e.stopPropagation()}>
                  <input type="checkbox" checked={selectedSet.has(a.id)} onChange={(e) => toggleSelect(a.id, e)}/>
                  <span className="cb-mark"/>
                </label>
                <div className="sp-item-sev">
                  <SevDot sev={a.sev}/>
                </div>
                <div className="sp-item-body">
                  <div className="sp-item-row1">
                    <span className="sp-item-id mono">{a.id}</span>
                    <span className="sp-item-title">{a.title}</span>
                    {!a.read && <span className="sp-unread-dot"/>}
                  </div>
                  <div className="sp-item-row2">
                    <span className="mono dim">{a.source}</span>
                    <span className="sp-tlp mono" style={{color: TLP_INFO[a.tlp].color, background: TLP_INFO[a.tlp].bg}}>{TLP_INFO[a.tlp].label}</span>
                    <span className="sp-status mono" data-status={a.status}>{a.status}</span>
                    <span className="sp-obs mono">
                      <ObsIcons obs={a.observables}/>
                    </span>
                    {a.similar > 0 && <span className="sp-similar mono">+{a.similar} similar</span>}
                  </div>
                  <div className="sp-item-row3">
                    {a.tags.slice(0, 4).map(t => <Chip key={t} mono>{t}</Chip>)}
                  </div>
                </div>
                <div className="sp-item-right">
                  {a.assignee
                    ? <span className="sp-avatar">{a.assignee[0].toUpperCase()}</span>
                    : <span className="sp-unassigned mono">—</span>
                  }
                  <span className="sp-time mono">{relAgo(a.when)}</span>
                </div>
              </li>
            ))}
          </ul>
        </main>

        <aside className="sp-detail">
          {selected && <SPAlertDetail alert={selected} onPromote={bulkPromote}/>}
        </aside>
      </div>
    </div>
  );
}

function ObsIcons({ obs }) {
  const items = [
    { k: 'ip',     icon: Icon.globe,  count: obs.ip },
    { k: 'domain', icon: Icon.share,  count: obs.domain },
    { k: 'url',    icon: Icon.target, count: obs.url },
    { k: 'hash',   icon: Icon.file,   count: obs.hash },
    { k: 'host',   icon: Icon.cpu,    count: obs.host },
  ].filter(it => it.count > 0);
  return (
    <>
      {items.map(it => {
        const Ic = it.icon;
        return (
          <span key={it.k} className="obs-pip" title={`${it.count} ${it.k}`}>
            <Ic width="10" height="10"/> {it.count}
          </span>
        );
      })}
    </>
  );
}

function SPAlertDetail({ alert, onPromote }) {
  return (
    <div className="sp-detail-inner">
      <div className="sp-detail-head">
        <SevChip sev={alert.sev}/>
        <span className="mono dim">{alert.id}</span>
        <span className="sp-tlp mono" style={{color: TLP_INFO[alert.tlp].color, background: TLP_INFO[alert.tlp].bg}}>{TLP_INFO[alert.tlp].label}</span>
      </div>
      <h2 className="sp-detail-title">{alert.title}</h2>
      <div className="sp-detail-meta mono">
        <span>{alert.source}</span>
        <span className="dim">·</span>
        <span>{alert.when.toISOString().slice(0,19).replace('T',' ')} UTC</span>
      </div>

      <p className="sp-detail-desc">{alert.description}</p>

      <div className="sp-detail-tags">
        {alert.tags.map(t => <Chip key={t} mono>{t}</Chip>)}
      </div>

      <div className="sp-section">
        <div className="ds-title">Observables <span className="ds-tag">{Object.values(alert.observables).reduce((a,b)=>a+b,0)}</span></div>
        <div className="sp-obs-grid">
          {Object.entries(alert.observables).filter(([,v]) => v > 0).map(([k,v]) => (
            <div key={k} className="sp-obs-cell">
              <div className="sp-obs-key mono">{k.toUpperCase()}</div>
              <div className="sp-obs-val">{v}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="sp-section">
        <div className="ds-title">AI triage <span className="ds-tag">SOCPilots AI</span></div>
        <div className="ai-verdict">
          <span className="av-pill">{alert.sev === 'critical' ? 'promote · critical' : 'promote · review'}</span>
          <p>{aiTriageNote(alert)}</p>
        </div>
      </div>

      <div className="sp-detail-actions">
        <button className="btn btn-primary" onClick={onPromote}><Icon.folder width="13" height="13"/> Promote to case</button>
        <button className="btn btn-ghost">Merge with similar</button>
        <button className="btn btn-ghost">Ignore</button>
        <button className="btn btn-ghost">Assign</button>
      </div>
    </div>
  );
}

function aiTriageNote(a) {
  const map = {
    critical: 'Behavior strongly indicates active intrusion. Recommend immediate promotion to P1 case with auto-attached IR runbook. Affected host should be isolated within 5 minutes.',
    high:     'Behavior is anomalous and aligns with documented adversary TTPs. Recommend promotion to P2 case. Pivot on observables to look for additional impacted hosts.',
    medium:   'Worth investigating but not currently spreading. Recommend reviewing within 4-hour SLA. Check whether tagged tactic has prior false positives in this environment.',
    low:      'Likely benign. Consider suppressing for 24h while collecting more data, or attach to an existing case if related.',
  };
  return map[a.sev];
}

function relAgo(d) {
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.round(h/24)}d`;
}

Object.assign(window, { PageSPAlerts });
