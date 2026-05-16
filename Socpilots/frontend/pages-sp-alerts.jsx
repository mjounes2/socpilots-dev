// SP-CM Alerts — TheHive inbox-style triage queue (production-parity)
const { useState: useSPA, useMemo: useSPM, useEffect: useSPE, useRef: useSPR, useCallback: useSPC } = React;

// ─── TLP metadata ────────────────────────────────────────────
const TLP_INFO = {
  red:   { color: 'oklch(0.68 0.20 22)',  bg: 'oklch(0.30 0.08 22  / 0.22)', label: 'TLP:RED'   },
  amber: { color: 'oklch(0.78 0.16 50)',  bg: 'oklch(0.30 0.08 50  / 0.22)', label: 'TLP:AMBER' },
  green: { color: 'oklch(0.78 0.14 150)', bg: 'oklch(0.30 0.08 150 / 0.22)', label: 'TLP:GREEN' },
  white: { color: 'oklch(0.85 0.005 250)',bg: 'oklch(0.30 0.005 250/ 0.22)', label: 'TLP:WHITE' },
};

// ─── Helpers ──────────────────────────────────────────────────
function sevStr(s) {
  if (typeof s === 'string') return s.toLowerCase();
  return { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low' }[s] || 'low';
}
function statusStr(s) {
  if (!s) return 'new';
  return { New: 'new', InProgress: 'updated', Imported: 'imported', Resolved: 'imported', Ignored: 'ignored' }[s] || s.toLowerCase();
}
function tlpFromTags(tags) {
  const t = (tags || []).find(x => /^tlp:/i.test(x));
  if (!t) return 'green';
  const v = t.split(':')[1]?.toLowerCase();
  return ['red','amber','green','white'].includes(v) ? v : 'green';
}
function relAgo(ts) {
  if (!ts) return '—';
  const s = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60)  return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60)  return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 24)  return `${h}h`;
  return `${Math.round(h / 24)}d`;
}

// Extract MITRE technique IDs from tags array
function extractMitre(tags) {
  return (tags || []).filter(t => /^T\d{4}(\.\d{3})?$/.test(t));
}

// Extract non-TLP, non-MITRE tags (regular named tags)
function extractNamedTags(tags) {
  return (tags || []).filter(t => !/^tlp:/i.test(t) && !/^T\d{4}/.test(t));
}

// Parse observables from description markdown text
function parseObservables(description) {
  if (!description) return { ip: 0, url: 0, hash: 0, host: 0, total: 0 };
  const ipRe   = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
  const urlRe  = /https?:\/\/[^\s)\]|'"]+/g;
  const hashRe = /\b[0-9a-f]{32}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b/gi;
  const hostRe = /\*\*Agent Name\*\*\s*\|\s*([^\n|]+)/gi;
  const ips    = new Set((description.match(ipRe)   || []).filter(ip => !ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('172.')));
  const urls   = new Set(description.match(urlRe)   || []);
  const hashes = new Set(description.match(hashRe)  || []);
  const hosts  = new Set([...(description.match(hostRe) || [])].map(m => m.replace(/.*\|\s*/, '').trim()));
  const ip   = ips.size;
  const url  = urls.size;
  const hash = hashes.size;
  const host = hosts.size;
  return { ip, url, hash, host, total: ip + url + hash + host };
}

// Extract rule ID from sourceRef string
function extractRuleId(sourceRef, description) {
  if (!sourceRef) return null;
  // sourceRef like "sfl1778958227762" or "wazuh-rule-100200" or "rule 92653"
  const ruleMatch = (description || '').match(/Rule ID\*\*\s*\|\s*(\d+)/i) ||
                    (description || '').match(/\*\*Rule ID.*?\*\*.*?(\d{3,6})/i);
  return ruleMatch ? ruleMatch[1] : null;
}

// AI triage recommendation based on severity + tags
function getAIRecommendation(alert) {
  const sev   = sevStr(alert.severity);
  const mitre = extractMitre(alert.tags);
  const named = extractNamedTags(alert.tags);

  const recs = {
    critical: { tone: 'var(--crit)', action: 'promote · critical',
      text: 'Behavior strongly indicates active intrusion. Recommend immediate promotion to P1 case with auto-attached IR runbook. Affected host should be isolated within 5 minutes.' },
    high:     { tone: 'var(--high)', action: 'promote · high',
      text: 'High-severity indicator detected. Recommend promotion to case for analyst review. Correlate with UEBA and check lateral movement paths before escalating.' },
    medium:   { tone: 'var(--med)',  action: 'investigate · medium',
      text: 'Medium confidence signal. Verify against baseline and similar alerts. Correlate with other indicators before promotion. May be a true positive requiring further analysis.' },
    low:      { tone: 'var(--low)',  action: 'monitor · low',
      text: 'Low-priority signal. Likely benign activity. Monitor for recurrence. No immediate action required unless part of a pattern.' },
  };
  return recs[sev] || recs.low;
}

// ─── Observable icons in list row ────────────────────────────
function ObsPips({ obs }) {
  if (!obs || obs.total === 0) return null;
  const items = [
    { k: 'ip',   icon: '⊙', count: obs.ip   },
    { k: 'url',  icon: '⌁', count: obs.url  },
    { k: 'hash', icon: '#', count: obs.hash  },
    { k: 'host', icon: '⬡', count: obs.host  },
  ].filter(i => i.count > 0);
  return (
    <span style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>
      {items.map(it => (
        <span key={it.k} title={`${it.count} ${it.k}${it.count > 1 ? 's' : ''}`}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 3,
                   fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--fg-3)' }}>
          <span>{it.icon}</span>
          <span>{it.count}</span>
        </span>
      ))}
    </span>
  );
}

// ─── Observable type cards in detail panel ───────────────────
function ObsCards({ obs }) {
  if (!obs || obs.total === 0) return <span className="mono dim" style={{ fontSize: 11 }}>No observables extracted</span>;
  const types = [
    { k: 'ip',   label: 'IP',   count: obs.ip   },
    { k: 'url',  label: 'URL',  count: obs.url  },
    { k: 'hash', label: 'HASH', count: obs.hash },
    { k: 'host', label: 'HOST', count: obs.host },
  ].filter(t => t.count > 0);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.min(types.length, 4)}, 1fr)`, gap: 8, marginTop: 8 }}>
      {types.map(t => (
        <div key={t.k} style={{ background: 'var(--bg-0)', border: '1px solid var(--ln)',
                                borderRadius: 4, padding: '8px 10px', textAlign: 'center' }}>
          <div style={{ fontSize: 20, fontWeight: 500, fontFamily: 'var(--mono)', color: 'var(--fg-0)' }}>{t.count}</div>
          <div style={{ fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--fg-3)', marginTop: 2 }}>{t.label}</div>
        </div>
      ))}
    </div>
  );
}

// ─── Alert detail panel ───────────────────────────────────────
function SPAlertDetail({ alert, onPromote, onIgnore, onAssign, currentUser }) {
  const API     = window.SOC_API;
  const sev     = sevStr(alert.severity);
  const tlpKey  = tlpFromTags(alert.tags);
  const tlp     = TLP_INFO[tlpKey];
  const mitre   = extractMitre(alert.tags);
  const named   = extractNamedTags(alert.tags);
  const obs     = parseObservables(alert.description);
  const ruleId  = extractRuleId(alert.sourceRef, alert.description);
  const aiRec   = getAIRecommendation(alert);
  const [promoting, setPromoting]   = useSPA(false);
  const [assigning, setAssigning]   = useSPA(false);

  async function promote() {
    setPromoting(true);
    const r = await API.post('/api/hive-alerts/promote', { alertId: alert.id });
    setPromoting(false);
    if (r && !r.error) {
      window.socToast?.({ title: 'Promoted to case', sub: `Case #${r.caseNumber || r.caseId}`, tone: 'ok' });
      if (onPromote) onPromote(alert.id);
    } else {
      window.socToast?.({ title: 'Promote failed', sub: r?.error || 'Check TheHive connection', tone: 'error' });
    }
  }

  async function ignore() {
    await API.post(`/api/hive-alerts/${alert.id}/ignore`, {});
    window.socToast?.({ title: 'Alert ignored', sub: alert.id, tone: 'default' });
    if (onIgnore) onIgnore(alert.id);
  }

  async function assign() {
    setAssigning(true);
    const r = await API.post(`/api/hive-alerts/${alert.id}/assign`, { assignee: currentUser });
    setAssigning(false);
    if (r && !r.error) window.socToast?.({ title: 'Assigned to you', sub: currentUser, tone: 'ok' });
    if (onAssign) onAssign(alert.id);
  }

  return (
    <div className="sp-detail-inner">
      {/* Head */}
      <div className="sp-detail-head">
        <SevChip sev={sev}/>
        <span className="mono dim">{alert.sourceRef || alert.id}</span>
        <span className="sp-tlp mono" style={{ color: tlp.color, background: tlp.bg }}>{tlp.label}</span>
      </div>

      <h2 className="sp-detail-title">{alert.title}</h2>

      <div className="sp-detail-meta mono">
        <span>{alert.source || '—'}</span>
        {ruleId && <><span className="dim">·</span><span>rule {ruleId}</span></>}
        <span className="dim">·</span>
        <span>{alert.created ? new Date(alert.created).toISOString().slice(0,19).replace('T',' ') + ' UTC' : '—'}</span>
      </div>

      {alert.description && (
        <p className="sp-detail-desc">
          {alert.description.replace(/#+\s*/g,'').replace(/\*\*([^*]+)\*\*/g,'$1').replace(/\|[^\n]+\n/g,'').trim().slice(0, 280)}
          {alert.description.length > 280 ? '…' : ''}
        </p>
      )}

      {/* MITRE tags */}
      {mitre.length > 0 && (
        <div className="sp-detail-tags" style={{ marginTop: 6 }}>
          {mitre.map(t => (
            <span key={t} style={{ padding: '2px 6px', background: 'rgba(255,171,0,.12)',
                                   border: '1px solid rgba(255,171,0,.25)', borderRadius: 3,
                                   fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--med)' }}>{t}</span>
          ))}
        </div>
      )}

      {/* Named tags */}
      {named.length > 0 && (
        <div className="sp-detail-tags">
          {named.map(t => <Chip key={t} mono>{t}</Chip>)}
        </div>
      )}

      {/* OBSERVABLES */}
      <div className="sp-section" style={{ marginTop: 12 }}>
        <div className="ds-title" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>OBSERVABLES</span>
          <span className="mono dim" style={{ fontSize: 10 }}>{obs.total}</span>
        </div>
        <ObsCards obs={obs} />
      </div>

      {/* AI TRIAGE */}
      <div className="sp-section" style={{ marginTop: 10 }}>
        <div className="ds-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ padding: '2px 7px', background: 'rgba(0,229,255,.12)', border: '1px solid rgba(0,229,255,.25)',
                         borderRadius: 3, fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--acc)' }}>AI TRIAGE</span>
          <span style={{ padding: '2px 7px', background: 'rgba(0,229,255,.08)', border: '1px solid rgba(0,229,255,.18)',
                         borderRadius: 3, fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--acc)' }}>SOCPilots AI</span>
        </div>
        <div style={{ marginTop: 8, padding: '10px 12px', background: 'var(--bg-0)', border: '1px solid var(--ln)',
                      borderLeft: `3px solid ${aiRec.tone}`, borderRadius: 4 }}>
          <div style={{ fontSize: 11, fontFamily: 'var(--mono)', color: aiRec.tone, marginBottom: 5 }}>
            {aiRec.action}
          </div>
          <div style={{ fontSize: 11, color: 'var(--fg-1)', lineHeight: 1.5 }}>
            {aiRec.text}
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="sp-detail-actions">
        <button className="btn btn-primary" style={{ flex: 2 }} onClick={promote} disabled={promoting}>
          <Icon.folder width="13" height="13"/>
          {promoting ? 'Promoting…' : 'Promote to case'}
        </button>
        <button className="btn btn-ghost" onClick={() => window.socToast?.({ title: 'Merge queued', sub: 'Similar alerts will be merged', tone: 'default' })}>
          Merge with similar
        </button>
        <button className="btn btn-ghost" onClick={ignore}>Ignore</button>
        <button className="btn btn-ghost" onClick={assign} disabled={assigning}>
          {assigning ? 'Assigning…' : 'Assign'}
        </button>
      </div>
    </div>
  );
}

// ─── PageSPAlerts ─────────────────────────────────────────────
function PageSPAlerts() {
  const [alerts,     setAlerts]    = useSPA([]);
  const [stats,      setStats]     = useSPA(null);
  const [loading,    setLoading]   = useSPA(true);
  const [error,      setError]     = useSPA(null);
  const [folderFilt, setFolder]    = useSPA('all');     // folder id
  const [statusFilt, setStatusFilt]= useSPA('');        // TheHive status value
  const [sevFilter,  setSevFilter] = useSPA('all');
  const [q,          setQ]         = useSPA('');
  const [page,       setPage]      = useSPA(1);
  const [total,      setTotal]     = useSPA(0);
  const [sort,       setSort]      = useSPA('newest');
  const [selectedId, setSelId]     = useSPA(null);
  const [selectedSet,setSelSet]    = useSPA(new Set());
  const [timeframe,  setTimeframe] = useSPA('24h');
  const [currentUser,setCurrentUser] = useSPA('');
  const searchTimer                = useSPR(null);
  const PAGE_SIZE = 20;

  useSPE(() => {
    window.SOC_API.get('/api/me').then(d => { if (d?.username) setCurrentUser(d.username); });
    loadStats();
  }, []);

  useSPE(() => { loadAlerts(1); }, [sevFilter, statusFilt, timeframe]);

  async function loadStats() {
    const d = await window.SOC_API.get('/api/hive-alerts/stats');
    if (d && !d.error) setStats(d);
  }

  async function loadAlerts(p) {
    setLoading(true); setError(null);
    const params = new URLSearchParams({ page: p, page_size: PAGE_SIZE });
    if (sevFilter !== 'all') {
      const sevMap = { critical: 4, high: 3, medium: 2, low: 1 };
      if (sevMap[sevFilter]) params.set('severity', sevMap[sevFilter]);
    }
    if (statusFilt) params.set('status', statusFilt);
    if (q.trim())   params.set('q', q.trim());
    if (timeframe !== 'all') {
      const ms = { '1h': 3600000, '24h': 86400000, '7d': 604800000 }[timeframe];
      if (ms) params.set('time_from', new Date(Date.now() - ms).toISOString());
    }
    const d = await window.SOC_API.get('/api/hive-alerts?' + params.toString());
    if (!d || d.error) { setError(d?.error || 'SP-CM unavailable'); setLoading(false); return; }
    const list = (d.alerts || d.items || []).map(a => ({
      ...a,
      _sev:   sevStr(a.severity),
      _status: statusStr(a.status),
      _tlp:   tlpFromTags(a.tags),
      _mitre: extractMitre(a.tags),
      _named: extractNamedTags(a.tags),
      _obs:   parseObservables(a.description),
    }));
    setAlerts(list);
    setTotal(d.total || list.length);
    setPage(p);
    if (!selectedId && list.length) setSelId(list[0].id || list[0]._id);
    setLoading(false);
  }

  function handleSearch(val) {
    setQ(val);
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => loadAlerts(1), 400);
  }

  // Source counts from current page
  const sourceCounts = useSPM(() => {
    const map = {};
    alerts.forEach(a => { const s = a.source || 'Unknown'; map[s] = (map[s] || 0) + 1; });
    return Object.entries(map).sort((a, b) => b[1] - a[1]);
  }, [alerts]);

  const counts = useSPM(() => ({
    all:      stats?.total  || total,
    unread:   stats?.new    || 0,
    new:      stats?.new    || 0,
    updated:  stats?.in_progress || 0,
    imported: 0,
  }), [stats, total]);

  const selected = alerts.find(a => (a.id || a._id) === selectedId);

  function toggleSelect(id, e) {
    e.stopPropagation();
    setSelSet(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }

  function afterPromote(id) {
    setAlerts(prev => prev.filter(a => (a.id || a._id) !== id));
    if (selectedId === id) setSelId(null);
    loadStats();
  }

  function afterIgnore(id) {
    setAlerts(prev => prev.filter(a => (a.id || a._id) !== id));
    if (selectedId === id) setSelId(null);
  }

  // Sorted alerts (client-side by current page)
  const sortedAlerts = useSPM(() => {
    const arr = [...alerts];
    if (sort === 'newest') arr.sort((a, b) => new Date(b.created || 0) - new Date(a.created || 0));
    else if (sort === 'oldest') arr.sort((a, b) => new Date(a.created || 0) - new Date(b.created || 0));
    else if (sort === 'severity') arr.sort((a, b) => sevStr(b.severity).localeCompare(sevStr(a.severity)));
    return arr;
  }, [alerts, sort]);

  const FOLDERS = [
    { id: 'all',      label: 'All alerts',     icon: Icon.inbox,   status: '',           count: counts.all },
    { id: 'unread',   label: 'Unread',          icon: Icon.bell,    status: 'New',        count: counts.unread },
    { id: 'new',      label: 'New',             icon: Icon.spark,   status: 'New',        count: counts.new },
    { id: 'updated',  label: 'Updated',         icon: Icon.refresh, status: 'InProgress', count: counts.updated },
    { id: 'imported', label: 'Imported',        icon: Icon.share,   status: 'Imported',   count: 0 },
    { id: 'mine',     label: 'Assigned to me',  icon: Icon.user,    status: '',           count: 0 },
    { id: 'unassigned',label:'Unassigned',      icon: Icon.alert,   status: '',           count: 0 },
  ];

  return (
    <div className="page" data-screen-label="13 SP-CM Alerts">
      <Topbar
        title="SP-CM Alerts"
        sub="Pre-case triage inbox · TheHive"
        actions={<>
          {stats && (
            <span style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--fg-2)' }}>
              <span style={{ color: 'var(--low)' }}>●</span>{' '}
              {new Date().toISOString().slice(0,19).replace('T',' ')} UTC
              {' · '}{stats.new || 0} unread · {stats.new || 0} new
            </span>
          )}
          <button className="btn btn-ghost" onClick={() => { loadAlerts(page); loadStats(); }}>
            <Icon.refresh width="13" height="13"/> Refresh
          </button>
          <button className="btn btn-ghost" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <Icon.filter width="13" height="13"/> Rules
          </button>
        </>}
      />

      <div className="page-body sp-alerts-body">

        {/* ── Left sidebar ── */}
        <aside className="sp-side">
          {/* Folders */}
          <div style={{ padding: '8px 10px 4px', fontSize: 11, fontWeight: 600, color: 'var(--fg-2)' }}>Folders</div>
          <div style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--fg-3)', padding: '0 10px 8px' }}>filter inbox</div>
          <ul className="sp-folders">
            {FOLDERS.map(f => {
              const Ic = f.icon;
              return (
                <li key={f.id}>
                  <button
                    className={`sp-folder ${folderFilt === f.id ? 'on' : ''}`}
                    onClick={() => { setFolder(f.id); setStatusFilt(f.status); setPage(1); loadAlerts(1); }}>
                    <Ic width="13" height="13"/>
                    <span>{f.label}</span>
                    <span className="sp-folder-count mono">{(f.count || 0).toLocaleString()}</span>
                  </button>
                </li>
              );
            })}
          </ul>

          {/* Severity filter */}
          <div style={{ padding: '10px 10px 4px', fontSize: 11, fontWeight: 600, color: 'var(--fg-2)', borderTop: '1px solid var(--ln)', marginTop: 4 }}>Severity</div>
          <ul className="sp-folders">
            {['all','critical','high','medium','low'].map(s => (
              <li key={s}>
                <button className={`sp-folder ${sevFilter === s ? 'on' : ''}`}
                  onClick={() => { setSevFilter(s); setPage(1); }}>
                  {s === 'all' ? <Icon.grid width="13" height="13"/> : <SevDot sev={s}/>}
                  <span style={{ textTransform: 'capitalize' }}>{s}</span>
                  <span className="sp-folder-count mono">
                    {s === 'all' ? (stats?.total || total).toLocaleString() :
                      (stats?.[s] || alerts.filter(a => a._sev === s).length || 0).toLocaleString()}
                  </span>
                </button>
              </li>
            ))}
          </ul>

          {/* Sources */}
          {sourceCounts.length > 0 && (
            <>
              <div style={{ padding: '10px 10px 4px', fontSize: 11, fontWeight: 600, color: 'var(--fg-2)', borderTop: '1px solid var(--ln)', marginTop: 4 }}>Sources</div>
              <div style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--fg-3)', padding: '0 10px 6px' }}>feed integrations</div>
              <ul className="sp-folders">
                {sourceCounts.slice(0, 6).map(([src, cnt]) => (
                  <li key={src}>
                    <button className="sp-folder" style={{ cursor: 'default' }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--low)', flexShrink: 0 }} />
                      <span style={{ flex: 1, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{src}</span>
                      <span className="sp-folder-count mono">{cnt}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </aside>

        {/* ── Inbox list ── */}
        <main className="sp-inbox">
          {/* Toolbar */}
          <div className="sp-inbox-tb">
            <label className="sp-checkbox">
              <input type="checkbox"
                checked={selectedSet.size === alerts.length && alerts.length > 0}
                onChange={() => selectedSet.size === alerts.length ? setSelSet(new Set()) : setSelSet(new Set(alerts.map(a => a.id || a._id)))}
              />
              <span className="cb-mark"/>
            </label>
            <input
              className="mono"
              placeholder="Search title…"
              value={q}
              onChange={e => handleSearch(e.target.value)}
              style={{ flex: 1, fontSize: 11, minWidth: 0 }}
            />
            <span className="sp-inbox-tb-label mono">
              {selectedSet.size > 0 ? `${selectedSet.size} selected` : `${total.toLocaleString()} alerts`}
            </span>
            {selectedSet.size > 0 && (
              <div style={{ display: 'flex', gap: 4 }}>
                <button className="btn btn-ghost btn-sm">Ignore</button>
                <button className="btn btn-ghost btn-sm">Assign</button>
              </div>
            )}
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--fg-3)' }}>sort:</span>
              <select className="mono" value={sort} onChange={e => setSort(e.target.value)}
                style={{ fontSize: 10, background: 'transparent', border: 'none', color: 'var(--fg-2)', cursor: 'pointer' }}>
                <option value="newest">newest</option>
                <option value="oldest">oldest</option>
                <option value="severity">severity</option>
              </select>
            </div>
          </div>

          {loading && <div className="empty mono" style={{ padding: 40 }}>Loading from SP-CM…</div>}
          {error   && <div className="empty mono" style={{ color: 'var(--crit)', padding: 40 }}>{error}</div>}

          {!loading && !error && (
            <ul className="sp-list">
              {sortedAlerts.length === 0 && (
                <li className="empty mono" style={{ padding: 32 }}>No alerts match filters</li>
              )}
              {sortedAlerts.map(a => {
                const id      = a.id || a._id;
                const tlp     = TLP_INFO[a._tlp] || TLP_INFO.green;
                const isUnread = a._status === 'new';
                return (
                  <li key={id}
                    className={`sp-item ${selectedId === id ? 'sel' : ''} ${selectedSet.has(id) ? 'checked' : ''}`}
                    onClick={() => setSelId(id)}>
                    <label className="sp-checkbox" onClick={e => e.stopPropagation()}>
                      <input type="checkbox" checked={selectedSet.has(id)} onChange={e => toggleSelect(id, e)}/>
                      <span className="cb-mark"/>
                    </label>
                    <div className="sp-item-sev"><SevDot sev={a._sev}/></div>
                    <div className="sp-item-body">
                      {/* Row 1: ID + title */}
                      <div className="sp-item-row1">
                        <span className="sp-item-id mono">{a.sourceRef || id}</span>
                        <span className="sp-item-title">{a.title}</span>
                      </div>
                      {/* Row 2: source · TLP · status · obs counts · similar */}
                      <div className="sp-item-row2">
                        <span className="mono dim">{a.source || '—'}</span>
                        <span className="sp-tlp mono" style={{ color: tlp.color, background: tlp.bg }}>{tlp.label}</span>
                        <span className="sp-status mono" data-status={a._status}>{a._status.toUpperCase()}</span>
                        <ObsPips obs={a._obs} />
                      </div>
                      {/* Row 3: MITRE + named tags */}
                      {(a._mitre.length > 0 || a._named.length > 0) && (
                        <div className="sp-item-row3">
                          {a._mitre.slice(0, 3).map(t => (
                            <span key={t} style={{ padding: '1px 5px', background: 'rgba(255,171,0,.12)',
                                                   border: '1px solid rgba(255,171,0,.22)', borderRadius: 2,
                                                   fontSize: 9, fontFamily: 'var(--mono)', color: 'var(--med)' }}>{t}</span>
                          ))}
                          {a._named.slice(0, 3).map(t => (
                            <Chip key={t} mono style={{ fontSize: 9 }}>{t}</Chip>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="sp-item-right">
                      {a.assignee
                        ? <span className="sp-avatar">{String(a.assignee)[0].toUpperCase()}</span>
                        : <span className="sp-unassigned mono">—</span>
                      }
                      <span className="sp-time mono">{relAgo(a.created || a.createdAt)}</span>
                      {isUnread && (
                        <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--acc)',
                                       boxShadow: '0 0 5px var(--acc)', flexShrink: 0 }} title="Unread" />
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}

          {total > PAGE_SIZE && (
            <div style={{ display: 'flex', gap: 8, justifyContent: 'center', padding: '12px 0', borderTop: '1px solid var(--ln)' }}>
              <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => loadAlerts(page - 1)}>← Prev</button>
              <span className="mono dim" style={{ lineHeight: '28px' }}>Page {page} / {Math.ceil(total / PAGE_SIZE)}</span>
              <button className="btn btn-ghost btn-sm" disabled={page * PAGE_SIZE >= total} onClick={() => loadAlerts(page + 1)}>Next →</button>
            </div>
          )}
        </main>

        {/* ── Detail panel ── */}
        <aside className="sp-detail">
          {selected
            ? <SPAlertDetail
                alert={selected}
                onPromote={afterPromote}
                onIgnore={afterIgnore}
                onAssign={id => loadAlerts(page)}
                currentUser={currentUser}
              />
            : <div className="empty mono" style={{ padding: 40 }}>Select an alert to view details</div>
          }
        </aside>
      </div>
    </div>
  );
}

Object.assign(window, { PageSPAlerts });
