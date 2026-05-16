// SP-CM Alerts — TheHive inbox-style triage queue (real API)
const { useState: useSPA, useMemo: useSPM, useEffect: useSPE, useRef: useSPR } = React;

const TLP_INFO = {
  red:    { color: 'oklch(0.68 0.20 22)',  bg: 'oklch(0.30 0.08 22 / 0.22)',  label: 'TLP:RED' },
  amber:  { color: 'oklch(0.78 0.16 50)',  bg: 'oklch(0.30 0.08 50 / 0.22)',  label: 'TLP:AMBER' },
  green:  { color: 'oklch(0.78 0.14 150)', bg: 'oklch(0.30 0.08 150 / 0.22)', label: 'TLP:GREEN' },
  white:  { color: 'oklch(0.85 0.005 250)',bg: 'oklch(0.30 0.005 250 / 0.22)',label: 'TLP:WHITE' },
};

// Map TheHive numeric severity to string
function sevStr(s) {
  if (typeof s === 'string') return s.toLowerCase();
  const m = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low' };
  return m[s] || 'low';
}

// Map TheHive status to display string
function statusStr(s) {
  if (!s) return 'new';
  const m = { New: 'new', InProgress: 'updated', Imported: 'imported', Resolved: 'imported' };
  return m[s] || s.toLowerCase();
}

function tlpFromTags(tags) {
  if (!tags) return 'green';
  const t = tags.find(x => /^tlp:/i.test(x));
  if (!t) return 'green';
  const v = t.split(':')[1]?.toLowerCase();
  return ['red', 'amber', 'green', 'white'].includes(v) ? v : 'green';
}

function relAgo(ts) {
  if (!ts) return '—';
  const s = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.round(h / 24)}d`;
}

function ObsIcons({ obs }) {
  if (!obs) return null;
  const items = [
    { k: 'ip',     icon: Icon.globe,  count: obs.ip     || 0 },
    { k: 'domain', icon: Icon.share,  count: obs.domain || 0 },
    { k: 'url',    icon: Icon.target, count: obs.url    || 0 },
    { k: 'hash',   icon: Icon.file,   count: obs.hash   || 0 },
    { k: 'host',   icon: Icon.cpu,    count: obs.host   || 0 },
  ].filter(it => it.count > 0);
  if (!items.length) return <span className="mono dim">—</span>;
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

function SPAlertDetail({ alert, onPromote, onIgnore }) {
  const sev    = sevStr(alert.severity);
  const tlpKey = tlpFromTags(alert.tags);
  const tlp    = TLP_INFO[tlpKey];

  async function promote() {
    const r = await window.SOC_API.post('/api/hive-alerts/promote', { alertId: alert.id });
    if (r && !r.error) {
      window.socToast?.({ title: 'Promoted to case', sub: r.caseId || 'Case created', tone: 'ok' });
      if (onPromote) onPromote(alert.id);
    } else {
      window.socToast?.({ title: 'Promote failed', sub: r?.error || 'Check TheHive connection', tone: 'error' });
    }
  }

  return (
    <div className="sp-detail-inner">
      <div className="sp-detail-head">
        <SevChip sev={sev}/>
        <span className="mono dim">{alert.sourceRef || alert.id}</span>
        <span className="sp-tlp mono" style={{ color: tlp.color, background: tlp.bg }}>{tlp.label}</span>
      </div>
      <h2 className="sp-detail-title">{alert.title}</h2>
      <div className="sp-detail-meta mono">
        <span>{alert.source || '—'}</span>
        <span className="dim">·</span>
        <span>{alert.createdAt ? new Date(alert.createdAt).toISOString().slice(0,19).replace('T',' ') + ' UTC' : '—'}</span>
      </div>

      {alert.description && <p className="sp-detail-desc">{alert.description}</p>}

      {(alert.tags || []).length > 0 && (
        <div className="sp-detail-tags">
          {alert.tags.map(t => <Chip key={t} mono>{t}</Chip>)}
        </div>
      )}

      <div className="sp-section">
        <div className="ds-title">Details</div>
        <table className="data-table" style={{ fontSize: 11 }}>
          <tbody>
            <tr><td className="dim">Status</td><td><Chip mono>{alert.status || '—'}</Chip></td></tr>
            <tr><td className="dim">Severity</td><td><SevChip sev={sev}/></td></tr>
            {alert.assignee && <tr><td className="dim">Assignee</td><td className="mono">{alert.assignee}</td></tr>}
            {alert.caseId   && <tr><td className="dim">Case</td><td className="mono">#{alert.caseId}</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="sp-detail-actions">
        <button className="btn btn-primary" onClick={promote}>
          <Icon.folder width="13" height="13"/> Promote to case
        </button>
        <button className="btn btn-ghost" onClick={onIgnore}>Ignore</button>
      </div>
    </div>
  );
}

function PageSPAlerts() {
  const [alerts, setAlerts]       = useSPA([]);
  const [stats, setStats]         = useSPA(null);
  const [loading, setLoading]     = useSPA(true);
  const [error, setError]         = useSPA(null);
  const [filter, setFilter]       = useSPA('all');
  const [sevFilter, setSevFilter] = useSPA('all');
  const [statusFilter, setStatusF]= useSPA('');
  const [q, setQ]                 = useSPA('');
  const [page, setPage]           = useSPA(1);
  const [total, setTotal]         = useSPA(0);
  const [selectedId, setSelId]    = useSPA(null);
  const [selectedSet, setSelSet]  = useSPA(new Set());
  const [timeframe, setTimeframe] = useSPA('24h');
  const searchTimer               = useSPR(null);
  const PAGE_SIZE = 20;

  useSPE(() => { loadAlerts(1); loadStats(); }, [sevFilter, statusFilter, timeframe]);

  async function loadStats() {
    const d = await window.SOC_API.get('/api/hive-alerts/stats');
    if (d && !d.error) setStats(d);
  }

  async function loadAlerts(p) {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ page: p, page_size: PAGE_SIZE });
    if (sevFilter !== 'all') params.set('severity', sevFilter === 'critical' ? 4 : sevFilter === 'high' ? 3 : sevFilter === 'medium' ? 2 : 1);
    if (statusFilter) params.set('status', statusFilter);
    if (q.trim())    params.set('q', q.trim());
    if (timeframe !== 'all') {
      const ms = { '1h': 3600000, '24h': 86400000, '7d': 604800000 }[timeframe];
      if (ms) params.set('time_from', new Date(Date.now() - ms).toISOString());
    }
    const d = await window.SOC_API.get('/api/hive-alerts?' + params.toString());
    if (!d || d.error) { setError(d?.error || 'SP-CM unavailable'); setLoading(false); return; }
    const list = (d.alerts || d.items || []).map(a => ({
      ...a,
      _sev: sevStr(a.severity),
      _status: statusStr(a.status),
      _tlp: tlpFromTags(a.tags),
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

  const counts = useSPM(() => {
    const base = stats || {};
    return {
      all:      base.total || alerts.length,
      unread:   base.new || alerts.filter(a => a._status === 'new').length,
      new:      alerts.filter(a => a._status === 'new').length,
      updated:  alerts.filter(a => a._status === 'updated').length,
      imported: alerts.filter(a => a._status === 'imported').length,
    };
  }, [alerts, stats]);

  const selected = alerts.find(a => (a.id || a._id) === selectedId);

  function toggleSelect(id, e) {
    e.stopPropagation();
    setSelSet(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }

  function afterPromote(id) {
    setAlerts(prev => prev.filter(a => (a.id || a._id) !== id));
    setSelId(null);
    loadStats();
  }

  return (
    <div className="page" data-screen-label="13 SP-CM Alerts">
      <Topbar
        title="SP-CM Alerts"
        sub="Pre-case triage inbox · TheHive"
        actions={<>
          {stats && <Chip mono>{(stats.new || 0)} new · {(stats.in_progress || 0)} in progress</Chip>}
          <select className="select-mini mono" value={timeframe} onChange={e => setTimeframe(e.target.value)}>
            {['1h','24h','7d','all'].map(t => <option key={t} value={t}>{t === 'all' ? 'All time' : `Last ${t}`}</option>)}
          </select>
          <button className="btn btn-ghost" onClick={() => { loadAlerts(1); loadStats(); }}>
            <Icon.refresh width="13" height="13"/> Refresh
          </button>
        </>}
      />
      <div className="page-body sp-alerts-body">
        {/* Left sidebar */}
        <aside className="sp-side">
          <Card title="Folders" sub="filter inbox">
            <ul className="sp-folders">
              {[
                { id: 'all',      label: 'All alerts',   icon: Icon.inbox,   status: '' },
                { id: 'new',      label: 'New',          icon: Icon.bell,    status: 'New' },
                { id: 'updated',  label: 'In Progress',  icon: Icon.refresh, status: 'InProgress' },
                { id: 'imported', label: 'Imported',     icon: Icon.share,   status: 'Imported' },
              ].map(f => {
                const Ic = f.icon;
                return (
                  <li key={f.id}>
                    <button
                      className={`sp-folder ${filter === f.id ? 'on' : ''}`}
                      onClick={() => { setFilter(f.id); setStatusF(f.status); setPage(1); loadAlerts(1); }}
                    >
                      <Ic width="13" height="13"/>
                      <span>{f.label}</span>
                      <span className="sp-folder-count mono">{counts[f.id] || 0}</span>
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
                  <button className={`sp-folder ${sevFilter === s ? 'on' : ''}`} onClick={() => { setSevFilter(s); setPage(1); }}>
                    {s === 'all' ? <Icon.grid width="13" height="13"/> : <SevDot sev={s}/>}
                    <span style={{ textTransform: 'capitalize' }}>{s}</span>
                    <span className="sp-folder-count mono">
                      {s === 'all' ? total : alerts.filter(a => a._sev === s).length}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </Card>

          {stats && (
            <Card title="Stats" sub="last period">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 11 }}>
                {[
                  ['Total',        stats.total],
                  ['True Positive',stats.true_positive],
                  ['False Positive',stats.false_positive],
                  ['Critical',     stats.critical],
                  ['High',         stats.high],
                ].map(([lbl, val]) => (
                  <div key={lbl} style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="dim">{lbl}</span>
                    <span className="mono">{(val || 0).toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </aside>

        {/* Inbox list */}
        <main className="sp-inbox">
          <div className="sp-inbox-tb">
            <label className="sp-checkbox">
              <input type="checkbox"
                checked={selectedSet.size === alerts.length && alerts.length > 0}
                onChange={() => {
                  if (selectedSet.size === alerts.length) setSelSet(new Set());
                  else setSelSet(new Set(alerts.map(a => a.id || a._id)));
                }}
              />
              <span className="cb-mark"/>
            </label>
            <input
              className="mono"
              placeholder="Search title…"
              value={q}
              onChange={e => handleSearch(e.target.value)}
              style={{ width: 200, fontSize: 11 }}
            />
            <span className="sp-inbox-tb-label mono">
              {selectedSet.size > 0 ? `${selectedSet.size} selected` : `${total.toLocaleString()} alerts`}
            </span>
            {selectedSet.size > 0 && (
              <div className="sp-inbox-actions">
                <button className="btn btn-ghost btn-sm">Ignore</button>
                <button className="btn btn-ghost btn-sm">Assign</button>
              </div>
            )}
            <div className="sp-inbox-tb-right">
              <Chip mono>page {page} / {Math.ceil(total / PAGE_SIZE) || 1}</Chip>
            </div>
          </div>

          {loading && <div className="empty mono" style={{ padding: 40 }}>Loading from SP-CM…</div>}
          {error && <div className="empty mono" style={{ color: 'var(--red)', padding: 40 }}>{error}</div>}

          {!loading && !error && (
            <ul className="sp-list">
              {alerts.length === 0 && <li className="empty mono" style={{ padding: 32 }}>No alerts match filters</li>}
              {alerts.map(a => {
                const id  = a.id || a._id;
                const tlp = TLP_INFO[a._tlp] || TLP_INFO.green;
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
                      <div className="sp-item-row1">
                        <span className="sp-item-id mono">{a.sourceRef || id}</span>
                        <span className="sp-item-title">{a.title}</span>
                      </div>
                      <div className="sp-item-row2">
                        <span className="mono dim">{a.source || '—'}</span>
                        <span className="sp-tlp mono" style={{ color: tlp.color, background: tlp.bg }}>{tlp.label}</span>
                        <span className="sp-status mono" data-status={a._status}>{a._status}</span>
                      </div>
                      {(a.tags || []).length > 0 && (
                        <div className="sp-item-row3">
                          {a.tags.slice(0, 4).map(t => <Chip key={t} mono>{t}</Chip>)}
                        </div>
                      )}
                    </div>
                    <div className="sp-item-right">
                      {a.assignee
                        ? <span className="sp-avatar">{String(a.assignee)[0].toUpperCase()}</span>
                        : <span className="sp-unassigned mono">—</span>
                      }
                      <span className="sp-time mono">{relAgo(a.createdAt || a.created)}</span>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}

          {total > PAGE_SIZE && (
            <div style={{ display: 'flex', gap: 8, justifyContent: 'center', padding: '12px 0' }}>
              <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => loadAlerts(page - 1)}>← Prev</button>
              <span className="mono dim" style={{ lineHeight: '28px' }}>Page {page} / {Math.ceil(total / PAGE_SIZE)}</span>
              <button className="btn btn-ghost btn-sm" disabled={page * PAGE_SIZE >= total} onClick={() => loadAlerts(page + 1)}>Next →</button>
            </div>
          )}
        </main>

        {/* Detail panel */}
        <aside className="sp-detail">
          {selected
            ? <SPAlertDetail alert={selected} onPromote={afterPromote} onIgnore={() => { setSelId(null); loadAlerts(page); }} />
            : <div className="empty mono" style={{ padding: 40 }}>Select an alert to view details</div>
          }
        </aside>
      </div>
    </div>
  );
}

Object.assign(window, { PageSPAlerts });
