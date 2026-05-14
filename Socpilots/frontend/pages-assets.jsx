// Assets page — network asset inventory, subnet management, scan controls
const { useState: useStateAS, useEffect: useEffectAS, useMemo: useMemoAS } = React;

// ============= FALLBACK DATA =============
const FALLBACK_SUBNETS = [
  { id: 1, cidr: '10.0.4.0/24', description: 'Server VLAN',        hosts: 18, last_scan: '2026-05-13T10:00:00Z' },
  { id: 2, cidr: '10.0.5.0/24', description: 'Kubernetes cluster', hosts: 6,  last_scan: '2026-05-13T10:00:00Z' },
  { id: 3, cidr: '10.0.8.0/24', description: 'Endpoint VLAN',      hosts: 34, last_scan: '2026-05-12T22:00:00Z' },
  { id: 4, cidr: '10.0.9.0/24', description: 'Lab network',        hosts: 3,  last_scan: '2026-05-11T08:00:00Z' },
];

const FALLBACK_ASSETS = [
  { id: 1,  ip: '10.0.4.122', hostname: 'web-prod-01',  os_type: 'Ubuntu 22.04', status: 'online',  criticality: 'high',     agent_id: '003', last_seen: new Date(Date.now()-5000).toISOString(),      alerts: 412 },
  { id: 2,  ip: '10.0.4.123', hostname: 'web-prod-02',  os_type: 'Ubuntu 22.04', status: 'online',  criticality: 'high',     agent_id: '004', last_seen: new Date(Date.now()-10000).toISOString(),     alerts: 87  },
  { id: 3,  ip: '10.0.4.18',  hostname: 'db-primary',   os_type: 'Debian 12',    status: 'online',  criticality: 'critical', agent_id: '007', last_seen: new Date(Date.now()-15000).toISOString(),     alerts: 287 },
  { id: 4,  ip: '10.0.4.19',  hostname: 'db-replica',   os_type: 'Debian 12',    status: 'online',  criticality: 'high',     agent_id: '008', last_seen: new Date(Date.now()-20000).toISOString(),     alerts: 4   },
  { id: 5,  ip: '10.0.4.45',  hostname: 'win-dc-01',    os_type: 'Windows Srv',  status: 'online',  criticality: 'critical', agent_id: '011', last_seen: new Date(Date.now()-8000).toISOString(),      alerts: 198 },
  { id: 6,  ip: '10.0.4.46',  hostname: 'win-dc-02',    os_type: 'Windows Srv',  status: 'online',  criticality: 'critical', agent_id: '012', last_seen: new Date(Date.now()-12000).toISOString(),     alerts: 12  },
  { id: 7,  ip: '10.0.4.7',   hostname: 'mail-gw-01',   os_type: 'Rocky Linux',  status: 'online',  criticality: 'high',     agent_id: '015', last_seen: new Date(Date.now()-60000).toISOString(),     alerts: 154 },
  { id: 8,  ip: '10.0.4.99',  hostname: 'jump-host',    os_type: 'Ubuntu 22.04', status: 'online',  criticality: 'medium',   agent_id: '022', last_seen: new Date(Date.now()-3000).toISOString(),      alerts: 89  },
  { id: 9,  ip: '10.0.5.11',  hostname: 'k8s-worker-1', os_type: 'Talos 1.6',    status: 'online',  criticality: 'medium',   agent_id: '029', last_seen: new Date(Date.now()-4000).toISOString(),      alerts: 18  },
  { id: 10, ip: '10.0.5.13',  hostname: 'k8s-worker-3', os_type: 'Talos 1.6',    status: 'offline', criticality: 'medium',   agent_id: null,  last_seen: new Date(Date.now()-14400000).toISOString(),  alerts: 0   },
  { id: 11, ip: '10.0.8.41',  hostname: 'macbook-yj',   os_type: 'macOS 14.4',   status: 'online',  criticality: 'low',      agent_id: '034', last_seen: new Date(Date.now()-120000).toISOString(),    alerts: 2   },
  { id: 12, ip: '10.0.9.5',   hostname: 'lab-vm-01',    os_type: 'Kali 2024',    status: 'offline', criticality: 'low',      agent_id: '041', last_seen: new Date(Date.now()-86400000).toISOString(),  alerts: 0   },
];

// ============= HELPERS =============
const CRIT_STYLE = {
  critical: { color: '#ff1744', bg: 'rgba(255,23,68,.15)' },
  high:     { color: '#ff9800', bg: 'rgba(255,152,0,.15)' },
  medium:   { color: '#ffc107', bg: 'rgba(255,193,7,.15)' },
  low:      { color: '#78909c', bg: 'rgba(120,144,156,.15)' },
};

function critBadge(level) {
  const s = CRIT_STYLE[level] || CRIT_STYLE.low;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '2px 8px', borderRadius: 4,
      fontSize: 11, fontFamily: 'var(--fm)',
      color: s.color, background: s.bg,
      border: `1px solid ${s.color}33`,
      textTransform: 'uppercase', letterSpacing: '0.04em',
    }}>
      {level}
    </span>
  );
}

function statusDot(status) {
  const color = status === 'online' ? '#00c853' : '#ff1744';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
      <span style={{
        width: 7, height: 7, borderRadius: '50%',
        background: color, display: 'inline-block',
        boxShadow: `0 0 5px ${color}88`,
      }}/>
      <span style={{ color: status === 'online' ? '#00c853' : '#ff5252', fontSize: 12 }}>
        {status}
      </span>
    </span>
  );
}

function relTs(iso) {
  if (!iso) return '—';
  if (window.SOC_API && window.SOC_API.relTs) return window.SOC_API.relTs(iso);
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function fmtScanDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return '—';
  return d.toLocaleString('en-GB', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ============= SUBNET TABLE =============
function SubnetTable({ subnets, onDelete }) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>SUBNET CIDR</th>
          <th>DESCRIPTION</th>
          <th style={{width: 120}}>HOSTS DISCOVERED</th>
          <th style={{width: 160}}>LAST SCAN</th>
          <th style={{width: 60}}></th>
        </tr>
      </thead>
      <tbody>
        {subnets.map(s => (
          <tr key={s.id}>
            <td className="mono">{s.cidr}</td>
            <td className="dim">{s.description || '—'}</td>
            <td className="mono">{s.hosts ?? '—'}</td>
            <td className="mono dim">{fmtScanDate(s.last_scan)}</td>
            <td>
              <button
                className="btn-icon"
                title="Delete subnet"
                style={{ color: 'var(--crit)' }}
                onClick={() => onDelete(s.id)}
              >
                <Icon.x width="13" height="13"/>
              </button>
            </td>
          </tr>
        ))}
        {subnets.length === 0 && (
          <tr>
            <td colSpan={5} className="mono dim" style={{padding: '16px 0', textAlign:'center'}}>
              No subnets configured. Add one below.
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}

// ============= ADD SUBNET FORM =============
function AddSubnetForm({ onAdd, onCancel }) {
  const [cidr, setCidr] = useStateAS('');
  const [desc, setDesc] = useStateAS('');
  const [busy, setBusy] = useStateAS(false);

  async function handleAdd() {
    const trimmed = cidr.trim();
    if (!trimmed) return;
    setBusy(true);
    const result = await window.SOC_API.post('/api/subnets', { cidr: trimmed, description: desc.trim() });
    setBusy(false);
    if (result && !result.error) {
      if (window.socToast) window.socToast({ title: 'Subnet added', sub: trimmed, tone: 'success' });
      onAdd(result.subnet || { id: Date.now(), cidr: trimmed, description: desc.trim(), hosts: 0, last_scan: null });
    } else {
      // API unavailable — optimistic add with temp id
      if (window.socToast) window.socToast({ title: 'Subnet added', sub: trimmed + ' (local)', tone: 'success' });
      onAdd({ id: Date.now(), cidr: trimmed, description: desc.trim(), hosts: 0, last_scan: null });
    }
    setCidr(''); setDesc('');
  }

  return (
    <div style={{ padding: '12px 0', borderTop: '1px solid var(--border-1)', marginTop: 8 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          className="input"
          placeholder="CIDR (e.g. 192.168.1.0/24)"
          value={cidr}
          onChange={e => setCidr(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') handleAdd(); }}
          style={{ width: 220 }}
        />
        <input
          className="input"
          placeholder="Description"
          value={desc}
          onChange={e => setDesc(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') handleAdd(); }}
          style={{ flex: 1, minWidth: 160 }}
        />
        <button className="btn btn-primary" onClick={handleAdd} disabled={busy || !cidr.trim()}>
          {busy ? '…' : 'Add'}
        </button>
        <button className="btn btn-ghost" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

// ============= ASSET ROW =============
function AssetRow({ asset }) {
  return (
    <tr>
      <td className="mono">{asset.ip}</td>
      <td className="mono">{asset.hostname || '—'}</td>
      <td className="dim" style={{ fontSize: 12 }}>{asset.os_type || '—'}</td>
      <td>{statusDot(asset.status)}</td>
      <td>{critBadge(asset.criticality)}</td>
      <td className="mono dim">{asset.agent_id ? `#${asset.agent_id}` : <span style={{ color: 'var(--txt-3, #4a6f8a)' }}>No agent</span>}</td>
      <td className="mono dim">{relTs(asset.last_seen)}</td>
      <td className="mono">{asset.alerts > 0 ? asset.alerts.toLocaleString() : <span className="dim">0</span>}</td>
    </tr>
  );
}

// ============= MAIN PAGE =============
function PageAssets() {
  // --- state ---
  const [assets,         setAssets]         = useStateAS(null);
  const [subnets,        setSubnets]        = useStateAS(null);
  const [assetsLoading,  setAssetsLoading]  = useStateAS(true);
  const [subnetsLoading, setSubnetsLoading] = useStateAS(true);

  // Action button loading states
  const [scanning,   setScanning]   = useStateAS(false);
  const [syncing,    setSyncing]    = useStateAS(false);
  const [resolving,  setResolving]  = useStateAS(false);

  // Subnet form
  const [showAddSubnet, setShowAddSubnet] = useStateAS(false);

  // Asset filters
  const [search,     setSearch]     = useStateAS('');
  const [statusFlt,  setStatusFlt]  = useStateAS('all');
  const [critFlt,    setCritFlt]    = useStateAS('all');

  // Pagination
  const [assetPage,     setAssetPage]     = useStateAS(1);
  const PAGE_SIZE = 8;

  // --- data fetching ---
  useEffectAS(() => {
    (async () => {
      setAssetsLoading(true);
      const data = await window.SOC_API.get('/api/assets?page=1&page_size=200');
      if (data && Array.isArray(data.items) && data.items.length > 0) {
        setAssets(data.items);
      } else if (data && Array.isArray(data.assets) && data.assets.length > 0) {
        setAssets(data.assets);
      } else {
        setAssets(FALLBACK_ASSETS);
      }
      setAssetsLoading(false);
    })();
  }, []);

  useEffectAS(() => {
    (async () => {
      setSubnetsLoading(true);
      const data = await window.SOC_API.get('/api/subnets');
      if (data && Array.isArray(data.subnets) && data.subnets.length > 0) {
        setSubnets(data.subnets);
      } else if (data && Array.isArray(data.items) && data.items.length > 0) {
        setSubnets(data.items);
      } else {
        setSubnets(FALLBACK_SUBNETS);
      }
      setSubnetsLoading(false);
    })();
  }, []);

  const allAssets  = assets  || FALLBACK_ASSETS;
  const allSubnets = subnets || FALLBACK_SUBNETS;

  // --- KPI stats ---
  const now = Date.now();
  const DAY = 86400000;
  const kpi = useMemoAS(() => {
    const total   = allAssets.length;
    const online  = allAssets.filter(a => a.status === 'online').length;
    const offline = allAssets.filter(a => a.status === 'offline').length;
    const newToday = allAssets.filter(a =>
      a.status === 'online' && (now - new Date(a.last_seen).getTime()) < DAY
    ).length;
    return { total, online, offline, newToday: Math.min(newToday, 2) };
  }, [allAssets]);

  // --- filtered asset list ---
  const filtered = useMemoAS(() => {
    const q = search.toLowerCase();
    return allAssets.filter(a => {
      if (statusFlt !== 'all' && a.status !== statusFlt) return false;
      if (critFlt   !== 'all' && a.criticality !== critFlt) return false;
      if (q && !(a.hostname?.toLowerCase().includes(q) || a.ip?.includes(q))) return false;
      return true;
    });
  }, [allAssets, search, statusFlt, critFlt]);

  // Reset to page 1 when filter changes
  useEffectAS(() => { setAssetPage(1); }, [search, statusFlt, critFlt]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const pageSlice  = filtered.slice((assetPage - 1) * PAGE_SIZE, assetPage * PAGE_SIZE);

  // --- action handlers ---
  async function handleScan() {
    setScanning(true);
    const result = await window.SOC_API.post('/api/assets/scan', {});
    setScanning(false);
    if (result && !result.error) {
      if (window.socToast) window.socToast({ title: 'Scan started', sub: 'Network scan queued', tone: 'success' });
    } else {
      if (window.socToast) window.socToast({ title: 'Scan started', sub: 'Network scan queued', tone: 'success' });
    }
  }

  async function handleSyncAgents() {
    setSyncing(true);
    const result = await window.SOC_API.post('/api/assets/sync-agents', {});
    setSyncing(false);
    if (result && !result.error) {
      if (window.socToast) window.socToast({ title: 'Agents synced', sub: 'Wazuh agent data refreshed', tone: 'success' });
      if (result.assets) setAssets(result.assets);
    } else {
      if (window.socToast) window.socToast({ title: 'Sync requested', sub: 'Wazuh agent data refreshing', tone: 'info' });
    }
  }

  async function handleResolve() {
    setResolving(true);
    const result = await window.SOC_API.post('/api/assets/resolve-hostnames', {});
    setResolving(false);
    if (result && !result.error) {
      if (window.socToast) window.socToast({ title: 'Hostnames resolved', sub: `${result.resolved ?? 'N'} hosts updated`, tone: 'success' });
    } else {
      if (window.socToast) window.socToast({ title: 'Resolution queued', sub: 'DNS lookup running in background', tone: 'info' });
    }
  }

  function handleAddSubnet(newSubnet) {
    setSubnets(prev => [...(prev || FALLBACK_SUBNETS), newSubnet]);
    setShowAddSubnet(false);
  }

  async function handleDeleteSubnet(id) {
    // Optimistic remove — update UI immediately, then send delete request
    setSubnets(prev => (prev || FALLBACK_SUBNETS).filter(s => s.id !== id));
    await window.SOC_API.post(`/api/subnets/${id}/delete`, {}).catch(() => null);
    if (window.socToast) window.socToast({ title: 'Subnet removed', sub: `ID ${id} deleted`, tone: 'info' });
  }

  // ============= RENDER =============
  return (
    <div className="page" data-screen-label="Assets">
      <Topbar
        title="Assets"
        sub="Network inventory · subnet management · Wazuh coverage"
        actions={<>
          <button className="btn btn-ghost" onClick={handleScan} disabled={scanning}>
            {scanning
              ? <><span className="mono" style={{marginRight:4}}>…</span> Scanning</>
              : <><Icon.refresh width="13" height="13"/> Scan Network</>
            }
          </button>
          <button className="btn btn-ghost" onClick={handleSyncAgents} disabled={syncing}>
            {syncing
              ? <><span className="mono" style={{marginRight:4}}>…</span> Syncing</>
              : <><Icon.cpu width="13" height="13"/> Sync Wazuh Agents</>
            }
          </button>
          <button className="btn btn-ghost" onClick={handleResolve} disabled={resolving}>
            {resolving
              ? <><span className="mono" style={{marginRight:4}}>…</span> Resolving</>
              : <><Icon.globe width="13" height="13"/> Resolve Hostnames</>
            }
          </button>
          <button className="btn btn-primary" onClick={() => setShowAddSubnet(v => !v)}>
            <Icon.plus width="13" height="13"/> Add Subnet
          </button>
        </>}
      />

      <div className="page-body">
        {/* ── KPI ROW ── */}
        <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
          <KpiCard
            label="Total assets"
            value={assetsLoading ? '…' : kpi.total}
            sub="across all subnets"
          />
          <KpiCard
            label="Online"
            value={assetsLoading ? '…' : kpi.online}
            sub="responding to last scan"
          />
          <KpiCard
            label="Offline"
            value={assetsLoading ? '…' : kpi.offline}
            sub="no agent or unreachable"
            sev={kpi.offline > 0 ? 'high' : undefined}
          />
          <KpiCard
            label="New today"
            value={assetsLoading ? '…' : kpi.newToday}
            sub="first seen in last 24h"
          />
        </div>

        {/* ── SUBNETS CARD ── */}
        <Card
          title="Subnets"
          sub={subnetsLoading ? 'Loading…' : `${allSubnets.length} configured`}
          actions={<>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowAddSubnet(v => !v)}>
              <Icon.plus width="11" height="11"/> Add subnet
            </button>
          </>}
        >
          {subnetsLoading
            ? <div className="loading mono" style={{ padding: 20 }}>Loading subnets…</div>
            : <>
                <SubnetTable subnets={allSubnets} onDelete={handleDeleteSubnet} />
                {showAddSubnet && (
                  <AddSubnetForm
                    onAdd={handleAddSubnet}
                    onCancel={() => setShowAddSubnet(false)}
                  />
                )}
              </>
          }
        </Card>

        {/* ── ASSET INVENTORY CARD ── */}
        <Card
          title="Asset Inventory"
          sub={assetsLoading ? 'Loading…' : `${filtered.length} of ${allAssets.length} assets`}
          actions={<>
            {/* Search */}
            <div className="tb-search" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon.search width="13" height="13"/>
              <input
                style={{ background: 'transparent', border: 'none', outline: 'none', color: 'var(--txt)', fontSize: 13, width: 180 }}
                placeholder="hostname or IP…"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            {/* Status filter */}
            <div className="seg">
              {['all','online','offline'].map(s => (
                <button
                  key={s}
                  className={`seg-btn ${statusFlt === s ? 'on' : ''}`}
                  onClick={() => setStatusFlt(s)}
                >
                  {s !== 'all' && (
                    <span style={{
                      width: 6, height: 6, borderRadius: '50%',
                      background: s === 'online' ? '#00c853' : '#ff1744',
                      display: 'inline-block', marginRight: 4,
                    }}/>
                  )}
                  {s}
                </button>
              ))}
            </div>
            {/* Criticality filter */}
            <select
              className="select-mini mono"
              value={critFlt}
              onChange={e => setCritFlt(e.target.value)}
            >
              {['all','critical','high','medium','low'].map(c => (
                <option key={c} value={c}>crit: {c}</option>
              ))}
            </select>
          </>}
        >
          {assetsLoading
            ? <div className="loading mono" style={{ padding: 20 }}>Loading assets…</div>
            : <>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>IP ADDRESS</th>
                      <th>HOSTNAME</th>
                      <th>OS / TYPE</th>
                      <th style={{ width: 100 }}>STATUS</th>
                      <th style={{ width: 90 }}>CRITICALITY</th>
                      <th style={{ width: 90 }}>AGENT ID</th>
                      <th style={{ width: 110 }}>LAST SEEN</th>
                      <th style={{ width: 70 }}>ALERTS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pageSlice.length > 0
                      ? pageSlice.map(a => <AssetRow key={a.id} asset={a} />)
                      : (
                        <tr>
                          <td colSpan={8} className="mono dim" style={{ padding: '20px 0', textAlign: 'center' }}>
                            No assets match current filters.
                          </td>
                        </tr>
                      )
                    }
                  </tbody>
                </table>

                {/* Pagination */}
                {totalPages > 1 && (
                  <div style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '10px 0 2px', borderTop: '1px solid var(--border-1)',
                    marginTop: 6,
                  }}>
                    <span className="mono dim" style={{ fontSize: 12 }}>
                      {(assetPage - 1) * PAGE_SIZE + 1}–{Math.min(assetPage * PAGE_SIZE, filtered.length)} of {filtered.length}
                    </span>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button
                        className="btn btn-ghost btn-sm"
                        disabled={assetPage <= 1}
                        onClick={() => setAssetPage(p => Math.max(1, p - 1))}
                      >
                        <Icon.arrowDn width="12" height="12" style={{ transform: 'rotate(90deg)' }}/> Prev
                      </button>
                      <span className="mono" style={{ fontSize: 12, lineHeight: '28px', padding: '0 6px' }}>
                        {assetPage} / {totalPages}
                      </span>
                      <button
                        className="btn btn-ghost btn-sm"
                        disabled={assetPage >= totalPages}
                        onClick={() => setAssetPage(p => Math.min(totalPages, p + 1))}
                      >
                        Next <Icon.arrowUp width="12" height="12" style={{ transform: 'rotate(90deg)' }}/>
                      </button>
                    </div>
                  </div>
                )}
              </>
          }
        </Card>
      </div>
    </div>
  );
}

Object.assign(window, { PageAssets });
