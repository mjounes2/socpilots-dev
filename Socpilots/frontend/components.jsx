// Shared UI components for SOC Pilots prototype
const { useState, useEffect, useRef, useMemo } = React;

// ============= ICONS (lucide-style, hand-tuned) =============
const Icon = {
  shield:  (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  grid:    (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>,
  bell:    (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M6 8a6 6 0 1112 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21a2 2 0 004 0"/></svg>,
  cpu:     (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="5" y="5" width="14" height="14" rx="1"/><rect x="9" y="9" width="6" height="6"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></svg>,
  search:  (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>,
  bug:     (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><rect x="7" y="9" width="10" height="11" rx="5"/><path d="M9 9V6a3 3 0 016 0v3M5 13h2M17 13h2M5 17l2-1M17 17l-2-1M5 9l2 1M17 9l-2 1M12 20v-7"/></svg>,
  folder:  (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/></svg>,
  inbox:   (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5 6l-3 6v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3-6a2 2 0 00-2-1H7a2 2 0 00-2 1z"/></svg>,
  target:  (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>,
  globe:   (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15 15 0 010 20M12 2a15 15 0 000 20"/></svg>,
  brain:   (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M9 4a3 3 0 00-3 3v0a2.5 2.5 0 00-2 4 2.5 2.5 0 002 4v0a3 3 0 003 3h6a3 3 0 003-3v0a2.5 2.5 0 002-4 2.5 2.5 0 00-2-4v0a3 3 0 00-3-3H9zM12 4v16"/></svg>,
  share:   (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4"/></svg>,
  file:    (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h6M9 9h2"/></svg>,
  cog:     (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 01-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 01-4 0v-.1a1.7 1.7 0 00-1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 01-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 010-4h.1a1.7 1.7 0 001.5-1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 012.8-2.8l.1.1a1.7 1.7 0 001.8.3h0a1.7 1.7 0 001-1.5V3a2 2 0 014 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 012.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8v0a1.7 1.7 0 001.5 1H21a2 2 0 010 4h-.1a1.7 1.7 0 00-1.5 1z"/></svg>,
  alert:   (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M10.3 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v4M12 17h0"/></svg>,
  arrowUp: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M7 17L17 7M17 7H8M17 7v9"/></svg>,
  arrowDn: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M17 7L7 17M7 17h9M7 17V8"/></svg>,
  dot:     (p) => <svg {...p} viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="4"/></svg>,
  chevron: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M9 6l6 6-6 6"/></svg>,
  send:    (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg>,
  spark:   (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M12 3v3M12 18v3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M3 12h3M18 12h3M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1"/></svg>,
  user:    (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0116 0"/></svg>,
  check:   (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12l5 5L20 7"/></svg>,
  x:       (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 6l12 12M18 6L6 18"/></svg>,
  plus:    (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 5v14M5 12h14"/></svg>,
  filter:  (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M22 3H2l8 9.5V19l4 2v-8.5L22 3z"/></svg>,
  refresh: (p) => <svg {...p} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M3 12a9 9 0 0115-6.7L21 8M21 3v5h-5M21 12a9 9 0 01-15 6.7L3 16M3 21v-5h5"/></svg>,
};

// ============= CHIPS / BADGES =============
function SevDot({ sev, size = 8 }) {
  return <span className="sev-dot" data-sev={sev} style={{ width: size, height: size }} />;
}

function SevChip({ sev, count }) {
  return (
    <span className="sev-chip" data-sev={sev}>
      <SevDot sev={sev} />
      <span className="sev-chip-label">{sev}</span>
      {count != null && <span className="sev-chip-count">{count}</span>}
    </span>
  );
}

function Chip({ children, tone = 'default', mono = false, icon }) {
  return (
    <span className={`chip ${mono ? 'chip-mono' : ''}`} data-tone={tone}>
      {icon}
      {children}
    </span>
  );
}

function Kbd({ children }) { return <kbd className="kbd">{children}</kbd>; }

function Spinner({ size = 24 }) {
  return (
    <div style={{
      width: size, height: size,
      border: `2px solid var(--ln)`,
      borderTopColor: 'var(--acc)',
      borderRadius: '50%',
      animation: 'spin 0.7s linear infinite',
    }} />
  );
}

// ============= SIDEBAR =============
function Sidebar({ current, onNav }) {
  const items = [
    { group: 'OVERVIEW', items: [
      { id: 'dashboard',     label: 'Dashboard',          icon: Icon.grid, badge: null },
      { id: 'alerts',        label: 'Alerts',             icon: Icon.bell, badge: '7' },
      { id: 'investigation', label: 'Investigations',     icon: Icon.search, badge: null },
      { id: 'notifications', label: 'Notifications',      icon: Icon.inbox, badge: '3' },
    ]},
    { group: 'DETECT', items: [
      { id: 'mitre',        label: 'ATT&CK Coverage',    icon: Icon.grid, badge: null },
      { id: 'rules',        label: 'Detection Rules',     icon: Icon.file, badge: null },
      { id: 'hunt',         label: 'Threat Hunt',         icon: Icon.search, badge: null },
      { id: 'log-sources',  label: 'Log Sources',         icon: Icon.share, badge: null },
    ]},
    { group: 'INVESTIGATE', items: [
      { id: 'copilot',      label: 'SOCPilots AI',        icon: Icon.brain, badge: null },
      { id: 'langchain',    label: 'LangChain Health',    icon: Icon.cpu, badge: null },
      { id: 'correlation',  label: 'Correlation',         icon: Icon.share, badge: null },
      { id: 'ioc',          label: 'IOC Enrichment',      icon: Icon.target, badge: null },
    ]},
    { group: 'ANALYTICS', items: [
      { id: 'ueba',         label: 'UEBA',                icon: Icon.user, badge: 'NEW' },
      { id: 'artifacts',    label: 'IOC Store',           icon: Icon.target, badge: null },
      { id: 'evidence',     label: 'Evidence',            icon: Icon.file, badge: null },
      { id: 'map',          label: 'Live Threat Map',     icon: Icon.globe, badge: null },
    ]},
    { group: 'RESPOND', items: [
      { id: 'cases',        label: 'SP-CM Cases',         icon: Icon.folder, badge: '23' },
      { id: 'sp-alerts',    label: 'SP-CM Alerts',        icon: Icon.inbox, badge: null },
      { id: 'darksoc',      label: 'Dark SOC',            icon: Icon.shield, badge: 'BETA' },
      { id: 'sla',          label: 'SLA Management',      icon: Icon.cog, badge: null },
    ]},
    { group: 'SYSTEM', items: [
      { id: 'agents',       label: 'Agents',              icon: Icon.cpu, badge: null },
      { id: 'assets',       label: 'Assets',              icon: Icon.globe, badge: null },
      { id: 'vulns',        label: 'Vulnerabilities',     icon: Icon.bug, badge: '142' },
      { id: 'reports',      label: 'Reports',             icon: Icon.file, badge: null },
      { id: 'users',        label: 'Users',               icon: Icon.user, badge: null },
      { id: 'settings',     label: 'Settings',            icon: Icon.cog, badge: null },
    ]},
  ];

  return (
    <aside className="sidebar">
      <div className="sb-brand">
        <div className="sb-mark">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
            <path d="M12 2L20 7V17L12 22L4 17V7Z"/>
            <circle cx="12" cy="12" r="3" fill="currentColor" />
          </svg>
        </div>
        <div className="sb-brand-text">
          <div className="sb-brand-name">SOC<span>PILOTS</span></div>
          <div className="sb-brand-sub">v3.0 · operational</div>
        </div>
      </div>

      <nav className="sb-nav">
        {items.map((grp) => (
          <div key={grp.group} className="sb-group">
            <div className="sb-group-label">{grp.group}</div>
            {grp.items.map((it) => {
              const IconC = it.icon;
              const active = current === it.id;
              return (
                <button
                  key={it.id}
                  className={`sb-item ${active ? 'active' : ''}`}
                  onClick={() => onNav(it.id)}
                >
                  <IconC width="15" height="15" />
                  <span className="sb-item-label">{it.label}</span>
                  {it.badge && (
                    <span className={`sb-badge ${it.badge === 'NEW' ? 'new' : ''}`}>{it.badge}</span>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="sb-foot">
        <div className="sb-status">
          <SevDot sev="low" />
          <div className="sb-status-text">
            <div className="sb-status-label">SIEM · SP-CM · AI</div>
            <div className="sb-status-sub">all systems nominal · 41ms</div>
          </div>
        </div>
        <div className="sb-user">
          <div className="sb-avatar">YJ</div>
          <div className="sb-user-text">
            <div className="sb-user-name">younes</div>
            <div className="sb-user-role">analyst · L3</div>
          </div>
        </div>
      </div>
    </aside>
  );
}

// ============= TOPBAR =============
function Topbar({ title, sub, actions }) {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  const stamp = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  return (
    <header className="topbar">
      <div className="tb-title-block">
        <div className="tb-title">{title}</div>
        {sub && <div className="tb-sub">{sub}</div>}
      </div>
      <div className="tb-search">
        <Icon.search width="14" height="14" />
        <input placeholder="Search alerts, agents, IPs, hashes, rules…" />
        <Kbd>⌘K</Kbd>
      </div>
      <div className="tb-meta">
        <div className="tb-clock">
          <SevDot sev="low" />
          <span className="mono">{stamp}</span>
        </div>
        {actions}
      </div>
    </header>
  );
}

// ============= CARD =============
function Card({ title, sub, icon, actions, children, padded = true, className = '', span = 1 }) {
  return (
    <section className={`card ${className}`} style={{ gridColumn: `span ${span}` }}>
      {(title || actions) && (
        <header className="card-head">
          <div className="card-head-left">
            {icon && <span className="card-icon">{icon}</span>}
            <div>
              <div className="card-title">{title}</div>
              {sub && <div className="card-sub">{sub}</div>}
            </div>
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      <div className={padded ? 'card-body' : 'card-body-flush'}>
        {children}
      </div>
    </section>
  );
}

// ============= MINI SPARKLINE =============
function Sparkline({ data, color = 'var(--acc)', height = 28, fill = true }) {
  const w = 100, h = height;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => [ (i / (data.length - 1)) * w, h - (v / max) * (h - 2) - 1 ]);
  const d = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ');
  const dFill = d + ` L${w} ${h} L0 ${h} Z`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" width="100%" height={h}>
      {fill && <path d={dFill} fill={color} opacity=".12" />}
      <path d={d} fill="none" stroke={color} strokeWidth="1.4" />
    </svg>
  );
}

// Export to window for cross-file use
Object.assign(window, { Icon, SevDot, SevChip, Chip, Kbd, Sidebar, Topbar, Card, Sparkline });
