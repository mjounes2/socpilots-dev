// Threat Hunt + IOC Enrichment pages
const { useState: useStateX, useMemo: useMemoX, useEffect: useEffectX } = React;

// ============= THREAT HUNT =============
const HUNT_PRESETS = [
  { id: 'lateral',  label: 'Lateral movement',       query: 'rule.mitre.tactic:"Lateral Movement" AND data.win.eventdata.targetUserName:* | last 24h' },
  { id: 'beacon',   label: 'C2 beacon patterns',     query: 'dst.port:(443 OR 8080) AND network.bytes_out > 1000 | groupby src.ip, dst.ip | interval 60s' },
  { id: 'pshell',   label: 'Suspicious PowerShell',  query: 'process.name:powershell.exe AND process.args:*-enc* OR process.args:*FromBase64* | last 6h' },
  { id: 'kerb',     label: 'Kerberoasting',          query: 'event.code:4769 AND ticket.encryption:0x17 | groupby user.name' },
  { id: 'creds',    label: 'Credential dumping',     query: 'process.parent.name:(lsass.exe) OR rule.id:(60103 OR 60106) | last 24h' },
  { id: 'persist',  label: 'New persistence',        query: 'registry.path:*\\Run\\* OR scheduled_task.created:* | last 7d' },
];

const HUNT_RESULTS = [
  { time: '2026-05-13 14:22:11', agent: 'web-prod-01', user: 'svc_backup', src: '10.0.4.122', dst: '10.0.4.45',  rule: '92653', mitre: 'T1059.001', score: 92 },
  { time: '2026-05-13 14:21:47', agent: 'win-dc-01',   user: 'admin',      src: '10.0.4.45',  dst: '10.0.4.7',   rule: '60106', mitre: 'T1070.001', score: 87 },
  { time: '2026-05-13 14:20:33', agent: 'jump-host',   user: 'svc_backup', src: '10.0.4.122', dst: '10.0.4.7',   rule: '11302', mitre: 'T1021.001', score: 76 },
  { time: '2026-05-13 14:18:09', agent: 'db-primary',  user: 'svc_backup', src: '10.0.4.122', dst: '10.0.4.18',  rule: '11302', mitre: 'T1021.001', score: 71 },
  { time: '2026-05-13 14:11:54', agent: 'web-prod-01', user: 'svc_backup', src: '10.0.4.122', dst: '10.0.4.45',  rule: '92653', mitre: 'T1059.001', score: 68 },
  { time: '2026-05-13 13:58:22', agent: 'jump-host',   user: 'jdoe',       src: '10.0.4.99',  dst: '10.0.4.122', rule: '5503',  mitre: 'T1078',     score: 42 },
];

function PageHunt() {
  const [preset, setPreset] = useStateX('lateral');
  const [query, setQuery]   = useStateX(HUNT_PRESETS[0].query);
  const [running, setRunning] = useStateX(false);
  const [done, setDone]     = useStateX(true);

  function selectPreset(id) {
    setPreset(id);
    const p = HUNT_PRESETS.find(h => h.id === id);
    if (p) setQuery(p.query);
  }
  function run() {
    setRunning(true); setDone(false);
    setTimeout(() => { setRunning(false); setDone(true); }, 1200);
  }

  return (
    <div className="page" data-screen-label="06 Threat Hunt">
      <Topbar
        title="Threat Hunt"
        sub="Direct SIEM search · AI co-analyst"
        actions={<>
          <button className="btn btn-ghost"><Icon.file width="13" height="13"/> Saved hunts</button>
          <button className="btn btn-ghost">Schedule</button>
          <button className="btn btn-primary"><Icon.brain width="13" height="13"/> Ask AI</button>
        </>}
      />
      <div className="page-body">
        {/* Hunt presets */}
        <Card title="Hunt presets" sub="MITRE-aligned starting points">
          <div className="hunt-presets">
            {HUNT_PRESETS.map(p => (
              <button key={p.id} className={`hunt-preset ${preset===p.id?'on':''}`} onClick={()=>selectPreset(p.id)}>
                <div className="hp-label">{p.label}</div>
                <div className="hp-q mono">{p.query.slice(0, 60)}…</div>
              </button>
            ))}
          </div>
        </Card>

        {/* Query builder */}
        <Card title="Query" sub="OpenSearch DSL · time-bounded · grouped" icon={<Icon.search width="14" height="14"/>}
          actions={<><Chip mono>last 24h</Chip><Chip mono>limit 500</Chip><button className="btn btn-primary" onClick={run}>{running ? 'Running…' : 'Run hunt'}</button></>}>
          <div className="query-box">
            <div className="query-gutter mono">
              {query.split(/(?<!^)/).reduce((a, _, i) => a.concat(i+1), []).slice(0, query.split('\n').length || 1).map((n,i) => <div key={i}>{n}</div>)}
              <div>1</div>
            </div>
            <textarea className="query-input mono" value={query} onChange={e=>setQuery(e.target.value)} spellCheck="false" rows="3"/>
          </div>
          <div className="query-foot">
            <span className="mono dim">⌘+Enter to run · ⌘+S to save · /docs for syntax</span>
          </div>
        </Card>

        {/* AI analysis */}
        {done && (
          <Card title="AI co-analyst verdict" icon={<Icon.brain width="14" height="14"/>}
            actions={<Chip mono tone="ok"><span className="pip pip-ok"/> analysis ready</Chip>}>
            <div className="ai-verdict">
              <span className="av-pill av-warn">credible threat · 84%</span>
              <p>The query surfaced <strong>6 events across 4 hosts</strong> in a 24-minute window, all initiated by the same service account <span className="mono">svc_backup</span>. The pattern is consistent with <strong>RDP/WinRM lateral movement</strong> (T1021.001) preceded by a base64-encoded PowerShell payload (T1059.001) on <span className="mono">web-prod-01</span>. The path <span className="mono">web-prod-01 → win-dc-01 → jump-host → db-primary</span> matches the classic compromise → privilege escalation → DC → data store progression.</p>
              <div className="verdict-actions">
                <button className="btn btn-primary btn-sm"><Icon.folder width="11" height="11"/> Promote to case</button>
                <button className="btn btn-ghost btn-sm">Pivot on svc_backup</button>
                <button className="btn btn-ghost btn-sm">Explain query</button>
              </div>
            </div>
          </Card>
        )}

        {/* Results */}
        <Card title="Results" sub={running ? 'streaming…' : `${HUNT_RESULTS.length} events · grouped by user`}
          actions={<><Chip mono>columns</Chip><Chip mono>export</Chip></>}>
          {running ? (
            <div className="hunt-running">
              <div className="hunt-progress"><div /></div>
              <div className="mono dim">querying SIEM · web-prod-01 · win-dc-01 · jump-host · db-primary…</div>
            </div>
          ) : (
            <table className="data-table hunt-results">
              <thead><tr>
                <th>TIME</th>
                <th>AGENT</th>
                <th>USER</th>
                <th>SRC → DST</th>
                <th>RULE</th>
                <th>MITRE</th>
                <th style={{width:140}}>SCORE</th>
              </tr></thead>
              <tbody>
                {HUNT_RESULTS.map((r,i) => (
                  <tr key={i}>
                    <td className="mono dim">{r.time.slice(11)}</td>
                    <td className="mono">{r.agent}</td>
                    <td className="mono">{r.user}</td>
                    <td className="mono"><span>{r.src}</span> <span className="dim">→</span> <span>{r.dst}</span></td>
                    <td className="mono dim">{r.rule}</td>
                    <td className="mono"><a href="#" className="link">{r.mitre}</a></td>
                    <td>
                      <div className="score-bar">
                        <div className="sb-fill" data-sev={r.score >= 80 ? 'critical' : r.score >= 60 ? 'high' : r.score >= 40 ? 'medium' : 'low'} style={{ width: `${r.score}%` }}/>
                        <span className="sb-num mono">{r.score}</span>
                      </div>
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

// ============= IOC ENRICHMENT =============
const IOC_TYPES = [
  { id: 'ip',     label: 'IP',     sample: '185.220.101.42' },
  { id: 'domain', label: 'Domain', sample: 'malicious-c2.xyz' },
  { id: 'url',    label: 'URL',    sample: 'http://185.220.101.42/payload.bin' },
  { id: 'hash',   label: 'Hash',   sample: 'a4f8b2c91d3e0775fa2b8c91d3e0775' },
];

const IOC_RESULT = {
  ioc: '185.220.101.42',
  type: 'ip',
  verdict: 'malicious',
  confidence: 94,
  firstSeen: '2024-08-12',
  lastSeen: '8s ago',
  geo: { country: 'Russia', city: 'Moscow', lat: 55.7, lng: 37.6, isp: 'PrivateLayer Inc', asn: 'AS51852' },
  intel: [
    { source: 'VirusTotal',  verdict: 'malicious', detail: '18 / 94 engines',    tone: 'crit' },
    { source: 'AbuseIPDB',   verdict: 'abusive',   detail: '100% confidence',    tone: 'crit' },
    { source: 'AlienVault',  verdict: 'malicious', detail: 'Tor exit node',      tone: 'warn' },
    { source: 'GreyNoise',   verdict: 'crawler',   detail: 'mass-scanner',       tone: 'warn' },
    { source: 'Shodan',      verdict: 'exposed',   detail: '4 open ports',       tone: 'warn' },
    { source: 'IPQualityScore', verdict: 'fraud',  detail: 'fraud score 96',     tone: 'crit' },
  ],
  ports: [22, 80, 443, 9001],
  tags: ['tor-exit', 'c2', 'cobalt-strike', 'scanner'],
  related: [
    { type: 'alert',  id: 'WZ-9281047', label: 'PowerShell C2 on web-prod-01', sev: 'critical' },
    { type: 'alert',  id: 'WZ-9281024', label: 'Process injection detected',   sev: 'critical' },
    { type: 'case',   id: 'CASE-4471',  label: 'Active intrusion · web-prod-01', sev: 'critical' },
    { type: 'case',   id: 'CASE-4438',  label: 'Contained: ransomware staging', sev: 'critical' },
    { type: 'hash',   id: 'a4f8b2c…',   label: 'Cobalt Strike loader',          sev: 'critical' },
  ],
  history: [3, 5, 12, 8, 19, 24, 18, 31, 28, 22, 35, 42, 38, 47],
};

function PageIOC() {
  const [type, setType] = useStateX('ip');
  const [input, setInput] = useStateX('185.220.101.42');
  const [enriched, setEnriched] = useStateX(true);

  return (
    <div className="page" data-screen-label="07 IOC Enrichment">
      <Topbar
        title="IOC Enrichment"
        sub="IP · Domain · URL · Hash"
        actions={<>
          <Chip mono>VT · AbuseIPDB · AlienVault · Shodan · GreyNoise</Chip>
          <button className="btn btn-ghost">History</button>
        </>}
      />
      <div className="page-body">
        {/* Input */}
        <Card title="Indicator" sub="paste an IOC to enrich across 6 threat-intel sources">
          <div className="ioc-input-row">
            <div className="seg">
              {IOC_TYPES.map(t => (
                <button key={t.id} className={`seg-btn ${type===t.id?'on':''}`} onClick={()=>{setType(t.id); setInput(t.sample);}}>{t.label}</button>
              ))}
            </div>
            <div className="ioc-field">
              <input value={input} onChange={e=>setInput(e.target.value)} className="mono" placeholder="185.220.101.42  ·  malicious-c2.xyz  ·  a4f8b2c…"/>
            </div>
            <button className="btn btn-primary" onClick={()=>setEnriched(true)}><Icon.search width="13" height="13"/> Enrich</button>
          </div>
        </Card>

        {enriched && (
          <>
            {/* Verdict + geo summary */}
            <div className="grid-12">
              <Card span={5} title="Verdict" sub={`${IOC_RESULT.intel.length} sources queried`}>
                <div className="verdict-block">
                  <div className="verdict-pill mono">malicious</div>
                  <div className="verdict-ioc mono">{IOC_RESULT.ioc}</div>
                  <div className="verdict-conf">
                    <div className="conf-track"><div className="conf-fill" data-sev="critical" style={{width: `${IOC_RESULT.confidence}%`}}/></div>
                    <span className="mono">{IOC_RESULT.confidence}% confidence</span>
                  </div>
                  <ul className="verdict-meta">
                    <li><span>first seen</span><span className="mono">{IOC_RESULT.firstSeen}</span></li>
                    <li><span>last seen</span><span className="mono">{IOC_RESULT.lastSeen}</span></li>
                    <li><span>ASN</span><span className="mono">{IOC_RESULT.geo.asn}</span></li>
                    <li><span>ISP</span><span className="mono">{IOC_RESULT.geo.isp}</span></li>
                  </ul>
                  <div className="ioc-tags">
                    {IOC_RESULT.tags.map(t => <Chip key={t} mono tone="warn">{t}</Chip>)}
                  </div>
                </div>
              </Card>

              <Card span={7} title="Geolocation" sub={`${IOC_RESULT.geo.city}, ${IOC_RESULT.geo.country}`}>
                <MiniMap lat={IOC_RESULT.geo.lat} lng={IOC_RESULT.geo.lng} city={IOC_RESULT.geo.city} country={IOC_RESULT.geo.country} />
              </Card>
            </div>

            {/* Threat intel sources */}
            <Card title="Threat intel" sub="cross-source enrichment">
              <div className="intel-grid">
                {IOC_RESULT.intel.map((s,i) => (
                  <div key={i} className="intel-card" data-tone={s.tone}>
                    <div className="ic-source">{s.source}</div>
                    <div className="ic-verdict">{s.verdict}</div>
                    <div className="ic-detail mono">{s.detail}</div>
                  </div>
                ))}
              </div>
            </Card>

            {/* Activity sparkline */}
            <div className="grid-12">
              <Card span={6} title="Activity (14d)" sub="alerts associated with this IOC">
                <Sparkline data={IOC_RESULT.history} height={80} color="var(--crit)" />
                <div className="spark-foot mono dim">peak: 47 alerts/day · {IOC_RESULT.history.reduce((a,b)=>a+b,0)} total in 14 days</div>
              </Card>

              <Card span={6} title="Open ports" sub="Shodan · 8s ago">
                <div className="ports-grid">
                  {IOC_RESULT.ports.map(p => (
                    <div key={p} className="port-cell">
                      <div className="port-num mono">{p}</div>
                      <div className="port-svc mono">{ {22:'ssh', 80:'http', 443:'https', 9001:'tor'}[p] || '?' }</div>
                    </div>
                  ))}
                </div>
              </Card>
            </div>

            {/* Related entities */}
            <Card title="Related entities" sub="across SIEM + SP-CM">
              <ul className="related-list">
                {IOC_RESULT.related.map(r => (
                  <li key={r.id} className="related-item">
                    <SevDot sev={r.sev}/>
                    <span className="rel-type mono">{r.type}</span>
                    <span className="rel-id mono">{r.id}</span>
                    <span className="rel-label">{r.label}</span>
                    <button className="btn btn-ghost btn-sm">Open</button>
                  </li>
                ))}
              </ul>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}

function MiniMap({ lat, lng, city, country }) {
  const W = 600, H = 240;
  const proj = (la, ln) => [ ((ln + 180) / 360) * W, ((90 - la) / 180) * H ];
  const [x, y] = proj(lat, lng);
  return (
    <div className="minimap-wrap">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height="auto" className="map">
        {/* Continent dots via simple grid mask */}
        {(() => {
          const dots = [];
          for (let ln=-180; ln<=180; ln+=6) {
            for (let la=-60; la<=75; la+=6) {
              if (isLand(ln, la)) {
                const [px, py] = proj(la, ln);
                dots.push(<circle key={`${ln},${la}`} cx={px} cy={py} r="1.2" fill="var(--map-land)"/>);
              }
            }
          }
          return dots;
        })()}
        {/* Target */}
        <g>
          <circle cx={x} cy={y} r="10" fill="none" stroke="var(--crit)" strokeWidth="1">
            <animate attributeName="r" values="10;22;10" dur="2s" repeatCount="indefinite"/>
            <animate attributeName="opacity" values="1;0;1" dur="2s" repeatCount="indefinite"/>
          </circle>
          <circle cx={x} cy={y} r="4" fill="var(--crit)"/>
          <line x1={x} y1={y} x2={x} y2={H} stroke="var(--crit)" strokeDasharray="2 4" opacity=".4"/>
          <text x={x+10} y={y-6} className="map-label" style={{fill: 'var(--crit)', fontWeight: 700}}>{city.toUpperCase()} · {country.toUpperCase()}</text>
        </g>
      </svg>
    </div>
  );

  function isLand(ln, la) {
    if (ln >= -135 && ln <= -55 && la >= 25 && la <= 70 && !(ln > -75 && la > 50)) return true;
    if (ln >= -82 && ln <= -35 && la >= -55 && la <= 12) return true;
    if (ln >= -10 && ln <= 40 && la >= 36 && la <= 70) return true;
    if (ln >= -18 && ln <= 52 && la >= -35 && la <= 36) return true;
    if (ln >= 40 && ln <= 145 && la >= 8 && la <= 75 && !(ln > 130 && la < 25)) return true;
    if (ln >= 95 && ln <= 140 && la >= -10 && la <= 8) return true;
    if (ln >= 112 && ln <= 155 && la >= -44 && la <= -12) return true;
    return false;
  }
}

Object.assign(window, { PageHunt, PageIOC });
