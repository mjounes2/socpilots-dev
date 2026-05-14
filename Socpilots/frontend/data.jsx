// Mock data for SOC Pilots prototype
const NOW = Date.now();
const ago = (m) => new Date(NOW - m * 60000);

const KPIS = {
  alerts24h: 1847,
  alertsTrend: +12.4,
  activeAgents: 142,
  agentsTotal: 156,
  openCases: 23,
  casesTrend: -8,
  criticalAlerts: 7,
  mttd: '4m 12s',
  mttr: '38m 04s',
};

const SEVERITY_DIST = [
  { level: 'critical', count: 47, color: 'crit' },
  { level: 'high', count: 184, color: 'high' },
  { level: 'medium', count: 612, color: 'med' },
  { level: 'low', count: 1004, color: 'low' },
];

// 24h timeline — hourly buckets
const TIMELINE_24H = Array.from({ length: 24 }, (_, i) => {
  const seed = (i * 7) % 13;
  return {
    hour: i,
    critical: Math.max(0, Math.round(2 + Math.sin(i / 3) * 2 + seed % 3)),
    high: Math.round(6 + Math.cos(i / 2) * 4 + seed),
    medium: Math.round(18 + Math.sin(i / 4) * 8 + seed * 2),
    low: Math.round(35 + Math.cos(i / 5) * 12 + seed * 3),
  };
});

const TOP_RULES = [
  { id: '5710', name: 'Multiple authentication failures', mitre: 'T1110', count: 284, sev: 'high' },
  { id: '92653', name: 'Suspicious PowerShell execution', mitre: 'T1059.001', count: 156, sev: 'critical' },
  { id: '31151', name: 'Web exploit attempt — SQL injection', mitre: 'T1190', count: 142, sev: 'high' },
  { id: '5503', name: 'PAM: User login session opened', mitre: 'T1078', count: 98, sev: 'low' },
  { id: '40111', name: 'Process injection detected', mitre: 'T1055', count: 76, sev: 'critical' },
  { id: '60106', name: 'Windows audit log cleared', mitre: 'T1070.001', count: 41, sev: 'high' },
];

const TOP_AGENTS = [
  { id: '003', name: 'web-prod-01', os: 'Ubuntu 22.04', alerts: 412, last: '2s ago', status: 'active' },
  { id: '007', name: 'db-primary', os: 'Debian 12', alerts: 287, last: '12s ago', status: 'active' },
  { id: '011', name: 'win-dc-01', os: 'Win Srv 2022', alerts: 198, last: '4s ago', status: 'active' },
  { id: '015', name: 'mail-gw-01', os: 'Rocky 9', alerts: 154, last: '1m ago', status: 'active' },
  { id: '022', name: 'jump-host', os: 'Ubuntu 22.04', alerts: 89, last: '3s ago', status: 'active' },
  { id: '028', name: 'k8s-worker-3', os: 'Talos 1.6', alerts: 0, last: '4h ago', status: 'offline' },
];

const RECENT_ALERTS = [
  { id: 'WZ-9281047', time: ago(0.5), agent: 'web-prod-01', srcIp: '185.220.101.42', rule: 'Suspicious PowerShell execution', mitre: 'T1059.001', sev: 'critical', geo: 'RU' },
  { id: 'WZ-9281044', time: ago(2),   agent: 'db-primary',  srcIp: '45.155.205.18',  rule: 'Multiple authentication failures', mitre: 'T1110', sev: 'high', geo: 'NL' },
  { id: 'WZ-9281041', time: ago(4),   agent: 'win-dc-01',   srcIp: '10.0.4.122',      rule: 'Windows audit log cleared', mitre: 'T1070.001', sev: 'high', geo: 'LAN' },
  { id: 'WZ-9281039', time: ago(6),   agent: 'mail-gw-01',  srcIp: '194.147.78.219', rule: 'Web exploit attempt — SQL injection', mitre: 'T1190', sev: 'high', geo: 'CN' },
  { id: 'WZ-9281036', time: ago(9),   agent: 'web-prod-01', srcIp: '141.98.10.55',   rule: 'Brute force SSH', mitre: 'T1110.001', sev: 'medium', geo: 'LT' },
  { id: 'WZ-9281031', time: ago(13),  agent: 'jump-host',   srcIp: '10.0.4.122',      rule: 'Privilege escalation attempt', mitre: 'T1068', sev: 'critical', geo: 'LAN' },
  { id: 'WZ-9281028', time: ago(17),  agent: 'db-primary',  srcIp: '91.219.236.222', rule: 'Outbound to known C2', mitre: 'T1071', sev: 'critical', geo: 'IR' },
  { id: 'WZ-9281024', time: ago(22),  agent: 'web-prod-01', srcIp: '185.220.101.42', rule: 'Process injection detected', mitre: 'T1055', sev: 'critical', geo: 'RU' },
  { id: 'WZ-9281020', time: ago(28),  agent: 'k8s-worker-1',srcIp: '167.99.74.103',  rule: 'Container escape attempt', mitre: 'T1611', sev: 'high', geo: 'US' },
  { id: 'WZ-9281015', time: ago(34),  agent: 'mail-gw-01',  srcIp: '198.51.100.7',   rule: 'Phishing URL clicked', mitre: 'T1566.002', sev: 'medium', geo: 'US' },
  { id: 'WZ-9281011', time: ago(41),  agent: 'win-dc-01',   srcIp: '10.0.4.45',       rule: 'Kerberoasting attempt', mitre: 'T1558.003', sev: 'high', geo: 'LAN' },
  { id: 'WZ-9281007', time: ago(48),  agent: 'web-prod-01', srcIp: '193.32.162.157', rule: 'Tor exit node connection', mitre: 'T1090.003', sev: 'medium', geo: 'DE' },
];

// World map dots — origins of recent attacks (rough lat/lng → svg coords for 720x360 equirect)
const ATTACK_ORIGINS = [
  { lat: 55.7,  lng: 37.6,  count: 47, country: 'RU', city: 'Moscow' },
  { lat: 39.9,  lng: 116.4, count: 38, country: 'CN', city: 'Beijing' },
  { lat: 35.7,  lng: 51.4,  count: 22, country: 'IR', city: 'Tehran' },
  { lat: 52.4,  lng: 4.9,   count: 18, country: 'NL', city: 'Amsterdam' },
  { lat: 40.4,  lng: -3.7,  count: 14, country: 'ES', city: 'Madrid' },
  { lat: 37.5,  lng: 127.0, count: 11, country: 'KR', city: 'Seoul' },
  { lat: 25.0,  lng: 121.5, count: 9,  country: 'TW', city: 'Taipei' },
  { lat: 19.4,  lng: -99.1, count: 7,  country: 'MX', city: 'Mexico City' },
  { lat: -23.5, lng: -46.6, count: 5,  country: 'BR', city: 'São Paulo' },
  { lat: 28.6,  lng: 77.2,  count: 4,  country: 'IN', city: 'Delhi' },
  { lat: 41.0,  lng: 28.9,  count: 4,  country: 'TR', city: 'Istanbul' },
  { lat: 54.7,  lng: 25.3,  count: 3,  country: 'LT', city: 'Vilnius' },
];
// Target (HQ)
const TARGET = { lat: 33.5, lng: 36.3, city: 'HQ' };

const CASES = {
  new: [
    { id: 'CASE-4471', title: 'Suspicious PowerShell on web-prod-01', sev: 'critical', age: '8m', alerts: 12, assignee: null, tags: ['T1059.001', 'execution'] },
    { id: 'CASE-4470', title: 'Brute force surge — SSH', sev: 'high', age: '24m', alerts: 47, assignee: null, tags: ['T1110', 'credential-access'] },
    { id: 'CASE-4468', title: 'Outbound to known C2 — db-primary', sev: 'critical', age: '41m', alerts: 3, assignee: null, tags: ['T1071', 'c2'] },
  ],
  inProgress: [
    { id: 'CASE-4465', title: 'Kerberoasting attempt on DC', sev: 'high', age: '2h', alerts: 8, assignee: 'younes', tags: ['T1558.003'] },
    { id: 'CASE-4462', title: 'Audit log tampering — win-dc-01', sev: 'high', age: '3h', alerts: 2, assignee: 'amir', tags: ['T1070.001'] },
    { id: 'CASE-4459', title: 'Phishing campaign — finance', sev: 'medium', age: '5h', alerts: 24, assignee: 'younes', tags: ['T1566.002', 'phishing'] },
    { id: 'CASE-4458', title: 'Container escape attempt', sev: 'high', age: '6h', alerts: 4, assignee: 'sara', tags: ['T1611'] },
  ],
  resolved: [
    { id: 'CASE-4451', title: 'False positive — backup job', sev: 'low', age: '1d', alerts: 6, assignee: 'amir', tags: ['fp'] },
    { id: 'CASE-4447', title: 'Patched: CVE-2026-1142', sev: 'medium', age: '1d', alerts: 1, assignee: 'sara', tags: ['cve'] },
  ],
  closed: [
    { id: 'CASE-4441', title: 'Resolved: Tor exit node block', sev: 'medium', age: '2d', alerts: 12, assignee: 'younes', tags: ['T1090.003'] },
    { id: 'CASE-4438', title: 'Contained: web-prod ransomware staging', sev: 'critical', age: '3d', alerts: 89, assignee: 'younes', tags: ['T1486'] },
  ],
};

const COPILOT_CONVO = [
  { role: 'user', text: 'Investigate alert WZ-9281047 — PowerShell on web-prod-01.' },
  { role: 'ai', text: 'Analyzing alert WZ-9281047…', evidence: [
    { type: 'query', label: 'SIEM query', value: 'agent.name:web-prod-01 AND rule.id:92653 last 1h' },
    { type: 'result', label: '3 matching events', value: '15:42:11, 15:43:02, 15:43:18 UTC' },
    { type: 'ioc', label: 'Process tree', value: 'cmd.exe → powershell.exe -enc JABw...' },
  ]},
  { role: 'ai', text: 'I found a base64-encoded PowerShell command spawned by cmd.exe at 15:42:11 UTC. Decoded payload attempts to download a second-stage binary from `185.220.101.42`. The source IP is a known Tor exit node and appears in 4 other recent alerts targeting the same agent. **MITRE: T1059.001 (Execution) + T1071 (C2).** This looks like an active intrusion, not a false positive.', evidence: [
    { type: 'enrich', label: 'IP intel — 185.220.101.42', value: 'VirusTotal: 18/94 malicious · AbuseIPDB: 100% · Tor exit node · Last seen: 2m ago' },
    { type: 'corr', label: 'Related cases', value: 'CASE-4471 (this), CASE-4438 (3d ago — same IP)' },
  ]},
  { role: 'user', text: 'Recommend containment.' },
];

const CORRELATION_NODES = [
  { id: 'ip1',   label: '185.220.101.42', type: 'ip',    x: 0.18, y: 0.30, sev: 'critical' },
  { id: 'a1',    label: 'web-prod-01',    type: 'agent', x: 0.45, y: 0.20, sev: 'critical' },
  { id: 'r1',    label: 'T1059.001',      type: 'rule',  x: 0.45, y: 0.55, sev: 'critical' },
  { id: 'c1',    label: 'CASE-4471',      type: 'case',  x: 0.72, y: 0.30, sev: 'critical' },
  { id: 'u1',    label: 'svc_backup',     type: 'user',  x: 0.45, y: 0.82, sev: 'high' },
  { id: 'a2',    label: 'db-primary',     type: 'agent', x: 0.18, y: 0.68, sev: 'high' },
  { id: 'r2',    label: 'T1071',          type: 'rule',  x: 0.72, y: 0.65, sev: 'high' },
  { id: 'h1',    label: 'a4f8b2c…',       type: 'hash',  x: 0.88, y: 0.50, sev: 'critical' },
];

const CORRELATION_EDGES = [
  ['ip1', 'a1'], ['ip1', 'a2'],
  ['a1',  'r1'], ['a1',  'c1'],
  ['r1',  'c1'], ['c1',  'r2'],
  ['a2',  'r2'], ['r2',  'h1'],
  ['u1',  'a1'], ['u1',  'a2'],
];

window.SOC_DATA = {
  KPIS, SEVERITY_DIST, TIMELINE_24H, TOP_RULES, TOP_AGENTS, RECENT_ALERTS,
  ATTACK_ORIGINS, TARGET, CASES, COPILOT_CONVO, CORRELATION_NODES, CORRELATION_EDGES,
};
