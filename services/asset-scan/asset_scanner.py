"""
SOCPilots — Asset Scanner Engine
=================================
Tier 1 Detection: Discovers all network hosts, identifies Wazuh coverage gaps,
calculates coverage percentage, and feeds data into Neo4j UEBA graph.

Pipeline:
  discover_assets_nmap()    — full nmap sweep with OS/service detection
  discover_assets_arp()     — fast ARP scan for local subnets only
  get_wazuh_agents()        — pull agent list from Wazuh Manager API
  store_assets()            — upsert discovered hosts into PostgreSQL
  sync_wazuh_agents()       — cache Wazuh agent data in wazuh_agents_cache
  match_agents_to_assets()  — correlate by IP then by hostname
  detect_coverage_gaps()    — find unmonitored/disconnected hosts
  assess_gap_risk()         — score each gap by severity (open ports, OS type)
  ingest_to_neo4j()         — push Asset+Gap nodes into Neo4j graph
  run_full_scan()           — orchestrate full pipeline
"""

import os
import re
import json
import logging
import subprocess
import ipaddress
from datetime import datetime, timezone
from typing import Optional

import httpx
import psycopg2
import psycopg2.extras

log = logging.getLogger(__name__)

# ── Config from environment ──────────────────────────────────────
PG_HOST     = os.getenv("PG_HOST", "postgres")
PG_PORT     = int(os.getenv("PG_PORT", "5432"))
PG_DB       = os.getenv("PG_DATABASE", "socpilots")
PG_USER     = os.getenv("PG_USER", "socpilots")
PG_PASS     = os.getenv("PG_PASSWORD", "")

WAZUH_HOST  = os.getenv("WAZUH_HOST", "")
WAZUH_PORT  = os.getenv("WAZUH_PORT", "55000")
WAZUH_USER  = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASS  = os.getenv("WAZUH_PASS", "")

OS_URL      = os.getenv("OPENSEARCH_URL", "")
OS_USER     = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS     = os.getenv("OPENSEARCH_PASS", "")
WAZUH_INDEX = os.getenv("WAZUH_INDEX", "wazuh-alerts-*")

NEO4J_URI   = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER  = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS  = os.getenv("NEO4J_PASSWORD", "")

N8N_URL     = os.getenv("N8N_WEBHOOK_URL", "")
SCAN_SUBNETS = os.getenv("SCAN_SUBNETS", "")   # comma-separated CIDRs


def db_conn():
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB,
        user=PG_USER, password=PG_PASS,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


# ── nmap XML Parser ──────────────────────────────────────────────
def parse_nmap_xml(xml: str) -> list[dict]:
    hosts = []
    import re
    host_blocks = re.findall(r'<host\b[^>]*>.*?</host>', xml, re.DOTALL)
    for block in host_blocks:
        state_m = re.search(r'<status\s[^>]*state="([^"]+)"', block)
        if not state_m or state_m.group(1) != 'up':
            continue
        ip, mac, vendor = '', '', ''
        for m in re.finditer(r'<address\s+addr="([^"]+)"\s+addrtype="([^"]+)"', block):
            if m.group(2) == 'ipv4':
                ip = m.group(1)
            elif m.group(2) == 'mac':
                mac = m.group(1)
                vm = re.search(r'vendor="([^"]+)"', m.group(0))
                if vm:
                    vendor = vm.group(1)
        if not ip:
            continue
        # Hostname
        hostname = ''
        hn_block = re.search(r'<hostnames>(.*?)</hostnames>', block, re.DOTALL)
        if hn_block:
            all_hn = re.findall(r'<hostname\s+name="([^"]+)"\s+type="([^"]+)"', hn_block.group(1))
            ptr = next((h[0] for h in all_hn if h[1] == 'PTR'), None)
            user = next((h[0] for h in all_hn if h[1] == 'user'), None)
            hostname = ptr or user or ''
        # OS
        os_guess = ''
        os_matches = re.findall(r'<osmatch\s+name="([^"]+)"\s+accuracy="(\d+)"', block)
        if os_matches:
            os_matches.sort(key=lambda x: -int(x[1]))
            os_guess = os_matches[0][0]
        if not os_guess:
            oc = re.search(r'<osclass\s[^>]*osfamily="([^"]+)"', block)
            if oc:
                os_guess = oc.group(1)
        # TTL hint
        if not os_guess:
            ttl_m = re.search(r'reason_ttl="(\d+)"', block)
            if ttl_m:
                ttl = int(ttl_m.group(1))
                os_guess = ('Linux/Unix' if ttl <= 64 else
                            'Windows' if ttl <= 128 else 'Network Device')
        # OS type classification
        os_type = 'unknown'
        os_lower = (os_guess or '').lower()
        if any(x in os_lower for x in ['linux', 'ubuntu', 'debian', 'centos', 'rhel', 'unix']):
            os_type = 'linux'
        elif any(x in os_lower for x in ['windows', 'win']):
            os_type = 'windows'
        elif any(x in os_lower for x in ['macos', 'darwin', 'apple']):
            os_type = 'macos'
        elif any(x in os_lower for x in ['cisco', 'juniper', 'router', 'switch', 'network']):
            os_type = 'network_device'
        # Open ports
        ports = []
        port_blocks = re.findall(r'<port\b[^>]*>.*?</port>', block, re.DOTALL)
        for pb in port_blocks:
            ps = re.search(r'<state\s+state="([^"]+)"', pb)
            if not ps or ps.group(1) != 'open':
                continue
            portid = re.search(r'portid="(\d+)"', pb)
            proto  = re.search(r'protocol="([^"]+)"', pb)
            svc    = re.search(r'<service\s+name="([^"]+)"', pb)
            prod   = re.search(r'product="([^"]+)"', pb)
            if portid:
                ports.append({
                    'port':    int(portid.group(1)),
                    'proto':   proto.group(1) if proto else 'tcp',
                    'service': svc.group(1) if svc else '',
                    'product': prod.group(1) if prod else '',
                })
        hosts.append({
            'ip': ip, 'mac': mac, 'vendor': vendor,
            'hostname': hostname, 'os_guess': os_guess, 'os_type': os_type,
            'ports': ports, 'status': 'online',
        })
    return hosts


class AssetScanner:

    def __init__(self):
        self._init_schema()

    def _init_schema(self):
        """Load extended schema into PostgreSQL (idempotent)."""
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        if not os.path.exists(schema_path):
            log.warning("schema.sql not found — skipping schema init")
            return
        try:
            with open(schema_path) as f:
                sql = f.read()
            with db_conn() as conn, conn.cursor() as cur:
                cur.execute(sql)
                conn.commit()
            log.info("Extended schema initialized")
        except Exception as e:
            log.error(f"Schema init error: {e}")

    # ── 1. Discover assets via nmap ──────────────────────────────
    def discover_assets_nmap(self, subnets: list[str]) -> list[dict]:
        """Full nmap sweep: host discovery + service + OS detection."""
        if not subnets:
            log.warning("No subnets provided for nmap scan")
            return []
        safe = [s for s in subnets if re.match(r'^[\d.:/]+$', s.strip())]
        if not safe:
            return []
        cmd = [
            'nmap', '-sV', '-O', '--osscan-guess', '--version-intensity', '3',
            '--top-ports', '50', '-T4', '--system-dns', '-oX', '-',
        ] + safe
        log.info(f"[NMAP] Scanning: {safe}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            hosts = parse_nmap_xml(result.stdout)
            log.info(f"[NMAP] Found {len(hosts)} hosts")
            return hosts
        except subprocess.TimeoutExpired:
            log.error("[NMAP] Scan timed out after 300s")
            return []
        except Exception as e:
            log.error(f"[NMAP] Error: {e}")
            return []

    # ── 2. Fast ARP scan for local subnets ──────────────────────
    def discover_assets_arp(self, subnets: list[str]) -> list[dict]:
        """Ping/ARP scan — very fast, no ports/OS. For local /24 subnets."""
        if not subnets:
            return []
        safe = [s for s in subnets if re.match(r'^[\d.:/]+$', s.strip())]
        cmd = ['nmap', '-sn', '-T5', '-oX', '-'] + safe
        log.info(f"[ARP] Quick scan: {safe}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            hosts = parse_nmap_xml(result.stdout)
            log.info(f"[ARP] Found {len(hosts)} hosts online")
            return hosts
        except Exception as e:
            log.error(f"[ARP] Error: {e}")
            return []

    # ── 3. Get Wazuh agents from API ─────────────────────────────
    def get_wazuh_agents(self) -> list[dict]:
        """Query Wazuh Manager API for all registered agents."""
        agents = []
        if not WAZUH_HOST or not WAZUH_PASS:
            log.warning("[WAZUH] WAZUH_HOST/PASS not configured — trying OpenSearch fallback")
            return self._get_agents_from_opensearch()
        try:
            with httpx.Client(verify=False, timeout=30) as client:
                # Authenticate
                auth_r = client.get(
                    f"https://{WAZUH_HOST}:{WAZUH_PORT}/security/user/authenticate",
                    auth=(WAZUH_USER, WAZUH_PASS)
                )
                if auth_r.status_code != 200:
                    log.error(f"[WAZUH] Auth failed: {auth_r.status_code}")
                    return self._get_agents_from_opensearch()
                token = auth_r.json()['data']['token']
                headers = {'Authorization': f'Bearer {token}'}
                # Fetch all agents (paginated)
                offset = 0
                while True:
                    r = client.get(
                        f"https://{WAZUH_HOST}:{WAZUH_PORT}/agents",
                        headers=headers,
                        params={'offset': offset, 'limit': 500,
                                'select': 'id,name,ip,status,version,os,lastKeepAlive,dateAdd,group,manager'}
                    )
                    if r.status_code != 200:
                        break
                    data = r.json().get('data', {})
                    items = data.get('affected_items', [])
                    for a in items:
                        if a.get('id') == '000':  # skip manager itself
                            continue
                        agents.append({
                            'agent_id':     a.get('id', ''),
                            'agent_name':   a.get('name', ''),
                            'agent_ip':     a.get('ip', ''),
                            'status':       a.get('status', ''),
                            'version':      a.get('version', ''),
                            'os_name':      (a.get('os') or {}).get('name', ''),
                            'os_platform':  (a.get('os') or {}).get('platform', ''),
                            'os_arch':      (a.get('os') or {}).get('arch', ''),
                            'last_keepalive': a.get('lastKeepAlive'),
                            'date_add':     a.get('dateAdd'),
                            'group_name':   ','.join(a.get('group') or []),
                            'manager_host': a.get('manager', ''),
                        })
                    total = data.get('total_affected_items', 0)
                    offset += len(items)
                    if offset >= total or not items:
                        break
            log.info(f"[WAZUH] Got {len(agents)} agents from API")
        except Exception as e:
            log.error(f"[WAZUH] API error: {e} — falling back to OpenSearch")
            return self._get_agents_from_opensearch()
        return agents

    def _get_agents_from_opensearch(self) -> list[dict]:
        """Fallback: extract agent list from OpenSearch alert aggregations."""
        if not OS_URL or not OS_PASS:
            return []
        try:
            with httpx.Client(verify=False, timeout=15) as client:
                r = client.post(
                    f"{OS_URL}/{WAZUH_INDEX}/_search",
                    auth=(OS_USER, OS_PASS),
                    json={
                        "size": 0,
                        "aggs": {
                            "agents": {
                                "terms": {"field": "agent.name", "size": 500},
                                "aggs": {
                                    "id":  {"terms": {"field": "agent.id",     "size": 1}},
                                    "ip":  {"terms": {"field": "agent.ip",     "size": 1}},
                                    "last":{"max":   {"field": "@timestamp"}},
                                }
                            }
                        }
                    }
                )
                buckets = r.json().get('aggregations', {}).get('agents', {}).get('buckets', [])
                agents = []
                for b in buckets:
                    last_ts = b.get('last', {}).get('value')
                    now_ms  = datetime.now(timezone.utc).timestamp() * 1000
                    diff_h  = (now_ms - (last_ts or 0)) / 3_600_000 if last_ts else 999
                    status  = 'active' if diff_h < 24 else 'disconnected'
                    agents.append({
                        'agent_id':    b.get('id', {}).get('buckets', [{}])[0].get('key', ''),
                        'agent_name':  b.get('key', ''),
                        'agent_ip':    b.get('ip', {}).get('buckets', [{}])[0].get('key', ''),
                        'status':      status,
                        'version':     '',
                        'os_name':     '',
                        'os_platform': '',
                        'os_arch':     '',
                        'last_keepalive': datetime.fromtimestamp(last_ts/1000, tz=timezone.utc).isoformat() if last_ts else None,
                        'date_add':    None,
                        'group_name':  '',
                        'manager_host':'',
                    })
                log.info(f"[OS_FALLBACK] Got {len(agents)} agents from OpenSearch")
                return agents
        except Exception as e:
            log.error(f"[OS_FALLBACK] Error: {e}")
            return []

    # ── 4. Store discovered assets in PostgreSQL ─────────────────
    def store_assets(self, hosts: list[dict], subnets: list[dict] = None) -> int:
        """Upsert all discovered hosts into assets table."""
        subnet_map = {s['cidr']: s['id'] for s in (subnets or [])}
        count = 0
        try:
            with db_conn() as conn, conn.cursor() as cur:
                for h in hosts:
                    ip = h.get('ip', '')
                    if not ip:
                        continue
                    subnet_id = None
                    for cidr, sid in subnet_map.items():
                        if _ip_in_subnet(ip, cidr):
                            subnet_id = sid
                            break
                    cur.execute("""
                        INSERT INTO assets
                          (ip, hostname, mac, vendor, os_guess, status, open_ports, subnet_id)
                        VALUES (%s, %s, %s, %s, %s, 'online', %s, %s)
                        ON CONFLICT(ip) DO UPDATE SET
                          hostname   = COALESCE(EXCLUDED.hostname,   assets.hostname),
                          mac        = COALESCE(EXCLUDED.mac,        assets.mac),
                          vendor     = COALESCE(EXCLUDED.vendor,     assets.vendor),
                          os_guess   = COALESCE(EXCLUDED.os_guess,   assets.os_guess),
                          open_ports = EXCLUDED.open_ports,
                          status     = 'online',
                          last_seen  = NOW(),
                          subnet_id  = COALESCE(EXCLUDED.subnet_id, assets.subnet_id)
                    """, (
                        ip,
                        h.get('hostname') or None,
                        h.get('mac') or None,
                        h.get('vendor') or None,
                        h.get('os_guess') or None,
                        json.dumps(h.get('ports', [])),
                        subnet_id,
                    ))
                    count += 1
                conn.commit()
        except Exception as e:
            log.error(f"[STORE] Error storing assets: {e}")
        log.info(f"[STORE] Upserted {count} assets")
        return count

    # ── 5. Sync Wazuh agents to cache table ──────────────────────
    def sync_wazuh_agents(self, agents: list[dict]) -> int:
        count = 0
        try:
            with db_conn() as conn, conn.cursor() as cur:
                for a in agents:
                    if not a.get('agent_id'):
                        continue
                    cur.execute("""
                        INSERT INTO wazuh_agents_cache
                          (agent_id, agent_name, agent_ip, status, version,
                           os_name, os_platform, os_arch, last_keepalive,
                           date_add, group_name, manager_host, synced_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                        ON CONFLICT(agent_id) DO UPDATE SET
                          agent_name=EXCLUDED.agent_name, agent_ip=EXCLUDED.agent_ip,
                          status=EXCLUDED.status, version=EXCLUDED.version,
                          os_name=EXCLUDED.os_name, last_keepalive=EXCLUDED.last_keepalive,
                          synced_at=NOW()
                    """, (
                        a['agent_id'], a['agent_name'], a['agent_ip'], a['status'],
                        a.get('version'), a.get('os_name'), a.get('os_platform'),
                        a.get('os_arch'), a.get('last_keepalive'), a.get('date_add'),
                        a.get('group_name'), a.get('manager_host'),
                    ))
                    count += 1
                conn.commit()
        except Exception as e:
            log.error(f"[SYNC] Error syncing agents: {e}")
        log.info(f"[SYNC] Synced {count} Wazuh agents")
        return count

    # ── 6. Match agents to assets ────────────────────────────────
    def match_agents_to_assets(self) -> int:
        """Cross-reference assets with Wazuh agents by IP and hostname."""
        updated = 0
        try:
            with db_conn() as conn, conn.cursor() as cur:
                # Match by exact IP
                cur.execute("""
                    UPDATE assets a
                    SET wazuh_agent_id     = w.agent_id,
                        wazuh_agent_name   = w.agent_name,
                        wazuh_agent_status = w.status
                    FROM wazuh_agents_cache w
                    WHERE a.ip = w.agent_ip AND w.agent_ip != ''
                """)
                updated += cur.rowcount
                # Match by hostname prefix (case-insensitive)
                cur.execute("""
                    UPDATE assets a
                    SET wazuh_agent_id     = w.agent_id,
                        wazuh_agent_name   = w.agent_name,
                        wazuh_agent_status = w.status
                    FROM wazuh_agents_cache w
                    WHERE a.wazuh_agent_id IS NULL
                      AND a.hostname IS NOT NULL
                      AND lower(split_part(a.hostname, '.', 1)) = lower(split_part(w.agent_name, '.', 1))
                """)
                updated += cur.rowcount
                conn.commit()
        except Exception as e:
            log.error(f"[MATCH] Error matching agents: {e}")
        log.info(f"[MATCH] Matched {updated} assets to Wazuh agents")
        return updated

    # ── 7. Detect coverage gaps ──────────────────────────────────
    def detect_coverage_gaps(self) -> list[dict]:
        """Find assets without an active Wazuh agent — these are the security gaps."""
        gaps = []
        try:
            with db_conn() as conn, conn.cursor() as cur:
                # Mark any previously open gaps as resolved if agent is now active
                cur.execute("""
                    UPDATE coverage_gaps g
                    SET resolved_at = NOW(), resolution_notes = 'Agent now active'
                    FROM assets a
                    WHERE g.asset_id = a.id
                      AND g.resolved_at IS NULL
                      AND a.wazuh_agent_status = 'active'
                """)
                conn.commit()

                # Find currently unmonitored assets
                cur.execute("""
                    SELECT a.id, a.ip, a.hostname, a.os_guess, a.open_ports,
                           a.wazuh_agent_id, a.wazuh_agent_status
                    FROM assets a
                    WHERE a.status = 'online'
                      AND (a.wazuh_agent_id IS NULL
                           OR a.wazuh_agent_status IN ('disconnected', 'never_connected', 'pending'))
                    ORDER BY a.ip
                """)
                assets_without_agent = cur.fetchall()

                for asset in assets_without_agent:
                    gap_type = (
                        'missing_agent'       if not asset['wazuh_agent_id'] else
                        'disconnected_agent'  if asset['wazuh_agent_status'] == 'disconnected' else
                        'inactive_agent'
                    )
                    severity = self.assess_gap_severity(asset)
                    risk_score = self.assess_gap_risk(asset)

                    # Check if gap already open
                    cur.execute("""
                        SELECT id FROM coverage_gaps
                        WHERE asset_id = %s AND resolved_at IS NULL LIMIT 1
                    """, (asset['id'],))
                    existing = cur.fetchone()

                    if existing:
                        # Update existing gap
                        cur.execute("""
                            UPDATE coverage_gaps
                            SET gap_type = %s, severity = %s, risk_score = %s,
                                os_guess = %s, open_ports = %s
                            WHERE id = %s
                        """, (gap_type, severity, risk_score,
                              asset['os_guess'], json.dumps(asset.get('open_ports') or []),
                              existing['id']))
                        gap_id = existing['id']
                    else:
                        # Create new gap
                        cur.execute("""
                            INSERT INTO coverage_gaps
                              (asset_id, asset_ip, asset_hostname, gap_type, severity,
                               risk_score, os_guess, open_ports)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                            RETURNING id
                        """, (asset['id'], asset['ip'],
                              asset.get('hostname') or asset['ip'],
                              gap_type, severity, risk_score,
                              asset.get('os_guess'),
                              json.dumps(asset.get('open_ports') or [])))
                        gap_id = cur.fetchone()['id']

                    gaps.append({
                        'id':           gap_id,
                        'asset_ip':     asset['ip'],
                        'hostname':     asset.get('hostname') or asset['ip'],
                        'gap_type':     gap_type,
                        'severity':     severity,
                        'risk_score':   risk_score,
                        'os_guess':     asset.get('os_guess'),
                        'open_ports':   asset.get('open_ports') or [],
                    })
                conn.commit()

        except Exception as e:
            log.error(f"[GAPS] Error detecting gaps: {e}")
        log.info(f"[GAPS] Found {len(gaps)} coverage gaps")
        return gaps

    def assess_gap_severity(self, asset: dict) -> str:
        """Determine gap severity based on asset characteristics."""
        ports = asset.get('open_ports') or []
        if isinstance(ports, str):
            ports = json.loads(ports)
        port_numbers = [p.get('port', 0) for p in ports]
        os_lower = (asset.get('os_guess') or '').lower()
        # Critical: servers with sensitive services
        critical_ports = {22, 3389, 445, 135, 139, 1433, 3306, 5432, 6379, 27017}
        if any(p in critical_ports for p in port_numbers):
            return 'critical'
        if any(x in os_lower for x in ['server', 'windows server', 'ubuntu server']):
            return 'critical'
        # High: systems with web/api services
        high_ports = {80, 443, 8080, 8443, 8000, 5000, 3000}
        if any(p in high_ports for p in port_numbers):
            return 'high'
        # Medium: workstations/endpoints
        if any(x in os_lower for x in ['windows', 'linux', 'macos']):
            return 'medium'
        return 'low'

    def assess_gap_risk(self, asset: dict) -> int:
        """Score gap risk 0-100."""
        score = 50  # base score for any gap
        ports = asset.get('open_ports') or []
        if isinstance(ports, str):
            ports = json.loads(ports)
        port_numbers = [p.get('port', 0) for p in ports]
        critical_ports = {22, 3389, 445, 1433, 3306, 5432}
        if any(p in critical_ports for p in port_numbers):
            score += 25
        if len(ports) > 10:
            score += 10
        os_lower = (asset.get('os_guess') or '').lower()
        if 'server' in os_lower:
            score += 15
        return min(score, 100)

    # ── 8. Ingest assets + gaps into Neo4j ───────────────────────
    def ingest_to_neo4j(self, hosts: list[dict], gaps: list[dict]):
        """Push Asset nodes and UNMONITORED relationships into Neo4j graph."""
        if not NEO4J_PASS:
            log.info("[NEO4J] Password not set — skipping graph ingest")
            return
        try:
            from neo4j import GraphDatabase
            driver = GraphDatabase.driver(
                NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS),
                connection_timeout=5
            )
            with driver.session() as session:
                for h in hosts:
                    session.run("""
                        MERGE (a:Asset {ip: $ip})
                        SET a.hostname = $hostname,
                            a.os_guess = $os,
                            a.vendor   = $vendor,
                            a.status   = 'online',
                            a.last_seen = $ts
                    """, ip=h['ip'], hostname=h.get('hostname',''),
                         os=h.get('os_guess',''), vendor=h.get('vendor',''),
                         ts=datetime.utcnow().isoformat())
                for g in gaps:
                    session.run("""
                        MERGE (a:Asset {ip: $ip})
                        SET a.agent_status = 'MISSING',
                            a.risk_score   = $risk,
                            a.gap_type     = $gap_type
                        WITH a
                        MERGE (g:CoverageGap {asset_ip: $ip})
                        SET g.severity   = $severity,
                            g.risk_score = $risk,
                            g.gap_type   = $gap_type,
                            g.detected_at = $ts
                        MERGE (a)-[:HAS_GAP]->(g)
                    """, ip=g['asset_ip'], risk=g['risk_score'],
                         gap_type=g['gap_type'], severity=g['severity'],
                         ts=datetime.utcnow().isoformat())
            driver.close()
            log.info(f"[NEO4J] Ingested {len(hosts)} assets + {len(gaps)} gaps into graph")
        except Exception as e:
            log.error(f"[NEO4J] Ingest error: {e}")

    # ── 9. Add gaps to deployment queue ─────────────────────────
    def queue_deployments(self, gaps: list[dict]):
        """Add critical/high gaps to the agent deployment queue."""
        queued = 0
        try:
            with db_conn() as conn, conn.cursor() as cur:
                for g in gaps:
                    if g['severity'] not in ('critical', 'high'):
                        continue
                    # Check if already queued
                    cur.execute("""
                        SELECT id FROM deployment_queue
                        WHERE asset_ip = %s AND status IN ('pending', 'in_progress')
                        LIMIT 1
                    """, (g['asset_ip'],))
                    if cur.fetchone():
                        continue
                    # Get asset id
                    cur.execute("SELECT id, os_guess FROM assets WHERE ip = %s", (g['asset_ip'],))
                    asset = cur.fetchone()
                    if not asset:
                        continue
                    os_type = 'unknown'
                    os_lower = (asset.get('os_guess') or '').lower()
                    if 'linux' in os_lower or 'ubuntu' in os_lower:
                        os_type = 'linux'
                    elif 'windows' in os_lower:
                        os_type = 'windows'
                    cur.execute("""
                        INSERT INTO deployment_queue
                          (asset_id, asset_ip, asset_hostname, os_type, priority, gap_id)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (asset['id'], g['asset_ip'], g.get('hostname', g['asset_ip']),
                          os_type, g['severity'], g.get('id')))
                    # Mark gap as queued
                    if g.get('id'):
                        cur.execute("""
                            UPDATE coverage_gaps SET in_deployment_queue = TRUE WHERE id = %s
                        """, (g['id'],))
                    queued += 1
                conn.commit()
        except Exception as e:
            log.error(f"[QUEUE] Error queuing deployments: {e}")
        log.info(f"[QUEUE] Added {queued} items to deployment queue")
        return queued

    # ── 10. Calculate coverage metrics ──────────────────────────
    def get_coverage_metrics(self) -> dict:
        try:
            with db_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    SELECT
                      COUNT(*)                                          AS total,
                      COUNT(*) FILTER (WHERE wazuh_agent_status = 'active') AS covered,
                      COUNT(*) FILTER (WHERE wazuh_agent_id IS NULL)   AS missing_agent,
                      COUNT(*) FILTER (WHERE wazuh_agent_status = 'disconnected') AS disconnected
                    FROM assets WHERE status = 'online'
                """)
                a = cur.fetchone()
                total    = a['total'] or 0
                covered  = a['covered'] or 0
                pct      = round((covered / total * 100), 1) if total > 0 else 0.0
                cur.execute("""
                    SELECT severity, COUNT(*) AS cnt
                    FROM coverage_gaps WHERE resolved_at IS NULL
                    GROUP BY severity
                """)
                gap_by_sev = {r['severity']: r['cnt'] for r in cur.fetchall()}
                cur.execute("""
                    SELECT COUNT(*) AS cnt FROM deployment_queue
                    WHERE status IN ('pending', 'in_progress')
                """)
                pending = cur.fetchone()['cnt'] or 0
                # Snapshot for trending
                cur.execute("""
                    INSERT INTO coverage_metrics
                      (total_assets, covered_assets, coverage_percentage,
                       critical_gaps, high_gaps, pending_deployments)
                    VALUES (%s,%s,%s,%s,%s,%s)
                """, (total, covered, pct,
                      gap_by_sev.get('critical', 0),
                      gap_by_sev.get('high', 0), pending))
                conn.commit()
                return {
                    'total_assets':         total,
                    'covered_assets':       covered,
                    'coverage_percentage':  pct,
                    'missing_agent':        a['missing_agent'] or 0,
                    'disconnected_agent':   a['disconnected'] or 0,
                    'gaps_by_severity':     gap_by_sev,
                    'pending_deployments':  pending,
                    'target_percentage':    98.0,
                    'meets_target':         pct >= 98.0,
                }
        except Exception as e:
            log.error(f"[METRICS] Error: {e}")
            return {'error': str(e)}

    # ── 11. Full pipeline orchestration ─────────────────────────
    def run_full_scan(self, subnets: list[str] = None,
                      triggered_by: str = 'api') -> dict:
        """Run complete discovery → match → gap-detect → score → ingest pipeline."""
        if not subnets:
            subnets = [s.strip() for s in SCAN_SUBNETS.split(',') if s.strip()]
        if not subnets:
            # Fall back to subnets in DB
            try:
                with db_conn() as conn, conn.cursor() as cur:
                    cur.execute("SELECT cidr FROM subnets WHERE enabled = TRUE")
                    subnets = [r['cidr'] for r in cur.fetchall()]
            except Exception:
                pass
        if not subnets:
            return {'error': 'No subnets configured. Add subnets via UI or SCAN_SUBNETS env var.'}

        scan_id = None
        try:
            with db_conn() as conn, conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scan_history(subnets_scanned, triggered_by)
                    VALUES (%s, %s) RETURNING id
                """, (subnets, triggered_by))
                scan_id = cur.fetchone()['id']
                conn.commit()
        except Exception as e:
            log.error(f"Failed to create scan record: {e}")

        start = datetime.utcnow()
        result = {'scan_id': scan_id, 'subnets': subnets}
        try:
            # Get configured subnets for subnet_id mapping
            db_subnets = []
            try:
                with db_conn() as conn, conn.cursor() as cur:
                    cur.execute("SELECT id, cidr FROM subnets")
                    db_subnets = cur.fetchall()
            except Exception:
                pass

            # Step 1: Discover assets
            log.info(f"[SCAN #{scan_id}] Step 1: Discovering assets on {subnets}")
            metrics_before = self.get_coverage_metrics()
            hosts = self.discover_assets_nmap(subnets)
            result['hosts_discovered'] = len(hosts)

            # Step 2: Store assets
            self.store_assets(hosts, db_subnets)

            # Step 3: Get and sync Wazuh agents
            log.info(f"[SCAN #{scan_id}] Step 2: Syncing Wazuh agents")
            agents = self.get_wazuh_agents()
            self.sync_wazuh_agents(agents)
            result['agents_synced'] = len(agents)

            # Step 4: Match agents to assets
            log.info(f"[SCAN #{scan_id}] Step 3: Matching agents to assets")
            self.match_agents_to_assets()

            # Step 5: Detect gaps
            log.info(f"[SCAN #{scan_id}] Step 4: Detecting coverage gaps")
            gaps = self.detect_coverage_gaps()
            result['gaps_found'] = len(gaps)

            # Step 6: Queue critical gaps for deployment
            queued = self.queue_deployments(gaps)
            result['queued_for_deployment'] = queued

            # Step 7: Ingest to Neo4j
            log.info(f"[SCAN #{scan_id}] Step 5: Ingesting to Neo4j graph")
            self.ingest_to_neo4j(hosts, gaps)

            # Step 8: Calculate final metrics
            metrics_after = self.get_coverage_metrics()
            result['metrics'] = metrics_after
            result['coverage_before'] = metrics_before.get('coverage_percentage', 0)
            result['coverage_after']  = metrics_after.get('coverage_percentage', 0)
            result['status'] = 'completed'

            duration = int((datetime.utcnow() - start).total_seconds())
            result['duration_seconds'] = duration
            log.info(f"[SCAN #{scan_id}] Complete in {duration}s — "
                     f"{len(hosts)} hosts, {len(gaps)} gaps, "
                     f"{metrics_after.get('coverage_percentage')}% coverage")

            # Update scan history
            if scan_id:
                try:
                    with db_conn() as conn, conn.cursor() as cur:
                        cur.execute("""
                            UPDATE scan_history SET
                              hosts_discovered  = %s, agents_synced = %s,
                              gaps_found        = %s, coverage_before = %s,
                              coverage_after    = %s, duration_seconds = %s,
                              completed_at      = NOW(), status = 'completed'
                            WHERE id = %s
                        """, (len(hosts), len(agents), len(gaps),
                              result['coverage_before'], result['coverage_after'],
                              duration, scan_id))
                        conn.commit()
                except Exception as e:
                    log.error(f"Failed to update scan history: {e}")

        except Exception as e:
            log.error(f"[SCAN #{scan_id}] Error: {e}")
            result['status'] = 'error'
            result['error'] = str(e)
            if scan_id:
                try:
                    with db_conn() as conn, conn.cursor() as cur:
                        cur.execute("""
                            UPDATE scan_history SET status='error', error_message=%s,
                              completed_at=NOW() WHERE id=%s
                        """, (str(e), scan_id))
                        conn.commit()
                except Exception:
                    pass

        return result


def _ip_in_subnet(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False
