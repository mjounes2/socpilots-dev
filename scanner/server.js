// ============================================================
//  SOCPilots — Network Scanner Microservice
//  Runs nmap as root inside its own container, exposes HTTP API
//  Called by webapp backend via internal Docker network
// ============================================================
const http     = require('http');
const { execFile } = require('child_process');
const dns      = require('dns').promises;

// ── nmap XML Parser ──────────────────────────────────────────
function parseNmapXml(xml) {
  const hosts = [];
  const hostBlocks = xml.match(/<host\b[^>]*>[\s\S]*?<\/host>/g) || [];

  for (const block of hostBlocks) {
    // Only include hosts that are up
    const stateM = block.match(/<status\s[^>]*state="([^"]+)"/);
    if (!stateM || stateM[1] !== 'up') continue;

    // IP and MAC
    const addrMatches = [...block.matchAll(/<address\s+addr="([^"]+)"\s+addrtype="([^"]+)"/g)];
    let ip = '', mac = '', vendor = '';
    for (const m of addrMatches) {
      if (m[2] === 'ipv4') ip = m[1];
      if (m[2] === 'mac') {
        mac = m[1];
        const vM = m[0].match(/vendor="([^"]+)"/);
        if (vM) vendor = vM[1];
      }
    }
    if (!ip) continue;

    // Hostname — nmap puts PTR/user hostnames inside <hostnames><hostname .../></hostnames>
    // Try all hostname entries, prefer PTR (reverse DNS), fall back to user
    let hostname = '';
    const hnBlock = block.match(/<hostnames>([\s\S]*?)<\/hostnames>/);
    if (hnBlock) {
      const allHn = [...hnBlock[1].matchAll(/<hostname\s+name="([^"]+)"\s+type="([^"]+)"/g)];
      const ptr  = allHn.find(m => m[2] === 'PTR');
      const user = allHn.find(m => m[2] === 'user');
      hostname = (ptr || user)?.[1] || '';
    }

    // OS — nmap returns multiple osmatch ordered by accuracy, take the best
    let os = '';
    const osMatches = [...block.matchAll(/<osmatch\s+name="([^"]+)"\s+accuracy="(\d+)"/g)];
    if (osMatches.length) {
      // Sort by accuracy desc, pick highest
      osMatches.sort((a, b) => parseInt(b[2]) - parseInt(a[2]));
      os = osMatches[0][1];
    }
    // Fallback: try osclass
    if (!os) {
      const oc = block.match(/<osclass\s[^>]*osfamily="([^"]+)"/);
      if (oc) os = oc[1];
    }

    // Fallback: ostype from service detection (e.g. SSH banner reveals "Linux")
    if (!os) {
      const stM = block.match(/ostype="([^"]+)"/);
      if (stM) os = stM[1];
    }
    // TTL-based OS hint if all else failed
    if (!os) {
      const ttlM = block.match(/reason_ttl="(\d+)"/);
      if (ttlM) {
        const ttl = parseInt(ttlM[1]);
        if (ttl <= 64)  os = 'Linux/Unix (TTL hint)';
        else if (ttl <= 128) os = 'Windows (TTL hint)';
        else if (ttl <= 255) os = 'Network Device (TTL hint)';
      }
    }

    // Open ports
    const ports = [];
    const portBlocks = block.match(/<port\b[^>]*>[\s\S]*?<\/port>/g) || [];
    for (const pb of portBlocks) {
      const pStateM = pb.match(/<state\s+state="([^"]+)"/);
      if (!pStateM || pStateM[1] !== 'open') continue;
      const portIdM  = pb.match(/portid="(\d+)"/);
      const protoM   = pb.match(/protocol="([^"]+)"/);
      const serviceM = pb.match(/<service\s+name="([^"]+)"/);
      const productM = pb.match(/product="([^"]+)"/);
      const versionM = pb.match(/version="([^"]+)"/);
      if (portIdM) ports.push({
        port:    parseInt(portIdM[1]),
        proto:   protoM?.[1] || 'tcp',
        service: serviceM?.[1] || '',
        product: [productM?.[1], versionM?.[1]].filter(Boolean).join(' '),
      });
    }

    hosts.push({ ip, mac, vendor, hostname, os, ports, status: 'online' });
  }
  return hosts;
}

// ── Reverse DNS fallback for hosts without nmap hostname ─────
async function enrichHostnames(hosts) {
  const enriched = await Promise.allSettled(
    hosts.map(async h => {
      if (h.hostname) return h;
      try {
        const result = await dns.reverse(h.ip);
        return { ...h, hostname: result[0] || '' };
      } catch {
        return h;
      }
    })
  );
  return enriched.map(r => r.status === 'fulfilled' ? r.value : r.reason);
}

// ── HTTP Server ───────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const respond = (code, body) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  };

  if (req.method === 'GET' && req.url === '/health') {
    return respond(200, { status: 'ok' });
  }

  if (req.method === 'POST' && req.url === '/scan') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      let subnets;
      try { ({ subnets } = JSON.parse(body)); }
      catch { return respond(400, { error: 'invalid json' }); }

      if (!Array.isArray(subnets) || !subnets.length)
        return respond(400, { error: 'subnets required' });

      // Validate to prevent command injection (only digits, dots, colons, slashes)
      const safe = subnets.filter(s => /^[\d.:/]+$/.test(s.trim()));
      if (!safe.length) return respond(400, { error: 'no valid subnets' });

      // -sV: version detection  -O: OS detection  --osscan-guess: best-effort OS
      // --top-ports 50: balance speed vs coverage  -T4: aggressive timing
      // --system-dns: use system resolver for PTR lookups
      const args = [
        '-sV', '-O', '--osscan-guess', '--version-intensity', '3',
        '--top-ports', '50', '-T4', '--system-dns', '-oX', '-',
        ...safe,
      ];

      console.log(`[SCAN] nmap ${args.join(' ')}`);

      execFile('nmap', args, { timeout: 300_000, maxBuffer: 10 * 1024 * 1024 }, async (err, stdout) => {
        if (err && !stdout) {
          console.error('[SCAN] nmap error:', err.message);
          return respond(500, { error: err.message });
        }
        try {
          let hosts = parseNmapXml(stdout || '');
          // DNS fallback for hosts that nmap didn't resolve
          hosts = await enrichHostnames(hosts);
          console.log(`[SCAN] Done — ${hosts.length} hosts found`);
          respond(200, { hosts, raw_xml: stdout });
        } catch (pe) {
          respond(500, { error: 'parse error: ' + pe.message });
        }
      });
    });
    return;
  }

  respond(404, { error: 'not found' });
});

server.listen(7777, '0.0.0.0', () => console.log('[SCANNER] Listening on :7777'));
