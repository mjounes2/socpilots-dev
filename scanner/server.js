// ============================================================
//  SOCPilots — Network Scanner Microservice
//  Runs nmap as root inside its own container, exposes HTTP API
//  Called by webapp backend via internal Docker network
// ============================================================
const http  = require('http');
const { execFile } = require('child_process');

function parseNmapXml(xml) {
  const hosts = [];
  const hostBlocks = xml.match(/<host\b[^>]*>[\s\S]*?<\/host>/g) || [];

  for (const block of hostBlocks) {
    const stateM = block.match(/<status\s[^>]*state="([^"]+)"/);
    if (!stateM || stateM[1] !== 'up') continue;

    const addrMatches = [...block.matchAll(/<address\s+addr="([^"]+)"\s+addrtype="([^"]+)"/g)];
    let ip = '', mac = '';
    for (const m of addrMatches) {
      if (m[2] === 'ipv4') ip = m[1];
      if (m[2] === 'mac')  mac = m[1];
    }
    if (!ip) continue;

    const hostnameM = block.match(/<hostname\s+name="([^"]+)"/);
    const hostname  = hostnameM ? hostnameM[1] : '';

    const osM  = block.match(/<osmatch\s+name="([^"]+)"/);
    const os   = osM ? osM[1] : '';

    const ports = [];
    const portBlocks = block.match(/<port\b[^>]*>[\s\S]*?<\/port>/g) || [];
    for (const pb of portBlocks) {
      const pStateM = pb.match(/<state\s+state="([^"]+)"/);
      if (!pStateM || pStateM[1] !== 'open') continue;
      const portIdM   = pb.match(/portid="(\d+)"/);
      const protoM    = pb.match(/protocol="([^"]+)"/);
      const serviceM  = pb.match(/<service\s+name="([^"]+)"/);
      const productM  = pb.match(/product="([^"]+)"/);
      if (portIdM) ports.push({
        port:    parseInt(portIdM[1]),
        proto:   protoM?.[1] || 'tcp',
        service: serviceM?.[1] || '',
        product: productM?.[1] || '',
      });
    }

    hosts.push({ ip, mac, hostname, os, ports, status: 'online' });
  }
  return hosts;
}

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
    req.on('end', () => {
      let subnets;
      try { ({ subnets } = JSON.parse(body)); } catch { return respond(400, { error: 'invalid json' }); }
      if (!Array.isArray(subnets) || !subnets.length) return respond(400, { error: 'subnets required' });

      // Validate each subnet looks like an IP/CIDR to prevent injection
      const safe = subnets.filter(s => /^[\d.:/]+$/.test(s.trim()));
      if (!safe.length) return respond(400, { error: 'no valid subnets' });

      const args = ['-sV', '--top-ports', '20', '-O', '--osscan-guess', '-T4', '-oX', '-', ...safe];
      console.log('[SCAN] Starting:', safe.join(', '));

      execFile('nmap', args, { timeout: 300_000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout) => {
        if (err && !stdout) {
          console.error('[SCAN] nmap error:', err.message);
          return respond(500, { error: err.message });
        }
        try {
          const hosts = parseNmapXml(stdout);
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
