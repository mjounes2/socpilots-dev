// SOC Pilots — centralised API layer (production-ready)
// Loaded BEFORE any page file; exposes window.SOC_API.
//
// MODES
// -----
// 1) Production: requires a session token in sessionStorage.soc_token.
//    Real fetch() against /api/*, 401 → redirect to /login.
//
// 2) Demo (no token):
//    - get / post / put / patch / delete resolve with {error}
//    - stream() returns a short, hard-coded AI completion
//    Pages already fall back to baked-in FALLBACK_* data when SOC_API
//    returns {error}, so the UI stays fully populated without a backend.
//
// To force demo mode from outside (e.g. running in Claude sandbox or a
// preview environment) set `window.SOC_DEMO_MODE = true` BEFORE this file
// is loaded, or append `?demo=1` to the URL.

(function () {
  const params      = new URLSearchParams(location.search);
  const forcedDemo  = window.SOC_DEMO_MODE === true || params.get('demo') === '1';
  const hasToken    = () => !!sessionStorage.getItem('soc_token');
  const isDemo      = () => forcedDemo || !hasToken();

  const tok   = () => sessionStorage.getItem('soc_token');
  const user  = () => ({
    username: sessionStorage.getItem('soc_user'),
    role:     sessionStorage.getItem('soc_role'),
  });

  function redir() {
    if (isDemo()) return; // don't bounce in demo mode
    if (!location.pathname.startsWith('/login')) location.href = '/login';
  }

  function authHeaders() {
    return { Authorization: `Bearer ${tok()}`, 'Content-Type': 'application/json' };
  }

  const DEMO_ERROR = { error: 'demo-mode' };

  async function get(url) {
    if (isDemo()) return DEMO_ERROR;
    try {
      const r = await fetch(url, { headers: { Authorization: `Bearer ${tok()}` } });
      if (r.status === 401) { redir(); return null; }
      if (!r.ok) return null;
      return r.json();
    } catch { return null; }
  }

  async function post(url, body) {
    if (isDemo()) return DEMO_ERROR;
    try {
      const r = await fetch(url, { method: 'POST', headers: authHeaders(), body: JSON.stringify(body) });
      if (r.status === 401) { redir(); return null; }
      const json = await r.json().catch(() => ({}));
      if (!r.ok) return { error: json.error || 'Request failed', status: r.status };
      return json;
    } catch { return null; }
  }

  async function put(url, body) {
    if (isDemo()) return DEMO_ERROR;
    try {
      const r = await fetch(url, { method: 'PUT', headers: authHeaders(), body: JSON.stringify(body) });
      if (r.status === 401) { redir(); return null; }
      const json = await r.json().catch(() => ({}));
      if (!r.ok) return { error: json.error || 'Request failed', status: r.status };
      return json;
    } catch { return null; }
  }

  async function patch(url, body) {
    if (isDemo()) return DEMO_ERROR;
    try {
      const r = await fetch(url, { method: 'PATCH', headers: authHeaders(), body: JSON.stringify(body) });
      if (r.status === 401) { redir(); return null; }
      const json = await r.json().catch(() => ({}));
      if (!r.ok) return { error: json.error || 'Request failed', status: r.status };
      return json;
    } catch { return null; }
  }

  async function del(url) {
    if (isDemo()) return DEMO_ERROR;
    try {
      const r = await fetch(url, { method: 'DELETE', headers: { Authorization: `Bearer ${tok()}` } });
      if (r.status === 401) { redir(); return null; }
      return r.ok ? { ok: true } : null;
    } catch { return null; }
  }

  // SSE AI streaming
  async function stream(url, body, onChunk, onDone) {
    if (isDemo()) {
      // Hard-coded demo completion so the AI chat still works without a backend
      const text = "**Demo mode** — no backend connected. The LangChain ReAct agent would run a multi-step investigation here, calling tools like `siem.search`, `mcp.enrich_ip`, and `spcm.find_related`. Connect to your real /api/langchain/* endpoint to see real responses.";
      let full = '';
      const tokens = text.split(' ');
      for (let i = 0; i < tokens.length; i++) {
        await new Promise(r => setTimeout(r, 35));
        full += (i ? ' ' : '') + tokens[i];
        onChunk(full);
      }
      onDone(full);
      return;
    }
    let full = '';
    try {
      const r = await fetch(url, { method: 'POST', headers: authHeaders(), body: JSON.stringify(body) });
      if (r.status === 401) { redir(); onDone(''); return; }
      if (!r.ok || !r.body) { onDone('AI unavailable'); return; }
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6).trim();
          if (raw === '[DONE]') { onDone(full); return; }
          try {
            const j = JSON.parse(raw);
            const tok2 = j.token || j.data || j.text || j.content || '';
            if (tok2) { full += tok2; onChunk(full); }
            if (j.type === 'done' || j.done) { onDone(full || j.response || ''); return; }
            if (j.type === 'error') { onDone(full || j.data || 'AI error'); return; }
            if (j.response && !full) { full = j.response; onChunk(full); onDone(full); return; }
          } catch {
            if (raw && raw !== '[DONE]') { full += raw; onChunk(full); }
          }
        }
      }
      onDone(full);
    } catch {
      onDone(full || 'Connection error');
    }
  }

  function logout() {
    if (isDemo()) { location.reload(); return; }
    post('/api/logout', {}).finally(() => {
      sessionStorage.clear();
      location.href = '/login';
    });
  }

  function sevFromLevel(lvl) {
    const n = parseInt(lvl) || 0;
    if (n >= 12) return 'critical';
    if (n >= 8)  return 'high';
    if (n >= 5)  return 'medium';
    return 'low';
  }

  function relTs(ts) {
    if (!ts) return '—';
    const s = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
    if (s < 0)     return 'just now';
    if (s < 60)    return `${s}s ago`;
    const m = Math.round(s / 60);
    if (m < 60)    return `${m}m ago`;
    const h = Math.round(m / 60);
    if (h < 24)    return `${h}h ago`;
    return `${Math.round(h / 24)}d ago`;
  }

  // Show a small badge in the corner when running in demo mode so it's
  // obvious the data is mocked.
  function injectDemoBadge() {
    if (!isDemo()) return;
    if (document.getElementById('soc-demo-badge')) return;
    const onReady = () => {
      const el = document.createElement('div');
      el.id = 'soc-demo-badge';
      el.title = 'SOC_API is in demo mode — pages show baked-in FALLBACK data. Log in to use the real backend.';
      el.innerHTML = '<span class="soc-demo-pip"></span> DEMO MODE · NO BACKEND';
      el.style.cssText = [
        'position:fixed','top:12px','right:14px','z-index:10000',
        'padding:4px 10px','border-radius:14px',
        'background:rgba(255,152,0,.12)','border:1px solid rgba(255,152,0,.45)',
        'color:#ffb74d','font:9.5px/1.4 ui-monospace,Menlo,monospace','letter-spacing:1.2px',
        'display:flex','align-items:center','gap:6px','pointer-events:auto','cursor:help',
        'backdrop-filter:blur(8px)','-webkit-backdrop-filter:blur(8px)',
      ].join(';');
      el.querySelector('.soc-demo-pip').style.cssText =
        'width:6px;height:6px;border-radius:50%;background:#ff9800;box-shadow:0 0 6px #ff9800;animation:soc-demo-pulse 1.6s ease-in-out infinite';
      const styleEl = document.createElement('style');
      styleEl.textContent = '@keyframes soc-demo-pulse{0%,100%{opacity:1}50%{opacity:.3}}';
      document.head.appendChild(styleEl);
      document.body.appendChild(el);
    };
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', onReady, { once: true });
    } else {
      onReady();
    }
  }
  injectDemoBadge();

  window.SOC_API = {
    get, post, put, patch, del, delete: del,
    stream, logout, user, isDemo,
    sevFromLevel, relTs,
  };
})();

// ── Splash progress engine ──────────────────────────────────────────────────
(function () {
  const PHASES = [
    { at:  0, label: 'Initializing security engine…' },
    { at: 12, label: 'Loading threat intelligence…'  },
    { at: 25, label: 'Compiling detection modules…'  },
    { at: 40, label: 'Loading MITRE ATT&CK framework…' },
    { at: 55, label: 'Connecting to SIEM…'           },
    { at: 68, label: 'Loading analytics pipeline…'   },
    { at: 80, label: 'Compiling response modules…'   },
    { at: 90, label: 'Preparing command center…'     },
  ];

  const barEl  = document.getElementById('sp-bar');
  const pctEl  = document.getElementById('sp-pct');
  const stEl   = document.getElementById('sp-status');
  let current  = 0;
  let target   = 0;
  let rafId    = null;

  function setLabel(pct) {
    const phase = [...PHASES].reverse().find(p => pct >= p.at);
    if (phase && stEl) stEl.textContent = phase.label;
  }

  function render() {
    current += (target - current) * 0.07;
    if (Math.abs(target - current) < 0.05) current = target;
    const v = Math.min(100, current);
    if (barEl) barEl.style.width = v + '%';
    if (pctEl) pctEl.textContent = Math.floor(v) + '%';
    setLabel(v);
    if (current < target) rafId = requestAnimationFrame(render);
    else rafId = null;
  }

  function advance(pct) {
    target = Math.max(target, Math.min(100, pct));
    if (!rafId) { rafId = requestAnimationFrame(render); }
  }

  // Timed ramp: 0→92% over ~5 s with non-linear easing so it looks real.
  // keyframes: [time_ms, pct]
  const RAMP = [[0,0],[400,18],[900,32],[1600,48],[2500,62],[3400,74],[4300,84],[5200,92]];
  const t0 = performance.now();
  let ri = 0;
  function rampTick() {
    const elapsed = performance.now() - t0;
    while (ri < RAMP.length && elapsed >= RAMP[ri][0]) {
      advance(RAMP[ri][1]);
      ri++;
    }
    if (ri < RAMP.length) requestAnimationFrame(rampTick);
  }
  requestAnimationFrame(rampTick);

  // Called by App's useEffect after first React render
  window._spDone = function () {
    advance(100);
    // Wait for bar animation to finish, then fade out
    setTimeout(function () {
      const splash = document.getElementById('splash');
      if (!splash) return;
      splash.classList.add('sp-fade');
      setTimeout(function () { splash.remove(); }, 520);
    }, 350);
  };
})();
