// SOC Pilots — centralised API layer (auth-aware)
// Loaded before all page files; exposes window.SOC_API

(function () {
  const tok  = () => sessionStorage.getItem('soc_token');
  const user = () => ({ username: sessionStorage.getItem('soc_user'), role: sessionStorage.getItem('soc_role') });

  function redir() {
    if (!location.pathname.startsWith('/login')) location.href = '/login';
  }

  function authHeaders() {
    return { Authorization: `Bearer ${tok()}`, 'Content-Type': 'application/json' };
  }

  async function get(url) {
    if (!tok()) { redir(); return null; }
    try {
      const r = await fetch(url, { headers: { Authorization: `Bearer ${tok()}` } });
      if (r.status === 401) { redir(); return null; }
      if (!r.ok) return null;
      return r.json();
    } catch { return null; }
  }

  async function post(url, body) {
    if (!tok()) { redir(); return null; }
    try {
      const r = await fetch(url, { method: 'POST', headers: authHeaders(), body: JSON.stringify(body) });
      if (r.status === 401) { redir(); return null; }
      const json = await r.json().catch(() => ({}));
      if (!r.ok) return { error: json.error || 'Request failed', status: r.status };
      return json;
    } catch { return null; }
  }

  async function del(url) {
    if (!tok()) { redir(); return null; }
    try {
      const r = await fetch(url, { method: 'DELETE', headers: { Authorization: `Bearer ${tok()}` } });
      if (r.status === 401) { redir(); return null; }
      return r.ok ? { ok: true } : null;
    } catch { return null; }
  }

  // SSE streaming for AI chat — calls onChunk(fullText) as tokens arrive, onDone(fullText) at end
  async function stream(url, body, onChunk, onDone) {
    if (!tok()) { redir(); onDone(''); return; }
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
        buf = lines.pop(); // keep incomplete last line
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
            // plain-text chunk (LangChain SSE fallback)
            if (j.response && !full) { full = j.response; onChunk(full); onDone(full); return; }
          } catch {
            // plain text token
            if (raw && raw !== '[DONE]') { full += raw; onChunk(full); }
          }
        }
      }
      onDone(full);
    } catch (e) {
      onDone(full || 'Connection error');
    }
  }

  async function put(url, body) {
    if (!tok()) { redir(); return null; }
    try {
      const r = await fetch(url, { method: 'PUT', headers: authHeaders(), body: JSON.stringify(body) });
      if (r.status === 401) { redir(); return null; }
      const json = await r.json().catch(() => ({}));
      if (!r.ok) return { error: json.error || 'Request failed', status: r.status };
      return json;
    } catch { return null; }
  }

  async function patch(url, body) {
    if (!tok()) { redir(); return null; }
    try {
      const r = await fetch(url, { method: 'PATCH', headers: authHeaders(), body: JSON.stringify(body) });
      if (r.status === 401) { redir(); return null; }
      const json = await r.json().catch(() => ({}));
      if (!r.ok) return { error: json.error || 'Request failed', status: r.status };
      return json;
    } catch { return null; }
  }

  // Logout helper
  function logout() {
    post('/api/logout', {}).finally(() => {
      sessionStorage.clear();
      location.href = '/login';
    });
  }

  // Severity helper (matches backend)
  function sevFromLevel(lvl) {
    const n = parseInt(lvl) || 0;
    if (n >= 12) return 'critical';
    if (n >= 8)  return 'high';
    if (n >= 5)  return 'medium';
    return 'low';
  }

  // Relative time helper
  function relTs(ts) {
    if (!ts) return '—';
    const s = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
    if (s < 0) return 'just now';
    if (s < 60) return `${s}s ago`;
    const m = Math.round(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.round(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.round(h / 24)}d ago`;
  }

  window.SOC_API = { get, post, put, patch, del, stream, logout, user, sevFromLevel, relTs };
})();
