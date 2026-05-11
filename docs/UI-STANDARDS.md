# UI-STANDARDS.md — SOCPilots Frontend Design System

## Design Philosophy

SOCPilots uses a **dark-theme glassmorphism** design system. All UI is rendered in a single vanilla JS SPA (`Socpilots/frontend/index.html`) with no build step, no CSS preprocessor, and no UI framework. Consistency depends entirely on following these standards.

---

## CSS Custom Properties (Design Tokens)

```css
:root {
  /* Primary palette */
  --c:    #00e5ff;                    /* Cyan — primary accent, interactive elements */
  --c2:   #00b8d4;                    /* Cyan dark — hover states */
  --cdim: rgba(0,229,255,.1);         /* Cyan dim — subtle backgrounds */
  --g:    #00e676;                    /* Green — success, active, healthy */
  --r:    #ff1744;                    /* Red — critical, error, danger */
  --rdim: rgba(255,23,68,.1);
  --o:    #ff9800;                    /* Orange — high severity */
  --y:    #ffc107;                    /* Yellow — medium severity, warning */
  --p:    #d500f9;                    /* Purple — special states */

  /* Background layers */
  --bg:   #0a1628;                    /* Base background */
  --bg2:  #0f1e35;                    /* Elevated surfaces */

  /* Border layers */
  --b1:   #1a2f4a;                    /* Subtle border */
  --b2:   #244060;                    /* Standard border */
  --b3:   #2e5070;                    /* Prominent border */

  /* Text hierarchy */
  --txt:  #e8f4fd;                    /* Primary text */
  --txt2: #8ab0d0;                    /* Secondary text / labels */
  --txt3: #4a6f8a;                    /* Muted text / placeholders */
  --txt4: #2a4f6a;                    /* Disabled text */

  /* Typography */
  --fw: 'Exo 2', 'Rajdhani', sans-serif;         /* Display / headings */
  --fm: 'Share Tech Mono', 'Courier New', monospace; /* Data / IDs / counts */

  /* Geometry */
  --r3: 6px;   /* Standard border radius */
}
```

---

## Typography Scale

| Class / Use | Font | Size | Weight | Use For |
|---|---|---|---|---|
| Page title (`.ph h1`) | `--fw` | 24px | 700 | Page header |
| Card title (`.card-ttl`) | `--fw` | 13px | 600 | Section header |
| KPI value (`.kpi-val`) | `--fw` | 32px | 700 | Big metric |
| KPI label (`.kpi-lbl`) | `--fm` | 9px | 400 | Metric label |
| Table cell | `--fm` or body | 11–12px | 400 | Data |
| Badge text | `--fm` | 8–10px | 600 | Tags / levels |
| Sidebar label (`.sbi-lbl`) | `--fw` | 11px | 500 | Nav |

---

## Component Patterns

### KPI Stats Cards

```html
<!-- Grid of 5 KPI cards -->
<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:12px">
  <div class="kpi cl"><div class="kpi-lbl">Total</div><div class="kpi-val" id="s-total">—</div><div class="kpi-sub">description</div></div>
  <div class="kpi cg">...</div>  <!-- green -->
  <div class="kpi cr">...</div>  <!-- red -->
  <div class="kpi co">...</div>  <!-- orange -->
  <div class="kpi cp">...</div>  <!-- purple -->
</div>
```

KPI color classes: `.cl` (cyan), `.cg` (green), `.cr` (red), `.co` (orange), `.cp` (purple)

### Cards

```html
<div class="card">
  <div class="card-hd">
    <div class="card-ttl">SECTION TITLE</div>
    <div style="font-family:var(--fm);font-size:10px;color:var(--txt3)">subtitle</div>
  </div>
  <!-- content -->
</div>

<!-- Card with no padding (for tables) -->
<div class="card" style="padding:0">
  <div class="card-hd">...</div>
  <div class="tbl"><table>...</table></div>
</div>
```

### Tables

```html
<div class="tbl">
  <table>
    <thead>
      <tr><th>Col 1</th><th>Col 2</th><th>Severity</th></tr>
    </thead>
    <tbody>
      <tr>
        <td style="font-family:var(--fm);color:var(--c)">ID-123</td>
        <td>${esc(value)}</td>
        <td><span class="badge ${sbadge(severity)}">${level}</span></td>
      </tr>
    </tbody>
  </table>
</div>
```

### Severity Badges

```javascript
// sbadge(severity) returns CSS class
'critical' → 'critical'  // red
'high'     → 'high'       // orange
'medium'   → 'med'        // yellow
'low'      → 'low'        // cyan
'ok'       → 'ok'         // green
```

```html
<span class="badge critical">15</span>
<span class="badge high">12</span>
<span class="badge med">8</span>
<span class="badge low">4</span>
<span class="badge ok">Active</span>
```

### Buttons

```html
<button class="btn btn-p">Primary Action</button>      <!-- cyan fill -->
<button class="btn btn-h">Cancel / Secondary</button>  <!-- ghost -->
<button class="btn btn-sm">Small Action</button>       <!-- compact -->
<button class="btn btn-p btn-sm">Small Primary</button>
```

### Filter Panel

```html
<div class="card" style="padding:12px;margin-bottom:12px">
  <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
    <input class="fi" style="width:200px" placeholder="Search..." id="q" oninput="searchDebounce()">
    <select class="fi" id="f-sev" onchange="applyFilters()" style="width:130px">
      <option value="">All Severities</option>
      <option value="critical">Critical</option>
    </select>
    <button class="btn btn-p btn-sm" onclick="loadData()" style="margin-left:auto">↻ Refresh</button>
  </div>
</div>
```

### Modals

```html
<div class="modal-ov" id="modal-NAME">
  <div class="modal" style="width:560px">
    <div class="modal-hd">
      <div class="modal-ttl">Modal Title</div>
      <button class="modal-x" onclick="closeModal('modal-NAME')">✕</button>
    </div>
    <div class="modal-body">
      <!-- content -->
    </div>
    <div class="modal-ft">
      <button class="btn btn-h" onclick="closeModal('modal-NAME')">Cancel</button>
      <button class="btn btn-p" onclick="submitAction()">Confirm</button>
    </div>
  </div>
</div>
```

### Form Controls

```html
<div class="fg">
  <label class="fl">Field Label</label>
  <input class="fi" id="field-id" placeholder="placeholder">
</div>
<div class="fg">
  <label class="fl">Dropdown</label>
  <select class="fs" id="sel-id">
    <option value="opt1">Option 1</option>
  </select>
</div>
<div class="fg">
  <label class="fl">Textarea</label>
  <textarea class="fta" id="ta-id" rows="4" placeholder="..."></textarea>
</div>
```

---

## Page Header Pattern

```html
<div class="ph">
  <h1>PAGE TITLE</h1>
  <p>Subtitle describing what this page shows</p>
</div>
```

---

## Loading / Empty / Error States

```javascript
// Always use these helpers — never custom loading HTML
spin('Loading data...')     // → animated spinner + text
empty('No results found')   // → centered empty state message
errBnr('Error message')     // → red error banner
```

---

## MITRE ATT&CK Coverage Matrix Styles

See `CLAUDE.md` section 11 and `docs/MITRE-COVERAGE.md` for the matrix-specific CSS classes: `.mitre-matrix`, `.mitre-col`, `.mitre-cell`, `.mc-high`, `.mc-medium`, `.mc-low`, `.mc-none`.

---

## Glassmorphism Card Pattern

For premium cards with glow effect:
```html
<div style="
  background: rgba(15,30,53,.85);
  border: 1px solid rgba(0,229,255,.15);
  border-radius: 12px;
  backdrop-filter: blur(10px);
  box-shadow: 0 8px 32px rgba(0,0,0,.4), inset 0 1px 0 rgba(255,255,255,.05);
  padding: 20px;
">
```

---

## Accessibility Notes

- All interactive elements have visible focus states
- Severity colors supplemented by text labels (not color-only)
- Contrast ratios: primary text (#e8f4fd on #0a1628) meets WCAG AA
- Modal overlays trap focus — `closeModal()` restores it

---

*All CSS lives in the single `<style>` block in `Socpilots/frontend/index.html`. No external stylesheets.*
