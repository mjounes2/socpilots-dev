# MITRE-COVERAGE.md — ATT&CK Coverage Module

## Overview

The ATT&CK Coverage module provides an interactive heatmap of SOCPilots' detection coverage against the MITRE ATT&CK Enterprise framework. Coverage is derived in real-time from Wazuh/OpenSearch alert data.

**Navigation:** Sidebar → ATT&CK Coverage (`go('mitre')`)

---

## Coverage Levels

| Level | Alert Count | Cell Color | Meaning |
|---|---|---|---|
| **High** | ≥ 10 | Green `#00c853` | Frequent active detections — strong coverage |
| **Medium** | 3–9 | Amber `#ffc107` | Some detections — partial coverage |
| **Low** | 1–2 | Orange `#ff6d00` | Rare detections — weak coverage |
| **None** | 0 | Dark gray | No detections for this technique in timeframe |

---

## Framework Data

### Tactics (14 Enterprise Tactics)

| ID | Name | Display |
|---|---|---|
| TA0043 | Reconnaissance | Column 1 |
| TA0042 | Resource Development | Column 2 |
| TA0001 | Initial Access | Column 3 |
| TA0002 | Execution | Column 4 |
| TA0003 | Persistence | Column 5 |
| TA0004 | Privilege Escalation | Column 6 |
| TA0005 | Defense Evasion | Column 7 |
| TA0006 | Credential Access | Column 8 |
| TA0007 | Discovery | Column 9 |
| TA0008 | Lateral Movement | Column 10 |
| TA0009 | Collection | Column 11 |
| TA0010 | Exfiltration | Column 12 |
| TA0011 | Command & Control | Column 13 |
| TA0040 | Impact | Column 14 |

### Techniques

**~190 parent Enterprise techniques** are hardcoded in `MITRE_TECHS` constant in `index.html`. Each entry: `[id, name, [tactic_ids...]]`.

Multi-tactic techniques appear in ALL relevant columns (e.g., T1078 Valid Accounts appears in Initial Access, Persistence, Privilege Escalation, Defense Evasion).

---

## Backend API

### GET /api/mitre/coverage

```
Query: ?timeframe=24h|7d|30d|90d (default: 7d)
Auth: Any authenticated user
Cache: 30s in-memory, keyed by timeframe

Response:
{
  "coverage": {
    "T1059": {
      "count": 450,
      "max_level": 12,
      "rules": ["100200", "100201"],
      "agents": ["web-server-01", "dc-01"],
      "tactics": ["execution"],
      "last_seen": 1716484800000
    },
    "T1110": { ... }
  },
  "timeframe": "7d"
}
```

OpenSearch query: terms aggregation on `rule.mitre.id`, size 500, with sub-aggs for rules (top 20), agents (top 20), tactics (top 5), max_level, last_seen.

### GET /api/mitre/technique/:id

```
Query: ?timeframe=24h|7d|30d|90d (default: 7d)
Auth: Any authenticated user
No cache (drill-down queries are user-triggered, not polling)

Response:
{
  "technique": "T1059",
  "timeframe": "7d",
  "total": 450,
  "recent_alerts": [
    { "id": "...", "timestamp": "...", "agent": "...", "rule": "...", "description": "...", "level": 12 }
  ],
  "rules": [
    { "id": "100200", "description": "...", "count": 200, "level": 12 }
  ],
  "agents": [{ "name": "web-server-01", "count": 300 }],
  "decoders": ["pam", "syslog"],
  "tactics": ["execution"],
  "timeline": [
    { "date": "2026-05-05", "count": 45 }
  ]
}
```

---

## Frontend Implementation

### Key JS State

```javascript
let _mitreCovData = null;  // {techId: {count, max_level, rules[], agents[], tactics[], last_seen}}
let _mitreTf = '7d';       // Active timeframe filter
let _mitreLoaded = false;  // Has data been loaded at least once?
```

### Key Functions

| Function | Purpose |
|---|---|
| `loadMitre()` | Fetch coverage data, update stats KPIs, populate tactic filter, render matrix |
| `applyMitreFilters()` | Re-render matrix after coverage level or tactic filter changes |
| `renderMitreMatrix()` | Build 14-column HTML heatmap from `MITRE_TECHS` + `_mitreCovData` |
| `mitreGetCovLevel(techId)` | Returns `'high'|'medium'|'low'|'none'` based on alert count |
| `mitreShowTech(id, name)` | Fetch drill-down data, open modal with KPIs/timeline/agents/rules |
| `mitreExportNav()` | Generate MITRE Navigator 4.9 JSON and trigger browser download |
| `loadMitreDash()` | Dashboard widget function (calls `/api/stats/mitre` — different from `loadMitre()`) |

**Important naming distinction:** `loadMitre()` is the coverage page function. `loadMitreDash()` is the dashboard mini-widget function. They call different endpoints and must not be confused.

### Matrix Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│ [Recon] [ResDev] [InitAccess] [Exec] [Persist] [PrivEsc] [DefEva] ... │
│ ┌─────┐ ┌─────┐  ┌─────────┐                                           │
│ │T1595│ │T1583│  │T1189    │                                           │
│ │green│ │dark │  │amber    │                                           │
│ │ 45  │ │  0  │  │  3      │                                           │
│ └─────┘ └─────┘  └─────────┘                                           │
│  ...                                                                    │
└─────────────────────────────────────────────────────────────────────────┘
  ← horizontal scroll for 14 columns →
```

Matrix container: `.mitre-matrix-wrap` (overflow-x: auto) → `.mitre-matrix` (display: flex, min-width: max-content)

### Navigator Export Format

Exports valid MITRE ATT&CK Navigator 4.9 layer JSON:
- File: `socpilots-attck-coverage-{timeframe}-{date}.json`
- Format: Navigator layer spec with techniques, scores, colors, gradient, legend
- Import directly at `https://mitre-attack.github.io/attack-navigator/`

---

## OpenSearch MITRE Fields

Wazuh indexes MITRE data into these fields:
- `rule.mitre.id` — technique IDs (e.g., `["T1059", "T1059.001"]`)
- `rule.mitre.tactic` — tactic names (e.g., `["execution"]`)
- `rule.mitre.technique` — technique names (e.g., `["Command and Scripting Interpreter"]`)

Only parent technique IDs (e.g., `T1059`) are aggregated in the coverage query — not sub-technique IDs (e.g., `T1059.001`). This maps correctly to the `MITRE_TECHS` constant which uses parent IDs only.

---

## Coverage Improvement Workflow

1. Open ATT&CK Coverage page
2. Set timeframe to 30d for full picture
3. Filter by "No Coverage" to see gaps
4. For each critical gap technique:
   - Click cell → drill-down modal → check if any rules exist
   - If no rules: go to Create Rules → generate detection rule for that technique
   - If rules exist but no alerts: check if rule is properly mapped in Wazuh
5. Export Navigator JSON to share coverage status with team

---

*See also: `CLAUDE.md` sections 11, `docs/AI-ENGINE.md`*
