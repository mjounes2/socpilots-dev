// ============================================================
//  SOCPilots — Dark SOC Playbook Execution Engine
//
//  Runs automated response actions with zero analyst interaction.
//
//  Security gates (applied in order):
//    1. FP probability check   — skip destructive action if FP too likely
//    2. Consensus validation   — second LLM must agree for host isolation
//    3. Audit logging          — every action stored in playbook_executions
//
//  Response actions available:
//    block_ip       → Wazuh MCP: wazuh_block_ip
//    isolate_host   → Wazuh MCP: wazuh_isolate_host   (requires consensus)
//    kill_process   → Wazuh MCP: wazuh_kill_process
//    disable_user   → Wazuh MCP: wazuh_disable_user   (requires consensus)
//    create_case    → TheHive: create case
//    close_case     → mark investigation as FP (no TheHive call needed)
// ============================================================

const axios = require('axios');
const https = require('https');
const db    = require('./db');
const email = require('./email-service');

const MCP_WAZUH_URL    = process.env.MCP_WAZUH_URL    || 'http://mcp-wazuh:3001';
const MCP_AUTH_SECRET  = process.env.MCP_AUTH_SECRET  || process.env.AUTH_SECRET_KEY || '';
const LANGCHAIN_URL    = process.env.LANGCHAIN_URL    || 'http://langchain-agent:8001';
const LANGCHAIN_TOKEN  = process.env.LANGCHAIN_INTERNAL_TOKEN || '';
const THEHIVE_URL      = (process.env.THEHIVE_URL     || '').replace(/\/$/, '');
const THEHIVE_KEY      = process.env.THEHIVE_API_KEY  || '';

const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// ── MCP Tool Caller ───────────────────────────────────────────
// Posts a JSON-RPC 2.0 tool call to the Wazuh MCP server
async function callWazuhMCP(toolName, args) {
  const payload = {
    jsonrpc: '2.0',
    id: Date.now(),
    method: 'tools/call',
    params: { name: toolName, arguments: args },
  };
  const headers = { 'Content-Type': 'application/json' };
  if (MCP_AUTH_SECRET) headers['Authorization'] = `Bearer ${MCP_AUTH_SECRET}`;

  const r = await axios.post(`${MCP_WAZUH_URL}/mcp`, payload, {
    headers, timeout: 30000, httpsAgent, validateStatus: () => true,
  });

  if (r.status >= 400) {
    throw new Error(`MCP HTTP ${r.status}: ${JSON.stringify(r.data).slice(0, 200)}`);
  }
  if (r.data?.error) {
    throw new Error(`MCP error: ${JSON.stringify(r.data.error).slice(0, 200)}`);
  }
  return r.data?.result ?? r.data;
}

// ── TheHive Case Creator ──────────────────────────────────────
async function createHiveCase(alert, severity = 'high', customTitle = null) {
  if (!THEHIVE_URL || !THEHIVE_KEY) return { skipped: true, reason: 'TheHive not configured' };

  const sevNum   = { low: 1, medium: 2, high: 3, critical: 4 }[severity] || 3;
  const title    = customTitle || `[DarkSOC] ${alert.description || 'Auto-detected threat'} — ${alert.agent || 'unknown'}`;
  const mitreTxt = Array.isArray(alert.mitre) && alert.mitre.length
    ? `\n\n**MITRE:** ${alert.mitre.join(', ')}`
    : '';

  const r = await axios.post(`${THEHIVE_URL}/api/v1/case`, {
    title,
    description: [
      `**Automated case created by Dark SOC engine**`,
      ``,
      `| Field | Value |`,
      `|---|---|`,
      `| Rule ID | ${alert.ruleId || '—'} |`,
      `| Level | ${alert.level || '—'} |`,
      `| Agent | ${alert.agent || '—'} |`,
      `| Source IP | ${alert.srcIp || '—'} |`,
      `| Severity | ${severity} |`,
      `| Timestamp | ${alert.timestamp || new Date().toISOString()} |`,
      mitreTxt,
    ].join('\n'),
    severity: sevNum,
    tags:   ['dark-soc', 'auto-response', `rule-${alert.ruleId}`, `agent-${alert.agent}`].filter(Boolean),
    tlp:    2,
    pap:    2,
    flag:   severity === 'critical',
  }, {
    headers: { Authorization: `Bearer ${THEHIVE_KEY}`, 'Content-Type': 'application/json' },
    httpsAgent, timeout: 15000,
  });

  return r.data;
}

// ── TheHive Case Creator (rich description) ───────────────────
// Used by UEBA/lateral monitor to pass a fully pre-built markdown description
async function createHiveCaseRich(alert, severity = 'high', title, description) {
  if (!THEHIVE_URL || !THEHIVE_KEY) return { skipped: true, reason: 'TheHive not configured' };
  const sevNum = { low: 1, medium: 2, high: 3, critical: 4 }[severity] || 3;
  const r = await axios.post(`${THEHIVE_URL}/api/v1/case`, {
    title:       title || `[DarkSOC] ${alert.description || 'Alert'} — ${alert.agent || 'unknown'}`,
    description: description || alert.description || '',
    severity:    sevNum,
    tags:        ['dark-soc', 'ueba', 'lateral-movement', `rule-${alert.ruleId}`, `agent-${alert.agent}`].filter(Boolean),
    tlp:         2,
    pap:         2,
    flag:        severity === 'critical',
  }, {
    headers: { Authorization: `Bearer ${THEHIVE_KEY}`, 'Content-Type': 'application/json' },
    httpsAgent, timeout: 15000,
  });
  return r.data;
}

// ── Consensus Validator ───────────────────────────────────────
// Calls /validate-action on LangChain agent — second LLM independently
// evaluates whether the destructive action is warranted.
async function validateWithConsensus(action, alert, evidence) {
  const headers = { 'Content-Type': 'application/json' };
  if (LANGCHAIN_TOKEN) headers['Authorization'] = `Bearer ${LANGCHAIN_TOKEN}`;

  const r = await axios.post(`${LANGCHAIN_URL}/validate-action`, {
    action, alert, evidence: (evidence || '').slice(0, 1500),
  }, { headers, timeout: 60000, httpsAgent });

  return r.data; // { approved: bool, confidence: float, reasoning: str }
}

// ── Process Name Extractor ────────────────────────────────────
// Tries to pull a process name from the investigation text
function extractProcessName(investigationText, alert) {
  if (!investigationText) return null;
  const patterns = [
    /suspicious[ly]?\s+process[:\s]+([^\s,\n"']+)/i,
    /process[:\s]+([^\s,\n"']+)/i,
    /malicious[ly]?\s+([^\s,\n"']+\.exe)/i,
    /command[:\s]+([^\s,\n"']+)/i,
  ];
  for (const pat of patterns) {
    const m = investigationText.match(pat);
    if (m?.[1] && m[1].length < 80) return m[1];
  }
  // fallback: use alert description first word as process hint
  const desc = alert?.description || '';
  const procMatch = desc.match(/process\s+([^\s,]+)/i);
  return procMatch?.[1] || null;
}

// ── Execute Single Action ─────────────────────────────────────
async function executeAction(action, alert, investigationText) {
  const result = { action: action.type, success: false, detail: '' };

  try {
    switch (action.type) {

      case 'block_ip': {
        if (!alert.srcIp) { result.detail = 'no srcIp in alert'; break; }
        const r = await callWazuhMCP('wazuh_block_ip', {
          ip:       alert.srcIp,
          duration: action.duration || 3600,
          reason:   `DarkSOC auto-block — Rule ${alert.ruleId}: ${alert.description}`,
        });
        result.success = true;
        result.detail  = `Blocked ${alert.srcIp} for ${action.duration || 3600}s`;
        result.raw     = JSON.stringify(r).slice(0, 300);
        break;
      }

      case 'isolate_host': {
        const agentRef = alert.agentId || alert.agent;
        if (!agentRef) { result.detail = 'no agent in alert'; break; }

        // ── Protected Asset Check ─────────────────────────────
        // Before isolating, check if this host is tagged as critical or protected.
        // Isolation of production hosts without human approval can cause outages.
        const protected_ = await db.getProtectedAsset(agentRef)
          .catch(() => null);

        // ── TIER: CRITICAL — NEVER auto-isolate ──────────────
        // Critical hosts (e.g. production DB, payment gateway) must never be
        // automatically isolated. Instead: block the attacker's source IP and
        // create a high-urgency TheHive case requiring human review.
        if (protected_?.tier === 'critical') {
          console.warn(`[Playbook] ⚠ CRITICAL HOST "${agentRef}" (${protected_.label}) — isolation BLOCKED. Escalating instead.`);
          result.action  = 'isolate_host_blocked_critical';
          result.success = false;
          result.skipped = true;
          result.detail  = `BLOCKED: "${agentRef}" is a CRITICAL protected host (${protected_.label || 'production system'}). Auto-isolation is NEVER permitted. Attacker IP blocked + human escalation case created.`;
          result.tier    = 'critical';

          // Alternative safe action: block the attacker source IP instead
          if (alert.srcIp) {
            try {
              await callWazuhMCP('wazuh_block_ip', {
                ip:       alert.srcIp,
                duration: 86400, // 24h block — gives humans time to respond
                reason:   `DarkSOC CRITICAL-HOST protection — attacker blocked instead of isolating ${agentRef}`,
              });
              result.detail += ` | Attacker ${alert.srcIp} blocked for 24h as safe alternative.`;
            } catch (blockErr) {
              result.detail += ` | Attacker IP block also failed: ${blockErr.message}`;
            }
          }

          // Create urgent TheHive case flagged for immediate human attention
          try {
            const urgentCase = await createHiveCase(
              { ...alert, description: `🚨 CRITICAL HOST RCE — HUMAN ACTION REQUIRED\n\nHost: ${agentRef} (${protected_.label || 'Critical Production System'})\nAttack: ${alert.description}\nIsolation was NOT performed (critical host protection).\n\nImmediate human decision required: manually isolate or contain.` },
              'critical',
              `[HUMAN-REVIEW] RCE on CRITICAL HOST ${agentRef} — Isolation Blocked`
            );
            result.hiveCaseId = urgentCase?.caseId || urgentCase?._id;
            result.detail    += ` | Urgent TheHive case #${result.hiveCaseId} created for human review.`;
          } catch (caseErr) {
            result.detail += ` | TheHive case creation failed: ${caseErr.message}`;
          }
          break;
        }

        // ── TIER: PROTECTED — require analyst approval first ──
        // Protected hosts (app servers, secondary DBs) can be isolated but only
        // after explicit analyst confirmation. A pending approval record is created
        // and the analyst has a configurable window (default 30 min) to decide.
        // The system auto-rejects after timeout to prevent indefinite holds.
        if (protected_?.tier === 'protected') {
          console.warn(`[Playbook] ⚠ PROTECTED HOST "${agentRef}" (${protected_.label}) — isolation requires approval.`);
          const timeoutMin = parseInt(await db.getSetting('isolation_approval_timeout_min').catch(()=>null) || '30');
          result.action  = 'isolate_host_pending_approval';
          result.success = false;
          result.pending = true;
          result.detail  = `APPROVAL REQUIRED: "${agentRef}" is a PROTECTED host (${protected_.label || ''}). Isolation queued — analyst has ${timeoutMin} min to approve or auto-rejects.`;
          result.tier    = 'protected';

          // Create TheHive case with explicit approval task
          let hiveCaseId = null;
          try {
            const pendingCase = await createHiveCase(
              { ...alert, description: `⏳ ISOLATION APPROVAL REQUIRED\n\nHost: ${agentRef} (${protected_.label || 'Protected Host'})\nAttack: ${alert.description}\n\nDark SOC engine wants to isolate this host but it is marked PROTECTED.\nAn analyst must approve or reject within ${timeoutMin} minutes.` },
              'high',
              `[APPROVAL NEEDED] Isolate PROTECTED host ${agentRef} — ${timeoutMin}min window`
            );
            hiveCaseId = pendingCase?.caseId || pendingCase?._id;
          } catch (caseErr) { /* non-fatal */ }

          // Create DB approval record (background worker polls and acts when approved)
          const approval = await db.createIsolationApproval({
            agent: agentRef, srcIp: alert.srcIp, alertData: alert,
            playbookName: action._playbookName || '',
            hiveCaseId: String(hiveCaseId || ''), timeoutMin,
          }).catch(() => null);

          // Send email notification for isolation approval needed
          if (approval) {
            const emailBody = email.generateIsolationApprovalEmail(approval, timeoutMin);
            await email.sendToRecipients(
              `[SOCPilots URGENT] Protected Asset Isolation Approval Needed: ${agentRef}`,
              emailBody
            ).catch(err => console.warn('[Playbook] Approval email send failed:', err.message));
          }

          result.approvalId = approval?.id;
          result.hiveCaseId = hiveCaseId;
          result.detail    += ` | Approval ID: ${approval?.id || 'N/A'} | TheHive case: #${hiveCaseId || 'N/A'}`;
          break;
        }

        // ── TIER: STANDARD (default) — auto-isolate as normal ─
        const r = await callWazuhMCP('wazuh_isolate_host', {
          agent_id: agentRef,
          reason:   `DarkSOC auto-isolate — Rule ${alert.ruleId}: ${alert.description}`,
        });
        result.success = true;
        result.detail  = `Isolated host ${agentRef}`;
        result.raw     = JSON.stringify(r).slice(0, 300);
        break;
      }

      case 'kill_process': {
        const procName = extractProcessName(investigationText, alert);
        if (!procName) { result.detail = 'process name not found in investigation'; break; }
        const agentRef = alert.agentId || alert.agent;
        if (!agentRef) { result.detail = 'no agent in alert'; break; }
        const r = await callWazuhMCP('wazuh_kill_process', {
          agent_id:     agentRef,
          process_name: procName,
          reason:       `DarkSOC auto-kill — Rule ${alert.ruleId}`,
        });
        result.success = true;
        result.detail  = `Killed process "${procName}" on ${agentRef}`;
        result.raw     = JSON.stringify(r).slice(0, 300);
        break;
      }

      case 'disable_user': {
        const user = alert.user || (investigationText || '').match(/user[:\s]+([^\s,\n"']+)/i)?.[1];
        if (!user) { result.detail = 'no username found'; break; }
        const r = await callWazuhMCP('wazuh_disable_user', {
          username: user,
          reason:   `DarkSOC auto-disable — Rule ${alert.ruleId}`,
        });
        result.success = true;
        result.detail  = `Disabled user "${user}"`;
        result.raw     = JSON.stringify(r).slice(0, 300);
        break;
      }

      case 'create_case': {
        const c = await createHiveCase(alert, action.severity || alert.severity || 'high');
        result.success = true;
        result.detail  = `Created TheHive case #${c.caseId || c._id || '?'}`;
        break;
      }

      case 'close_case': {
        // Logical close — marks in DB, no TheHive API needed
        result.success = true;
        result.detail  = `FP auto-close: ${action.reason || 'auto_fp'}`;
        break;
      }

      default:
        result.detail = `Unknown action type: "${action.type}"`;
    }
  } catch (e) {
    result.detail = e.message?.slice(0, 300) || 'unknown error';
    result.error  = true;
    console.error(`[Playbook] Action "${action.type}" error:`, e.message);
  }

  return result;
}

// ── Main: Run Playbook ────────────────────────────────────────
// Returns: { skipped, reason, consensusApproved, results[], actionsTaken }
async function runPlaybook(playbook, alert, investigationReport, fpProbability = 0) {
  const actions = Array.isArray(playbook.actions)
    ? playbook.actions
    : (() => { try { return JSON.parse(playbook.actions || '[]'); } catch { return []; } })();

  if (!actions.length) {
    return { skipped: true, reason: 'no_actions', results: [] };
  }

  const fpMax      = playbook.fp_confidence_max ?? 40;
  const results    = [];
  let   consensusApproved = null;

  // Identify destructive actions that require extra scrutiny
  const destructiveTypes  = ['isolate_host', 'disable_user', 'kill_process'];
  const hasDestructive    = actions.some(a => destructiveTypes.includes(a.type));

  // ── Consensus gate ───────────────────────────────────────────
  if (playbook.require_consensus && hasDestructive) {
    const destructiveAction = actions.find(a => destructiveTypes.includes(a.type));
    try {
      console.log(`[Playbook] ${playbook.name} → requesting consensus for "${destructiveAction.type}"...`);
      const validation = await validateWithConsensus(
        destructiveAction.type, alert, investigationReport
      );
      consensusApproved = validation?.approved === true;

      if (!consensusApproved) {
        const reason = validation?.reasoning?.slice(0, 120) || 'no reason given';
        console.log(`[Playbook] ${playbook.name} → consensus REJECTED: ${reason}`);
        return { skipped: true, reason: 'consensus_rejected', consensus: validation, results: [] };
      }
      console.log(`[Playbook] ${playbook.name} → consensus APPROVED (confidence: ${validation?.confidence})`);
    } catch (e) {
      console.warn(`[Playbook] ${playbook.name} → consensus check failed: ${e.message} — skipping`);
      return { skipped: true, reason: 'consensus_error', error: e.message, results: [] };
    }
  }

  // ── Execute actions ──────────────────────────────────────────
  for (const action of actions) {
    const isDestructive = destructiveTypes.includes(action.type) || action.type === 'block_ip';

    // FP safety gate per destructive action
    if (isDestructive && fpProbability > fpMax) {
      const r = {
        action:  action.type,
        success: false,
        detail:  `Skipped — FP probability ${fpProbability}% > threshold ${fpMax}%`,
      };
      results.push(r);
      console.log(`[Playbook] ${playbook.name} → ${action.type}: SKIPPED (FP=${fpProbability}%)`);
      continue;
    }

    const r = await executeAction(action, alert, investigationReport);
    results.push(r);
    console.log(`[Playbook] ${playbook.name} → ${action.type}: ${r.success ? '✓ OK' : '✗ FAIL'} — ${r.detail}`);

    // Send email notification for successful actions
    if (r.success && action.type !== 'create_case' && action.type !== 'close_case') {
      const assetRef = alert.agent || alert.agentId || alert.srcIp || 'unknown';
      const emailBody = email.generatePlaybookExecutionEmail(playbook.name, action.type, assetRef, r);
      await email.sendToRecipients(
        `[SOCPilots] Playbook Executed: ${playbook.name}`,
        emailBody
      ).catch(err => console.warn('[Playbook] Email send failed:', err.message));
    }
  }

  const actionsTaken = results.filter(r => r.success).map(r => r.action);
  return { skipped: false, consensusApproved, results, actionsTaken };
}

// ── Execute a deferred isolation (called when analyst approves) ───────────
// Used by the approval API route: POST /api/isolation-approvals/:id/approve
async function executeIsolationNow(approval) {
  const agentRef = approval.agent;
  try {
    const r = await callWazuhMCP('wazuh_isolate_host', {
      agent_id: agentRef,
      reason:   `DarkSOC approved-isolation — approved by ${approval.resolved_by || 'analyst'}: ${JSON.stringify(approval.alert_data?.description || '').slice(0,100)}`,
    });
    console.log(`[Playbook] ✓ Approved isolation executed for "${agentRef}"`);
    return { success: true, detail: `Isolated ${agentRef} after analyst approval`, raw: JSON.stringify(r).slice(0,200) };
  } catch (e) {
    console.error(`[Playbook] Approved isolation failed for "${agentRef}":`, e.message);
    return { success: false, detail: e.message };
  }
}

// ── Approval Expiry Worker (call from server.js setInterval every 2 min) ─
async function expireStaleApprovals() {
  try {
    const expired = await db.listExpiredApprovals();
    for (const appr of expired) {
      await db.resolveIsolationApproval(appr.id, {
        status: 'expired', resolvedBy: 'system',
        resolveNote: `Auto-expired after timeout. No isolation performed on ${appr.agent}.`,
      });
      console.log(`[Playbook] Approval #${appr.id} for "${appr.agent}" expired — isolation auto-rejected.`);
    }
  } catch (e) {
    console.warn('[Playbook] expireStaleApprovals error:', e.message);
  }
}

module.exports = { runPlaybook, callWazuhMCP, createHiveCase, createHiveCaseRich, executeIsolationNow, expireStaleApprovals };
