"""
ExecutorAgent — Dispatches planned Dark SOC actions.

Behavior depends on dynamic policy fetched from /api/autonomous/config:

  • Actions in `auto_execute_actions` list  → execute immediately (e.g. create_case)
  • Actions in `approval_actions` list      → create action_approvals entry,
                                                 do NOT execute, wait for human
  • Actions in neither list                  → blocked (unknown action)
  • Actions blocked by safety_gate           → recorded as failed

This gives operators a master ENABLE/DISABLE toggle on the engine itself
and per-action-type control over what is autonomous vs human-gated.
"""
import time
import logging
from typing import Dict, Any

from ..state import InvestigationState
from ..tools import (
    tool_execute_playbook, tool_create_case,
    tool_create_approval, tool_fetch_autonomous_config,
)

log = logging.getLogger(__name__)


def executor_node(state: InvestigationState) -> Dict[str, Any]:
    """Execute auto-allowed actions; route destructive actions to approval queue."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    inv_id = state.get("investigation_id") or 0
    actions = state.get("planned_actions", []) or []
    safety_blocks = state.get("safety_blocks", []) or []
    blocked_types = {b.get("action_type") for b in safety_blocks}

    # Dynamic policy — operator-controlled via settings
    cfg = tool_fetch_autonomous_config()
    auto_set     = set(cfg.get("auto_execute_actions", []) or [])
    approval_set = set(cfg.get("approval_actions", []) or [])

    executed = []
    failed = []
    pending_approvals = []
    case_id = None
    fp_prob = state.get("triage_fp_probability", 50) / 100.0
    report_excerpt = state.get("final_report", "")[:1500] if state.get("final_report") else ""

    # Priority order: 1 = highest
    sorted_actions = sorted(actions, key=lambda a: a.get("priority", 5))

    for action in sorted_actions:
        atype = action.get("type")
        target = action.get("target", "")
        reason = action.get("reason", "")
        confidence = float(action.get("confidence", 0.0))

        # Safety gate veto always wins
        if atype in blocked_types:
            failed.append({
                "type": atype, "target": target,
                "error": "blocked by safety gate", "blocked": True,
            })
            continue

        # Route by policy
        if atype in approval_set:
            # Destructive action → queue for human approval (do NOT execute)
            result = tool_create_approval(
                investigation_id=inv_id,
                alert=alert,
                action_type=atype,
                target=target,
                reason=reason,
                confidence=confidence,
                fp_probability=state.get("triage_fp_probability", 50),
                summary=f"AI recommends {atype} on {target}: {reason}",
            )
            if result.get("approval_id"):
                pending_approvals.append({
                    "type":         atype,
                    "target":       target,
                    "reason":       reason,
                    "approval_id":  result["approval_id"],
                    "expires_at":   result.get("expires_at"),
                    "status":       "pending_approval",
                })
                log.info(f"[executor] → approval queued: {atype} on {target} (id={result['approval_id']})")
            else:
                failed.append({
                    "type": atype, "target": target,
                    "error": f"approval queue failed: {result.get('error', 'unknown')}",
                })

        elif atype in auto_set:
            # Safe action — execute immediately
            try:
                if atype == "create_case":
                    result = tool_create_case(alert, inv_id, report_excerpt)
                    if result.get("case_id") or result.get("id"):
                        case_id = result.get("case_id") or result.get("id")
                        executed.append({"type": atype, "target": target,
                                          "result": result, "timestamp": time.time()})
                    else:
                        failed.append({"type": atype, "error": result.get("error", "unknown")})
                else:
                    result = tool_execute_playbook(atype, alert, inv_id, report_excerpt, fp_prob)
                    if result.get("ok") or result.get("success") or result.get("executed"):
                        executed.append({"type": atype, "target": target,
                                          "result": result, "timestamp": time.time()})
                        log.info(f"[executor] ✓ {atype} on {target} (auto)")
                    else:
                        failed.append({"type": atype, "target": target,
                                        "error": result.get("error", "unknown")})
                        log.warning(f"[executor] ✗ {atype}: {result.get('error')}")
            except Exception as e:
                log.error(f"[executor] {atype} crashed: {e}")
                failed.append({"type": atype, "target": target, "error": str(e)[:200]})

        else:
            # Unknown action — refuse for safety
            failed.append({
                "type": atype, "target": target,
                "error": f"action '{atype}' not in auto_execute or approval policy — refused",
            })
            log.warning(f"[executor] refused unknown action: {atype}")

    log.info(f"[executor] executed={len(executed)} pending_approval={len(pending_approvals)} "
              f"failed={len(failed)} safety_blocked={len(blocked_types)}")
    return {
        "executed_actions":   executed,
        "failed_actions":     failed,
        "pending_approvals":  pending_approvals,
        "case_id":            case_id,
        "node_trace": [{
            "node": "executor",
            "executed_count":         len(executed),
            "pending_approval_count": len(pending_approvals),
            "failed_count":           len(failed),
            "duration_ms":            int((time.time() - start) * 1000),
        }],
    }
