"""
ExecutorAgent — Autonomously executes planned Dark SOC actions.

Calls the webapp playbook engine which already implements all 6 action types.
Only executes actions that passed the safety gate.
"""
import time
import logging
from typing import Dict, Any

from ..state import InvestigationState
from ..tools import tool_execute_playbook, tool_create_case

log = logging.getLogger(__name__)


def executor_node(state: InvestigationState) -> Dict[str, Any]:
    """Execute all safety-approved actions in priority order."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    inv_id = state.get("investigation_id") or 0
    actions = state.get("planned_actions", []) or []
    safety_blocks = state.get("safety_blocks", []) or []
    blocked_types = {b.get("action_type") for b in safety_blocks}

    executed = []
    failed = []
    case_id = None
    fp_prob = state.get("triage_fp_probability", 50) / 100.0
    report_excerpt = state.get("final_report", "")[:1500] if state.get("final_report") else ""

    # Sort by priority (1 = highest)
    sorted_actions = sorted(actions, key=lambda a: a.get("priority", 5))

    for action in sorted_actions:
        atype = action.get("type")
        if atype in blocked_types:
            failed.append({
                "type": atype, "target": action.get("target"),
                "error": "blocked by safety gate", "blocked": True,
            })
            continue

        try:
            if atype == "create_case":
                result = tool_create_case(alert, inv_id, report_excerpt)
                if result.get("case_id") or result.get("id"):
                    case_id = result.get("case_id") or result.get("id")
                    executed.append({"type": atype, "target": action.get("target"),
                                      "result": result, "timestamp": time.time()})
                else:
                    failed.append({"type": atype, "error": result.get("error", "unknown")})
            else:
                result = tool_execute_playbook(atype, alert, inv_id, report_excerpt, fp_prob)
                if result.get("ok") or result.get("success") or result.get("executed"):
                    executed.append({"type": atype, "target": action.get("target"),
                                      "result": result, "timestamp": time.time()})
                    log.info(f"[executor] ✓ {atype} on {action.get('target')}")
                else:
                    failed.append({"type": atype, "target": action.get("target"),
                                    "error": result.get("error", "unknown")})
                    log.warning(f"[executor] ✗ {atype}: {result.get('error')}")
        except Exception as e:
            log.error(f"[executor] {atype} crashed: {e}")
            failed.append({"type": atype, "target": action.get("target"),
                            "error": str(e)[:200]})

    log.info(f"[executor] executed={len(executed)} failed={len(failed)} blocked={len(blocked_types)}")
    return {
        "executed_actions": executed,
        "failed_actions": failed,
        "case_id": case_id,
        "node_trace": [{
            "node": "executor",
            "executed_count": len(executed),
            "failed_count": len(failed),
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }
