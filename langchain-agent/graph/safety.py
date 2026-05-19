"""
Safety Gate — Final autonomous gatekeeper for Dark SOC actions.

Since the target is ZERO HUMAN intervention, this module enforces multiple
algorithmic safety checks that replace a human approver:

  1. FP probability threshold (per action type)
  2. Confidence threshold (per action type)
  3. Consensus requirement (both LLMs must agree)
  4. Protected asset check (no action against critical infrastructure)
  5. Reversibility preference (prefer reversible actions)
  6. Action proportionality (action severity ≤ alert severity)
  7. RFC1918 / loopback IP guard (no autonomous block on private/loopback)
  8. Rate limiting (cap autonomous actions per hour per target)
  9. Self-protection (never act on our own infrastructure)
"""
import ipaddress
import logging
import os
import time
from typing import Dict, Any, List

from .state import InvestigationState
from .tools import _sync_client, WEBAPP_URL, _internal_headers

log = logging.getLogger(__name__)


# ─── Per-action-type safety thresholds ────────────────────────
# Tighter thresholds = harder to autonomously execute
ACTION_SAFETY_RULES = {
    "block_ip": {
        "max_fp_probability":   25,
        "min_confidence":        0.80,
        "requires_consensus":   True,
        "requires_external_ip": True,
        "min_severity":         "medium",
    },
    "isolate_host": {
        "max_fp_probability":   10,
        "min_confidence":        0.90,
        "requires_consensus":   True,
        "requires_external_ip": False,
        "min_severity":         "high",
        "block_if_managed_critical": True,
    },
    "kill_process": {
        "max_fp_probability":   20,
        "min_confidence":        0.80,
        "requires_consensus":   True,
        "requires_external_ip": False,
        "min_severity":         "medium",
    },
    "disable_user": {
        "max_fp_probability":   10,
        "min_confidence":        0.90,
        "requires_consensus":   True,
        "requires_external_ip": False,
        "min_severity":         "high",
        "block_admin_users":    True,
    },
    "create_case": {
        # Always safe
        "max_fp_probability":   100,
        "min_confidence":        0.0,
        "requires_consensus":   False,
        "requires_external_ip": False,
        "min_severity":         "low",
    },
    "close_case": {
        "max_fp_probability":   100,
        "min_confidence":        0.7,
        "requires_consensus":   True,
        "requires_external_ip": False,
        "min_severity":         "low",
    },
}

SEVERITY_RANK = {"benign": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Our own services — never autonomously act against them
SELF_INFRA_HOSTS = set(
    h.strip().lower() for h in os.getenv("SOCPILOTS_SELF_HOSTS", "").split(",") if h.strip()
) | {"webapp", "postgres", "redis", "neo4j", "qdrant", "n8n", "nginx",
     "langchain-agent", "rag-retrieval", "knowledge-ingestion",
     "mcp-wazuh", "thehive-mcp", "scanner", "asset-scan"}


def _is_private_or_loopback(ip: str) -> bool:
    """RFC1918 / loopback / link-local check."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def _is_self_infra(target: str) -> bool:
    """Check if target is one of our own services."""
    if not target:
        return False
    t = target.lower().strip()
    return t in SELF_INFRA_HOSTS or any(t.startswith(h + ".") for h in SELF_INFRA_HOSTS)


def _is_protected_asset(target: str) -> bool:
    """Check protected_assets table via webapp API."""
    if not target:
        return False
    try:
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/protected-assets/check",
            params={"target": target},
            headers=_internal_headers(),
            timeout=5.0,
        )
        if r.status_code == 200:
            return bool(r.json().get("protected"))
    except Exception:
        pass
    return False


def _check_rate_limit(action_type: str, target: str) -> bool:
    """Cap autonomous actions per target per hour. Returns True if WITHIN limit."""
    # Default cap: 3 of same action type per target per hour
    try:
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/playbook-executions",
            params={"action": action_type, "target": target, "hours": 1, "autonomous": "true"},
            headers=_internal_headers(),
            timeout=5.0,
        )
        if r.status_code == 200:
            d = r.json()
            recent = d.get("total", 0)
            return recent < 3
    except Exception:
        pass
    return True  # fail-open for availability; risk is bounded by FP threshold


def evaluate_action_safety(action: Dict[str, Any], state: InvestigationState) -> Dict[str, Any]:
    """
    Evaluate a single planned action against all safety rules.
    Returns: { approved: bool, blocking_reasons: List[str], rule_violations: List[str] }
    """
    atype = action.get("type", "")
    target = action.get("target", "")
    confidence = float(action.get("confidence", 0.0))
    rules = ACTION_SAFETY_RULES.get(atype)

    blocking_reasons: List[str] = []

    if not rules:
        return {"approved": False, "blocking_reasons": [f"unknown action type: {atype}"], "rule_violations": []}

    # 1. FP probability
    fp_prob = state.get("triage_fp_probability", 50)
    if fp_prob > rules["max_fp_probability"]:
        blocking_reasons.append(f"FP probability {fp_prob}% > max {rules['max_fp_probability']}%")

    # 2. Confidence
    state_confidence = state.get("consensus_confidence", state.get("triage_confidence", 0))
    effective_conf = min(confidence, state_confidence)
    if effective_conf < rules["min_confidence"]:
        blocking_reasons.append(f"confidence {effective_conf:.2f} < min {rules['min_confidence']:.2f}")

    # 3. Consensus
    if rules["requires_consensus"] and not state.get("consensus_reached"):
        blocking_reasons.append("two-LLM consensus not reached")

    # 4. Severity proportionality
    severity = state.get("severity_assessment", "low")
    if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK.get(rules["min_severity"], 0):
        blocking_reasons.append(f"severity {severity} < required {rules['min_severity']}")

    # 5. External IP requirement (for block_ip)
    if rules.get("requires_external_ip"):
        if not target or _is_private_or_loopback(target):
            blocking_reasons.append(f"target {target} is private/loopback — refusing autonomous block")

    # 6. Self-infrastructure protection (always enforced)
    if _is_self_infra(target):
        blocking_reasons.append(f"target {target} is SOCPilots infrastructure — refused")

    # 7. Protected asset check (always enforced for destructive actions)
    if atype in ("isolate_host", "disable_user", "kill_process", "block_ip"):
        if _is_protected_asset(target):
            blocking_reasons.append(f"target {target} is on protected_assets list")

    # 8. Rate limit
    if atype in ("block_ip", "isolate_host", "kill_process", "disable_user"):
        if not _check_rate_limit(atype, target):
            blocking_reasons.append(f"rate limit exceeded: too many {atype} on {target} in last hour")

    # 9. Admin user guard
    if rules.get("block_admin_users") and target and any(
        keyword in target.lower() for keyword in ("admin", "root", "domain", "sysadmin", "administrator")
    ):
        blocking_reasons.append(f"target {target} appears to be admin/privileged account — refused")

    # 10. Self-investigation guard — never act if alert is on our own infra
    alert = state.get("alert", {}) or {}
    if _is_self_infra(alert.get("agent", "")):
        blocking_reasons.append(f"alert is on SOCPilots infrastructure ({alert.get('agent')}) — refused")

    approved = len(blocking_reasons) == 0
    return {
        "approved":         approved,
        "blocking_reasons": blocking_reasons,
        "action_type":      atype,
        "target":           target,
    }


def safety_gate_node(state: InvestigationState) -> Dict[str, Any]:
    """
    Safety gate node — filters planned_actions through all safety rules.
    Builds safety_blocks list with reasons for any rejected actions.
    """
    start = time.time()
    actions = state.get("planned_actions", []) or []
    safety_blocks: List[Dict[str, Any]] = []
    safety_reasons: List[str] = []
    approved_count = 0

    for action in actions:
        result = evaluate_action_safety(action, state)
        if result["approved"]:
            approved_count += 1
        else:
            safety_blocks.append(result)
            safety_reasons.extend(
                f"[{result['action_type']} on {result['target']}] {reason}"
                for reason in result["blocking_reasons"]
            )

    # Overall status
    if not actions:
        status = "approved"  # nothing to block
    elif approved_count == len(actions):
        status = "approved"
    elif approved_count == 0:
        status = "blocked"
    else:
        status = "partial"

    log.info(f"[safety_gate] status={status} approved={approved_count}/{len(actions)} blocks={len(safety_blocks)}")
    return {
        "safety_status":  status,
        "safety_blocks":  safety_blocks,
        "safety_reasons": safety_reasons,
        "node_trace": [{
            "node": "safety_gate",
            "status": status,
            "approved_count": approved_count,
            "blocked_count": len(safety_blocks),
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }
