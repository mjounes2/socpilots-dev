"""
ActionPlannerAgent — Decides which playbook actions to take.

For zero-human Dark SOC: the LLM proposes actions, the safety gate filters them.
"""
import time
import json
import logging
from typing import Dict, Any

from ..state import InvestigationState
from ..llm import get_primary_llm, parse_json_response

log = logging.getLogger(__name__)


PLANNER_PROMPT = """You are a Dark SOC autonomous response planner.
Both primary and consensus LLMs agree this alert is real. You must decide which response actions to execute.

ALERT:
- Rule {rule_id} (level {level}) on {agent}
- Source IP: {src_ip}
- Description: {description}
- MITRE: {mitre}

VERDICT:
- Severity: {severity}
- FP probability: {fp_prob}%
- Correlation score: {corr_score}
- Consensus confidence: {consensus_conf}

EVIDENCE SUMMARY:
- Confirming: {confirming}
- IOC intel suggests malicious: {ioc_malicious}
- UEBA anomaly score: {ueba_score}
- Asset is managed: {asset_managed}

AVAILABLE ACTIONS (Dark SOC playbook actions):
- block_ip       — block source IP at firewall (REVERSIBLE, low risk)
- isolate_host   — quarantine host from network (REVERSIBLE, high impact)
- kill_process   — terminate suspicious process (REVERSIBLE per-process)
- disable_user   — disable user account (REVERSIBLE, high impact)
- create_case    — open TheHive case (always safe)
- close_case     — close as benign (only if FP confirmed)

DECISION RULES (strict):
1. Always include "create_case" when severity is high or critical
2. "block_ip" only if IOC intel shows malicious + IP is external (not RFC1918)
3. "isolate_host" only if severity=critical AND attack-chain shows lateral movement or active C2
4. "kill_process" only if specific process is identified in evidence
5. "disable_user" only if user account was used to attack and severity=critical
6. NEVER suggest destructive action if FP probability > 25
7. NEVER suggest destructive action if confidence < 0.75

Return ONLY valid JSON:
{{
  "planned_actions": [
    {{
      "type": "block_ip|isolate_host|kill_process|disable_user|create_case|close_case",
      "target": "the IP, host, user, or process this action targets",
      "reason": "one sentence justification grounded in evidence",
      "confidence": 0.0-1.0,
      "reversible": true|false,
      "priority": 1-5
    }}
  ],
  "rationale": "brief overall explanation"
}}"""


def planner_node(state: InvestigationState) -> Dict[str, Any]:
    """Decide which Dark SOC playbook actions to execute."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    enr = state.get("enrichments", {}) or {}
    primary = state.get("primary_verdict", {}) or {}

    ioc_intel = enr.get("ioc_intel", {}) or {}
    ioc_malicious = bool(
        ioc_intel.get("malicious_votes", 0) > 0 or
        ioc_intel.get("abuse_confidence", 0) > 25 or
        len(ioc_intel.get("otx_pulses", []) or []) > 0
    )

    ueba = enr.get("ueba_profile", {}) or {}
    ueba_score = ueba.get("risk_score", 0)

    assets = enr.get("assets", {}) or {}
    asset_managed = bool(assets.get("matched"))

    prompt = PLANNER_PROMPT.format(
        rule_id=alert.get("ruleId", "?"),
        level=alert.get("level", "?"),
        agent=alert.get("agent", "?"),
        src_ip=alert.get("srcIp") or "N/A",
        description=alert.get("description", "?")[:200],
        mitre=", ".join(alert.get("mitre", []) or []) or "none",
        severity=state.get("severity_assessment", "medium"),
        fp_prob=state.get("triage_fp_probability", 50),
        corr_score=state.get("correlation_score", 0.0),
        consensus_conf=state.get("consensus_confidence", 0.0),
        confirming=", ".join(primary.get("confirming_evidence", []) or [])[:300],
        ioc_malicious="yes" if ioc_malicious else "no",
        ueba_score=ueba_score,
        asset_managed="yes" if asset_managed else "no",
    )

    try:
        llm = get_primary_llm()
        resp = llm.invoke(prompt)
        result = parse_json_response(resp.content, default={"planned_actions": []})
        actions = result.get("planned_actions", []) or []
        log.info(f"[planner] {len(actions)} actions planned: {[a.get('type') for a in actions]}")
        return {
            "planned_actions": actions,
            "node_trace": [{
                "node": "planner",
                "action_count": len(actions),
                "rationale": result.get("rationale", "")[:200],
                "duration_ms": int((time.time() - start) * 1000),
            }],
        }
    except Exception as e:
        log.error(f"[planner] {e}")
        # Fail safe: always create a case so analyst can review
        return {
            "planned_actions": [{
                "type": "create_case", "target": alert.get("agent", "unknown"),
                "reason": "Planner failed; creating case for human review",
                "confidence": 1.0, "reversible": True, "priority": 1,
            }],
            "errors": [f"planner: {str(e)[:200]}"],
            "node_trace": [{"node": "planner", "error": str(e)[:200], "fallback": "create_case"}],
        }
