"""
VerdictAgent — Two-LLM consensus validation.

In a zero-human Dark SOC, the SECOND opinion comes from a second LLM, not a human.
This node is the gatekeeper before any autonomous action is executed.
"""
import time
import json
import logging
from typing import Dict, Any

from ..state import InvestigationState
from ..llm import get_consensus_llm, parse_json_response

log = logging.getLogger(__name__)


CONSENSUS_PROMPT = """You are an independent SOC reviewer auditing another analyst's findings.
Your job is to confirm or REJECT their conclusions. Be skeptical.

PRIMARY ANALYST'S FINDINGS:
- Triage verdict: {triage_verdict} (FP probability: {fp_prob}%, confidence: {triage_conf})
- Triage reasoning: {triage_reasoning}
- Correlation severity: {severity}
- Correlation score: {corr_score}
- MITRE techniques claimed: {mitre}
- Attack chain steps: {chain_count}
- Confirming evidence: {confirming}
- Counter evidence: {counter}

KEY ALERT FACTS:
- Rule {rule_id} (level {level}) - {description}
- Agent: {agent}, Source IP: {src_ip}

TASK: Independent review. Do you agree with the primary findings?
Return ONLY valid JSON:
{{
  "verdict": "true_positive|false_positive|suspicious|inconclusive",
  "agrees_with_primary": true|false,
  "confidence": 0.0-1.0,
  "fp_probability": 0-100,
  "consensus_reached": true|false,
  "reasoning": "two sentences explaining your independent assessment",
  "blocking_concerns": ["list any concerns that should block autonomous action"]
}}

Be honest. If the evidence is weak, say so. If the primary missed something, flag it."""


def consensus_node(state: InvestigationState) -> Dict[str, Any]:
    """Independent second-LLM validation of the primary verdict."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    primary = state.get("primary_verdict", {}) or {}

    prompt = CONSENSUS_PROMPT.format(
        triage_verdict=state.get("triage_verdict", "?"),
        fp_prob=state.get("triage_fp_probability", 50),
        triage_conf=state.get("triage_confidence", 0.5),
        triage_reasoning=state.get("triage_reasoning", "?")[:300],
        severity=state.get("severity_assessment", "?"),
        corr_score=state.get("correlation_score", 0.0),
        mitre=", ".join(state.get("mitre_techniques", []) or []) or "none",
        chain_count=len(state.get("attack_chain", []) or []),
        confirming=", ".join(primary.get("confirming_evidence", []) or [])[:300],
        counter=", ".join(primary.get("counter_evidence", []) or [])[:300],
        rule_id=alert.get("ruleId", "?"),
        level=alert.get("level", "?"),
        description=alert.get("description", "?")[:200],
        agent=alert.get("agent", "?"),
        src_ip=alert.get("srcIp") or "N/A",
    )

    try:
        llm = get_consensus_llm()
        resp = llm.invoke(prompt)
        result = parse_json_response(resp.content, default={
            "verdict": "inconclusive", "agrees_with_primary": False,
            "confidence": 0.0, "fp_probability": 50, "consensus_reached": False,
            "reasoning": "Consensus parsing failed", "blocking_concerns": ["parse_error"],
        })
        # Consensus = both LLMs INDEPENDENTLY reached the same verdict.
        # We use verdict equality (the actual decision) — not the `agrees_with_primary`
        # flag, since LLMs sometimes return contradictory metadata while the verdict
        # itself agrees. The safety_gate enforces per-action safety, so this gate
        # is intentionally about "do we have a clear shared decision?"
        confidence = float(result.get("confidence", 0.0))
        primary_verdict = state.get("triage_verdict", "inconclusive")
        secondary_verdict = result.get("verdict", "inconclusive")
        verdict_matches = primary_verdict == secondary_verdict
        consensus_reached = (
            verdict_matches
            and confidence >= 0.6
            and primary_verdict in ("true_positive", "suspicious", "false_positive")
        )
        log.info(f"[consensus] reached={consensus_reached} primary={primary_verdict} "
                  f"secondary={secondary_verdict} match={verdict_matches} conf={confidence}")
        return {
            "consensus_verdict":    result,
            "consensus_reached":    consensus_reached,
            "consensus_confidence": confidence,
            "node_trace": [{
                "node": "consensus",
                "consensus_reached": consensus_reached,
                "duration_ms": int((time.time() - start) * 1000),
            }],
        }
    except Exception as e:
        log.error(f"[consensus] {e}")
        return {
            "consensus_reached": False,
            "consensus_confidence": 0.0,
            "errors": [f"consensus: {str(e)[:200]}"],
            "node_trace": [{"node": "consensus", "error": str(e)[:200]}],
        }


def route_after_consensus(state: InvestigationState) -> str:
    """Route based on consensus + severity assessment."""
    consensus = state.get("consensus_reached", False)
    severity = state.get("severity_assessment", "medium")
    secondary = state.get("consensus_verdict", {}) or {}

    # No consensus → escalate (save report, no autonomous action)
    if not consensus:
        return "no_consensus"

    # Consensus FP → close
    if secondary.get("verdict") == "false_positive":
        return "close_fp"

    # Consensus benign / low → save only
    if severity in ("benign", "low"):
        return "save_only"

    # Consensus TP/suspicious + medium-or-higher → plan action
    return "plan_action"
