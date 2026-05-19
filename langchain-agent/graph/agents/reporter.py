"""
ReporterAgent — Final structured investigation report.

Generates the markdown report + structured verdict that gets persisted
to the investigations table.
"""
import time
import json
import logging
from typing import Dict, Any

from ..state import InvestigationState
from ..llm import get_primary_llm, parse_json_response

log = logging.getLogger(__name__)


REPORT_PROMPT = """You are a senior SOC analyst writing the final investigation report.
This is an AUTONOMOUS Dark SOC investigation — no human will edit your output.

ALERT:
- Rule {rule_id} (level {level})
- Description: {description}
- Agent: {agent}
- Source IP: {src_ip}
- MITRE: {mitre}
- Timestamp: {timestamp}

ANALYSIS PIPELINE RESULTS:

Triage:
- Verdict: {triage_verdict} (confidence {triage_conf}, FP {fp_prob}%)
- Reasoning: {triage_reasoning}

Correlation:
- Severity: {severity}
- Score: {corr_score}
- MITRE techniques: {mitre_tech}
- Attack chain steps: {chain_count}

Consensus:
- Reached: {consensus}
- Secondary verdict: {secondary}

Actions taken autonomously:
{actions_summary}

Evidence excerpts:
- IOC intel: {ioc_intel}
- UEBA: {ueba}
- Threat hunt: {hunt}
- Case history: {cases}

Write the report in markdown using these exact sections:

## VERDICT
**[TRUE POSITIVE | FALSE POSITIVE | SUSPICIOUS]**
Confidence: [HIGH | MEDIUM | LOW]
FP probability: {fp_prob}%
Autonomous actions: [list executed action types or "none"]

## EXECUTIVE SUMMARY
3-5 sentences: what happened, who/what was affected, what the Dark SOC did about it.

## ATTACK CHAIN
Step-by-step reconstruction from the correlation analysis.

## TECHNICAL EVIDENCE
| Source | Finding | Confidence |
|---|---|---|
One row per key piece of evidence.

## MITRE ATT&CK
List each technique with evidence.

## AUTONOMOUS RESPONSE
Detail every action executed, who/what it targeted, and why it was safe to execute.

## REMEDIATION (manual follow-up)
What the human team should do next, if anything.

## SAFETY ASSESSMENT
Why this autonomous response was safe (consensus, FP probability, asset checks).

Be specific. Quote exact values from the evidence above. Do not invent IPs, hashes, or users."""


def _truncate(d: Any, n: int = 400) -> str:
    s = json.dumps(d, default=str) if not isinstance(d, str) else d
    return s[:n]


def reporter_node(state: InvestigationState) -> Dict[str, Any]:
    """Generate final markdown report + structured verdict."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    enr = state.get("enrichments", {}) or {}
    executed = state.get("executed_actions", []) or []
    failed = state.get("failed_actions", []) or []

    pending = state.get("pending_approvals", []) or []
    actions_summary = "None executed."
    if executed or failed or pending:
        lines = []
        for a in executed:
            lines.append(f"  ✓ AUTO-EXECUTED: {a.get('type')} on {a.get('target')}")
        for a in pending:
            lines.append(f"  ⏸ AWAITING APPROVAL: {a.get('type')} on {a.get('target')} "
                          f"(approval_id={a.get('approval_id')}, expires={a.get('expires_at')})")
        for a in failed:
            lines.append(f"  ✗ FAILED: {a.get('type')}: {a.get('error', 'failed')}")
        actions_summary = "\n".join(lines)

    consensus = state.get("consensus_verdict", {}) or {}

    prompt = REPORT_PROMPT.format(
        rule_id=alert.get("ruleId", "?"),
        level=alert.get("level", "?"),
        description=alert.get("description", "?")[:200],
        agent=alert.get("agent", "?"),
        src_ip=alert.get("srcIp") or "N/A",
        mitre=", ".join(alert.get("mitre", []) or []) or "none",
        timestamp=alert.get("timestamp", "?"),
        triage_verdict=state.get("triage_verdict", "?"),
        triage_conf=state.get("triage_confidence", 0),
        fp_prob=state.get("triage_fp_probability", 50),
        triage_reasoning=state.get("triage_reasoning", "?")[:200],
        severity=state.get("severity_assessment", "?"),
        corr_score=state.get("correlation_score", 0.0),
        mitre_tech=", ".join(state.get("mitre_techniques", []) or []) or "none",
        chain_count=len(state.get("attack_chain", []) or []),
        consensus=state.get("consensus_reached", False),
        secondary=consensus.get("verdict", "?"),
        actions_summary=actions_summary,
        ioc_intel=_truncate(enr.get("ioc_intel"), 300),
        ueba=_truncate(enr.get("ueba_profile"), 200),
        hunt=_truncate(enr.get("threat_hunt"), 200),
        cases=_truncate(enr.get("case_history"), 200),
    )

    try:
        llm = get_primary_llm()
        resp = llm.invoke(prompt)
        report_text = resp.content if hasattr(resp, "content") else str(resp)
    except Exception as e:
        log.error(f"[reporter] {e}")
        report_text = f"# Autonomous Investigation Report\n\nReport generation failed: {e}\n\nRaw verdict: {state.get('severity_assessment')}\nFP: {state.get('triage_fp_probability')}%\nActions executed: {len(executed)}"

    structured = {
        "verdict":               state.get("triage_verdict", "inconclusive"),
        "consensus_verdict":     consensus.get("verdict") if consensus else None,
        "consensus_reached":     state.get("consensus_reached", False),
        "confidence":            int(state.get("consensus_confidence", state.get("triage_confidence", 0)) * 100),
        "fp_probability":        state.get("triage_fp_probability", 50),
        "severity":              state.get("severity_assessment", "medium"),
        "correlation_score":     state.get("correlation_score", 0.0),
        "mitre_technique":       (state.get("mitre_techniques", []) or [None])[0],
        "mitre_techniques":      state.get("mitre_techniques", []),
        "attack_chain":          state.get("attack_chain", []),
        "recommended_actions":   [a.get("type") for a in state.get("planned_actions", [])],
        "executed_actions":      [a.get("type") for a in executed],
        "pending_approvals":     pending,
        "failed_actions":        [a.get("type") for a in failed],
        "safety_status":         state.get("safety_status", "approved"),
        "safety_reasons":        state.get("safety_reasons", []),
        "case_id":               state.get("case_id"),
        "investigation_id":      state.get("investigation_id"),
        "autonomous":            True,
        "engine":                "langgraph",
    }

    return {
        "final_report":       report_text,
        "structured_verdict": structured,
        "completed_at":       time.time(),
        "duration_ms":        int((time.time() - state.get("started_at", time.time())) * 1000),
        "node_trace": [{
            "node": "reporter",
            "report_chars": len(report_text),
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }
