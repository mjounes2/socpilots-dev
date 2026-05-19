"""
TriageAgent — Fast initial assessment.

Decides whether the alert warrants full investigation or can be closed immediately.
Outputs: triage_verdict, triage_confidence, triage_fp_probability, triage_summary.
"""
import time
import logging
from typing import Dict, Any

from ..state import InvestigationState
from ..llm import get_fast_llm, parse_json_response

log = logging.getLogger(__name__)


TRIAGE_PROMPT = """You are a SOC triage analyst performing rapid initial assessment.

ALERT:
- Rule ID: {rule_id}
- Severity: {severity} (level {level})
- Description: {description}
- Agent: {agent}
- Source IP: {src_ip}
- MITRE: {mitre}
- Timestamp: {timestamp}

PRIOR CONTEXT:
- Past investigations on this rule: {prior_count}
- Past TP rate for this rule: {prior_tp_rate}
- Known-malicious IOC match: {known_ioc}

TASK: Provide a fast triage verdict in JSON. Be decisive.

Rules:
- "true_positive"   = clear evidence of malicious activity
- "false_positive"  = strong indicators this is benign (known good source, expected behavior, low TP rate, no IOC match)
- "suspicious"      = needs deep investigation (cannot determine from alert alone)
- "inconclusive"    = insufficient data

Return ONLY valid JSON:
{{
  "verdict": "true_positive|false_positive|suspicious|inconclusive",
  "confidence": 0.0-1.0,
  "fp_probability": 0-100,
  "summary": "one sentence",
  "reasoning": "two sentences citing specific evidence",
  "needs_deep_investigation": true|false
}}"""


def triage_node(state: InvestigationState) -> Dict[str, Any]:
    """Fast triage assessment using small/fast LLM."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    prior = state.get("prior_investigations", []) or []
    entity_rep = state.get("entity_reputation", {}) or {}

    # Build prior context
    prior_count = len(prior)
    tp_count = sum(1 for p in prior if p.get("tp_status") == "confirmed_tp")
    fp_count = sum(1 for p in prior if p.get("tp_status") == "confirmed_fp")
    total_labelled = tp_count + fp_count
    tp_rate = f"{(tp_count/total_labelled*100):.0f}%" if total_labelled else "unknown"

    otx_pulses = entity_rep.get("otx_pulses") or []
    pulse_count = len(otx_pulses) if isinstance(otx_pulses, list) else int(otx_pulses or 0)
    known_ioc = "yes" if (entity_rep.get("known_malicious") or pulse_count > 0) else "no"

    prompt = TRIAGE_PROMPT.format(
        rule_id=alert.get("ruleId", "?"),
        severity=alert.get("severity", "?"),
        level=alert.get("level", "?"),
        description=alert.get("description", "?")[:300],
        agent=alert.get("agent", "?"),
        src_ip=alert.get("srcIp") or "N/A",
        mitre=", ".join(alert.get("mitre", []) or []) or "none",
        timestamp=alert.get("timestamp", "?"),
        prior_count=prior_count,
        prior_tp_rate=tp_rate,
        known_ioc=known_ioc,
    )

    try:
        llm = get_fast_llm()
        resp = llm.invoke(prompt)
        result = parse_json_response(resp.content, default={
            "verdict": "inconclusive", "confidence": 0.0, "fp_probability": 50,
            "summary": "Triage parsing failed", "reasoning": "LLM response could not be parsed",
            "needs_deep_investigation": True,
        })
        log.info(f"[triage] verdict={result.get('verdict')} fp={result.get('fp_probability')}%")
        return {
            "triage_verdict":        result.get("verdict", "inconclusive"),
            "triage_confidence":     float(result.get("confidence", 0.5)),
            "triage_fp_probability": int(result.get("fp_probability", 50)),
            "triage_summary":        result.get("summary", ""),
            "triage_reasoning":      result.get("reasoning", ""),
            "node_trace": [{
                "node": "triage", "duration_ms": int((time.time() - start) * 1000),
                "verdict": result.get("verdict"),
            }],
        }
    except Exception as e:
        log.error(f"[triage] {e}")
        return {
            "triage_verdict": "inconclusive",
            "triage_confidence": 0.0,
            "triage_fp_probability": 50,
            "errors": [f"triage: {str(e)[:200]}"],
            "node_trace": [{"node": "triage", "error": str(e)[:200]}],
        }


def route_after_triage(state: InvestigationState) -> str:
    """Conditional routing based on triage verdict."""
    verdict = state.get("triage_verdict", "inconclusive")
    fp_prob = state.get("triage_fp_probability", 50)
    confidence = state.get("triage_confidence", 0.0)

    # Strong FP signal — skip to close
    if verdict == "false_positive" and confidence >= 0.85 and fp_prob >= 80:
        return "close_fp"
    # Everything else proceeds to deep enrichment
    return "enrich"
