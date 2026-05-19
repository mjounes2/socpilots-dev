"""
CorrelationAgent — Synthesizes parallel enrichment results into attack chain.
"""
import time
import json
import logging
from typing import Dict, Any

from ..state import InvestigationState
from ..llm import get_primary_llm, parse_json_response

log = logging.getLogger(__name__)


CORRELATION_PROMPT = """You are a senior SOC analyst correlating multi-source threat intelligence.

ORIGINAL ALERT:
{alert_summary}

GATHERED EVIDENCE (truncated):
- IOC Intelligence (VT/IPDB/OTX): {ioc_intel}
- Shodan host scan: {shodan}
- UEBA behavior profile: {ueba}
- Threat hunt (related alerts last 7d): {threat_hunt}
- Case history (TheHive): {case_history}
- Asset inventory: {assets}
- Knowledge base (MITRE/rules): {knowledge}

TASK: Synthesize this evidence. Build the attack chain and assess severity.

Return ONLY valid JSON:
{{
  "correlation_score": 0.0-1.0,
  "severity_assessment": "critical|high|medium|low|benign",
  "attack_chain": [
    {{"step": 1, "phase": "initial_access|execution|persistence|...", "evidence": "...", "source": "tool name"}}
  ],
  "mitre_techniques": ["T1234", "T5678"],
  "key_indicators": ["specific IOC, host, user, etc."],
  "counter_evidence": ["what could make this benign"],
  "confirming_evidence": ["what confirms this is real"]
}}

Be strict: only include evidence that is supported by the data above. Quote exact values."""


def _truncate(d: Any, max_chars: int = 500) -> str:
    """Compact JSON snapshot for LLM context."""
    if not d:
        return "{}"
    s = json.dumps(d, default=str)
    return s[:max_chars] + ("..." if len(s) > max_chars else "")


def correlation_node(state: InvestigationState) -> Dict[str, Any]:
    """Merge all enrichment outputs and build attack chain."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    enr = state.get("enrichments", {}) or {}

    alert_summary = (
        f"Rule {alert.get('ruleId')} (level {alert.get('level')}) - "
        f"{alert.get('description', '')[:200]} on {alert.get('agent')} from {alert.get('srcIp') or 'N/A'}"
    )

    prompt = CORRELATION_PROMPT.format(
        alert_summary=alert_summary,
        ioc_intel=_truncate(enr.get("ioc_intel"), 700),
        shodan=_truncate(enr.get("shodan"), 400),
        ueba=_truncate(enr.get("ueba_profile"), 400),
        threat_hunt=_truncate(enr.get("threat_hunt"), 400),
        case_history=_truncate(enr.get("case_history"), 300),
        assets=_truncate(enr.get("assets"), 200),
        knowledge=_truncate(enr.get("knowledge_base"), 400),
    )

    try:
        llm = get_primary_llm()
        resp = llm.invoke(prompt)
        result = parse_json_response(resp.content, default={})
        log.info(f"[correlation] severity={result.get('severity_assessment')} score={result.get('correlation_score')}")
        return {
            "correlation_score":   float(result.get("correlation_score", 0.0)),
            "severity_assessment": result.get("severity_assessment", "medium"),
            "attack_chain":        result.get("attack_chain", []) or [],
            "mitre_techniques":    result.get("mitre_techniques", []) or [],
            "primary_verdict":     {
                "key_indicators":     result.get("key_indicators", []),
                "counter_evidence":   result.get("counter_evidence", []),
                "confirming_evidence":result.get("confirming_evidence", []),
            },
            "node_trace": [{
                "node": "correlation",
                "severity": result.get("severity_assessment"),
                "duration_ms": int((time.time() - start) * 1000),
            }],
        }
    except Exception as e:
        log.error(f"[correlation] {e}")
        return {
            "correlation_score": 0.0,
            "severity_assessment": "medium",
            "errors": [f"correlation: {str(e)[:200]}"],
            "node_trace": [{"node": "correlation", "error": str(e)[:200]}],
        }
