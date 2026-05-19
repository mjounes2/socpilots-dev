"""
Memory module — cross-investigation memory retrieval and persistence.

Three tiers:
  1. Short-term: graph state (in-memory, current investigation)
  2. Medium-term: PostgreSQL via webapp API (entity reputation, rule FP rates)
  3. Long-term: Qdrant RAG (semantic similarity to past investigations)
"""
import time
import logging
from typing import Dict, Any, List

from .state import InvestigationState
from .tools import _sync_client, WEBAPP_URL, _internal_headers, tool_query_knowledge_base

log = logging.getLogger(__name__)


def _fetch_prior_investigations(rule_id: str, src_ip: str, agent: str) -> List[Dict[str, Any]]:
    """Get past investigations matching this alert."""
    try:
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/investigations",
            params={
                "ruleId": rule_id or "",
                "q": src_ip or agent or "",
                "page_size": 10,
                "sort_by": "created_at",
                "sort_dir": "desc",
            },
            headers=_internal_headers(),
            timeout=10.0,
        )
        if r.status_code == 200:
            d = r.json()
            return d.get("items", []) or []
    except Exception as e:
        log.warning(f"[_fetch_prior_investigations] {e}")
    return []


def _fetch_entity_reputation(src_ip: str) -> Dict[str, Any]:
    """Check OTX feed and prior known-bad indicator status."""
    if not src_ip:
        return {}
    rep = {}
    try:
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/otx/check/{src_ip}",
            headers=_internal_headers(),
            timeout=5.0,
        )
        if r.status_code == 200:
            d = r.json()
            rep["otx_pulses"] = d.get("pulses", [])
            rep["known_malicious"] = bool(d.get("known"))
    except Exception:
        pass
    return rep


def memory_node(state: InvestigationState) -> Dict[str, Any]:
    """
    Retrieve prior context before investigation begins.
    Loads similar past investigations, entity reputation, known IOC matches.
    """
    start = time.time()
    alert = state.get("alert", {}) or {}
    rule_id = str(alert.get("ruleId", ""))
    src_ip = alert.get("srcIp", "")
    agent = alert.get("agent", "")

    prior = _fetch_prior_investigations(rule_id, src_ip, agent)
    reputation = _fetch_entity_reputation(src_ip)

    # Semantic similarity to past investigations via RAG
    similar = []
    if alert.get("description"):
        rag_query = f"{alert.get('description','')} {' '.join(alert.get('mitre', []) or [])}"
        rag_result = tool_query_knowledge_base(rag_query)
        similar = rag_result.get("results", []) if isinstance(rag_result, dict) else []

    log.info(f"[memory] prior={len(prior)} reputation_keys={list(reputation.keys())} similar={len(similar)}")
    return {
        "prior_investigations": prior,
        "entity_reputation":    reputation,
        "known_iocs":           similar[:5] if similar else [],
        "node_trace": [{
            "node": "memory",
            "prior_count": len(prior),
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }


def persist_node(state: InvestigationState) -> Dict[str, Any]:
    """
    Final node — persists investigation to PostgreSQL + Qdrant knowledge base.
    Saves via webapp API which handles the DB writes.
    """
    start = time.time()
    alert = state.get("alert", {}) or {}
    report = state.get("final_report", "")
    structured = state.get("structured_verdict", {}) or {}

    # Save investigation record via webapp
    saved_id = None
    try:
        body = {
            "alert": alert,
            "prompt": "Autonomous Dark SOC investigation",
            "autoTriaged": True,
            "deep_mode": state.get("deep_mode", True),
            "session_id": state.get("session_id"),
            # Pre-computed result (skip re-investigation)
            "_precomputed": {
                "report": report,
                "structured": structured,
                "executed_actions": state.get("executed_actions", []),
                "engine": "langgraph",
            },
        }
        r = _sync_client.post(
            f"{WEBAPP_URL}/api/ai/investigate/persist",
            json=body,
            headers=_internal_headers(),
            timeout=30.0,
        )
        if r.status_code == 200:
            saved_id = r.json().get("investigation_id")
            log.info(f"[persist] saved investigation_id={saved_id}")
    except Exception as e:
        log.warning(f"[persist] save failed: {e}")

    return {
        "investigation_id": saved_id or state.get("investigation_id"),
        "node_trace": [{
            "node": "persist",
            "saved_id": saved_id,
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }
