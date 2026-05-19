"""
EnrichmentAgent — Parallel fan-out IOC enrichment.

Four parallel nodes (IOC intel, Shodan, UEBA, knowledge base) each write
to the merged `enrichments` dict in state.
"""
import time
import logging
from typing import Dict, Any

from ..state import InvestigationState
from ..tools import (
    tool_enrich_ip, tool_query_shodan, tool_query_ueba,
    tool_check_cases, tool_query_assets, tool_query_knowledge_base,
    tool_search_alerts,
)

log = logging.getLogger(__name__)


def ioc_enrichment_node(state: InvestigationState) -> Dict[str, Any]:
    """VirusTotal + AbuseIPDB + OTX enrichment for source IP."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    src_ip = alert.get("srcIp")
    if not src_ip:
        return {
            "enrichments": {"ioc_intel": {"skipped": "no source IP"}},
            "node_trace": [{"node": "ioc_enrichment", "skipped": True}],
        }
    result = tool_enrich_ip(src_ip)
    log.info(f"[ioc_enrichment] ip={src_ip} keys={list(result.keys())[:5]}")
    return {
        "enrichments": {"ioc_intel": result},
        "node_trace": [{
            "node": "ioc_enrichment", "ip": src_ip,
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }


def shodan_node(state: InvestigationState) -> Dict[str, Any]:
    """Shodan host scan — open ports, services, CVEs."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    src_ip = alert.get("srcIp")
    if not src_ip:
        return {
            "enrichments": {"shodan": {"skipped": "no source IP"}},
            "node_trace": [{"node": "shodan", "skipped": True}],
        }
    result = tool_query_shodan(src_ip)
    return {
        "enrichments": {"shodan": result},
        "node_trace": [{
            "node": "shodan", "ip": src_ip,
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }


def ueba_node(state: InvestigationState) -> Dict[str, Any]:
    """Neo4j UEBA behavior profile for agent/user/host."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    entity = alert.get("agent") or alert.get("user") or alert.get("srcIp")
    if not entity:
        return {
            "enrichments": {"ueba_profile": {"skipped": "no entity"}},
            "node_trace": [{"node": "ueba", "skipped": True}],
        }
    result = tool_query_ueba(entity)
    return {
        "enrichments": {"ueba_profile": result},
        "node_trace": [{
            "node": "ueba", "entity": entity,
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }


def threat_hunt_node(state: InvestigationState) -> Dict[str, Any]:
    """Broader OpenSearch hunt — related alerts in last 7 days."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    src_ip = alert.get("srcIp")
    rule_id = alert.get("ruleId")
    agent = alert.get("agent")

    # Two parallel queries: IP-based + rule/agent-based
    results = {}
    if src_ip:
        ip_hits = tool_search_alerts(src_ip, hours=168, size=20)
        results["by_ip"] = {"count": ip_hits.get("count", 0), "samples": ip_hits.get("alerts", [])[:5]}
    if rule_id and agent:
        rule_hits = tool_search_alerts(f"{rule_id} {agent}", hours=168, size=20)
        results["by_rule_agent"] = {"count": rule_hits.get("count", 0), "samples": rule_hits.get("alerts", [])[:5]}

    return {
        "enrichments": {"threat_hunt": results},
        "node_trace": [{
            "node": "threat_hunt",
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }


def case_history_node(state: InvestigationState) -> Dict[str, Any]:
    """Check TheHive for related cases."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    src_ip = alert.get("srcIp")
    rule_id = alert.get("ruleId")
    query = src_ip or str(rule_id or "")
    if not query:
        return {
            "enrichments": {"case_history": {"skipped": "no query"}},
            "node_trace": [{"node": "case_history", "skipped": True}],
        }
    result = tool_check_cases(query)
    return {
        "enrichments": {"case_history": result},
        "node_trace": [{
            "node": "case_history", "query": query[:50],
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }


def knowledge_base_node(state: InvestigationState) -> Dict[str, Any]:
    """RAG semantic search over MITRE, rules, past investigations."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    query = f"{alert.get('description','')} MITRE {' '.join(alert.get('mitre', []) or [])}"
    result = tool_query_knowledge_base(query.strip() or "security incident")
    return {
        "enrichments": {"knowledge_base": result},
        "node_trace": [{
            "node": "knowledge_base",
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }


def assets_node(state: InvestigationState) -> Dict[str, Any]:
    """Check if source IP/agent is a managed asset."""
    start = time.time()
    alert = state.get("alert", {}) or {}
    target = alert.get("agent") or alert.get("srcIp")
    if not target:
        return {
            "enrichments": {"assets": {"matched": False}},
            "node_trace": [{"node": "assets", "skipped": True}],
        }
    result = tool_query_assets(target)
    return {
        "enrichments": {"assets": result},
        "node_trace": [{
            "node": "assets", "target": target,
            "duration_ms": int((time.time() - start) * 1000),
        }],
    }
