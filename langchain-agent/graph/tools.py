"""
SOCPilots Autonomous Investigation — Tool Wrappers

Thin wrappers around existing tool functions in main.py.
These are called directly from graph nodes (no LLM in the loop) for
deterministic data gathering. The LLM only interprets results.
"""
import os
import json
import logging
import httpx
from typing import Any, Dict, List

log = logging.getLogger(__name__)

# Reuse the same sync client + configuration as main.py
_sync_client = httpx.Client(verify=False, timeout=30.0)

OPENSEARCH_URL  = os.getenv("OPENSEARCH_URL", "")
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.getenv("OPENSEARCH_PASS", "")
WAZUH_INDEX     = os.getenv("WAZUH_INDEX", "wazuh-alerts-*")
WEBAPP_URL      = os.getenv("WEBAPP_URL", "http://webapp:3000")
INTERNAL_TOKEN  = os.getenv("LANGCHAIN_INTERNAL_TOKEN", "")
RAG_URL         = os.getenv("RAG_URL", "http://rag-retrieval:5005")
RAG_API_KEY     = os.getenv("RAG_API_KEY", "")


def _internal_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {INTERNAL_TOKEN}"} if INTERNAL_TOKEN else {}


def tool_search_alerts(query: str, hours: int = 24, size: int = 30) -> Dict[str, Any]:
    """Search Wazuh/OpenSearch alerts. Returns structured dict."""
    if not OPENSEARCH_URL:
        return {"error": "OpenSearch not configured", "count": 0, "alerts": []}
    try:
        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                        {"multi_match": {
                            "query": query,
                            "fields": ["data.srcip", "data.dstip", "agent.name",
                                       "rule.description", "data.win.eventdata.user",
                                       "rule.id", "rule.groups"],
                        }} if query and query.lower() not in ("*", "all", "any") else {"match_all": {}},
                    ],
                }
            },
        }
        r = _sync_client.post(
            f"{OPENSEARCH_URL}/{WAZUH_INDEX}/_search",
            json=body, auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        )
        r.raise_for_status()
        data = r.json()
        hits = data.get("hits", {}).get("hits", [])
        return {
            "count": data.get("hits", {}).get("total", {}).get("value", len(hits)),
            "alerts": [{
                "id":          h.get("_id"),
                "timestamp":   h["_source"].get("@timestamp"),
                "ruleId":      h["_source"].get("rule", {}).get("id"),
                "level":       h["_source"].get("rule", {}).get("level"),
                "description": h["_source"].get("rule", {}).get("description"),
                "agent":       h["_source"].get("agent", {}).get("name"),
                "srcIp":       h["_source"].get("data", {}).get("srcip"),
                "dstIp":       h["_source"].get("data", {}).get("dstip"),
                "mitre":       h["_source"].get("rule", {}).get("mitre", {}).get("id", []),
            } for h in hits],
        }
    except Exception as e:
        log.warning(f"[tool_search_alerts] {e}")
        return {"error": str(e), "count": 0, "alerts": []}


def tool_enrich_ip(ip: str) -> Dict[str, Any]:
    """Multi-source IOC enrichment via webapp proxy (VT + IPDB + OTX)."""
    if not ip or ip in ("N/A", "unknown", ""):
        return {"error": "No IP provided"}
    try:
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/threat-intel/enrich",
            params={"indicator": ip, "type": "ip"},
            headers=_internal_headers(),
        )
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "ip": ip}
    except Exception as e:
        log.warning(f"[tool_enrich_ip] {e}")
        return {"error": str(e), "ip": ip}


def tool_query_shodan(ip: str) -> Dict[str, Any]:
    """Shodan host lookup via webapp proxy."""
    if not ip:
        return {"error": "No IP"}
    try:
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/shodan/host/{ip}",
            headers=_internal_headers(),
        )
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def tool_query_ueba(entity: str) -> Dict[str, Any]:
    """Neo4j UEBA behavior profile via webapp proxy."""
    if not entity:
        return {"error": "No entity"}
    try:
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/ueba/profile/{entity}",
            headers=_internal_headers(),
        )
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def tool_check_cases(query: str) -> Dict[str, Any]:
    """TheHive case search via webapp proxy."""
    try:
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/cases",
            params={"q": query, "page_size": 10},
            headers=_internal_headers(),
        )
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "cases": []}
    except Exception as e:
        return {"error": str(e), "cases": []}


def tool_query_assets(ip_or_host: str) -> Dict[str, Any]:
    """Asset inventory lookup."""
    try:
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/assets",
            params={"q": ip_or_host, "page_size": 5},
            headers=_internal_headers(),
        )
        if r.status_code == 200:
            d = r.json()
            items = d.get("items", [])
            return {"matched": len(items) > 0, "assets": items}
        return {"error": f"HTTP {r.status_code}", "matched": False}
    except Exception as e:
        return {"error": str(e), "matched": False}


def tool_query_knowledge_base(query: str) -> Dict[str, Any]:
    """RAG semantic search over MITRE/rules/past investigations."""
    if not RAG_URL:
        return {"error": "RAG not configured", "results": []}
    try:
        headers = {"X-API-Key": RAG_API_KEY} if RAG_API_KEY else {}
        prefix = "Represent this sentence for searching relevant passages: "
        r = _sync_client.post(
            f"{RAG_URL}/retrieve",
            json={"query": prefix + query, "top_k": 5},
            headers=headers,
        )
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "results": []}
    except Exception as e:
        return {"error": str(e), "results": []}


def tool_execute_playbook(action: str, alert: Dict[str, Any], investigation_id: int,
                          report_excerpt: str = "", fp_probability: float = 0) -> Dict[str, Any]:
    """Execute a Dark SOC playbook action (block_ip, isolate_host, etc.)."""
    if not investigation_id:
        return {"error": "investigation_id required"}
    try:
        r = _sync_client.post(
            f"{WEBAPP_URL}/api/playbook/execute",
            json={
                "action": action,
                "alert": alert,
                "investigation_id": investigation_id,
                "investigationText": report_excerpt,
                "fpProbability": fp_probability,
                "autonomous": True,
            },
            headers=_internal_headers(),
            timeout=60.0,
        )
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"error": str(e)}


def tool_create_case(alert: Dict[str, Any], investigation_id: int, report: str) -> Dict[str, Any]:
    """Create a TheHive case from investigation findings."""
    try:
        r = _sync_client.post(
            f"{WEBAPP_URL}/api/cases/from-investigation",
            json={
                "investigation_id": investigation_id,
                "alert": alert,
                "report": report[:5000],
            },
            headers=_internal_headers(),
            timeout=30.0,
        )
        if r.status_code in (200, 201):
            return r.json()
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}
