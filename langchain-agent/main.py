"""
SOCPilots — LangChain Multi-Step Investigation Agent
ReAct pattern: Reason → Act → Observe → loop until answer found

Tools available to the agent:
  search_alerts      — query Wazuh/OpenSearch for related alerts
  enrich_ip          — VirusTotal + AbuseIPDB lookup
  check_cases        — search TheHive for related cases
  query_ueba         — ask Neo4j for entity behavior profile
  query_assets       — check if IP/host is in asset inventory
  query_log_sources  — list all active log sources and cloud integrations

Endpoints:
  POST /investigate   — deep multi-step investigation
  POST /triage        — fast single-step triage
  GET  /health
"""

import asyncio
import os, json, re, time, logging
import httpx
import redis as redis_lib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from langchain.agents import AgentExecutor, create_react_agent, create_tool_calling_agent
from langchain.tools import tool
from langchain_openai import ChatOpenAI
from langchain_mistralai import ChatMistralAI
from langchain.prompts import PromptTemplate
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage
from langchain.callbacks.base import AsyncCallbackHandler
from langchain_core.runnables.config import RunnableConfig

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="SOCPilots LangChain Agent")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Config ────────────────────────────────────────────────────
OPENSEARCH_URL   = os.getenv("OPENSEARCH_URL", "")
OPENSEARCH_USER  = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS  = os.getenv("OPENSEARCH_PASS", "")
WAZUH_INDEX      = os.getenv("WAZUH_INDEX", "wazuh-alerts-*")
THEHIVE_URL      = os.getenv("THEHIVE_URL", "")
THEHIVE_API_KEY  = os.getenv("THEHIVE_API_KEY", "")
WEBAPP_URL       = os.getenv("WEBAPP_URL", "http://webapp:3000")
OPENAI_API_KEY   = os.getenv("OPENAI_API_KEY", "")
MISTRAL_API_KEY  = os.getenv("MISTRAL_API_KEY", "")
INTERNAL_TOKEN   = os.getenv("LANGCHAIN_INTERNAL_TOKEN", "")
REDIS_URL        = os.getenv("REDIS_URL", "")
RAG_URL          = os.getenv("RAG_URL", "http://rag-retrieval:5005")
RAG_API_KEY      = os.getenv("RAG_API_KEY", "")
SHODAN_API_KEY   = os.getenv("SHODAN_API_KEY", "")
OTX_API_KEY      = os.getenv("OTX_API_KEY", "")

# ── Redis IOC Cache ───────────────────────────────────────────
_redis = None
if REDIS_URL:
    try:
        _redis = redis_lib.from_url(REDIS_URL, decode_responses=True, socket_timeout=2)
        _redis.ping()
        log.info(f"Redis cache connected: {REDIS_URL}")
    except Exception as _re:
        log.warning(f"Redis unavailable ({_re}) — IOC caching disabled")
        _redis = None

_IOC_TTL = 3600  # 1 hour cache for IOC results

def _cache_get(key: str) -> str | None:
    if not _redis:
        return None
    try:
        return _redis.get(key)
    except Exception:
        return None

def _cache_set(key: str, value: str, ttl: int = _IOC_TTL) -> None:
    if not _redis:
        return
    try:
        _redis.setex(key, ttl, value)
    except Exception:
        pass

# Synchronous client — used by @tool functions (called from thread pool, no event loop)
_sync_client = httpx.Client(verify=False, timeout=30.0)

# ── LangChain Tools (all synchronous) ───────────────────────

_GENERIC_QUERIES = {
    "*", "all", "any", "everything", "threat", "threats", "security", "alerts",
    "summary", "summarize", "overview", "recent", "latest", "today", "now",
    "status", "report", "news", "incidents", "events",
}

@tool
def search_alerts(query: str, hours: int = 24) -> str:
    """
    Search Wazuh/OpenSearch for security alerts related to an IP, hostname, user, rule ID, or keyword.
    Input: a specific indicator or keyword. To look further back append 'hours=N' or 'days=N'.
      Examples:
        "192.168.1.5"               — all alerts involving that IP (last 24h)
        "failed login hours=168"    — failed-login rules in the last 7 days
        "T1059"                     — alerts mapped to MITRE technique T1059
        "agent-name hours=48"       — all alerts from a specific agent
    For a FULL THREAT OVERVIEW use get_threat_summary instead of this tool.
    Returns: matching alerts with timestamp, rule ID, level, description, agent, source IP.
    """
    if not OPENSEARCH_URL:
        return "OpenSearch not configured"
    try:
        import re as _re
        lookback_hours = int(hours)
        h_match = _re.search(r'\bhours?=(\d+)\b', query, _re.IGNORECASE)
        d_match = _re.search(r'\bdays?=(\d+)\b', query, _re.IGNORECASE)
        if h_match:
            lookback_hours = int(h_match.group(1))
            query = _re.sub(r'\bhours?=\d+\b', '', query, flags=_re.IGNORECASE).strip().strip(',').strip()
        elif d_match:
            lookback_hours = int(d_match.group(1)) * 24
            query = _re.sub(r'\bdays?=\d+\b', '', query, flags=_re.IGNORECASE).strip().strip(',').strip()
        query = query.strip('"\'').strip()
        lookback_hours = max(1, min(lookback_hours, 720))

        time_filter = {"range": {"@timestamp": {"gte": f"now-{lookback_hours}h"}}}
        is_generic = not query or query.lower() in _GENERIC_QUERIES

        if is_generic:
            # Broad fetch — top 15 by severity then recency, plus severity histogram
            body = {
                "size": 15,
                "sort": [{"rule.level": {"order": "desc"}}, {"@timestamp": {"order": "desc"}}],
                "query": {"bool": {"filter": [time_filter]}},
                "aggs": {
                    "by_level": {"range": {"field": "rule.level",
                        "ranges": [{"key":"critical","from":12},{"key":"high","from":8,"to":12},
                                   {"key":"medium","from":4,"to":8},{"key":"low","to":4}]}},
                    "top_rules":  {"terms": {"field": "rule.id", "size": 5}},
                    "top_agents": {"terms": {"field": "agent.name", "size": 5}},
                },
            }
        else:
            body = {
                "size": 15,
                "sort": [{"rule.level": {"order": "desc"}}, {"@timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "should": [{
                            "multi_match": {
                                "query": query,
                                "fields": ["data.srcip^3", "agent.name^2", "rule.id^2",
                                           "rule.description", "full_log", "data.dstuser",
                                           "data.integration", "rule.mitre.id"],
                                "type": "best_fields",
                            }
                        }],
                        "filter": [time_filter],
                        "minimum_should_match": 1,
                    }
                },
            }

        r = _sync_client.post(
            f"{OPENSEARCH_URL}/{WAZUH_INDEX}/_search",
            json=body,
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        )
        data = r.json()
        hits  = data.get("hits", {}).get("hits", [])
        total = data.get("hits", {}).get("total", {}).get("value", 0)

        if not hits:
            if not is_generic:
                # Fallback: broaden to match_all so the agent knows there are (or aren't) alerts
                fb = _sync_client.post(
                    f"{OPENSEARCH_URL}/{WAZUH_INDEX}/_search",
                    json={"size": 5, "sort": [{"rule.level": {"order": "desc"}}],
                          "query": {"bool": {"filter": [time_filter]}}},
                    auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
                )
                fb_data = fb.json()
                fb_total = fb_data.get("hits", {}).get("total", {}).get("value", 0)
                if fb_total > 0:
                    return (f"No alerts matched '{query}' directly, but there are {fb_total} "
                            f"alerts in the last {lookback_hours}h. Try a more specific term or "
                            f"call get_threat_summary for an overview.")
            return f"No alerts in the last {lookback_hours}h"

        aggs = data.get("aggregations", {})
        by_level = {b["key"]: b["doc_count"] for b in aggs.get("by_level", {}).get("buckets", [])}

        label = "all" if is_generic else f"matching '{query}'"
        lines = [f"Found {total} alert(s) {label} in the last {lookback_hours}h"]
        if by_level:
            lines.append(
                f"  Severity: critical={by_level.get('critical',0)} | "
                f"high={by_level.get('high',0)} | medium={by_level.get('medium',0)} | "
                f"low={by_level.get('low',0)}"
            )
        lines.append(f"Top {len(hits)} by severity:")
        for h in hits:
            s = h["_source"]
            integ = s.get("data", {}).get("integration", "")
            mitre = s.get("rule", {}).get("mitre", {})
            mitre_ids = mitre.get("id", []) if isinstance(mitre, dict) else []
            mitre_str = f" | MITRE:{','.join(mitre_ids[:2])}" if mitre_ids else ""
            integ_str = f" | integ:{integ}" if integ else ""
            lines.append(
                f"  [{s.get('@timestamp','')[:16]}] Rule {s.get('rule',{}).get('id','')} "
                f"L{s.get('rule',{}).get('level','?')} — "
                f"{s.get('rule',{}).get('description','')} | "
                f"agent:{s.get('agent',{}).get('name','')} | "
                f"src:{s.get('data',{}).get('srcip','—')}"
                f"{integ_str}{mitre_str}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error searching alerts: {e}"


@tool
def get_threat_summary(hours: int = 24) -> str:
    """
    Get a comprehensive SIEM threat summary for the given time window.
    USE THIS TOOL for any overview/summary request: 'summarize threats', 'what happened today',
    'security status', 'threat overview', 'last 24h threats', 'any attacks?'.
    Input: number of hours to look back (1–720, default 24).
    Returns: total alert count, severity breakdown, top triggered rules (with counts),
             top affected agents, top attacker source IPs, active MITRE techniques,
             and the 10 highest-severity recent alerts with full detail.
    """
    if not OPENSEARCH_URL:
        return "OpenSearch not configured"
    try:
        h = max(1, min(int(hours), 720))
        time_filter = {"range": {"@timestamp": {"gte": f"now-{h}h"}}}
        body = {
            "size": 10,
            "sort": [{"rule.level": {"order": "desc"}}, {"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": [time_filter]}},
            "aggs": {
                "by_level": {"range": {"field": "rule.level",
                    "ranges": [{"key":"critical","from":12},{"key":"high","from":8,"to":12},
                               {"key":"medium","from":4,"to":8},{"key":"low","to":4}]}},
                "top_rules":  {"terms": {"field": "rule.description.keyword", "size": 8,
                                         "order": {"_count": "desc"}}},
                "top_agents": {"terms": {"field": "agent.name", "size": 5,
                                         "order": {"_count": "desc"}}},
                "top_srcips": {"terms": {"field": "data.srcip", "size": 5,
                                         "order": {"_count": "desc"},
                                         "exclude": ["", "0.0.0.0", "127.0.0.1"]}},
                "top_mitre":  {"terms": {"field": "rule.mitre.id", "size": 6,
                                         "order": {"_count": "desc"}}},
                "hourly":     {"date_histogram": {"field": "@timestamp",
                                "calendar_interval": "hour", "min_doc_count": 1}},
            },
        }
        r = _sync_client.post(
            f"{OPENSEARCH_URL}/{WAZUH_INDEX}/_search",
            json=body,
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        )
        data = r.json()
        hits  = data.get("hits", {}).get("hits", [])
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        aggs  = data.get("aggregations", {})

        if total == 0:
            return (f"No alerts recorded in the last {h}h. "
                    "SIEM is collecting events but no rules triggered in this window. "
                    "This may indicate a quiet period or a log-collection gap — check log sources.")

        by_level = {b["key"]: b["doc_count"] for b in aggs.get("by_level", {}).get("buckets", [])}
        critical = by_level.get("critical", 0)
        high     = by_level.get("high", 0)
        medium   = by_level.get("medium", 0)
        low      = by_level.get("low", 0)

        lines = [
            f"=== SIEM THREAT SUMMARY — LAST {h}h ===",
            f"Total alerts : {total:,}",
            f"Severity     : CRITICAL={critical} | HIGH={high} | MEDIUM={medium} | LOW={low}",
        ]

        top_rules = aggs.get("top_rules", {}).get("buckets", [])
        if top_rules:
            lines.append("Top triggered rules:")
            for b in top_rules:
                lines.append(f"  [{b['doc_count']:>5}x] {b['key']}")

        top_agents = aggs.get("top_agents", {}).get("buckets", [])
        if top_agents:
            lines.append("Most active agents:")
            for b in top_agents:
                lines.append(f"  [{b['doc_count']:>5}] {b['key']}")

        top_ips = aggs.get("top_srcips", {}).get("buckets", [])
        if top_ips:
            lines.append("Top attacker source IPs:")
            for b in top_ips:
                lines.append(f"  [{b['doc_count']:>5}] {b['key']}")

        top_mitre = aggs.get("top_mitre", {}).get("buckets", [])
        if top_mitre:
            mitre_str = ", ".join(f"{b['key']}({b['doc_count']})" for b in top_mitre)
            lines.append(f"Active MITRE techniques: {mitre_str}")

        hourly = aggs.get("hourly", {}).get("buckets", [])
        if len(hourly) >= 2:
            peak = max(hourly, key=lambda b: b["doc_count"])
            lines.append(f"Peak hour: {peak['key_as_string'][:13]} UTC ({peak['doc_count']} alerts)")

        lines.append(f"Highest-severity alerts (top {len(hits)}):")
        for hit in hits:
            s = hit["_source"]
            ts    = s.get("@timestamp", "")[:16].replace("T", " ")
            rule  = s.get("rule", {})
            agent = s.get("agent", {}).get("name", "—")
            srcip = s.get("data", {}).get("srcip", "")
            mitre = s.get("rule", {}).get("mitre", {})
            mids  = mitre.get("id", []) if isinstance(mitre, dict) else []
            m_str = f" [{','.join(mids[:2])}]" if mids else ""
            s_str = f" src:{srcip}" if srcip else ""
            lines.append(
                f"  {ts} | L{rule.get('level','?')} | {rule.get('description','')}"
                f" | agent:{agent}{s_str}{m_str}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error getting threat summary: {e}"


@tool
def enrich_ip(ip_address: str) -> str:
    """
    Enrich an IP address with threat intelligence from VirusTotal, AbuseIPDB, Shodan, and OTX AlienVault.
    Input: an IPv4 address like '1.2.3.4'.
    Returns: reputation score, malicious votes, country, ISP, categories, OTX pulse matches.
    """
    ip = ip_address.strip()
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
        return f"Invalid IP format: {ip}"

    cached = _cache_get(f"ioc:ip:{ip}")
    if cached:
        log.info(f"Cache HIT enrich_ip: {ip}")
        return cached

    results = []

    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if vt_key:
        try:
            r = _sync_client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": vt_key}
            )
            if r.status_code == 200:
                d = r.json().get("data", {}).get("attributes", {})
                stats = d.get("last_analysis_stats", {})
                results.append(
                    f"VirusTotal: malicious={stats.get('malicious',0)} "
                    f"suspicious={stats.get('suspicious',0)} "
                    f"harmless={stats.get('harmless',0)} "
                    f"country={d.get('country','')} "
                    f"owner={d.get('as_owner','')}"
                )
        except Exception as e:
            results.append(f"VirusTotal error: {e}")

    ab_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if ab_key:
        try:
            r = _sync_client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": ab_key, "Accept": "application/json"}
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                results.append(
                    f"AbuseIPDB: score={d.get('abuseConfidenceScore',0)}% "
                    f"reports={d.get('totalReports',0)} "
                    f"country={d.get('countryCode','')} "
                    f"isp={d.get('isp','')} "
                    f"usage={d.get('usageType','')}"
                )
        except Exception as e:
            results.append(f"AbuseIPDB error: {e}")

    if SHODAN_API_KEY:
        try:
            r = _sync_client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": SHODAN_API_KEY}
            )
            if r.status_code == 200:
                d = r.json()
                ports = d.get("ports", [])
                vulns = list(d.get("vulns", {}).keys())
                results.append(
                    f"Shodan: ports={','.join(str(p) for p in ports[:20])} "
                    f"org={d.get('org','')} "
                    f"os={d.get('os','unknown')} "
                    f"country={d.get('country_name','')} "
                    f"hostnames={','.join(d.get('hostnames',[])[:5])} "
                    f"vulns={','.join(vulns[:10]) if vulns else 'none'}"
                )
            elif r.status_code == 404:
                results.append(f"Shodan: no data found for {ip}")
        except Exception as e:
            results.append(f"Shodan error: {e}")

    if OTX_API_KEY:
        try:
            r = _sync_client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                pulse_count = d.get("pulse_info", {}).get("count", 0)
                pulses = d.get("pulse_info", {}).get("pulses", [])[:3]
                pulse_names = [p.get("name", "") for p in pulses if p.get("name")]
                results.append(
                    f"OTX AlienVault: {pulse_count} pulse(s) match this IP"
                    + (f" — {', '.join(pulse_names)}" if pulse_names else "")
                )
        except Exception as e:
            results.append(f"OTX error: {e}")

    result_text = "\n".join(results) if results else f"No threat intel API keys configured — cannot enrich {ip}"
    if results:
        _cache_set(f"ioc:ip:{ip}", result_text)
    return result_text


@tool
def query_shodan(ip_address: str) -> str:
    """
    Query Shodan for detailed host information: open ports, running services,
    known CVEs/vulnerabilities, OS, organisation, and banners.
    Input: an IPv4 address like '1.2.3.4'.
    Use this for deep infrastructure analysis during investigations.
    Returns: ports, services, CVEs, OS, ISP, hostnames.
    """
    if not SHODAN_API_KEY:
        return "Shodan not configured (SHODAN_API_KEY missing)"
    ip = ip_address.strip()
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
        return f"Invalid IP format: {ip}"

    cache_key = f"shodan:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        log.info(f"Cache HIT query_shodan: {ip}")
        return cached

    try:
        r = _sync_client.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY}
        )
        if r.status_code == 404:
            return f"Shodan: no indexed data for {ip}"
        if r.status_code != 200:
            return f"Shodan error: HTTP {r.status_code}"

        d = r.json()
        ports   = d.get("ports", [])
        vulns   = list(d.get("vulns", {}).keys())
        banners = []
        for svc in (d.get("data") or [])[:5]:
            transport = svc.get("transport", "tcp")
            port      = svc.get("port", "?")
            product   = svc.get("product", "")
            version   = svc.get("version", "")
            banner    = svc.get("data", "")[:100].replace("\n", " ")
            banners.append(f"  {port}/{transport} {product} {version}: {banner}")

        lines = [
            f"Shodan host report for {ip}:",
            f"  Organisation : {d.get('org','—')}",
            f"  ISP          : {d.get('isp','—')}",
            f"  Country      : {d.get('country_name','—')} ({d.get('country_code','—')})",
            f"  OS           : {d.get('os','unknown')}",
            f"  Hostnames    : {', '.join(d.get('hostnames',[])[:8]) or 'none'}",
            f"  Open ports   : {', '.join(str(p) for p in sorted(ports)[:30]) or 'none'}",
            f"  CVEs         : {', '.join(vulns[:15]) if vulns else 'none'}",
            f"  Last update  : {d.get('last_update','—')}",
        ]
        if banners:
            lines.append("  Services:")
            lines.extend(banners)

        result = "\n".join(lines)
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        return f"Shodan query error: {e}"


@tool
def check_cases(search_term: str) -> str:
    """
    Search TheHive (SP-CM) for existing security cases related to an IP, hostname, or keyword.
    Input: search term like '192.168.1.5' or 'ransomware'.
    Returns: list of matching cases with title, severity, status, creation date.
    """
    if not THEHIVE_URL or not THEHIVE_API_KEY:
        return "TheHive not configured"
    try:
        r = _sync_client.post(
            f"{THEHIVE_URL}/api/v1/query",
            json=[
                {"_name": "listCase"},
                {"_name": "filter", "_field": "_string", "_value": search_term},
                {"_name": "page", "from": 0, "to": 5}
            ],
            headers={"Authorization": f"Bearer {THEHIVE_API_KEY}"}
        )
        cases = r.json() if isinstance(r.json(), list) else []
        if not cases:
            return f"No cases found for: {search_term}"
        results = []
        for c in cases[:5]:
            results.append(
                f"Case #{c.get('caseId','')} [{c.get('status','')}] "
                f"Severity:{c.get('severity','')} — {c.get('title','')} "
                f"({c.get('_createdAt','')})"
            )
        return "\n".join(results)
    except Exception as e:
        return f"TheHive error: {e}"


@tool
def query_ueba(entity_name: str) -> str:
    """
    Query the UEBA behavioral graph for a user, host, or IP address.
    Input: entity name like 'john.doe', '192.168.1.10', or 'workstation-01'.
    Returns: risk score, recent behavior, detected anomalies.
    """
    try:
        headers = {}
        if INTERNAL_TOKEN:
            headers["Authorization"] = f"Bearer {INTERNAL_TOKEN}"
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/ueba/graph/{entity_name}",
            headers=headers
        )
        if r.status_code != 200:
            return f"UEBA lookup failed: {r.status_code}"
        edges = r.json().get("edges", [])
        if not edges:
            return f"No UEBA data found for entity: {entity_name}"
        summary = f"Found {len(edges)} graph relationships for {entity_name}:\n"
        for e in edges[:10]:
            dev = e.get('deviation', 0)
            flag = f" ⚠ {','.join(e.get('flags',[]))}" if e.get('flags') else ""
            summary += (f"  {e['rel']}: {e['src']}({e['src_type']}) → "
                       f"{e['dst']}({e['dst_type']}) at {e.get('time','?')}"
                       f" [deviation: {dev}]{flag}\n")
        return summary
    except Exception as e:
        return f"UEBA error: {e}"


@tool
def query_knowledge_base(query: str) -> str:
    """
    Search the RAG knowledge base for relevant MITRE ATT&CK techniques,
    detection rules, and historical incident cases matching the query.
    Use this to enrich investigation context with threat intelligence.
    """
    try:
        rag_headers = {"X-API-Key": RAG_API_KEY} if RAG_API_KEY else {}
        r = _sync_client.post(
            f"{RAG_URL}/search/investigation",
            json={"query": query, "limit": 5},
            headers=rag_headers,
            timeout=15
        )
        if r.status_code != 200:
            return f"Knowledge base unavailable: {r.status_code}"
        data = r.json()
        lines = []
        for item in data.get("attack_patterns", []):
            meta = item.get("metadata", {})
            lines.append(
                f"[MITRE {meta.get('technique_id','?')}] {item['title']} "
                f"(tactic: {meta.get('tactic','?')}, similarity: {item['score']})"
            )
        for item in data.get("similar_incidents", []):
            lines.append(f"[PAST INCIDENT] {item['title']} (similarity: {item['score']})")
        for item in data.get("detection_rules", []):
            lines.append(f"[DETECTION RULE] {item['title']} (similarity: {item['score']})")
        return "\n".join(lines) if lines else "No relevant knowledge base entries found."
    except Exception as e:
        return f"Knowledge base query error: {e}"


@tool
def query_assets(ip_or_hostname: str) -> str:
    """
    Check if an IP address or hostname is in the asset inventory.
    Returns asset details: OS, open ports, Wazuh agent status, risk score.
    """
    try:
        headers = {}
        if INTERNAL_TOKEN:
            headers["Authorization"] = f"Bearer {INTERNAL_TOKEN}"
        r = _sync_client.get(
            f"{WEBAPP_URL}/api/assets?q={ip_or_hostname}",
            headers=headers
        )
        if r.status_code != 200:
            return f"Asset lookup failed: {r.status_code}"
        assets = r.json().get("assets", [])
        if not assets:
            return f"Asset '{ip_or_hostname}' not found in inventory"
        a = assets[0]
        ports = ", ".join([f"{p['port']}/{p['service']}" for p in (a.get('open_ports') or [])[:8]])
        return (f"Asset: {a['ip']} | Hostname: {a.get('hostname','—')} | "
                f"OS: {a.get('os','—')} | Open ports: {ports or 'none'} | "
                f"Wazuh agent: {a.get('wazuh_agent_name','none')} ({a.get('wazuh_agent_status','—')}) | "
                f"Risk score: {a.get('risk_score', 0)} | Last seen: {a.get('last_seen','—')}")
    except Exception as e:
        return f"Asset query error: {e}"


@tool
def query_log_sources(filter_str: str = "all") -> str:
    """
    List all active SIEM log sources: endpoint agents, syslog forwarders, and cloud API integrations.
    Input: 'all' for everything, or a filter keyword like 'cloud_api', 'server', 'proxy',
           or a vendor/integration name like 'google', 'gsuite', 'aws', 'azure', 'cloudflare'.
    Returns: each source's name, vendor, type, 24h event count, last seen, and integration tag.
    Use this for ANY question about what logs are being collected, which integrations are active,
    whether a specific platform (Google Workspace, AWS, Azure, etc.) is connected, or log coverage gaps.
    """
    try:
        headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"} if INTERNAL_TOKEN else {}
        r = _sync_client.get(f"{WEBAPP_URL}/api/log-sources", headers=headers)
        if r.status_code != 200:
            return f"Log sources lookup failed: {r.status_code}"
        data = r.json()
        sources = data.get("sources", [])
        summary = data.get("summary", {})
        if not sources:
            return "No log sources found"

        flt = filter_str.strip().strip('"\'').lower()
        if flt and flt != "all":
            sources = [
                s for s in sources
                if flt in (s.get("type") or "").lower()
                or flt in (s.get("vendor") or "").lower()
                or flt in (s.get("integration") or "").lower()
                or flt in (s.get("source_name") or "").lower()
            ]
            if not sources:
                return f"No log sources matching '{filter_str}'"

        lines = [
            f"Log Source Inventory — {summary.get('total_sources', len(sources))} sources, "
            f"{summary.get('total_events_24h', 0):,} events/24h, "
            f"EPS: {summary.get('total_eps', 0):.2f}",
            ""
        ]
        for s in sources:
            status = "ACTIVE" if s.get("event_count_24h", 0) > 0 else "SILENT"
            integ = f" [integration:{s['integration']}]" if s.get("integration") else ""
            lines.append(
                f"  [{status}] {s['source_name']} | vendor:{s.get('vendor','?')} "
                f"type:{s.get('type','?')}{integ} | "
                f"24h:{s.get('event_count_24h',0):,} events | "
                f"last_seen:{s.get('last_seen','?')[:10]}"
            )
        if summary.get("cloud_api_sources"):
            lines.append(f"\nCloud API integrations: {summary['cloud_api_sources']}")
        if summary.get("anomaly_count"):
            lines.append(f"Anomalous sources: {summary['anomaly_count']}")
        return "\n".join(lines)
    except Exception as e:
        return f"Log sources query error: {e}"


# ── LLM Selection ─────────────────────────────────────────────
def get_llm(model_preference: str = "auto"):
    """
    LLM routing:
      "gpt"     / "openai"  → GPT-4o (deep analysis, best tool use)
      "mistral"             → Mistral-large (fast, good for enrichment)
      "auto"                → GPT-4o if available, else Mistral-large
    """
    pref = (model_preference or "auto").lower()
    if pref in ("mistral",) and MISTRAL_API_KEY:
        return ChatMistralAI(model="mistral-large-latest", api_key=MISTRAL_API_KEY, temperature=0)
    if OPENAI_API_KEY:
        return ChatOpenAI(model="gpt-4o", api_key=OPENAI_API_KEY, temperature=0)
    if MISTRAL_API_KEY:
        return ChatMistralAI(model="mistral-large-latest", api_key=MISTRAL_API_KEY, temperature=0)
    raise ValueError("No LLM API key configured (OPENAI_API_KEY or MISTRAL_API_KEY)")


# ── ReAct Prompt (standard mode — 3-5 tool calls, fast) ───────
REACT_PROMPT = PromptTemplate.from_template("""You are an expert SOC analyst. Use tools to investigate the input, then write a Final Answer.

IMPORTANT: After 3-5 tool calls, stop gathering data and write your Final Answer. Do not loop endlessly.

Tools:
{tools}

Tool names: {tool_names}

Tool selection guide:
- Questions about log sources, integrations, cloud connectors (Google Workspace, AWS, Azure, Cloudflare) → query_log_sources
- Questions about historical alerts or events → search_alerts, append hours=N for longer lookback e.g. "gsuite hours=720" for 30 days
- Questions about an IP address reputation → enrich_ip
- Questions about open ports/services on an IP → query_shodan
- Questions about cases or incidents → check_cases
- Questions about user/entity behavior → query_ueba
- Questions about hosts or assets → query_assets
- Questions about detection rules or MITRE techniques → query_knowledge_base

Input: {input}

Rules:
- Call each tool at most once per investigation
- After gathering key evidence, write Final Answer immediately
- Final Answer must be a structured report with: Summary, Key Findings, Risk Level, Recommended Actions

Format:
Thought: reasoning
Action: tool_name
Action Input: input
Observation: result
(repeat 3-5 times max)
Final Answer: [your structured report]

{agent_scratchpad}""")


# ── Deep Investigation Prompt (deep mode — 8+ tool calls, full evidence-grounded report) ──
DEEP_REACT_PROMPT = PromptTemplate.from_template("""You are a senior SOC analyst performing a DEEP, evidence-based security investigation.

════ ACCURACY MANDATE ════
You are responsible for 100% accuracy. Every finding you state MUST be grounded in actual tool output.
• Quote EXACT values from tool results — IPs, scores, CVEs, rule IDs, timestamps, user names
• If a tool returns no data: state "No data from [source]" — NEVER speculate or invent
• Confidence per finding: HIGH = 2+ independent sources confirm | MEDIUM = 1 direct source | LOW = indirect
• If you find counter-evidence (suggests false positive), report it — do NOT ignore it

════ INVESTIGATION PROTOCOL ════
You MUST complete ALL of these tool calls before writing your Final Answer:
1. search_alerts — search the specific indicator (source IP / agent / username) in last 24h
2. search_alerts — broader search on rule description keywords in last 7 days (append hours=168)
3. enrich_ip — enrich the source IP if present (VirusTotal + AbuseIPDB + OTX reputation)
4. query_shodan — deep host scan of source IP (open ports, CVEs, running services)
5. query_ueba — behavioral profile of the agent/host/user involved
6. query_assets — check if the involved IP/hostname is a known managed asset
7. check_cases — search for related past cases using the IP or rule description
8. query_knowledge_base — MITRE ATT&CK technique mapping for the observed behavior

Minimum 7 tool calls required. Complete all 8 if source IP is present.

Tools:
{tools}

Tool names: {tool_names}

Input: {input}

════ REQUIRED OUTPUT FORMAT ════
After ALL tool calls are complete, write your Final Answer using EXACTLY these sections:

## VERDICT
**[TRUE POSITIVE | FALSE POSITIVE | INCONCLUSIVE]**
Confidence: [HIGH | MEDIUM | LOW]
False Positive Probability: [0-100]%
Justification: one sentence citing the strongest evidence for this verdict.

## EXECUTIVE SUMMARY
3-5 sentences written for a non-technical manager. What happened, who was involved, what is the real risk.

## ATTACK CHAIN
Step-by-step reconstruction of what occurred. Only include steps supported by tool evidence.
Format each step as: **Step N** | [timestamp or 'unknown'] | [action/event] | Source: [tool name]

## TECHNICAL EVIDENCE
| Evidence Source | Exact Finding | Confidence |
|---|---|---|
One row per key finding. Quote exact values from tool outputs (scores, IPs, CVE IDs).

## IOC INVENTORY
Only list IOCs that tools explicitly returned — do NOT add IPs or hashes not seen in tool outputs.
| Type | Value | Verdict | Intelligence Source |
|---|---|---|---|
Types: IP, Domain, Hash, User, Host, Process, Port/Service

## MITRE ATT&CK MAPPING
Map techniques only when behavioral evidence exists from tool output — not just based on rule name.
**[TXXXX] Technique Name** — Tactic: [tactic name]
Evidence: [exact observation from a specific tool that justifies this mapping]

## FALSE POSITIVE ANALYSIS
**Counter-evidence** (what could make this benign): [state explicitly if none found]
**Confirming evidence** (what rules out FP): [list each piece]
**Final FP probability**: [X]% — [one sentence explanation]

## REMEDIATION PLAN
All steps MUST reference the specific hosts, IPs, users, and processes found during this investigation.
No generic advice.

### Immediate — within 1 hour:
- [specific step referencing actual asset/IP/user from investigation]

### Short-term — within 24 hours:
- [specific investigation and containment steps]

### Long-term — within 1 week:
- [specific hardening and eradication steps]

## MITIGATION CONTROLS
Controls to prevent this specific attack pattern from recurring:
| Control | Specific Implementation | Priority |
|---|---|---|

## ANALYST DIRECTIVE
One paragraph. What must the analyst do RIGHT NOW. Reference the specific hosts, IPs, users, and indicators
found in this investigation. If verdict is FALSE POSITIVE, explicitly state why the analyst can close this safely.

Format:
Thought: reasoning about what to investigate next
Action: tool_name
Action Input: the input string
Observation: result
(repeat until all required tool calls are done — minimum 7)
Final Answer: [complete report with all sections above]

{agent_scratchpad}""")


async def _extract_structured(report: str, llm) -> dict:
    """
    Second-pass structured extractor.
    Runs after the ReAct investigation and extracts a fixed JSON schema.
    ONLY extracts what is explicitly stated in the report — no inference.
    """
    schema_prompt = f"""Extract structured data from this security investigation report.

STRICT RULE: Only extract information EXPLICITLY stated in the report text below.
Do NOT infer, add, or speculate. If a field has no supporting text, use null or [].

Report:
---
{report[:4500]}
---

Return ONLY valid JSON matching this exact schema (no markdown, no explanation):
{{
  "verdict": "true_positive|false_positive|inconclusive",
  "confidence": "high|medium|low",
  "confidence_score": 0,
  "false_positive_probability": 0,
  "mitre_techniques": [
    {{"id": "T1059", "name": "Technique Name", "tactic": "tactic", "evidence": "brief quote from report"}}
  ],
  "key_iocs": [
    {{"type": "ip|domain|hash|user|host|process", "value": "exact value", "verdict": "malicious|suspicious|benign|unknown", "source": "source name"}}
  ],
  "attack_chain": [
    {{"step": 1, "action": "brief action description", "evidence": "tool source name", "timestamp": null}}
  ],
  "remediation_immediate": ["action 1"],
  "remediation_short_term": ["action 1"],
  "remediation_long_term": ["action 1"],
  "mitigation_controls": [
    {{"control": "control name", "implementation": "specific how-to", "priority": "high|medium|low"}}
  ],
  "affected_assets": ["hostname or IP"],
  "evidence_sources": ["tool names used"],
  "analyst_directive": "one paragraph from the Analyst Directive section, or null"
}}"""

    try:
        response = await llm.ainvoke(schema_prompt)
        text = response.content.strip()
        data = _parse_json_response(text)
        if not isinstance(data, dict):
            return {}
        # Clamp numeric fields to valid ranges
        if "confidence_score" in data:
            data["confidence_score"] = max(0, min(100, int(data.get("confidence_score") or 0)))
        if "false_positive_probability" in data:
            data["false_positive_probability"] = max(0, min(100, int(data.get("false_positive_probability") or 0)))
        return data
    except Exception as e:
        log.warning(f"[structured-extract] Failed: {e}")
        return {}

TOOLS = [search_alerts, enrich_ip, query_shodan, check_cases, query_ueba, query_assets, query_knowledge_base, query_log_sources]

# ── Request Models ────────────────────────────────────────────
class InvestigateRequest(BaseModel):
    alert: dict | None = None
    message: str | None = None
    model: str = "auto"
    deep_mode: bool = False

class TriageRequest(BaseModel):
    alert: dict
    model: str = "mistral"

class EnrichRequest(BaseModel):
    indicator: str
    type: str = "ip"  # ip | domain | url | hash

class HuntQueriesRequest(BaseModel):
    type: str   # ip | user | hash | domain | process | rule
    value: str
    context: str = ""
    model: str = "auto"

# ── Endpoints ─────────────────────────────────────────────────

@app.get("/health")
def health():
    redis_ok = False
    if _redis:
        try:
            _redis.ping()
            redis_ok = True
        except Exception:
            pass
    return {
        "status":      "ok",
        "ai_engine":   bool(OPENAI_API_KEY or MISTRAL_API_KEY),
        "opensearch":  bool(OPENSEARCH_URL),
        "thehive":     bool(THEHIVE_URL),
        "redis":       redis_ok,
        "vt":          bool(os.getenv("VIRUSTOTAL_API_KEY")),
        "abuseipdb":   bool(os.getenv("ABUSEIPDB_API_KEY")),
        "shodan":      bool(SHODAN_API_KEY),
        "otx":         bool(OTX_API_KEY),
        "engine":      "SOCPilots AI" if (OPENAI_API_KEY or MISTRAL_API_KEY) else "offline",
    }


@app.post("/investigate")
async def investigate(req: InvestigateRequest):
    start = time.time()
    try:
        llm = get_llm(req.model)
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))

    if req.alert:
        a = req.alert
        context = (
            f"Alert ID: {a.get('id','unknown')}\n"
            f"Rule: {a.get('rule',{}).get('description','')}\n"
            f"Severity: {a.get('rule',{}).get('level','?')}\n"
            f"Agent: {a.get('agent',{}).get('name','')}\n"
            f"Source IP: {a.get('data',{}).get('srcip','')}\n"
            f"Timestamp: {a.get('timestamp','')}\n"
            f"Full log: {a.get('full_log','')[:500]}"
        )
    else:
        context = req.message or "Investigate the current threat landscape"

    prompt_template  = DEEP_REACT_PROMPT if req.deep_mode else REACT_PROMPT
    max_iterations   = 16 if req.deep_mode else 12
    max_exec_time    = 155 if req.deep_mode else 120

    try:
        agent = create_react_agent(llm, TOOLS, prompt_template)
        executor = AgentExecutor(
            agent=agent, tools=TOOLS,
            verbose=True, max_iterations=max_iterations,
            max_execution_time=max_exec_time,
            early_stopping_method="force",
            handle_parsing_errors=True,
            return_intermediate_steps=True,
        )
        result = await executor.ainvoke({"input": context})
        report = result.get("output", "")

        # Deep mode: second-pass structured extraction
        structured = None
        if req.deep_mode and report:
            structured = await _extract_structured(report, llm)

        return {
            "report":      report,
            "structured":  structured,
            "steps":       len(result.get("intermediate_steps", [])),
            "duration_ms": int((time.time() - start) * 1000),
            "model":       req.model,
            "deep_mode":   req.deep_mode,
        }
    except Exception as e:
        log.error(f"Investigation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/triage")
async def triage(req: TriageRequest):
    start = time.time()
    try:
        llm = get_llm(req.model)
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))

    a = req.alert
    prompt = f"""Analyze this security alert and respond in JSON only:

Alert: {json.dumps(a, default=str)[:1500]}

Return ONLY valid JSON with these fields:
{{
  "severity": "critical|high|medium|low|informational",
  "false_positive_probability": 0-100,
  "mitre_tactic": "tactic name or null",
  "mitre_technique": "T1234 or null",
  "summary": "one sentence",
  "recommended_action": "investigate|monitor|close|escalate",
  "key_indicators": ["list", "of", "iocs"]
}}"""

    try:
        response = await llm.ainvoke(prompt)
        text = response.content.strip()
        match = re.search(r'\{[\s\S]*\}', text)
        result = json.loads(match.group()) if match else {"raw": text}
        result["duration_ms"] = int((time.time() - start) * 1000)
        return result
    except Exception as e:
        log.error(f"Triage error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/enrich")
def enrich_direct(req: EnrichRequest):
    """Direct enrichment — structured JSON, Redis-cached. Supports ip/domain/url/hash."""
    indicator = req.indicator.strip()
    ioc_type  = req.type.lower()
    cache_key = f"ioc:{ioc_type}:{indicator}"

    cached = _cache_get(cache_key)
    if cached:
        log.info(f"Cache HIT /enrich: {indicator}")
        data = json.loads(cached)
        data["cached"] = True
        return data

    result: dict = {"indicator": indicator, "type": ioc_type, "vt": None, "abuse": None, "shodan": None, "otx": None, "cached": False}
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    ab_key  = os.getenv("ABUSEIPDB_API_KEY", "")

    # ── VirusTotal ──
    if vt_key:
        try:
            vt_endpoint_map = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files"}
            vt_ep = vt_endpoint_map.get(ioc_type, "ip_addresses")
            lookup = indicator
            if ioc_type == "url":
                import base64
                lookup = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            r = _sync_client.get(
                f"https://www.virustotal.com/api/v3/{vt_ep}/{lookup}",
                headers={"x-apikey": vt_key}
            )
            if r.status_code == 200:
                attr = r.json().get("data", {}).get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                result["vt"] = {
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "country":    attr.get("country", ""),
                    "owner":      attr.get("as_owner", ""),
                    "reputation": attr.get("reputation", 0),
                    "tags":       attr.get("tags", []),
                }
            elif r.status_code == 404:
                result["vt"] = {"error": "Not found in VirusTotal"}
            else:
                result["vt"] = {"error": f"VT HTTP {r.status_code}"}
        except Exception as e:
            result["vt"] = {"error": str(e)}

    # ── AbuseIPDB (IPs only) ──
    if ab_key and ioc_type == "ip":
        try:
            r = _sync_client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": indicator, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": ab_key, "Accept": "application/json"}
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                result["abuse"] = {
                    "score":     d.get("abuseConfidenceScore", 0),
                    "reports":   d.get("totalReports", 0),
                    "country":   d.get("countryCode", ""),
                    "isp":       d.get("isp", ""),
                    "usage":     d.get("usageType", ""),
                    "is_public": d.get("isPublic", True),
                    "domain":    d.get("domain", ""),
                }
            else:
                result["abuse"] = {"error": f"AbuseIPDB HTTP {r.status_code}"}
        except Exception as e:
            result["abuse"] = {"error": str(e)}

    # ── Shodan (IPs only) ──
    if SHODAN_API_KEY and ioc_type == "ip":
        try:
            r = _sync_client.get(
                f"https://api.shodan.io/shodan/host/{indicator}",
                params={"key": SHODAN_API_KEY}
            )
            if r.status_code == 200:
                d = r.json()
                services = []
                for svc in (d.get("data") or [])[:10]:
                    services.append({
                        "port":      svc.get("port"),
                        "transport": svc.get("transport", "tcp"),
                        "product":   svc.get("product", ""),
                        "version":   svc.get("version", ""),
                        "cpe":       svc.get("cpe", []),
                    })
                result["shodan"] = {
                    "org":       d.get("org", ""),
                    "isp":       d.get("isp", ""),
                    "country":   d.get("country_name", ""),
                    "city":      d.get("city", ""),
                    "os":        d.get("os"),
                    "ports":     sorted(d.get("ports", [])),
                    "hostnames": d.get("hostnames", []),
                    "domains":   d.get("domains", []),
                    "vulns":     list(d.get("vulns", {}).keys()),
                    "tags":      d.get("tags", []),
                    "services":  services,
                    "last_update": d.get("last_update", ""),
                }
            elif r.status_code == 404:
                result["shodan"] = {"error": "No Shodan data for this IP"}
            else:
                result["shodan"] = {"error": f"Shodan HTTP {r.status_code}"}
        except Exception as e:
            result["shodan"] = {"error": str(e)}

    # ── OTX AlienVault (all indicator types) ──
    if OTX_API_KEY:
        try:
            otx_type_map = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}
            otx_type = otx_type_map.get(ioc_type, "IPv4")
            # IPv6 detection
            if ioc_type == "ip" and ":" in indicator:
                otx_type = "IPv6"
            r = _sync_client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/general",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                pulse_info = d.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])[:5]
                result["otx"] = {
                    "pulse_count":       pulse_info.get("count", 0),
                    "pulses":            [{"name": p.get("name",""), "tags": p.get("tags",[])[:5],
                                           "malware_families": p.get("malware_families",[]),
                                           "author": p.get("author_name","")} for p in pulses],
                    "reputation":        d.get("reputation", 0),
                    "false_positive":    d.get("false_positive", []),
                    "sections":          d.get("sections", []),
                }
            elif r.status_code == 404:
                result["otx"] = {"error": "Not found in OTX"}
            else:
                result["otx"] = {"error": f"OTX HTTP {r.status_code}"}
        except Exception as e:
            result["otx"] = {"error": str(e)}

    _cache_set(cache_key, json.dumps(result))
    return result


@app.post("/hunt-queries")
async def hunt_queries(req: HuntQueriesRequest):
    """AI-generated threat hunt hypotheses and OpenSearch query suggestions."""
    start = time.time()
    try:
        llm = get_llm(req.model)
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))

    prompt = f"""You are an expert SOC threat hunter. Generate hunt hypotheses and OpenSearch query suggestions.

Indicator type: {req.type}
Indicator value: {req.value}
Context: {req.context or "No additional context"}

Return ONLY valid JSON:
{{
  "summary": "one-sentence hunting strategy",
  "hypotheses": [
    {{"title": "...", "description": "...", "mitre_technique": "T1234", "mitre_tactic": "...", "risk": "high|medium|low"}}
  ],
  "opensearch_queries": [
    {{"name": "...", "description": "...", "field": "data.srcip", "value": "{req.value}"}}
  ],
  "related_iocs": ["list of related indicators to also hunt for"],
  "recommended_tools": ["nmap", "VirusTotal", "etc"]
}}"""

    try:
        response = await llm.ainvoke(prompt)
        text = response.content.strip()
        match = re.search(r'\{[\s\S]*\}', text)
        result = json.loads(match.group()) if match else {"raw": text, "summary": "Parse error"}
        result["duration_ms"] = int((time.time() - start) * 1000)
        return result
    except Exception as e:
        log.error(f"Hunt queries error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ═══════════════════════════════════════════════════════════════
#  SOCPILOTS AI CHAT — Conversational mode with live tool access
#
#  Keeps n8n in the loop (server.js fires n8n background hook).
#  This endpoint provides the actual AI response with tool access.
#  Tools: search_alerts, enrich_ip, query_assets, query_ueba,
#         query_knowledge_base (5 tools — Shodan/TheHive excluded
#         for conversational speed)
# ═══════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    message: str
    history: list[dict] = []   # [{"role": "user|assistant", "content": "..."}]
    username: str = "analyst"
    role: str = "l2"
    model: str = "auto"

@tool
def query_agents(filter_str: str = "all") -> str:
    """
    List Wazuh agents and their status (active/inactive/disconnected).
    Input: 'all' for all agents, or a status filter like 'active', 'inactive', 'disconnected'.
    Returns: agent name, ID, IP, status, last seen, alert count.
    Use this for any question about agent count, status, or activity.
    """
    try:
        headers = {}
        if INTERNAL_TOKEN:
            headers["Authorization"] = f"Bearer {INTERNAL_TOKEN}"
        r = _sync_client.get(f"{WEBAPP_URL}/api/agents", headers=headers)
        if r.status_code != 200:
            return f"Agent lookup failed: {r.status_code}"
        data = r.json()
        agents = data.get("agents", [])
        if not agents:
            return "No agents found"
        flt = filter_str.strip().lower()
        if flt and flt != "all":
            agents = [a for a in agents if a.get("status", "").lower() == flt]
        lines = [f"Total agents: {data.get('total', len(agents))}"]
        for a in agents[:20]:
            lines.append(
                f"  {a['name']} (ID:{a['id']}, IP:{a['ip']}) — "
                f"status:{a['status']} lastSeen:{a.get('lastSeen','?')} "
                f"alerts:{a.get('alertCount',0)}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Agent query error: {e}"


CHAT_TOOLS = [get_threat_summary, search_alerts, enrich_ip, check_cases, query_assets, query_ueba, query_knowledge_base, query_agents, query_log_sources]

# ChatPromptTemplate required by create_tool_calling_agent (native function calling).
# Works with GPT-4o-mini and Mistral — far more reliable than string-based ReAct.
CHAT_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "You are SOCPilots AI, a senior Tier-3 SOC analyst with deep expertise in threat detection, "
     "incident response, SIEM analysis, and threat intelligence. You have real-time access to your "
     "organisation's live security environment.\n\n"
     "ANALYST MINDSET\n"
     "- Think like an experienced threat hunter: correlate data across multiple sources, identify "
     "patterns, and reason about attacker intent and kill-chain stage\n"
     "- Always pull real data before answering — use tools proactively and chain multiple tool calls "
     "to build complete situational awareness before drawing conclusions\n"
     "- When investigating a host, IP, or alert: search_alerts + enrich_ip + check_cases + "
     "query_ueba — do not answer from a single tool alone\n"
     "- Ask: what does the data tell you? What is abnormal? What is the attacker trying to achieve?\n\n"
     "RESPONSE QUALITY\n"
     "- Lead with the key finding or direct answer, then support it with specific evidence from tool results\n"
     "- Include exact numbers, timestamps, rule IDs, agent names, severity levels, and threat scores "
     "from tool results — vague answers are unacceptable\n"
     "- Assess risk clearly (Critical / High / Medium / Low) with justification tied to real data\n"
     "- End with concrete, prioritised next steps the analyst can action immediately\n"
     "- Use markdown formatting: **bold** for critical findings, `code` for IPs/hashes/commands, "
     "headers for sections in longer responses\n"
     "- For multi-step investigations, reason through the data as you gather it\n\n"
     "TOOL SELECTION GUIDE\n"
     "- get_threat_summary: ALWAYS use first for any overview/summary/status request "
     "('summarize threats', 'what happened today', 'last 24h threats', 'any attacks', 'security status'). "
     "Pass hours=N to adjust the lookback window. This is your primary situational-awareness tool.\n"
     "- search_alerts: search for a SPECIFIC indicator — source IP, agent name, rule ID, username, "
     "MITRE technique ID, or keyword. Do NOT call with generic words like 'threats' or 'security'.\n"
     "- enrich_ip: full threat intel (VT + AbuseIPDB + OTX) — always use for any external IP found\n"
     "- check_cases: TheHive cases — check for existing cases on a specific host, IP, or user\n"
     "- query_ueba: user/host behavioural risk scores, anomaly detection, lateral movement\n"
     "- query_assets: asset inventory, OS, open ports, Wazuh agent coverage gaps\n"
     "- query_knowledge_base: MITRE ATT&CK techniques, detection rules, playbooks\n"
     "- query_agents: Wazuh agent status, coverage, last-seen, disconnected endpoints\n"
     "- query_log_sources: active log sources, collection health, cloud integrations\n\n"
     "RESPONSE FORMAT\n"
     "- Lead with concrete data from tools — never state 'no data' without actually calling a tool\n"
     "- Use exact numbers, timestamps, rule IDs, agent names from tool output\n"
     "- Use markdown: **bold** key findings, `code` for IPs/hashes, ## headers for sections\n"
     "- Risk assessment: Critical/High/Medium/Low with justification from real data\n"
     "- End with prioritised, actionable next steps\n\n"
     "Apply expertise in: MITRE ATT&CK, threat hunting, malware analysis, Windows/Linux IR, "
     "Active Directory attacks, and SOC operations."),
    MessagesPlaceholder("chat_history", optional=True),
    ("human", "{input}"),
    MessagesPlaceholder("agent_scratchpad"),
])


def _format_history(history: list[dict]) -> list:
    """Convert history dicts to LangChain message objects for tool-calling agent."""
    messages = []
    for msg in history[-10:]:
        content = str(msg.get("content", ""))[:1000]
        if msg.get("role") == "user":
            messages.append(HumanMessage(content=content))
        else:
            messages.append(AIMessage(content=content))
    return messages


class SSECallbackHandler(AsyncCallbackHandler):
    """Puts tool-lifecycle events into an asyncio.Queue for SSE streaming."""
    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    async def on_tool_start(self, serialized: dict, input_str: str, **kwargs):
        await self.queue.put(("tool_start", {
            "tool": serialized.get("name", "tool"),
            "input": str(input_str)[:200],
        }))

    async def on_tool_end(self, output: str, **kwargs):
        await self.queue.put(("tool_end", None))


@app.post("/chat")
async def chat(req: ChatRequest):
    """Conversational SOCPilots AI with live tool access. Non-streaming."""
    start = time.time()
    try:
        llm = get_llm(req.model)
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))
    try:
        agent = create_tool_calling_agent(llm, CHAT_TOOLS, CHAT_PROMPT)
        executor = AgentExecutor(
            agent=agent, tools=CHAT_TOOLS,
            verbose=False, max_iterations=12,
            max_execution_time=120,
            handle_parsing_errors=True,
            return_intermediate_steps=True,
        )
        result = await executor.ainvoke({
            "input": req.message,
            "chat_history": _format_history(req.history),
        })
        return {
            "response":   result.get("output", ""),
            "tools_used": len(result.get("intermediate_steps", [])),
            "duration_ms": int((time.time() - start) * 1000),
            "ok": True,
        }
    except Exception as e:
        log.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/chat/stream")
async def chat_stream(req: ChatRequest):
    """Conversational SOCPilots AI — SSE stream of tool events + final answer."""
    async def generate():
        queue: asyncio.Queue = asyncio.Queue()
        handler = SSECallbackHandler(queue)

        async def run_agent():
            try:
                llm = get_llm(req.model)
                agent = create_tool_calling_agent(llm, CHAT_TOOLS, CHAT_PROMPT)
                executor = AgentExecutor(
                    agent=agent, tools=CHAT_TOOLS,
                    verbose=False, max_iterations=12,
                    max_execution_time=120,
                    handle_parsing_errors=True,
                )
                # Pass callbacks via RunnableConfig so they propagate through
                # the full LCEL chain (including tool invocations). Passing
                # callbacks only on AgentExecutor's constructor does NOT fire
                # on_tool_start/on_tool_end with create_tool_calling_agent in
                # LangChain 0.2.x.
                cfg = RunnableConfig(callbacks=[handler])
                result = await executor.ainvoke({
                    "input": req.message,
                    "chat_history": _format_history(req.history),
                }, config=cfg)
                await queue.put(("done", result.get("output", "")))
            except Exception as e:
                await queue.put(("error", str(e)[:300]))

        task = asyncio.create_task(run_agent())

        while True:
            try:
                event_type, data = await asyncio.wait_for(queue.get(), timeout=130.0)
                yield f"data: {json.dumps({'type': event_type, 'data': data})}\n\n"
                if event_type in ("done", "error"):
                    break
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'type': 'error', 'data': 'Response timed out after 130s'})}\n\n"
                break

        try:
            await asyncio.wait_for(task, timeout=5.0)
        except (asyncio.TimeoutError, Exception):
            task.cancel()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ═══════════════════════════════════════════════════════════════
#  DARK SOC — Consensus Validation Endpoint
#  Called by playbook-engine.js before destructive actions.
#  Uses a SECOND, independent LLM call to validate the action.
#  Returns: { approved: bool, confidence: float, reasoning: str }
# ═══════════════════════════════════════════════════════════════

class ValidateActionRequest(BaseModel):
    action: str          # e.g. "isolate_host", "kill_process", "disable_user"
    alert: dict
    evidence: str = ""   # investigation report excerpt (first 1500 chars)
    model: str = "auto"  # always uses a different model than primary


@app.post("/validate-action")
async def validate_action(req: ValidateActionRequest):
    """
    Dark SOC consensus gate — a second LLM independently evaluates
    whether a destructive response action is warranted.

    Returns approved=True only if confidence is high and the action
    is proportionate to the threat severity.
    """
    start = time.time()

    # Intentionally use a different model than the primary investigation
    # Primary: GPT-4o-mini (if available) → Secondary: Mistral, and vice versa
    if req.model == "auto":
        secondary_model = "mistral" if OPENAI_API_KEY else "auto"
    else:
        secondary_model = req.model

    try:
        llm = get_llm(secondary_model)
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))

    a = req.alert
    prompt = f"""You are a senior SOC analyst reviewing an automated response action.
A Dark SOC system wants to execute: **{req.action}**

ALERT DETAILS:
- Rule ID: {a.get('ruleId', '?')}
- Severity: {a.get('severity', '?')} (level {a.get('level', '?')})
- Description: {a.get('description', '?')}
- Agent/Host: {a.get('agent', '?')}
- Source IP: {a.get('srcIp', '?')}
- MITRE: {', '.join(a.get('mitre', [])) or 'unknown'}

INVESTIGATION EVIDENCE:
{req.evidence[:1200] if req.evidence else 'No evidence provided'}

TASK: Decide if executing "{req.action}" is APPROVED or REJECTED.

Rules:
- APPROVE only if the evidence clearly justifies this action
- REJECT if false positive probability is high, evidence is weak, or action is disproportionate
- {req.action} is a DESTRUCTIVE action — err on the side of caution

Return ONLY valid JSON:
{{
  "approved": true or false,
  "confidence": 0.0 to 1.0,
  "reasoning": "one sentence justification",
  "false_positive_risk": "low|medium|high"
}}"""

    try:
        response = await llm.ainvoke(prompt)
        text  = response.content.strip()
        match = re.search(r'\{{[\s\S]*\}}', text)
        if not match:
            # Fallback: reject if we can't parse
            return {"approved": False, "confidence": 0.0,
                    "reasoning": "Could not parse validation response — rejecting for safety",
                    "duration_ms": int((time.time() - start) * 1000)}
        result = json.loads(match.group())
        result["duration_ms"] = int((time.time() - start) * 1000)
        log.info(f"[Consensus] action={req.action} approved={result.get('approved')} confidence={result.get('confidence')}")
        return result
    except Exception as e:
        log.error(f"Validate-action error: {e}")
        # Always reject on error — safer than accidentally approving
        return {"approved": False, "confidence": 0.0,
                "reasoning": f"Validation error: {str(e)[:100]} — rejecting for safety",
                "duration_ms": int((time.time() - start) * 1000)}


# ═══════════════════════════════════════════════════════════════
#  LOG SOURCES INTELLIGENCE — Multi-LLM Pipeline
#
#  Pipeline: GPT-mini (routing) → Mistral (deep analysis)
#            → GPT-mini (classify + format final output)
# ═══════════════════════════════════════════════════════════════

class LogSourcesAnalyzeRequest(BaseModel):
    sources: list[dict]


def _get_gpt_mini():
    if OPENAI_API_KEY:
        return ChatOpenAI(model="gpt-4o-mini", api_key=OPENAI_API_KEY, temperature=0)
    return None


def _get_mistral():
    if MISTRAL_API_KEY:
        return ChatMistralAI(model="mistral-large-latest", api_key=MISTRAL_API_KEY, temperature=0)
    return None


# Map internal model identifiers to generic SOC engine labels.
# No vendor or version strings must reach the frontend.
_ENGINE_LABEL: dict[str, str] = {
    "gpt-4o-mini":          "SOC AI Analyzer",
    "gpt-4o":               "SOC AI Analyzer",
    "gpt-4-turbo":          "AI Detection Engine",
    "gpt-4":                "AI Detection Engine",
    "mistral-large-latest": "Threat Analysis Engine",
    "mistral-large":        "Threat Analysis Engine",
    "mistral-medium":       "Threat Analysis Engine",
    "mistral-small-latest": "SOC AI Analyzer",
    "mistral-small":        "SOC AI Analyzer",
}

def _engine(model_id: str) -> str:
    return _ENGINE_LABEL.get(model_id, "AI Detection Engine")


def _parse_json_response(text: str) -> any:
    """Strip markdown fences and parse JSON with bracket-matching fallback."""
    text = text.strip()
    # Strip markdown code fences
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1].lstrip("json\n").strip() if len(parts) > 1 else text

    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Bracket-matching extraction — finds first balanced JSON array or object
    for start_char, end_char in [('[', ']'), ('{', '}')]:
        start = text.find(start_char)
        if start == -1:
            continue
        depth, in_str, escape = 0, False, False
        for i in range(start, len(text)):
            c = text[i]
            if escape:
                escape = False
                continue
            if c == '\\' and in_str:
                escape = True
                continue
            if c == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if c == start_char:
                depth += 1
            elif c == end_char:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break  # try next start_char

    # Greedy regex last resort
    match = re.search(r'[\[{][\s\S]*[\]}]', text)
    if match:
        return json.loads(match.group())
    return json.loads(text)


@app.post("/log-sources/analyze")
async def analyze_log_sources(req: LogSourcesAnalyzeRequest):
    """
    Multi-LLM log sources analysis pipeline.
    GPT-mini handles routing/classification/formatting.
    Mistral handles deep vendor detection and behavioral analysis.
    """
    sources = req.sources[:50]  # cap to prevent abuse
    if not sources:
        raise HTTPException(status_code=400, detail="sources list is empty")

    gpt_mini = _get_gpt_mini()
    mistral  = _get_mistral()

    if not gpt_mini and not mistral:
        raise HTTPException(status_code=503, detail="No LLM API key configured")

    models_used = {
        "routing":    _engine("gpt-4o-mini"          if gpt_mini else "mistral-large-latest"),
        "analysis":   _engine("mistral-large-latest" if mistral  else "gpt-4o-mini"),
        "formatting": _engine("gpt-4o-mini"          if gpt_mini else "mistral-large-latest"),
    }

    # ── Step 1: GPT-mini routing decision ──────────────────────
    routing_llm = gpt_mini or mistral
    routing_map = {}
    try:
        source_summaries = [
            {"id": s.get("source_id"), "type": s.get("type"), "vendor": s.get("vendor"),
             "decoder": s.get("top_decoder"), "groups": s.get("top_groups"),
             "integration": s.get("integration"), "is_new": s.get("is_new"),
             "anomaly": s.get("anomaly"), "confidence": s.get("confidence")}
            for s in sources
        ]
        routing_resp = await routing_llm.ainvoke(
            f"""You are a SOC orchestrator. For each log source, decide if it needs deep Mistral analysis.
Mark as "analyze" if: vendor is unknown, type is unknown/server with low confidence, or anomaly=true or is_new=true.
Mark as "skip" if: well-classified (confidence > 0.8) and not anomalous.

Sources: {json.dumps(source_summaries)}

Return ONLY a JSON array: [{{"id": "...", "decision": "analyze|skip"}}]"""
        )
        decisions = _parse_json_response(routing_resp.content)
        for d in decisions:
            routing_map[str(d.get("id"))] = d.get("decision", "skip")
    except Exception as e:
        log.warning(f"[log-sources] Routing step failed: {e} — analyzing all")
        routing_map = {str(s.get("source_id")): "analyze" for s in sources}

    # ── Step 2: Mistral deep analysis (only flagged sources) ──
    analysis_llm = mistral or gpt_mini
    mistral_results = {}
    to_analyze = [s for s in sources if routing_map.get(str(s.get("source_id"))) == "analyze"]
    for src in to_analyze[:10]:  # cap at 10 deep analyses per call
        try:
            resp = await analysis_llm.ainvoke(
                f"""You are a security data engineer analyzing a Wazuh SIEM log source.

Source metadata (no raw logs, only aggregated stats):
- Name: {src.get('source_name')}
- Current type: {src.get('type')} | Vendor: {src.get('vendor')}
- Protocol: {src.get('protocol')} | Integration: {src.get('integration')}
- Top rule groups: {src.get('top_groups')}
- Top decoder: {src.get('top_decoder')}
- EPS (24h avg): {src.get('eps')} | Events 24h: {src.get('event_count_24h')}
- New source: {src.get('is_new')} | Anomaly flagged: {src.get('anomaly')}
- Severity dist: {src.get('severity_dist')}

Tasks:
1. Identify the most likely vendor and source type
2. Assess if the behavior is normal, suspicious, or anomalous
3. Provide 1-2 specific SOC recommendations

Return ONLY valid JSON (no markdown):
{{"vendor": "...", "type": "firewall|waf|proxy|server|cloud_api|network|unknown", "confidence": 0.0-1.0, "assessment": "normal|suspicious|anomalous", "recommendations": ["..."]}}"""
            )
            mistral_results[str(src.get("source_id"))] = _parse_json_response(resp.content)
        except Exception as e:
            log.warning(f"[log-sources] Mistral analysis failed for {src.get('source_id')}: {e}")

    # ── Step 3: GPT-mini classify & normalize enriched sources ─
    enriched = []
    for src in sources:
        s = dict(src)
        sid = str(s.get("source_id"))
        if sid in mistral_results:
            insight = mistral_results[sid]
            if insight.get("vendor") and insight["vendor"].lower() not in ("unknown", ""):
                s["vendor"]     = insight["vendor"]
                s["confidence"] = insight.get("confidence", s.get("confidence", 0.5))
            if insight.get("type") and insight["type"] != "unknown":
                s["type"] = insight["type"]
            s["ai_assessment"]     = insight.get("assessment", "unknown")
            s["ai_recommendations"]= insight.get("recommendations", [])
        enriched.append(s)

    # ── Step 4: GPT-mini final SOC insights summary ─────────────
    format_llm = gpt_mini or mistral
    ai_insights = []
    try:
        summary_input = [
            {"name": s.get("source_name"), "type": s.get("type"), "vendor": s.get("vendor"),
             "eps": s.get("eps"), "anomaly": s.get("anomaly"),
             "assessment": s.get("ai_assessment", "—")}
            for s in enriched[:20]
        ]
        fmt_resp = await format_llm.ainvoke(
            f"""You are a senior SOC analyst. Write 3-5 concise, actionable insights about this log source inventory.
Focus on: coverage gaps, anomalous sources, high-volume sources, vendor diversity, detection opportunities.

Sources: {json.dumps(summary_input)}

Return ONLY a JSON array of insight strings (no markdown). Be specific and reference source names."""
        )
        ai_insights = _parse_json_response(fmt_resp.content)
        if not isinstance(ai_insights, list):
            ai_insights = [str(ai_insights)]
    except Exception as e:
        log.warning(f"[log-sources] Summary step failed: {e}")
        ai_insights = ["AI analysis complete — review enriched source table for vendor and behavioral assessments"]

    return {
        "enriched_sources": enriched,
        "ai_insights": ai_insights,
        "models_used": models_used,
        "sources_analyzed": len(to_analyze),
        "total_sources": len(sources),
    }


# ═══════════════════════════════════════════════════════════════
#  MITRE ATT&CK COVERAGE INTELLIGENCE — Multi-LLM Pipeline
#
#  Pipeline: GPT-mini (gap prioritization) → Mistral (deep analysis)
#            → GPT-mini (format recommendations)
# ═══════════════════════════════════════════════════════════════

class MitreAnalyzeRequest(BaseModel):
    covered_techniques: list[dict]   # [{id, name, count, rules, agents, coverage_score, tactics}]
    gap_techniques: list[dict]       # [{id, name, tactics}]
    log_sources: list[str]           # available source types: ["proxy","server","cloud_api",...]
    agents: list[str]                # monitored agent names
    summary: dict                    # {covered, gaps, pct, timeframe}


@app.post("/mitre/analyze")
async def analyze_mitre_coverage(req: MitreAnalyzeRequest):
    """
    Multi-LLM MITRE ATT&CK coverage intelligence pipeline.
    GPT-mini handles gap prioritization and recommendation formatting.
    Mistral handles deep gap explanation and attack behavior analysis.
    """
    gpt_mini = _get_gpt_mini()
    mistral  = _get_mistral()

    if not gpt_mini and not mistral:
        raise HTTPException(status_code=503, detail="No LLM API key configured")

    models_used = {
        "gap_prioritization": _engine("gpt-4o-mini"          if gpt_mini else "mistral-large-latest"),
        "deep_analysis":      _engine("mistral-large-latest" if mistral  else "gpt-4o-mini"),
        "recommendations":    _engine("gpt-4o-mini"          if gpt_mini else "mistral-large-latest"),
    }

    covered  = req.covered_techniques[:100]
    gaps     = req.gap_techniques[:200]
    log_srcs = req.log_sources[:20]
    agents   = req.agents[:20]
    summary  = req.summary

    # ── Step 1: GPT-mini — identify top 15 most critical gaps ──
    priority_llm = gpt_mini or mistral
    priority_gaps = []
    try:
        gap_input = [{"id": g["id"], "name": g["name"], "tactics": g.get("tactics", [])} for g in gaps[:50]]
        prio_resp = await priority_llm.ainvoke(
            f"""You are a SOC detection engineer. Select the 15 highest-priority ATT&CK technique gaps to address.

Environment:
- Available log sources: {json.dumps(log_srcs)}
- Coverage: {summary.get('covered_count',0)} of {summary.get('total_techniques',0)} techniques covered ({summary.get('coverage_pct',0)}%)
- Timeframe: {summary.get('timeframe','7d')}

Uncovered gaps: {json.dumps(gap_input)}

Prioritize by:
1. High-impact tactics: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access
2. Techniques detectable with available log sources ({', '.join(log_srcs) or 'unknown'})
3. Commonly seen in enterprise attacks

Return ONLY a JSON array of 15 technique IDs in priority order: ["T1059", "T1566", ...]"""
        )
        priority_ids = _parse_json_response(prio_resp.content)
        if isinstance(priority_ids, list):
            priority_set = {str(p) for p in priority_ids[:15]}
            priority_gaps = [g for g in gaps if g["id"] in priority_set]
    except Exception as e:
        log.warning(f"[mitre-analyze] Gap prioritization failed: {e}")
        priority_gaps = gaps[:15]

    # ── Step 2: Mistral — deep gap analysis ──────────────────────
    analysis_llm = mistral or gpt_mini
    gap_analysis = []
    try:
        covered_json = json.dumps([
            {"id": t["id"], "name": t["name"], "alerts": t.get("count", 0),
             "rules": t.get("rule_count", 0), "score": t.get("score", 0)}
            for t in covered[:20]
        ])
        pgaps_json = json.dumps([
            {"id": g["id"], "name": g["name"], "tactics": g.get("tactics", [])}
            for g in priority_gaps
        ])
        resp = await analysis_llm.ainvoke(
            f"""You are an expert SOC Detection Engineer and MITRE ATT&CK specialist.

Environment telemetry:
- Log sources: {json.dumps(log_srcs)}
- Monitored agents/hosts: {json.dumps(agents)}
- Coverage: {json.dumps(summary)}

Currently covered techniques (evidence): {covered_json}

Priority gaps (no detection coverage): {pgaps_json}

For each gap technique, provide concise (max 120 chars each):
1. why_missing: why it goes undetected with these log sources
2. attack_behavior: what attacker behavior is observable in available telemetry
3. detection_opportunity: one specific Wazuh rule or log source addition

IMPORTANT: Keep all string values under 120 characters. No newlines inside strings.

Return ONLY a valid JSON array, no markdown, no extra text:
[{{"id":"T1059","name":"Command and Scripting Interpreter","tactics":["execution"],"why_missing":"...","attack_behavior":"...","detection_opportunity":"..."}}]"""
        )
        gap_analysis = _parse_json_response(resp.content)
        if not isinstance(gap_analysis, list):
            gap_analysis = []
    except Exception as e:
        log.warning(f"[mitre-analyze] Deep analysis failed: {e}")
        gap_analysis = [{"id": g["id"], "name": g["name"], "tactics": g.get("tactics", []),
                         "why_missing": "Analysis unavailable", "attack_behavior": "—",
                         "detection_opportunity": "Review log source coverage"}
                        for g in priority_gaps[:10]]

    # ── Step 3: GPT-mini — prioritized recommendations ──────────
    format_llm = gpt_mini or mistral
    recommendations = []
    try:
        fmt_resp = await format_llm.ainvoke(
            f"""You are a SOC Detection Engineering lead. Produce 6-8 actionable recommendations to improve ATT&CK coverage.

Environment: coverage={summary.get('coverage_pct',0)}%, log_sources={json.dumps(log_srcs)}, agents={json.dumps(agents)}
Gap analysis: {json.dumps(gap_analysis[:15])}

Group by effort level. Focus on what's achievable with available log sources.

Return ONLY a JSON array (no markdown):
[{{"effort":"quick_win|medium_effort|strategic","title":"Enable Wazuh Auditd on Linux","impact":"Covers 12 gaps in Execution","techniques_covered":["T1059.004","T1222"],"steps":"Brief action description"}}]"""
        )
        recommendations = _parse_json_response(fmt_resp.content)
        if not isinstance(recommendations, list):
            recommendations = []
    except Exception as e:
        log.warning(f"[mitre-analyze] Recommendations step failed: {e}")

    # ── Tactic breakdown — server-side aggregation ───────────────
    # Normalize to lowercase_with_underscores so "Defense Evasion" and
    # "defense_evasion" merge into the same bucket.
    def _norm_tactic(t: str) -> str:
        return t.strip().lower().replace(" ", "_").replace("-", "_")

    tactic_counts: dict = {}
    for tech in covered:
        for tactic in tech.get("tactics", []):
            key = _norm_tactic(tactic)
            tactic_counts.setdefault(key, {"covered": 0, "gaps": 0})
            tactic_counts[key]["covered"] += 1
    for tech in gaps:
        for tactic in tech.get("tactics", []):
            key = _norm_tactic(tactic)
            tactic_counts.setdefault(key, {"covered": 0, "gaps": 0})
            tactic_counts[key]["gaps"] += 1

    tactic_breakdown = []
    for tactic, counts in tactic_counts.items():
        total = counts["covered"] + counts["gaps"]
        pct   = round(counts["covered"] / total * 100) if total else 0
        tactic_breakdown.append({"tactic": tactic, "covered": counts["covered"],
                                  "gaps": counts["gaps"], "total": total, "pct": pct})
    tactic_breakdown.sort(key=lambda x: x["pct"], reverse=True)

    log.info(f"[mitre-analyze] gaps={len(gap_analysis)} recs={len(recommendations)} tactics={len(tactic_breakdown)}")

    return {
        "gap_analysis":         gap_analysis,
        "recommendations":      recommendations,
        "tactic_breakdown":     tactic_breakdown,
        "models_used":          models_used,
        "priority_gaps_count":  len(priority_gaps),
        "total_gaps":           len(gaps),
        "total_covered":        len(covered),
    }


# ═══════════════════════════════════════════════════════════════
#  UEBA EXPLAIN — Direct LLM risk narrative (no agent loop)
# ═══════════════════════════════════════════════════════════════

class UebaDigestRequest(BaseModel):
    top_entities: list
    anomaly_summary: dict
    period_days: int = 7


class UebaExplainRequest(BaseModel):
    entity: str
    profile: dict


@app.post("/ueba/digest")
async def ueba_digest(req: UebaDigestRequest):
    """
    Generate a weekly UEBA threat intelligence digest as Markdown.
    Summarises the worst offenders, anomaly trends, and recommended actions.
    Uses Mistral (fast) with a direct invoke — no agent loop.
    """
    llm = _get_mistral() or _get_gpt_mini()
    if not llm:
        raise HTTPException(status_code=503, detail="No LLM available for UEBA digest")

    # Build entity summary lines
    entity_lines = []
    for e in req.top_entities[:10]:
        name        = e.get("name") or e.get("entity") or "unknown"
        score       = e.get("risk_score", 0)
        anomalies   = e.get("anomaly_count", 0)
        entity_type = e.get("entity_type", "user")
        hosts       = e.get("all_hosts") or []
        host_str    = ", ".join(str(h) for h in hosts[:5]) if hosts else "N/A"
        entity_lines.append(f"- {name} ({entity_type}): risk={score}/100, anomalies={anomalies}, hosts={host_str}")

    entity_block = "\n".join(entity_lines) if entity_lines else "- No high-risk entities detected"

    # Build anomaly trend block
    anomaly_lines = []
    for atype, count in req.anomaly_summary.items():
        anomaly_lines.append(f"- {atype}: {count} occurrence(s)")
    anomaly_block = "\n".join(anomaly_lines) if anomaly_lines else "- No anomalies recorded"

    total_anomalies = sum(req.anomaly_summary.values())
    high_risk_count = sum(1 for e in req.top_entities if (e.get("risk_score") or 0) >= 70)

    prompt_text = f"""You are a senior SOC analyst writing a weekly UEBA threat intelligence digest for the security team.
Write a concise, actionable Markdown report covering the past {req.period_days} days.
Use specific data provided — no generic filler. Be direct and professional.

Data:
- Total entities monitored: {len(req.top_entities)}
- High-risk entities (score ≥70): {high_risk_count}
- Total anomalies detected: {total_anomalies}

Top risk entities:
{entity_block}

Anomaly breakdown:
{anomaly_block}

Write the digest with these EXACT Markdown sections:
## Executive Summary
(2-3 sentences: overall threat posture, headline risk, trend vs typical week)

## Top Risk Entities
(Bullet list: name, score, key concern, recommended immediate action)

## Anomaly Trends
(Which anomaly types are spiking or notable, what they indicate)

## Recommended Actions
(Numbered list of 3-5 prioritised actions for the SOC team this week)

Digest:"""

    from langchain_core.messages import SystemMessage, HumanMessage as HM
    try:
        response = await llm.ainvoke([
            SystemMessage(content="You are a senior SOC analyst producing weekly UEBA threat intelligence digests. Be specific, data-driven, and actionable. Output valid Markdown only."),
            HM(content=prompt_text),
        ])
        digest_md = response.content.strip()
    except Exception as e:
        log.error(f"[ueba/digest] LLM error: {e}")
        raise HTTPException(status_code=500, detail=f"LLM error: {str(e)}")

    return {
        "digest_md": digest_md,
        "period_days": req.period_days,
        "entity_count": len(req.top_entities),
        "high_risk_count": high_risk_count,
        "total_anomalies": total_anomalies,
    }


@app.post("/ueba/explain")
async def ueba_explain(req: UebaExplainRequest):
    """
    Generate a plain-English SOC analyst narrative explaining WHY an entity
    has its current risk score. Uses Mistral (fast) with a direct invoke —
    no agent loop, no tools.
    """
    llm = _get_mistral() or _get_gpt_mini()
    if not llm:
        raise HTTPException(status_code=503, detail="No LLM available for UEBA explanation")

    p = req.profile
    entity_type  = p.get("entity_type", "user")
    risk_score   = p.get("risk_score", 0)
    anomaly_cnt  = p.get("anomaly_count", 0)
    total_events = p.get("total_events", 0)
    last_anomaly = p.get("last_anomaly", "unknown")
    all_hosts    = p.get("all_hosts") or p.get("all_users") or []
    typical_hrs  = p.get("typical_hours", [])

    # Build recent activity summary from logins
    logins = p.get("recent_logins", []) or []
    flagged = [l for l in logins if l.get("flags") or (l.get("deviation", 0) or 0) > 30]
    high_dev = sorted(logins, key=lambda l: l.get("deviation", 0) or 0, reverse=True)[:3]

    flags_summary = ""
    if flagged:
        flag_lines = []
        for l in flagged[:5]:
            fl = l.get("flags") or []
            dev = l.get("deviation") or 0
            host = l.get("host") or l.get("user") or "?"
            flag_lines.append(f"  - {host}: flags={fl}, deviation={dev}")
        flags_summary = "Flagged activity:\n" + "\n".join(flag_lines)

    high_dev_summary = ""
    if high_dev:
        hd_lines = [f"  - {l.get('host') or l.get('user') or '?'}: deviation score {l.get('deviation', 0)}" for l in high_dev]
        high_dev_summary = "Highest deviation events:\n" + "\n".join(hd_lines)

    prompt_text = f"""You are a senior SOC analyst. Explain why this {entity_type} has a behavioral risk score of {risk_score}/100.
Be specific, concise, and actionable. Write 3-5 sentences in plain English.
Focus on the most suspicious indicators and tell the analyst what to investigate first.
Do NOT use generic filler. If the score is low, say so and explain why there is little concern.

Entity: {req.entity}
Type: {entity_type}
Risk Score: {risk_score}/100
Anomaly Count: {anomaly_cnt}
Total Events: {total_events}
Associated Hosts/Users: {', '.join(str(h) for h in all_hosts[:10]) or 'none observed'}
Typical access hours: {', '.join(str(h)+'h' for h in typical_hrs) or 'not established'}
Last anomaly: {last_anomaly}
{flags_summary}
{high_dev_summary}

Analyst narrative:"""

    from langchain_core.messages import SystemMessage, HumanMessage as HM
    try:
        response = await llm.ainvoke([
            SystemMessage(content="You are a senior SOC analyst writing behavioral risk explanations for a UEBA dashboard. Be specific, direct, and actionable."),
            HM(content=prompt_text),
        ])
        explanation = response.content.strip()
    except Exception as e:
        log.error(f"[ueba/explain] LLM error: {e}")
        raise HTTPException(status_code=500, detail=f"LLM error: {str(e)}")

    return {"explanation": explanation, "entity": req.entity, "risk_score": risk_score}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
