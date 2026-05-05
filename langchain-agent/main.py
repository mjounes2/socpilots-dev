"""
SOCPilots — LangChain Multi-Step Investigation Agent
ReAct pattern: Reason → Act → Observe → loop until answer found

Tools available to the agent:
  search_alerts     — query Wazuh/OpenSearch for related alerts
  enrich_ip         — VirusTotal + AbuseIPDB lookup
  check_cases       — search TheHive for related cases
  query_ueba        — ask Neo4j for entity behavior profile
  query_assets      — check if IP/host is in asset inventory

Endpoints:
  POST /investigate   — deep multi-step investigation
  POST /triage        — fast single-step triage
  GET  /health
"""

import os, json, re, time, logging
import httpx
import redis as redis_lib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool
from langchain_openai import ChatOpenAI
from langchain_mistralai import ChatMistralAI
from langchain.prompts import PromptTemplate

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

@tool
def search_alerts(query: str) -> str:
    """
    Search Wazuh/OpenSearch for security alerts related to an IP, hostname, user, or keyword.
    Input: a search string like '192.168.1.5' or 'failed login root' or 'agent_name:webserver'.
    Returns: list of recent matching alerts with timestamp, rule, severity, agent.
    """
    if not OPENSEARCH_URL:
        return "OpenSearch not configured"
    try:
        body = {
            "size": 10,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [{
                        "multi_match": {
                            "query": query,
                            "fields": ["data.srcip", "agent.name", "full_log",
                                       "rule.description", "data.dstuser"]
                        }
                    }],
                    "filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}]
                }
            }
        }
        r = _sync_client.post(
            f"{OPENSEARCH_URL}/{WAZUH_INDEX}/_search",
            json=body,
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS)
        )
        hits = r.json().get("hits", {}).get("hits", [])
        if not hits:
            return "No alerts found matching: " + query
        results = []
        for h in hits:
            s = h["_source"]
            results.append(
                f"[{s.get('@timestamp','')}] Rule {s.get('rule',{}).get('id','')} "
                f"(level {s.get('rule',{}).get('level','?')}) — "
                f"{s.get('rule',{}).get('description','')} | "
                f"Agent: {s.get('agent',{}).get('name','')} | "
                f"SrcIP: {s.get('data',{}).get('srcip','')}"
            )
        return "\n".join(results)
    except Exception as e:
        return f"Error searching alerts: {e}"


@tool
def enrich_ip(ip_address: str) -> str:
    """
    Enrich an IP address with threat intelligence from VirusTotal and AbuseIPDB.
    Input: an IPv4 address like '1.2.3.4'.
    Returns: reputation score, malicious votes, country, ISP, categories.
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

    result_text = "\n".join(results) if results else f"No threat intel API keys configured — cannot enrich {ip}"
    if results:
        _cache_set(f"ioc:ip:{ip}", result_text)
    return result_text


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
        r = _sync_client.post(
            f"{RAG_URL}/search/investigation",
            json={"query": query, "limit": 5},
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


# ── LLM Selection ─────────────────────────────────────────────
def get_llm(model_preference: str = "auto"):
    if model_preference == "mistral" and MISTRAL_API_KEY:
        return ChatMistralAI(
            model="mistral-small-latest",
            api_key=MISTRAL_API_KEY,
            temperature=0,
        )
    if OPENAI_API_KEY:
        return ChatOpenAI(
            model="gpt-4o-mini",
            api_key=OPENAI_API_KEY,
            temperature=0,
        )
    if MISTRAL_API_KEY:
        return ChatMistralAI(
            model="mistral-small-latest",
            api_key=MISTRAL_API_KEY,
            temperature=0,
        )
    raise ValueError("No LLM API key configured (OPENAI_API_KEY or MISTRAL_API_KEY)")


# ── ReAct Prompt ──────────────────────────────────────────────
REACT_PROMPT = PromptTemplate.from_template("""You are an expert SOC analyst. Use tools to investigate the input, then write a Final Answer.

IMPORTANT: After 3-5 tool calls, stop gathering data and write your Final Answer. Do not loop endlessly.

Tools:
{tools}

Tool names: {tool_names}

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

TOOLS = [search_alerts, enrich_ip, check_cases, query_ueba, query_assets, query_knowledge_base]

# ── Request Models ────────────────────────────────────────────
class InvestigateRequest(BaseModel):
    alert: dict | None = None
    message: str | None = None
    model: str = "auto"

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
        "status": "ok",
        "openai":     bool(OPENAI_API_KEY),
        "mistral":    bool(MISTRAL_API_KEY),
        "opensearch": bool(OPENSEARCH_URL),
        "thehive":    bool(THEHIVE_URL),
        "redis":      redis_ok,
        "vt":         bool(os.getenv("VIRUSTOTAL_API_KEY")),
        "abuseipdb":  bool(os.getenv("ABUSEIPDB_API_KEY")),
        "model": "gpt-4o-mini" if OPENAI_API_KEY else ("mistral-small-latest" if MISTRAL_API_KEY else "none"),
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

    try:
        agent = create_react_agent(llm, TOOLS, REACT_PROMPT)
        executor = AgentExecutor(
            agent=agent, tools=TOOLS,
            verbose=True, max_iterations=12,
            max_execution_time=120,
            early_stopping_method="generate",
            handle_parsing_errors=True,
            return_intermediate_steps=True,
        )
        result = await executor.ainvoke({"input": context})
        return {
            "report":      result.get("output", ""),
            "steps":       len(result.get("intermediate_steps", [])),
            "duration_ms": int((time.time() - start) * 1000),
            "model":       req.model,
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

    result: dict = {"indicator": indicator, "type": ioc_type, "vt": None, "abuse": None, "cached": False}
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
