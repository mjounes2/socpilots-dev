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

    return "\n".join(results) if results else f"No threat intel API keys configured — cannot enrich {ip}"


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

TOOLS = [search_alerts, enrich_ip, check_cases, query_ueba, query_assets]

# ── Request Models ────────────────────────────────────────────
class InvestigateRequest(BaseModel):
    alert: dict | None = None
    message: str | None = None
    model: str = "auto"

class TriageRequest(BaseModel):
    alert: dict
    model: str = "mistral"

# ── Endpoints ─────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "openai":  bool(OPENAI_API_KEY),
        "mistral": bool(MISTRAL_API_KEY),
        "opensearch": bool(OPENSEARCH_URL),
        "thehive": bool(THEHIVE_URL),
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
