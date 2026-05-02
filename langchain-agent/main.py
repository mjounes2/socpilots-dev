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
from typing import Any
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

http_client = httpx.AsyncClient(verify=False, timeout=30.0)

# ── LangChain Tools ──────────────────────────────────────────

@tool
def search_alerts(query: str) -> str:
    """
    Search Wazuh/OpenSearch for security alerts related to an IP, hostname, user, or keyword.
    Input: a search string like '192.168.1.5' or 'failed login root' or 'agent_name:webserver'.
    Returns: list of recent matching alerts with timestamp, rule, severity, agent.
    """
    import asyncio
    return asyncio.get_event_loop().run_until_complete(_search_alerts(query))

async def _search_alerts(query: str) -> str:
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
        r = await http_client.post(
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
    import asyncio
    return asyncio.get_event_loop().run_until_complete(_enrich_ip(ip_address))

async def _enrich_ip(ip: str) -> str:
    ip = ip.strip()
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
        return f"Invalid IP format: {ip}"
    results = []
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if vt_key:
        try:
            r = await http_client.get(
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
            r = await http_client.get(
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

    return "\n".join(results) if results else f"No API keys configured for {ip}"

@tool
def check_cases(search_term: str) -> str:
    """
    Search TheHive (SP-CM) for existing security cases related to an IP, hostname, or keyword.
    Input: search term like '192.168.1.5' or 'ransomware'.
    Returns: list of matching cases with title, severity, status, creation date.
    """
    import asyncio
    return asyncio.get_event_loop().run_until_complete(_check_cases(search_term))

async def _check_cases(term: str) -> str:
    if not THEHIVE_URL or not THEHIVE_API_KEY:
        return "TheHive not configured"
    try:
        r = await http_client.post(
            f"{THEHIVE_URL}/api/v1/query",
            json=[
                {"_name": "listCase"},
                {"_name": "filter", "_field": "_string", "_value": term},
                {"_name": "page", "from": 0, "to": 5}
            ],
            headers={"Authorization": f"Bearer {THEHIVE_API_KEY}"}
        )
        cases = r.json() if isinstance(r.json(), list) else []
        if not cases:
            return f"No cases found for: {term}"
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
    import asyncio
    return asyncio.get_event_loop().run_until_complete(_query_ueba(entity_name))

async def _query_ueba(name: str) -> str:
    try:
        r = await http_client.get(
            f"{WEBAPP_URL}/api/ueba/graph/{name}",
            headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"}
        )
        if r.status_code != 200:
            return f"UEBA lookup failed: {r.status_code}"
        edges = r.json().get("edges", [])
        if not edges:
            return f"No UEBA data found for entity: {name}"
        summary = f"Found {len(edges)} graph relationships for {name}:\n"
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
    import asyncio
    return asyncio.get_event_loop().run_until_complete(_query_assets(ip_or_hostname))

async def _query_assets(q: str) -> str:
    try:
        r = await http_client.get(
            f"{WEBAPP_URL}/api/assets?q={q}",
            headers={"Authorization": f"Bearer {INTERNAL_TOKEN}"}
        )
        if r.status_code != 200:
            return f"Asset lookup failed: {r.status_code}"
        assets = r.json().get("assets", [])
        if not assets:
            return f"Asset '{q}' not found in inventory"
        a = assets[0]
        ports = ", ".join([f"{p['port']}/{p['service']}" for p in (a.get('open_ports') or [])[:8]])
        return (f"Asset: {a['ip']} | Hostname: {a.get('hostname','—')} | "
                f"OS: {a.get('os_guess','—')} | Open ports: {ports or 'none'} | "
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

# ── ReAct Agent ───────────────────────────────────────────────
REACT_PROMPT = PromptTemplate.from_template("""You are an expert SOC analyst performing a security investigation.
Use the available tools to gather evidence, then provide a structured analysis.

Tools available:
{tools}

Tool names: {tool_names}

Alert to investigate:
{input}

Investigation instructions:
1. Start by searching for related alerts around the same time and IP/host
2. If there's an IP address, enrich it with threat intelligence
3. Check if there are existing TheHive cases related to this incident
4. Query UEBA for behavioral anomalies for involved users/hosts
5. Check the asset inventory for involved IPs/hosts
6. Synthesize all findings into a structured report

Format your response as:
Thought: [your reasoning]
Action: [tool name]
Action Input: [input to the tool]
Observation: [tool result]
... (repeat as needed)
Final Answer: [structured investigation report]

Begin:
{agent_scratchpad}""")

TOOLS = [search_alerts, enrich_ip, check_cases, query_ueba, query_assets]

# ── Request Models ────────────────────────────────────────────
class InvestigateRequest(BaseModel):
    alert: dict | None = None
    message: str | None = None
    model: str = "auto"   # "auto", "openai", "mistral"

class TriageRequest(BaseModel):
    alert: dict
    model: str = "mistral"  # Use Mistral for fast/cheap triage

# ── Endpoints ─────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "openai":  bool(OPENAI_API_KEY),
        "mistral": bool(MISTRAL_API_KEY),
        "opensearch": bool(OPENSEARCH_URL),
        "thehive": bool(THEHIVE_URL),
    }

@app.post("/investigate")
async def investigate(req: InvestigateRequest):
    """
    Deep multi-step investigation using ReAct agent.
    Agent will use 5 tools iteratively to gather evidence.
    """
    start = time.time()
    try:
        llm = get_llm(req.model)
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))

    # Build alert context string
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
            verbose=True, max_iterations=8,
            handle_parsing_errors=True,
            return_intermediate_steps=True,
        )
        result = await executor.ainvoke({"input": context})
        duration_ms = int((time.time() - start) * 1000)
        return {
            "report":       result.get("output", ""),
            "steps":        len(result.get("intermediate_steps", [])),
            "duration_ms":  duration_ms,
            "model":        req.model,
        }
    except Exception as e:
        log.error(f"Investigation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/triage")
async def triage(req: TriageRequest):
    """
    Fast single-step triage: classify severity, false-positive score, MITRE mapping.
    Uses Mistral (cheap, fast) by default.
    """
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
        # Extract JSON even if LLM adds surrounding text
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
