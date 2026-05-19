"""
SOCPilots Autonomous Investigation — LangGraph Engine

Multi-agent supervisor graph for ZERO-HUMAN Dark SOC operations.

Graph topology:

  START → memory → triage
                     ├─ close_fp ──────────────────────────────┐
                     ▼ enrich                                  │
                  [fanout] ──┬─ ioc_intel ─┐                   │
                              ├─ shodan ────┤                   │
                              ├─ ueba ──────┤                   │
                              ├─ threat_hunt┤→ correlation →    │
                              ├─ case_history                   │
                              ├─ assets ────┤    consensus →    │
                              └─ knowledge ─┘    │              │
                                                  ├─ plan_action │
                                                  │  └→ planner →│
                                                  │    safety →  │
                                                  │    executor →│
                                                  ├─ save_only ──┤
                                                  ├─ close_fp ───┤
                                                  └─ no_consensus┤
                                                                 ▼
                                                            reporter → persist → END
"""
import logging
from typing import Any, Dict

from langgraph.graph import StateGraph, END, START

from .state import InvestigationState, empty_state
from .memory import memory_node, persist_node
from .safety import safety_gate_node
from .agents.triage import triage_node, route_after_triage
from .agents.enrichment import (
    ioc_enrichment_node, shodan_node, ueba_node,
    threat_hunt_node, case_history_node, knowledge_base_node, assets_node,
)
from .agents.correlation import correlation_node
from .agents.verdict import consensus_node, route_after_consensus
from .agents.planner import planner_node
from .agents.executor import executor_node
from .agents.reporter import reporter_node

log = logging.getLogger(__name__)

# Optional in-memory checkpointer (Redis can be added later via langgraph-checkpoint-redis)
_checkpointer = None
try:
    from langgraph.checkpoint.memory import MemorySaver
    _checkpointer = MemorySaver()
    log.info("[engine] Using in-memory checkpointer")
except Exception as e:
    log.warning(f"[engine] No checkpointer available: {e}")


def _fanout_node(state: InvestigationState) -> Dict[str, Any]:
    """Pass-through node that splits flow into parallel enrichment branches."""
    return {"node_trace": [{"node": "fanout"}]}


def build_graph():
    """Compile the autonomous investigation graph."""
    g = StateGraph(InvestigationState)

    # ── Nodes ──
    g.add_node("memory",          memory_node)
    g.add_node("triage",          triage_node)
    g.add_node("fanout",          _fanout_node)
    g.add_node("ioc_intel",       ioc_enrichment_node)
    g.add_node("shodan",          shodan_node)
    g.add_node("ueba",            ueba_node)
    g.add_node("threat_hunt",     threat_hunt_node)
    g.add_node("case_history",    case_history_node)
    g.add_node("assets",          assets_node)
    g.add_node("knowledge_base",  knowledge_base_node)
    g.add_node("correlation",     correlation_node)
    g.add_node("consensus",       consensus_node)
    g.add_node("planner",         planner_node)
    g.add_node("safety_gate",     safety_gate_node)
    g.add_node("executor",        executor_node)
    g.add_node("reporter",        reporter_node)
    g.add_node("persist",         persist_node)

    # ── Edges ──
    g.add_edge(START, "memory")
    g.add_edge("memory", "triage")

    g.add_conditional_edges("triage", route_after_triage, {
        "enrich":    "fanout",
        "close_fp":  "reporter",
    })

    # Parallel fan-out from "fanout" — all 7 enrichment nodes run concurrently.
    # LangGraph blocks correlation until ALL parent edges have completed.
    PARALLEL_ENRICHMENT = [
        "ioc_intel", "shodan", "ueba", "threat_hunt",
        "case_history", "assets", "knowledge_base",
    ]
    for node in PARALLEL_ENRICHMENT:
        g.add_edge("fanout", node)
        g.add_edge(node, "correlation")

    g.add_edge("correlation", "consensus")

    g.add_conditional_edges("consensus", route_after_consensus, {
        "plan_action":   "planner",
        "save_only":     "reporter",
        "close_fp":      "reporter",
        "no_consensus":  "reporter",
    })

    g.add_edge("planner", "safety_gate")
    g.add_edge("safety_gate", "executor")
    g.add_edge("executor", "reporter")
    g.add_edge("reporter", "persist")
    g.add_edge("persist", END)

    return g.compile(checkpointer=_checkpointer) if _checkpointer else g.compile()


# Singleton compiled graph
_COMPILED_GRAPH = None

def get_graph():
    global _COMPILED_GRAPH
    if _COMPILED_GRAPH is None:
        _COMPILED_GRAPH = build_graph()
        log.info("[engine] Autonomous investigation graph compiled")
    return _COMPILED_GRAPH


def run_autonomous_investigation(alert: dict, session_id: str = "", deep_mode: bool = True) -> dict:
    """Execute a complete autonomous investigation. Returns final state."""
    graph = get_graph()
    state = empty_state(alert, session_id=session_id, deep_mode=deep_mode)
    config = {"configurable": {"thread_id": state["session_id"]}, "recursion_limit": 50}

    try:
        final = graph.invoke(state, config=config)
        log.info(f"[engine] Investigation complete: severity={final.get('severity_assessment')} "
                 f"executed={len(final.get('executed_actions', []))} duration={final.get('duration_ms')}ms")
        return final
    except Exception as e:
        log.exception(f"[engine] Investigation failed: {e}")
        return {
            **state,
            "errors": [f"engine_failure: {str(e)[:300]}"],
            "final_report": f"# Autonomous Investigation Failed\n\nEngine error: {e}",
            "structured_verdict": {
                "verdict": "inconclusive", "autonomous": True, "engine": "langgraph",
                "error": str(e)[:200],
            },
        }


async def stream_autonomous_investigation(alert: dict, session_id: str = "", deep_mode: bool = True):
    """Async streaming: yield each node completion event."""
    graph = get_graph()
    state = empty_state(alert, session_id=session_id, deep_mode=deep_mode)
    config = {"configurable": {"thread_id": state["session_id"]}, "recursion_limit": 50}
    async for event in graph.astream(state, config=config, stream_mode="updates"):
        yield event
