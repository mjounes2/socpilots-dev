"""
SOCPilots Autonomous Investigation — LangGraph State Schema

The State is the shared memory passed between all graph nodes.
Every agent reads and writes to this object.
Designed for zero-human Dark SOC: full autonomous decision-making.
"""
from typing import TypedDict, Annotated, List, Dict, Any, Optional
from operator import add


def merge_dicts(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    """Reducer for parallel node writes — merges dicts without overwriting."""
    if not left:
        return right or {}
    if not right:
        return left
    out = dict(left)
    out.update(right)
    return out


class InvestigationState(TypedDict, total=False):
    # ── Input ──────────────────────────────────────────────────
    alert: Dict[str, Any]
    investigation_id: Optional[int]
    session_id: str
    deep_mode: bool

    # ── Phase 0: Memory retrieval ──────────────────────────────
    prior_investigations: List[Dict[str, Any]]
    entity_reputation: Dict[str, Any]
    known_iocs: List[Dict[str, Any]]

    # ── Phase 1: Triage (fast initial assessment) ──────────────
    triage_verdict: str               # "true_positive" | "false_positive" | "suspicious" | "inconclusive"
    triage_confidence: float          # 0.0 - 1.0
    triage_fp_probability: int        # 0 - 100
    triage_summary: str
    triage_reasoning: str

    # ── Phase 2: Parallel enrichment (merged from multiple nodes) ──
    enrichments: Annotated[Dict[str, Any], merge_dicts]
    # Keys: ioc_intel, ueba_profile, threat_hunt, case_history, shodan, knowledge_base

    # ── Phase 3: Correlation synthesis ─────────────────────────
    correlation_score: float          # 0.0 - 1.0
    attack_chain: List[Dict[str, Any]]
    mitre_techniques: List[str]
    severity_assessment: str          # "critical" | "high" | "medium" | "low" | "benign"

    # ── Phase 4: Consensus verdict (two-LLM agreement) ─────────
    primary_verdict: Dict[str, Any]
    consensus_verdict: Dict[str, Any]
    consensus_reached: bool
    consensus_confidence: float

    # ── Phase 5: Action planning ───────────────────────────────
    planned_actions: List[Dict[str, Any]]
    # Each action: { type, target, reason, confidence, reversible }

    # ── Phase 6: Safety gate ───────────────────────────────────
    safety_status: str                # "approved" | "blocked" | "partial"
    safety_blocks: List[Dict[str, Any]]
    safety_reasons: List[str]

    # ── Phase 7: Execution ─────────────────────────────────────
    executed_actions: List[Dict[str, Any]]
    failed_actions: List[Dict[str, Any]]
    case_id: Optional[str]

    # ── Phase 8: Final report ──────────────────────────────────
    final_report: str
    structured_verdict: Dict[str, Any]

    # ── Audit trail (append-only) ──────────────────────────────
    node_trace: Annotated[List[Dict[str, Any]], add]
    errors: Annotated[List[str], add]

    # ── Metadata ───────────────────────────────────────────────
    started_at: float
    completed_at: Optional[float]
    duration_ms: Optional[int]


def empty_state(alert: Dict[str, Any], session_id: str = "", deep_mode: bool = True) -> InvestigationState:
    """Initialize a fresh investigation state."""
    import time
    return {
        "alert": alert,
        "session_id": session_id or f"auto_{int(time.time()*1000)}",
        "deep_mode": deep_mode,
        "prior_investigations": [],
        "entity_reputation": {},
        "known_iocs": [],
        "enrichments": {},
        "attack_chain": [],
        "mitre_techniques": [],
        "planned_actions": [],
        "safety_blocks": [],
        "safety_reasons": [],
        "executed_actions": [],
        "failed_actions": [],
        "node_trace": [],
        "errors": [],
        "started_at": time.time(),
        "completed_at": None,
        "duration_ms": None,
        "consensus_reached": False,
        "safety_status": "pending",
    }
