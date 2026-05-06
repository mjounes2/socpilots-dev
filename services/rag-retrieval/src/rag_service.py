"""
SOCPilots — RAG Retrieval Service
Performs semantic search over the Qdrant knowledge base using
BAAI/bge-small-en-v1.5 embeddings (384-dim).
"""

import os
import json
import time
import logging
import numpy as np
from collections import deque
from functools import wraps

from flask import Flask, jsonify, request
from flask_cors import CORS
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ── Configuration ────────────────────────────────────────────────
QDRANT_URL  = os.environ.get("QDRANT_URL", "http://qdrant:6333")
RAG_API_KEY = os.environ.get("RAG_API_KEY", "")
COLLECTION  = "socpilots_knowledge"

# BGE query prefix — required for retrieval queries (not for documents)
BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

# ── Per-route latency tracking (P50/P95) — last 1000 samples each ──
_latency_store: dict[str, deque] = {
    "retrieve":              deque(maxlen=1000),
    "search_investigation":  deque(maxlen=1000),
    "search_hunting":        deque(maxlen=1000),
}

# ── Model init ───────────────────────────────────────────────────
log.info("Loading sentence-transformer model BAAI/bge-small-en-v1.5…")
_model = SentenceTransformer("BAAI/bge-small-en-v1.5")
log.info("Model loaded — 384 dimensions.")

# ── Qdrant client ────────────────────────────────────────────────
_qdrant: QdrantClient | None = None

def _get_qdrant() -> QdrantClient:
    global _qdrant
    if _qdrant is None:
        _qdrant = QdrantClient(url=QDRANT_URL)
    return _qdrant


# ── Helpers ──────────────────────────────────────────────────────

def encode_query(text: str) -> list[float]:
    """Encode a retrieval query with the BGE prefix, return float list."""
    prefixed = BGE_QUERY_PREFIX + text
    return _model.encode(prefixed, normalize_embeddings=True).tolist()


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    arr = np.array(values, dtype=float)
    return round(float(np.percentile(arr, pct)), 4)


def _record_latency(route_key: str, elapsed: float) -> None:
    if route_key in _latency_store:
        _latency_store[route_key].append(elapsed)


# ── API key auth ─────────────────────────────────────────────────

def require_api_key(f):
    """Decorator: enforce X-API-Key header when RAG_API_KEY is configured."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if RAG_API_KEY:
            client_key = request.headers.get("X-API-Key", "")
            if client_key != RAG_API_KEY:
                return jsonify({"error": "Unauthorized — invalid or missing X-API-Key"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Core retrieval logic ─────────────────────────────────────────

class RAGRetrieval:
    def retrieve(self, query: str, limit: int = 5, item_type: str | None = None) -> list[dict]:
        embedding = encode_query(query)
        client = _get_qdrant()

        search_filter = None
        if item_type:
            search_filter = Filter(
                must=[
                    FieldCondition(
                        key="type",
                        match=MatchValue(value=item_type),
                    )
                ]
            )

        hits = client.search(
            collection_name=COLLECTION,
            query_vector=embedding,
            query_filter=search_filter,
            limit=limit,
            with_payload=True,
        )

        out = []
        for hit in hits:
            payload = hit.payload or {}
            meta = payload.get("metadata") or {}
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            out.append({
                "id":      payload.get("id", str(hit.id)),
                "title":   payload.get("title", ""),
                "content": payload.get("content", ""),
                "type":    payload.get("type", ""),
                "metadata": meta,
                "score":   round(hit.score, 4),
            })
        return out

    def search_investigation(self, alert_description: str, limit: int = 5) -> dict:
        attack_patterns  = self.retrieve(alert_description, limit=limit,  item_type="AttackPattern")
        similar_incidents = self.retrieve(alert_description, limit=3,     item_type="IncidentCase")
        detection_rules  = self.retrieve(alert_description, limit=3,     item_type="DetectionRule")

        context_lines = []
        for item in attack_patterns:
            meta = item["metadata"]
            context_lines.append(
                f"[MITRE {meta.get('technique_id', '?')}] {item['title']} "
                f"(tactic: {meta.get('tactic', '?')}, score: {item['score']})"
            )
        for item in similar_incidents:
            context_lines.append(f"[INCIDENT] {item['title']} (score: {item['score']})")
        for item in detection_rules:
            context_lines.append(f"[RULE] {item['title']} (score: {item['score']})")

        return {
            "attack_patterns":   attack_patterns,
            "similar_incidents": similar_incidents,
            "detection_rules":   detection_rules,
            "context_text":      "\n".join(context_lines),
        }

    def search_hunting(self, hypothesis: str, limit: int = 5) -> dict:
        patterns = self.retrieve(hypothesis, limit=limit, item_type="AttackPattern")
        rules    = self.retrieve(hypothesis, limit=3,     item_type="DetectionRule")

        context_lines = []
        for item in patterns:
            meta = item["metadata"]
            context_lines.append(
                f"[{meta.get('technique_id', '?')}] {item['title']} — "
                f"tactic: {meta.get('tactic', '?')} | "
                f"platforms: {', '.join(meta.get('platforms', []))} | "
                f"score: {item['score']}"
            )
        for item in rules:
            context_lines.append(f"[RULE] {item['title']} (score: {item['score']})")

        return {
            "attack_patterns": patterns,
            "detection_rules": rules,
            "context_text":    "\n".join(context_lines),
        }


_rag = RAGRetrieval()


# ── Routes ───────────────────────────────────────────────────────

@app.route("/health")
def health():
    """Health check — verifies Qdrant connectivity. No auth required."""
    try:
        client = _get_qdrant()
        collections = client.get_collections()
        names = [c.name for c in collections.collections]
        qdrant_ok = COLLECTION in names
        return jsonify({
            "status":     "ok" if qdrant_ok else "degraded",
            "qdrant":     True,
            "collection": COLLECTION,
            "collection_exists": qdrant_ok,
            "collections": names,
        })
    except Exception as e:
        log.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "qdrant": False, "error": str(e)}), 503


@app.route("/metrics")
def metrics():
    """Return P50/P95 latency (seconds) per route. No auth required."""
    result = {}
    for route_key, dq in _latency_store.items():
        samples = list(dq)
        result[route_key] = {
            "samples": len(samples),
            "p50_seconds": _percentile(samples, 50),
            "p95_seconds": _percentile(samples, 95),
        }
    return jsonify({"latency": result})


@app.route("/retrieve", methods=["POST"])
@require_api_key
def retrieve():
    t0 = time.time()
    body  = request.get_json(silent=True) or {}
    query = body.get("query", "").strip()
    if not query:
        return jsonify({"error": "query is required"}), 400

    limit     = min(int(body.get("limit", 5)), 20)
    item_type = body.get("type")  # AttackPattern | IncidentCase | DetectionRule | None

    try:
        results = _rag.retrieve(query, limit=limit, item_type=item_type)
        _record_latency("retrieve", time.time() - t0)
        return jsonify({"results": results, "count": len(results)})
    except Exception as e:
        log.error(f"Retrieve error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/search/investigation", methods=["POST"])
@require_api_key
def search_investigation():
    t0 = time.time()
    body  = request.get_json(silent=True) or {}
    query = body.get("query", "").strip()
    if not query:
        return jsonify({"error": "query is required"}), 400

    limit = min(int(body.get("limit", 5)), 20)
    try:
        result = _rag.search_investigation(query, limit=limit)
        _record_latency("search_investigation", time.time() - t0)
        return jsonify(result)
    except Exception as e:
        log.error(f"Investigation search error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/search/hunting", methods=["POST"])
@require_api_key
def search_hunting():
    t0 = time.time()
    body  = request.get_json(silent=True) or {}
    query = body.get("query", "").strip()
    if not query:
        return jsonify({"error": "query is required"}), 400

    limit = min(int(body.get("limit", 5)), 20)
    try:
        result = _rag.search_hunting(query, limit=limit)
        _record_latency("search_hunting", time.time() - t0)
        return jsonify(result)
    except Exception as e:
        log.error(f"Hunting search error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005, debug=False)
