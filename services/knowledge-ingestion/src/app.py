import os
import logging
from functools import wraps
from flask import Flask, jsonify, request
from flask_cors import CORS
from knowledge_ingest import KnowledgeIngestionService

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ── Configuration ────────────────────────────────────────────────
QDRANT_URL  = os.environ.get("QDRANT_URL", "http://qdrant:6333")
RAG_API_KEY = os.environ.get("RAG_API_KEY", "")

_svc: KnowledgeIngestionService | None = None


def _get_service() -> KnowledgeIngestionService:
    global _svc
    if _svc is None:
        _svc = KnowledgeIngestionService()
    return _svc


# ── API key auth ─────────────────────────────────────────────────

def require_api_key(f):
    """Enforce X-API-Key header when RAG_API_KEY is set."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if RAG_API_KEY:
            client_key = request.headers.get("X-API-Key", "")
            if client_key != RAG_API_KEY:
                return jsonify({"error": "Unauthorized — invalid or missing X-API-Key"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Routes ───────────────────────────────────────────────────────

@app.route("/health")
def health():
    """Health check — verifies Qdrant connectivity."""
    try:
        svc = _get_service()
        collections = svc.client.get_collections()
        names = [c.name for c in collections.collections]
        qdrant_ok = svc.collection in names
        return jsonify({
            "status":            "ok" if qdrant_ok else "degraded",
            "qdrant":            True,
            "collection":        svc.collection,
            "collection_exists": qdrant_ok,
        })
    except Exception as e:
        log.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "qdrant": False, "error": str(e)}), 503


@app.route("/ingest", methods=["POST"])
@require_api_key
def ingest():
    body    = request.get_json(silent=True) or {}
    sources = body.get(
        "sources",
        ["mitre", "rules", "incidents", "incident_reports", "response_procedures"],
    )

    try:
        svc     = _get_service()
        results = svc.run_ingestion(sources=sources)
        return jsonify({"status": "ok", "results": results})
    except Exception as e:
        log.error(f"Ingestion error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/stats")
def stats():
    """Return per-type point counts from Qdrant."""
    try:
        svc = _get_service()
        return jsonify({"status": "ok", "stats": svc.get_stats()})
    except Exception as e:
        log.error(f"Stats error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)
