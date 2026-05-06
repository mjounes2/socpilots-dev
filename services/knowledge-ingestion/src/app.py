import os
import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from knowledge_ingest import KnowledgeIngestionService

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

NEO4J_URI  = os.environ.get("NEO4J_URI",  "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "socpilots")

_svc: KnowledgeIngestionService | None = None

def _get_service() -> KnowledgeIngestionService:
    global _svc
    if _svc is None:
        _svc = KnowledgeIngestionService()
    return _svc


@app.route("/health")
def health():
    try:
        svc = _get_service()
        stats = svc.get_stats()
        return jsonify({"status": "ok", "neo4j": True, "stats": stats})
    except Exception as e:
        log.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "neo4j": False, "error": str(e)}), 503


@app.route("/ingest", methods=["POST"])
def ingest():
    body = request.get_json(silent=True) or {}
    sources = body.get("sources", ["mitre", "rules", "incidents"])

    try:
        svc = _get_service()
        results = svc.run_ingestion(sources=sources)
        return jsonify({"status": "ok", "results": results})
    except Exception as e:
        log.error(f"Ingestion error: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/stats")
def stats():
    try:
        svc = _get_service()
        return jsonify({"status": "ok", "stats": svc.get_stats()})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)
