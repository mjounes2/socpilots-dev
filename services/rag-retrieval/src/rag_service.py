import os
import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

NEO4J_URI  = os.environ.get("NEO4J_URI",  "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "socpilots")

log.info("Loading sentence-transformer model…")
_model = SentenceTransformer("all-MiniLM-L6-v2")
log.info("Model loaded.")

_driver = None

def _get_driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    return _driver


class RAGRetrieval:
    def retrieve(self, query: str, limit: int = 5, item_type: str | None = None) -> list[dict]:
        embedding = _model.encode(query).tolist()
        driver = _get_driver()
        with driver.session() as session:
            if item_type:
                result = session.run(
                    """
                    CALL db.index.vector.queryNodes('knowledgeIndex', $limit, $embedding)
                    YIELD node, score
                    WHERE node.type = $item_type
                    RETURN node.id        AS id,
                           node.title     AS title,
                           node.content   AS content,
                           node.type      AS type,
                           node.metadata  AS metadata,
                           score
                    ORDER BY score DESC
                    """,
                    embedding=embedding, limit=limit * 2, item_type=item_type
                )
            else:
                result = session.run(
                    """
                    CALL db.index.vector.queryNodes('knowledgeIndex', $limit, $embedding)
                    YIELD node, score
                    RETURN node.id        AS id,
                           node.title     AS title,
                           node.content   AS content,
                           node.type      AS type,
                           node.metadata  AS metadata,
                           score
                    ORDER BY score DESC
                    """,
                    embedding=embedding, limit=limit
                )
            rows = result.data()

        # parse metadata JSON string if needed
        import json
        out = []
        for r in rows[:limit]:
            meta = r.get("metadata") or "{}"
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            out.append({
                "id":       r["id"],
                "title":    r["title"],
                "content":  r["content"],
                "type":     r["type"],
                "metadata": meta,
                "score":    round(r["score"], 4),
            })
        return out

    def search_investigation(self, alert_description: str, limit: int = 5) -> dict:
        attack_patterns = self.retrieve(alert_description, limit=limit, item_type="AttackPattern")
        similar_incidents = self.retrieve(alert_description, limit=3, item_type="IncidentCase")
        detection_rules = self.retrieve(alert_description, limit=3, item_type="DetectionRule")

        context_lines = []
        for item in attack_patterns:
            meta = item["metadata"]
            context_lines.append(
                f"[MITRE {meta.get('technique_id','?')}] {item['title']} "
                f"(tactic: {meta.get('tactic','?')}, score: {item['score']})"
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
                f"[{meta.get('technique_id','?')}] {item['title']} — "
                f"tactic: {meta.get('tactic','?')} | "
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


@app.route("/health")
def health():
    try:
        driver = _get_driver()
        with driver.session() as s:
            s.run("RETURN 1")
        return jsonify({"status": "ok", "neo4j": True})
    except Exception as e:
        return jsonify({"status": "error", "neo4j": False, "error": str(e)}), 503


@app.route("/retrieve", methods=["POST"])
def retrieve():
    body  = request.get_json(silent=True) or {}
    query = body.get("query", "").strip()
    if not query:
        return jsonify({"error": "query is required"}), 400

    limit     = min(int(body.get("limit", 5)), 20)
    item_type = body.get("type")  # AttackPattern | IncidentCase | DetectionRule | None

    try:
        results = _rag.retrieve(query, limit=limit, item_type=item_type)
        return jsonify({"results": results, "count": len(results)})
    except Exception as e:
        log.error(f"Retrieve error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/search/investigation", methods=["POST"])
def search_investigation():
    body  = request.get_json(silent=True) or {}
    query = body.get("query", "").strip()
    if not query:
        return jsonify({"error": "query is required"}), 400

    limit = min(int(body.get("limit", 5)), 20)
    try:
        result = _rag.search_investigation(query, limit=limit)
        return jsonify(result)
    except Exception as e:
        log.error(f"Investigation search error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/search/hunting", methods=["POST"])
def search_hunting():
    body  = request.get_json(silent=True) or {}
    query = body.get("query", "").strip()
    if not query:
        return jsonify({"error": "query is required"}), 400

    limit = min(int(body.get("limit", 5)), 20)
    try:
        result = _rag.search_hunting(query, limit=limit)
        return jsonify(result)
    except Exception as e:
        log.error(f"Hunting search error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005, debug=False)
