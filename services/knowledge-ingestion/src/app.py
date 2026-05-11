import hashlib
import os
import logging
from functools import wraps
from flask import Flask, jsonify, request
from flask_cors import CORS
from knowledge_ingest import KnowledgeIngestionService
from file_processor import validate_file, extract_text, chunk_text
from qdrant_client.models import (
    Distance, VectorParams, PointStruct,
    Filter, FieldCondition, MatchValue, MatchAny,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ── Configuration ────────────────────────────────────────────────
QDRANT_URL       = os.environ.get("QDRANT_URL", "http://qdrant:6333")
QDRANT_API_KEY   = os.environ.get("QDRANT_API_KEY", "") or None
RAG_API_KEY      = os.environ.get("RAG_API_KEY", "")
EVIDENCE_COLLECTION = "socpilots_evidence"

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


# ── Evidence collection helpers ──────────────────────────────────

def _ensure_evidence_collection(client) -> None:
    try:
        client.create_collection(
            collection_name=EVIDENCE_COLLECTION,
            vectors_config=VectorParams(size=384, distance=Distance.COSINE),
        )
        log.info("Created Qdrant collection '%s'", EVIDENCE_COLLECTION)
    except Exception as e:
        err = str(e).lower()
        if "already exists" not in err and "conflict" not in err:
            log.warning("Evidence collection setup warning: %s", e)


def _delete_evidence_points(client, file_id: int) -> None:
    """Remove all Qdrant points belonging to a given file_id."""
    try:
        client.delete(
            collection_name=EVIDENCE_COLLECTION,
            points_selector=Filter(
                must=[FieldCondition(key="file_id", match=MatchValue(value=file_id))]
            ),
        )
    except Exception as exc:
        log.warning("Could not delete evidence points for file_id=%s: %s", file_id, exc)


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


@app.route("/add_document", methods=["POST"])
@require_api_key
def add_document():
    """
    Embed and upsert a single document into socpilots_knowledge.
    Body: { item_id, title, description, item_type, source, metadata }
    Used for cross-investigation memory.
    """
    body = request.get_json(silent=True) or {}
    item_id     = body.get("item_id", "")
    title       = body.get("title", "")
    description = body.get("description", "")
    item_type   = body.get("item_type", "past_investigation")
    source      = body.get("source", "investigation")
    metadata    = body.get("metadata", {})

    if not item_id or not title or not description:
        return jsonify({"error": "item_id, title, and description are required"}), 400

    try:
        svc = _get_service()
        svc._upsert_knowledge_item(
            item_id=item_id,
            title=title,
            description=description,
            item_type=item_type,
            source=source,
            metadata=metadata,
        )
        return jsonify({"status": "ok", "item_id": item_id})
    except Exception as e:
        log.error(f"add_document error: {e}")
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


@app.route("/upload", methods=["POST"])
@require_api_key
def upload_evidence():
    """
    Receive a file upload, extract text, generate embeddings, store in Qdrant.
    Expects multipart/form-data with fields:
      file       — the file bytes
      file_id    — integer Postgres ID (for linking)
      uploaded_by — username
      alert_id, case_id, investigation_id — optional linkage metadata
    Returns: { status, chunk_count, point_ids, extracted_text_preview, sha256 }
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    f = request.files['file']
    data = f.read()
    filename = f.filename or 'unknown'

    file_id        = request.form.get('file_id', '0')
    uploaded_by    = request.form.get('uploaded_by', 'unknown')
    alert_id       = request.form.get('alert_id') or None
    case_id        = request.form.get('case_id') or None
    investigation_id = request.form.get('investigation_id') or None

    # Validate
    ok, mime, err = validate_file(data, filename)
    if not ok:
        return jsonify({"error": err}), 422

    # SHA-256 fingerprint
    sha256 = hashlib.sha256(data).hexdigest()

    # Extract text
    text = extract_text(data, mime, filename)
    chunks = chunk_text(text)

    if not chunks:
        return jsonify({
            "status": "ok",
            "chunk_count": 0,
            "point_ids": [],
            "extracted_text_preview": "",
            "sha256": sha256,
        })

    svc = _get_service()
    _ensure_evidence_collection(svc.client)

    # Remove any previous embedding for this file_id (re-upload scenario)
    _delete_evidence_points(svc.client, int(file_id))

    points = []
    point_ids = []
    for idx, chunk in enumerate(chunks):
        embedding = svc._embed(chunk)
        # Stable point ID: hash of (file_id, chunk_index)
        raw_id = f"evidence:{file_id}:{idx}"
        pt_id  = abs(hash(raw_id)) % (2 ** 63)
        point_ids.append(pt_id)
        points.append(PointStruct(
            id=pt_id,
            vector=embedding,
            payload={
                "file_id":         int(file_id),
                "filename":        filename,
                "mime_type":       mime,
                "chunk_index":     idx,
                "chunk_text":      chunk,
                "uploaded_by":     uploaded_by,
                "alert_id":        alert_id,
                "case_id":         case_id,
                "investigation_id": investigation_id,
                "sha256":          sha256,
            },
        ))

    # Batch upsert in groups of 100
    for i in range(0, len(points), 100):
        svc.client.upsert(
            collection_name=EVIDENCE_COLLECTION,
            points=points[i:i + 100],
        )

    log.info("Embedded file_id=%s (%s) → %d chunks", file_id, filename, len(chunks))

    return jsonify({
        "status":                "ok",
        "chunk_count":           len(chunks),
        "point_ids":             point_ids,
        "extracted_text_preview": text[:3000],
        "sha256":                sha256,
    })


@app.route("/evidence/search", methods=["POST"])
@require_api_key
def evidence_search():
    """
    Semantic search over the evidence collection.
    Body: { query, limit, file_id (optional), case_id (optional) }
    """
    body  = request.get_json(silent=True) or {}
    query = body.get("query", "").strip()
    if not query:
        return jsonify({"error": "query required"}), 400

    limit     = min(int(body.get("limit", 5)), 20)
    file_id   = body.get("file_id")
    case_id   = body.get("case_id")

    svc = _get_service()
    _ensure_evidence_collection(svc.client)

    # Build optional filter
    must = []
    if file_id is not None:
        must.append(FieldCondition(key="file_id", match=MatchValue(value=int(file_id))))
    if case_id:
        must.append(FieldCondition(key="case_id", match=MatchValue(value=case_id)))

    qfilter = Filter(must=must) if must else None

    # BGE query prefix for retrieval
    prefixed = "Represent this sentence for searching relevant passages: " + query
    vec = svc.model.encode(prefixed, normalize_embeddings=True).tolist()

    results = svc.client.search(
        collection_name=EVIDENCE_COLLECTION,
        query_vector=vec,
        query_filter=qfilter,
        limit=limit,
        with_payload=True,
    )

    hits = [
        {
            "score":       round(r.score, 4),
            "file_id":     r.payload.get("file_id"),
            "filename":    r.payload.get("filename"),
            "mime_type":   r.payload.get("mime_type"),
            "chunk_index": r.payload.get("chunk_index"),
            "chunk_text":  r.payload.get("chunk_text", "")[:400],
            "uploaded_by": r.payload.get("uploaded_by"),
            "case_id":     r.payload.get("case_id"),
            "alert_id":    r.payload.get("alert_id"),
        }
        for r in results
    ]

    return jsonify({"status": "ok", "hits": hits, "total": len(hits)})


@app.route("/evidence/delete", methods=["POST"])
@require_api_key
def evidence_delete():
    """Remove all Qdrant points for a given file_id."""
    body    = request.get_json(silent=True) or {}
    file_id = body.get("file_id")
    if file_id is None:
        return jsonify({"error": "file_id required"}), 400
    svc = _get_service()
    _ensure_evidence_collection(svc.client)
    _delete_evidence_points(svc.client, int(file_id))
    return jsonify({"status": "ok", "file_id": file_id})


@app.route("/evidence/stats")
def evidence_stats():
    """Return evidence collection point count."""
    try:
        svc = _get_service()
        _ensure_evidence_collection(svc.client)
        info = svc.client.get_collection(EVIDENCE_COLLECTION)
        return jsonify({
            "status":      "ok",
            "collection":  EVIDENCE_COLLECTION,
            "point_count": info.points_count or 0,
        })
    except Exception as e:
        log.error("Evidence stats error: %s", e)
        return jsonify({"status": "error", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)
