"""ueba-ml — Unsupervised ML anomaly scoring for SOCPilots UEBA.

Periodic pipeline (every 15 min):
  1. Extract feature vectors for all users from Neo4j
  2. Score with IsolationForest + per-user z-score + DBSCAN peer-distance
  3. Compute composite ml_score = max(three normalized scores)
  4. Persist back to Neo4j User nodes

Endpoints:
  GET  /health                   service liveness
  POST /score-all                manual trigger (admin)
  GET  /score/<entity>           single-entity score (uses cache from latest run)
  GET  /explain/<entity>         per-feature contribution + peer comparison
  GET  /peers/<entity>           peer group members
  GET  /stats                    last-run telemetry
"""
import os
import time
import threading
import logging
from datetime import datetime, timezone
from flask import Flask, jsonify, request, abort
from neo4j import GraphDatabase

from src.features import extract_features, FEATURE_NAMES
from src.models import score_all

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [ueba-ml] %(message)s",
)
log = logging.getLogger(__name__)

# ── Config ───────────────────────────────────────────────────
NEO4J_URI      = os.environ.get("NEO4J_URI",  "bolt://neo4j:7687")
NEO4J_USER     = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD") or os.environ.get("NEO4J_PASS", "")
SCORE_INTERVAL = int(os.environ.get("UEBA_ML_INTERVAL_SEC", "900"))  # 15 min
FEATURE_HOURS  = int(os.environ.get("UEBA_ML_WINDOW_HOURS", "24"))
API_KEY        = os.environ.get("UEBA_ML_API_KEY", "")  # optional auth for admin endpoints

# Last-run cache
_LAST_RUN: dict = {
    "at": None,
    "duration_sec": 0,
    "users_scored": 0,
    "errors": [],
    "scores_by_user": {},   # name → score dict (for /score/<entity> lookup)
}
_LAST_RUN_LOCK = threading.Lock()

_driver = None


def get_driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD),
            max_connection_lifetime=300,
        )
    return _driver


# ── Persistence: write ML scores back to Neo4j ────────────────
WRITE_QUERY = """
UNWIND $rows AS row
MATCH (u:User {name: row.name})
SET u.ml_score             = row.ml_score,
    u.ml_iforest_score     = row.ml_iforest_score,
    u.ml_zscore            = row.ml_zscore,
    u.ml_peer_distance     = row.ml_peer_distance,
    u.ml_peer_group        = row.ml_peer_group,
    u.ml_top_features_json = row.top_features_json,
    u.ml_last_scored_at    = $at
RETURN count(u) AS updated
"""


def persist_scores(scored: list) -> int:
    """Write scores back to Neo4j in one UNWIND batch."""
    if not scored:
        return 0
    import json
    rows = []
    for s in scored:
        rows.append({
            "name":              s["name"],
            "ml_score":          float(s["ml_score"]),
            "ml_iforest_score":  float(s["ml_iforest_score"]),
            "ml_zscore":         float(s["ml_zscore"]),
            "ml_peer_distance":  float(s["ml_peer_distance"]),
            "ml_peer_group":     int(s["ml_peer_group"]),
            "top_features_json": json.dumps(s["ml_top_features"] or []),
        })
    at = datetime.now(timezone.utc).isoformat()
    with get_driver().session() as sess:
        r = sess.run(WRITE_QUERY, {"rows": rows, "at": at}).single()
        return int(r["updated"] or 0)


# ── Main scoring loop ────────────────────────────────────────
def run_scoring() -> dict:
    start = time.time()
    errors = []
    users_scored = 0
    scores_by_user = {}

    try:
        log.info(f"Starting ML scoring run (window={FEATURE_HOURS}h)…")
        X, names, rows = extract_features(get_driver(), hours=FEATURE_HOURS)
        log.info(f"Extracted {len(names)} user feature vectors")

        if len(names) == 0:
            errors.append("no feature data — graph empty?")
        else:
            scored = score_all(X, names, FEATURE_NAMES)
            users_scored = persist_scores(scored)
            log.info(f"Persisted {users_scored} ML scores")

            # Cache for /score/<entity> lookups
            scores_by_user = {s["name"]: s for s in scored}

    except Exception as e:
        log.exception(f"ML run failed: {e}")
        errors.append(str(e)[:300])

    duration = time.time() - start
    with _LAST_RUN_LOCK:
        _LAST_RUN.update({
            "at": datetime.now(timezone.utc).isoformat(),
            "duration_sec": round(duration, 2),
            "users_scored": users_scored,
            "errors": errors,
            "scores_by_user": scores_by_user,
        })
    log.info(f"ML run complete — {users_scored} users, {duration:.1f}s, {len(errors)} errors")
    return dict(_LAST_RUN)


# ── Background scheduler ─────────────────────────────────────
def scheduler_loop():
    # Wait 60s after boot so Neo4j is reachable
    time.sleep(60)
    while True:
        try:
            run_scoring()
        except Exception as e:
            log.exception(f"scheduler error: {e}")
        time.sleep(SCORE_INTERVAL)


# ── Flask app ────────────────────────────────────────────────
app = Flask(__name__)


def _check_api_key():
    if not API_KEY:
        return
    if request.headers.get("X-API-Key") != API_KEY:
        abort(403, "invalid api key")


@app.get("/health")
def health():
    try:
        with get_driver().session() as s:
            s.run("RETURN 1").single()
        neo4j_ok = True
    except Exception as e:
        neo4j_ok = False
        log.warning(f"neo4j ping failed: {e}")
    with _LAST_RUN_LOCK:
        last = dict(_LAST_RUN)
        last.pop("scores_by_user", None)  # don't dump everyone in health
    return jsonify({
        "ok":           True,
        "service":      "ueba-ml",
        "neo4j":        neo4j_ok,
        "last_run":     last,
        "interval_sec": SCORE_INTERVAL,
        "window_hours": FEATURE_HOURS,
    })


@app.get("/stats")
def stats():
    with _LAST_RUN_LOCK:
        last = dict(_LAST_RUN)
    scores = last.pop("scores_by_user", {}) or {}
    high = sum(1 for s in scores.values() if s["ml_score"] >= 70)
    return jsonify({
        **last,
        "high_anomaly_count": high,
        "total_scored":       len(scores),
    })


@app.post("/score-all")
def trigger_run():
    _check_api_key()
    res = run_scoring()
    res = dict(res); res.pop("scores_by_user", None)
    return jsonify(res)


@app.get("/score/<path:entity>")
def get_score(entity):
    with _LAST_RUN_LOCK:
        score = _LAST_RUN["scores_by_user"].get(entity)
    if score:
        return jsonify(score)

    # Fallback: look up from Neo4j (in case of webapp restart but scores persisted)
    try:
        with get_driver().session() as s:
            r = s.run(
                """MATCH (u:User {name: $name})
                   RETURN coalesce(u.ml_score, 0)          AS ml_score,
                          coalesce(u.ml_iforest_score, 0)  AS ml_iforest_score,
                          coalesce(u.ml_zscore, 0)         AS ml_zscore,
                          coalesce(u.ml_peer_distance, 0)  AS ml_peer_distance,
                          coalesce(u.ml_peer_group, -1)    AS ml_peer_group,
                          u.ml_top_features_json           AS top_features_json,
                          u.ml_last_scored_at              AS scored_at""",
                {"name": entity}
            ).single()
            if not r:
                return jsonify({"error": "not found"}), 404
            import json
            tf_raw = r["top_features_json"]
            top_features = json.loads(tf_raw) if tf_raw else []
            return jsonify({
                "name":              entity,
                "ml_score":          float(r["ml_score"] or 0),
                "ml_iforest_score":  float(r["ml_iforest_score"] or 0),
                "ml_zscore":         float(r["ml_zscore"] or 0),
                "ml_peer_distance":  float(r["ml_peer_distance"] or 0),
                "ml_peer_group":     int(r["ml_peer_group"] or -1),
                "ml_top_features":   top_features,
                "ml_last_scored_at": r["scored_at"],
            })
    except Exception as e:
        log.error(f"score/{entity}: {e}")
        return jsonify({"error": str(e)}), 500


@app.get("/explain/<path:entity>")
def explain_entity(entity):
    """Detailed explanation: feature values + z-scores vs population."""
    with _LAST_RUN_LOCK:
        scored = _LAST_RUN["scores_by_user"].get(entity)
    if not scored:
        return jsonify({"error": "not found in latest run", "hint": "call /score-all first"}), 404
    return jsonify({
        "name":            entity,
        "ml_score":        scored["ml_score"],
        "components": {
            "isolation_forest": scored["ml_iforest_score"],
            "z_score":          scored["ml_zscore"],
            "peer_distance":    scored["ml_peer_distance"],
        },
        "top_features":    scored["ml_top_features"],
        "peer_group":      scored["ml_peer_group"],
        "interpretation":  _interpret(scored),
    })


def _interpret(s: dict) -> str:
    parts = []
    if s["ml_score"] >= 80:
        parts.append("HIGH anomaly score — strongly recommend investigation.")
    elif s["ml_score"] >= 50:
        parts.append("Moderate anomaly — worth review.")
    else:
        parts.append("Low anomaly score — likely normal.")

    if s["ml_peer_group"] == -1:
        parts.append("Behaves unlike any peer cluster.")
    if s["ml_zscore"] >= 70:
        parts.append("Activity volume is far above own historical baseline.")
    if s["ml_iforest_score"] >= 70:
        parts.append("Isolation Forest flags as global outlier.")

    feats = s.get("ml_top_features") or []
    if feats:
        names = ", ".join(f["feature"] for f in feats[:2])
        parts.append(f"Dominant features: {names}.")
    return " ".join(parts)


@app.get("/peers/<path:entity>")
def peers(entity):
    """Return other users in the same peer group."""
    with _LAST_RUN_LOCK:
        scored = _LAST_RUN["scores_by_user"].get(entity)
        all_scored = _LAST_RUN["scores_by_user"]
    if not scored:
        return jsonify({"error": "not found"}), 404
    group = scored["ml_peer_group"]
    if group == -1:
        return jsonify({"entity": entity, "peer_group": -1, "peers": [], "note": "noise point — no peers"})
    peers_list = [
        {"name": k, "ml_score": v["ml_score"]}
        for k, v in all_scored.items()
        if v["ml_peer_group"] == group and k != entity
    ]
    peers_list.sort(key=lambda x: -x["ml_score"])
    return jsonify({"entity": entity, "peer_group": group, "peer_count": len(peers_list), "peers": peers_list[:50]})


@app.get("/top-anomalies")
def top_anomalies():
    """Top ML-detected anomalies — useful for the 'unknown unknowns' card."""
    limit = min(int(request.args.get("limit", 20)), 200)
    min_score = float(request.args.get("min_score", 60))
    with _LAST_RUN_LOCK:
        all_scored = list(_LAST_RUN["scores_by_user"].values())
    high = [s for s in all_scored if s["ml_score"] >= min_score]
    high.sort(key=lambda x: -x["ml_score"])
    return jsonify({
        "total": len(high),
        "items": high[:limit],
    })


# ── Boot ─────────────────────────────────────────────────────
def start_scheduler():
    t = threading.Thread(target=scheduler_loop, daemon=True, name="ueba-ml-scheduler")
    t.start()
    log.info(f"Scheduler started (interval={SCORE_INTERVAL}s, window={FEATURE_HOURS}h)")


# Start scheduler at import time so gunicorn picks it up too
start_scheduler()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5006)), threaded=True)
