import os
import uuid
import threading
from datetime import datetime, timezone
from flask import Flask, jsonify, request, abort
import psycopg2
import psycopg2.extras
import logging

from asset_scanner import AssetScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# ── DB connection ────────────────────────────────────────────────────────────

def get_db():
    return psycopg2.connect(
        host=os.environ.get("PG_HOST", "postgres"),
        port=int(os.environ.get("PG_PORT", 5432)),
        dbname=os.environ.get("PG_DB", "socpilots"),
        user=os.environ.get("PG_USER", "socpilots"),
        password=os.environ.get("PG_PASSWORD", ""),
    )

# ── Background scan state ────────────────────────────────────────────────────

_active_scans: dict[str, dict] = {}
_scan_lock = threading.Lock()

def _run_scan_bg(job_id: str, subnets: list[str], triggered_by: str):
    with _scan_lock:
        _active_scans[job_id] = {"status": "running", "started_at": datetime.now(timezone.utc).isoformat()}
    try:
        scanner = AssetScanner()
        result = scanner.run_full_scan(subnets, triggered_by=triggered_by)
        with _scan_lock:
            _active_scans[job_id] = {
                "status": "completed",
                "result": result,
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }
    except Exception as exc:
        log.exception("Scan job %s failed", job_id)
        with _scan_lock:
            _active_scans[job_id] = {
                "status": "failed",
                "error": str(exc),
                "completed_at": datetime.now(timezone.utc).isoformat(),
            }

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        return jsonify({"status": "ok", "db": "connected"})
    except Exception as exc:
        return jsonify({"status": "degraded", "db": str(exc)}), 503


@app.route("/scan/start", methods=["POST"])
def scan_start():
    body = request.get_json(silent=True) or {}
    subnets = body.get("subnets")
    triggered_by = body.get("triggered_by", "api")

    if not subnets:
        # fall back to subnets stored in DB
        try:
            with get_db() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT cidr FROM subnets WHERE enabled = TRUE")
                    rows = cur.fetchall()
                    subnets = [r["cidr"] for r in rows]
        except Exception as exc:
            return jsonify({"error": f"Could not load subnets: {exc}"}), 500

    if not subnets:
        return jsonify({"error": "No subnets provided and none configured in DB"}), 400

    job_id = str(uuid.uuid4())
    t = threading.Thread(target=_run_scan_bg, args=(job_id, subnets, triggered_by), daemon=True)
    t.start()

    return jsonify({"job_id": job_id, "status": "started", "subnets": subnets}), 202


@app.route("/scan/status/<job_id>")
def scan_status(job_id: str):
    with _scan_lock:
        job = _active_scans.get(job_id)
    if job is None:
        abort(404)
    return jsonify({"job_id": job_id, **job})


@app.route("/assets")
def list_assets():
    page = max(1, int(request.args.get("page", 1)))
    limit = min(500, max(1, int(request.args.get("limit", 100))))
    offset = (page - 1) * limit

    status_filter = request.args.get("status")
    agent_filter = request.args.get("agent_status")

    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                where_clauses = []
                params: list = []

                if status_filter:
                    where_clauses.append("status = %s")
                    params.append(status_filter)
                if agent_filter:
                    where_clauses.append("wazuh_agent_status = %s")
                    params.append(agent_filter)

                where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

                cur.execute(
                    f"SELECT COUNT(*) AS total FROM assets {where_sql}",
                    params,
                )
                total = cur.fetchone()["total"]

                cur.execute(
                    f"""SELECT id, ip, mac, hostname, os, vendor, status,
                               wazuh_agent_id, wazuh_agent_name, wazuh_agent_status,
                               risk_score, open_ports, last_seen, first_seen
                        FROM assets {where_sql}
                        ORDER BY last_seen DESC NULLS LAST
                        LIMIT %s OFFSET %s""",
                    [*params, limit, offset],
                )
                rows = cur.fetchall()

        return jsonify({"total": total, "page": page, "limit": limit, "assets": rows})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/gaps")
def list_gaps():
    resolved = request.args.get("resolved", "false").lower() == "true"
    severity = request.args.get("severity")

    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                where_clauses = ["resolved_at IS " + ("NOT NULL" if resolved else "NULL")]
                params: list = []

                if severity:
                    where_clauses.append("severity = %s")
                    params.append(severity)

                where_sql = "WHERE " + " AND ".join(where_clauses)

                cur.execute(
                    f"""SELECT id, asset_id, asset_ip, asset_hostname,
                               gap_type, severity, risk_score,
                               open_ports, os_guess,
                               detected_at, resolved_at,
                               in_deployment_queue, thehive_case_id
                        FROM coverage_gaps {where_sql}
                        ORDER BY risk_score DESC, detected_at DESC
                        LIMIT 500""",
                    params,
                )
                rows = cur.fetchall()

        return jsonify({"resolved": resolved, "gaps": rows})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/gaps/<int:gap_id>/resolve", methods=["POST"])
def resolve_gap(gap_id: int):
    body = request.get_json(silent=True) or {}
    notes = body.get("notes", "Manually resolved")

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE coverage_gaps
                       SET resolved_at = NOW(), resolution_notes = %s
                       WHERE id = %s AND resolved_at IS NULL
                       RETURNING id""",
                    (notes, gap_id),
                )
                row = cur.fetchone()
            conn.commit()

        if row is None:
            return jsonify({"error": "Gap not found or already resolved"}), 404
        return jsonify({"resolved": gap_id})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/metrics")
def get_metrics():
    try:
        scanner = AssetScanner()
        metrics = scanner.get_coverage_metrics()
        return jsonify(metrics)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/metrics/history")
def metrics_history():
    limit = min(720, max(1, int(request.args.get("limit", 48))))
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """SELECT recorded_at, total_assets, covered_assets,
                              coverage_percentage, critical_gaps, high_gaps,
                              pending_deployments
                       FROM coverage_metrics
                       ORDER BY recorded_at DESC
                       LIMIT %s""",
                    (limit,),
                )
                rows = cur.fetchall()
        return jsonify({"history": rows})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/deployment-queue")
def deployment_queue():
    status_filter = request.args.get("status", "pending")
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """SELECT id, asset_ip, asset_hostname, os_type, priority,
                              status, thehive_case_id, deployment_method,
                              created_at, started_at, completed_at, retry_count
                       FROM deployment_queue
                       WHERE status = %s
                       ORDER BY
                         CASE priority
                           WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                           WHEN 'medium' THEN 3 ELSE 4 END,
                         created_at ASC
                       LIMIT 200""",
                    (status_filter,),
                )
                rows = cur.fetchall()
        return jsonify({"status_filter": status_filter, "queue": rows})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/wazuh-agents")
def wazuh_agents():
    status_filter = request.args.get("status")
    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if status_filter:
                    cur.execute(
                        """SELECT agent_id, agent_name, agent_ip, status,
                                  version, os_name, os_platform, last_keepalive, synced_at
                           FROM wazuh_agents_cache WHERE status = %s
                           ORDER BY agent_name""",
                        (status_filter,),
                    )
                else:
                    cur.execute(
                        """SELECT agent_id, agent_name, agent_ip, status,
                                  version, os_name, os_platform, last_keepalive, synced_at
                           FROM wazuh_agents_cache
                           ORDER BY status, agent_name"""
                    )
                rows = cur.fetchall()
        return jsonify({"agents": rows})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5003))
    app.run(host="0.0.0.0", port=port)
