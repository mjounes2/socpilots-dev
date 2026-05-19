"""Feature extraction from Neo4j for ML scoring.

Returns a feature matrix X and a name list:
  rows  = users
  cols  = [event_count_24h, distinct_hosts_24h, distinct_processes_24h,
           after_hours_frac, avg_deviation, failed_login_ratio, velocity_stddev]
"""
import logging
from typing import List, Tuple
import numpy as np

log = logging.getLogger(__name__)

FEATURE_NAMES = [
    "event_count_24h",
    "distinct_hosts_24h",
    "distinct_processes_24h",
    "after_hours_frac",
    "avg_deviation",
    "failed_login_ratio",
    "velocity_stddev",
]


# ── Cypher: 7 features per user over the last `hours` window ───
FEATURE_QUERY = """
MATCH (u:User)
WHERE coalesce(u.total_events, 0) > 0
OPTIONAL MATCH (u)-[r:LOGGED_IN]->(h:Host)
WHERE r.time IS NOT NULL
  AND datetime(r.time) > datetime() - duration({hours: $hours})
WITH u, r, h
WITH u,
     count(r)                                AS event_count,
     count(DISTINCT h)                        AS distinct_hosts,
     sum(CASE WHEN r.hour IS NULL THEN 0
              WHEN r.hour < 7 OR r.hour > 19 THEN 1 ELSE 0 END) AS after_hours,
     avg(coalesce(r.deviation_score, 0))      AS avg_dev,
     sum(CASE WHEN any(f IN r.flags WHERE f IN ['failed_auth','authentication_failed']) THEN 1 ELSE 0 END) AS failed,
     collect(r.time)                          AS times
OPTIONAL MATCH (u)-[e:EXECUTED]->(p:Process)
WHERE e.time IS NOT NULL
  AND datetime(e.time) > datetime() - duration({hours: $hours})
WITH u, event_count, distinct_hosts, after_hours, avg_dev, failed, times,
     count(DISTINCT p) AS distinct_procs
RETURN u.name           AS name,
       event_count,
       distinct_hosts,
       distinct_procs,
       after_hours,
       avg_dev,
       failed,
       times
ORDER BY event_count DESC
LIMIT 5000
"""


def _velocity_stddev(times: list) -> float:
    """Std deviation of seconds-between-consecutive events.
    Indicates burstiness / regularity vs spread-out activity.
    """
    if not times or len(times) < 3:
        return 0.0
    try:
        # Times come back as Neo4j datetimes; convert to epoch seconds
        epochs = []
        for t in times:
            if t is None:
                continue
            if hasattr(t, "to_native"):
                epochs.append(t.to_native().timestamp())
            else:
                # Fallback: parse string
                from datetime import datetime
                epochs.append(datetime.fromisoformat(str(t).replace("Z", "+00:00")).timestamp())
        if len(epochs) < 3:
            return 0.0
        epochs.sort()
        diffs = np.diff(epochs)
        # Cap to avoid extreme outliers dominating
        diffs = np.clip(diffs, 0, 86400)
        return float(np.std(diffs))
    except Exception:
        return 0.0


def extract_features(driver, hours: int = 24) -> Tuple[np.ndarray, List[str], list]:
    """Run the Cypher feature query and assemble the feature matrix.

    Returns (X, names, raw_rows) where:
      X       — (n_users, 7) numpy array of features
      names   — list of user names matching X rows
      raw_rows — original dict per row (for explainability)
    """
    rows: list = []
    names: List[str] = []
    feats: list = []

    with driver.session() as s:
        result = s.run(FEATURE_QUERY, {"hours": hours})
        for rec in result:
            name = rec["name"]
            if not name:
                continue
            event_count    = rec["event_count"] or 0
            distinct_hosts = rec["distinct_hosts"] or 0
            distinct_procs = rec["distinct_procs"] or 0
            after_hours    = rec["after_hours"] or 0
            avg_dev        = float(rec["avg_dev"] or 0)
            failed         = rec["failed"] or 0
            times          = rec["times"] or []

            after_hours_frac = (after_hours / event_count) if event_count > 0 else 0.0
            failed_ratio     = (failed / event_count) if event_count > 0 else 0.0
            velocity_std     = _velocity_stddev(times)

            feats.append([
                float(event_count),
                float(distinct_hosts),
                float(distinct_procs),
                float(after_hours_frac),
                float(avg_dev),
                float(failed_ratio),
                float(velocity_std),
            ])
            names.append(name)
            rows.append({
                "name":               name,
                "event_count":        event_count,
                "distinct_hosts":     distinct_hosts,
                "distinct_processes": distinct_procs,
                "after_hours_frac":   after_hours_frac,
                "avg_deviation":      avg_dev,
                "failed_login_ratio": failed_ratio,
                "velocity_stddev":    velocity_std,
            })

    if not feats:
        return np.zeros((0, len(FEATURE_NAMES))), [], []

    X = np.array(feats, dtype=np.float64)
    return X, names, rows
