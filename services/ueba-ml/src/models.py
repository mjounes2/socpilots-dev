"""Three unsupervised anomaly models with explainability.

  1. Isolation Forest      — overall behavioral outlier
  2. Per-user z-score      — divergence vs the user's own 30d baseline
  3. Peer-group DBSCAN     — distance from peer cluster centroid

All scores are normalized to [0, 100]. The composite ml_score = max of the
three. Each user also gets `ml_top_features`: the 3 features contributing
most to their anomaly (computed from the per-feature z-score against the
population, not the model internals — gives reasonable explanations
without paying SHAP/LIME's runtime cost).
"""
import logging
from typing import List, Dict, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN

log = logging.getLogger(__name__)

# Module-level history cache for per-user z-score. Key = user name → list of
# historical event_count values. Resets on container restart; for prod-grade
# persistence write/read these via Neo4j (`u.ml_history_json`).
_USER_HISTORY: Dict[str, List[float]] = {}
_HISTORY_MAX = 30


def _normalize(scores: np.ndarray, invert: bool = False) -> np.ndarray:
    """Min-max normalize to [0, 100]. If `invert`, higher input = lower output."""
    if len(scores) == 0:
        return scores
    finite = scores[np.isfinite(scores)]
    if len(finite) < 2:
        return np.zeros_like(scores)
    lo, hi = float(np.min(finite)), float(np.max(finite))
    if hi - lo < 1e-9:
        return np.zeros_like(scores)
    n = (scores - lo) / (hi - lo)
    if invert:
        n = 1.0 - n
    return np.clip(n * 100.0, 0.0, 100.0)


def isolation_forest_scores(X: np.ndarray) -> np.ndarray:
    """Return per-row anomaly score in [0, 100]. Higher = more anomalous."""
    if X.shape[0] < 10:
        # Not enough samples — return 0 for everyone (no signal)
        return np.zeros(X.shape[0])
    try:
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)
        # contamination=auto avoids forcing a fixed outlier ratio; n_estimators
        # tuned for <5k users
        iforest = IsolationForest(
            n_estimators=200,
            contamination="auto",
            random_state=42,
            n_jobs=-1,
        )
        iforest.fit(Xs)
        # decision_function: higher = more normal; invert it
        raw = iforest.decision_function(Xs)
        return _normalize(-raw)  # negate so anomalies score high
    except Exception as e:
        log.error(f"[ml] iforest error: {e}")
        return np.zeros(X.shape[0])


def zscore_scores(X: np.ndarray, names: List[str], feature_idx: int = 0) -> np.ndarray:
    """Per-user time-series z-score.

    Compares each user's CURRENT feature value to their OWN historical
    distribution. feature_idx=0 = event_count (the most useful single metric).

    First-time users get score 0 (no baseline yet). Returns score in [0, 100].
    """
    out = np.zeros(X.shape[0])
    for i, name in enumerate(names):
        history = _USER_HISTORY.get(name, [])
        current = float(X[i, feature_idx])

        if len(history) >= 5:
            mean = float(np.mean(history))
            std = float(np.std(history) or 1.0)
            z = abs(current - mean) / std
            # z >= 3 → very anomalous; map [0,5] → [0,100]
            out[i] = min(100.0, (z / 5.0) * 100.0)

        # Update history (rolling 30d)
        history.append(current)
        if len(history) > _HISTORY_MAX:
            history = history[-_HISTORY_MAX:]
        _USER_HISTORY[name] = history

    return out


def peer_distance_scores(X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """DBSCAN peer-group clustering. Returns (scores, cluster_labels).

    cluster_labels[i] = -1 means user i is a noise point (no peer group).
    Noise points score 100. Cluster members score by distance to centroid.
    """
    if X.shape[0] < 10:
        return np.zeros(X.shape[0]), np.full(X.shape[0], -1)

    try:
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)

        # eps tuned for 7-dim space; min_samples=5 means a peer group is
        # at least 5 users with similar behavior
        dbscan = DBSCAN(eps=1.2, min_samples=5)
        labels = dbscan.fit_predict(Xs)

        scores = np.zeros(X.shape[0])

        # For each cluster, compute centroid and per-member distance
        unique = set(labels) - {-1}
        for cl in unique:
            mask = labels == cl
            centroid = Xs[mask].mean(axis=0)
            dists = np.linalg.norm(Xs[mask] - centroid, axis=1)
            # Normalize per-cluster — distant outliers within a cluster
            if dists.max() > 0:
                scores[mask] = (dists / dists.max()) * 60.0  # cap at 60

        # Noise points (label -1) get high score
        scores[labels == -1] = 95.0

        return scores, labels
    except Exception as e:
        log.error(f"[ml] dbscan error: {e}")
        return np.zeros(X.shape[0]), np.full(X.shape[0], -1)


def top_contributing_features(X: np.ndarray, feature_names: List[str], top_k: int = 3) -> List[List[str]]:
    """For each row, return the top_k features with highest z-score vs population.

    This is the explanation we surface to analysts ("This user is anomalous
    BECAUSE their after_hours_frac is 3.2 std above peers"). Not as
    rigorous as SHAP but interpretable and fast.
    """
    if X.shape[0] == 0:
        return []
    means = X.mean(axis=0)
    stds = X.std(axis=0)
    stds[stds < 1e-9] = 1.0  # avoid div-by-zero
    Z = np.abs((X - means) / stds)  # (n, 7)

    result = []
    for i in range(X.shape[0]):
        # Argsort descending by z-score
        idx_sorted = np.argsort(-Z[i])
        top = []
        for idx in idx_sorted[:top_k]:
            if Z[i, idx] >= 1.5:  # only include if at least 1.5 std deviation
                top.append({
                    "feature": feature_names[idx],
                    "z": round(float(Z[i, idx]), 2),
                    "value": round(float(X[i, idx]), 3),
                })
        result.append(top)
    return result


def score_all(X: np.ndarray, names: List[str], feature_names: List[str]) -> List[Dict]:
    """Run all 3 models + explainability. Returns per-user score dict."""
    iforest = isolation_forest_scores(X)
    zscore  = zscore_scores(X, names, feature_idx=0)
    peer, labels = peer_distance_scores(X)

    composite = np.maximum.reduce([iforest, zscore, peer])
    top_feats = top_contributing_features(X, feature_names)

    out = []
    for i, name in enumerate(names):
        out.append({
            "name":                name,
            "ml_iforest_score":    round(float(iforest[i]), 1),
            "ml_zscore":           round(float(zscore[i]), 1),
            "ml_peer_distance":    round(float(peer[i]), 1),
            "ml_score":            round(float(composite[i]), 1),
            "ml_peer_group":       int(labels[i]),
            "ml_top_features":     top_feats[i] if i < len(top_feats) else [],
        })
    return out
