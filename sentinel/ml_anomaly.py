import math
from functools import lru_cache
from collections.abc import Iterable

from sentinel.ml_features import extract_feature_row
from sentinel.models import RequestContext

try:
    from sklearn.ensemble import IsolationForest
except ImportError:  # Optional at runtime; rules remain available without sklearn.
    IsolationForest = None


@lru_cache(maxsize=128)
def _cached_anomaly_score(feature_rows: tuple[tuple[float, ...], ...]) -> float:
    if len(feature_rows) < 3 or IsolationForest is None:
        return 0.0
    baseline = feature_rows[:-1]
    current = feature_rows[-1]
    means = [sum(row[index] for row in baseline) / len(baseline) for index in range(len(current))]
    deviations = []
    for index, mean in enumerate(means):
        variance = sum((row[index] - mean) ** 2 for row in baseline) / len(baseline)
        deviations.append(max(math.sqrt(variance), 0.25))
    distance = math.sqrt(sum(((value - means[index]) / deviations[index]) ** 2 for index, value in enumerate(current)))
    distance_score = 1.0 - math.exp(-distance / 3.0)

    model = IsolationForest(random_state=42, contamination="auto", n_estimators=50)
    model.fit(baseline)

    training_scores = model.score_samples(baseline)
    current_score = model.score_samples([current])[0]
    low_score = min(training_scores)
    high_score = max(training_scores)
    score_gap = high_score - low_score
    forest_score = 0.0 if math.isclose(score_gap, 0.0, abs_tol=1e-9) else 1.0 - ((current_score - low_score) / score_gap)
    return max(0.0, min(1.0, max(distance_score, forest_score)))


def anomaly_score(history: Iterable[RequestContext]) -> float:
    items = list(history)
    if not items:
        return 0.0
    feature_rows = tuple(tuple(extract_feature_row(item)) for item in items)
    return _cached_anomaly_score(feature_rows)
