from collections.abc import Iterable
from sentinel.models import RequestContext
from sentinel.ml_features import extract_features

try:
    from sklearn.ensemble import IsolationForest
except ImportError:  # Optional at runtime; rules remain available without sklearn.
    IsolationForest = None


def anomaly_score(history: Iterable[RequestContext]) -> float:
    items = list(history)
    if not items or IsolationForest is None:
        return 0.0
    model = IsolationForest(random_state=42, contamination="auto", n_estimators=50)
    model.fit([extract_features(items)])
    return 0.0 if model.predict([extract_features(items)])[0] == 1 else 1.0
