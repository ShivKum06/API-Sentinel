from collections.abc import Iterable
from sentinel.models import RequestContext


def extract_features(history: Iterable[RequestContext]) -> list[float]:
    items = list(history)
    if not items:
        return [0.0] * 8
    endpoints = {item.endpoint for item in items}
    failures = sum(item.status_code in (401, 403) for item in items)
    return [len(items), len(endpoints), failures, len({item.endpoint for item in items if "/" in item.endpoint}), sum(item.response_size for item in items) / len(items), sum(item.request_size for item in items) / len(items), failures / len(items), 0.0]
