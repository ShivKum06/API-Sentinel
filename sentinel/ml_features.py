import math
import re
from collections.abc import Iterable
from sentinel.models import RequestContext


def extract_feature_row(context: RequestContext) -> list[float]:
    normalized_endpoint = re.sub(r"/\d+", "/{id}", context.endpoint)
    method_code = {"GET": 0.0, "POST": 1.0, "PUT": 2.0, "PATCH": 3.0, "DELETE": 4.0}.get(context.method, 5.0)
    return [
        method_code,
        float(len(normalized_endpoint)),
        float(normalized_endpoint.count("/")),
        float(context.status_code >= 400),
        math.log1p(max(0, context.request_size)),
        math.log1p(max(0, context.response_size)),
        math.log1p(max(0.0, context.latency_ms)),
        math.log1p(len(context.query) + len(context.body)),
    ]


def extract_features(history: Iterable[RequestContext]) -> list[float]:
    items = list(history)
    if not items:
        return [0.0] * 8
    return extract_feature_row(items[-1])
