import re
import time
from collections import defaultdict, deque
from sentinel.models import RequestContext

WINDOW_SECONDS = 60
RATE_LIMIT = 100
FAILED_LOGIN_LIMIT = 5

_requests: defaultdict[str, deque[float]] = defaultdict(deque)
_failed_logins: defaultdict[str, deque[float]] = defaultdict(deque)
_objects: defaultdict[tuple[str, str], set[str]] = defaultdict(set)


def _recent(bucket: deque[float], now: float) -> int:
    while bucket and now - bucket[0] > WINDOW_SECONDS:
        bucket.popleft()
    return len(bucket)


def detect(context: RequestContext) -> list[dict[str, object]]:
    now = time.time()
    signals: list[dict[str, object]] = []
    requests = _requests[context.ip]
    requests.append(now)
    request_count = _recent(requests, now)
    if request_count > RATE_LIMIT:
        signals.append({"type": "RATE_ABUSE", "score": min(100, 60 + request_count // 10), "reason": "Requests exceeded configured per-minute threshold"})

    if context.endpoint == "/login" and context.status_code in (401, 403):
        failures = _failed_logins[context.ip]
        failures.append(now)
        failed_count = _recent(failures, now)
        if failed_count >= FAILED_LOGIN_LIMIT:
            signals.append({"type": "BRUTE_FORCE", "score": min(100, 60 + failed_count * 3), "reason": "Repeated authentication failures"})

    match = re.search(r"/(?:users?|products)/(\d+)", context.endpoint)
    if match:
        key = (context.ip, re.sub(r"/\d+$", "/{id}", context.endpoint))
        _objects[key].add(match.group(1))
        if len(_objects[key]) >= 10:
            signals.append({"type": "API_ENUMERATION", "score": min(100, 85 + len(_objects[key]) // 2), "reason": "Large number of unique object IDs"})

    suspicious = re.compile(r"(?:union\s+select|drop\s+table|<script|or\s+1=1|;--)", re.I)
    if suspicious.search(context.query) or suspicious.search(context.body):
        signals.append({"type": "INJECTION", "score": 95, "reason": "Request contains a known suspicious input pattern"})
    return signals
