import json
import re
from typing import Any

from sentinel.models import RequestContext

RESOURCE_OWNERSHIP = {
    "order_101": "usr_alpha",
    "order_102": "usr_alpha",
    "order_201": "usr_beta",
}

SCHEMA_SPECIFICATIONS: dict[str, dict[str, set[str]]] = {
    "/api/v1/user/profile": {
        "allowed_keys": {"display_name", "bio", "avatar_url"},
        "forbidden_keys": {"is_admin", "role", "permissions", "balance", "tier"},
    },
    "/api/v1/orders/checkout": {
        "allowed_keys": {"order_id", "items", "shipping_address"},
        "forbidden_keys": {"discount_override", "approved_by", "tax_exempt"},
    },
}

PII_PATTERNS = {
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
    "AADHAAR_NUMBER": re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"),
    "PAN_CARD": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
    "JWT_SECRET_LEAK": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    "EMAIL_EXPOSURE": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b"),
}


def inspect_request_controls(context: RequestContext) -> list[dict[str, object]]:
    signals: list[dict[str, object]] = []
    order_match = re.fullmatch(r"/api/v1/orders/(order_[A-Za-z0-9_]+)", context.endpoint)
    if order_match:
        resource_id = order_match.group(1)
        owner = RESOURCE_OWNERSHIP.get(resource_id)
        if owner and owner != (context.user_id or "anonymous"):
            signals.append({
                "type": "BOLA_IDOR",
                "score": 100,
                "reason": f"User '{context.user_id or 'anonymous'}' attempted to access '{resource_id}' owned by '{owner}'",
            })

    schema = SCHEMA_SPECIFICATIONS.get(context.endpoint)
    if schema and context.method in {"POST", "PUT", "PATCH"} and context.body:
        try:
            payload: Any = json.loads(context.body)
        except json.JSONDecodeError:
            signals.append({
                "type": "MALFORMED_JSON",
                "score": 90,
                "reason": "Request body is not valid JSON for a protected schema endpoint",
            })
        else:
            if isinstance(payload, dict):
                keys = set(payload)
                forbidden = keys & schema["forbidden_keys"]
                unknown = keys - schema["allowed_keys"]
                invalid = forbidden | unknown
                if invalid:
                    labels = ", ".join(sorted(invalid))
                    signals.append({
                        "type": "MASS_ASSIGNMENT_TAMPERING",
                        "score": 98,
                        "reason": f"Protected schema rejected unauthorized fields: {labels}",
                    })

    return signals


def redact_sensitive_data(raw_payload: str) -> tuple[str, list[str]]:
    leaks: list[str] = []

    def redact_text(value: str) -> str:
        sanitized = value
        for name, pattern in PII_PATTERNS.items():
            matches = pattern.findall(sanitized)
            if matches:
                leaks.append(f"{name} (x{len(matches)})")
                sanitized = pattern.sub("[REDACTED_BY_API_SENTINEL]", sanitized)
        return sanitized

    try:
        payload: Any = json.loads(raw_payload)
    except json.JSONDecodeError:
        return redact_text(raw_payload), leaks

    def redact_value(value: Any) -> Any:
        if isinstance(value, str):
            return redact_text(value)
        if isinstance(value, list):
            return [redact_value(item) for item in value]
        if isinstance(value, dict):
            return {key: redact_value(item) for key, item in value.items()}
        return value

    return json.dumps(redact_value(payload), separators=(",", ":")), leaks
