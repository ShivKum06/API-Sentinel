from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, Field


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RequestContext(BaseModel):
    request_id: str
    timestamp: str
    ip: str
    user_id: str | None = None
    method: str
    endpoint: str
    request_size: int = 0
    response_size: int = 0
    status_code: int = 200
    latency_ms: float = 0
    query: str = ""
    body: str = ""


class SecurityResult(BaseModel):
    request_id: str
    anomaly_score: float = Field(ge=0, le=1)
    threat_score: int = Field(ge=0, le=100)
    risk_score: int = Field(ge=0, le=100)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    threat_type: str = "NONE"
    reasons: list[str] = []


class DecisionResult(BaseModel):
    request_id: str
    decision: Literal["ALLOW", "MONITOR", "RATE_LIMIT", "REVIEW", "BLOCK"]
    reason: str
    policy: str = "DEFAULT"
    risk_score: int


class OverrideRequest(BaseModel):
    action: Literal["ALLOW", "MONITOR", "RATE_LIMIT", "REVIEW", "BLOCK"]
    reason: str = Field(min_length=3, max_length=500)
    reviewer: str = "dashboard-user"
