from sentinel.models import SecurityResult


def calculate_risk(threat_score: int, anomaly_score: float, endpoint_criticality: int = 30, auth_risk: int = 0) -> tuple[int, str]:
    risk = round(threat_score * 0.33 + anomaly_score * 100 * 0.47 + endpoint_criticality * 0.12 + auth_risk * 0.08)
    risk = max(0, min(100, risk))
    severity = "LOW" if risk < 30 else "MEDIUM" if risk < 60 else "HIGH" if risk < 80 else "CRITICAL"
    return risk, severity


def build_result(request_id: str, signals: list[dict[str, object]], anomaly_score: float = 0.0) -> SecurityResult:
    threat_score = max((int(signal["score"]) for signal in signals), default=0)
    signal_type = max(signals, key=lambda signal: int(signal["score"]))["type"] if signals else "NONE"
    reasons = [str(signal["reason"]) for signal in signals]
    criticality = 90 if signal_type in {"INJECTION", "API_ENUMERATION"} else 60 if signal_type == "RATE_ABUSE" else 40
    score, severity = calculate_risk(threat_score, anomaly_score, criticality)
    if anomaly_score >= 0.75 and threat_score < 35:
        score, severity = max(score, 68), "HIGH" if score >= 68 else severity
    if threat_score >= 90:
        score, severity = max(score, 80), "CRITICAL"
    return SecurityResult(request_id=request_id, anomaly_score=anomaly_score, threat_score=threat_score, risk_score=score, severity=severity, threat_type=str(signal_type), reasons=reasons)
