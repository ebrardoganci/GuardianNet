def calculate_risk(active_alerts, events):
    severity_weight = {"low": 5, "medium": 12, "high": 22, "critical": 35}
    alert_score = sum(severity_weight.get(alert.severity, 0) for alert in active_alerts)
    event_score = sum(event.risk_score for event in events[:10]) // 5
    risk_score = min(100, alert_score + event_score)
    level = "high" if risk_score >= 70 else "medium" if risk_score >= 35 else "low"
    return {"risk_score": risk_score, "risk_level": level, "security_score": max(0, 100 - risk_score)}
