from datetime import timedelta

from django.utils import timezone

from dashboard.models import Alert, Device, HoneypotEvent, RiskSnapshot, SecurityEvent
from dashboard.security_explanations import RISK_IMPACTS
from dashboard.services.data_scope import (
    is_real_mode,
    real_alerts,
    real_devices,
    real_honeypot_events,
    real_security_events,
)


FALLBACK_SEVERITY_POINTS = {"low": 2, "medium": 5, "high": 10, "critical": 15}
EVENT_RISK_TYPES = {"honeypot", "brute_force", "dos_suspected", "port_scan"}


def _add_reason(reason_totals, key, count=1):
    label, points = RISK_IMPACTS[key]
    current = reason_totals.setdefault(key, {"label": label, "points": 0, "count": 0})
    current["points"] += points * count
    current["count"] += count


def _add_custom_reason(reason_totals, key, label, points, count=1):
    current = reason_totals.setdefault(key, {"label": label, "points": 0, "count": 0})
    current["points"] += points * count
    current["count"] += count


def _recent_event_rows(events, since):
    if hasattr(events, "filter"):
        return list(events.filter(created_at__gte=since))
    return [item for item in events if getattr(item, "created_at", since) >= since]


def _risk_reason_rows(reason_totals):
    return sorted(reason_totals.values(), key=lambda item: item["points"], reverse=True)


def calculate_risk(active_alerts=None, events=None, include_reasons=False):
    real_mode = is_real_mode()
    active_alerts = active_alerts if active_alerts is not None else Alert.objects.filter(status="active")
    events = events if events is not None else SecurityEvent.objects.all()
    if real_mode and hasattr(active_alerts, "exclude"):
        active_alerts = real_alerts(active_alerts)
    if real_mode and hasattr(events, "exclude"):
        events = real_security_events(events)
    since = timezone.now() - timedelta(hours=24)
    alert_rows = list(active_alerts)
    device_qs = real_devices() if real_mode else Device.objects.all()
    unknown_devices = device_qs.filter(is_trusted=False).count()
    partial_devices = device_qs.filter(status="partial").count()
    honeypot_qs = HoneypotEvent.objects.filter(created_at__gte=since)
    if real_mode:
        honeypot_qs = real_honeypot_events(honeypot_qs)
    honeypot_count = honeypot_qs.count()

    reason_totals = {}
    covered_types = set()
    for alert in alert_rows:
        if alert.alert_type in RISK_IMPACTS:
            _add_reason(reason_totals, alert.alert_type)
            covered_types.add(alert.alert_type)
        else:
            points = FALLBACK_SEVERITY_POINTS.get(alert.severity, 3)
            _add_custom_reason(reason_totals, f"alert:{alert.alert_type}", alert.get_alert_type_display(), points)

    if partial_devices:
        _add_reason(reason_totals, "partial_device", partial_devices)
    if unknown_devices:
        _add_custom_reason(
            reason_totals,
            "unknown_devices",
            "Güvenilmeyen veya bilinmeyen cihaz",
            min(unknown_devices, 10) * 2,
        )
    if honeypot_count and "honeypot" not in covered_types:
        _add_reason(reason_totals, "honeypot", min(honeypot_count, 3))

    recent_events = _recent_event_rows(events, since)
    for event_type in EVENT_RISK_TYPES:
        if event_type in covered_types:
            continue
        count = sum(item.event_type == event_type for item in recent_events)
        if count and event_type in RISK_IMPACTS:
            _add_reason(reason_totals, event_type, min(count, 3))
    if "arp_spoof" not in covered_types:
        arp_count = sum(item.event_type == "arp_anomaly" for item in recent_events)
        if arp_count:
            _add_reason(reason_totals, "arp_spoof", min(arp_count, 3))

    risk_reasons = _risk_reason_rows(reason_totals)
    risk_score = min(100, sum(item["points"] for item in risk_reasons))
    level = "high" if risk_score >= 70 else "medium" if risk_score >= 35 else "low"
    result = {
        "risk_score": risk_score,
        "risk_level": level,
        "security_score": 100 - risk_score,
        "active_alerts": len(alert_rows),
    }
    if include_reasons:
        result["risk_reasons"] = risk_reasons
        result["risk_actions"] = [
            "Tanımadığınız cihazları modem veya yönlendirici arayüzünden doğrulayın.",
            "Gereksiz açık portları kapatın veya sadece güvenilir IP adreslerine açın.",
            "Brute-force veya DoS şüphesinde kaynak IP için güvenlik duvarı/rate-limit kuralı uygulayın.",
        ]
    return result


def create_risk_snapshot():
    result = calculate_risk()
    return RiskSnapshot.objects.create(
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        security_score=result["security_score"],
        active_alerts=result["active_alerts"],
    )
