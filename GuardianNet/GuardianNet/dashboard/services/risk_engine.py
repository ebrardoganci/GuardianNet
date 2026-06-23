from datetime import timedelta

from django.utils import timezone

from dashboard.models import Alert, Device, HoneypotEvent, RiskSnapshot, SecurityEvent
from dashboard.services.runtime_settings import get_value


def _real_devices():
    return Device.objects.exclude(ip_address__startswith="192.0.2.").exclude(ip_address__startswith="198.51.100.").exclude(ip_address__startswith="203.0.113.")


def calculate_risk(active_alerts=None, events=None):
    real_mode = get_value("guardiannet_mode", "real") == "real"
    active_alerts = active_alerts if active_alerts is not None else Alert.objects.exclude(status="resolved")
    events = events if events is not None else SecurityEvent.objects.all()
    if real_mode and hasattr(active_alerts, "exclude"):
        active_alerts = active_alerts.exclude(title__startswith="[demo-")
    if real_mode and hasattr(events, "exclude"):
        events = events.exclude(title__startswith="[demo-")
    since = timezone.now() - timedelta(hours=24)
    alert_rows = list(active_alerts)
    high_count = sum(item.severity in {"high", "critical"} for item in alert_rows)
    device_qs = _real_devices() if real_mode else Device.objects.all()
    unknown_devices = device_qs.filter(is_trusted=False).count()
    honeypot_count = HoneypotEvent.objects.filter(created_at__gte=since, is_mock=False).count()
    event_types = set(events.filter(created_at__gte=since).values_list("event_type", flat=True)) if hasattr(events, "filter") else {item.event_type for item in events}
    risk_score = min(100, len(alert_rows) * 3 + high_count * 10 + min(unknown_devices, 10) * 2
                     + min(honeypot_count, 20) + (12 if "port_scan" in event_types else 0)
                     + (15 if "brute_force" in event_types else 0) + (18 if "arp_anomaly" in event_types else 0))
    level = "high" if risk_score >= 70 else "medium" if risk_score >= 35 else "low"
    return {"risk_score": risk_score, "risk_level": level, "security_score": 100 - risk_score,
            "active_alerts": len(alert_rows)}


def create_risk_snapshot():
    result = calculate_risk()
    return RiskSnapshot.objects.create(**result)
