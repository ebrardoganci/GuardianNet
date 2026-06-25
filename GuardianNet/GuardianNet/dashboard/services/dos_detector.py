from collections import Counter
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from dashboard.models import Alert, SecurityEvent
from dashboard.services.data_scope import is_real_mode, real_security_events


def detect_dos_patterns(events, threshold=20):
    attempts = Counter()
    for event in events:
        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip") or "honeypot"
        destination_port = event.get("destination_port") or event.get("service") or "unknown"
        if source_ip:
            attempts[(str(source_ip), str(destination_ip), str(destination_port))] += 1
    return [
        {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "attempts": count,
            "detected": True,
        }
        for (source_ip, destination_ip, destination_port), count in attempts.items()
        if count >= threshold
    ]


def analyze_dos_logs(threshold=None, minutes=None):
    threshold = threshold or getattr(settings, "DOS_REQUEST_THRESHOLD", 20)
    minutes = minutes or settings.DETECTION_WINDOW_MINUTES
    since = timezone.now() - timedelta(minutes=minutes)
    event_qs = SecurityEvent.objects.filter(created_at__gte=since).exclude(event_type="dos_suspected")
    if is_real_mode():
        event_qs = real_security_events(event_qs)
    else:
        event_qs = event_qs.exclude(title__startswith="[demo-")
    rows = list(event_qs.values("source_ip", "destination_ip", "destination_port", "protocol"))
    findings = detect_dos_patterns(rows, threshold)
    bucket = since.strftime("%Y%m%d%H%M")
    for finding in findings:
        source_ip = finding["source_ip"]
        destination_ip = None if finding["destination_ip"] == "honeypot" else finding["destination_ip"]
        destination_port = None if finding["destination_port"] == "unknown" else finding["destination_port"]
        message = (
            f"{minutes} dakika içinde aynı kaynaktan aynı hedefe "
            f"{finding['attempts']} bağlantı/istek denemesi görüldü."
        )
        Alert.objects.get_or_create(
            alert_type="dos_suspected",
            source_ip=source_ip,
            status="active",
            defaults={
                "severity": "high",
                "title": "DoS şüphesi",
                "message": message,
            },
        )
        SecurityEvent.objects.get_or_create(
            event_type="dos_suspected",
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            title=f"DoS şüphesi {bucket}",
            defaults={
                "description": message,
                "level": "danger",
                "protocol": "TCP",
                "risk_score": 85,
            },
        )
    return findings
