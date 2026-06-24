from collections import Counter
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from dashboard.models import Alert, HoneypotEvent, SecurityEvent
from dashboard.services.data_scope import is_real_mode, real_honeypot_events


def detect_bruteforce(login_events, threshold=5):
    failures = Counter(str(event.get("source_ip")) for event in login_events
                       if not event.get("success", False) and event.get("source_ip"))
    return [{"source_ip": source, "failed_attempts": count, "detected": True}
            for source, count in failures.items() if count >= threshold]


def analyze_ssh_attempt_logs(minutes=None):
    minutes = minutes or settings.DETECTION_WINDOW_MINUTES
    since = timezone.now() - timedelta(minutes=minutes)
    honeypot_qs = HoneypotEvent.objects.filter(service="ssh", created_at__gte=since, is_mock=False)
    if is_real_mode():
        honeypot_qs = real_honeypot_events(honeypot_qs)
    findings = []
    for event in honeypot_qs:
        description = (
            "Honeypot SSH servisine erisim denemesi kaydedildi. "
            f"Kaynak IP: {event.source_ip}. Hedef port: {event.destination_port or '-'}."
        )
        Alert.objects.get_or_create(
            alert_type="honeypot",
            source_ip=event.source_ip,
            status="active",
            defaults={
                "severity": "medium",
                "title": "SSH baglanti denemesi algilandi",
                "message": description,
            },
        )
        security_event, _ = SecurityEvent.objects.get_or_create(
            event_type="honeypot",
            source_ip=event.source_ip,
            title=f"SSH baglanti denemesi algilandi #{event.pk}",
            defaults={
                "description": description,
                "level": "warning",
                "destination_port": event.destination_port,
                "protocol": "SSH",
                "risk_score": 35,
            },
        )
        findings.append({"source_ip": event.source_ip, "event_id": event.pk, "security_event_id": security_event.pk})
    return findings


def analyze_bruteforce_logs(threshold=None, minutes=None):
    threshold = threshold or settings.BRUTE_FORCE_THRESHOLD
    minutes = minutes or settings.DETECTION_WINDOW_MINUTES
    since = timezone.now() - timedelta(minutes=minutes)
    honeypot_qs = HoneypotEvent.objects.filter(service="ssh", created_at__gte=since, is_mock=False)
    if is_real_mode():
        honeypot_qs = real_honeypot_events(honeypot_qs)
    events = [{"source_ip": row.source_ip, "success": row.login_success}
              for row in honeypot_qs.exclude(username="")]
    findings = detect_bruteforce(events, threshold)
    bucket = since.strftime("%Y%m%d%H%M")
    for finding in findings:
        source_ip = finding["source_ip"]
        message = f"{minutes} dakika icinde {finding['failed_attempts']} basarisiz SSH giris kaydi."
        Alert.objects.get_or_create(alert_type="brute_force", source_ip=source_ip, status="active",
                                    defaults={"severity": "high", "title": "Olasi SSH brute force denemesi", "message": message})
        SecurityEvent.objects.get_or_create(event_type="brute_force", source_ip=source_ip,
                                            title=f"Olasi SSH brute force denemesi {bucket}",
                                            defaults={"description": message, "level": "danger", "protocol": "SSH", "risk_score": 80})
    return findings
