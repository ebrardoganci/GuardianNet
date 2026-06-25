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
    honeypot_qs = HoneypotEvent.objects.filter(created_at__gte=since, is_mock=False)
    if is_real_mode():
        honeypot_qs = real_honeypot_events(honeypot_qs)
    findings = []
    for event in honeypot_qs:
        description = (
            "Bir cihaz sahte honeypot servisine bağlanmaya çalıştı. "
            f"Kaynak IP: {event.source_ip}. Kaynak port: {event.source_port or '-'}. "
            f"Hedef port: {event.destination_port or '-'}. Kaynak veri türü: {event.source_type or 'Honeypot logu'}."
        )
        Alert.objects.get_or_create(
            alert_type="honeypot",
            source_ip=event.source_ip,
            status="active",
            defaults={
                "severity": "medium",
                "title": "Honeypot bağlantı denemesi",
                "message": description,
            },
        )
        security_event, _ = SecurityEvent.objects.get_or_create(
            event_type="honeypot",
            source_ip=event.source_ip,
            title=f"Honeypot bağlantı denemesi #{event.pk}",
            defaults={
                "description": description,
                "level": "warning",
                "destination_port": event.destination_port,
                "protocol": event.service.upper(),
                "risk_score": 35,
            },
        )
        findings.append({"source_ip": event.source_ip, "event_id": event.pk, "security_event_id": security_event.pk})
    return findings


def analyze_bruteforce_logs(threshold=None, minutes=None):
    threshold = threshold or settings.BRUTE_FORCE_THRESHOLD
    minutes = minutes or settings.DETECTION_WINDOW_MINUTES
    since = timezone.now() - timedelta(minutes=minutes)
    honeypot_qs = HoneypotEvent.objects.filter(
        service__in=["ssh", "telnet", "ftp"],
        created_at__gte=since,
        is_mock=False,
        login_success=False,
    )
    if is_real_mode():
        honeypot_qs = real_honeypot_events(honeypot_qs)
    events = [{"source_ip": row.source_ip, "success": row.login_success}
              for row in honeypot_qs.exclude(username="")]
    findings = detect_bruteforce(events, threshold)
    bucket = since.strftime("%Y%m%d%H%M")
    for finding in findings:
        source_ip = finding["source_ip"]
        message = (
            "Kısa süre içinde aynı kaynak IP'den çok sayıda başarısız honeypot giriş denemesi oluştu. "
            f"{minutes} dakika içinde {finding['failed_attempts']} başarısız SSH/Telnet/FTP giriş kaydı görüldü. "
            "Kaynak veri türü: OpenCanary logu / Honeypot auth logu."
        )
        Alert.objects.get_or_create(alert_type="brute_force", source_ip=source_ip, status="active",
                                    defaults={"severity": "high", "title": "SSH brute-force şüphesi", "message": message})
        SecurityEvent.objects.get_or_create(event_type="brute_force", source_ip=source_ip,
                                            title=f"SSH brute-force şüphesi {bucket}",
                                            defaults={"description": message, "level": "danger", "protocol": "SSH", "risk_score": 80})
    return findings
