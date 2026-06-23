from collections import defaultdict
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from dashboard.models import Alert, HoneypotEvent, SecurityEvent
from dashboard.services.data_scope import is_real_mode, real_honeypot_events, real_security_events


def detect_port_scan(events, threshold=8):
    ports_by_source = defaultdict(set)
    for event in events:
        target = event.get("destination_port") or event.get("service")
        if event.get("source_ip") and target:
            ports_by_source[str(event["source_ip"])].add(str(target))
    return [{"source_ip": source, "unique_ports": len(ports), "detected": True}
            for source, ports in ports_by_source.items() if len(ports) >= threshold]


def analyze_port_scan_logs(threshold=None, minutes=None):
    threshold = threshold or settings.PORT_SCAN_THRESHOLD
    minutes = minutes or settings.DETECTION_WINDOW_MINUTES
    since = timezone.now() - timedelta(minutes=minutes)
    honeypot_qs = HoneypotEvent.objects.filter(created_at__gte=since, is_mock=False)
    if is_real_mode():
        honeypot_qs = real_honeypot_events(honeypot_qs)
    rows = list(honeypot_qs.values("source_ip", "destination_port", "service"))
    event_qs = SecurityEvent.objects.filter(created_at__gte=since).exclude(event_type="port_scan")
    if is_real_mode():
        event_qs = real_security_events(event_qs)
    else:
        event_qs = event_qs.exclude(title__startswith="[demo-")
    rows += list(event_qs.values("source_ip", "destination_port", "protocol"))
    findings = detect_port_scan(rows, threshold)
    bucket = since.strftime("%Y%m%d%H%M")
    for finding in findings:
        source_ip = finding["source_ip"]
        message = f"{minutes} dakika icinde {finding['unique_ports']} farkli port/servis gozlemlendi."
        Alert.objects.get_or_create(alert_type="port_scan", source_ip=source_ip, status="active",
                                    defaults={"severity": "high", "title": "Port tarama davranisi", "message": message})
        SecurityEvent.objects.get_or_create(event_type="port_scan", source_ip=source_ip,
                                            title=f"Port tarama suphesi {bucket}",
                                            defaults={"description": message, "level": "danger", "risk_score": 75})
    return findings
