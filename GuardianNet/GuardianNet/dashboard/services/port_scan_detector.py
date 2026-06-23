from collections import defaultdict
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from dashboard.models import Alert, HoneypotEvent, SecurityEvent


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
    rows = list(HoneypotEvent.objects.filter(created_at__gte=since, is_mock=False).values("source_ip", "destination_port", "service"))
    rows += list(SecurityEvent.objects.filter(created_at__gte=since).exclude(event_type="port_scan").exclude(title__startswith="[demo-").values("source_ip", "destination_port", "protocol"))
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
