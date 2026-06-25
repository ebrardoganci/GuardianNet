from collections import defaultdict
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from dashboard.models import Alert, HoneypotEvent, SecurityEvent
from dashboard.services.data_scope import is_real_mode, real_honeypot_events


def detect_port_scan(events, threshold=8):
    ports_by_source = defaultdict(set)
    for event in events:
        target = event.get("destination_port") or event.get("service")
        if event.get("source_ip") and target:
            ports_by_source[str(event["source_ip"])].add(str(target))
    return [{"source_ip": source, "unique_ports": len(ports), "detected": True}
            for source, ports in ports_by_source.items() if len(ports) >= threshold]


def analyze_port_scan_logs(threshold=None, minutes=None):
    threshold = threshold or getattr(settings, "HONEYPOT_PORT_SCAN_THRESHOLD", settings.PORT_SCAN_THRESHOLD)
    if minutes is None:
        since = timezone.now() - timedelta(seconds=getattr(settings, "HONEYPOT_PORT_SCAN_WINDOW_SECONDS", 60))
        window_label = f"{getattr(settings, 'HONEYPOT_PORT_SCAN_WINDOW_SECONDS', 60)} saniye"
    else:
        since = timezone.now() - timedelta(minutes=minutes)
        window_label = f"{minutes} dakika"
    honeypot_qs = HoneypotEvent.objects.filter(created_at__gte=since, is_mock=False)
    if is_real_mode():
        honeypot_qs = real_honeypot_events(honeypot_qs)
    rows = list(honeypot_qs.values("source_ip", "destination_port", "service"))
    findings = detect_port_scan(rows, threshold)
    bucket = since.strftime("%Y%m%d%H%M")
    for finding in findings:
        source_ip = finding["source_ip"]
        message = (
            f"{window_label} içinde aynı kaynak IP {finding['unique_ports']} farklı honeypot port/servisine bağlanmayı denedi. "
            "Kaynak veri türü: Honeypot listener / OpenCanary logu."
        )
        Alert.objects.get_or_create(alert_type="port_scan", source_ip=source_ip, status="active",
                                    defaults={"severity": "high", "title": "Port tarama saldırısı şüphesi", "message": message})
        SecurityEvent.objects.get_or_create(event_type="port_scan", source_ip=source_ip,
                                            title=f"Port tarama saldırısı şüphesi {bucket}",
                                            defaults={"description": message, "level": "danger", "risk_score": 75})
    return findings
