from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from dashboard.models import Alert, Device, HoneypotEvent, RiskSnapshot, SecurityEvent, SystemSetting
from dashboard.services.network_scanner import DEMO_DEVICES


class Command(BaseCommand):
    help = "GuardianNet icin tekrar kullanilabilir demo verisi olusturur."

    def handle(self, *args, **options):
        devices = {}
        for data in DEMO_DEVICES:
            device, _ = Device.objects.update_or_create(ip_address=data["ip_address"], defaults=data)
            devices[data["ip_address"]] = device

        alert_rows = [
            ("demo-new-device", "new_device", "medium", "Yeni demo cihaz", "192.0.2.21", "active"),
            ("demo-port-detection", "port_scan", "high", "Port tarama davranisi tespit edildi", "192.0.2.45", "investigating"),
            ("demo-honeypot", "honeypot", "critical", "Honeypot etkilesimi", "198.51.100.23", "active"),
        ]
        for key, alert_type, severity, title, source_ip, status in alert_rows:
            Alert.objects.update_or_create(
                title=f"[{key}] {title}",
                defaults={"alert_type": alert_type, "severity": severity, "status": status,
                          "message": "Savunma amacli demo tespit kaydi.", "source_ip": source_ip,
                          "device": devices.get(source_ip)},
            )

        event_rows = [
            ("demo-network", "network", "Ag gozlemi", "192.0.2.21", "192.0.2.1", 443, "TCP", 20),
            ("demo-port", "port_scan", "Port tarama davranisi", "192.0.2.45", "192.0.2.10", 22, "TCP", 72),
            ("demo-honeypot-event", "honeypot", "Honeypot baglantisi", "198.51.100.23", "192.0.2.10", 22, "TCP", 88),
        ]
        for key, event_type, title, source_ip, destination_ip, port, protocol, score in event_rows:
            SecurityEvent.objects.update_or_create(
                title=f"[{key}] {title}",
                defaults={"event_type": event_type, "description": "Demo log verisinden uretilen olay.",
                          "level": "danger" if score >= 70 else "warning", "source_ip": source_ip,
                          "destination_ip": destination_ip, "destination_port": port,
                          "protocol": protocol, "risk_score": score},
            )

        honeypot_rows = [
            ("198.51.100.23", "ssh", "demo-user", "authentication failed"),
            ("203.0.113.18", "http", "", "GET /admin"),
            ("198.51.100.44", "ftp", "anonymous", "login attempt"),
        ]
        for source_ip, service, username, command in honeypot_rows:
            HoneypotEvent.objects.update_or_create(
                source_ip=source_ip, service=service, command=command,
                defaults={"username": username, "is_mock": True},
            )

        SystemSetting.objects.update_or_create(
            key="data_mode", defaults={"value": "demo", "description": "Gercek araclar yoksa kullanilan veri modu"}
        )
        now = timezone.now()
        snapshots = [(2, 31, 69), (1, 44, 56), (0, 62, 38)]
        for days_ago, risk, security in snapshots:
            marker = f"demo-risk-{days_ago}"
            setting, _ = SystemSetting.objects.get_or_create(key=marker, defaults={"value": "created"})
            snapshot, created = RiskSnapshot.objects.get_or_create(
                pk=1000 + days_ago,
                defaults={"risk_level": "medium" if risk < 60 else "high", "risk_score": risk,
                          "security_score": security, "active_alerts": 3},
            )
            if created:
                RiskSnapshot.objects.filter(pk=snapshot.pk).update(recorded_at=now - timedelta(days=days_ago))

        self.stdout.write(self.style.SUCCESS("Demo verisi hazirlandi; mevcut demo kayitlari yinelenmedi."))
