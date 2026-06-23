from django.core.management.base import BaseCommand

from dashboard.services.arp_monitor import analyze_arp_observations
from dashboard.services.bruteforce_detector import analyze_bruteforce_logs
from dashboard.services.port_scan_detector import analyze_port_scan_logs
from dashboard.services.risk_engine import create_risk_snapshot


class Command(BaseCommand):
    help = "Kayitli guvenlik verilerini analiz eder ve risk puanini gunceller."

    def handle(self, *args, **options):
        arp = analyze_arp_observations()
        ports = analyze_port_scan_logs()
        brute = analyze_bruteforce_logs()
        snapshot = create_risk_snapshot()
        self.stdout.write(self.style.SUCCESS(
            f"Analiz tamamlandi. ARP: {len(arp)}, port: {len(ports)}, SSH: {len(brute)}, risk: {snapshot.risk_score}"
        ))
