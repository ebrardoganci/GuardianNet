from django.core.management.base import BaseCommand

from dashboard.services.bruteforce_detector import analyze_bruteforce_logs
from dashboard.services.honeypot_manager import ingest_honeypot_logs
from dashboard.services.port_scan_detector import analyze_port_scan_logs


class Command(BaseCommand):
    help = "OpenCanary JSON loglarini tekillestirerek aktarir ve savunma analizlerini calistirir."

    def handle(self, *args, **options):
        result = ingest_honeypot_logs()
        port_findings = analyze_port_scan_logs()
        brute_findings = analyze_bruteforce_logs()
        message = f"{result['message']} Port tarama suphesi: {len(port_findings)}, SSH suphesi: {len(brute_findings)}"
        self.stdout.write(self.style.SUCCESS(message) if result["success"] else self.style.WARNING(message))
