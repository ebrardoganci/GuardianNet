from django.core.management.base import BaseCommand

from dashboard.services.bruteforce_detector import analyze_bruteforce_logs
from dashboard.services.honeypot_manager import ingest_honeypot_logs
from dashboard.services.port_scan_detector import analyze_port_scan_logs


class Command(BaseCommand):
    help = "OpenCanary JSON loglarini tekillestirerek aktarir ve savunma analizlerini calistirir."

    def add_arguments(self, parser):
        parser.add_argument("--path", help="Varsayilan OPENCANARY_LOG_PATH yerine okunacak log dosyasi.")

    def handle(self, *args, **options):
        result = ingest_honeypot_logs(path=options.get("path"))
        port_findings = analyze_port_scan_logs()
        brute_findings = analyze_bruteforce_logs()
        message = (
            f"{result['message']} "
            f"Satir: {result.get('read', 0)}, eklendi: {result.get('created', 0)}, "
            f"duplicate: {result.get('skipped', 0)}, parse hatasi: {result.get('invalid', 0)}. "
            f"Port tarama suphesi: {len(port_findings)}, SSH suphesi: {len(brute_findings)}"
        )
        self.stdout.write(self.style.SUCCESS(message) if result["success"] else self.style.WARNING(message))
