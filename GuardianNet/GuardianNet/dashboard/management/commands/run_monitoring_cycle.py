from django.core.management.base import BaseCommand

from dashboard.services.monitoring_cycle import run_monitoring_cycle


class Command(BaseCommand):
    help = "Ag kesfi, honeypot log aktarimi ve guvenlik analizini tek monitoring cycle olarak calistirir."

    def add_arguments(self, parser):
        parser.add_argument(
            "--scan-limit",
            type=int,
            help="Ag kesfinde taranacak host hedef sayisini sinirlar.",
        )
        parser.add_argument("--skip-scan", action="store_true", help="Ag kesfi adimini atla.")
        parser.add_argument("--skip-honeypot", action="store_true", help="OpenCanary log aktarimi adimini atla.")
        parser.add_argument("--skip-analysis", action="store_true", help="Guvenlik analizi adimini atla.")

    def _write_step_result(self, label, status, result):
        if status == "skipped":
            self.stdout.write(f"{label}: atlandi")
        elif status == "completed":
            self.stdout.write(self.style.SUCCESS(f"{label}: tamamlandi"))
        else:
            message = (result or {}).get("error") or (result or {}).get("message", "bilinmiyor")
            self.stdout.write(self.style.ERROR(f"{label}: hata - {message}"))

    def handle(self, *args, **options):
        result = run_monitoring_cycle(
            scan_limit=options.get("scan_limit"),
            skip_scan=options["skip_scan"],
            skip_honeypot=options["skip_honeypot"],
            skip_analysis=options["skip_analysis"],
        )

        self._write_step_result("Scan", result["scan_status"], result["scan_result"])
        self._write_step_result("Honeypot", result["honeypot_status"], result["honeypot_result"])
        self._write_step_result("Analysis", result["analysis_status"], result["analysis_result"])

        self.stdout.write("Monitoring cycle ozeti:")
        self.stdout.write(f"  scan: {result['scan_summary']}")
        self.stdout.write(f"  honeypot: {result['honeypot_summary']}")
        self.stdout.write(f"  analysis: {result['analysis_summary']}")
        if result["step_errors"]:
            self.stdout.write(self.style.WARNING(f"Hata veren adimlar: {result['error_summary']}"))
