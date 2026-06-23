from django.core.management.base import BaseCommand
from django.utils import timezone

from dashboard.models import SystemSetting
from dashboard.services.honeypot_manager import ingest_honeypot_logs
from dashboard.services.network_scanner import scan_network
from dashboard.services.security_analysis import run_security_analysis


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

    def _run_scan(self, limit):
        result = scan_network(limit=limit)
        SystemSetting.objects.update_or_create(
            key="last_network_scan",
            defaults={"value": timezone.now().isoformat(), "description": "Son ag kesfi"},
        )
        return result

    def _write_step_result(self, label, result):
        if result.get("success", True):
            self.stdout.write(self.style.SUCCESS(f"{label}: tamamlandi"))
        else:
            self.stdout.write(self.style.WARNING(f"{label}: hata - {result.get('error') or result.get('message', 'bilinmiyor')}"))

    def handle(self, *args, **options):
        scan_result = None
        honeypot_result = None
        analysis_result = None
        step_errors = []

        if options["skip_scan"]:
            self.stdout.write("Scan: atlandi")
        else:
            try:
                scan_result = self._run_scan(options.get("scan_limit"))
                self._write_step_result("Scan", scan_result)
            except Exception as exc:
                step_errors.append(("scan", str(exc)))
                self.stdout.write(self.style.ERROR(f"Scan adimi hata verdi: {exc}"))

        if options["skip_honeypot"]:
            self.stdout.write("Honeypot: atlandi")
        else:
            try:
                honeypot_result = ingest_honeypot_logs()
                self._write_step_result("Honeypot", honeypot_result)
            except Exception as exc:
                step_errors.append(("honeypot", str(exc)))
                self.stdout.write(self.style.ERROR(f"Honeypot adimi hata verdi: {exc}"))

        if options["skip_analysis"]:
            self.stdout.write("Analysis: atlandi")
        else:
            try:
                analysis_result = run_security_analysis()
                self.stdout.write(self.style.SUCCESS("Analysis: tamamlandi"))
            except Exception as exc:
                step_errors.append(("analysis", str(exc)))
                self.stdout.write(self.style.ERROR(f"Analysis adimi hata verdi: {exc}"))

        error_steps = {step for step, _ in step_errors}
        scan_summary = (
            f"success={scan_result.get('success')}, found={scan_result.get('found_devices')}, new={scan_result.get('new_devices')}"
            if scan_result else "error" if "scan" in error_steps else "skipped"
        )
        honeypot_summary = (
            f"read={honeypot_result.get('read', 0)}, created={honeypot_result.get('created', 0)}, "
            f"duplicate={honeypot_result.get('skipped', 0)}, parse_errors={honeypot_result.get('invalid', 0)}"
            if honeypot_result else "error" if "honeypot" in error_steps else "skipped"
        )
        analysis_summary = (
            f"ARP={analysis_result.get('arp')}, port={analysis_result.get('port')}, SSH={analysis_result.get('ssh')}, risk={analysis_result.get('risk')}"
            if analysis_result else "error" if "analysis" in error_steps else "skipped"
        )

        self.stdout.write("Monitoring cycle ozeti:")
        self.stdout.write(f"  scan: {scan_summary}")
        self.stdout.write(f"  honeypot: {honeypot_summary}")
        self.stdout.write(f"  analysis: {analysis_summary}")
        if step_errors:
            joined = "; ".join(f"{step}: {message}" for step, message in step_errors)
            self.stdout.write(self.style.WARNING(f"Hata veren adimlar: {joined}"))
