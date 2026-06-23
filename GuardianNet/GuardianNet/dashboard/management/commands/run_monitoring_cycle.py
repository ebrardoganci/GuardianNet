from django.core.management.base import BaseCommand
from django.utils import timezone

from dashboard.models import MonitoringCycleRun, SystemSetting
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

    def _overall_status(self, step_statuses):
        attempted = [status for status in step_statuses if status != "skipped"]
        if not attempted:
            return "completed"
        failed = [status for status in attempted if status == "failed"]
        completed = [status for status in attempted if status == "completed"]
        if failed and completed:
            return "partial"
        if failed:
            return "failed"
        return "completed"

    def handle(self, *args, **options):
        cycle_run = MonitoringCycleRun.objects.create(
            raw_summary={
                "options": {
                    "scan_limit": options.get("scan_limit"),
                    "skip_scan": options["skip_scan"],
                    "skip_honeypot": options["skip_honeypot"],
                    "skip_analysis": options["skip_analysis"],
                }
            }
        )
        scan_result = None
        honeypot_result = None
        analysis_result = None
        step_errors = []
        scan_status = "skipped" if options["skip_scan"] else "pending"
        honeypot_status = "skipped" if options["skip_honeypot"] else "pending"
        analysis_status = "skipped" if options["skip_analysis"] else "pending"

        if options["skip_scan"]:
            self.stdout.write("Scan: atlandi")
        else:
            try:
                scan_result = self._run_scan(options.get("scan_limit"))
                scan_status = "completed" if scan_result.get("success") else "failed"
                if scan_status == "failed":
                    step_errors.append(("scan", scan_result.get("error") or scan_result.get("message", "bilinmiyor")))
                self._write_step_result("Scan", scan_result)
            except Exception as exc:
                scan_status = "failed"
                step_errors.append(("scan", str(exc)))
                self.stdout.write(self.style.ERROR(f"Scan adimi hata verdi: {exc}"))

        if options["skip_honeypot"]:
            self.stdout.write("Honeypot: atlandi")
        else:
            try:
                honeypot_result = ingest_honeypot_logs()
                honeypot_status = "completed" if honeypot_result.get("success") else "failed"
                if honeypot_status == "failed":
                    step_errors.append(("honeypot", honeypot_result.get("message", "bilinmiyor")))
                self._write_step_result("Honeypot", honeypot_result)
            except Exception as exc:
                honeypot_status = "failed"
                step_errors.append(("honeypot", str(exc)))
                self.stdout.write(self.style.ERROR(f"Honeypot adimi hata verdi: {exc}"))

        if options["skip_analysis"]:
            self.stdout.write("Analysis: atlandi")
        else:
            try:
                analysis_result = run_security_analysis()
                analysis_status = "completed"
                self.stdout.write(self.style.SUCCESS("Analysis: tamamlandi"))
            except Exception as exc:
                analysis_status = "failed"
                step_errors.append(("analysis", str(exc)))
                self.stdout.write(self.style.ERROR(f"Analysis adimi hata verdi: {exc}"))

        scan_summary = (
            f"success={scan_result.get('success')}, found={scan_result.get('found_devices')}, new={scan_result.get('new_devices')}"
            if scan_result else "error" if scan_status == "failed" else "skipped"
        )
        honeypot_summary = (
            f"read={honeypot_result.get('read', 0)}, created={honeypot_result.get('created', 0)}, "
            f"duplicate={honeypot_result.get('skipped', 0)}, parse_errors={honeypot_result.get('invalid', 0)}"
            if honeypot_result else "error" if honeypot_status == "failed" else "skipped"
        )
        analysis_summary = (
            f"ARP={analysis_result.get('arp')}, port={analysis_result.get('port')}, SSH={analysis_result.get('ssh')}, risk={analysis_result.get('risk')}"
            if analysis_result else "error" if analysis_status == "failed" else "skipped"
        )
        error_summary = "; ".join(f"{step}: {message}" for step, message in step_errors)

        cycle_run.completed_at = timezone.now()
        cycle_run.status = self._overall_status([scan_status, honeypot_status, analysis_status])
        cycle_run.scan_status = scan_status
        cycle_run.scan_found_devices = scan_result.get("found_devices", 0) if scan_result else 0
        cycle_run.scan_new_devices = scan_result.get("new_devices", 0) if scan_result else 0
        cycle_run.honeypot_status = honeypot_status
        cycle_run.honeypot_read_lines = honeypot_result.get("read", 0) if honeypot_result else 0
        cycle_run.honeypot_created_events = honeypot_result.get("created", 0) if honeypot_result else 0
        cycle_run.honeypot_duplicates = honeypot_result.get("skipped", 0) if honeypot_result else 0
        cycle_run.honeypot_parse_errors = honeypot_result.get("invalid", 0) if honeypot_result else 0
        cycle_run.analysis_status = analysis_status
        cycle_run.arp_alerts = analysis_result.get("arp", 0) if analysis_result else 0
        cycle_run.port_alerts = analysis_result.get("port", 0) if analysis_result else 0
        cycle_run.ssh_alerts = analysis_result.get("ssh", 0) if analysis_result else 0
        cycle_run.risk_score = analysis_result.get("risk", 0) if analysis_result else 0
        cycle_run.error_summary = error_summary
        cycle_run.raw_summary = {
            "options": {
                "scan_limit": options.get("scan_limit"),
                "skip_scan": options["skip_scan"],
                "skip_honeypot": options["skip_honeypot"],
                "skip_analysis": options["skip_analysis"],
            },
            "scan": scan_result,
            "honeypot": honeypot_result,
            "analysis": analysis_result,
            "errors": [{"step": step, "message": message} for step, message in step_errors],
        }
        cycle_run.save()

        self.stdout.write("Monitoring cycle ozeti:")
        self.stdout.write(f"  scan: {scan_summary}")
        self.stdout.write(f"  honeypot: {honeypot_summary}")
        self.stdout.write(f"  analysis: {analysis_summary}")
        if step_errors:
            self.stdout.write(self.style.WARNING(f"Hata veren adimlar: {error_summary}"))
