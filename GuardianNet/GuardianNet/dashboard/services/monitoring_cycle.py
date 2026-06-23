from django.utils import timezone

from dashboard.models import MonitoringCycleRun, SystemSetting
from dashboard.services.honeypot_manager import ingest_honeypot_logs
from dashboard.services.network_scanner import scan_network
from dashboard.services.security_analysis import run_security_analysis


def _overall_status(step_statuses):
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


def _run_scan(limit):
    result = scan_network(limit=limit)
    SystemSetting.objects.update_or_create(
        key="last_network_scan",
        defaults={"value": timezone.now().isoformat(), "description": "Son ag kesfi"},
    )
    return result


def _scan_summary(scan_result, scan_status):
    if scan_result:
        return (
            f"success={scan_result.get('success')}, "
            f"found={scan_result.get('found_devices')}, "
            f"new={scan_result.get('new_devices')}"
        )
    return "error" if scan_status == "failed" else "skipped"


def _honeypot_summary(honeypot_result, honeypot_status):
    if honeypot_result:
        return (
            f"read={honeypot_result.get('read', 0)}, "
            f"created={honeypot_result.get('created', 0)}, "
            f"duplicate={honeypot_result.get('skipped', 0)}, "
            f"ignored={honeypot_result.get('ignored', 0)}, "
            f"parse_errors={honeypot_result.get('invalid', 0)}"
        )
    return "error" if honeypot_status == "failed" else "skipped"


def _analysis_summary(analysis_result, analysis_status):
    if analysis_result:
        return (
            f"ARP={analysis_result.get('arp')}, "
            f"port={analysis_result.get('port')}, "
            f"SSH={analysis_result.get('ssh')}, "
            f"risk={analysis_result.get('risk')}"
        )
    return "error" if analysis_status == "failed" else "skipped"


def run_monitoring_cycle(scan_limit=None, skip_scan=False, skip_honeypot=False, skip_analysis=False):
    options = {
        "scan_limit": scan_limit,
        "skip_scan": skip_scan,
        "skip_honeypot": skip_honeypot,
        "skip_analysis": skip_analysis,
    }
    cycle_run = MonitoringCycleRun.objects.create(raw_summary={"options": options})
    scan_result = None
    honeypot_result = None
    analysis_result = None
    step_errors = []
    scan_status = "skipped" if skip_scan else "pending"
    honeypot_status = "skipped" if skip_honeypot else "pending"
    analysis_status = "skipped" if skip_analysis else "pending"

    if not skip_scan:
        try:
            scan_result = _run_scan(scan_limit)
            scan_status = "completed" if scan_result.get("success") else "failed"
            if scan_status == "failed":
                step_errors.append(("scan", scan_result.get("error") or scan_result.get("message", "bilinmiyor")))
        except Exception as exc:
            scan_status = "failed"
            step_errors.append(("scan", str(exc)))

    if not skip_honeypot:
        try:
            honeypot_result = ingest_honeypot_logs()
            honeypot_status = "completed" if honeypot_result.get("success") else "failed"
            if honeypot_status == "failed":
                step_errors.append(("honeypot", honeypot_result.get("message", "bilinmiyor")))
        except Exception as exc:
            honeypot_status = "failed"
            step_errors.append(("honeypot", str(exc)))

    if not skip_analysis:
        try:
            analysis_result = run_security_analysis()
            analysis_status = "completed"
        except Exception as exc:
            analysis_status = "failed"
            step_errors.append(("analysis", str(exc)))

    error_summary = "; ".join(f"{step}: {message}" for step, message in step_errors)
    cycle_run.completed_at = timezone.now()
    cycle_run.status = _overall_status([scan_status, honeypot_status, analysis_status])
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
        "options": options,
        "scan": scan_result,
        "honeypot": honeypot_result,
        "analysis": analysis_result,
        "errors": [{"step": step, "message": message} for step, message in step_errors],
    }
    cycle_run.save()

    return {
        "cycle_run": cycle_run,
        "scan_result": scan_result,
        "honeypot_result": honeypot_result,
        "analysis_result": analysis_result,
        "scan_status": scan_status,
        "honeypot_status": honeypot_status,
        "analysis_status": analysis_status,
        "status": cycle_run.status,
        "step_errors": step_errors,
        "error_summary": error_summary,
        "scan_summary": _scan_summary(scan_result, scan_status),
        "honeypot_summary": _honeypot_summary(honeypot_result, honeypot_status),
        "analysis_summary": _analysis_summary(analysis_result, analysis_status),
    }
