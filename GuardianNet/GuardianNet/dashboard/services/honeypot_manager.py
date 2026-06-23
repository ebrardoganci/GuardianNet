import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from dashboard.models import HoneypotEvent, SystemSetting
from dashboard.services.runtime_settings import get_bool, get_value


PORT_SERVICES = {21: "ftp", 22: "ssh", 80: "http", 8080: "http"}


def get_log_path():
    return Path(str(get_value("opencanary_log_path", settings.OPENCANARY_LOG_PATH)))


def get_honeypot_status():
    path = get_log_path()
    enabled = get_bool("enable_honeypot_logs", settings.ENABLE_HONEYPOT_LOGS)
    available = enabled and path.is_file()
    return {"mode": "opencanary" if available else "demo",
            "label": "OpenCanary loglari aktif" if available else "OpenCanary bulunamadi / demo fallback",
            "services": {"ssh": "izleniyor", "http": "izleniyor", "ftp": "izleniyor"},
            "available": available, "executable": shutil.which("opencanaryd") is not None, "log_path": str(path)}


def _parse_time(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else timezone.make_aware(parsed)
    except (TypeError, ValueError):
        return None


def _event_values(payload):
    logdata = payload.get("logdata") if isinstance(payload.get("logdata"), dict) else {}
    source_ip = payload.get("src_host") or payload.get("source_ip") or logdata.get("REMOTE_IP")
    destination_port = payload.get("dst_port") or logdata.get("PORT")
    try:
        destination_port = int(destination_port) if destination_port else None
    except (TypeError, ValueError):
        destination_port = None
    service = str(payload.get("service") or PORT_SERVICES.get(destination_port, "http")).lower()
    if service not in {"ssh", "http", "ftp"}:
        service = PORT_SERVICES.get(destination_port, "http")
    username = str(logdata.get("USERNAME") or payload.get("username") or "")[:100]
    command = str(logdata.get("COMMAND") or logdata.get("URL") or payload.get("message") or "")[:255]
    success = bool(logdata.get("SUCCESS") or payload.get("login_success", False))
    return source_ip, service, username, command, destination_port, success


def ingest_honeypot_logs(path=None):
    if not get_bool("enable_honeypot_logs", settings.ENABLE_HONEYPOT_LOGS):
        return {"success": True, "created": 0, "skipped": 0, "message": "Honeypot log entegrasyonu kapali."}
    log_path = Path(path) if path else get_log_path()
    if not log_path.is_file():
        return {"success": False, "created": 0, "skipped": 0, "message": f"Log dosyasi bulunamadi: {log_path}"}
    created_count = skipped = invalid = 0
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            raw = line.strip()
            if not raw:
                continue
            event_id = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            if HoneypotEvent.objects.filter(event_id=event_id).exists():
                skipped += 1
                continue
            try:
                payload = json.loads(raw)
                source_ip, service, username, command, port, success = _event_values(payload)
                if not source_ip:
                    raise ValueError("Kaynak IP yok")
                event = HoneypotEvent.objects.create(event_id=event_id, source_ip=source_ip, service=service,
                                                     username=username, command=command, destination_port=port,
                                                     login_success=success, raw_data=payload, is_mock=False)
                observed_at = _parse_time(payload.get("local_time") or payload.get("timestamp"))
                if observed_at:
                    HoneypotEvent.objects.filter(pk=event.pk).update(created_at=observed_at)
                created_count += 1
            except (json.JSONDecodeError, ValueError, TypeError):
                invalid += 1
    SystemSetting.objects.update_or_create(key="last_honeypot_ingest", defaults={"value": timezone.now().isoformat(), "description": "Son OpenCanary log aktarimi"})
    return {"success": True, "created": created_count, "skipped": skipped, "invalid": invalid,
            "message": f"{created_count} log eklendi, {skipped} log zaten vardi, {invalid} satir gecersizdi."}
