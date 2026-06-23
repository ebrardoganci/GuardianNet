import hashlib
import json
import shutil
from datetime import datetime
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from dashboard.models import HoneypotEvent, SystemSetting
from dashboard.services.runtime_settings import get_bool, get_value


PORT_SERVICES = {21: "ftp", 22: "ssh", 80: "http", 8080: "http", 2121: "ftp", 2222: "ssh"}
SUPPORTED_SERVICES = {"ssh", "http", "ftp"}
EVENT_ID_KEYS = ("event_id", "id", "uuid", "log_id", "logid")
TIMESTAMP_KEYS = ("local_time", "timestamp", "time", "utc_time")


def _resolve_log_path(value, prefer_cwd=False):
    path = Path(str(value)).expanduser()
    if path.is_absolute():
        return path
    if prefer_cwd:
        cwd_path = Path.cwd() / path
        if cwd_path.exists():
            return cwd_path
    return Path(settings.PROJECT_ROOT) / path


def get_log_path():
    return _resolve_log_path(get_value("opencanary_log_path", settings.OPENCANARY_LOG_PATH))


def get_honeypot_status():
    path = get_log_path()
    enabled = get_bool("enable_honeypot_logs", settings.ENABLE_HONEYPOT_LOGS)
    available = enabled and path.is_file()
    if available:
        mode = "opencanary"
        label = "OpenCanary loglari aktif"
    elif enabled:
        mode = "unavailable"
        label = "OpenCanary logu bulunamadi"
    else:
        mode = "disabled"
        label = "Honeypot loglari kapali"
    return {"mode": mode,
            "label": label,
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


def _first_value(*sources_and_keys):
    for source, keys in sources_and_keys:
        for key in keys:
            value = source.get(key) if isinstance(source, dict) else None
            if value not in (None, ""):
                return value
    return None


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "success", "succeeded"}


def _normalize_service(value, destination_port=None):
    raw = str(value or "").lower()
    for service in SUPPORTED_SERVICES:
        if service in raw:
            return service
    return PORT_SERVICES.get(destination_port, "http")


def _event_values(payload):
    logdata = payload.get("logdata") if isinstance(payload.get("logdata"), dict) else {}
    source_ip = _first_value(
        (payload, ("src_host", "src_ip", "source_ip", "remote_ip", "remote_addr")),
        (logdata, ("REMOTE_IP", "REMOTE_ADDR", "SRC_HOST", "SRC_IP")),
    )
    destination_port = _first_value(
        (payload, ("dst_port", "destination_port", "port")),
        (logdata, ("PORT", "DST_PORT", "DESTINATION_PORT")),
    )
    try:
        destination_port = int(destination_port) if destination_port else None
    except (TypeError, ValueError):
        destination_port = None
    service = _normalize_service(_first_value((payload, ("service", "protocol", "logtype"))), destination_port)
    username = str(_first_value((logdata, ("USERNAME", "USER", "USER_NAME")), (payload, ("username", "user"))) or "")[:100]
    command = str(_first_value(
        (logdata, ("COMMAND", "URL", "URI", "REQUEST", "REQUEST_URI", "PATH")),
        (payload, ("command", "request", "path", "message")),
    ) or "")[:255]
    success = _as_bool(_first_value((logdata, ("SUCCESS",)), (payload, ("login_success", "success"))) or False)
    observed_at = _parse_time(_first_value((payload, TIMESTAMP_KEYS), (logdata, TIMESTAMP_KEYS)))
    return source_ip, service, username, command, destination_port, success, observed_at


def _event_id(payload, source_ip, service, username, command, destination_port, observed_at):
    explicit = _first_value((payload, EVENT_ID_KEYS))
    if explicit:
        explicit = str(explicit)
        return explicit if len(explicit) <= 64 else hashlib.sha256(f"event-id:{explicit}".encode("utf-8")).hexdigest()
    timestamp = observed_at.isoformat() if observed_at else str(_first_value((payload, TIMESTAMP_KEYS)) or "")
    fingerprint = json.dumps(
        {
            "source_ip": source_ip,
            "service": service,
            "timestamp": timestamp,
            "username": username,
            "command": command,
            "destination_port": destination_port,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()


def ingest_honeypot_logs(path=None):
    if not get_bool("enable_honeypot_logs", settings.ENABLE_HONEYPOT_LOGS):
        return {"success": True, "read": 0, "created": 0, "skipped": 0, "invalid": 0,
                "message": "Honeypot log entegrasyonu kapali."}
    log_path = _resolve_log_path(path, prefer_cwd=True) if path else get_log_path()
    if not log_path.is_file():
        return {"success": True, "read": 0, "created": 0, "skipped": 0, "invalid": 0, "missing": True,
                "message": f"OpenCanary logu bulunamadi: {log_path}"}
    read_count = created_count = skipped = invalid = 0
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            read_count += 1
            raw = line.strip()
            if not raw:
                continue
            try:
                payload = json.loads(raw)
                source_ip, service, username, command, port, success, observed_at = _event_values(payload)
                if not source_ip:
                    raise ValueError("Kaynak IP yok")
                event_id = _event_id(payload, source_ip, service, username, command, port, observed_at)
                if HoneypotEvent.objects.filter(event_id=event_id).exists():
                    skipped += 1
                    continue
                event = HoneypotEvent.objects.create(event_id=event_id, source_ip=source_ip, service=service,
                                                     username=username, command=command, destination_port=port,
                                                     login_success=success, raw_data=payload, is_mock=False)
                if observed_at:
                    HoneypotEvent.objects.filter(pk=event.pk).update(created_at=observed_at)
                created_count += 1
            except (json.JSONDecodeError, ValueError, TypeError):
                invalid += 1
    SystemSetting.objects.update_or_create(key="last_honeypot_ingest", defaults={"value": timezone.now().isoformat(), "description": "Son OpenCanary log aktarimi"})
    return {"success": True, "read": read_count, "created": created_count, "skipped": skipped, "invalid": invalid,
            "message": f"{read_count} satir okundu, {created_count} event eklendi, {skipped} duplicate atlandi, {invalid} satir gecersizdi."}
