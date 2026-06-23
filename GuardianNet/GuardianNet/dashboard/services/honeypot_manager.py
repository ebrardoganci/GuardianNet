import hashlib
import ipaddress
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
SOURCE_IP_KEYS = ("src_host", "src_ip", "source_ip", "source", "remote_ip", "remote_addr", "host")
DESTINATION_PORT_KEYS = ("dst_port", "destination_port", "port", "dport")
USERNAME_KEYS = ("USERNAME", "USER", "USER_NAME", "username", "user", "login")
COMMAND_KEYS = (
    "COMMAND", "command", "URL", "url", "URI", "uri", "REQUEST", "request",
    "REQUEST_URI", "request_uri", "PATH", "path", "message", "msg",
)
SUCCESS_KEYS = ("SUCCESS", "login_success", "success")
LIFECYCLE_LOGTYPES = {"1001"}
LIFECYCLE_MARKERS = ("canary running", "added service", "starting", "started", "listening")


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


def _value_from_dict(source, keys):
    if not isinstance(source, dict):
        return None
    for key in keys:
        value = source.get(key)
        if value not in (None, ""):
            return value
    lowered = {str(key).lower(): value for key, value in source.items()}
    for key in keys:
        value = lowered.get(str(key).lower())
        if value not in (None, ""):
            return value
    return None


def _first_value(*sources_and_keys):
    for source, keys in sources_and_keys:
        value = _value_from_dict(source, keys)
        if value not in (None, ""):
            return value
    return None


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "success", "succeeded"}


def _normalize_service(value, destination_port=None, logdata=None):
    raw = str(value or "").lower()
    for service in SUPPORTED_SERVICES:
        if service in raw:
            return service
    if destination_port in PORT_SERVICES:
        return PORT_SERVICES[destination_port]
    if _first_value((logdata, ("PATH", "REQUEST", "URL", "HOSTNAME", "USERAGENT"))):
        return "http"
    return "http"


def _parse_port(value):
    try:
        port = int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None
    return port if port and 0 < port <= 65535 else None


def _normalize_source_ip(value):
    if value in (None, ""):
        return ""
    source_ip = str(value).strip()
    if not source_ip:
        return ""
    try:
        return str(ipaddress.ip_address(source_ip))
    except ValueError as exc:
        raise ValueError("Kaynak IP gecersiz") from exc


def _logdata_sections(payload):
    logdata = payload.get("logdata") if isinstance(payload.get("logdata"), dict) else {}
    msg = _value_from_dict(logdata, ("msg", "message"))
    nested = msg if isinstance(msg, dict) else {}
    return logdata, nested


def _payload_message(payload):
    logdata, nested = _logdata_sections(payload)
    value = _first_value((nested, ("logdata", "message", "msg")), (logdata, ("logdata", "message", "msg")), (payload, ("message", "msg")))
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value or "")


def _is_lifecycle_payload(payload, source_ip, destination_port):
    logtype = str(_first_value((payload, ("logtype", "event_type"))) or "").strip().lower()
    message = _payload_message(payload).strip().lower()
    if source_ip:
        return False
    if logtype in LIFECYCLE_LOGTYPES:
        return True
    if destination_port is None and any(marker in message for marker in LIFECYCLE_MARKERS):
        return True
    return False


def _event_values(payload):
    logdata, nested = _logdata_sections(payload)
    source_ip = _first_value(
        (payload, SOURCE_IP_KEYS),
        (logdata, SOURCE_IP_KEYS + ("REMOTE_IP", "REMOTE_ADDR", "SRC_HOST", "SRC_IP")),
        (nested, SOURCE_IP_KEYS + ("REMOTE_IP", "REMOTE_ADDR", "SRC_HOST", "SRC_IP")),
    )
    destination_port = _first_value(
        (payload, DESTINATION_PORT_KEYS),
        (logdata, DESTINATION_PORT_KEYS + ("PORT", "DST_PORT", "DESTINATION_PORT")),
        (nested, DESTINATION_PORT_KEYS + ("PORT", "DST_PORT", "DESTINATION_PORT")),
    )
    destination_port = _parse_port(destination_port)
    service = _normalize_service(_first_value((payload, ("service", "protocol", "logtype")), (logdata, ("service", "protocol"))), destination_port, logdata)
    source_ip = _normalize_source_ip(source_ip)
    username = str(_first_value((logdata, USERNAME_KEYS), (nested, USERNAME_KEYS), (payload, USERNAME_KEYS)) or "")[:100]
    command = str(_first_value(
        (logdata, COMMAND_KEYS),
        (nested, COMMAND_KEYS),
        (payload, COMMAND_KEYS),
    ) or "")[:255]
    success = _as_bool(_first_value((logdata, SUCCESS_KEYS), (nested, SUCCESS_KEYS), (payload, SUCCESS_KEYS)) or False)
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
        return {"success": True, "read": 0, "created": 0, "skipped": 0, "invalid": 0, "ignored": 0,
                "message": "Honeypot log entegrasyonu kapali."}
    log_path = _resolve_log_path(path, prefer_cwd=True) if path else get_log_path()
    if not log_path.is_file():
        return {"success": True, "read": 0, "created": 0, "skipped": 0, "invalid": 0, "ignored": 0, "missing": True,
                "message": f"OpenCanary logu bulunamadi: {log_path}"}
    read_count = created_count = skipped = invalid = ignored = 0
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            read_count += 1
            raw = line.strip()
            if not raw:
                ignored += 1
                continue
            try:
                if not raw.startswith(("{", "[")):
                    ignored += 1
                    continue
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    ignored += 1
                    continue
                source_ip, service, username, command, port, success, observed_at = _event_values(payload)
                if _is_lifecycle_payload(payload, source_ip, port):
                    ignored += 1
                    continue
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
            "ignored": ignored, "parse_errors": invalid, "duplicates": skipped,
            "message": f"{read_count} satir okundu, {created_count} event eklendi, {skipped} duplicate atlandi, {ignored} non-event satir yok sayildi, {invalid} parse hatasi oldu."}
