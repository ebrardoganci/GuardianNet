from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import Alert, ArpObservation, Device, HoneypotEvent, MonitoringCycleRun, NetworkScan, OpenPort, RiskSnapshot, SecurityEvent, SystemSetting
from .security_explanations import get_alert_explanation, get_port_explanation
from .services.honeypot_manager import get_honeypot_status
from .services.monitoring_cycle import run_monitoring_cycle as execute_monitoring_cycle
from .services.network_scanner import scan_network
from .services.network_scanner import resolve_target_subnet
from .services.data_scope import (
    is_real_mode,
    real_alerts,
    real_devices,
    real_honeypot_events,
    real_risk_snapshots,
    real_security_events,
)
from .services.risk_engine import calculate_risk
from .services.runtime_health import get_runtime_health
from .services.runtime_settings import get_bool, get_value
from .services.security_data import CLEAR_TARGETS, clear_security_data


DEVICE_FILTERS = {
    "all": "Tumu",
    "online": "Online",
    "offline": "Offline",
    "partial": "Eksik bilgi",
    "new": "Yeni cihazlar",
    "alerts": "Uyarisi olan cihazlar",
}
ALERT_STATUS_FILTERS = {
    "all": "Tumu",
    "active": "Active",
    "acknowledged": "Acknowledged",
    "resolved": "Resolved",
}
ALERT_ACTION_STATUSES = {"active", "acknowledged", "resolved"}
NETWORK_PROTOCOLS = {"tcp", "udp", "icmp"}
TCP_IDENTITY_NOTE = "Bu adres TCP cevabıyla algılandı; MAC/hostname doğrulanamadı."
TCP_IDENTITY_SHORT_NOTE = "TCP/Nmap, kimlik doğrulanmadı"
NMAP_PORT_UNCERTAINTY_NOTE = "Bu port Nmap tarafından açık raporlandı; ancak cihaz kimliği doğrulanamadığı için hotspot/ağ geçidi cevabı olabilir."
MAC_UNAVAILABLE_LABEL = "Alınamadı"
MAC_UNAVAILABLE_NOTE = "ARP tablosunda bu IP için MAC kaydı bulunamadı."
MAC_UNAVAILABLE_SHORT_NOTE = "ARP kaydı yok"


def _monitoring_scan_limit_default():
    return str(get_value("monitoring_cycle_scan_limit", settings.MONITORING_CYCLE_SCAN_LIMIT) or "").strip()


def _parse_scan_limit(raw_value):
    raw_value = str(raw_value or "").strip()
    if not raw_value:
        return None
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Scan limiti pozitif bir tam sayi olmali.") from exc
    if value <= 0:
        raise ValueError("Scan limiti pozitif bir tam sayi olmali.")
    return value


def _cycle_message(result):
    scan = result["scan_result"] or {}
    honeypot = result["honeypot_result"] or {}
    analysis = result["analysis_result"] or {}
    return (
        "Monitoring cycle tamamlandi. "
        f"Scan found/new: {scan.get('found_devices', 0)}/{scan.get('new_devices', 0)}. "
        f"Honeypot read/created/duplicate/ignored/parse: "
        f"{honeypot.get('read', 0)}/{honeypot.get('created', 0)}/"
        f"{honeypot.get('skipped', 0)}/{honeypot.get('ignored', 0)}/{honeypot.get('invalid', 0)}. "
        f"Risk: {analysis.get('risk', 0)}."
    )


def _risk_context():
    _, alerts_qs, events_qs, _ = _data_sources()
    calculated = calculate_risk(alerts_qs.filter(status="active"), events_qs, include_reasons=True)
    if is_real_mode():
        return calculated
    latest = RiskSnapshot.objects.first()
    if latest:
        calculated.update({"risk_score": latest.risk_score, "risk_level": latest.risk_level, "security_score": latest.security_score})
        return calculated
    return calculated


def _data_sources():
    devices_qs = Device.objects.all()
    alerts_qs = Alert.objects.all()
    events_qs = SecurityEvent.objects.all()
    honeypot_qs = HoneypotEvent.objects.all()
    if is_real_mode():
        devices_qs = real_devices(devices_qs)
        alerts_qs = real_alerts(alerts_qs)
        events_qs = real_security_events(events_qs)
        honeypot_qs = real_honeypot_events(honeypot_qs)
    return devices_qs, alerts_qs, events_qs, honeypot_qs


def _latest_real_scan():
    return NetworkScan.objects.filter(is_mock=False, status="completed").order_by("-started_at").first()


def _has_verified_identity(device):
    return bool(_trusted_mac_observation(device) or device.hostname or (device.vendor and device.vendor != "Bilinmiyor"))


def _mac_source_label(source):
    normalized = str(source or "").lower()
    if "scapy-arp" in normalized:
        return "Scapy ARP"
    if "system-arp" in normalized:
        return "System ARP"
    if normalized == "arp" or "arp gözlemi" in normalized:
        return "ARP"
    return ""


def _trusted_mac_observation(device):
    if not device.mac_address:
        return None
    observations = ArpObservation.objects.filter(
        ip_address=device.ip_address,
        mac_address=device.mac_address,
    ).order_by("-observed_at")
    for observation in observations:
        if _mac_source_label(observation.source):
            return observation
    return None


def _mac_display(device):
    observation = _trusted_mac_observation(device)
    if observation:
        return {
            "value": device.mac_address,
            "source": _mac_source_label(observation.source),
            "note": "",
            "short_note": "",
        }
    return {
        "value": MAC_UNAVAILABLE_LABEL,
        "source": MAC_UNAVAILABLE_LABEL,
        "note": MAC_UNAVAILABLE_NOTE,
        "short_note": MAC_UNAVAILABLE_SHORT_NOTE,
    }


def _detection_source(device):
    port_sources = set(OpenPort.objects.filter(device=device).values_list("source", flat=True))
    if "nmap-port" in port_sources:
        return "TCP/Nmap"
    if "socket-fallback" in port_sources:
        return "TCP/Socket fallback"
    observation_sources = " ".join(ArpObservation.objects.filter(ip_address=device.ip_address).values_list("source", flat=True)).lower()
    if "scapy-arp" in observation_sources:
        return "ARP/Scapy"
    if "system-arp" in observation_sources:
        return "System ARP"
    return "Ağ taraması"


def _is_unverified_nmap_tcp_device(device):
    return (
        device.status == "partial"
        and not _has_verified_identity(device)
        and OpenPort.objects.filter(device=device, source="nmap-port").exists()
    )


def _device_open_port_rows(device):
    unverified_nmap_tcp = _is_unverified_nmap_tcp_device(device)
    ports_qs = OpenPort.objects.filter(device=device).order_by("port")
    rows_by_port = {}
    for open_port in ports_qs:
        if open_port.port in rows_by_port:
            continue
        explanation = get_port_explanation(open_port.port, open_port.service_name)
        rows_by_port[open_port.port] = {
            "port": open_port.port,
            "service": explanation["service"],
            "description": explanation["description"],
            "risk": explanation["risk"],
            "risk_key": explanation["risk_key"],
            "action": explanation["action"],
            "source": open_port.source or "Gerçek ağ taraması",
            "last_seen": open_port.last_seen,
            "uncertainty_note": NMAP_PORT_UNCERTAINTY_NOTE if unverified_nmap_tcp and open_port.source == "nmap-port" else "",
        }
    return [rows_by_port[key] for key in sorted(rows_by_port)]


def _open_port_event_rows(events):
    rows = []
    for event in events:
        row = {
            "event": event,
            "ip": event.source_ip or event.destination_ip or "-",
            "port": "-",
            "service": "-",
            "protocol": event.protocol or "-",
            "source_data_type": event.get_event_type_display(),
        }
        if event.event_type == "open_port":
            ip_address = event.destination_ip or event.source_ip
            open_port = None
            if ip_address and event.destination_port:
                open_port = (
                    OpenPort.objects.filter(device__ip_address=ip_address, port=event.destination_port)
                    .order_by("-last_seen")
                    .first()
                )
            raw_protocol = (open_port.protocol if open_port else event.protocol or "").lower()
            protocol = raw_protocol if raw_protocol in NETWORK_PROTOCOLS else ""
            service_hint = ""
            if open_port and open_port.service_name:
                service_hint = open_port.service_name
            elif event.protocol and event.protocol.lower() not in NETWORK_PROTOCOLS:
                service_hint = event.protocol
            service = get_port_explanation(event.destination_port, service_hint)["service"] if event.destination_port else service_hint.upper()
            source = open_port.source if open_port else ""
            row.update({
                "ip": ip_address or "-",
                "port": event.destination_port or "-",
                "service": service or "-",
                "protocol": protocol or "-",
                "source_data_type": f"OpenPort kaydı / {source or 'Güvenlik analizi'}",
            })
        rows.append(row)
    return rows


def _inventory_rows(devices_qs):
    latest_scan = _latest_real_scan()
    active_alerts_qs = real_alerts(Alert.objects.filter(status="active")) if is_real_mode() else Alert.objects.filter(status="active")
    new_alerts_qs = active_alerts_qs.filter(alert_type="new_device")
    rows = []
    for device in devices_qs:
        device_alerts = active_alerts_qs.filter(Q(device=device) | Q(source_ip=device.ip_address)).distinct()
        has_new_alert = new_alerts_qs.filter(Q(device=device) | Q(source_ip=device.ip_address)).exists()
        rows.append({
            "device": device,
            "mac": _mac_display(device),
            "detection_source": _detection_source(device),
            "seen_in_last_scan": device.status in {"online", "partial"} and latest_scan is not None,
            "active_alert_count": device_alerts.count(),
            "is_new": has_new_alert or (latest_scan is not None and device.first_seen >= latest_scan.started_at),
            "identity_note": TCP_IDENTITY_NOTE if _is_unverified_nmap_tcp_device(device) else "",
            "identity_short_note": TCP_IDENTITY_SHORT_NOTE if _is_unverified_nmap_tcp_device(device) else "",
            "open_ports": _device_open_port_rows(device),
        })
    return rows


def _apply_device_filter(rows, filter_key):
    if filter_key == "online":
        return [row for row in rows if row["device"].status == "online"]
    if filter_key == "offline":
        return [row for row in rows if row["device"].status == "offline"]
    if filter_key == "partial":
        return [row for row in rows if row["device"].status == "partial"]
    if filter_key == "new":
        return [row for row in rows if row["is_new"]]
    if filter_key == "alerts":
        return [row for row in rows if row["active_alert_count"] > 0]
    return rows


@login_required
def index(request):
    mode = get_value("guardiannet_mode", "real")
    devices_qs, alerts_qs, events_qs, honeypot_qs = _data_sources()
    online = devices_qs.filter(status="online").count()
    offline = devices_qs.filter(status="offline").count()
    partial = devices_qs.filter(status="partial").count()
    unknown = devices_qs.filter(status="unknown").count()
    latest_scan = _latest_real_scan()
    latest_cycle = MonitoringCycleRun.objects.first()
    latest_analysis = RiskSnapshot.objects.first()
    recent_honeypot_events = list(honeypot_qs[:5])
    recent_events = list(events_qs[:6])
    has_recent_ssh_honeypot_event = any(event.service == "ssh" for event in recent_honeypot_events)
    active_alerts_count = (
        real_alerts(Alert.objects.filter(status="active")).count()
        if is_real_mode()
        else Alert.objects.filter(status="active").count()
    )
    context = {
        "total_devices": devices_qs.count(), "active_devices": online,
        "online_devices": online, "offline_devices": offline, "partial_devices": partial,
        "last_scan_found_devices": latest_scan.devices_found if latest_scan else None,
        "latest_scan": latest_scan,
        "active_alerts": active_alerts_count,
        "recent_events": recent_events, "recent_event_rows": _open_port_event_rows(recent_events), "recent_alerts": alerts_qs[:6],
        "recent_honeypot_events": recent_honeypot_events,
        "has_recent_ssh_honeypot_event": has_recent_ssh_honeypot_event,
        "honeypot_status": get_honeypot_status(),
        "latest_monitoring_cycle": latest_cycle,
        "latest_analysis": latest_analysis,
        "monitoring_scan_limit_default": _monitoring_scan_limit_default(),
        "operation_mode": mode,
        "device_chart": {"labels": ["Online", "Offline", "Kısmen algılandı", "Bilinmiyor"], "values": [online, offline, partial, unknown]},
        "severity_chart": {"labels": ["Dusuk", "Orta", "Yuksek", "Kritik"], "values": [alerts_qs.filter(severity=value).count() for value in ["low", "medium", "high", "critical"]]},
        **_risk_context(),
    }
    return render(request, "dashboard/index.html", context)


@login_required
@require_POST
def run_monitoring_cycle_view(request):
    raw_limit = request.POST.get("scan_limit", "").strip() or _monitoring_scan_limit_default()
    try:
        scan_limit = _parse_scan_limit(raw_limit)
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("dashboard:index")

    result = execute_monitoring_cycle(scan_limit=scan_limit)
    message = _cycle_message(result)
    if result["status"] == "completed":
        messages.success(request, message)
    elif result["status"] == "partial":
        messages.warning(request, f"{message} Bazı adımlar tamamlanamadı; sistem ayarlarını kontrol edin.")
    else:
        messages.error(request, "İşlem tamamlanamadı. Terminal çıktısını veya sistem ayarlarını kontrol edin.")
    return redirect("dashboard:index")


@login_required
def devices(request):
    filter_key = request.GET.get("filter", "all")
    if filter_key not in DEVICE_FILTERS:
        filter_key = "all"
    devices_qs = _data_sources()[0]
    rows = _inventory_rows(devices_qs)
    filtered_rows = _apply_device_filter(rows, filter_key)
    out_of_scope_count = 0
    if is_real_mode():
        out_of_scope_count = Device.objects.exclude(pk__in=devices_qs.values("pk")).count()
    return render(request, "dashboard/devices.html", {
        "device_rows": filtered_rows,
        "device_filters": DEVICE_FILTERS,
        "active_filter": filter_key,
        "out_of_scope_count": out_of_scope_count,
        "latest_scan": _latest_real_scan(),
    })


@login_required
def device_detail(request, pk):
    device = get_object_or_404(Device, pk=pk)
    if is_real_mode() and not real_devices(Device.objects.filter(pk=device.pk)).exists():
        raise Http404("Cihaz kullanilan subnet kapsaminda degil.")
    alerts_qs = real_alerts(Alert.objects.filter(Q(device=device) | Q(source_ip=device.ip_address))) if is_real_mode() else Alert.objects.filter(Q(device=device) | Q(source_ip=device.ip_address))
    events_qs = real_security_events(SecurityEvent.objects.filter(Q(source_ip=device.ip_address) | Q(destination_ip=device.ip_address))) if is_real_mode() else SecurityEvent.objects.filter(Q(source_ip=device.ip_address) | Q(destination_ip=device.ip_address))
    row = _inventory_rows(Device.objects.filter(pk=device.pk))[0]
    return render(request, "dashboard/device_detail.html", {
        "device": device,
        "inventory": row,
        "mac": _mac_display(device),
        "detection_source": _detection_source(device),
        "alerts": alerts_qs,
        "events": events_qs,
        "open_port_rows": _device_open_port_rows(device),
    })


@login_required
def alerts(request):
    alerts_qs = _data_sources()[1].select_related("device")
    status_filter = request.GET.get("status", "all")
    severity_filter = request.GET.get("severity", "all")
    type_filter = request.GET.get("type", "all")
    if status_filter not in ALERT_STATUS_FILTERS:
        status_filter = "all"
    severity_values = {value for value, _ in Alert.SEVERITY_CHOICES}
    type_values = {value for value, _ in Alert.ALERT_TYPE_CHOICES}
    if severity_filter != "all" and severity_filter not in severity_values:
        severity_filter = "all"
    if type_filter != "all" and type_filter not in type_values:
        type_filter = "all"
    if status_filter != "all":
        alerts_qs = alerts_qs.filter(status=status_filter)
    if severity_filter != "all":
        alerts_qs = alerts_qs.filter(severity=severity_filter)
    if type_filter != "all":
        alerts_qs = alerts_qs.filter(alert_type=type_filter)
    alert_rows = [{"alert": item, "explanation": get_alert_explanation(item)} for item in alerts_qs]
    return render(request, "dashboard/alerts.html", {
        "alerts": alerts_qs,
        "alert_rows": alert_rows,
        "status_filters": ALERT_STATUS_FILTERS,
        "severity_filters": Alert.SEVERITY_CHOICES,
        "type_filters": Alert.ALERT_TYPE_CHOICES,
        "active_status_filter": status_filter,
        "active_severity_filter": severity_filter,
        "active_type_filter": type_filter,
    })


@login_required
@require_POST
def update_alert_status(request, pk):
    new_status = request.POST.get("status", "")
    next_url = request.POST.get("next", "")
    redirect_target = next_url if next_url.startswith("/") else None
    if new_status not in ALERT_ACTION_STATUSES:
        messages.error(request, "Gecersiz uyari durumu.")
        return redirect(redirect_target or "dashboard:alerts")
    queryset = real_alerts(Alert.objects.all()) if is_real_mode() else Alert.objects.all()
    alert = get_object_or_404(queryset, pk=pk)
    alert.status = new_status
    alert.save(update_fields=["status", "is_resolved", "updated_at"])
    messages.success(request, "Uyari durumu guncellendi.")
    return redirect(redirect_target or "dashboard:alerts")


@login_required
def security_events(request):
    return render(request, "dashboard/security_events.html", {"events": _data_sources()[2]})


@login_required
def reports(request):
    devices_qs, alerts_qs, events_qs, honeypot_qs = _data_sources()
    since = timezone.now() - timedelta(days=7)
    daily_counts = {}
    for row in events_qs.filter(created_at__gte=since).annotate(day=TruncDate("created_at")).values("day").annotate(total=Count("id")):
        daily_counts[row["day"]] = daily_counts.get(row["day"], 0) + row["total"]
    for row in honeypot_qs.filter(created_at__gte=since).annotate(day=TruncDate("created_at")).values("day").annotate(total=Count("id")):
        daily_counts[row["day"]] = daily_counts.get(row["day"], 0) + row["total"]
    daily = [{"day": day, "total": total} for day, total in sorted(daily_counts.items())]
    service_rows = list(honeypot_qs.values("service").annotate(total=Count("id")).order_by("service"))
    open_port_rows = list(
        OpenPort.objects.filter(device__in=devices_qs)
        .values("port")
        .annotate(total=Count("id"))
        .order_by("port")
    )
    alert_type_labels = dict(Alert.ALERT_TYPE_CHOICES)
    alert_type_rows = list(alerts_qs.values("alert_type").annotate(total=Count("id")).order_by("alert_type"))
    snapshot_qs = RiskSnapshot.objects.order_by("recorded_at")
    if is_real_mode():
        snapshot_qs = real_risk_snapshots(snapshot_qs)
    snapshots = list(snapshot_qs)
    online = devices_qs.filter(status="online").count()
    offline = devices_qs.filter(status="offline").count()
    partial = devices_qs.filter(status="partial").count()
    untrusted = devices_qs.filter(is_trusted=False).count()
    new_devices = devices_qs.filter(first_seen__gte=since).count()
    activity_chart = {"labels": [row["day"].isoformat() for row in daily], "values": [row["total"] for row in daily]}
    risk_chart = {"labels": [item.recorded_at.strftime("%d.%m") for item in snapshots], "values": [item.risk_score for item in snapshots]}
    device_report_chart = {"labels": ["Online", "Offline", "Kısmen algılandı", "Güvenilmeyen", "Yeni cihaz"], "values": [online, offline, partial, untrusted, new_devices]}
    service_chart = {"labels": [row["service"].upper() for row in service_rows], "values": [row["total"] for row in service_rows]}
    open_port_chart = {"labels": [str(row["port"]) for row in open_port_rows], "values": [row["total"] for row in open_port_rows]}
    alert_type_chart = {"labels": [alert_type_labels.get(row["alert_type"], row["alert_type"]) for row in alert_type_rows], "values": [row["total"] for row in alert_type_rows]}
    context = {
        "risky_devices": devices_qs.order_by("-risk_score")[:10],
        "daily_chart": activity_chart,
        "risk_chart": risk_chart,
        "device_report_chart": device_report_chart,
        "service_chart": service_chart,
        "open_port_chart": open_port_chart,
        "alert_type_chart": alert_type_chart,
        "has_report_data": any(activity_chart["values"] + risk_chart["values"] + device_report_chart["values"] + service_chart["values"] + open_port_chart["values"] + alert_type_chart["values"]),
    }
    return render(request, "dashboard/reports.html", context)


@login_required
def honeypot(request):
    honeypot_status = get_honeypot_status()
    empty_message = "OpenCanary logu bulunamadi" if is_real_mode() and not honeypot_status["available"] else "Henuz gercek honeypot olayi yok"
    return render(request, "dashboard/honeypot.html", {
        "honeypot_status": honeypot_status,
        "events": _data_sources()[3],
        "honeypot_empty_message": empty_message,
    })


@login_required
def settings_view(request):
    if request.method == "POST":
        raw_scan_limit = request.POST.get("monitoring_cycle_scan_limit", "").strip()
        try:
            scan_limit_value = str(_parse_scan_limit(raw_scan_limit)) if raw_scan_limit else ""
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect("dashboard:settings")
        values = {
            "guardiannet_mode": "real",
            "scan_interval_seconds": request.POST.get("scan_interval_seconds", "300"),
            "monitoring_cycle_scan_limit": scan_limit_value,
            "opencanary_log_path": request.POST.get("opencanary_log_path", "").strip() or get_value("opencanary_log_path", ""),
            "enable_real_scan": "true" if request.POST.get("enable_real_scan") else "false",
            "enable_honeypot_logs": "true" if request.POST.get("enable_honeypot_logs") else "false",
        }
        if not getattr(settings, "LOCAL_SUBNET_ENV", None):
            values["local_subnet"] = request.POST.get("local_subnet", "").strip()
        for key, value in values.items():
            SystemSetting.objects.update_or_create(key=key, defaults={"value": value, "description": "GuardianNet calisma ayari"})
        messages.success(request, "Ayar kaydedildi.")
        return redirect("dashboard:settings")
    try:
        used_subnet = str(resolve_target_subnet())
    except Exception:
        used_subnet = "Algilanamadi"
    last_ingest = SystemSetting.objects.filter(key="last_honeypot_ingest").first()
    mode = get_value("guardiannet_mode", "real")
    last_scan_qs = NetworkScan.objects.all()
    if mode == "real":
        last_scan_qs = last_scan_qs.filter(is_mock=False)
    return render(request, "dashboard/settings.html", {
        "guardiannet_mode": mode,
        "local_subnet": get_value("local_subnet", ""), "local_subnet_locked": bool(getattr(settings, "LOCAL_SUBNET_ENV", None)), "used_subnet": used_subnet,
        "scan_interval_seconds": get_value("scan_interval_seconds", "300"),
        "monitoring_cycle_scan_limit": _monitoring_scan_limit_default(),
        "enable_real_scan": get_bool("enable_real_scan", True),
        "enable_honeypot_logs": get_bool("enable_honeypot_logs", True),
        "opencanary_log_path": get_value("opencanary_log_path", ""),
        "honeypot_status": get_honeypot_status(), "last_scan": last_scan_qs.first(),
        "last_ingest": last_ingest.value if last_ingest else "Henuz calismadi",
        "last_analysis": RiskSnapshot.objects.first(),
        "runtime_health_checks": get_runtime_health(),
        "clear_targets": CLEAR_TARGETS,
        "subnet_warning": "/" in used_subnet and used_subnet.rsplit("/", 1)[-1].isdigit() and int(used_subnet.rsplit("/", 1)[-1]) > 24,
    })


@login_required
@require_POST
def clear_security_data_view(request):
    target = request.POST.get("target", "")
    try:
        result = clear_security_data(target)
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("dashboard:settings")
    messages.success(request, f"{result['label']} temizlendi. Silinen kayıt: {result['total']}.")
    return redirect("dashboard:settings")


@login_required
def scan_network_view(request):
    if request.method == "POST":
        result = scan_network()
        if result["success"]:
            messages.success(request, f"Yerel cihaz kesfi tamamlandi. {result['found_devices']} cihaz bulundu.")
        else:
            messages.warning(request, "İşlem tamamlanamadı. Terminal çıktısını veya sistem ayarlarını kontrol edin.")
    return redirect("dashboard:index")
