from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.shortcuts import redirect, render
from django.utils import timezone

from .models import Alert, Device, HoneypotEvent, NetworkScan, RiskSnapshot, SecurityEvent, SystemSetting
from .services.honeypot_manager import get_honeypot_status
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
from .services.runtime_settings import get_bool, get_value


def _risk_context():
    _, alerts_qs, events_qs, _ = _data_sources()
    calculated = calculate_risk(alerts_qs.exclude(status="resolved"), events_qs)
    if is_real_mode():
        return calculated
    latest = RiskSnapshot.objects.first()
    if latest:
        return {"risk_score": latest.risk_score, "risk_level": latest.risk_level, "security_score": latest.security_score}
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


@login_required
def index(request):
    mode = get_value("guardiannet_mode", "real")
    if mode == "demo" and not Device.objects.exists():
        scan_network(force_demo=True)
    devices_qs, alerts_qs, events_qs, _ = _data_sources()
    online = devices_qs.filter(status="online").count()
    offline = devices_qs.filter(status="offline").count()
    unknown = devices_qs.filter(status="unknown").count()
    active_alerts_count = (
        real_alerts(Alert.objects.filter(status="active")).count()
        if is_real_mode()
        else Alert.objects.filter(status="active").count()
    )
    context = {
        "total_devices": devices_qs.count(), "active_devices": online,
        "online_devices": online, "offline_devices": offline,
        "active_alerts": active_alerts_count,
        "recent_events": events_qs[:6], "recent_alerts": alerts_qs[:6],
        "honeypot_status": get_honeypot_status(),
        "operation_mode": mode,
        "device_chart": {"labels": ["Online", "Offline", "Bilinmiyor"], "values": [online, offline, unknown]},
        "severity_chart": {"labels": ["Dusuk", "Orta", "Yuksek", "Kritik"], "values": [alerts_qs.filter(severity=value).count() for value in ["low", "medium", "high", "critical"]]},
        **_risk_context(),
    }
    return render(request, "dashboard/index.html", context)


@login_required
def devices(request):
    return render(request, "dashboard/devices.html", {"devices": _data_sources()[0]})


@login_required
def alerts(request):
    return render(request, "dashboard/alerts.html", {"alerts": _data_sources()[1]})


@login_required
def security_events(request):
    return render(request, "dashboard/security_events.html", {"events": _data_sources()[2]})


@login_required
def reports(request):
    devices_qs, _, events_qs, _ = _data_sources()
    since = timezone.now() - timedelta(days=7)
    daily = list(events_qs.filter(created_at__gte=since).annotate(day=TruncDate("created_at")).values("day").annotate(total=Count("id")).order_by("day"))
    by_type = list(events_qs.values("event_type").annotate(total=Count("id")).order_by("event_type"))
    snapshot_qs = RiskSnapshot.objects.order_by("recorded_at")
    if is_real_mode():
        snapshot_qs = real_risk_snapshots(snapshot_qs)
    snapshots = list(snapshot_qs)
    context = {
        "risky_devices": devices_qs.order_by("-risk_score")[:10],
        "daily_chart": {"labels": [row["day"].isoformat() for row in daily], "values": [row["total"] for row in daily]},
        "type_chart": {"labels": [row["event_type"] for row in by_type], "values": [row["total"] for row in by_type]},
        "risk_chart": {"labels": [item.recorded_at.strftime("%d.%m") for item in snapshots], "values": [item.risk_score for item in snapshots]},
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
        values = {
            "guardiannet_mode": request.POST.get("guardiannet_mode", "real"),
            "local_subnet": request.POST.get("local_subnet", "").strip(),
            "scan_interval_seconds": request.POST.get("scan_interval_seconds", "300"),
            "opencanary_log_path": request.POST.get("opencanary_log_path", "").strip() or get_value("opencanary_log_path", ""),
            "enable_real_scan": "true" if request.POST.get("enable_real_scan") else "false",
            "enable_honeypot_logs": "true" if request.POST.get("enable_honeypot_logs") else "false",
        }
        if values["guardiannet_mode"] not in {"real", "demo"}:
            values["guardiannet_mode"] = "real"
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
        "local_subnet": settings.LOCAL_SUBNET or get_value("local_subnet", ""), "used_subnet": used_subnet,
        "scan_interval_seconds": get_value("scan_interval_seconds", "300"),
        "enable_real_scan": get_bool("enable_real_scan", True),
        "enable_honeypot_logs": get_bool("enable_honeypot_logs", True),
        "opencanary_log_path": get_value("opencanary_log_path", ""),
        "honeypot_status": get_honeypot_status(), "last_scan": last_scan_qs.first(),
        "last_ingest": last_ingest.value if last_ingest else "Henuz calismadi",
    })


@login_required
def scan_network_view(request):
    if request.method == "POST":
        result = scan_network()
        if result["success"]:
            messages.success(request, f"Yerel cihaz kesfi tamamlandi. {result['found_devices']} cihaz bulundu.")
        else:
            messages.warning(request, f"Gercek kesif yapilamadi; demo fallback uretilmedi. {result.get('error', '')}")
    return redirect("dashboard:index")
