from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.shortcuts import redirect, render
from django.utils import timezone

from .models import Alert, Device, HoneypotEvent, NetworkScan, RiskSnapshot, SecurityEvent, SystemSetting
from .services.honeypot_manager import get_honeypot_status
from .services.network_scanner import scan_network
from .services.network_scanner import detect_local_subnet
from .services.risk_engine import calculate_risk
from .services.runtime_settings import get_bool, get_value


def _risk_context():
    _, alerts_qs, events_qs, _ = _data_sources()
    calculated = calculate_risk(alerts_qs.exclude(status="resolved"), events_qs)
    latest = RiskSnapshot.objects.first()
    if latest:
        return {"risk_score": latest.risk_score, "risk_level": latest.risk_level, "security_score": latest.security_score}
    return calculated


def _data_sources():
    devices_qs = Device.objects.all()
    alerts_qs = Alert.objects.all()
    events_qs = SecurityEvent.objects.all()
    honeypot_qs = HoneypotEvent.objects.all()
    if get_value("guardiannet_mode", "real") == "real":
        real_devices = devices_qs.exclude(ip_address__startswith="192.0.2.").exclude(ip_address__startswith="198.51.100.").exclude(ip_address__startswith="203.0.113.")
        real_alerts = alerts_qs.exclude(title__startswith="[demo-")
        real_events = events_qs.exclude(title__startswith="[demo-")
        real_honeypot = honeypot_qs.filter(is_mock=False)
        devices_qs = real_devices if real_devices.exists() else devices_qs
        alerts_qs = real_alerts if real_alerts.exists() else alerts_qs
        events_qs = real_events if real_events.exists() else events_qs
        honeypot_qs = real_honeypot if real_honeypot.exists() else honeypot_qs
    return devices_qs, alerts_qs, events_qs, honeypot_qs


@login_required
def index(request):
    mode = get_value("guardiannet_mode", "real")
    if not Device.objects.exists() or mode == "demo" and not Device.objects.filter(ip_address__startswith="192.0.2.").exists():
        scan_network(force_demo=True)
    devices_qs, alerts_qs, events_qs, _ = _data_sources()
    online = devices_qs.filter(status="online").count()
    offline = devices_qs.filter(status="offline").count()
    unknown = devices_qs.filter(status="unknown").count()
    context = {
        "total_devices": devices_qs.count(), "active_devices": online,
        "online_devices": online, "offline_devices": offline,
        "active_alerts": alerts_qs.exclude(status="resolved").count(),
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
    snapshots = list(RiskSnapshot.objects.order_by("recorded_at"))
    context = {
        "risky_devices": devices_qs.order_by("-risk_score")[:10],
        "daily_chart": {"labels": [row["day"].isoformat() for row in daily], "values": [row["total"] for row in daily]},
        "type_chart": {"labels": [row["event_type"] for row in by_type], "values": [row["total"] for row in by_type]},
        "risk_chart": {"labels": [item.recorded_at.strftime("%d.%m") for item in snapshots], "values": [item.risk_score for item in snapshots]},
    }
    return render(request, "dashboard/reports.html", context)


@login_required
def honeypot(request):
    return render(request, "dashboard/honeypot.html", {"honeypot_status": get_honeypot_status(), "events": _data_sources()[3]})


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
        detected_subnet = str(detect_local_subnet() or "Algilanamadi")
    except Exception:
        detected_subnet = "Algilanamadi"
    last_ingest = SystemSetting.objects.filter(key="last_honeypot_ingest").first()
    return render(request, "dashboard/settings.html", {
        "guardiannet_mode": get_value("guardiannet_mode", "real"),
        "local_subnet": get_value("local_subnet", ""), "detected_subnet": detected_subnet,
        "scan_interval_seconds": get_value("scan_interval_seconds", "300"),
        "enable_real_scan": get_bool("enable_real_scan", True),
        "enable_honeypot_logs": get_bool("enable_honeypot_logs", True),
        "opencanary_log_path": get_value("opencanary_log_path", ""),
        "honeypot_status": get_honeypot_status(), "last_scan": NetworkScan.objects.first(),
        "last_ingest": last_ingest.value if last_ingest else "Henuz calismadi",
    })


@login_required
def scan_network_view(request):
    if request.method == "POST":
        result = scan_network()
        if result["success"]:
            messages.success(request, f"Yerel cihaz kesfi tamamlandi. {result['found_devices']} cihaz bulundu.")
        else:
            messages.warning(request, f"Gercek kesif yapilamadi; fallback aktif. {result.get('error', '')}")
    return redirect("dashboard:index")
