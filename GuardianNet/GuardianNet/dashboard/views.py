from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.shortcuts import redirect, render
from django.utils import timezone

from .models import Alert, Device, HoneypotEvent, RiskSnapshot, SecurityEvent, SystemSetting
from .services.honeypot_manager import get_honeypot_status
from .services.network_scanner import scan_network
from .services.risk_engine import calculate_risk


def _risk_context():
    calculated = calculate_risk(Alert.objects.exclude(status="resolved"), SecurityEvent.objects.all())
    latest = RiskSnapshot.objects.first()
    if latest:
        return {"risk_score": latest.risk_score, "risk_level": latest.risk_level, "security_score": latest.security_score}
    return calculated


@login_required
def index(request):
    online = Device.objects.filter(status="online").count()
    offline = Device.objects.filter(status="offline").count()
    unknown = Device.objects.filter(status="unknown").count()
    context = {
        "total_devices": Device.objects.count(), "active_devices": online,
        "online_devices": online, "offline_devices": offline,
        "active_alerts": Alert.objects.exclude(status="resolved").count(),
        "recent_events": SecurityEvent.objects.all()[:6], "recent_alerts": Alert.objects.all()[:6],
        "honeypot_status": get_honeypot_status(),
        "device_chart": {"labels": ["Online", "Offline", "Bilinmiyor"], "values": [online, offline, unknown]},
        "severity_chart": {"labels": ["Dusuk", "Orta", "Yuksek", "Kritik"], "values": [Alert.objects.filter(severity=value).count() for value in ["low", "medium", "high", "critical"]]},
        **_risk_context(),
    }
    return render(request, "dashboard/index.html", context)


@login_required
def devices(request):
    return render(request, "dashboard/devices.html", {"devices": Device.objects.all()})


@login_required
def alerts(request):
    return render(request, "dashboard/alerts.html", {"alerts": Alert.objects.all()})


@login_required
def security_events(request):
    return render(request, "dashboard/security_events.html", {"events": SecurityEvent.objects.all()})


@login_required
def reports(request):
    since = timezone.now() - timedelta(days=7)
    daily = list(SecurityEvent.objects.filter(created_at__gte=since).annotate(day=TruncDate("created_at")).values("day").annotate(total=Count("id")).order_by("day"))
    by_type = list(SecurityEvent.objects.values("event_type").annotate(total=Count("id")).order_by("event_type"))
    snapshots = list(RiskSnapshot.objects.order_by("recorded_at"))
    context = {
        "risky_devices": Device.objects.order_by("-risk_score")[:10],
        "daily_chart": {"labels": [row["day"].isoformat() for row in daily], "values": [row["total"] for row in daily]},
        "type_chart": {"labels": [row["event_type"] for row in by_type], "values": [row["total"] for row in by_type]},
        "risk_chart": {"labels": [item.recorded_at.strftime("%d.%m") for item in snapshots], "values": [item.risk_score for item in snapshots]},
    }
    return render(request, "dashboard/reports.html", context)


@login_required
def honeypot(request):
    return render(request, "dashboard/honeypot.html", {"honeypot_status": get_honeypot_status(), "events": HoneypotEvent.objects.all()})


@login_required
def settings_view(request):
    if request.method == "POST":
        value = request.POST.get("data_mode", "demo")
        if value not in {"demo", "opencanary"}:
            value = "demo"
        SystemSetting.objects.update_or_create(key="data_mode", defaults={"value": value, "description": "MVP veri modu"})
        messages.success(request, "Ayar kaydedildi.")
        return redirect("dashboard:settings")
    setting, _ = SystemSetting.objects.get_or_create(key="data_mode", defaults={"value": "demo", "description": "MVP veri modu"})
    return render(request, "dashboard/settings.html", {"data_mode": setting.value, "honeypot_status": get_honeypot_status()})


@login_required
def scan_network_view(request):
    if request.method == "POST":
        result = scan_network()
        messages.success(request, f"Guvenli demo taramasi tamamlandi. {result['found_devices']} cihaz kaydi hazirlandi.")
    return redirect("dashboard:index")
