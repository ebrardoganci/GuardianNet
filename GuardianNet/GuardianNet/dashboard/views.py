from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from .models import Device, Alert, SecurityEvent


@login_required
def index(request):
    connected_devices = Device.objects.filter(status="online").count()
    active_alerts = Alert.objects.filter(is_resolved=False).count()

    high_alerts = Alert.objects.filter(
        is_resolved=False,
        severity__in=["high", "critical"]
    ).count()

    if high_alerts > 0:
        risk_level = "Yüksek"
    elif active_alerts > 0:
        risk_level = "Orta"
    else:
        risk_level = "Düşük"

    dashboard_data = {
        "connected_devices": connected_devices,
        "active_alerts": active_alerts,
        "risk_level": risk_level,
        "network_status": "Aktif İzleme",
    }

    recent_events = SecurityEvent.objects.order_by("-created_at")[:5]
    recent_alerts = Alert.objects.order_by("-created_at")[:5]
    recent_devices = Device.objects.order_by("-last_seen")[:5]

    context = {
        "dashboard_data": dashboard_data,
        "recent_events": recent_events,
        "recent_alerts": recent_alerts,
        "recent_devices": recent_devices,
    }

    return render(request, "dashboard/index.html", context)