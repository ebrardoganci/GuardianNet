from django.utils import timezone

from dashboard.models import Device, NetworkScan


DEMO_DEVICES = [
    {"ip_address": "192.0.2.10", "mac_address": "02:00:00:00:00:10", "hostname": "demo-router", "vendor": "Demo Networks", "status": "online", "is_trusted": True, "risk_score": 10},
    {"ip_address": "192.0.2.21", "mac_address": "02:00:00:00:00:21", "hostname": "lab-workstation", "vendor": "Example Labs", "status": "online", "is_trusted": True, "risk_score": 28},
    {"ip_address": "192.0.2.45", "mac_address": "02:00:00:00:00:45", "hostname": "unknown-client", "vendor": "Bilinmiyor", "status": "offline", "is_trusted": False, "risk_score": 72},
]


def scan_network():
    """Return deterministic documentation-range demo data without probing a network."""
    for data in DEMO_DEVICES:
        Device.objects.update_or_create(ip_address=data["ip_address"], defaults=data)

    scan = NetworkScan.objects.create(
        network_range="192.0.2.0/24 (demo)",
        status="demo",
        devices_found=len(DEMO_DEVICES),
        is_mock=True,
        message="Aktif ag taramasi yapilmadi; guvenli demo verisi kullanildi.",
        completed_at=timezone.now(),
    )
    return {"success": True, "is_mock": True, "found_devices": len(DEMO_DEVICES), "scan_id": scan.pk}
