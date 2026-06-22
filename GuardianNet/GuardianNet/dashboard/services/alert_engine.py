from dashboard.models import Alert


def create_detection_alert(*, alert_type, title, message, severity="medium", source_ip=None, source_mac="", device=None):
    """Store a defensive detection result as an alert."""
    return Alert.objects.create(
        alert_type=alert_type, title=title, message=message, severity=severity,
        source_ip=source_ip, source_mac=source_mac, device=device, status="active",
    )
