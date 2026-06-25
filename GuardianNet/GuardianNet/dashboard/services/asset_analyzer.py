from django.db.models import Q

from dashboard.models import Alert, Device, OpenPort, SecurityEvent
from dashboard.security_explanations import alert_type_for_open_port, get_port_explanation
from dashboard.services.data_scope import is_real_mode, real_devices, real_open_ports


def _new_device_message(device):
    if device.status == "partial":
        return (
            "Ağda daha önce görülmeyen veya kimlik bilgisi eksik bir cihaz tespit edildi. "
            "Cihaz ping'e cevap vermediği, güvenlik duvarı kullandığı veya aynı ağ katmanında olmadığı için "
            "MAC/vendor bilgisi alınamamış olabilir."
        )
    return (
        "Ağda daha önce görülmeyen yeni bir cihaz tespit edildi. Bu cihaz size ait olabilir; "
        "ancak tanınmayan cihazlar ağ güvenliği açısından kontrol edilmelidir."
    )


def analyze_new_devices():
    device_qs = Device.objects.filter(is_trusted=False)
    if is_real_mode():
        device_qs = real_devices(device_qs)
    findings = []
    for device in device_qs:
        existing = Alert.objects.filter(
            Q(source_ip=device.ip_address) | Q(device=device),
            alert_type="new_device",
            status="active",
        ).exists()
        if existing:
            continue
        alert = Alert.objects.create(
            device=device,
            alert_type="new_device",
            severity="medium",
            status="active",
            title=(
                f"Yeni cihaz kısmen algılandı: {device.ip_address}"
                if device.status == "partial"
                else f"Yeni cihaz tespit edildi: {device.ip_address}"
            ),
            message=_new_device_message(device),
            source_ip=device.ip_address,
            source_mac=device.mac_address or "",
        )
        findings.append({"device_id": device.pk, "alert_id": alert.pk, "ip_address": device.ip_address})
    return findings


def _open_port_risk_score(risk_key):
    return {"low": 15, "medium": 40, "high": 70}.get(risk_key, 40)


def analyze_open_ports():
    port_qs = OpenPort.objects.select_related("device")
    if is_real_mode():
        port_qs = real_open_ports(port_qs)
    findings = []
    for open_port in port_qs:
        device = open_port.device
        explanation = get_port_explanation(open_port.port, open_port.service_name)
        service = explanation["service"]
        risk_key = explanation["risk_key"]
        level = "danger" if risk_key == "high" else "warning" if risk_key == "medium" else "info"
        description = (
            f"{device.ip_address}:{open_port.port} açık görünüyor. {explanation['description']} "
            f"Öneri: {explanation['action']} Kaynak: {open_port.source or 'Gerçek ağ taraması'}."
        )
        security_event, _ = SecurityEvent.objects.get_or_create(
            event_type="open_port",
            destination_ip=device.ip_address,
            destination_port=open_port.port,
            protocol=service,
            defaults={
                "source_ip": device.ip_address,
                "source_mac": device.mac_address or "",
                "title": f"Açık port tespit edildi: {device.ip_address}:{open_port.port}",
                "description": description,
                "level": level,
                "risk_score": _open_port_risk_score(risk_key),
            },
        )
        alert = None
        if risk_key != "low":
            alert_type = alert_type_for_open_port(open_port.port)
            title = f"{service} portu açık: {device.ip_address}:{open_port.port}"
            alert, _ = Alert.objects.get_or_create(
                alert_type=alert_type,
                source_ip=device.ip_address,
                status="active",
                title=title,
                defaults={
                    "device": device,
                    "severity": "high" if risk_key == "high" else "medium",
                    "message": description,
                    "source_mac": device.mac_address or "",
                },
            )
        findings.append({
            "open_port_id": open_port.pk,
            "security_event_id": security_event.pk,
            "alert_id": alert.pk if alert else None,
            "port": open_port.port,
        })
    return findings
