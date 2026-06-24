from dashboard.models import Alert, Device, SecurityEvent
from dashboard.services.data_scope import is_real_mode, real_devices


def detect_arp_anomalies(entries):
    """Detect conflicting IP/MAC observations supplied by an authorized source."""
    seen = {}
    ips_by_mac = {}
    anomalies = []
    for entry in entries:
        ip_address = entry.get("ip_address")
        mac_address = (entry.get("mac_address") or "").lower()
        if ip_address in seen and mac_address and seen[ip_address] != mac_address:
            anomalies.append({"type": "ip_mac_conflict", "ip_address": ip_address, "mac_addresses": [seen[ip_address], mac_address]})
        elif ip_address and mac_address:
            seen[ip_address] = mac_address
        if ip_address and mac_address:
            ips_by_mac.setdefault(mac_address, set()).add(ip_address)
    for mac_address, ip_addresses in ips_by_mac.items():
        if len(ip_addresses) > 1:
            anomalies.append({"type": "mac_multi_ip", "mac_address": mac_address, "ip_addresses": sorted(ip_addresses)})
    return anomalies


def analyze_arp_observations(entries=None):
    if entries is None:
        device_qs = Device.objects.exclude(mac_address__isnull=True)
        if is_real_mode():
            device_qs = real_devices(device_qs)
        entries = list(device_qs.values("ip_address", "mac_address"))
    anomalies = detect_arp_anomalies(entries)
    for item in anomalies:
        if item.get("type") == "mac_multi_ip":
            source_ip = item["ip_addresses"][0]
            description = f"Ayni MAC adresi birden fazla IP ile goruldu: {item['mac_address']} -> {', '.join(item['ip_addresses'])}"
        else:
            source_ip = item["ip_address"]
            description = f"Ayni IP icin farkli MAC adresleri: {', '.join(item['mac_addresses'])}"
        SecurityEvent.objects.get_or_create(
            event_type="arp_anomaly", source_ip=source_ip, description=description,
            defaults={"title": "Olasi ARP spoofing suphesi", "level": "danger", "risk_score": 80},
        )
        Alert.objects.get_or_create(
            alert_type="arp_spoof", source_ip=source_ip, status="active",
            defaults={"severity": "high", "title": "Olasi ARP spoofing suphesi", "message": description},
        )
    return anomalies
