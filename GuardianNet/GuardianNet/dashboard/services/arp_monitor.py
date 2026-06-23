from dashboard.models import Alert, Device, SecurityEvent


def detect_arp_anomalies(entries):
    """Detect conflicting IP/MAC observations supplied by an authorized source."""
    seen = {}
    anomalies = []
    for entry in entries:
        ip_address = entry.get("ip_address")
        mac_address = (entry.get("mac_address") or "").lower()
        if ip_address in seen and mac_address and seen[ip_address] != mac_address:
            anomalies.append({"ip_address": ip_address, "mac_addresses": [seen[ip_address], mac_address]})
        elif ip_address and mac_address:
            seen[ip_address] = mac_address
    return anomalies


def analyze_arp_observations(entries=None):
    entries = entries or list(Device.objects.exclude(mac_address__isnull=True).values("ip_address", "mac_address"))
    anomalies = detect_arp_anomalies(entries)
    for item in anomalies:
        source_ip = item["ip_address"]
        description = f"Ayni IP icin farkli MAC adresleri: {', '.join(item['mac_addresses'])}"
        SecurityEvent.objects.get_or_create(
            event_type="arp_anomaly", source_ip=source_ip, description=description,
            defaults={"title": "ARP eslesme anomalisi", "level": "danger", "risk_score": 80},
        )
        Alert.objects.get_or_create(
            alert_type="arp_spoof", source_ip=source_ip, status="active",
            defaults={"severity": "high", "title": "ARP anomalisi tespit edildi", "message": description},
        )
    return anomalies
