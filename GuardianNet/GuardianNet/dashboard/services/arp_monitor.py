def detect_arp_anomalies(entries):
    """Detect conflicting IP/MAC observations supplied by an authorized log source."""
    seen = {}
    anomalies = []
    for entry in entries:
        ip_address = entry.get("ip_address")
        mac_address = entry.get("mac_address")
        if ip_address in seen and seen[ip_address] != mac_address:
            anomalies.append({"ip_address": ip_address, "mac_addresses": [seen[ip_address], mac_address]})
        elif ip_address and mac_address:
            seen[ip_address] = mac_address
    return anomalies
