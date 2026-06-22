from collections import defaultdict


def detect_port_scan(events, threshold=8):
    """Flag sources contacting many destination ports in existing telemetry."""
    ports_by_source = defaultdict(set)
    for event in events:
        if event.get("source_ip") and event.get("destination_port"):
            ports_by_source[event["source_ip"]].add(int(event["destination_port"]))
    return [
        {"source_ip": source, "unique_ports": len(ports), "detected": True}
        for source, ports in ports_by_source.items() if len(ports) >= threshold
    ]
