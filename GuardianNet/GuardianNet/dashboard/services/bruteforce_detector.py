from collections import Counter


def detect_bruteforce(login_events, threshold=5):
    """Analyze failed-login records; this function never attempts authentication."""
    failures = Counter(
        event.get("source_ip") for event in login_events
        if not event.get("success", False) and event.get("source_ip")
    )
    return [
        {"source_ip": source, "failed_attempts": count, "detected": True}
        for source, count in failures.items() if count >= threshold
    ]
