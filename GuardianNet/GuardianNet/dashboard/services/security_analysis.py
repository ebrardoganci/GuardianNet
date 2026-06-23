from dashboard.services.arp_monitor import analyze_arp_observations
from dashboard.services.bruteforce_detector import analyze_bruteforce_logs
from dashboard.services.port_scan_detector import analyze_port_scan_logs
from dashboard.services.risk_engine import create_risk_snapshot


def run_security_analysis():
    arp = analyze_arp_observations()
    ports = analyze_port_scan_logs()
    brute = analyze_bruteforce_logs()
    snapshot = create_risk_snapshot()
    return {
        "arp": len(arp),
        "port": len(ports),
        "ssh": len(brute),
        "risk": snapshot.risk_score,
        "snapshot_id": snapshot.pk,
    }
