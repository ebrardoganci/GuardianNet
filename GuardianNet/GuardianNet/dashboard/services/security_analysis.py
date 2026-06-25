from dashboard.services.arp_monitor import analyze_arp_observations
from dashboard.services.asset_analyzer import analyze_new_devices, analyze_open_ports
from dashboard.services.bruteforce_detector import analyze_bruteforce_logs, analyze_ssh_attempt_logs
from dashboard.services.dos_detector import analyze_dos_logs
from dashboard.services.port_scan_detector import analyze_port_scan_logs
from dashboard.services.risk_engine import create_risk_snapshot


def run_security_analysis():
    new_devices = analyze_new_devices()
    open_ports = analyze_open_ports()
    arp = analyze_arp_observations()
    ports = analyze_port_scan_logs()
    ssh_attempts = analyze_ssh_attempt_logs()
    brute = analyze_bruteforce_logs()
    dos = analyze_dos_logs()
    snapshot = create_risk_snapshot()
    return {
        "arp": len(arp),
        "open_ports": len(open_ports),
        "new_devices": len(new_devices),
        "port": len(ports),
        "ssh": len(ssh_attempts) + len(brute),
        "ssh_attempts": len(ssh_attempts),
        "ssh_bruteforce": len(brute),
        "dos": len(dos),
        "risk": snapshot.risk_score,
        "snapshot_id": snapshot.pk,
    }
