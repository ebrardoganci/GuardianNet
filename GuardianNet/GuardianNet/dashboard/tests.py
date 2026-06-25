import json
from datetime import datetime
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import Alert, ArpObservation, Device, HoneypotEvent, MonitoringCycleRun, NetworkScan, OpenPort, RiskSnapshot, SecurityEvent
from .security_explanations import get_port_explanation
from .services.arp_monitor import analyze_arp_observations, detect_arp_anomalies
from .services.bruteforce_detector import analyze_bruteforce_logs, analyze_ssh_attempt_logs, detect_bruteforce
from .services.dos_detector import analyze_dos_logs, detect_dos_patterns
from .services.honeypot_manager import ingest_honeypot_logs
from .services.honeypot_listener import record_honeypot_connection
from .services.network_scanner import resolve_target_subnet, scan_network
from .services.port_scan_detector import analyze_port_scan_logs, detect_port_scan
from .services.risk_engine import calculate_risk
from .services.runtime_health import get_runtime_health
from .services.security_analysis import run_security_analysis


class DashboardMVPTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(username="demo", password="test-pass-123")

    def test_pages_require_login_and_render_for_user(self):
        names = ["dashboard:index", "dashboard:devices", "dashboard:alerts", "dashboard:events", "dashboard:reports", "dashboard:honeypot", "dashboard:settings"]
        for name in names:
            self.assertIn("/login/", self.client.get(reverse(name)).url)
        self.client.force_login(self.user)
        for name in names:
            self.assertEqual(self.client.get(reverse(name)).status_code, 200)

    def test_demo_commands_do_not_create_security_data(self):
        output = StringIO()
        call_command("seed_demo_data", stdout=output)
        call_command("simulate_security_events", stdout=output)
        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(Alert.objects.count(), 0)
        self.assertEqual(SecurityEvent.objects.count(), 0)
        self.assertEqual(HoneypotEvent.objects.count(), 0)
        self.assertEqual(RiskSnapshot.objects.count(), 0)
        self.assertIn("devre dışı", output.getvalue())

    def test_detection_services_only_analyze_supplied_data(self):
        self.assertEqual(len(detect_arp_anomalies([{"ip_address": "192.168.1.1", "mac_address": "aa"}, {"ip_address": "192.168.1.1", "mac_address": "bb"}])), 1)
        self.assertEqual(len(detect_arp_anomalies([{"ip_address": "192.168.1.10", "mac_address": "aa"}, {"ip_address": "192.168.1.11", "mac_address": "aa"}])), 1)
        self.assertEqual(len(detect_port_scan([{"source_ip": "192.168.1.2", "destination_port": port} for port in range(1, 9)])), 1)
        self.assertEqual(len(detect_bruteforce([{"source_ip": "192.168.1.3", "success": False}] * 5)), 1)
        self.assertEqual(len(detect_dos_patterns([{"source_ip": "192.168.1.4", "destination_ip": "192.168.1.10", "destination_port": 443}] * 20)), 1)

    @override_settings(LOCAL_SUBNET="8.8.8.0/24")
    def test_public_subnet_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_target_subnet()

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24", ENABLE_REAL_SCAN=True)
    @patch("dashboard.services.network_scanner._scan_system_arp_table")
    @patch("dashboard.services.network_scanner._scan_with_scapy")
    @patch("dashboard.services.network_scanner._scan_with_nmap_ports")
    @patch("dashboard.services.network_scanner._scan_with_nmap")
    def test_real_scan_updates_devices_without_port_scan(self, nmap_scan, port_scan, scapy_scan, arp_scan):
        nmap_scan.return_value = ([{"ip_address": "192.168.50.10", "mac_address": "00:11:22:33:44:55", "hostname": None, "vendor": "Test"}], "nmap-ping")
        port_scan.return_value = ([], "nmap-port")
        scapy_scan.return_value = ([], "scapy-arp")
        arp_scan.return_value = ([], "system-arp")
        result = scan_network()
        self.assertTrue(result["success"])
        self.assertTrue(Device.objects.filter(ip_address="192.168.50.10", status="online").exists())

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_device_inventory_uses_real_scope_and_shows_offline(self):
        self.client.force_login(self.user)
        Device.objects.create(ip_address="192.168.50.10", mac_address="00:11:22:33:44:55", status="offline")
        Device.objects.create(ip_address="192.168.60.10", mac_address="00:11:22:33:44:66", status="online")
        response = self.client.get(reverse("dashboard:devices"))
        self.assertContains(response, "192.168.50.10")
        self.assertContains(response, "Offline")
        self.assertContains(response, "Yeni/bilinmeyen cihaz")
        self.assertNotContains(response, "192.168.60.10")

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24", ENABLE_REAL_SCAN=True)
    @patch("dashboard.services.network_scanner._scan_system_arp_table")
    @patch("dashboard.services.network_scanner._scan_with_scapy")
    @patch("dashboard.services.network_scanner._scan_with_nmap_ports")
    @patch("dashboard.services.network_scanner._scan_with_nmap")
    def test_real_scan_does_not_duplicate_new_device_alerts(self, nmap_scan, port_scan, scapy_scan, arp_scan):
        nmap_scan.return_value = ([{"ip_address": "192.168.50.20", "mac_address": "00:11:22:33:44:77", "hostname": None, "vendor": "Test"}], "nmap-ping")
        port_scan.return_value = ([], "nmap-port")
        scapy_scan.return_value = ([], "scapy-arp")
        arp_scan.return_value = ([], "system-arp")
        self.assertTrue(scan_network()["success"])
        self.assertTrue(scan_network()["success"])
        run_security_analysis()
        run_security_analysis()
        self.assertEqual(Alert.objects.filter(alert_type="new_device", source_ip="192.168.50.20", status="active").count(), 1)

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24", ENABLE_REAL_SCAN=True)
    @patch("dashboard.services.network_scanner._scan_system_arp_table")
    @patch("dashboard.services.network_scanner._scan_with_scapy")
    @patch("dashboard.services.network_scanner._scan_with_nmap_ports")
    @patch("dashboard.services.network_scanner._scan_with_nmap")
    def test_partial_detected_device_is_saved_and_alerted(self, nmap_scan, port_scan, scapy_scan, arp_scan):
        nmap_scan.return_value = ([{"ip_address": "192.168.50.60", "mac_address": None, "hostname": None, "vendor": "Bilinmiyor"}], "nmap-ping")
        port_scan.return_value = ([], "nmap-port")
        scapy_scan.return_value = ([], "scapy-arp")
        arp_scan.return_value = ([], "system-arp")

        result = scan_network()

        self.assertTrue(result["success"])
        device = Device.objects.get(ip_address="192.168.50.60")
        self.assertEqual(device.status, "partial")
        run_security_analysis()
        alert = Alert.objects.get(alert_type="new_device", source_ip="192.168.50.60")
        self.assertIn("MAC/vendor", alert.message)

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24", ENABLE_REAL_SCAN=True)
    @patch("dashboard.services.network_scanner._scan_system_arp_table")
    @patch("dashboard.services.network_scanner._scan_with_scapy")
    @patch("dashboard.services.network_scanner._scan_with_nmap_ports")
    @patch("dashboard.services.network_scanner._scan_with_nmap")
    def test_port_scan_records_explained_open_ports(self, nmap_scan, port_scan, scapy_scan, arp_scan):
        nmap_scan.return_value = ([], "nmap-ping")
        port_scan.return_value = ([
            {
                "ip_address": "192.168.50.61",
                "mac_address": None,
                "hostname": None,
                "vendor": "Bilinmiyor",
                "open_ports": [
                    {"port": 22, "protocol": "tcp", "service": "ssh"},
                    {"port": 5432, "protocol": "tcp", "service": "postgresql"},
                ],
            }
        ], "nmap-port")
        scapy_scan.return_value = ([], "scapy-arp")
        arp_scan.return_value = ([], "system-arp")

        result = scan_network()

        self.assertTrue(result["success"])
        device = Device.objects.get(ip_address="192.168.50.61")
        self.assertEqual(OpenPort.objects.filter(device=device).count(), 2)
        self.assertEqual(Alert.objects.filter(source_ip=device.ip_address).count(), 0)
        run_security_analysis()
        self.assertEqual(SecurityEvent.objects.filter(event_type="open_port", destination_ip=device.ip_address).count(), 2)
        self.assertTrue(Alert.objects.filter(alert_type="ssh_port_open", source_ip=device.ip_address).exists())
        self.assertTrue(Alert.objects.filter(alert_type="database_port_open", source_ip=device.ip_address).exists())
        self.client.force_login(self.user)
        response = self.client.get(reverse("dashboard:device_detail", args=[device.pk]))
        self.assertContains(response, "Açık Portlar")
        self.assertContains(response, "PostgreSQL")

    def test_port_explanation_dictionary_returns_expected_fields(self):
        ssh = get_port_explanation(22)
        unknown = get_port_explanation(9999, "custom")

        self.assertEqual(ssh["service"], "SSH")
        self.assertEqual(ssh["risk_key"], "medium")
        self.assertIn("uzaktan", ssh["description"])
        self.assertEqual(unknown["service"], "CUSTOM")
        self.assertIn("gerekmiyorsa", unknown["action"])

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24", ENABLE_REAL_SCAN=True)
    @patch("dashboard.services.network_scanner._scan_system_arp_table")
    @patch("dashboard.services.network_scanner._scan_with_scapy")
    @patch("dashboard.services.network_scanner._scan_with_socket_ports")
    @patch("dashboard.services.network_scanner._scan_with_nmap_ports")
    @patch("dashboard.services.network_scanner._scan_with_nmap")
    def test_socket_fallback_records_open_ports_when_nmap_port_scan_missing(self, nmap_scan, nmap_port_scan, socket_scan, scapy_scan, arp_scan):
        nmap_scan.return_value = ([], "nmap-ping")
        nmap_port_scan.side_effect = RuntimeError("Nmap bulunamadi.")
        socket_scan.return_value = ([
            {
                "ip_address": "192.168.50.62",
                "mac_address": None,
                "hostname": None,
                "vendor": "Bilinmiyor",
                "open_ports": [{"port": 5432, "protocol": "tcp", "service": "", "source": "socket-fallback"}],
            }
        ], "socket-fallback")
        scapy_scan.return_value = ([], "scapy-arp")
        arp_scan.return_value = ([], "system-arp")

        result = scan_network()

        self.assertTrue(result["success"])
        device = Device.objects.get(ip_address="192.168.50.62")
        self.assertTrue(OpenPort.objects.filter(device=device, port=5432, source="socket-fallback").exists())
        run_security_analysis()
        self.assertTrue(Alert.objects.filter(alert_type="database_port_open", source_ip=device.ip_address).exists())

    @override_settings(ENABLE_HONEYPOT_LOGS=True)
    def test_honeypot_ingest_is_idempotent(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "opencanary.log"
            source_ip = "10.10.10.50"
            startup = {
                "dst_host": "",
                "dst_port": -1,
                "local_time": "2026-01-01 09:59:59.000000",
                "logdata": {"msg": {"logdata": "Canary running!!!"}},
                "logtype": 1001,
                "src_host": "",
                "src_port": -1,
                "utc_time": "2026-01-01 09:59:59.000000",
            }
            payload = {
                "src_host": source_ip,
                "src_port": 53210,
                "dst_port": 2222,
                "local_time": "2026-01-01 10:00:00.000000",
                "utc_time": "2026-01-01 10:00:00.000000",
                "logtype": 4002,
                "logdata": {"USERNAME": "test", "PASSWORD": "sensitive-test-value"},
            }
            path.write_text(
                "\n".join(["OpenCanary starting", json.dumps(startup), json.dumps(payload), "{not-json}"]) + "\n",
                encoding="utf-8",
            )
            first = ingest_honeypot_logs(path)
            second = ingest_honeypot_logs(path)
            self.assertEqual(first["read"], 4)
            self.assertEqual(first["created"], 1)
            self.assertEqual(first["ignored"], 2)
            self.assertEqual(first["invalid"], 1)
            self.assertEqual(second["created"], 0)
            self.assertEqual(second["skipped"], 1)
            self.assertEqual(second["ignored"], 2)
            event = HoneypotEvent.objects.get(is_mock=False)
            self.assertEqual(event.source_ip, source_ip)
            self.assertEqual(event.source_port, 53210)
            self.assertEqual(event.service, "ssh")
            self.assertEqual(event.destination_port, 2222)
            self.assertEqual(event.source_type, "OpenCanary logu")
            self.assertEqual(event.event_type, "auth_failure")
            self.assertEqual(event.username, "test")
            self.assertIn("PASSWORD", event.raw_data["logdata"])
            self.assertNotIn("sensitive-test-value", event.command)
            self.assertEqual(HoneypotEvent.objects.filter(is_mock=False).count(), 1)

    @override_settings(ENABLE_HONEYPOT_LOGS=True)
    def test_honeypot_ingest_ignores_non_event_lines_without_fake_events(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "opencanary.log"
            startup = {
                "dst_port": -1,
                "logdata": {"msg": {"logdata": "Added service from class CanarySSH"}},
                "logtype": 1001,
                "src_host": "",
            }
            path.write_text("plain startup line\n" + json.dumps(startup) + "\n[]\n", encoding="utf-8")
            result = ingest_honeypot_logs(path)
            self.assertEqual(result["read"], 3)
            self.assertEqual(result["created"], 0)
            self.assertEqual(result["ignored"], 3)
            self.assertEqual(result["invalid"], 0)
            self.assertEqual(HoneypotEvent.objects.count(), 0)

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_honeypot_listener_records_connection_and_analysis_creates_alerts(self):
        for port in (2222, 8080, 2121):
            record_honeypot_connection(
                source_ip="192.168.50.90",
                source_port=50000 + port,
                destination_port=port,
                payload="test connection",
            )

        result = run_security_analysis()

        self.assertEqual(HoneypotEvent.objects.filter(source_type="Honeypot listener").count(), 3)
        self.assertGreaterEqual(result["port"], 1)
        self.assertTrue(Alert.objects.filter(alert_type="honeypot", source_ip="192.168.50.90").exists())
        self.assertTrue(Alert.objects.filter(alert_type="port_scan", source_ip="192.168.50.90").exists())
        self.client.force_login(self.user)
        response = self.client.get(reverse("dashboard:honeypot"))
        self.assertContains(response, "Honeypot listener")
        self.assertContains(response, "52222")

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_monitoring_cycle_runs_with_skip_options(self):
        output = StringIO()
        call_command("run_monitoring_cycle", "--skip-scan", "--skip-honeypot", stdout=output)
        text = output.getvalue()
        self.assertIn("Scan: atlandi", text)
        self.assertIn("Honeypot: atlandi", text)
        self.assertIn("analysis: new_devices=0, open_ports=0, ARP=", text)
        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(HoneypotEvent.objects.count(), 0)
        self.assertEqual(RiskSnapshot.objects.count(), 1)
        self.assertEqual(MonitoringCycleRun.objects.count(), 1)
        run = MonitoringCycleRun.objects.first()
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.scan_status, "skipped")
        self.assertEqual(run.honeypot_status, "skipped")
        self.assertEqual(run.analysis_status, "completed")

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_dashboard_get_does_not_trigger_monitoring_cycle(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("dashboard:run_monitoring_cycle"))
        self.assertEqual(response.status_code, 405)
        self.assertEqual(MonitoringCycleRun.objects.count(), 0)
        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(HoneypotEvent.objects.count(), 0)

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_dashboard_renders_latest_monitoring_cycle_without_raw_template_tags(self):
        self.client.force_login(self.user)
        started_at = timezone.make_aware(datetime(2026, 6, 24, 1, 27))
        completed_at = timezone.make_aware(datetime(2026, 6, 24, 1, 28))
        run = MonitoringCycleRun.objects.create(
            completed_at=completed_at,
            status="completed",
            scan_status="completed",
            scan_found_devices=1,
            scan_new_devices=0,
            honeypot_status="completed",
            honeypot_read_lines=9,
            honeypot_created_events=0,
            honeypot_duplicates=1,
            honeypot_parse_errors=0,
            analysis_status="completed",
            risk_score=11,
            raw_summary={"honeypot": {"ignored": 8}},
        )
        MonitoringCycleRun.objects.filter(pk=run.pk).update(started_at=started_at)
        HoneypotEvent.objects.create(
            source_ip="192.168.50.40",
            service="ssh",
            username="adminuser",
            command="login attempt",
            destination_port=2222,
            raw_data={"logtype": 4002},
            is_mock=False,
        )

        response = self.client.get(reverse("dashboard:index"))

        self.assertContains(response, "Cycle 24.06 01:27")
        self.assertContains(response, "Scan bulunan/yeni")
        self.assertContains(response, "Honeypot okunan/eklenen")
        self.assertContains(response, "1 duplicate")
        self.assertContains(response, "8 ignored")
        self.assertContains(response, "Son cycle analiz skoru")
        self.assertContains(response, "Son Honeypot Olayları")
        self.assertContains(response, "Honeypot bağlantı denemesi")
        self.assertContains(response, "Honeypot")
        self.assertContains(response, "Yeni bağlantı denemesi")
        self.assertContains(response, "192.168.50.40")
        self.assertContains(response, "2222")
        content = response.content.decode()
        self.assertNotIn("{{", content)
        self.assertNotIn("latest_monitoring_cycle.started_at", content)

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    @patch("dashboard.services.monitoring_cycle.run_security_analysis")
    @patch("dashboard.services.monitoring_cycle.ingest_honeypot_logs")
    @patch("dashboard.services.monitoring_cycle.scan_network")
    def test_dashboard_post_triggers_monitoring_cycle_without_fake_data(self, scan, ingest, analysis):
        scan.return_value = {"success": True, "is_mock": False, "found_devices": 0, "new_devices": 0}
        ingest.return_value = {"success": True, "read": 0, "created": 0, "skipped": 0, "ignored": 0, "invalid": 0}
        analysis.return_value = {"arp": 0, "port": 0, "ssh": 0, "risk": 0}
        self.client.force_login(self.user)
        response = self.client.post(reverse("dashboard:run_monitoring_cycle"), {"scan_limit": "7"})
        self.assertRedirects(response, reverse("dashboard:index"))
        scan.assert_called_once_with(limit=7)
        ingest.assert_called_once_with()
        analysis.assert_called_once_with()
        self.assertEqual(MonitoringCycleRun.objects.count(), 1)
        run = MonitoringCycleRun.objects.first()
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.scan_found_devices, 0)
        self.assertEqual(run.honeypot_ignored_lines, 0)
        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(HoneypotEvent.objects.count(), 0)

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_ssh_honeypot_attempt_creates_user_visible_alert(self):
        HoneypotEvent.objects.create(
            source_ip="192.168.50.41",
            service="ssh",
            username="adminuser",
            destination_port=2222,
            is_mock=False,
        )

        findings = analyze_ssh_attempt_logs(minutes=10)

        self.assertEqual(len(findings), 1)
        self.assertTrue(Alert.objects.filter(alert_type="honeypot", title__icontains="Honeypot").exists())
        self.assertTrue(SecurityEvent.objects.filter(event_type="honeypot", protocol="SSH", source_ip="192.168.50.41").exists())
        self.client.force_login(self.user)
        response = self.client.get(reverse("dashboard:alerts"))
        self.assertContains(response, "Honeypot bağlantı denemesi")
        self.assertContains(response, "Ne oldu?")
        self.assertContains(response, "Neden önemli?")
        self.assertContains(response, "Ne yapmalıyım?")
        self.assertContains(response, "Yanlış alarm olabilir mi?")
        self.assertContains(response, "Kaynak veri türü")
        self.assertContains(response, "OpenCanary logu")

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_honeypot_port_scan_and_bruteforce_analysis_create_alerts(self):
        for port, service in [(2222, "ssh"), (8080, "http"), (2121, "ftp")]:
            HoneypotEvent.objects.create(source_ip="192.168.50.42", service=service, destination_port=port, is_mock=False)
        for _ in range(3):
            HoneypotEvent.objects.create(source_ip="192.168.50.43", service="ssh", username="adminuser", destination_port=2222, is_mock=False)

        port_findings = analyze_port_scan_logs(threshold=3, minutes=10)
        brute_findings = analyze_bruteforce_logs(threshold=3, minutes=10)

        self.assertEqual(len(port_findings), 1)
        self.assertEqual(len(brute_findings), 1)
        self.assertTrue(Alert.objects.filter(alert_type="port_scan", title__icontains="port").exists())
        self.assertTrue(Alert.objects.filter(alert_type="brute_force", title__icontains="SSH").exists())

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_dos_analysis_creates_alert_from_safe_event_counts(self):
        for index in range(5):
            SecurityEvent.objects.create(
                event_type="network",
                source_ip="192.168.50.70",
                destination_ip="192.168.50.10",
                destination_port=443,
                title=f"request {index}",
                description="safe test event",
                level="warning",
            )

        findings = analyze_dos_logs(threshold=5, minutes=10)

        self.assertEqual(len(findings), 1)
        self.assertTrue(Alert.objects.filter(alert_type="dos_suspected", source_ip="192.168.50.70").exists())
        self.assertTrue(SecurityEvent.objects.filter(event_type="dos_suspected", source_ip="192.168.50.70").exists())

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_simulate_security_events_command_is_disabled(self):
        output = StringIO()
        call_command("simulate_security_events", stdout=output)

        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(Alert.objects.count(), 0)
        self.assertEqual(SecurityEvent.objects.count(), 0)
        self.assertEqual(HoneypotEvent.objects.count(), 0)
        self.assertIn("devre dışı", output.getvalue())

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_risk_score_reasons_are_calculated(self):
        device = Device.objects.create(ip_address="192.168.50.80", status="partial", is_trusted=False)
        Alert.objects.create(device=device, alert_type="new_device", severity="medium", status="active", title="new", message="test", source_ip=device.ip_address)
        Alert.objects.create(alert_type="brute_force", severity="high", status="active", title="brute", message="test", source_ip="192.168.50.81")

        result = calculate_risk(include_reasons=True)

        labels = {item["label"]: item["points"] for item in result["risk_reasons"]}
        self.assertGreaterEqual(result["risk_score"], 48)
        self.assertEqual(labels["Yeni cihaz tespit edildi"], 10)
        self.assertEqual(labels["Brute-force şüphesi"], 30)
        self.assertEqual(labels["Kısmen algılanmış cihaz"], 8)

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_clear_security_data_command_clears_only_security_tables(self):
        device = Device.objects.create(ip_address="192.168.50.82", status="online")
        OpenPort.objects.create(device=device, port=5432, protocol="tcp", service_name="postgresql")
        Alert.objects.create(device=device, alert_type="new_device", severity="medium", title="new", message="test", source_ip=device.ip_address)
        SecurityEvent.objects.create(event_type="open_port", title="port", description="test", destination_ip=device.ip_address, destination_port=5432)
        HoneypotEvent.objects.create(source_ip="192.168.50.83", service="ssh", is_mock=False)
        ArpObservation.objects.create(ip_address=device.ip_address, mac_address="00:11:22:33:44:55")
        RiskSnapshot.objects.create(risk_level="medium", risk_score=40, security_score=60, active_alerts=1)
        MonitoringCycleRun.objects.create(status="completed")
        NetworkScan.objects.create(network_range="192.168.50.0/24", status="completed", is_mock=False)

        output = StringIO()
        call_command("clear_security_data", stdout=output)

        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(OpenPort.objects.count(), 0)
        self.assertEqual(Alert.objects.count(), 0)
        self.assertEqual(SecurityEvent.objects.count(), 0)
        self.assertEqual(HoneypotEvent.objects.count(), 0)
        self.assertEqual(ArpObservation.objects.count(), 0)
        self.assertEqual(RiskSnapshot.objects.count(), 0)
        self.assertEqual(MonitoringCycleRun.objects.count(), 0)
        self.assertEqual(NetworkScan.objects.count(), 0)
        self.assertTrue(get_user_model().objects.filter(username="demo").exists())
        self.assertIn("Toplam silinen", output.getvalue())

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_settings_clear_security_data_requires_post_and_clears_selected_target(self):
        self.client.force_login(self.user)
        Alert.objects.create(alert_type="system", severity="low", title="test", message="test")

        response = self.client.get(reverse("dashboard:clear_security_data"), {"target": "alerts"})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(Alert.objects.count(), 1)

        response = self.client.post(reverse("dashboard:clear_security_data"), {"target": "alerts"})
        self.assertRedirects(response, reverse("dashboard:settings"))
        self.assertEqual(Alert.objects.count(), 0)

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_arp_spoofing_analysis_creates_alert_from_existing_observations(self):
        findings = analyze_arp_observations([
            {"ip_address": "192.168.50.44", "mac_address": "00:11:22:33:44:55"},
            {"ip_address": "192.168.50.45", "mac_address": "00:11:22:33:44:55"},
        ])

        self.assertEqual(len(findings), 1)
        self.assertTrue(Alert.objects.filter(alert_type="arp_spoof", title__icontains="ARP").exists())

        Alert.objects.all().delete()
        SecurityEvent.objects.all().delete()
        ArpObservation.objects.create(ip_address="192.168.50.1", mac_address="00:11:22:33:44:aa", is_gateway=True)
        ArpObservation.objects.create(ip_address="192.168.50.1", mac_address="00:11:22:33:44:bb", is_gateway=True)
        findings = analyze_arp_observations()
        self.assertEqual(len(findings), 1)
        self.assertTrue(Alert.objects.filter(alert_type="arp_spoof", source_ip="192.168.50.1").exists())

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_reports_page_contains_chart_data_when_database_has_events(self):
        self.client.force_login(self.user)
        Device.objects.create(ip_address="192.168.50.46", status="online", is_trusted=False, risk_score=20)
        HoneypotEvent.objects.create(source_ip="192.168.50.47", service="ssh", destination_port=2222, is_mock=False)
        SecurityEvent.objects.create(event_type="honeypot", title="SSH event", description="test", source_ip="192.168.50.47", protocol="SSH", risk_score=35)
        RiskSnapshot.objects.create(risk_level="low", risk_score=13, security_score=87, active_alerts=1)

        response = self.client.get(reverse("dashboard:reports"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "daily-chart-data")
        self.assertContains(response, "risk-chart-data")
        self.assertContains(response, "device-report-chart-data")
        self.assertContains(response, "service-chart-data")

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_alert_status_update_requires_post_and_updates_status(self):
        self.client.force_login(self.user)
        device = Device.objects.create(ip_address="192.168.50.30", status="online")
        alert = Alert.objects.create(
            device=device, alert_type="new_device", severity="medium", status="active",
            title="Yeni cihaz tespit edildi: 192.168.50.30", message="test", source_ip="192.168.50.30",
        )
        response = self.client.get(reverse("dashboard:update_alert_status", args=[alert.pk]), {"status": "resolved"})
        self.assertEqual(response.status_code, 405)
        alert.refresh_from_db()
        self.assertEqual(alert.status, "active")
        self.client.post(reverse("dashboard:update_alert_status", args=[alert.pk]), {"status": "acknowledged"})
        alert.refresh_from_db()
        self.assertEqual(alert.status, "acknowledged")
        self.assertFalse(alert.is_resolved)
        self.client.post(reverse("dashboard:update_alert_status", args=[alert.pk]), {"status": "resolved"})
        alert.refresh_from_db()
        self.assertEqual(alert.status, "resolved")
        self.assertTrue(alert.is_resolved)

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_dashboard_active_alert_count_excludes_acknowledged_resolved_and_out_of_scope(self):
        self.client.force_login(self.user)
        device = Device.objects.create(ip_address="192.168.50.31", status="online")
        out_device = Device.objects.create(ip_address="192.168.60.31", status="online")
        Alert.objects.create(device=device, alert_type="new_device", severity="medium", status="active", title="active", message="test", source_ip="192.168.50.31")
        Alert.objects.create(device=device, alert_type="new_device", severity="medium", status="acknowledged", title="ack", message="test", source_ip="192.168.50.31")
        Alert.objects.create(device=device, alert_type="new_device", severity="medium", status="resolved", title="resolved", message="test", source_ip="192.168.50.31")
        Alert.objects.create(device=out_device, alert_type="new_device", severity="medium", status="active", title="scope-excluded-alert", message="test", source_ip="192.168.60.31")
        response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.context["active_alerts"], 1)
        alerts_response = self.client.get(reverse("dashboard:alerts"))
        self.assertContains(alerts_response, "active")
        self.assertNotContains(alerts_response, "scope-excluded-alert")

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_runtime_health_returns_structured_checks_without_creating_fake_data(self):
        before = (Device.objects.count(), Alert.objects.count(), HoneypotEvent.objects.count(), SecurityEvent.objects.count())
        checks = get_runtime_health()
        after = (Device.objects.count(), Alert.objects.count(), HoneypotEvent.objects.count(), SecurityEvent.objects.count())
        self.assertEqual(before, after)
        self.assertTrue(checks)
        required_keys = {"key", "label", "status", "value", "message", "hint"}
        for item in checks:
            self.assertTrue(required_keys.issubset(item.keys()))
            self.assertIn(item["status"], {"ok", "warning", "error", "unknown"})

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_check_runtime_health_command_runs_without_creating_fake_data(self):
        before = (Device.objects.count(), Alert.objects.count(), HoneypotEvent.objects.count(), SecurityEvent.objects.count())
        output = StringIO()
        call_command("check_runtime_health", stdout=output)
        after = (Device.objects.count(), Alert.objects.count(), HoneypotEvent.objects.count(), SecurityEvent.objects.count())
        self.assertEqual(before, after)
        self.assertIn("Ozet:", output.getvalue())
