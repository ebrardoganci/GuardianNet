import json
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse

from .models import Alert, Device, HoneypotEvent, MonitoringCycleRun, RiskSnapshot, SecurityEvent
from .services.arp_monitor import detect_arp_anomalies
from .services.bruteforce_detector import detect_bruteforce
from .services.honeypot_manager import ingest_honeypot_logs
from .services.network_scanner import resolve_target_subnet, scan_network
from .services.port_scan_detector import detect_port_scan


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

    def test_seed_command_is_idempotent(self):
        call_command("seed_demo_data", verbosity=0)
        first = (Device.objects.count(), Alert.objects.count(), SecurityEvent.objects.count(), HoneypotEvent.objects.count(), RiskSnapshot.objects.count())
        call_command("seed_demo_data", verbosity=0)
        self.assertEqual(first, (Device.objects.count(), Alert.objects.count(), SecurityEvent.objects.count(), HoneypotEvent.objects.count(), RiskSnapshot.objects.count()))

    def test_detection_services_only_analyze_supplied_data(self):
        self.assertEqual(len(detect_arp_anomalies([{"ip_address": "192.168.1.1", "mac_address": "aa"}, {"ip_address": "192.168.1.1", "mac_address": "bb"}])), 1)
        self.assertEqual(len(detect_port_scan([{"source_ip": "192.168.1.2", "destination_port": port} for port in range(1, 9)])), 1)
        self.assertEqual(len(detect_bruteforce([{"source_ip": "192.168.1.3", "success": False}] * 5)), 1)

    @override_settings(LOCAL_SUBNET="8.8.8.0/24")
    def test_public_subnet_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_target_subnet()

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24", ENABLE_REAL_SCAN=True)
    @patch("dashboard.services.network_scanner._scan_with_nmap")
    def test_real_scan_updates_devices_without_port_scan(self, nmap_scan):
        nmap_scan.return_value = ([{"ip_address": "192.168.50.10", "mac_address": "00:11:22:33:44:55", "hostname": None, "vendor": "Test"}], "nmap-ping")
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
        self.assertNotContains(response, "192.168.60.10")

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24", ENABLE_REAL_SCAN=True)
    @patch("dashboard.services.network_scanner._scan_with_nmap")
    def test_real_scan_does_not_duplicate_new_device_alerts(self, nmap_scan):
        nmap_scan.return_value = ([{"ip_address": "192.168.50.20", "mac_address": "00:11:22:33:44:77", "hostname": None, "vendor": "Test"}], "nmap-ping")
        self.assertTrue(scan_network()["success"])
        self.assertTrue(scan_network()["success"])
        self.assertEqual(Alert.objects.filter(alert_type="new_device", source_ip="192.168.50.20", status="active").count(), 1)

    @override_settings(ENABLE_HONEYPOT_LOGS=True)
    def test_honeypot_ingest_is_idempotent(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "opencanary.log"
            payload = {
                "event_id": "unit-test-honeypot-event",
                "src_host": "198.51.100.10",
                "dst_port": 22,
                "local_time": "2026-01-01T10:00:00Z",
                "logdata": {"USERNAME": "test", "COMMAND": "noop"},
            }
            path.write_text(json.dumps(payload) + "\n{not-json}\n", encoding="utf-8")
            first = ingest_honeypot_logs(path)
            second = ingest_honeypot_logs(path)
            self.assertEqual(first["read"], 2)
            self.assertEqual(first["created"], 1)
            self.assertEqual(first["invalid"], 1)
            self.assertEqual(second["created"], 0)
            self.assertEqual(second["skipped"], 1)
            self.assertEqual(HoneypotEvent.objects.filter(is_mock=False).count(), 1)

    @override_settings(GUARDIANNET_MODE="real", LOCAL_SUBNET="192.168.50.0/24")
    def test_monitoring_cycle_runs_with_skip_options(self):
        output = StringIO()
        call_command("run_monitoring_cycle", "--skip-scan", "--skip-honeypot", stdout=output)
        text = output.getvalue()
        self.assertIn("Scan: atlandi", text)
        self.assertIn("Honeypot: atlandi", text)
        self.assertIn("analysis: ARP=", text)
        self.assertEqual(Device.objects.count(), 0)
        self.assertEqual(HoneypotEvent.objects.count(), 0)
        self.assertEqual(RiskSnapshot.objects.count(), 1)
        self.assertEqual(MonitoringCycleRun.objects.count(), 1)
        run = MonitoringCycleRun.objects.first()
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.scan_status, "skipped")
        self.assertEqual(run.honeypot_status, "skipped")
        self.assertEqual(run.analysis_status, "completed")
