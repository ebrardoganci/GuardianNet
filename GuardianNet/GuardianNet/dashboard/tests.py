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

from .models import Alert, Device, HoneypotEvent, MonitoringCycleRun, RiskSnapshot, SecurityEvent
from .services.arp_monitor import detect_arp_anomalies
from .services.bruteforce_detector import detect_bruteforce
from .services.honeypot_manager import ingest_honeypot_logs
from .services.network_scanner import resolve_target_subnet, scan_network
from .services.port_scan_detector import detect_port_scan
from .services.runtime_health import get_runtime_health


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
            self.assertEqual(event.service, "ssh")
            self.assertEqual(event.destination_port, 2222)
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

        response = self.client.get(reverse("dashboard:index"))

        self.assertContains(response, "Cycle 24.06 01:27")
        self.assertContains(response, "Scan found/new")
        self.assertContains(response, "Honeypot read/created")
        self.assertContains(response, "1 duplicate")
        self.assertContains(response, "8 ignored")
        self.assertContains(response, "Risk score")
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
