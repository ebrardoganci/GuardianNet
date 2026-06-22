from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse

from .models import Alert, Device, HoneypotEvent, RiskSnapshot, SecurityEvent
from .services.arp_monitor import detect_arp_anomalies
from .services.bruteforce_detector import detect_bruteforce
from .services.port_scan_detector import detect_port_scan


class DashboardMVPTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(username="demo", password="test-pass-123")

    def test_pages_require_login(self):
        for name in ["dashboard:index", "dashboard:devices", "dashboard:alerts", "dashboard:events", "dashboard:reports", "dashboard:honeypot", "dashboard:settings"]:
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 302)
            self.assertIn("/login/", response.url)

    def test_authenticated_pages_render(self):
        self.client.force_login(self.user)
        for name in ["dashboard:index", "dashboard:devices", "dashboard:alerts", "dashboard:events", "dashboard:reports", "dashboard:honeypot", "dashboard:settings"]:
            self.assertEqual(self.client.get(reverse(name)).status_code, 200)

    def test_seed_command_is_idempotent(self):
        call_command("seed_demo_data", verbosity=0)
        first = (Device.objects.count(), Alert.objects.count(), SecurityEvent.objects.count(), HoneypotEvent.objects.count(), RiskSnapshot.objects.count())
        call_command("seed_demo_data", verbosity=0)
        second = (Device.objects.count(), Alert.objects.count(), SecurityEvent.objects.count(), HoneypotEvent.objects.count(), RiskSnapshot.objects.count())
        self.assertEqual(first, second)

    def test_detection_services_only_analyze_supplied_data(self):
        self.assertEqual(len(detect_arp_anomalies([{"ip_address": "192.0.2.1", "mac_address": "aa"}, {"ip_address": "192.0.2.1", "mac_address": "bb"}])), 1)
        self.assertEqual(len(detect_port_scan([{"source_ip": "192.0.2.2", "destination_port": port} for port in range(1, 9)])), 1)
        self.assertEqual(len(detect_bruteforce([{"source_ip": "192.0.2.3", "success": False}] * 5)), 1)
