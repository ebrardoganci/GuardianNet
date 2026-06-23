from django.core.management.base import BaseCommand
from django.db.models import Q

from dashboard.models import Alert, Device, HoneypotEvent, NetworkScan, RiskSnapshot, SecurityEvent, SystemSetting
from dashboard.services.data_scope import (
    DEMO_TEST_NETWORKS,
    demo_risk_snapshot_ids,
    demo_text_q,
    devices_for_subnet,
    filter_ip_fields_in_networks,
)


def _pk_set(queryset):
    return set(queryset.values_list("pk", flat=True))


class Command(BaseCommand):
    help = "Demo/fallback kaynakli kayitlari varsayilan olarak dry-run modunda raporlar."

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--dry-run", action="store_true", help="Silmeden sadece raporla. Varsayilan davranistir.")
        group.add_argument("--apply", action="store_true", help="Raporlanan demo/fallback kayitlarini sil.")

    def _targets(self):
        targets = []

        protected_device_pks = set(devices_for_subnet(Device.objects.all()).values_list("pk", flat=True))
        device_ip = filter_ip_fields_in_networks(Device.objects.all(), ("ip_address",), DEMO_TEST_NETWORKS)
        device_text = Device.objects.filter(demo_text_q("hostname", "vendor")).exclude(pk__in=protected_device_pks)
        targets.append(("Device", Device, {"demo/test IP blogu": device_ip, "demo/fallback metni": device_text}))

        alert_ip = filter_ip_fields_in_networks(Alert.objects.all(), ("source_ip",), DEMO_TEST_NETWORKS)
        alert_text = Alert.objects.filter(demo_text_q("alert_type", "title", "message", "source_mac"))
        alert_type = Alert.objects.filter(alert_type="system")
        targets.append(("Alert", Alert, {"demo/test IP blogu": alert_ip, "demo/fallback/source/type alani": alert_text | alert_type}))

        event_ip = filter_ip_fields_in_networks(SecurityEvent.objects.all(), ("source_ip", "destination_ip"), DEMO_TEST_NETWORKS)
        event_text = SecurityEvent.objects.filter(demo_text_q("event_type", "title", "description", "protocol", "source_mac"))
        event_type = SecurityEvent.objects.filter(event_type="system")
        targets.append(("SecurityEvent", SecurityEvent, {"demo/test IP blogu": event_ip, "demo/fallback/source/type alani": event_text | event_type}))

        honeypot_ip = filter_ip_fields_in_networks(HoneypotEvent.objects.all(), ("source_ip",), DEMO_TEST_NETWORKS)
        honeypot_mock = HoneypotEvent.objects.filter(Q(is_mock=True) | demo_text_q("username", "command"))
        targets.append(("HoneypotEvent", HoneypotEvent, {"demo/test IP blogu": honeypot_ip, "mock/demo/fallback alani": honeypot_mock}))

        scan_demo = NetworkScan.objects.filter(
            Q(is_mock=True)
            | Q(status="demo")
            | demo_text_q("network_range", "scan_method", "message", "notes")
        )
        targets.append(("NetworkScan", NetworkScan, {"demo/fallback/source/type alani": scan_demo}))

        risk_ids = demo_risk_snapshot_ids()
        risk_demo = RiskSnapshot.objects.filter(pk__in=risk_ids)
        targets.append(("RiskSnapshot", RiskSnapshot, {"demo-risk marker": risk_demo}))

        settings_demo = SystemSetting.objects.filter(
            Q(key="data_mode")
            | Q(key__startswith="demo-risk-")
            | demo_text_q("key", "value", "description")
        ).exclude(key="guardiannet_mode")
        targets.append(("SystemSetting", SystemSetting, {"demo/fallback ayari": settings_demo}))

        return targets

    def handle(self, *args, **options):
        apply_changes = options["apply"]
        mode = "APPLY" if apply_changes else "DRY-RUN"
        blocks = ", ".join(str(network) for network in DEMO_TEST_NETWORKS)
        self.stdout.write(f"{mode}: demo veri temizleme raporu")
        self.stdout.write(f"Demo/test IP bloklari: {blocks}")

        total = 0
        deletion_plan = []
        for label, model, reason_map in self._targets():
            pks = set()
            for queryset in reason_map.values():
                pks.update(_pk_set(queryset))
            total += len(pks)
            deletion_plan.append((model, pks))
            self.stdout.write(f"{label}: {len(pks)} kayit")
            for reason, queryset in reason_map.items():
                self.stdout.write(f"  - {reason}: {queryset.count()}")

        if not apply_changes:
            self.stdout.write(self.style.WARNING(f"Dry-run tamamlandi. Silinecek toplam kayit: {total}. Silmek icin --apply kullanin."))
            return

        deleted_total = 0
        for model, pks in deletion_plan:
            if not pks:
                continue
            deleted, _ = model.objects.filter(pk__in=pks).delete()
            deleted_total += deleted
        self.stdout.write(self.style.SUCCESS(f"Demo/fallback temizligi tamamlandi. Silinen toplam kayit: {deleted_total}."))
