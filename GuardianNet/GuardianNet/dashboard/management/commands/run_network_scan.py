from django.core.management.base import BaseCommand
from django.utils import timezone

from dashboard.models import SystemSetting
from dashboard.services.network_scanner import scan_network


class Command(BaseCommand):
    help = "Yalnizca izinli ozel yerel agda cihaz kesfi yapar."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            help="Komut satiri dogrulamalari icin kabul edilen opsiyonel host limiti.",
        )

    def handle(self, *args, **options):
        result = scan_network(limit=options.get("limit"))
        SystemSetting.objects.update_or_create(key="last_network_scan", defaults={"value": timezone.now().isoformat(), "description": "Son ag kesfi"})
        message = result.get("message", "Tarama tamamlandi.")
        if result["success"]:
            self.stdout.write(self.style.SUCCESS(f"{message} Cihaz: {result['found_devices']}"))
        else:
            self.stdout.write(self.style.WARNING(f"{message} Hata: {result.get('error', 'bilinmiyor')}"))
