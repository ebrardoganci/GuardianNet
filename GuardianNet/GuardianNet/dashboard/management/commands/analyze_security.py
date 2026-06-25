from django.core.management.base import BaseCommand

from dashboard.services.security_analysis import run_security_analysis


class Command(BaseCommand):
    help = "Kayitli guvenlik verilerini analiz eder ve risk puanini gunceller."

    def handle(self, *args, **options):
        result = run_security_analysis()
        self.stdout.write(self.style.SUCCESS(
            "Analiz tamamlandi. "
            f"Yeni cihaz: {result.get('new_devices', 0)}, acik port: {result.get('open_ports', 0)}, "
            f"ARP: {result['arp']}, port scan: {result['port']}, SSH: {result['ssh']}, "
            f"DoS: {result.get('dos', 0)}, risk: {result['risk']}"
        ))
