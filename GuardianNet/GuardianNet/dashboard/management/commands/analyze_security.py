from django.core.management.base import BaseCommand

from dashboard.services.security_analysis import run_security_analysis


class Command(BaseCommand):
    help = "Kayitli guvenlik verilerini analiz eder ve risk puanini gunceller."

    def handle(self, *args, **options):
        result = run_security_analysis()
        self.stdout.write(self.style.SUCCESS(
            f"Analiz tamamlandi. ARP: {result['arp']}, port: {result['port']}, SSH: {result['ssh']}, risk: {result['risk']}"
        ))
