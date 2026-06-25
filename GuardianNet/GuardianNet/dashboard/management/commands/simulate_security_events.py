from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Sunum sürümünde devre dışıdır; demo/simülasyon güvenlik verisi üretmez."

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.WARNING(
                "simulate_security_events devre dışı. GuardianNet artık demo/simülasyon alert, event veya risk kaydı üretmez."
            )
        )
