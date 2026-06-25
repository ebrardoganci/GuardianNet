from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Sunum sürümünde devre dışıdır; demo güvenlik verisi üretmez."

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.WARNING(
                "seed_demo_data devre dışı. GuardianNet demo cihaz, alert, event veya risk kaydı üretmez."
            )
        )
