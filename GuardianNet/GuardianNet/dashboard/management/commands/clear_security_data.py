from django.core.management.base import BaseCommand, CommandError

from dashboard.services.security_data import CLEAR_TARGETS, clear_security_data


class Command(BaseCommand):
    help = "GuardianNet guvenlik verilerini temizler; kullanici, admin, session ve migration tablolarina dokunmaz."

    def add_arguments(self, parser):
        parser.add_argument(
            "--target",
            choices=list(CLEAR_TARGETS.keys()),
            default="all",
            help="Temizlenecek veri grubu. Varsayilan: all.",
        )

    def handle(self, *args, **options):
        try:
            result = clear_security_data(options["target"])
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(self.style.SUCCESS(f"{result['label']} temizlendi. Toplam silinen: {result['total']}"))
        for model_name, count in result["deleted"].items():
            self.stdout.write(f"  {model_name}: {count}")
