from django.core.management.base import BaseCommand

from dashboard.services.runtime_health import get_runtime_health, summarize_health


class Command(BaseCommand):
    help = "GuardianNet runtime ve sistem sagligi kontrollerini listeler."

    def _write_check(self, item):
        status = item["status"].upper()
        value = f" [{item['value']}]" if item.get("value") else ""
        line = f"{status}: {item['label']}{value} - {item['message']}"
        if item.get("hint"):
            line = f"{line} Hint: {item['hint']}"
        if item["status"] == "ok":
            self.stdout.write(self.style.SUCCESS(line))
        elif item["status"] == "error":
            self.stdout.write(self.style.ERROR(line))
        elif item["status"] == "warning":
            self.stdout.write(self.style.WARNING(line))
        else:
            self.stdout.write(line)

    def handle(self, *args, **options):
        checks = get_runtime_health()
        for item in checks:
            self._write_check(item)
        summary = summarize_health(checks)
        self.stdout.write(
            f"Ozet: ok={summary['ok']}, warning={summary['warning']}, "
            f"error={summary['error']}, unknown={summary['unknown']}"
        )
