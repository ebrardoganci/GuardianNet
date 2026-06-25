import time

from django.core.management.base import BaseCommand, CommandError

from dashboard.services.honeypot_listener import ListenerAlreadyRunning, ListenerLock, start_listener_servers, stop_listener_servers


class Command(BaseCommand):
    help = "Gelistirme/test icin sahte SSH/Web/FTP honeypot portlarini dinler ve baglanti denemelerini kaydeder."

    def handle(self, *args, **options):
        try:
            with ListenerLock():
                servers, _, counter = start_listener_servers(stdout=self.stdout)
                self.stdout.write(self.style.SUCCESS("Honeypot listener basladi. Kapatmak icin CTRL+C."))
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    self.stdout.write("")
                    self.stdout.write(self.style.WARNING(f"Honeypot listener kapatiliyor. Kaydedilen baglanti: {counter['count']}"))
                finally:
                    stop_listener_servers(servers)
        except ListenerAlreadyRunning as exc:
            raise CommandError(str(exc)) from exc
        except OSError as exc:
            raise CommandError(
                "Honeypot listener portlari acilamadi. 2222, 8080 veya 2121 portlari kullanimda olabilir. "
                f"Detay: {exc}"
            ) from exc
