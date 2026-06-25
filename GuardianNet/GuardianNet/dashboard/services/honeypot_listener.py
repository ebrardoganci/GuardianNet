import os
import socketserver
import tempfile
import threading
import uuid
from contextlib import suppress

from django.utils import timezone

from dashboard.models import HoneypotEvent


LISTENER_SERVICES = {
    2222: ("ssh", "Sahte SSH"),
    8080: ("http", "Sahte Web paneli"),
    2121: ("ftp", "Sahte FTP"),
}
LOCK_PATH = os.path.join(tempfile.gettempdir(), "guardiannet_honeypot_listener.lock")


def record_honeypot_connection(*, source_ip, source_port=None, destination_port, payload="", source_type="Honeypot listener"):
    service, _ = LISTENER_SERVICES.get(int(destination_port), ("http", "Sahte servis"))
    event = HoneypotEvent.objects.create(
        event_id=f"listener-{uuid.uuid4().hex}",
        source_ip=source_ip,
        source_port=source_port,
        destination_port=destination_port,
        service=service,
        event_type="connection",
        command=str(payload or "")[:255],
        protocol="tcp",
        source_type=source_type,
        login_success=False,
        raw_data={
            "source_type": source_type,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "service": service,
            "protocol": "tcp",
            "observed_at": timezone.now().isoformat(),
        },
        is_mock=False,
    )
    return event


class ListenerAlreadyRunning(RuntimeError):
    pass


class ListenerLock:
    def __init__(self, path=LOCK_PATH):
        self.path = path
        self.fd = None

    def __enter__(self):
        try:
            self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise ListenerAlreadyRunning(
                "Honeypot listener zaten çalışıyor görünüyor. Eski süreç kapandıysa lock dosyasını silin: "
                f"{self.path}"
            ) from exc
        os.write(self.fd, str(os.getpid()).encode("ascii"))
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            with suppress(OSError):
                os.close(self.fd)
        with suppress(OSError):
            os.unlink(self.path)


def _response_for_port(port):
    if port == 8080:
        return b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 25\r\n\r\nGuardianNet honeypot\r\n"
    if port == 2121:
        return b"220 GuardianNet FTP honeypot\r\n"
    if port == 2222:
        return b"SSH-2.0-GuardianNet_Honeypot\r\n"
    return b""


def make_handler(port, stdout=None, counter=None):
    class HoneypotTCPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            source_ip, source_port = self.client_address[:2]
            payload = ""
            self.request.settimeout(0.5)
            with suppress(OSError, UnicodeDecodeError):
                data = self.request.recv(512)
                payload = data.decode("utf-8", errors="replace")
            event = record_honeypot_connection(
                source_ip=source_ip,
                source_port=source_port,
                destination_port=port,
                payload=payload,
            )
            with suppress(OSError):
                response = _response_for_port(port)
                if response:
                    self.request.sendall(response)
            if counter is not None:
                counter["count"] += 1
            if stdout is not None:
                service, label = LISTENER_SERVICES[port]
                stdout.write(f"[{counter['count'] if counter else '?'}] {source_ip}:{source_port} -> {port}/{service} ({label}) kaydedildi. Event #{event.pk}")

    return HoneypotTCPHandler


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_listener_servers(stdout=None):
    servers = []
    threads = []
    counter = {"count": 0}
    try:
        for port, (service, label) in LISTENER_SERVICES.items():
            server = ThreadedTCPServer(("0.0.0.0", port), make_handler(port, stdout=stdout, counter=counter))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
            if stdout is not None:
                stdout.write(f"{label} dinleniyor: 0.0.0.0:{port} ({service})")
    except OSError:
        for server in servers:
            server.shutdown()
            server.server_close()
        raise
    return servers, threads, counter


def stop_listener_servers(servers):
    for server in servers:
        server.shutdown()
        server.server_close()
