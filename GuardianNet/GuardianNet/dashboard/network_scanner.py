import ipaddress
import platform
import re
import socket
import subprocess
from datetime import datetime

from django.utils import timezone

from .models import Device, Alert, SecurityEvent


def get_local_ip():
    """
    Bilgisayarın yerel ağ IP adresini bulur.
    Örnek: 192.168.1.34
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()

    return local_ip


def get_network_range():
    """
    Yerel IP'den /24 ağ aralığı üretir.
    Örnek:
    IP: 192.168.1.34
    Ağ: 192.168.1.0/24
    """
    local_ip = get_local_ip()

    if local_ip.startswith("127."):
        return None

    parts = local_ip.split(".")
    network_address = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    return ipaddress.ip_network(network_address, strict=False)


def ping_ip(ip):
    """
    IP adresine ping atar.
    Cevap varsa cihaz aktif kabul edilir.
    Windows ve Linux için ayrı komut kullanır.
    """
    system_name = platform.system().lower()

    if system_name == "windows":
        command = ["ping", "-n", "1", "-w", "300", str(ip)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(ip)]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return result.returncode == 0

    except Exception:
        return False


def get_arp_table():
    """
    Bilgisayarın ARP tablosunu okur.
    ARP tablosunda IP - MAC eşleşmeleri bulunur.
    """
    arp_data = {}

    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        output = result.stdout

        pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9:-]{17})"

        for ip, mac in re.findall(pattern, output):
            arp_data[ip] = mac.replace("-", ":").lower()

    except Exception:
        pass

    return arp_data


def get_hostname(ip):
    """
    IP adresinden cihaz adını bulmaya çalışır.
    Bulamazsa None döner.
    """
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except Exception:
        return None


def scan_local_network():
    """
    Yerel ağı tarar.
    Bulunan cihazları Device tablosuna kaydeder.
    Yeni cihaz bulunursa Alert ve SecurityEvent oluşturur.
    """

    network = get_network_range()

    if network is None:
        SecurityEvent.objects.create(
            title="Ağ taraması başarısız",
            description="Yerel IP adresi tespit edilemedi.",
            level="danger"
        )

        return {
            "success": False,
            "message": "Yerel IP adresi tespit edilemedi.",
            "found_devices": 0,
            "new_devices": 0,
        }

    active_ips = []

    for ip in network.hosts():
        if ping_ip(ip):
            active_ips.append(str(ip))

    arp_table = get_arp_table()

    found_devices = 0
    new_devices = 0

    for ip in active_ips:
        mac_address = arp_table.get(ip)
        hostname = get_hostname(ip)

        device, created = Device.objects.update_or_create(
            ip_address=ip,
            defaults={
                "mac_address": mac_address,
                "hostname": hostname,
                "status": "online",
                "last_seen": timezone.now(),
            }
        )

        found_devices += 1

        if created:
            new_devices += 1

            Alert.objects.create(
                device=device,
                alert_type="new_device",
                severity="medium",
                title="Yeni cihaz tespit edildi",
                message=f"{ip} IP adresine sahip yeni bir cihaz ağa bağlandı.",
                is_resolved=False
            )

            SecurityEvent.objects.create(
                title="Yeni cihaz bulundu",
                description=f"IP: {ip}, MAC: {mac_address or 'Bilinmiyor'}, Hostname: {hostname or 'Bilinmiyor'}",
                level="warning"
            )

    Device.objects.exclude(ip_address__in=active_ips).update(status="offline")

    SecurityEvent.objects.create(
        title="Ağ taraması tamamlandı",
        description=f"{network} ağı tarandı. {found_devices} aktif cihaz bulundu. {new_devices} yeni cihaz tespit edildi.",
        level="info"
    )

    return {
        "success": True,
        "message": "Ağ taraması tamamlandı.",
        "network": str(network),
        "found_devices": found_devices,
        "new_devices": new_devices,
    }