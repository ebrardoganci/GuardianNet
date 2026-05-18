import ipaddress 
import platform
import socket 
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_local_ip():

    # bilgisayarın yerel ağdaki ıpsini bulur 

    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

         # Burada gerçek anlamda Google'a veri göndermiyoruz.
        # Python sadece hangi ağ kartından çıkacağını anlamak için
        # bu adres üzerinden yerel IP'yi seçiyor.
        s.connect(("8.8.8.8",80))

        local_ip = s.getsockname()[0]
        s.close()

        return local_ip
    
    except Exception:
        return "127.0.0.1"
    
def get_local_network(cidr_suffix=24):
    # yerel ip adresinden ağ bloğunu üretir. 


    local_ip = get_local_ip()

    network_text = f"{local_ip}/{cidr_suffix}"
    network = ipaddress.ip_network(network_text, strict=False)
    return network

def ping_hosts(ip_address, timeout_ms=700):
    """
    Tek bir IP adresine ping atar . 
    Eğer c,haz cevap verirse true döner cevap vermezse false döner.
    """

    system_name = platform.system().lower()

    if "windows" in system_name:
        command = [
            "ping",
            "-n",
            "1",
            "-w",
            str(timeout_ms),
            str(ip_address),
        ]
    else:
        command =[
              "ping",
            "-c",
            "1",
            "-W",
            "1",
            str(ip_address),
        ]

    try:
        results =subprocess.run(
            command, 
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        return results.returncode == 0
    except Exception:
        return False 
    

def resolve_hostname(ip_address):
    """
    IP adresinden cihaz adını bulmaya çalışır.

    Her zaman çalışmaz.
    Bazı cihazlar hostname bilgisini vermez.
    """

    try:
        hostname = socket.gethostbyaddr(str(ip_address))[0]
        return hostname

    except Exception:
        return None


def scan_local_network(max_workers=50):
    """
    Yerel ağı tarar.

    Dönen veri örneği:
        [
            {
                "ip_address": "192.168.1.1",
                "hostname": "modem.local",
                "status": "online",
                "risk_score": 10,
            },
            {
                "ip_address": "192.168.1.34",
                "hostname": "Ebrar-PC",
                "status": "online",
                "risk_score": 10,
            }
        ]
    """

    network = get_local_network(cidr_suffix=24)

    found_devices = []

    hosts = list(network.hosts())

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(ping_host, ip): ip
            for ip in hosts
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]

            try:
                is_alive = future.result()

                if is_alive:
                    hostname = resolve_hostname(ip)

                    found_devices.append(
                        {
                            "ip_address": str(ip),
                            "hostname": hostname,
                            "status": "online",
                            "risk_score": 10,
                        }
                    )

            except Exception:
                continue

    found_devices = sorted(
        found_devices,
        key=lambda device: tuple(
            int(part) for part in device["ip_address"].split(".")
        )
    )

    return found_devices
