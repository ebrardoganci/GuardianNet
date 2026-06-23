import ipaddress
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from itertools import islice

from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from dashboard.models import Alert, Device, NetworkScan, SecurityEvent
from dashboard.services.runtime_settings import get_bool, get_value


DEMO_DEVICES = [
    {"ip_address": "192.0.2.10", "mac_address": "02:00:00:00:00:10", "hostname": "demo-router", "vendor": "Demo Networks", "status": "online", "is_trusted": True, "risk_score": 10},
    {"ip_address": "192.0.2.21", "mac_address": "02:00:00:00:00:21", "hostname": "lab-workstation", "vendor": "Example Labs", "status": "online", "is_trusted": True, "risk_score": 28},
    {"ip_address": "192.0.2.45", "mac_address": "02:00:00:00:00:45", "hostname": "unknown-client", "vendor": "Bilinmiyor", "status": "offline", "is_trusted": False, "risk_score": 72},
]
ALLOWED_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _is_allowed_network(network):
    return (
        network.version == 4
        and not network.is_loopback
        and any(network.subnet_of(allowed) for allowed in ALLOWED_PRIVATE_NETWORKS)
        and network.num_addresses <= settings.NETWORK_SCAN_MAX_HOSTS
    )


def _run_route_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _default_gateway_interface_names():
    names = set()
    powershell = shutil.which("powershell") or shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell:
        script = (
            "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
            "| Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } "
            "| Sort-Object RouteMetric,InterfaceIndex "
            "| Select-Object -ExpandProperty InterfaceAlias"
        )
        output = _run_route_command([powershell, "-NoProfile", "-Command", script])
        names.update(line.strip().lower() for line in output.splitlines() if line.strip())
        if names:
            return names

    ip_command = shutil.which("ip")
    if ip_command:
        output = _run_route_command([ip_command, "route", "show", "default"])
        for line in output.splitlines():
            parts = line.split()
            if "dev" in parts:
                index = parts.index("dev")
                if index + 1 < len(parts):
                    names.add(parts[index + 1].lower())
        if names:
            return names

    route_command = shutil.which("route")
    if route_command:
        output = _run_route_command([route_command, "-n", "get", "default"])
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("interface:"):
                names.add(line.split(":", 1)[1].strip().lower())
    return names


def _looks_virtual_interface(name):
    lowered = name.lower()
    hints = ("virtual", "vmware", "vbox", "docker", "hyper-v", "loopback", "bluetooth", "tailscale", "zerotier", "wsl")
    return any(hint in lowered for hint in hints)


def detect_local_subnet():
    """Detect an active private IPv4 subnet and cap automatic discovery to /24."""
    try:
        import psutil
    except ImportError:
        return None
    gateway_names = _default_gateway_interface_names()
    stats = psutil.net_if_stats()
    candidates = []
    for interface_name, addresses in psutil.net_if_addrs().items():
        interface_stats = stats.get(interface_name)
        if interface_stats and not interface_stats.isup:
            continue
        has_gateway = interface_name.lower() in gateway_names
        is_virtual = _looks_virtual_interface(interface_name)
        for address in addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            ip = ipaddress.ip_address(address.address)
            if not ip.is_private or ip.is_loopback or ip.is_link_local:
                continue
            detected = ipaddress.ip_network(f"{ip}/{address.netmask}", strict=False)
            if detected.prefixlen < 24:
                detected = ipaddress.ip_network(f"{ip}/24", strict=False)
            if _is_allowed_network(detected):
                candidates.append((0 if has_gateway else 1, 1 if is_virtual else 0, interface_name, detected))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[:3])
    return candidates[0][3]


def resolve_target_subnet():
    configured = settings.LOCAL_SUBNET or get_value("local_subnet", "")
    if configured:
        try:
            network = ipaddress.ip_network(configured, strict=False)
        except ValueError as exc:
            raise ValueError("LOCAL_SUBNET gecerli bir CIDR olmali.") from exc
        if not _is_allowed_network(network):
            raise ValueError("LOCAL_SUBNET yalnizca ozel IPv4 agi olmali ve host limiti asilmamali.")
        return network
    network = detect_local_subnet()
    if not network:
        raise RuntimeError("Aktif ozel IPv4 agi otomatik algilanamadi.")
    return network


def _normalize_limit(limit):
    if limit is None:
        return None
    try:
        value = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError("Tarama limiti pozitif bir tam sayi olmali.") from exc
    if value <= 0:
        raise ValueError("Tarama limiti pozitif bir tam sayi olmali.")
    return value


def _scan_targets(network, limit=None):
    limit = _normalize_limit(limit)
    if limit is None:
        return [str(network)]
    targets = [str(host) for host in islice(network.hosts(), limit)]
    if not targets:
        raise ValueError("Taranacak host bulunamadi.")
    return targets


def _scan_with_nmap(targets):
    executable = shutil.which("nmap")
    if not executable:
        raise RuntimeError("Nmap bulunamadi.")
    result = subprocess.run(
        [executable, "-sn", "-n", "-oX", "-", *targets],
        capture_output=True, text=True, timeout=120, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "Nmap cihaz kesfi basarisiz.").strip())
    devices = []
    for host in ET.fromstring(result.stdout).findall("host"):
        if host.find("status") is None or host.find("status").get("state") != "up":
            continue
        addresses = {item.get("addrtype"): item for item in host.findall("address")}
        ipv4 = addresses.get("ipv4")
        if ipv4 is None:
            continue
        mac = addresses.get("mac")
        devices.append({
            "ip_address": ipv4.get("addr"),
            "mac_address": mac.get("addr", "").lower() if mac is not None else None,
            "hostname": None,
            "vendor": mac.get("vendor", "Bilinmiyor") if mac is not None else "Bilinmiyor",
        })
    return devices, "nmap-ping"


def _scan_with_scapy(targets):
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as exc:
        raise RuntimeError("Scapy bulunamadi.") from exc
    pdst = targets[0] if len(targets) == 1 else targets
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=pdst), timeout=3, retry=1, verbose=False)
    devices = []
    for _, response in answered:
        devices.append({"ip_address": response.psrc, "mac_address": response.hwsrc.lower(), "hostname": None, "vendor": "Bilinmiyor"})
    return devices, "scapy-arp"


def _seed_demo_fallback():
    if Device.objects.exists():
        return
    for data in DEMO_DEVICES:
        Device.objects.update_or_create(ip_address=data["ip_address"], defaults=data)


def _record_devices(network, discovered):
    active_ips = []
    new_count = 0
    for data in discovered:
        ip_address = data["ip_address"]
        try:
            if ipaddress.ip_address(ip_address) not in network:
                continue
        except ValueError:
            continue
        active_ips.append(ip_address)
        previous = Device.objects.filter(ip_address=ip_address).first()
        old_mac = previous.mac_address if previous else None
        device, created = Device.objects.update_or_create(
            ip_address=ip_address,
            defaults={"mac_address": data.get("mac_address"), "hostname": data.get("hostname"),
                      "vendor": data.get("vendor") or "Bilinmiyor", "status": "online"},
        )
        if created:
            new_count += 1
            existing_new_device_alert = Alert.objects.filter(
                Q(source_ip=ip_address) | Q(device=device),
                alert_type="new_device",
                status="active",
            ).exists()
            if not existing_new_device_alert:
                mac_note = f" MAC: {device.mac_address}" if device.mac_address else ""
                Alert.objects.create(device=device, alert_type="new_device", severity="medium", status="active",
                                     title=f"Yeni cihaz tespit edildi: {ip_address}",
                                     message=f"Yeni cihaz tespit edildi: {ip_address}.{mac_note}",
                                     source_ip=ip_address, source_mac=device.mac_address or "")
        elif old_mac and device.mac_address and old_mac.lower() != device.mac_address.lower():
            SecurityEvent.objects.create(event_type="arp_anomaly", title="IP/MAC eslesmesi degisti",
                                         description=f"{ip_address}: {old_mac} -> {device.mac_address}", level="danger",
                                         source_ip=ip_address, source_mac=device.mac_address, risk_score=80)
            Alert.objects.get_or_create(alert_type="arp_spoof", source_ip=ip_address, status="active",
                                        defaults={"device": device, "severity": "high", "title": "ARP anomalisi",
                                                  "message": "Ayni IP icin farkli MAC adresi gozlemlendi.", "source_mac": device.mac_address})
    for device in Device.objects.exclude(ip_address__in=active_ips):
        try:
            if ipaddress.ip_address(device.ip_address) in network:
                device.status = "offline"
                device.save(update_fields=["status"])
        except ValueError:
            continue
    return new_count, len(active_ips)


def scan_network(force_demo=False, limit=None):
    """Discover hosts on an explicitly bounded private LAN; never scans ports."""
    if force_demo or get_value("guardiannet_mode", settings.GUARDIANNET_MODE) == "demo":
        _seed_demo_fallback()
        scan = NetworkScan.objects.create(network_range="192.0.2.0/24 (demo)", status="demo", scan_method="demo",
                                          devices_found=len(DEMO_DEVICES), is_mock=True,
                                          message="Demo modu kullanildi.", completed_at=timezone.now())
        return {"success": True, "is_mock": True, "found_devices": len(DEMO_DEVICES), "new_devices": 0, "scan_id": scan.pk, "message": scan.message}

    scan = NetworkScan.objects.create(network_range="algilaniyor", status="failed", is_mock=False)
    try:
        if not get_bool("enable_real_scan", settings.ENABLE_REAL_SCAN):
            raise RuntimeError("ENABLE_REAL_SCAN kapali.")
        network = resolve_target_subnet()
        targets = _scan_targets(network, limit)
        scan.network_range = str(network)
        errors = []
        try:
            discovered, method = _scan_with_nmap(targets)
        except Exception as nmap_error:
            errors.append(str(nmap_error))
            try:
                discovered, method = _scan_with_scapy(targets)
            except Exception as scapy_error:
                errors.append(str(scapy_error))
                raise RuntimeError("; ".join(errors)) from scapy_error
        new_count, found_count = _record_devices(network, discovered)
        scan.status = "completed"
        scan.scan_method = method
        scan.devices_found = found_count
        scan.message = "Yerel cihaz kesfi tamamlandi."
        scan.notes = "; ".join(errors)
        scan.completed_at = timezone.now()
        scan.save()
        return {"success": True, "is_mock": False, "found_devices": found_count, "new_devices": new_count,
                "scan_id": scan.pk, "network": str(network), "method": method, "message": scan.message}
    except Exception as exc:
        scan.status = "failed"
        scan.is_mock = False
        scan.scan_method = "real-failed"
        scan.message = "Gercek kesif basarisiz; demo fallback uretilmedi."
        scan.notes = str(exc)
        scan.completed_at = timezone.now()
        scan.save()
        return {"success": False, "is_mock": False, "found_devices": 0, "new_devices": 0,
                "scan_id": scan.pk, "message": scan.message, "error": str(exc)}
