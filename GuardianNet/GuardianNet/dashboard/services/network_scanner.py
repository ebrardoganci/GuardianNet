import ipaddress
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from itertools import islice

from django.conf import settings
from django.utils import timezone

from dashboard.models import ArpObservation, Device, NetworkScan, OpenPort, SecurityEvent
from dashboard.security_explanations import PORT_SCAN_PORTS
from dashboard.services.runtime_settings import get_bool, get_value


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


def _scan_with_nmap_ports(targets):
    executable = shutil.which("nmap")
    if not executable:
        raise RuntimeError("Nmap bulunamadi.")
    ports = ",".join(str(port) for port in PORT_SCAN_PORTS)
    result = subprocess.run(
        [
            executable,
            "-n",
            "-sT",
            "--open",
            "--max-retries",
            "1",
            "--host-timeout",
            "20s",
            "-p",
            ports,
            "-oX",
            "-",
            *targets,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "Nmap port taramasi basarisiz.").strip())
    devices = []
    for host in ET.fromstring(result.stdout).findall("host"):
        addresses = {item.get("addrtype"): item for item in host.findall("address")}
        ipv4 = addresses.get("ipv4")
        if ipv4 is None:
            continue
        open_ports = []
        for port_node in host.findall("ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port_node.find("service")
            try:
                port_number = int(port_node.get("portid"))
            except (TypeError, ValueError):
                continue
            open_ports.append({
                "port": port_number,
                "protocol": port_node.get("protocol") or "tcp",
                "service": service.get("name", "") if service is not None else "",
                "source": "nmap-port",
            })
        if open_ports:
            devices.append({
                "ip_address": ipv4.get("addr"),
                "mac_address": None,
                "hostname": None,
                "vendor": "Bilinmiyor",
                "open_ports": open_ports,
            })
    return devices, "nmap-port"


def _socket_target_hosts(targets):
    hosts = []
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            hosts.append(str(target))
            continue
        if not _is_allowed_network(network):
            continue
        hosts.extend(str(host) for host in network.hosts())
    return hosts


def _scan_with_socket_ports(targets):
    hosts = _socket_target_hosts(targets)
    if not hosts:
        raise RuntimeError("Socket fallback icin hedef host bulunamadi.")
    devices = []
    for host in hosts:
        open_ports = []
        for port in PORT_SCAN_PORTS:
            try:
                with socket.create_connection((host, int(port)), timeout=0.25):
                    open_ports.append({
                        "port": int(port),
                        "protocol": "tcp",
                        "service": "",
                        "source": "socket-fallback",
                    })
            except OSError:
                continue
        if open_ports:
            devices.append({
                "ip_address": host,
                "mac_address": None,
                "hostname": None,
                "vendor": "Bilinmiyor",
                "open_ports": open_ports,
            })
    return devices, "socket-fallback"


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


def _normalize_mac(value):
    if not value:
        return ""
    return str(value).strip().replace("-", ":").lower()


def _scan_system_arp_table():
    executable = shutil.which("arp")
    if not executable:
        raise RuntimeError("ARP komutu bulunamadi.")
    result = subprocess.run([executable, "-a"], capture_output=True, text=True, timeout=5, check=False)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "Sistem ARP tablosu okunamadi.").strip())
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    mac_pattern = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
    devices = []
    for line in result.stdout.splitlines():
        ip_match = ip_pattern.search(line)
        mac_match = mac_pattern.search(line)
        if not ip_match or not mac_match:
            continue
        mac_address = _normalize_mac(mac_match.group(0))
        if mac_address in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
            continue
        devices.append({
            "ip_address": ip_match.group(0),
            "mac_address": mac_address,
            "hostname": None,
            "vendor": "Bilinmiyor",
        })
    return devices, "system-arp"


def _merge_open_ports(existing, incoming):
    seen = {(item.get("port"), item.get("protocol", "tcp")) for item in existing}
    for item in incoming or []:
        key = (item.get("port"), item.get("protocol", "tcp"))
        if item.get("port") and key not in seen:
            existing.append(item)
            seen.add(key)


def _merge_discovered_records(collections):
    records = {}
    for devices, method in collections:
        for data in devices:
            ip_address = data.get("ip_address")
            if not ip_address:
                continue
            record = records.setdefault(ip_address, {
                "ip_address": ip_address,
                "mac_address": None,
                "hostname": None,
                "vendor": "Bilinmiyor",
                "open_ports": [],
                "sources": [],
            })
            mac_address = _normalize_mac(data.get("mac_address"))
            if mac_address:
                record["mac_address"] = mac_address
            if data.get("hostname") and not record.get("hostname"):
                record["hostname"] = data["hostname"]
            vendor = data.get("vendor")
            if vendor and (not record.get("vendor") or record["vendor"] == "Bilinmiyor"):
                record["vendor"] = vendor
            _merge_open_ports(record["open_ports"], data.get("open_ports"))
            if method not in record["sources"]:
                record["sources"].append(method)
    return list(records.values())


def _enrich_with_previous_records(network, discovered):
    previous = {}
    for device in Device.objects.all():
        try:
            if ipaddress.ip_address(device.ip_address) in network:
                previous[device.ip_address] = device
        except ValueError:
            continue
    for data in discovered:
        device = previous.get(data["ip_address"])
        if not device:
            continue
        if not data.get("mac_address") and device.mac_address:
            data["previous_mac_address"] = device.mac_address
            data["mac_address"] = device.mac_address
            data["identity_from_previous"] = True
        if not data.get("hostname") and device.hostname:
            data["hostname"] = device.hostname
        if (not data.get("vendor") or data["vendor"] == "Bilinmiyor") and device.vendor:
            data["vendor"] = device.vendor
        if "previous-record" not in data["sources"]:
            data["sources"].append("previous-record")
    return discovered


def _new_device_message(device, partial):
    missing = (
        " Cihaz ping'e cevap vermediği, güvenlik duvarı kullandığı veya aynı ağ katmanında olmadığı için "
        "MAC/vendor bilgisi alınamamış olabilir."
        if partial else ""
    )
    return (
        "Ağda daha önce görülmeyen yeni bir cihaz tespit edildi. Bu cihaz size ait olabilir; "
        "ancak tanınmayan cihazlar ağ güvenliği açısından kontrol edilmelidir."
        f"{missing}"
    )


def _record_open_ports(device, open_ports):
    recorded = 0
    for item in open_ports or []:
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        protocol = str(item.get("protocol") or "tcp").lower()
        OpenPort.objects.update_or_create(
            device=device,
            port=port,
            protocol=protocol,
            defaults={
                "service_name": item.get("service") or "",
                "source": item.get("source") or "network-scan",
            },
        )
        recorded += 1
    return recorded


def _record_devices(network, discovered):
    active_ips = []
    new_count = 0
    open_port_count = 0
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
        current_mac = _normalize_mac(data.get("mac_address"))
        current_vendor = data.get("vendor") or ""
        has_current_identity = (
            bool(current_mac)
            and bool(current_vendor and current_vendor != "Bilinmiyor")
            and not data.get("identity_from_previous")
        )
        partial = not has_current_identity
        mac_address = current_mac or (previous.mac_address if previous else None)
        hostname = data.get("hostname") if data.get("hostname") is not None else (previous.hostname if previous else None)
        vendor = current_vendor if current_vendor and current_vendor != "Bilinmiyor" else (previous.vendor if previous and previous.vendor else "Bilinmiyor")
        device, created = Device.objects.update_or_create(
            ip_address=ip_address,
            defaults={"mac_address": mac_address, "hostname": hostname, "vendor": vendor,
                      "status": "partial" if partial else "online"},
        )
        if current_mac:
            ArpObservation.objects.create(
                ip_address=ip_address,
                mac_address=current_mac,
                source="+".join(data.get("sources") or ["ARP gözlemi"])[:80],
            )
        open_port_count += _record_open_ports(device, data.get("open_ports"))
        if created:
            new_count += 1
        elif old_mac and current_mac and old_mac.lower() != current_mac.lower():
            SecurityEvent.objects.create(event_type="arp_anomaly", title="IP/MAC eslesmesi degisti",
                                         description=f"{ip_address}: {old_mac} -> {current_mac}", level="danger",
                                         source_ip=ip_address, source_mac=current_mac, risk_score=80)
    for device in Device.objects.exclude(ip_address__in=active_ips):
        try:
            if ipaddress.ip_address(device.ip_address) in network:
                device.status = "offline"
                device.save(update_fields=["status"])
        except ValueError:
            continue
    return new_count, len(active_ips), open_port_count


def scan_network(force_demo=False, limit=None):
    """Discover hosts on an explicitly bounded private LAN with safe, limited checks."""
    if force_demo or get_value("guardiannet_mode", settings.GUARDIANNET_MODE) == "demo":
        scan = NetworkScan.objects.create(
            network_range="real-scan-disabled",
            status="failed",
            scan_method="disabled",
            devices_found=0,
            is_mock=False,
            message="Demo/simülasyon veri üretimi devre dışı. Gerçek tarama için real modu kullanın.",
            completed_at=timezone.now(),
        )
        return {
            "success": False,
            "is_mock": False,
            "found_devices": 0,
            "new_devices": 0,
            "open_ports": 0,
            "scan_id": scan.pk,
            "message": scan.message,
            "error": scan.message,
        }

    scan = NetworkScan.objects.create(network_range="algilaniyor", status="failed", is_mock=False)
    try:
        if not get_bool("enable_real_scan", settings.ENABLE_REAL_SCAN):
            raise RuntimeError("ENABLE_REAL_SCAN kapali.")
        network = resolve_target_subnet()
        targets = _scan_targets(network, limit)
        scan.network_range = str(network)
        errors = []
        discovery_sets = []
        scanners = [_scan_with_nmap, _scan_with_nmap_ports, _scan_with_scapy, lambda ignored: _scan_system_arp_table()]
        for scanner in scanners:
            try:
                found, method = scanner(targets)
                discovery_sets.append((found, method))
            except Exception as scan_error:
                errors.append(str(scan_error))
                if scanner == _scan_with_nmap_ports:
                    try:
                        found, method = _scan_with_socket_ports(targets)
                        discovery_sets.append((found, method))
                    except Exception as socket_error:
                        errors.append(str(socket_error))
        discovered = _merge_discovered_records(discovery_sets)
        discovered = _enrich_with_previous_records(network, discovered)
        method = "+".join(method for _, method in discovery_sets) or "none"
        if not discovered and errors and not discovery_sets:
            raise RuntimeError("; ".join(errors))
        new_count, found_count, open_port_count = _record_devices(network, discovered)
        scan.status = "completed"
        scan.scan_method = method
        scan.devices_found = found_count
        scan.message = "Yerel cihaz kesfi tamamlandi."
        scan.notes = "; ".join(errors)
        scan.completed_at = timezone.now()
        scan.save()
        return {"success": True, "is_mock": False, "found_devices": found_count, "new_devices": new_count,
                "open_ports": open_port_count, "scan_id": scan.pk, "network": str(network), "method": method,
                "message": scan.message}
    except Exception as exc:
        scan.status = "failed"
        scan.is_mock = False
        scan.scan_method = "real-failed"
        scan.message = "Gercek kesif basarisiz; guvenlik verisi uretilmedi."
        scan.notes = str(exc)
        scan.completed_at = timezone.now()
        scan.save()
        return {"success": False, "is_mock": False, "found_devices": 0, "new_devices": 0,
                "open_ports": 0, "scan_id": scan.pk, "message": scan.message, "error": str(exc)}
