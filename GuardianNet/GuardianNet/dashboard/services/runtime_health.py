import os
import platform
import shutil
import subprocess

from django.conf import settings
from django.utils import timezone

from dashboard.models import MonitoringCycleRun, NetworkScan, RiskSnapshot
from dashboard.services.honeypot_manager import get_log_path
from dashboard.services.network_scanner import resolve_target_subnet
from dashboard.services.runtime_settings import get_bool, get_value


HEALTH_STATUSES = ("ok", "warning", "error", "unknown")


def _check(key, label, status, value="", message="", hint=""):
    if status not in HEALTH_STATUSES:
        status = "unknown"
    return {
        "key": key,
        "label": label,
        "status": status,
        "value": "" if value is None else str(value),
        "message": message,
        "hint": hint,
    }


def _enabled_label(value):
    return "aktif" if value else "kapali"


def _format_dt(value):
    if not value:
        return ""
    return timezone.localtime(value).strftime("%Y-%m-%d %H:%M:%S")


def _run_command(command, timeout=5):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return exc


def _nmap_checks():
    executable = shutil.which("nmap")
    if not executable:
        return [
            _check(
                "nmap_path",
                "Nmap",
                "warning",
                "bulunamadi",
                "Nmap bulunamadı, socket fallback aktif.",
                "Nmap kurulu değilse GuardianNet sınırlı port listesi için güvenli socket fallback kullanır.",
            ),
            _check(
                "nmap_version",
                "Nmap versiyonu",
                "unknown",
                "",
                "Nmap bulunmadigi icin versiyon okunamadi.",
                "Nmap kurulduktan sonra yeni terminalde nmap --version ile dogrulayin.",
            ),
        ]

    result = _run_command([executable, "--version"])
    if isinstance(result, Exception):
        version_check = _check(
            "nmap_version",
            "Nmap versiyonu",
            "warning",
            "",
            f"Nmap versiyonu okunamadi: {result}",
            "Nmap kurulumu veya PATH yetkilerini kontrol edin.",
        )
    else:
        output = (result.stdout or result.stderr or "").strip()
        first_line = output.splitlines()[0] if output else ""
        version_check = _check(
            "nmap_version",
            "Nmap versiyonu",
            "ok" if result.returncode == 0 and first_line else "warning",
            first_line,
            "Nmap versiyonu okunabiliyor." if result.returncode == 0 and first_line else "Nmap calisti ama versiyon bilgisi beklenen sekilde okunamadi.",
            "" if result.returncode == 0 and first_line else "nmap --version komutunu terminalde manuel dogrulayin.",
        )

    return [
        _check("nmap_path", "Nmap", "ok", executable, "Nmap bulundu.", ""),
        version_check,
    ]


def _scapy_check():
    try:
        import scapy.all  # noqa: F401
    except Exception as exc:
        return _check(
            "scapy_import",
            "Scapy",
            "warning",
            "import edilemedi",
            f"Scapy import edilemedi: {exc}",
            "Nmap yoksa ARP discovery icin scapy ve gerekli sistem izinleri gerekir.",
        )
    return _check("scapy_import", "Scapy", "ok", "import edildi", "Scapy aktif.", "")


def _socket_fallback_check():
    if shutil.which("nmap"):
        return _check(
            "socket_fallback",
            "Socket fallback",
            "ok",
            "hazir",
            "Nmap bulundu; socket fallback yedek olarak hazır.",
            "",
        )
    return _check(
        "socket_fallback",
        "Socket fallback",
        "ok",
        "aktif",
        "Nmap bulunamadı, socket fallback aktif.",
        "Fallback yalnızca izinli LOCAL_SUBNET içinde sınırlı port listesini kısa timeout ile dener.",
    )


def _arp_table_check():
    executable = shutil.which("arp")
    if not executable:
        return _check(
            "arp_table",
            "ARP tablo okuma",
            "warning",
            "bulunamadi",
            "ARP komutu bulunamadı.",
            "Sistem ARP tablosu fallback kaynağı olarak kullanılamaz.",
        )
    return _check(
        "arp_table",
        "ARP tablo okuma",
        "ok",
        executable,
        "ARP fallback aktif.",
        "",
    )


def _npcap_check():
    if platform.system().lower() != "windows":
        return _check(
            "npcap_service",
            "Npcap servisi",
            "unknown",
            platform.system() or "bilinmiyor",
            "Windows disi sistemde Npcap kontrolu uygulanmaz.",
            "",
        )

    powershell = shutil.which("powershell") or shutil.which("powershell.exe") or shutil.which("pwsh")
    if not powershell:
        return _check(
            "npcap_service",
            "Npcap servisi",
            "warning",
            "kontrol edilemedi",
            "PowerShell bulunamadigi icin Npcap servisi kontrol edilemedi.",
            "Npcap kurulumunu ve servis durumunu Windows Services uzerinden kontrol edin.",
        )

    script = "Get-Service -Name npcap -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status"
    result = _run_command([powershell, "-NoProfile", "-Command", script])
    if isinstance(result, Exception):
        return _check(
            "npcap_service",
            "Npcap servisi",
            "warning",
            "kontrol edilemedi",
            f"Npcap servisi kontrol edilemedi: {result}",
            "Npcap servisini Windows Services uzerinden kontrol edin.",
        )
    status = (result.stdout or "").strip()
    if status.lower() == "running":
        return _check("npcap_service", "Npcap servisi", "ok", status, "Npcap servisi calisiyor.", "")
    if status:
        return _check(
            "npcap_service",
            "Npcap servisi",
            "warning",
            status,
            "Npcap servisi calisiyor gorunmuyor.",
            "Npcap servisini kontrol edin.",
        )
    return _check(
        "npcap_service",
        "Npcap servisi",
        "warning",
        "bulunamadi",
        "Npcap servisi bulunamadi.",
        "Windows'ta Nmap/Scapy ARP kesfi icin Npcap kurulu ve calisir durumda olmali.",
    )


def _opencanary_checks():
    configured = get_value("opencanary_log_path", settings.OPENCANARY_LOG_PATH)
    path = get_log_path()
    parent = path.parent
    checks = [
        _check(
            "opencanary_log_path",
            "OpenCanary log yolu",
            "ok" if configured else "warning",
            str(path),
            "OpenCanary log yolu ayarlandi." if configured else "OpenCanary log yolu bos.",
            "" if configured else "OPENCANARY_LOG_PATH degerini .env veya Ayarlar sayfasindan tanimlayin.",
        )
    ]
    if path.is_file():
        checks.append(_check("opencanary_log_file", "OpenCanary log dosyasi", "ok", str(path), "Log dosyasi bulundu.", ""))
    else:
        checks.append(
            _check(
                "opencanary_log_file",
                "OpenCanary log dosyasi",
                "warning",
                str(path),
                "OpenCanary log dosyasi bulunamadi.",
                "Bu hata degil; henuz honeypot logu yok veya OPENCANARY_LOG_PATH farkli bir dosyayi gosteriyor.",
            )
        )

    if parent.exists() and parent.is_dir():
        writable = os.access(parent, os.W_OK)
        checks.append(
            _check(
                "logs_directory",
                "Logs klasoru",
                "ok" if writable else "warning",
                str(parent),
                "Logs klasoru var ve yazilabilir." if writable else "Logs klasoru var ama yazilabilir gorunmuyor.",
                "" if writable else "OpenCanary'nin bu klasore yazma izni oldugunu kontrol edin.",
            )
        )
    else:
        checks.append(
            _check(
                "logs_directory",
                "Logs klasoru",
                "warning",
                str(parent),
                "Logs klasoru bulunamadi.",
                "OpenCanary baslatilmadan once log klasorunu olusturun veya OPENCANARY_LOG_PATH degerini guncelleyin.",
            )
        )
    return checks


def _latest_checks(mode):
    scan_qs = NetworkScan.objects.all()
    if mode == "real":
        scan_qs = scan_qs.filter(is_mock=False)
    latest_scan = scan_qs.first()
    latest_cycle = MonitoringCycleRun.objects.first()
    latest_risk = RiskSnapshot.objects.first()
    return [
        _check(
            "latest_network_scan",
            "Son NetworkScan",
            "ok" if latest_scan else "warning",
            _format_dt(latest_scan.started_at) if latest_scan else "",
            f"{latest_scan.get_status_display()} - {latest_scan.devices_found} cihaz" if latest_scan else "Henuz gercek network scan kaydi yok.",
            "" if latest_scan else "python manage.py run_monitoring_cycle veya run_network_scan calistirin.",
        ),
        _check(
            "latest_monitoring_cycle",
            "Son MonitoringCycleRun",
            "ok" if latest_cycle else "warning",
            _format_dt(latest_cycle.started_at) if latest_cycle else "",
            latest_cycle.get_status_display() if latest_cycle else "Henuz monitoring cycle kaydi yok.",
            "" if latest_cycle else "python manage.py run_monitoring_cycle calistirin.",
        ),
        _check(
            "latest_risk_snapshot",
            "Son RiskSnapshot",
            "ok" if latest_risk else "warning",
            _format_dt(latest_risk.recorded_at) if latest_risk else "",
            f"Risk={latest_risk.risk_score}, guvenlik={latest_risk.security_score}" if latest_risk else "Henuz risk snapshot kaydi yok.",
            "" if latest_risk else "python manage.py analyze_security veya run_monitoring_cycle calistirin.",
        ),
    ]


def get_runtime_health():
    mode = str(get_value("guardiannet_mode", "real")).strip().lower()
    configured_subnet = str(get_value("local_subnet", settings.LOCAL_SUBNET) or "").strip()
    enable_real_scan = get_bool("enable_real_scan", settings.ENABLE_REAL_SCAN)
    enable_honeypot_logs = get_bool("enable_honeypot_logs", settings.ENABLE_HONEYPOT_LOGS)

    checks = [
        _check(
            "guardiannet_mode",
            "GUARDIANNET_MODE",
            "ok" if mode == "real" else "warning",
            mode or "bos",
            "GuardianNet real modda calisiyor." if mode == "real" else "GuardianNet real modda degil.",
            "" if mode == "real" else "Gercek sistem izleme icin GUARDIANNET_MODE=real kullanin.",
        ),
        _check(
            "local_subnet",
            "LOCAL_SUBNET",
            "ok" if configured_subnet else "warning",
            configured_subnet or "otomatik",
            "LOCAL_SUBNET ayari kullanilacak." if configured_subnet else "LOCAL_SUBNET bos; otomatik algilama kullanilacak.",
            "" if configured_subnet else "Kararli real kullanim icin izinli yerel subnet'i .env icinde tanimlayin.",
        ),
    ]

    try:
        checks.append(
            _check(
                "resolved_subnet",
                "Kullanilan subnet",
                "ok",
                resolve_target_subnet(),
                "Subnet basariyla cozuldu.",
                "",
            )
        )
    except Exception as exc:
        checks.append(
            _check(
                "resolved_subnet",
                "Kullanilan subnet",
                "error",
                "",
                f"Subnet cozumlenemedi: {exc}",
                "LOCAL_SUBNET degerini izinli ozel CIDR olarak ayarlayin veya aktif gateway'i olan adapter'i kontrol edin.",
            )
        )

    checks.extend(
        [
            _check(
                "enable_real_scan",
                "ENABLE_REAL_SCAN",
                "ok" if enable_real_scan else "warning",
                _enabled_label(enable_real_scan),
                "Gercek ag kesfi etkin." if enable_real_scan else "Gercek ag kesfi kapali.",
                "" if enable_real_scan else "Real tarama istiyorsaniz ENABLE_REAL_SCAN=True yapin.",
            ),
            _check(
                "enable_honeypot_logs",
                "ENABLE_HONEYPOT_LOGS",
                "ok" if enable_honeypot_logs else "warning",
                _enabled_label(enable_honeypot_logs),
                "Honeypot log aktarimi etkin." if enable_honeypot_logs else "Honeypot log aktarimi kapali.",
                "" if enable_honeypot_logs else "OpenCanary loglarini izlemek icin ENABLE_HONEYPOT_LOGS=True yapin.",
            ),
        ]
    )
    checks.extend(_nmap_checks())
    checks.append(_scapy_check())
    checks.append(_socket_fallback_check())
    checks.append(_arp_table_check())
    checks.append(_npcap_check())
    checks.extend(_opencanary_checks())
    checks.extend(_latest_checks(mode))
    return checks


def summarize_health(checks):
    summary = {status: 0 for status in HEALTH_STATUSES}
    for check in checks:
        status = check.get("status", "unknown")
        summary[status if status in summary else "unknown"] += 1
    return summary
