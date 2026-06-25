from collections import OrderedDict

from dashboard.models import Alert, ArpObservation, Device, HoneypotEvent, MonitoringCycleRun, NetworkScan, OpenPort, RiskSnapshot, SecurityEvent


CLEAR_TARGETS = OrderedDict(
    [
        ("alerts", ("Tüm uyarılar", [Alert])),
        ("events", ("Güvenlik olayları", [SecurityEvent])),
        ("honeypot", ("Honeypot kayıtları", [HoneypotEvent])),
        ("risk", ("Risk geçmişi", [RiskSnapshot])),
        ("devices", ("Cihaz kayıtları", [OpenPort, Device])),
        (
            "all",
            (
                "Tüm güvenlik verileri",
                [Alert, SecurityEvent, HoneypotEvent, ArpObservation, RiskSnapshot, MonitoringCycleRun, NetworkScan, OpenPort, Device],
            ),
        ),
    ]
)


def clear_security_data(target):
    if target not in CLEAR_TARGETS:
        raise ValueError("Geçersiz veri temizleme hedefi.")
    _, models = CLEAR_TARGETS[target]
    deleted = OrderedDict()
    total = 0
    for model in models:
        count, _ = model.objects.all().delete()
        deleted[model.__name__] = count
        total += count
    return {"target": target, "label": CLEAR_TARGETS[target][0], "deleted": deleted, "total": total}
