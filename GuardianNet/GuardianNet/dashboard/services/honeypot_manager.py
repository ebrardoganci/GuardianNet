import shutil


def get_honeypot_status():
    available = shutil.which("opencanaryd") is not None
    return {
        "mode": "opencanary" if available else "demo",
        "label": "OpenCanary hazir" if available else "Demo/Mock",
        "services": {"ssh": "izleniyor", "http": "izleniyor", "ftp": "izleniyor"},
        "available": available,
    }
