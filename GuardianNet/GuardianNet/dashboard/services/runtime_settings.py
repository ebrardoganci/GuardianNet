from django.conf import settings

from dashboard.models import SystemSetting


def get_value(key, default=None):
    normalized = key.lower()
    if normalized == "guardiannet_mode" and getattr(settings, "GUARDIANNET_MODE_ENV", None):
        return settings.GUARDIANNET_MODE
    if normalized == "local_subnet" and getattr(settings, "LOCAL_SUBNET_ENV", None):
        return settings.LOCAL_SUBNET
    row = SystemSetting.objects.filter(key=normalized).first()
    return row.value if row else getattr(settings, key.upper(), default)


def get_bool(key, default=False):
    value = get_value(key, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
