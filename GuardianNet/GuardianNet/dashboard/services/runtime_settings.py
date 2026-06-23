from django.conf import settings

from dashboard.models import SystemSetting


def get_value(key, default=None):
    row = SystemSetting.objects.filter(key=key.lower()).first()
    return row.value if row else getattr(settings, key.upper(), default)


def get_bool(key, default=False):
    value = get_value(key, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
