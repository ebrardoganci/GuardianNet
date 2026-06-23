import ipaddress

from django.db.models import Q

from dashboard.models import Alert, Device, HoneypotEvent, NetworkScan, RiskSnapshot, SecurityEvent, SystemSetting
from dashboard.services.network_scanner import resolve_target_subnet
from dashboard.services.runtime_settings import get_value


DEMO_TEST_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
LOCAL_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
DEMO_TEXT_MARKERS = ("demo", "fallback", "fake", "mock")
LOCAL_ALERT_TYPES = ("new_device", "arp_spoof", "arp_anomaly", "port_scan", "brute_force", "suspicious_traffic")


def is_real_mode():
    return str(get_value("guardiannet_mode", "real")).strip().lower() == "real"


def ip_in_networks(value, networks):
    if not value:
        return False
    try:
        ip_address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return any(ip_address in network for network in networks)


def _parse_ip(value):
    if not value:
        return None
    try:
        return ipaddress.ip_address(str(value))
    except ValueError:
        return None


def _pks_with_ip_in_networks(queryset, field_names, networks):
    pks = []
    for item in queryset.only("pk", *field_names):
        if any(ip_in_networks(getattr(item, field), networks) for field in field_names):
            pks.append(item.pk)
    return pks


def filter_ip_fields_in_networks(queryset, field_names, networks):
    pks = _pks_with_ip_in_networks(queryset, field_names, networks)
    return queryset.filter(pk__in=pks)


def exclude_ip_fields_in_networks(queryset, field_names, networks):
    pks = _pks_with_ip_in_networks(queryset, field_names, networks)
    return queryset.exclude(pk__in=pks)


def _ip_is_local_private(ip_address):
    return any(ip_address in network for network in LOCAL_PRIVATE_NETWORKS)


def _ip_in_subnet(ip_address, subnet):
    return subnet is not None and ip_address is not None and ip_address in subnet


def _pks_with_invalid_real_scope_ips(queryset, field_names, subnet=None):
    subnet = subnet if subnet is not None else get_current_subnet()
    pks = []
    for item in queryset.only("pk", *field_names):
        for field in field_names:
            ip_address = _parse_ip(getattr(item, field))
            if not ip_address:
                continue
            if any(ip_address in network for network in DEMO_TEST_NETWORKS):
                pks.append(item.pk)
                break
            if _ip_is_local_private(ip_address) and (subnet is None or ip_address not in subnet):
                pks.append(item.pk)
                break
    return pks


def _ip_is_valid_real_source(ip_address, subnet):
    if any(ip_address in network for network in DEMO_TEST_NETWORKS):
        return False
    if _ip_is_local_private(ip_address):
        return subnet is not None and ip_address in subnet
    return True


def _pks_with_invalid_real_alert_scope(queryset, subnet=None):
    subnet = subnet if subnet is not None else get_current_subnet()
    pks = []
    for alert in queryset.select_related("device").only("pk", "alert_type", "source_ip", "device_id", "device__ip_address"):
        source_ip = _parse_ip(alert.source_ip)
        device_ip = _parse_ip(alert.device.ip_address) if alert.device_id else None
        if source_ip:
            if not _ip_is_valid_real_source(source_ip, subnet):
                pks.append(alert.pk)
                continue
            if alert.alert_type in LOCAL_ALERT_TYPES and not (_ip_in_subnet(source_ip, subnet) or _ip_in_subnet(device_ip, subnet)):
                pks.append(alert.pk)
                continue
            continue

        if device_ip:
            if not _ip_is_valid_real_source(device_ip, subnet):
                pks.append(alert.pk)
            continue

        if alert.alert_type in LOCAL_ALERT_TYPES:
            pks.append(alert.pk)
    return pks


def exclude_invalid_real_alert_scope(queryset, subnet=None):
    pks = _pks_with_invalid_real_alert_scope(queryset, subnet)
    return queryset.exclude(pk__in=pks)


def exclude_invalid_real_scope_ips(queryset, field_names, subnet=None):
    pks = _pks_with_invalid_real_scope_ips(queryset, field_names, subnet)
    return queryset.exclude(pk__in=pks)


def demo_text_q(*field_names):
    query = Q()
    for field in field_names:
        for marker in DEMO_TEXT_MARKERS:
            query |= Q(**{f"{field}__icontains": marker})
    return query


def get_current_subnet():
    try:
        return resolve_target_subnet()
    except Exception:
        return None


def devices_for_subnet(queryset=None, subnet=None):
    queryset = queryset if queryset is not None else Device.objects.all()
    subnet = subnet if subnet is not None else get_current_subnet()
    if subnet is None:
        return queryset.none()
    return filter_ip_fields_in_networks(queryset, ("ip_address",), (subnet,))


def real_devices(queryset=None):
    queryset = queryset if queryset is not None else Device.objects.all()
    return devices_for_subnet(queryset)


def real_alerts(queryset=None):
    queryset = queryset if queryset is not None else Alert.objects.all()
    queryset = queryset.exclude(alert_type="system").exclude(demo_text_q("alert_type", "title", "message"))
    return exclude_invalid_real_alert_scope(queryset)


def real_security_events(queryset=None):
    queryset = queryset if queryset is not None else SecurityEvent.objects.all()
    queryset = queryset.exclude(event_type="system").exclude(demo_text_q("event_type", "title", "description"))
    return exclude_invalid_real_scope_ips(queryset, ("source_ip", "destination_ip"))


def real_honeypot_events(queryset=None):
    queryset = queryset if queryset is not None else HoneypotEvent.objects.all()
    queryset = queryset.filter(is_mock=False).exclude(demo_text_q("event_id", "service", "username", "command"))
    return exclude_ip_fields_in_networks(queryset, ("source_ip",), DEMO_TEST_NETWORKS)


def demo_risk_snapshot_ids():
    ids = []
    for key in SystemSetting.objects.filter(key__startswith="demo-risk-").values_list("key", flat=True):
        try:
            ids.append(1000 + int(key.rsplit("-", 1)[1]))
        except (IndexError, ValueError):
            continue
    return ids


def real_risk_snapshots(queryset=None):
    queryset = queryset if queryset is not None else RiskSnapshot.objects.all()
    first_real_scan = NetworkScan.objects.filter(is_mock=False, status="completed").order_by("started_at").first()
    if not first_real_scan:
        return queryset.none()
    queryset = queryset.filter(recorded_at__gte=first_real_scan.started_at)
    ids = demo_risk_snapshot_ids()
    return queryset.exclude(pk__in=ids) if ids else queryset
