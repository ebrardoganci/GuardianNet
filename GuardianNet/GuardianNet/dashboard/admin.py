from django.contrib import admin

from .models import Alert, ArpObservation, Device, HoneypotEvent, MonitoringCycleRun, NetworkScan, OpenPort, RiskSnapshot, SecurityEvent, SystemSetting


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "mac_address", "hostname", "vendor", "status", "is_trusted", "risk_score", "last_seen")
    list_filter = ("status", "is_trusted", "vendor")
    search_fields = ("ip_address", "mac_address", "hostname", "vendor")


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("title", "alert_type", "severity", "status", "source_ip", "device", "created_at", "updated_at")
    list_filter = ("alert_type", "severity", "status", "created_at", "updated_at")
    search_fields = ("title", "message", "source_ip", "source_mac")


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ("title", "event_type", "source_ip", "destination_ip", "destination_port", "protocol", "risk_score", "created_at")
    list_filter = ("event_type", "level", "protocol", "created_at")
    search_fields = ("title", "description", "source_ip", "source_mac", "destination_ip")


@admin.register(OpenPort)
class OpenPortAdmin(admin.ModelAdmin):
    list_display = ("device", "port", "protocol", "service_name", "source", "first_seen", "last_seen")
    list_filter = ("protocol", "service_name", "source", "last_seen")
    search_fields = ("device__ip_address", "service_name", "source")


@admin.register(NetworkScan)
class NetworkScanAdmin(admin.ModelAdmin):
    list_display = ("network_range", "status", "scan_method", "devices_found", "is_mock", "started_at", "completed_at")
    list_filter = ("status", "scan_method", "is_mock", "started_at")
    search_fields = ("network_range", "message", "notes")


@admin.register(HoneypotEvent)
class HoneypotEventAdmin(admin.ModelAdmin):
    list_display = ("source_ip", "source_port", "service", "destination_port", "event_type", "source_type", "login_success", "is_mock", "created_at")
    list_filter = ("service", "event_type", "source_type", "login_success", "is_mock", "created_at")
    search_fields = ("event_id", "source_ip", "username", "command")


@admin.register(ArpObservation)
class ArpObservationAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "mac_address", "source", "is_gateway", "observed_at")
    list_filter = ("source", "is_gateway", "observed_at")
    search_fields = ("ip_address", "mac_address", "source")


@admin.register(SystemSetting)
class SystemSettingAdmin(admin.ModelAdmin):
    list_display = ("key", "value", "description", "updated_at")
    search_fields = ("key", "value", "description")


@admin.register(RiskSnapshot)
class RiskSnapshotAdmin(admin.ModelAdmin):
    list_display = ("risk_level", "risk_score", "security_score", "active_alerts", "recorded_at")
    list_filter = ("risk_level", "recorded_at")
    search_fields = ("risk_level",)


@admin.register(MonitoringCycleRun)
class MonitoringCycleRunAdmin(admin.ModelAdmin):
    list_display = ("started_at", "completed_at", "status", "scan_status", "honeypot_status", "analysis_status", "risk_score")
    list_filter = ("status", "scan_status", "honeypot_status", "analysis_status", "started_at")
    search_fields = ("error_summary",)
