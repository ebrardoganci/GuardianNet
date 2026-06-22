from django.contrib import admin
from .models import Device, Alert, SecurityEvent


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = (
        "ip_address",
        "mac_address",
        "hostname",
        "status",
        "risk_score",
        "first_seen",
        "last_seen",
    )

    list_filter = (
        "status",
        "first_seen",
        "last_seen",
    )

    search_fields = (
        "ip_address",
        "mac_address",
        "hostname",
    )


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "alert_type",
        "severity",
        "device",
        "is_resolved",
        "created_at",
    )

    list_filter = (
        "alert_type",
        "severity",
        "is_resolved",
        "created_at",
    )

    search_fields = (
        "title",
        "message",
    )


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "level",
        "created_at",
    )

    list_filter = (
        "level",
        "created_at",
    )

    search_fields = (
        "title",
        "description",
    )