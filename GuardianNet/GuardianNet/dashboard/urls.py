from django.urls import path

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.index, name="index"), path("devices/", views.devices, name="devices"),
    path("devices/<int:pk>/", views.device_detail, name="device_detail"),
    path("alerts/", views.alerts, name="alerts"), path("alerts/<int:pk>/status/", views.update_alert_status, name="update_alert_status"),
    path("events/", views.security_events, name="events"),
    path("reports/", views.reports, name="reports"), path("honeypot/", views.honeypot, name="honeypot"),
    path("settings/", views.settings_view, name="settings"), path("scan/", views.scan_network_view, name="scan_network"),
    path("monitoring-cycle/", views.run_monitoring_cycle_view, name="run_monitoring_cycle"),
]
