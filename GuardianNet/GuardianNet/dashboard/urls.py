from django.urls import path

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.index, name="index"), path("devices/", views.devices, name="devices"),
    path("alerts/", views.alerts, name="alerts"), path("events/", views.security_events, name="events"),
    path("reports/", views.reports, name="reports"), path("honeypot/", views.honeypot, name="honeypot"),
    path("settings/", views.settings_view, name="settings"), path("scan/", views.scan_network_view, name="scan_network"),
]
