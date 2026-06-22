from django.contrib import admin
from django.urls import include, path

from accounts import views as account_views
from dashboard import views as dashboard_views

urlpatterns = [
    path("admin/", admin.site.urls), path("login/", account_views.login_view, name="login"),
    path("logout/", account_views.logout_view, name="logout"), path("accounts/", include("accounts.urls")),
    path("dashboard/", include("dashboard.urls")), path("devices/", dashboard_views.devices, name="devices"),
    path("alerts/", dashboard_views.alerts, name="alerts"), path("events/", dashboard_views.security_events, name="events"),
    path("reports/", dashboard_views.reports, name="reports"), path("honeypot/", dashboard_views.honeypot, name="honeypot"),
    path("settings/", dashboard_views.settings_view, name="settings"), path("", dashboard_views.index, name="home"),
]
