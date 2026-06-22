from django.urls import path
from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.index, name="index"),
    path("scan/", views.scan_network_view, name="scan_network"),
]