"""Dashboard URL routes."""

from django.urls import path

from web.dashboard import views

urlpatterns = [
    path("", views.index, name="dashboard-index"),
    path("scan/", views.scan_trigger, name="dashboard-scan"),
    path("incident/<str:incident_id>/", views.incident_detail, name="dashboard-incident"),
]
