"""Dashboard views — server-rendered UI (Django templates)."""

from __future__ import annotations

from django.http import HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse

from infra.persistence.incident_store import store

from workers.pipeline import run_pipeline


def index(request):
    """List incidents from the shared store."""
    incidents = store.list_incidents()
    return render(
        request,
        "dashboard/index.html",
        {"incidents": incidents, "stats": store.stats(), "empty": not incidents},
    )


def incident_detail(request, incident_id: str):
    """Show a single incident with alerts, IoCs and playbook."""
    incident = store.get_incident(incident_id)
    if incident is None:
        return render(request, "dashboard/not_found.html", {"incident_id": incident_id}, status=404)
    return render(request, "dashboard/incident_detail.html", {"incident": incident})


def scan_trigger(request) -> HttpResponseRedirect:
    """Run the demo pipeline and redirect back to the dashboard."""
    if request.method == "POST":
        run_pipeline()
    return redirect(reverse("dashboard-index"))
