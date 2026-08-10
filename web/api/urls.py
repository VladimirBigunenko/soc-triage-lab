"""Ninja API for soc-triage-lab.

Delivery layer (hexagonal): exposes the domain through REST endpoints.
Phase 6 — alerts, incidents, stats, and a POST /scan trigger.
"""

from __future__ import annotations

from ninja import NinjaAPI
from ninja.errors import HttpError

from core.entities.alert import Alert
from core.entities.incident import Incident
from infra.persistence.incident_store import store
from web.schemas import AlertOut, IncidentDetailOut, IncidentOut, StatsOut

from workers.pipeline import run_pipeline

api = NinjaAPI(
    title="SOC Triage Lab API",
    version="0.2.0",
    description="Working SOC laboratory — collect, detect, correlate, respond, visualize.",
)


# --- domain -> schema converters -------------------------------------------
def _ioc_out(ioc) -> dict:
    return {"type": ioc.type, "value": ioc.value, "confidence": ioc.confidence}


def _alert_out(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "detector": alert.detector,
        "title": alert.title,
        "severity": alert.severity.name,
        "mitre": alert.mitre,
        "source": alert.source,
        "timestamp": alert.timestamp,
        "iocs": [_ioc_out(i) for i in alert.iocs],
    }


def _incident_out(incident: Incident) -> dict:
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity.name,
        "status": incident.status.value,
        "opened_at": incident.opened_at,
        "alerts_count": len(incident.alerts),
        "mitre_ttps": sorted(incident.mitre_ttps),
        "playbook": incident.playbook.name if incident.playbook else None,
    }


def _incident_detail_out(incident: Incident) -> dict:
    detail = _incident_out(incident)
    detail["summary"] = incident.summary
    detail["alerts"] = [_alert_out(a) for a in incident.alerts]
    detail["playbook_steps"] = (
        [
            {
                "order": s.order,
                "action": s.action,
                "description": s.description,
                "assignee_role": s.assignee_role,
            }
            for s in incident.playbook.steps
        ]
        if incident.playbook
        else []
    )
    return detail


# --- endpoints ---------------------------------------------------------------
@api.get("/health", tags=["system"])
def health(request) -> dict:
    """Liveness check for the API."""
    return {"status": "ok", "service": "soc-triage-lab"}


@api.get("/alerts", response=list[AlertOut], tags=["soc"])
def list_alerts(request) -> list[dict]:
    """List alerts from the last pipeline run."""
    return [_alert_out(a) for a in store.alerts]


@api.get("/incidents", response=list[IncidentOut], tags=["soc"])
def list_incidents(request, severity: str | None = None) -> list[dict]:
    """List incidents, optionally filtered by severity."""
    return [_incident_out(i) for i in store.list_incidents(severity=severity)]


@api.get("/incidents/{incident_id}", response=IncidentDetailOut, tags=["soc"])
def incident_detail(request, incident_id: str):
    """Full detail of a single incident (alerts + playbook steps)."""
    incident = store.get_incident(incident_id)
    if incident is None:
        raise HttpError(404, f"Incident {incident_id} not found")
    return _incident_detail_out(incident)


@api.get("/stats", response=StatsOut, tags=["soc"])
def stats(request) -> dict:
    """Aggregated statistics over the demo data."""
    return store.stats()


@api.post("/scan", tags=["soc"])
def run_scan(request, seed: int = 42, strategy: str = "ioc") -> dict:
    """Run the demo SOC pipeline and return a summary."""
    result = run_pipeline(seed=seed, strategy=strategy)
    return {
        "events": result.events,
        "alerts": len(result.alerts),
        "escalated": result.escalated,
        "incidents": len(result.incidents),
        "stats": store.stats(),
    }
