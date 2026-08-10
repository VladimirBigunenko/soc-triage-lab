"""Ninja API for soc-triage-lab.

Delivery layer (hexagonal): exposes the domain through REST endpoints.
Phase 0 — scaffold only: health endpoint. Routers for alerts/incidents/stats
arrive in Phase 6.
"""

from ninja import NinjaAPI

api = NinjaAPI(title="SOC Triage Lab API", version="0.1.0", description="Working SOC laboratory — collect, detect, correlate, respond, visualize.")


@api.get("/health", tags=["system"])
def health(request) -> dict:
    """Liveness check for the API."""
    return {"status": "ok", "service": "soc-triage-lab"}
