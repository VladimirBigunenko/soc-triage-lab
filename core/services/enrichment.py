"""EnrichmentService — adds MITRE ATT&CK context to alerts and incidents.

An L1 analyst benefits from knowing the technique name, tactic and what
to do next. Enrichment injects that metadata without changing alert state.
"""

from __future__ import annotations

from core.entities.alert import Alert
from core.entities.incident import Incident
from core.ports.ports import TechniqueRepository


class EnrichmentService:
    """Attaches MITRE metadata (name, tactic, L1 guidance) to entities."""

    def __init__(self, techniques: TechniqueRepository) -> None:
        self._techniques = techniques

    def enrich_alert(self, alert: Alert) -> Alert:
        """Add MITRE context into the alert's metadata (idempotent)."""
        technique = self._techniques.get(alert.mitre) if alert.mitre else None
        if technique is not None:
            alert.metadata["mitre_technique"] = technique.name
            alert.metadata["mitre_tactic"] = technique.tactic
            alert.metadata["mitre_guidance"] = technique.l1_guidance
        return alert

    def enrich_incident(self, incident: Incident) -> Incident:
        """Enrich the incident with technique context for all its TTPs."""
        for technique_id in sorted(incident.mitre_ttps):
            technique = self._techniques.get(technique_id)
            if technique is None:
                continue
            incident.summary += (
                f"\n[{technique.id}] {technique.name} ({technique.tactic}): "
                f"{technique.l1_guidance}"
            )
        return incident

    def enrich_alerts(self, alerts: list[Alert]) -> list[Alert]:
        """Enrich a batch of alerts."""
        for alert in alerts:
            self.enrich_alert(alert)
        return alerts
