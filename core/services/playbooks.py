"""PlaybookEngine — attaches the matching response procedure to an incident.

Picks a playbook by the incident's MITRE technique (first match across
sorted TTPs), stores the steps in incident metadata and moves the
incident to INVESTIGATING. Depends on the PlaybookRepository port only.
"""

from __future__ import annotations

from core.entities.incident import Incident
from core.entities.severity import IncidentStatus
from core.ports.ports import PlaybookRepository


class PlaybookEngine:
    """Binds a playbook to an incident based on its MITRE TTPs."""

    def __init__(self, repository: PlaybookRepository) -> None:
        self._repository = repository

    def apply(self, incident: Incident) -> Incident:
        """Find and attach a playbook for the incident (first matching TTP)."""
        for technique_id in sorted(incident.mitre_ttps):
            playbook = self._repository.get_by_technique(technique_id)
            if playbook is not None:
                incident.status = IncidentStatus.INVESTIGATING
                incident.playbook = playbook
                return incident
        return incident

    def steps_for(self, incident: Incident) -> list[dict]:
        """Return the playbook steps as plain dicts (for rendering/API)."""
        playbook = incident.playbook
        if playbook is None:
            return []
        return [
            {
                "order": step.order,
                "action": step.action,
                "description": step.description,
                "assignee_role": step.assignee_role,
            }
            for step in playbook.steps
        ]


__all__ = ["PlaybookEngine"]
