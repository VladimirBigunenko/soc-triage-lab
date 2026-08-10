"""Ports (interfaces) of the hexagonal core.

Ports are Protocol definitions only — no implementation lives here.
Adapters in ``infra/`` implement these protocols; services in
``core/services/`` depend on them via dependency injection.
"""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from core.entities.alert import Alert, LogEvent
from core.entities.incident import Incident
from core.entities.mitre import Technique
from core.entities.severity import AlertStatus


@runtime_checkable
class LogSource(Protocol):
    """Reads raw log events from some source (file, docker, API)."""

    name: str

    def read_events(self) -> Iterator[LogEvent]:
        """Yield log events for analysis."""
        ...


@runtime_checkable
class Detector(Protocol):
    """Analyzes a log event and may produce an alert."""

    name: str

    def analyze(self, event: LogEvent) -> Alert | None:
        """Return an Alert if the event matches, else None."""
        ...


@runtime_checkable
class AlertNotifier(Protocol):
    """Delivers alerts/incidents to humans (Telegram, console, ...)."""

    def notify_alert(self, alert: Alert) -> None:
        """Send a notification about a single alert."""
        ...

    def notify_incident(self, incident: Incident) -> None:
        """Send a notification about an incident."""
        ...


@runtime_checkable
class ReportRenderer(Protocol):
    """Renders incidents into human-readable documents."""

    def render_incident(self, incident: Incident) -> str:
        """Render an incident (HTML, Markdown, ...)."""
        ...


@runtime_checkable
class AlertRepository(Protocol):
    """Persists and retrieves alerts."""

    def save(self, alert: Alert) -> None:
        """Store an alert."""
        ...

    def list_by_status(self, status: AlertStatus) -> list[Alert]:
        """Return alerts with the given status."""
        ...


@runtime_checkable
class TechniqueRepository(Protocol):
    """Read-only access to MITRE ATT&CK technique metadata."""

    def get(self, technique_id: str) -> Technique | None:
        """Return technique metadata or None if unknown."""
        ...

    def list_all(self) -> list[Technique]:
        """Return all known techniques."""
        ...


__all__ = [
    "LogSource",
    "Detector",
    "AlertNotifier",
    "ReportRenderer",
    "AlertRepository",
    "TechniqueRepository",
]
