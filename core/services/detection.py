"""DetectionService — runs events through detectors and collects alerts."""

from __future__ import annotations

from collections.abc import Iterable

from core.entities.alert import Alert, LogEvent
from core.ports.ports import Detector


class DetectionService:
    """Feeds log events into all registered detectors and returns alerts.

    The service depends on the ``Detector`` port only — new detectors are
    added by registering new adapters, the core stays untouched.
    """

    def __init__(self, detectors: Iterable[Detector] = ()) -> None:
        self._detectors: list[Detector] = list(detectors)

    @property
    def detectors(self) -> list[Detector]:
        """Registered detectors (read-only view)."""
        return list(self._detectors)

    def register(self, detector: Detector) -> None:
        """Register an additional detector."""
        self._detectors.append(detector)

    def process_event(self, event: LogEvent) -> list[Alert]:
        """Run one event through all detectors; return any alerts produced."""
        alerts: list[Alert] = []
        for detector in self._detectors:
            alert = detector.analyze(event)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def process_batch(self, events: Iterable[LogEvent]) -> list[Alert]:
        """Run a batch of events; return alerts produced across all of them."""
        alerts: list[Alert] = []
        for event in events:
            alerts.extend(self.process_event(event))
        return alerts
