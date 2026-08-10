"""Alert and LogEvent entities."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.entities.ioc import Ioc
from core.entities.severity import AlertStatus, Severity


@dataclass
class LogEvent:
    """A raw log line normalized for analysis."""

    source: str  # e.g. "auth", "web", "endpoint"
    raw: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    """Result of a detector analysis — the basic unit a SOC L1 analyst triages."""

    id: str
    detector: str
    title: str
    severity: Severity
    source: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""
    mitre: str = ""  # MITRE ATT&CK technique id, e.g. "T1110.001"
    iocs: list[Ioc] = field(default_factory=list)
    event: LogEvent | None = None
    status: AlertStatus = AlertStatus.NEW
    metadata: dict[str, Any] = field(default_factory=dict)

    def escalate(self) -> None:
        """Mark the alert as escalated to a higher tier."""
        self.status = AlertStatus.ESCALATED

    def resolve(self) -> None:
        """Mark the alert as resolved (handled)."""
        self.status = AlertStatus.RESOLVED

    def mark_false_positive(self) -> None:
        """Mark the alert as a false positive."""
        self.status = AlertStatus.FALSE_POSITIVE
