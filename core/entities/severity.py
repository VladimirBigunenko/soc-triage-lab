"""Domain value objects: severity levels and statuses.

Pure Python — no framework dependencies.
"""

from enum import Enum, IntEnum


class Severity(IntEnum):
    """Severity of an alert/incident. Ordered so comparisons work: HIGH > MEDIUM."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()


class AlertStatus(str, Enum):
    """Lifecycle of an alert through the SOC process."""

    NEW = "new"
    TRIAGED = "triaged"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, Enum):
    """Lifecycle of an incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"
