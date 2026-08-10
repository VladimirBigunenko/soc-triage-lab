"""BruteForceDetector — flags credential-stuffing / password guessing.

Listens to ``auth`` events carrying ``ip`` and ``success`` (or ECS
``source.ip`` / ``event.outcome``). When a source IP exceeds the failed
attempt threshold within the window, an alert fires (MITRE T1110.001).
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from core.entities.alert import Alert, LogEvent
from core.entities.ioc import Ioc
from core.entities.severity import Severity


class BruteForceDetector:
    """Sliding-window brute-force detector, stateful per source IP."""

    name = "brute-force"

    def __init__(self, window_minutes: int = 10, threshold: int = 5) -> None:
        self.window_minutes = window_minutes
        self.threshold = threshold
        # ip -> deque of timestamps of failed attempts
        self._failures: dict[str, deque[datetime]] = {}

    def analyze(self, event: LogEvent) -> Alert | None:
        if event.source != "auth":
            return None

        ip = self._field(event, "ip", "source.ip")
        success = self._field(event, "success", "event.outcome")
        if not ip:
            return None

        # success=True resets the counter for that IP (legit login)
        if success is True or str(success).lower() in {"success", "ok", "pass"}:
            self._failures.pop(ip, None)
            return None

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self.window_minutes)
        attempts = self._failures.setdefault(ip, deque())
        attempts.append(event.timestamp)
        # drop attempts outside the window
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        if len(attempts) >= self.threshold:
            # reset after firing to avoid alert spam per event
            self._failures.pop(ip, None)
            return Alert(
                id=f"ALT-{self.name}-{uuid4().hex[:8]}",
                detector=self.name,
                title=f"Brute-force: {len(attempts)} failed logins from {ip}",
                severity=Severity.HIGH,
                source=event.source,
                timestamp=event.timestamp,
                description=(
                    f"{len(attempts)} failed authentication attempts from {ip} "
                    f"within {self.window_minutes} minutes."
                ),
                mitre="T1110.001",
                iocs=[Ioc(type="ip", value=ip, source=self.name, confidence=0.8)],
                event=event,
                metadata={"window_minutes": self.window_minutes, "threshold": self.threshold},
            )
        return None

    @staticmethod
    def _field(event: LogEvent, *keys: str) -> Any:
        for key in keys:
            if key in event.fields:
                return event.fields[key]
        return None
