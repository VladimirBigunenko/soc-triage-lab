"""PortScanDetector — flags network scans (many distinct ports per IP)."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from core.entities.alert import Alert, LogEvent
from core.entities.ioc import Ioc
from core.entities.severity import Severity


class PortScanDetector:
    """Sliding-window port-scan detector: distinct dst ports per source IP."""

    name = "port-scan"

    def __init__(self, window_minutes: int = 10, distinct_ports_threshold: int = 20) -> None:
        self.window_minutes = window_minutes
        self.distinct_ports_threshold = distinct_ports_threshold
        # ip -> list of (timestamp, port)
        self._hits: dict[str, list[tuple[datetime, int]]] = defaultdict(list)

    def analyze(self, event: LogEvent) -> Alert | None:
        if event.source not in {"endpoint", "network", "firewall"}:
            return None

        ip = self._field(event, "ip", "source.ip")
        port = self._field(event, "dst_port", "destination.port")
        if not ip or port is None:
            return None

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self.window_minutes)
        hits = self._hits[ip]
        hits.append((event.timestamp, int(port)))
        # drop stale hits
        self._hits[ip] = [(ts, p) for ts, p in hits if ts >= cutoff]

        distinct_ports = {p for _, p in self._hits[ip]}
        if len(distinct_ports) >= self.distinct_ports_threshold:
            self._hits.pop(ip, None)
            return Alert(
                id=f"ALT-{self.name}-{uuid4().hex[:8]}",
                detector=self.name,
                title=f"Port scan: {len(distinct_ports)} ports from {ip}",
                severity=Severity.MEDIUM,
                source=event.source,
                timestamp=event.timestamp,
                description=(
                    f"{len(distinct_ports)} distinct destination ports observed "
                    f"from {ip} within {self.window_minutes} minutes — possible scan."
                ),
                mitre="T1046",
                iocs=[Ioc(type="ip", value=ip, source=self.name, confidence=0.7)],
                event=event,
                metadata={
                    "window_minutes": self.window_minutes,
                    "distinct_ports": len(distinct_ports),
                },
            )
        return None

    @staticmethod
    def _field(event: LogEvent, *keys: str) -> Any:
        for key in keys:
            if key in event.fields:
                return event.fields[key]
        return None
