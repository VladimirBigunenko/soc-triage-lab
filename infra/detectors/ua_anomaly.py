"""UaAnomalyDetector — flags requests from known scanner/offensive tools."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from core.entities.alert import Alert, LogEvent
from core.entities.ioc import Ioc
from core.entities.severity import Severity

from infra.detectors.patterns import SUSPICIOUS_USER_AGENTS


class UaAnomalyDetector:
    """Detects known offensive/scanner User-Agents in web traffic."""

    name = "ua-anomaly"

    def analyze(self, event: LogEvent) -> Alert | None:
        if event.source != "web":
            return None

        ua = self._field(event, "user_agent", "user_agent.original")
        if not ua:
            return None

        ua_lower = str(ua).lower()
        for signature in SUSPICIOUS_USER_AGENTS:
            if signature in ua_lower:
                ip = self._field(event, "ip", "source.ip")
                return Alert(
                    id=f"ALT-{self.name}-{uuid4().hex[:8]}",
                    detector=self.name,
                    title=f"Suspicious User-Agent: {signature}",
                    severity=Severity.MEDIUM,
                    source=event.source,
                    timestamp=event.timestamp,
                    description=f"Request from {ip or 'unknown'} used UA matching scanner tool '{signature}'.",
                    mitre="T1595",
                    iocs=[Ioc(type="ip", value=ip, source=self.name, confidence=0.6)]
                    if ip
                    else [],
                    event=event,
                    metadata={"matched_ua": signature},
                )
        return None

    @staticmethod
    def _field(event: LogEvent, *keys: str) -> Any:
        for key in keys:
            if key in event.fields:
                return event.fields[key]
        return None
