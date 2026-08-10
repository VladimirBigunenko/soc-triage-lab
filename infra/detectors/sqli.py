"""SqlIDetector — flags SQL injection attempts in web requests."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from core.entities.alert import Alert, LogEvent
from core.entities.ioc import Ioc
from core.entities.severity import Severity

from infra.detectors.patterns import SQLI_PATTERNS


class SqlIDetector:
    """Matches SQL-injection signatures against the request URL."""

    name = "sqli"

    def __init__(self, check_body: bool = False) -> None:
        self.check_body = check_body

    def analyze(self, event: LogEvent) -> Alert | None:
        if event.source != "web":
            return None

        url = self._field(event, "url", "url.full")
        if url is None:
            return None

        for pattern in SQLI_PATTERNS:
            if pattern.search(str(url)):
                ip = self._field(event, "ip", "source.ip")
                return Alert(
                    id=f"ALT-{self.name}-{uuid4().hex[:8]}",
                    detector=self.name,
                    title="SQL injection attempt detected",
                    severity=Severity.HIGH,
                    source=event.source,
                    timestamp=event.timestamp,
                    description=f"SQLi signature matched in URL: {url[:200]}",
                    mitre="T1190",
                    iocs=[Ioc(type="ip", value=ip, source=self.name, confidence=0.7)]
                    if ip
                    else [],
                    event=event,
                    metadata={"matched_pattern": pattern.pattern},
                )
        return None

    @staticmethod
    def _field(event: LogEvent, *keys: str) -> Any:
        for key in keys:
            if key in event.fields:
                return event.fields[key]
        return None
