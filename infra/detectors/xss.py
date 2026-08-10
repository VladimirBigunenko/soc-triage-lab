"""XssDetector — flags cross-site scripting attempts in web requests."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from core.entities.alert import Alert, LogEvent
from core.entities.ioc import Ioc
from core.entities.severity import Severity

from infra.detectors.patterns import XSS_PATTERNS


class XssDetector:
    """Matches XSS signatures against the request URL (and optionally body)."""

    name = "xss"

    def __init__(self, check_body: bool = True) -> None:
        self.check_body = check_body

    def analyze(self, event: LogEvent) -> Alert | None:
        if event.source != "web":
            return None

        candidates = []
        url = self._field(event, "url", "url.full")
        if url is not None:
            candidates.append(str(url))
        if self.check_body:
            body = self._field(event, "body", "http.request.body")
            if body is not None:
                candidates.append(str(body))

        if not candidates:
            return None

        for pattern in XSS_PATTERNS:
            for candidate in candidates:
                if pattern.search(candidate):
                    ip = self._field(event, "ip", "source.ip")
                    return Alert(
                        id=f"ALT-{self.name}-{uuid4().hex[:8]}",
                        detector=self.name,
                        title="Cross-site scripting (XSS) attempt detected",
                        severity=Severity.HIGH,
                        source=event.source,
                        timestamp=event.timestamp,
                        description=f"XSS signature matched: {candidate[:200]}",
                        mitre="T1059.007",
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
