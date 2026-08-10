"""Shared test fixtures and factories (pure pytest — no Django)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.entities.alert import Alert, LogEvent
from core.entities.ioc import Ioc
from core.entities.severity import Severity


def make_event(
    source: str = "auth",
    raw: str = "raw line",
    fields: dict | None = None,
    timestamp: datetime | None = None,
) -> LogEvent:
    return LogEvent(
        source=source,
        raw=raw,
        fields=fields or {},
        timestamp=timestamp or datetime.now(timezone.utc),
    )


def make_alert(
    detector: str = "test-detector",
    title: str = "Test alert",
    severity: Severity = Severity.MEDIUM,
    mitre: str = "T1110",
    iocs: list[Ioc] | None = None,
    timestamp: datetime | None = None,
    source: str = "auth",
) -> Alert:
    return Alert(
        id=f"ALT-{detector}-{abs(hash((detector, title))) % 100000:05d}",
        detector=detector,
        title=title,
        severity=severity,
        source=source,
        mitre=mitre,
        iocs=iocs or [],
        timestamp=timestamp or datetime.now(timezone.utc),
    )


def make_ioc(type_: str = "ip", value: str = "10.0.0.1") -> Ioc:
    return Ioc(type=type_, value=value)


@pytest.fixture
def event_factory():
    return make_event


@pytest.fixture
def alert_factory():
    return make_alert


@pytest.fixture
def ioc_factory():
    return make_ioc
