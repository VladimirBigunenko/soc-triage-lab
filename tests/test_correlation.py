"""Tests for CorrelationService."""

from datetime import datetime, timedelta, timezone

import pytest

from core.entities.severity import Severity
from core.services.correlation import CorrelationService

from tests.conftest import make_alert, make_ioc


def ts(minutes_ago: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)


class TestCorrelationService:
    def test_groups_alerts_shared_ioc(self):
        service = CorrelationService(min_alerts_per_incident=2)
        alerts = [
            make_alert(iocs=[make_ioc(value="1.2.3.4")], timestamp=ts(1)),
            make_alert(iocs=[make_ioc(value="1.2.3.4")], timestamp=ts(2)),
        ]
        incidents = service.correlate(alerts)
        assert len(incidents) == 1
        assert len(incidents[0].alerts) == 2

    def test_different_iocs_no_correlation(self):
        service = CorrelationService(min_alerts_per_incident=2)
        alerts = [
            make_alert(iocs=[make_ioc(value="1.2.3.4")], timestamp=ts(1)),
            make_alert(iocs=[make_ioc(value="5.6.7.8")], timestamp=ts(2)),
        ]
        assert service.correlate(alerts) == []

    def test_min_alerts_threshold(self):
        service = CorrelationService(min_alerts_per_incident=3)
        alerts = [
            make_alert(iocs=[make_ioc(value="1.2.3.4")], timestamp=ts(1)),
            make_alert(iocs=[make_ioc(value="1.2.3.4")], timestamp=ts(2)),
        ]
        assert service.correlate(alerts) == []

    def test_outside_window_ignored(self):
        service = CorrelationService(window_minutes=15, min_alerts_per_incident=2)
        alerts = [
            make_alert(iocs=[make_ioc(value="1.2.3.4")], timestamp=ts(60)),
            make_alert(iocs=[make_ioc(value="1.2.3.4")], timestamp=ts(1)),
        ]
        assert service.correlate(alerts) == []

    def test_incident_severity_is_max(self):
        service = CorrelationService(min_alerts_per_incident=2)
        alerts = [
            make_alert(iocs=[make_ioc(value="1.2.3.4")], severity=Severity.LOW, timestamp=ts(2)),
            make_alert(iocs=[make_ioc(value="1.2.3.4")], severity=Severity.CRITICAL, timestamp=ts(1)),
        ]
        incidents = service.correlate(alerts)
        assert incidents[0].severity == Severity.CRITICAL

    def test_incident_has_unique_ttps(self):
        service = CorrelationService(min_alerts_per_incident=2)
        alerts = [
            make_alert(iocs=[make_ioc(value="1.2.3.4")], mitre="T1110", timestamp=ts(2)),
            make_alert(iocs=[make_ioc(value="1.2.3.4")], mitre="T1059", timestamp=ts(1)),
        ]
        incidents = service.correlate(alerts)
        assert incidents[0].mitre_ttps == {"T1110", "T1059"}

    def test_sorted_by_severity_desc(self):
        service = CorrelationService(min_alerts_per_incident=2)
        low_group = [
            make_alert(iocs=[make_ioc(value="1.1.1.1")], severity=Severity.LOW, timestamp=ts(2)),
            make_alert(iocs=[make_ioc(value="1.1.1.1")], severity=Severity.LOW, timestamp=ts(1)),
        ]
        crit_group = [
            make_alert(iocs=[make_ioc(value="2.2.2.2")], severity=Severity.CRITICAL, timestamp=ts(2)),
            make_alert(iocs=[make_ioc(value="2.2.2.2")], severity=Severity.CRITICAL, timestamp=ts(1)),
        ]
        incidents = service.correlate(low_group + crit_group)
        assert incidents[0].severity == Severity.CRITICAL


class TestCorrelationStrategies:
    def test_source_strategy_groups_by_ip(self):
        service = CorrelationService(strategy="source", min_alerts_per_incident=2)
        alerts = [
            make_alert(iocs=[make_ioc(value="9.9.9.9")], timestamp=ts(2)),
            make_alert(iocs=[make_ioc(value="9.9.9.9")], timestamp=ts(1)),
            make_alert(iocs=[make_ioc(value="8.8.8.8")], timestamp=ts(0)),
        ]
        incidents = service.correlate(alerts)
        assert len(incidents) == 1
        assert len(incidents[0].alerts) == 2

    def test_technique_strategy_groups_by_mitre(self):
        service = CorrelationService(strategy="technique", min_alerts_per_incident=2)
        alerts = [
            make_alert(mitre="T1110", timestamp=ts(2)),
            make_alert(mitre="T1110", timestamp=ts(1)),
            make_alert(mitre="T1059", timestamp=ts(0)),
        ]
        incidents = service.correlate(alerts)
        assert len(incidents) == 1
        assert incidents[0].mitre_ttps == {"T1110"}

    def test_invalid_strategy_rejected(self):
        with pytest.raises(ValueError):
            CorrelationService(strategy="bogus")
