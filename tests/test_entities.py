"""Tests for domain entities."""

import pytest

from core.entities.alert import Alert, LogEvent
from core.entities.incident import Incident
from core.entities.ioc import Ioc
from core.entities.playbook import Playbook, PlaybookStep
from core.entities.severity import (
    AlertStatus,
    IncidentStatus,
    Severity,
)

from tests.conftest import make_alert, make_ioc


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_label(self):
        assert Severity.CRITICAL.label == "Critical"
        assert Severity.INFO.label == "Info"


class TestIoc:
    def test_valid(self):
        ioc = Ioc(type="ip", value="1.2.3.4", confidence=0.9)
        assert ioc.value == "1.2.3.4"

    def test_rejects_unknown_type(self):
        with pytest.raises(ValueError):
            Ioc(type="mac-address", value="aa:bb")

    def test_rejects_empty_value(self):
        with pytest.raises(ValueError):
            Ioc(type="ip", value="   ")

    def test_rejects_bad_confidence(self):
        with pytest.raises(ValueError):
            Ioc(type="ip", value="1.2.3.4", confidence=1.5)


class TestAlert:
    def test_status_lifecycle(self):
        alert = make_alert()
        assert alert.status == AlertStatus.NEW
        alert.escalate()
        assert alert.status == AlertStatus.ESCALATED
        alert.resolve()
        assert alert.status == AlertStatus.RESOLVED

    def test_false_positive(self):
        alert = make_alert()
        alert.mark_false_positive()
        assert alert.status == AlertStatus.FALSE_POSITIVE

    def test_default_severity(self):
        assert make_alert().severity == Severity.MEDIUM


class TestIncident:
    def test_add_alert_escalates_severity(self):
        incident = Incident(id="INC-1", title="Case")
        low = make_alert(severity=Severity.LOW)
        critical = make_alert(severity=Severity.CRITICAL)
        incident.add_alert(low)
        incident.add_alert(critical)
        assert incident.severity == Severity.CRITICAL

    def test_mitre_ttps_are_unique(self):
        incident = Incident(id="INC-2", title="Case")
        incident.add_alert(make_alert(mitre="T1110"))
        incident.add_alert(make_alert(mitre="T1110"))
        incident.add_alert(make_alert(mitre="T1059"))
        assert incident.mitre_ttps == {"T1110", "T1059"}

    def test_iocs_deduplicated(self):
        incident = Incident(id="INC-3", title="Case")
        incident.add_alert(make_alert(iocs=[make_ioc(value="1.2.3.4")]))
        incident.add_alert(make_alert(iocs=[make_ioc(value="1.2.3.4")]))
        incident.add_alert(make_alert(iocs=[make_ioc(value="5.6.7.8")]))
        assert len(incident.iocs) == 2

    def test_close(self):
        incident = Incident(id="INC-4", title="Case")
        incident.close(summary="Contained and eradicated")
        assert incident.status == IncidentStatus.CLOSED
        assert incident.closed_at is not None
        assert incident.summary == "Contained and eradicated"


class TestPlaybook:
    def test_steps_ordered(self):
        pb = Playbook(
            id="PB-1",
            name="Brute Force Response",
            trigger="T1110",
            steps=(
                PlaybookStep(order=0, action="Block source IP"),
                PlaybookStep(order=1, action="Reset affected accounts"),
            ),
        )
        assert [s.order for s in pb.steps] == [0, 1]

    def test_negative_order_rejected(self):
        with pytest.raises(ValueError):
            PlaybookStep(order=-1, action="nope")
