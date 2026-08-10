"""Tests for PlaybookEngine and PlaybookLibrary."""

from core.entities.incident import Incident
from core.entities.severity import IncidentStatus
from core.services.playbooks import PlaybookEngine
from infra.playbooks.library import PlaybookLibrary

from tests.conftest import make_alert


class TestPlaybookLibrary:
    def test_get_known_technique(self):
        library = PlaybookLibrary()
        pb = library.get_by_technique("T1110.001")
        assert pb is not None
        assert pb.name == "Brute Force Response"
        assert len(pb.steps) >= 3

    def test_get_unknown_returns_none(self):
        library = PlaybookLibrary()
        assert library.get_by_technique("T9999") is None

    def test_list_all_non_empty(self):
        library = PlaybookLibrary()
        assert len(library.list_all()) >= 5


class TestPlaybookEngine:
    def test_apply_attaches_playbook_and_investigating(self):
        engine = PlaybookEngine(PlaybookLibrary())
        incident = Incident(id="INC-1", title="Case")
        incident.add_alert(make_alert(mitre="T1110.001"))
        engine.apply(incident)
        assert incident.playbook is not None
        assert incident.status == IncidentStatus.INVESTIGATING

    def test_apply_no_match_keeps_open(self):
        engine = PlaybookEngine(PlaybookLibrary())
        incident = Incident(id="INC-2", title="Case")
        incident.add_alert(make_alert(mitre="T9999"))
        engine.apply(incident)
        assert incident.playbook is None
        assert incident.status == IncidentStatus.OPEN

    def test_steps_for_returns_dicts(self):
        engine = PlaybookEngine(PlaybookLibrary())
        incident = Incident(id="INC-3", title="Case")
        incident.add_alert(make_alert(mitre="T1110.001"))
        engine.apply(incident)
        steps = engine.steps_for(incident)
        assert steps
        assert {"order", "action", "description", "assignee_role"} <= set(steps[0])

    def test_steps_for_without_playbook_empty(self):
        engine = PlaybookEngine(PlaybookLibrary())
        incident = Incident(id="INC-4", title="Case")
        assert engine.steps_for(incident) == []
