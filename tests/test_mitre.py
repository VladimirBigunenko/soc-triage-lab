"""Tests for MITRE ATT&CK repository and EnrichmentService."""

import pytest

from core.entities.mitre import Technique
from core.services.enrichment import EnrichmentService
from infra.mitre.attck import MITRE_BASE, MitreAttckRepository

from tests.conftest import make_alert


class TestMitreAttckRepository:
    def test_get_known_technique(self):
        repo = MitreAttckRepository()
        tech = repo.get("T1110.001")
        assert tech is not None
        assert tech.name == "Brute Force: Password Guessing"
        assert tech.tactic == "Credential Access"
        assert tech.l1_guidance  # non-empty guidance

    def test_get_unknown_returns_none(self):
        repo = MitreAttckRepository()
        assert repo.get("T9999") is None

    def test_list_all(self):
        repo = MitreAttckRepository()
        techniques = repo.list_all()
        assert len(techniques) >= 9
        assert all(isinstance(t, Technique) for t in techniques)

    def test_all_techniques_referenced_by_detectors(self):
        """Every MITRE id used by detectors must exist in the knowledge base."""
        repo = MitreAttckRepository()
        for technique_id in MITRE_BASE:
            assert repo.get(technique_id) is not None


class TestEnrichmentService:
    def test_enrich_alert_adds_metadata(self):
        service = EnrichmentService(MitreAttckRepository())
        alert = make_alert(mitre="T1110")
        service.enrich_alert(alert)
        assert alert.metadata["mitre_technique"] == "Brute Force"
        assert alert.metadata["mitre_tactic"] == "Credential Access"
        assert "guidance" in alert.metadata["mitre_guidance"].lower() or alert.metadata["mitre_guidance"]

    def test_enrich_unknown_technique_noop(self):
        service = EnrichmentService(MitreAttckRepository())
        alert = make_alert(mitre="T9999")
        service.enrich_alert(alert)
        assert "mitre_technique" not in alert.metadata

    def test_enrich_alert_without_mitre_noop(self):
        service = EnrichmentService(MitreAttckRepository())
        alert = make_alert(mitre="")
        service.enrich_alert(alert)
        assert "mitre_technique" not in alert.metadata

    def test_enrich_incident_appends_guidance(self):
        service = EnrichmentService(MitreAttckRepository())
        from core.entities.incident import Incident

        incident = Incident(id="INC-1", title="Case")
        incident.add_alert(make_alert(mitre="T1110"))
        incident.add_alert(make_alert(mitre="T1059"))
        service.enrich_incident(incident)
        assert "[T1059]" in incident.summary
        assert "[T1110]" in incident.summary
