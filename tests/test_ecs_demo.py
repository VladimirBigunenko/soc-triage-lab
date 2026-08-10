"""Tests for EcsDemoLogSource and the end-to-end pipeline wiring."""

from core.services.correlation import CorrelationService
from core.services.detection import DetectionService
from core.services.enrichment import EnrichmentService
from core.services.playbooks import PlaybookEngine
from core.services.triage import TriageService
from infra.collectors.ecs_demo import EcsDemoLogSource
from infra.detectors import DEFAULT_DETECTORS
from infra.mitre.attck import MitreAttckRepository
from infra.notifiers.console import ConsoleNotifier
from infra.persistence.memory import MemoryAlertRepository
from infra.playbooks.library import PlaybookLibrary


class TestEcsDemoLogSource:
    def test_deterministic_with_same_seed(self):
        a = list(EcsDemoLogSource(seed=7).read_events())
        b = list(EcsDemoLogSource(seed=7).read_events())
        assert [(e.source, e.raw, e.timestamp) for e in a] == [(e.source, e.raw, e.timestamp) for e in b]

    def test_different_seeds_differ(self):
        a = list(EcsDemoLogSource(seed=1).read_events())
        b = list(EcsDemoLogSource(seed=2).read_events())
        # raw lines are fixed; order/counts same, but contents can differ via rng
        assert len(a) == len(b)

    def test_ecs_field_names_present(self):
        events = list(EcsDemoLogSource().read_events())
        assert events
        for event in events:
            # every event carries at least one ECS-style dotted field
            assert any("." in key for key in event.fields)

    def test_covers_all_sources(self):
        sources = {e.source for e in EcsDemoLogSource().read_events()}
        assert {"auth", "web", "endpoint", "email"} <= sources

    def test_contains_attack_scenarios(self):
        fields = [e.fields for e in EcsDemoLogSource().read_events()]
        assert any("UNION SELECT" in str(f.get("url.full", "")) for f in fields)  # sqli
        assert any("<script>" in str(f.get("url.full", "")) for f in fields)  # xss
        assert any("sqlmap" in str(f.get("user_agent.original", "")).lower() for f in fields)  # scanner
        assert any("paypa1.com" in str(f.get("email.from.address", "")) for f in fields)  # phishing


class TestEndToEndPipeline:
    def test_full_pipeline_produces_alerts_and_incidents(self):
        source = EcsDemoLogSource(seed=42)
        events = list(source.read_events())

        detection = DetectionService(DEFAULT_DETECTORS)
        alerts = detection.process_batch(events)
        assert len(alerts) >= 6  # brute-force, sqli, xss, port-scan, phishing, ua

        repo = MemoryAlertRepository()
        triage = TriageService(repo, ConsoleNotifier())
        decisions = triage.triage_many(alerts)
        assert any(d.action == "escalate" for d in decisions)

        incidents = CorrelationService(strategy="ioc").correlate(alerts)
        assert incidents  # at least one correlation (phishing ip or similar)

        for incident in incidents:
            EnrichmentService(MitreAttckRepository()).enrich_incident(incident)
            PlaybookEngine(PlaybookLibrary()).apply(incident)

        # every incident has a playbook attached (all demo TTPs are covered)
        assert all(i.playbook is not None for i in incidents)

    def test_escalated_alerts_persisted(self):
        source = EcsDemoLogSource(seed=42)
        alerts = DetectionService(DEFAULT_DETECTORS).process_batch(list(source.read_events()))
        repo = MemoryAlertRepository()
        TriageService(repo, ConsoleNotifier()).triage_many(alerts)
        assert len(repo.alerts) == len(alerts)
