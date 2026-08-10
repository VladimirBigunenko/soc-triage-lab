"""Pipeline — the full SOC flow, reusable by CLI and API."""

from __future__ import annotations

from dataclasses import dataclass, field

from core.entities.alert import Alert
from core.entities.incident import Incident
from core.ports.ports import AlertNotifier
from core.services.correlation import CorrelationService
from core.services.detection import DetectionService
from core.services.enrichment import EnrichmentService
from core.services.playbooks import PlaybookEngine
from core.services.triage import TriageService
from infra.collectors.ecs_demo import EcsDemoLogSource
from infra.detectors import DEFAULT_DETECTORS
from infra.mitre.attck import MitreAttckRepository
from infra.notifiers.console import ConsoleNotifier
from infra.persistence.incident_store import store
from infra.persistence.memory import MemoryAlertRepository
from infra.playbooks.library import PlaybookLibrary


@dataclass
class PipelineResult:
    """Outcome of a pipeline run."""

    events: int = 0
    alerts: list[Alert] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    escalated: int = 0


def run_pipeline(
    seed: int = 42,
    strategy: str = "ioc",
    notifier: AlertNotifier | None = None,
) -> PipelineResult:
    """Collect -> detect -> triage -> correlate -> enrich -> playbook.

    Results are written to the shared IncidentStore for the API/dashboard.
    """
    notifier = notifier or ConsoleNotifier()
    result = PipelineResult()

    # 1. Collect
    source = EcsDemoLogSource(seed=seed)
    events = list(source.read_events())
    result.events = len(events)

    # 2. Detect
    detection = DetectionService(DEFAULT_DETECTORS)
    result.alerts = detection.process_batch(events)

    # 3. Triage
    repo = MemoryAlertRepository()
    triage = TriageService(repo, notifier)
    decisions = triage.triage_many(result.alerts)
    result.escalated = sum(1 for d in decisions if d.action == "escalate")

    # 4. Correlate
    correlation = CorrelationService(strategy=strategy)
    result.incidents = correlation.correlate(result.alerts)

    # 5. Enrich + playbook
    enrichment = EnrichmentService(MitreAttckRepository())
    playbook_engine = PlaybookEngine(PlaybookLibrary())
    for incident in result.incidents:
        enrichment.enrich_incident(incident)
        playbook_engine.apply(incident)

    # 6. Persist to shared store
    store.reset()
    store.add_alerts(result.alerts)
    for incident in result.incidents:
        store.add_incident(incident)
    store.updated_at = result.incidents[0].opened_at if result.incidents else None

    return result
