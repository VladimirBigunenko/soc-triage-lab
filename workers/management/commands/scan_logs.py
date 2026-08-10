"""scan_logs — run the full SOC pipeline over a log source.

Wires the hexagonal layers together:
  LogSource -> DetectionService -> alerts
            -> TriageService (notify + save)
            -> CorrelationService -> incidents
            -> EnrichmentService + PlaybookEngine
            -> MarkdownReportRenderer -> reports/

Demo mode (default): EcsDemoLogSource generates deterministic ECS events.
"""

from __future__ import annotations

import os
from pathlib import Path

from django.core.management.base import BaseCommand

from core.services.correlation import CorrelationService
from core.services.detection import DetectionService
from core.services.enrichment import EnrichmentService
from core.services.playbooks import PlaybookEngine
from core.services.triage import TriageService
from infra.collectors.ecs_demo import EcsDemoLogSource
from infra.detectors import DEFAULT_DETECTORS
from infra.mitre.attck import MitreAttckRepository
from infra.notifiers.console import ConsoleNotifier
from infra.notifiers.telegram import TelegramNotifier
from infra.persistence.memory import MemoryAlertRepository
from infra.playbooks.library import PlaybookLibrary
from infra.reports.markdown import MarkdownReportRenderer


class Command(BaseCommand):
    help = "Run the SOC pipeline (collect -> detect -> triage -> correlate -> respond) and render reports."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--seed", type=int, default=42, help="RNG seed for the demo log source")
        parser.add_argument("--out", default="reports", help="Output directory for reports")
        parser.add_argument("--strategy", default="ioc", choices=["ioc", "source", "technique"])
        parser.add_argument("--telegram", action="store_true", help="Send notifications via Telegram (uses TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)")

    def handle(self, *args, **options) -> None:
        seed = options["seed"]
        out_dir = Path(options["out"])
        strategy = options["strategy"]

        # 1. Collect
        source = EcsDemoLogSource(seed=seed)
        events = list(source.read_events())
        self.stdout.write(f"[collect] {len(events)} events from {source.name}")

        # 2. Detect
        detection = DetectionService(DEFAULT_DETECTORS)
        alerts = detection.process_batch(events)
        self.stdout.write(f"[detect] {len(alerts)} alerts fired")

        # 3. Triage (notify + persist)
        notifier = self._build_notifier(options["telegram"])
        repo = MemoryAlertRepository()
        triage = TriageService(repo, notifier)
        decisions = triage.triage_many(alerts)
        escalated = sum(1 for d in decisions if d.action == "escalate")
        self.stdout.write(f"[triage] {escalated} escalated, {len(decisions) - escalated} resolved")

        # 4. Correlate
        correlation = CorrelationService(strategy=strategy)
        incidents = correlation.correlate(alerts)
        self.stdout.write(f"[correlate] {len(incidents)} incidents (strategy={strategy})")

        # 5. Enrich + playbook
        enrichment = EnrichmentService(MitreAttckRepository())
        playbook_engine = PlaybookEngine(PlaybookLibrary())
        for incident in incidents:
            enrichment.enrich_incident(incident)
            playbook_engine.apply(incident)

        # 6. Render reports
        out_dir.mkdir(parents=True, exist_ok=True)
        renderer = MarkdownReportRenderer()
        for incident in incidents:
            path = out_dir / f"{incident.id}.md"
            path.write_text(renderer.render_incident(incident), encoding="utf-8")
            self.stdout.write(f"[report] {path}")

        self.stdout.write(self.style.SUCCESS(f"Done: {len(alerts)} alerts, {len(incidents)} incidents -> {out_dir}/"))

    @staticmethod
    def _build_notifier(use_telegram: bool):
        if use_telegram:
            return TelegramNotifier(
                token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
                chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
            )
        return ConsoleNotifier()
