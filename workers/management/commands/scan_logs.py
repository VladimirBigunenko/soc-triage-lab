"""scan_logs — run the full SOC pipeline over the demo log source."""

from __future__ import annotations

import os
from pathlib import Path

from django.core.management.base import BaseCommand

from infra.notifiers.console import ConsoleNotifier
from infra.notifiers.telegram import TelegramNotifier
from infra.reports.markdown import MarkdownReportRenderer

from workers.pipeline import run_pipeline


class Command(BaseCommand):
    help = "Run the SOC pipeline (collect -> detect -> triage -> correlate -> respond) and render reports."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--seed", type=int, default=42, help="RNG seed for the demo log source")
        parser.add_argument("--out", default="reports", help="Output directory for reports")
        parser.add_argument("--strategy", default="ioc", choices=["ioc", "source", "technique"])
        parser.add_argument(
            "--telegram",
            action="store_true",
            help="Send notifications via Telegram (uses TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID)",
        )

    def handle(self, *args, **options) -> None:
        seed = options["seed"]
        out_dir = Path(options["out"])
        strategy = options["strategy"]

        notifier = self._build_notifier(options["telegram"])
        result = run_pipeline(seed=seed, strategy=strategy, notifier=notifier)

        self.stdout.write(f"[collect] {result.events} events")
        self.stdout.write(f"[detect] {len(result.alerts)} alerts fired")
        self.stdout.write(f"[triage] {result.escalated} escalated, {len(result.alerts) - result.escalated} resolved")
        self.stdout.write(f"[correlate] {len(result.incidents)} incidents (strategy={strategy})")

        out_dir.mkdir(parents=True, exist_ok=True)
        renderer = MarkdownReportRenderer()
        for incident in result.incidents:
            path = out_dir / f"{incident.id}.md"
            path.write_text(renderer.render_incident(incident), encoding="utf-8")
            self.stdout.write(f"[report] {path}")

        self.stdout.write(
            self.style.SUCCESS(f"Done: {len(result.alerts)} alerts, {len(result.incidents)} incidents -> {out_dir}/")
        )

    @staticmethod
    def _build_notifier(use_telegram: bool):
        if use_telegram:
            return TelegramNotifier(
                token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
                chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
            )
        return ConsoleNotifier()
