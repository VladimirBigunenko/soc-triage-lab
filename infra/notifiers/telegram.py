"""TelegramNotifier — AlertNotifier adapter sending messages via Bot API.

Uses ``httpx`` directly (no python-telegram-bot dependency). If the bot
token is missing the notifier degrades to silent no-ops so the pipeline
still works in demo mode.
"""

from __future__ import annotations

import httpx

from core.entities.alert import Alert
from core.entities.incident import Incident


class TelegramNotifier:
    """Sends alert/incident notifications to a Telegram chat."""

    def __init__(
        self,
        token: str = "",
        chat_id: str = "",
        base_url: str = "https://api.telegram.org",
        timeout: float = 10.0,
    ) -> None:
        self.token = token
        self.chat_id = chat_id
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def _send(self, text: str) -> bool:
        if not self.enabled:
            return False
        try:
            response = self._client.post(
                f"{self.base_url}/bot{self.token}/sendMessage",
                json={"chat_id": self.chat_id, "text": text, "disable_web_page_preview": True},
            )
            response.raise_for_status()
            return True
        except httpx.HTTPError:
            return False

    def notify_alert(self, alert: Alert) -> None:
        text = (
            f"[ALERT] {alert.severity.label} | {alert.title}\n"
            f"ID: {alert.id}\n"
            f"Detector: {alert.detector}\n"
            f"MITRE: {alert.mitre or 'n/a'}\n"
            f"Source: {alert.source}"
        )
        self._send(text)

    def notify_incident(self, incident: Incident) -> None:
        ttps = ", ".join(sorted(incident.mitre_ttps)) or "n/a"
        text = (
            f"[INCIDENT] {incident.severity.label} | {incident.title}\n"
            f"ID: {incident.id}\n"
            f"Alerts: {len(incident.alerts)}\n"
            f"MITRE TTPs: {ttps}\n"
            f"Status: {incident.status.value}"
        )
        self._send(text)
