"""EcsDemoLogSource — deterministic synthetic ECS-formatted log generator.

Implements the ``LogSource`` port. Produces events using Elastic Common
Schema field names (``source.ip``, ``url.full``, ``user_agent.original``,
``event.outcome``, ...) so the demo mirrors what a real SIEM pipeline
would feed into the detectors.

Deterministic: the same seed produces the same event stream.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

from core.entities.alert import LogEvent

# Realistic background (benign) user-agents.
BENIGN_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0",
)

# Scanner / offensive tools.
SCANNER_UA = (
    "sqlmap/1.7.2#stable (http://sqlmap.org)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "curl/8.0.1",
)


class EcsDemoLogSource:
    """Generates a mix of benign events and attack scenarios."""

    name = "ecs-demo"

    def __init__(
        self,
        seed: int = 42,
        brute_force_failures: int = 8,
        port_scan_ports: int = 25,
    ) -> None:
        self.seed = seed
        self.brute_force_failures = brute_force_failures
        self.port_scan_ports = port_scan_ports
        self._rng = random.Random(seed)

    # ------------------------------------------------------------------
    def read_events(self) -> Iterator[LogEvent]:
        """Yield the full deterministic event stream."""
        yield from self._auth_background()
        yield from self._brute_force()
        yield from self._web_background()
        yield from self._sqli()
        yield from self._xss()
        yield from self._scanner_ua()
        yield from self._port_scan()
        yield from self._phishing()

    # ------------------------------------------------------------------
    def _auth_background(self) -> Iterator[LogEvent]:
        for i in range(6):
            yield self._event(
                source="auth",
                raw=f"Accepted password for user{i} from 192.168.{i}.10 port 22 ssh2",
                fields={
                    "source.ip": f"192.168.{i}.10",
                    "event.category": "authentication",
                    "event.outcome": "success",
                    "user.name": f"user{i}",
                },
                offset=i,
            )

    def _brute_force(self) -> Iterator[LogEvent]:
        ip = "203.0.113.77"
        for i in range(self.brute_force_failures):
            yield self._event(
                source="auth",
                raw=f"Failed password for invalid user admin from {ip} port {50000 + i} ssh2",
                fields={
                    "source.ip": ip,
                    "event.category": "authentication",
                    "event.outcome": "failure",
                    "user.name": "admin",
                },
                offset=i,
            )
        # one success afterwards (attacker got in)
        yield self._event(
            source="auth",
            raw=f"Accepted password for admin from {ip} port 50300 ssh2",
            fields={
                "source.ip": ip,
                "event.category": "authentication",
                "event.outcome": "success",
                "user.name": "admin",
            },
            offset=100,
        )

    def _web_background(self) -> Iterator[LogEvent]:
        for i in range(8):
            yield self._event(
                source="web",
                raw=f'GET /page/{i} HTTP/1.1" 200',
                fields={
                    "source.ip": f"198.51.100.{i + 10}",
                    "url.full": f"https://demo.example/page/{i}",
                    "url.path": f"/page/{i}",
                    "http.request.method": "GET",
                    "http.response.status_code": 200,
                    "user_agent.original": self._rng.choice(BENIGN_UA),
                },
                offset=i,
            )

    def _sqli(self) -> Iterator[LogEvent]:
        for i, payload in enumerate(
            ["/products?id=1 UNION SELECT username,password FROM users", "/login?user=' OR '1'='1'--"]
        ):
            yield self._event(
                source="web",
                raw=f'GET {payload} HTTP/1.1" 500',
                fields={
                    "source.ip": "45.155.205.10",
                    "url.full": f"https://demo.example{payload}",
                    "url.path": payload,
                    "http.request.method": "GET",
                    "http.response.status_code": 500,
                    "user_agent.original": "Mozilla/5.0 (sqlmap)",
                },
                offset=200 + i,
            )

    def _xss(self) -> Iterator[LogEvent]:
        for i, payload in enumerate(
            ['/search?q=<script>alert(1)</script>', '/comment?body=<img src=x onerror=alert(1)>']
        ):
            yield self._event(
                source="web",
                raw=f'GET {payload} HTTP/1.1" 200',
                fields={
                    "source.ip": "45.155.205.11",
                    "url.full": f"https://demo.example{payload}",
                    "url.path": payload,
                    "http.request.method": "GET",
                    "http.response.status_code": 200,
                    "user_agent.original": self._rng.choice(BENIGN_UA),
                },
                offset=300 + i,
            )

    def _scanner_ua(self) -> Iterator[LogEvent]:
        for i, ua in enumerate(SCANNER_UA):
            yield self._event(
                source="web",
                raw=f'GET / HTTP/1.1" 200',
                fields={
                    "source.ip": f"185.220.101.{i + 1}",
                    "url.full": "https://demo.example/",
                    "url.path": "/",
                    "http.request.method": "GET",
                    "http.response.status_code": 200,
                    "user_agent.original": ua,
                },
                offset=400 + i,
            )

    def _port_scan(self) -> Iterator[LogEvent]:
        ip = "185.220.102.50"
        for i in range(self.port_scan_ports):
            port = 1000 + i * 137 % 60000
            yield self._event(
                source="endpoint",
                raw=f"TCP connection attempt {ip}:{port}",
                fields={
                    "source.ip": ip,
                    "destination.port": port,
                    "destination.ip": "203.0.113.10",
                    "event.category": "network",
                    "event.type": "connection",
                },
                offset=500 + i,
            )

    def _phishing(self) -> Iterator[LogEvent]:
        for i in range(2):
            yield self._event(
                source="email",
                raw="email: security@paypa1.com -> victim@demo.example",
                fields={
                    "source.ip": "91.240.118.40",
                    "email.from.address": "security@paypa1.com",
                    "email.reply_to.address": "attacker@mail.ru",
                    "email.subject": "Your account has been locked — verify now",
                    "email.auth.spf": "fail",
                    "email.auth.dkim": "fail",
                    "email.auth.dmarc": "fail",
                    "email.body.text": "Click here to verify your login: http://paypa1-secure.example/login",
                },
                offset=600 + i,
            )

    # ------------------------------------------------------------------
    def _event(self, source: str, raw: str, fields: dict, offset: int) -> LogEvent:
        base = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
        return LogEvent(
            source=source,
            raw=raw,
            timestamp=base + timedelta(seconds=offset),
            fields=fields,
        )


__all__ = ["EcsDemoLogSource"]
