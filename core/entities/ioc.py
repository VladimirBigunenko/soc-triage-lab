"""Indicator of Compromise (IoC) entity."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class Ioc:
    """A single indicator of compromise extracted from an alert.

    Examples: malicious IP, domain, URL, file hash, sender email.
    """

    type: str  # one of: ip, domain, url, hash, email
    value: str
    source: str = ""
    confidence: float = 0.5
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.type not in {"ip", "domain", "url", "hash", "email"}:
            raise ValueError(f"Unsupported IoC type: {self.type!r}")
        if not self.value.strip():
            raise ValueError("IoC value must not be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be in [0, 1], got {self.confidence}")
