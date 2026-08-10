"""Playbook entities — predefined response procedures for L1 analysts."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PlaybookStep:
    """A single ordered step in a playbook."""

    order: int
    action: str
    description: str = ""
    assignee_role: str = "L1"

    def __post_init__(self) -> None:
        if self.order < 0:
            raise ValueError(f"Order must be >= 0, got {self.order}")


@dataclass(frozen=True)
class Playbook:
    """A response procedure triggered by a condition (e.g. MITRE TTP)."""

    id: str
    name: str
    trigger: str  # MITRE technique id or human-readable condition
    steps: tuple[PlaybookStep, ...] = ()
