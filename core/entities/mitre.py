"""MITRE ATT&CK Technique entity."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    """A MITRE ATT&CK technique/sub-technique.

    ``l1_guidance`` contains practical instructions for an L1 analyst —
    used by enrichment to tell the analyst what to do with an alert.
    """

    id: str  # e.g. "T1110.001"
    name: str
    tactic: str  # e.g. "Credential Access"
    description: str
    l1_guidance: str

    def __post_init__(self) -> None:
        if not self.id.startswith("T"):
            raise ValueError(f"Technique id must start with 'T': {self.id!r}")
