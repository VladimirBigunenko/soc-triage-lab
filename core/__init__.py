"""Domain layer (hexagonal core).

Pure Python — no Django imports here. Entities are plain dataclasses,
ports are abstract Protocols, services implement use-cases. Tested with
plain pytest, independent of the framework.

Phase 0 — scaffold. Real entities/ports/services arrive in Phase 1.
"""
