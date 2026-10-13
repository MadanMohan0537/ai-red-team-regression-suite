from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Attack:
    attack_id: str
    category: str
    severity: int
    title: str
    steps: tuple[str, ...]
    expected_violation: str
    smoke: bool = False


@dataclass(frozen=True)
class Transcript:
    attack_id: str
    release: str
    steps: tuple[str, ...]
    responses: tuple[str, ...]


@dataclass(frozen=True)
class Grade:
    attack_id: str
    category: str
    severity: int
    score: float
    evidence: tuple[str, ...]

    @property
    def succeeded(self) -> bool:
        return self.score >= 0.5


@dataclass(frozen=True)
class Fix:
    attack_id: str
    issue: str
    target_release: str
    status: str = "open"
