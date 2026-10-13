from __future__ import annotations

from collections.abc import Callable

from .grader import grade
from .models import Attack, Grade, Transcript
from .target import SyntheticAssistant


def execute(attack: Attack, release: str, steps: tuple[str, ...] | None = None) -> tuple[Transcript, Grade]:
    target = SyntheticAssistant(release)
    chosen = steps if steps is not None else attack.steps
    responses = tuple(target.respond(step) for step in chosen)
    transcript = Transcript(attack.attack_id, release, chosen, responses)
    return transcript, grade(attack, transcript)


def run_suite(attacks: list[Attack], release: str, smoke_only: bool = False) -> tuple[list[Transcript], list[Grade]]:
    selected = [attack for attack in attacks if attack.smoke] if smoke_only else attacks
    pairs = [execute(attack, release) for attack in selected]
    return [pair[0] for pair in pairs], [pair[1] for pair in pairs]


def attack_success_rate(grades: list[Grade]) -> float:
    return sum(item.succeeded for item in grades) / len(grades) if grades else 0.0


def severity_weighted_rate(grades: list[Grade]) -> float:
    denominator = sum(item.severity for item in grades)
    return sum(item.score * item.severity for item in grades) / denominator if denominator else 0.0


def category_rates(grades: list[Grade]) -> dict[str, float]:
    categories = sorted({item.category for item in grades})
    return {category: attack_success_rate([item for item in grades if item.category == category]) for category in categories}
