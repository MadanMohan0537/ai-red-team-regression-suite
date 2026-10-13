from __future__ import annotations

from dataclasses import replace

from .models import Attack, Grade, Transcript
from .runner import execute


def minimize(attack: Attack, release: str, trials: int = 3) -> tuple[Attack, dict]:
    """Greedily remove steps only when the same violation reproduces every trial."""
    _, original_grade = execute(attack, release)
    if not original_grade.succeeded:
        return attack, {"original_steps": len(attack.steps), "minimal_steps": len(attack.steps), "trials": trials, "reproduced": False}
    current = list(attack.steps)
    index = 0
    while index < len(current) and len(current) > 1:
        candidate = tuple(current[:index] + current[index + 1 :])
        grades = [execute(attack, release, candidate)[1] for _ in range(trials)]
        if all(item.succeeded and item.score >= original_grade.score for item in grades):
            current = list(candidate)
        else:
            index += 1
    reduced = replace(attack, steps=tuple(current))
    return reduced, {
        "original_steps": len(attack.steps),
        "minimal_steps": len(reduced.steps),
        "steps_removed": len(attack.steps) - len(reduced.steps),
        "trials": trials,
        "reproduced": execute(reduced, release)[1].succeeded,
    }
