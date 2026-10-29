from __future__ import annotations

from .library import load_attacks
from .minimizer import minimize
from .models import Fix
from .runner import attack_success_rate, category_rates, run_suite, severity_weighted_rate
from .tracker import FixTracker
from .utility import defense_utility_experiment


def run_demo() -> dict:
    attacks = load_attacks()
    release_rows = []
    release_grades = {}
    for release in ("v1-vulnerable", "v2-guarded"):
        transcripts, grades = run_suite(attacks, release)
        release_grades[release] = grades
        release_rows.append({
            "release": release,
            "attacks": len(grades),
            "attack_success_rate": attack_success_rate(grades),
            "severity_weighted_rate": severity_weighted_rate(grades),
            "category_rates": category_rates(grades),
        })
    successful = [attack for attack, grade in zip(attacks, release_grades["v1-vulnerable"]) if grade.succeeded]
    minimized = [minimize(attack, "v1-vulnerable") for attack in successful]
    tracker = FixTracker()
    for attack in successful:
        tracker.save(Fix(attack.attack_id, f"Harden {attack.category} handling", "v2-guarded"))
    for attack, grade in zip(attacks, release_grades["v2-guarded"]):
        if attack.attack_id in {item.attack_id for item in successful}:
            tracker.verify(attack.attack_id, grade.succeeded)
    return {
        "project": "GuardrailCI",
        "catalog_trace": {"number": 10, "original_title": "Red-Team Regression Suite"},
        "library": {"attacks": len(attacks), "categories": 4, "smoke_attacks": sum(item.smoke for item in attacks)},
        "releases": release_rows,
        "fixes": [fix.__dict__ for fix in tracker.all()],
        "minimization": {
            "successful_attacks": len(successful),
            "original_steps": sum(item[1]["original_steps"] for item in minimized),
            "minimal_steps": sum(item[1]["minimal_steps"] for item in minimized),
            "all_reproduced": all(item[1]["reproduced"] for item in minimized),
            "details": [{"attack_id": item.attack_id, **metrics} for item, metrics in minimized],
        },
        "defense_utility": defense_utility_experiment(attacks),
    }

