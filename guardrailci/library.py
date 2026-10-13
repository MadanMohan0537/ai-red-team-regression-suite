from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

from .models import Attack


def load_attacks(path: str | Path | None = None) -> list[Attack]:
    source = Path(path) if path else files("guardrailci").joinpath("data/attacks.yaml")
    raw = json.loads(source.read_text(encoding="utf-8"))
    attacks = [Attack(**{**item, "steps": tuple(item["steps"])}) for item in raw]
    ids = [item.attack_id for item in attacks]
    if len(ids) != len(set(ids)):
        raise ValueError("attack ids must be unique")
    for item in attacks:
        if item.category not in {"direct_jailbreak", "indirect_injection", "data_exfiltration", "tool_misuse"}:
            raise ValueError(f"unsupported category: {item.category}")
        if not 1 <= item.severity <= 5 or not item.steps:
            raise ValueError(f"invalid attack: {item.attack_id}")
    return attacks
