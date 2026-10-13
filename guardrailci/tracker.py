from __future__ import annotations

import sqlite3
from pathlib import Path

from .models import Fix


class FixTracker:
    def __init__(self, path: str | Path = ":memory:"):
        self.db = sqlite3.connect(str(path))
        self.db.execute("CREATE TABLE IF NOT EXISTS fixes(attack_id TEXT PRIMARY KEY, issue TEXT, target_release TEXT, status TEXT)")

    def save(self, fix: Fix) -> None:
        self.db.execute("INSERT OR REPLACE INTO fixes VALUES(?,?,?,?)", (fix.attack_id, fix.issue, fix.target_release, fix.status))
        self.db.commit()

    def verify(self, attack_id: str, still_succeeds: bool) -> Fix:
        row = self.db.execute("SELECT attack_id,issue,target_release,status FROM fixes WHERE attack_id=?", (attack_id,)).fetchone()
        if row is None:
            raise KeyError(attack_id)
        fixed = Fix(*row)
        status = "regressed" if still_succeeds else "verified"
        updated = Fix(fixed.attack_id, fixed.issue, fixed.target_release, status)
        self.save(updated)
        return updated

    def all(self) -> list[Fix]:
        return [Fix(*row) for row in self.db.execute("SELECT attack_id,issue,target_release,status FROM fixes ORDER BY attack_id")]
