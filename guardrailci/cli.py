from __future__ import annotations

import argparse
import json
from pathlib import Path

from .demo import run_demo
from .report import html_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run GuardrailCI's reproducible adversarial release benchmark")
    parser.add_argument("--output", default="guardrailci-report.json")
    parser.add_argument("--html", default="guardrailci-report.html")
    args = parser.parse_args()
    report = run_demo()
    Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    Path(args.html).write_text(html_report(report), encoding="utf-8")
    print(json.dumps({
        "attacks": report["library"]["attacks"],
        "releases": report["releases"],
        "minimization": {k: v for k, v in report["minimization"].items() if k != "details"},
        "defense_utility": {
            name: {
                key: value
                for key, value in result.items()
                if key != "false_blocks"
            }
            for name, result in report["defense_utility"].items()
            if isinstance(result, dict) and name != "acceptance"
        },
    }, indent=2))


if __name__ == "__main__":
    main()

