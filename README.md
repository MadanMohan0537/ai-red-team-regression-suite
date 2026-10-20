# AI Red-Team Regression Suite

[![CI](https://github.com/MadanMohan0537/ai-red-team-regression-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/MadanMohan0537/ai-red-team-regression-suite/actions/workflows/ci.yml)

**Run a versioned library of multi-step attacks against two deterministic synthetic releases, score them with visible marker rubrics, and record whether a linked fix blocked the attack.**

A Python MVP with no runtime dependencies. The package and CLI are still called `guardrailci`.

## Problem and who it's for

Red-team findings often live in a one-off spreadsheet. After a fix ships, nobody re-runs the attack, so regressions come back quietly. This suite is meant for AI application teams, security reviewers, and the AI PMs who own release sign-off, so the same adversarial checks can be repeated on later releases.

## Approach

- A versioned attack library at `guardrailci/data/attacks.yaml`. The file is JSON, so it is valid YAML, and `guardrailci/library.py` loads it with the standard-library `json` module. Each attack has an ID, a category, a severity, a title, ordered steps, an expected violation, and a smoke flag. The categories are direct jailbreak, indirect prompt injection, data exfiltration, and tool misuse.
- The runner can execute the full library or the four-attack smoke subset (`run_suite(..., smoke_only=True)`). The `guardrailci` CLI always runs the full demo. Continuous integration runs on push and pull request.
- Category rubrics count visible evidence markers. The partial score is matched markers divided by the markers for that category. A grade counts as an attack success at 0.5 or above. Results roll up into an overall attack-success rate, per-category rates, and a severity-weighted rate that uses the partial score.
- Each run builds a transcript in memory (the steps and the responses) and grades that transcript. The CLI writes a JSON report and a standalone HTML bar chart. Those files contain rates, fix rows, and minimization counts. They do not contain the transcripts.
- Fix verification uses SQLite. The demo opens an in-memory database, stores one fix per attack that succeeded on the vulnerable release, and marks it `verified` when the guarded release blocks the attack or `regressed` when the attack still succeeds. The CLI copies those rows into the JSON report. It exits 0 either way.
- The attack-path minimizer deletes a step only when the violation still reproduces on every trial (default 3) at the original score or higher. It leaves at least one step. The JSON report stores the step counts for that reduction.

## What exists today

These figures match the current tests and a local `guardrailci` run on Python 3.12.

- 20 synthetic attacks, five in each of the four categories. Four are flagged for the smoke subset: `DJ-01`, `II-01`, `DE-01`, and `TM-01`.
- Two synthetic releases, `v1-vulnerable` and `v2-guarded`. The CLI reports an attack-success rate of 1.0 on `v1-vulnerable` and 0.0 on `v2-guarded`. The severity-weighted rates are the same. Tests assert both attack-success rates.
- On the 20 attacks that succeed against `v1-vulnerable`, the CLI reports 41 original steps reduced to 20, with `all_reproduced` true and 3 trials per candidate. Tests assert that the total falls and that every minimized path reproduces. They do not assert the exact counts 41 and 20.
- A JSON results file (`--output`, default `guardrailci-report.json`) and a standalone HTML bar chart of attack-success rate by release (`--html`, default `guardrailci-report.html`).
- 20 unit tests in `tests/test_guardrailci.py`. `.github/workflows/ci.yml` runs those tests and the full CLI on Python 3.11, 3.12, and 3.13 for every push and pull request. The workflow has no schedule.

## How success would be measured

| Measure | Status |
|---|---|
| Known-vulnerable vs. guarded synthetic release separated | Tests assert attack-success 1.0 on `v1-vulnerable` and 0.0 on `v2-guarded` |
| Triage steps saved by minimization on a real application | Not yet measured. On this fixture the CLI reports 41 → 20 steps |
| Regressions caught before release on a real application | Not yet measured. There is no real-model adapter |
| Over-refusal of legitimate requests | Not yet measured. Paired benign lookalikes are the next backlog item |

## Limitations

- This is a workflow benchmark for the synthetic fixture. It does not measure whether any model or application is safe.
- The only target is `SyntheticAssistant`, limited to `v1-vulnerable` and `v2-guarded`. There is no real-model adapter, HTTP adapter, semantic grader, or external attack feed.
- Rubrics match fixed strings. A paraphrased violation that contains none of those markers scores as a miss.
- The CLI records a `regressed` fix in the JSON report and still exits 0.
- Run it only against systems you own or are authorized to test. The bundled attacks use harmless markers. Do not put real credentials in attacks, transcripts, or reports.

See [docs/METHOD.md](docs/METHOD.md) and [docs/BACKLOG.md](docs/BACKLOG.md).

## Quick start

Requires Python 3.11 or newer. The commands do not call a model, use an API key, make a network request, or read a real secret.

```bash
git clone https://github.com/MadanMohan0537/ai-red-team-regression-suite.git
cd ai-red-team-regression-suite
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
guardrailci --output guardrailci-report.json --html guardrailci-report.html
```

## Deployment

Cloudflare Workers is the planned target. This project is not deployed, and Workers is not configured yet.

There is no `wrangler.toml` and no Worker entry point. Deploying still needs:

- a `wrangler.toml`
- a Worker entry point
- Python Workers support for this package, or a JavaScript/TypeScript port of the runner

When that configuration is in place, deploy with:

```bash
npx wrangler deploy
```

## License

MIT. See [LICENSE](LICENSE).
