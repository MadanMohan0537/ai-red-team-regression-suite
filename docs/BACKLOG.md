# Evidence-driven backlog

| Priority | Feature | User problem and behavior | Dependencies | Success test | Risks and tradeoffs | Status |
|---|---|---|---|---|---|---|
| P1 | Attack-path minimizer | Long successful attacks are hard to reproduce. Remove steps while preserving the same violation across repeated trials. | Sequence runner, category grader | Reduce total steps for every seeded success while retaining 100% reproduction across three trials | Nondeterminism may erase failures; keep originals and repeat trials | Shipped |
| P2 | Defense utility tradeoff | A fix may block legitimate users. Pair every malicious case with a benign lookalike and report attack success beside false-block rate. | Benign holdout, paired IDs | Detect a seeded over-broad defense and keep independently authored holdouts | Easy synthetic lookalikes understate user harm; production holdouts must be independent | Shipped |
| P2 | Grader disagreement queue | A single grader can turn ambiguity into false certainty. Run two rubrics and route score deltas for review. | Independent rubric, reviewer labels | Surface all seeded ambiguous transcripts without flooding the queue | Added review cost may exceed benefit | Planned |
| P2 | Attack-library freshness ledger | Public techniques arrive faster than quarterly reviews. Track source date, owner, coverage date, and retirement reason. | Source metadata, review cadence | Every seeded stale entry produces an owner-visible freshness warning | Incentivizes quantity over meaningful coverage | Planned |
| P2 | Nondeterministic confidence bounds | One lucky block can hide a flaky vulnerability. Repeat attacks and report Wilson intervals per category. | Real-model adapter, trial budget | Flag seeded intermittent failures at the predeclared trial count | Runtime and cost rise rapidly | Planned |
| P3 | Semantic secret canary | Exact markers miss encoded or paraphrased leakage. Plant synthetic canaries and detect transformations. | Canary issuer, encoding detectors | Detect seeded direct, base64, split, and paraphrased leakage | Detectors can expose canaries in logs | Planned |
| P3 | Tool side-effect sandbox | Text markers do not prove whether tools acted. Execute against an isolated simulator and reconcile proposed versus committed actions. | Capability sandbox, audit events | No unauthorized seeded action reaches commit state | Simulator behavior may diverge from production | Planned |
| P3 | Adaptive mutation budget | Near-miss attacks deserve targeted variants. Allocate mutation attempts by information gain and severity. | Mutation operators, budget policy | Improve held-out discovery at equal run budget | Optimizing against the grader can create artifacts | Planned |
| P3 | Cross-release root-cause bisect | Teams know a regression exists but not which prompt/tool change caused it. Replay attacks across saved versions and bisect the first bad change. | Immutable artifacts, replay compatibility | Identify every seeded first-bad revision | Historical dependencies may no longer replay | Planned |
| P4 | Disclosure packet generator | Security findings are hard to communicate safely. Produce redacted reproduction, impact, scope, and remediation sections. | Redaction policy, approval workflow | Seeded secrets never enter exported packets | Templates can encourage premature disclosure | Planned |

## Further rigorous additions

| Priority | Feature | User problem and behavior | Dependencies | Success test | Risks and tradeoffs | Status |
|---|---|---|---|---|---|---|
| P2 | Utility severity weighting | Blocking a harmless explanation and blocking an urgent accessibility workflow have different costs. Add business-owned impact weights beside the raw false-block rate. | Benign case taxonomy, impact owners | A seeded high-impact false block prevents promotion even when the aggregate rate stays below threshold | Subjective weights can hide tradeoffs; publish unweighted denominators too | Planned |
| P2 | Holdout independence ledger | Defense authors can accidentally tune against the benign fixture. Record author, creation date, exposure, and refresh status for each holdout case. | Case metadata, access policy, refresh cadence | Every seeded exposed case is excluded from promotion evidence | Metadata cannot prove true independence | Planned |
| P2 | Partial-utility rubric | A response may avoid outright refusal yet still be unusably vague. Score completeness and task success for benign cases. | Reference criteria, reviewer labels | Detect seeded evasive answers without increasing false alarms beyond a declared bound | Semantic grading adds disagreement and review cost | Planned |

Next slice: grader disagreement queue, because a single marker rubric still turns ambiguous transcripts into false certainty.

