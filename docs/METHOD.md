# Method and limitations

GuardrailCI treats an attack as a versioned sequence, not a single prompt. Each category has explicit output markers and a partial-compliance rubric. The headline attack-success rate is accompanied by category rates and a severity-weighted rate so a fall in low-severity failures cannot hide a critical regression.

The included target is deliberately deterministic. `v1-vulnerable` exposes known violations and `v2-guarded` blocks them. This makes CI reproducible and proves that the workflow, trend report, fix tracker, and minimizer behave correctly. It does **not** estimate the safety of a real language model.

The P1 minimizer greedily removes messages from a successful attack and repeats each candidate three times. A shorter path is accepted only when the original violation score survives every trial. The original transcript remains available conceptually; production adapters should persist it immutably.

Important limitations:

- Marker-based grading is transparent but cannot understand novel semantic violations.
- Synthetic attacks are not a substitute for independent red teams, threat modeling, or responsible disclosure.
- A zero percent success rate means only that this library did not find a violation.
- The fixture is deterministic; real systems require repeated trials and uncertainty intervals.
- The project never targets third-party services. Only systems you own or are authorized to test should be connected.
- Attack payloads are intentionally harmless demonstrations and contain no real credentials or destructive integrations.
