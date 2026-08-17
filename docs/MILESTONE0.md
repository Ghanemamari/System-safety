# Milestone 0: infrastructure validation

## Repository architecture

`configs/` holds versioned experiment inputs; `data/benchmark_v0/` holds normalized paired cases; `src/secure_llm/` contains types, backend interfaces, architectures, attacks, policy/tools, evaluation, metrics, runner, and analysis; `scripts/` are stable CLI entry points; `tests/` contains unit/integration/security regression tests; and `results/` receives immutable artifacts.

## Exact scope

- 1 email domain; 10 paired cases.
- 1 explicitly mocked backend.
- `naive`, `prompt_defense`, and `policy_gate`.
- clean, direct, and contextual inputs.
- Seeded repetitions, deterministic tool simulator and evaluator.
- ASR, utility, over-refusal, `Delta_sec`, smoothed differential influence, confidence intervals.
- CSV/JSON summaries and two dependency-free SVG plots.

## Files created

Configuration and data: `configs/experiments/milestone0.yaml`, `data/benchmark_v0/email.json`.

Implementation: modules under `src/secure_llm/`, plus CLI wrappers in `scripts/`.

Verification: tests under `tests/`, immutable results under `results/`.

## Known threats to validity

Construct validity is limited by keyword task scoring and a binary policy model. Internal validity is limited by a synthetic mock with programmed response rates. External validity is absent until real models, domains, and held-out attacks are evaluated. Repetitions measure generation variability but are clustered within cases. Any real-model nondeterminism can remain even at temperature zero and must be reported.
