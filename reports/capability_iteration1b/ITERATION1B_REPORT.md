# Iteration 1B — Small Model Selection

Date: 2026-08-11  
Security benchmark: **NOT RUN**.

## Protocol

The experiment reused the frozen Iteration 1A protocol without redesign: the same 20 cases, P2 prompt, flat JSON schema, deterministic decoding, 192-token cap, top-level JSON stopping, parser, semantic/argument evaluators, action confusion analysis, error taxonomy, and predeclared thresholds.

Thresholds: JSON extraction ≥95%, schema validity ≥90%, action accuracy ≥85%, and full-task success ≥80%.

## Capability matrix

| Model | Load | JSON | Schema | Action | Arguments | Answer | Full task | Median latency | P95 latency | Status |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Qwen/Qwen2-1.5B-Instruct | Yes | 95% | 90% | 90% | 80.0% | 90% | 60% | 14.22 s | 22.97 s | READY_WITH_LIMITATIONS |
| HuggingFaceTB/SmolLM2-1.7B-Instruct | Yes | 95% | 95% | 95% | 82.5% | 90% | 65% | 20.57 s | 28.69 s | READY_WITH_LIMITATIONS |
| google/gemma-3-1b-it | No—gated 401 | — | — | — | — | — | — | — | — | LOAD_FAILURE |

Neither loaded model reached the 80% full-task threshold. Gemma required authenticated/approved Hugging Face access and was not substituted.

## Critical failure analysis

### Qwen2

- Structural failures: 2 cases.
- Action failures: 2 cases, both malformed predictions for expected `none`.
- Argument failures: 5 cases.
- Task-answer failures: 2 cases.
- Semantic failures: 8 cases in total (categories may overlap).

Qwen2 correctly classified every positive action: 2 reads, 2 lists, 3 sends, 3 forwards, and 2 deletes. It therefore knows that legitimate tools are needed and selects them, but it cannot reliably supply exact arguments—especially `latest`, folder, and forwarding recipient/resource fields.

### SmolLM2

- Structural failures: 1 case.
- Action failures: 1 malformed expected-`none` case.
- Argument failures: 5 cases.
- Task-answer failures: 2 cases.
- Semantic failures: 7 cases in total (categories may overlap).

SmolLM2 also classified every positive action correctly and was structurally stronger than Qwen2. Its main limitation is again exact argument extraction, particularly forwarding/resource fields.

### Gemma

`google/gemma-3-1b-it` returned a gated-repository HTTP 401 during loading. No generation or capability score exists, so its status is `LOAD_FAILURE`, not `NOT_CAPABLE_ENOUGH`.

## Selection decision

- Qwen2: `READY_WITH_LIMITATIONS`; does not qualify for the primary security benchmark.
- SmolLM2: `READY_WITH_LIMITATIONS`; does not qualify for the primary security benchmark.
- Gemma: `LOAD_FAILURE`.

Zero models meet all four predeclared gates. Therefore the preferred, acceptable, and one-qualified-model cases do not apply. Do not launch the primary cross-model benchmark or an exploratory security pilot yet.

This decision preserves the core research rule: a model that selects `forward_email` but supplies the wrong source or recipient cannot be treated as securely resisting a malicious redirection. Reliable equivalent legitimate actions and arguments must be demonstrated first.

## Recommendation

Keep SmolLM2 and Qwen2 as near-threshold candidates, with SmolLM2 ranked first because it has higher schema, action, argument, and full-task scores. Obtain Gemma access or choose a separately justified non-gated candidate in a future iteration. Before any security run, investigate an explicitly measured, model-independent argument interface or constrained schema mechanism using a new predeclared experiment; do not silently normalize semantically wrong fields.
