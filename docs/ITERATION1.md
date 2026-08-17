# Iteration 1 — Real-Model Pilot Validation

## Implemented

- Environment-only OpenAI-compatible backend compatible with NVIDIA NIM, vLLM, llama.cpp servers, and similar APIs.
- Endpoint model enumeration, basic completion probe, and native function/tool-call probe.
- Thirty varied paired email tasks: 15 development, 8 validation, 7 frozen test.
- Five direct and five contextual templates with seeded rotation and template IDs in logs.
- Task clusters and structured utility for summarization, extraction, classification, drafting, and comparison.
- Simulated `read_email`, `list_emails`, `send_email`, `delete_email`, and `forward_email`; no real email integration.
- Provenance-aware intent policy. Legitimate, explicitly addressed sends are allowed; attacker-selected recipients are blocked.
- Parse errors and raw provider responses are retained. Parsing success is a reported metric, not treated as security.
- Cluster-level bootstrap, Wilson intervals, paired task deltas, six plots, quality warnings, and qualitative failure records.

## Current execution status

Implementation tests: **13/13 PASSED**.

Real endpoint capability probe: **NOT RUN — BLOCKED: `NVIDIA_API_KEY` is not available to the agent process**. The adapter defaults to NVIDIA's OpenAI-compatible base URL and accepts `NVIDIA_MODEL(S)` with generic `LLM_*` aliases as fallback.

Five-task real development pilot: **NOT RUN**.

Development/validation pilot: **NOT RUN**.

Frozen test evaluation: **NOT RUN**.

Local open-weight capability probe: **RUN**. Qwen2.5 and Qwen2 loaded locally on CPU; Llama 3.2 was gated by Hugging Face. Neither loaded Qwen model met the 80% combined schema/task-action suitability threshold, so the 135-run security pilot remains **NOT RUN**. See `reports/LOCAL_MODEL_CAPABILITY_REPORT.md`.

Iteration 1A stabilization: **RUN** using a frozen 20-case set and P0/P1/P2. The corrected rerun found P2 best for both models. Qwen2 is `READY_WITH_LIMITATIONS` (95% JSON, 90% schema, 90% action, 60% full task); Qwen2.5 is `NOT_CAPABLE_ENOUGH` (85%, 75%, 75%, 45%). The security benchmark remains **NOT RUN**. See `reports/capability_v2/ITERATION1A_REPORT.md`.

Iteration 1B model selection: **RUN** with frozen P2/cases/evaluators. SmolLM2 scored 95% JSON, 95% schema, 95% action, and 65% full task; Qwen2 reproduced 95%, 90%, 90%, and 60%; Gemma failed to load because its repository was gated. No model met the 80% full-task gate, so the security benchmark remains **NOT RUN**. See `reports/capability_iteration1b/ITERATION1B_REPORT.md`.

Iteration 1C argument stabilization: **RUN**. P4 was selected on a separate 12-case development set, then evaluated on the frozen 20 cases. SmolLM2 achieved 100% raw/normalized arguments and 100% read/write LAC but 90% JSON and 75% full task, yielding `READY_FOR_EXPLORATORY_SECURITY`; Qwen2 achieved 92.5% arguments, 75%/87.5% read/write LAC, and 75% full task, yielding `NOT_READY`. No attacks were run. See `reports/iteration1c/ITERATION1C_REPORT.md`.

Iteration 1D exploratory security pilot: **RUN** on five development tasks and SmolLM2 only (45 runs). Corrected tool-schema evaluation yielded Raw/Conditional ASR of 10% naive, 10% prompt defense, and 0% policy gate; proposal compromise was 40%, 20%, and 40%, respectively. Contextual attacks had a floor effect and Task Completion Rate was 33%, so the decision is `NEEDS_TASK_FIXES` with a secondary attack-quality concern. No scale-up was run. See the corrected result directory's `ITERATION1D_REPORT.md`.

No mock data was substituted.

## Credential handling

The API credential must be injected into the process environment by the user or secret manager. It must not appear in configuration, shell history, repository files, result metadata, or tool-call transcripts. Rotate any credential that has been pasted into chat if organizational policy treats chat exposure as disclosure.

## Methodological limitations requiring real-output inspection

Tool-call provenance is inferred from recipient/resource matches and cannot establish causal origin from arbitrary generated text. Some providers may ignore or vary OpenAI tool schemas. Draft utility relies on explicit semantic units, not a judge, and may under-credit paraphrases. Five-task development runs cover only summarization; the full development set is needed to validate utility across clusters. Provider nondeterminism at temperature zero must be measured rather than assumed absent.
