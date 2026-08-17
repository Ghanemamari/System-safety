# Iteration 1A — Local Model Capability Stabilization

Date: 2026-08-11  
Security benchmark status: **NOT RUN**.

## Experimental controls

- Frozen set: 20 attack-free tasks balanced across no-action, negative-action, read, write, and argument extraction.
- Models: `Qwen/Qwen2.5-1.5B-Instruct` and `Qwen/Qwen2-1.5B-Instruct`; loaded one at a time, unquantized, CPU-only.
- Prompt variants: P0 legacy nested schema, P1 explicit flat schema, P2 flat schema plus three fixed examples.
- Decoding: deterministic (`do_sample=false`, temperature 0), maximum 192 new tokens, tokenizer-specific chat template and EOS token.
- Syntax repair: fences, smart quotes, and trailing commas only; all repairs are logged. No repair changed action semantics or arguments. Repair rate was 0% in this run.
- Predeclared thresholds: JSON extraction ≥95%, schema validity ≥90%, action accuracy ≥85%, full-task success ≥80%.

## Adapter correction

The first v2 execution was invalidated because the stop criterion accepted a completed nested `arguments` object and truncated the outer JSON object. It is preserved in `reports/capability_v2_adapter_bug/`. The criterion was corrected to validate only the first top-level object; all results below come from the corrected rerun.

## Results

| Model | Prompt | JSON | Schema | Action | Arguments | Answer | Full task | Median latency | P95 latency | Thresholds met |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Qwen2 | P0 | 100% | 0% | 20% | 45.0% | 60% | 0% | 11.51 s | 22.12 s | No |
| Qwen2 | P1 | 100% | 80% | 80% | 60.8% | 95% | 35% | 9.54 s | 13.16 s | No |
| Qwen2 | P2 | 95% | 90% | 90% | 80.0% | 90% | 60% | 15.08 s | 28.29 s | No |
| Qwen2.5 | P0 | 100% | 0% | 0% | 48.3% | 60% | 0% | 12.73 s | 21.00 s | No |
| Qwen2.5 | P1 | 95% | 25% | 65% | 71.7% | 85% | 10% | 12.05 s | 19.01 s | No |
| Qwen2.5 | P2 | 85% | 75% | 75% | 77.5% | 90% | 45% | 14.48 s | 18.55 s | No |

P2 is the best prompt for both models under the frozen global selection rule. It improves action understanding substantially but does not make either model pass the full-task threshold.

## Action understanding and errors

Under P2, Qwen2 correctly classified all 12 positive read/write actions: two reads, two lists, three sends, three forwards, and two deletes. Its two action errors were malformed/invalid predictions on no-action cases. Qwen2.5 correctly classified all positive send, forward, delete, and read actions, but both list actions were invalid and three no-action cases were incorrect or invalid.

The dominant residual error is argument extraction: both models had five missing-argument failures (25%). Qwen2 had one JSON parse error and one schema error; Qwen2.5 had three parse errors, two schema errors, and three wrong actions. Failures are therefore mostly semantic/argument-level for Qwen2, while Qwen2.5 still has both syntax/schema and semantic failures.

## Status by model

- `Qwen/Qwen2-1.5B-Instruct`: **READY_WITH_LIMITATIONS**. It passes JSON, schema, and action thresholds with P2, and clearly understands legitimate write actions, but 60% full-task success is below the 80% gate because argument extraction remains unreliable.
- `Qwen/Qwen2.5-1.5B-Instruct`: **NOT_CAPABLE_ENOUGH**. P2 misses JSON, schema, action, and full-task thresholds.
- `meta-llama/Llama-3.2-1B-Instruct`: **ACCESS_BLOCKED**. Hugging Face returned a gated-repository 401. It was not substituted.

## Decision questions

1. **Best prompt:** P2 (explicit flat schema plus fixed examples) for both models.
2. **Syntax or semantics:** Qwen2 failures are primarily missing/wrong arguments; Qwen2.5 failures are mixed parser/schema, action, and argument failures.
3. **Legitimate writes:** yes, especially Qwen2, which classified every positive write/read case correctly under P2. Exact arguments remain unreliable.
4. **Can later low ASR be separated from incapability?** Not adequately for a publication-quality comparison yet. Qwen2's 90% action accuracy helps, but 60% full success would still confound action/argument failures with resistance.
5. **CPU feasibility:** technically feasible but slow. P2 median latency is 14–15 seconds and p95 reaches 18–28 seconds. A 135-run, one-repetition pilot would require roughly 34 minutes per model from median generation latency alone, excluding loading and analysis.
6. **Models for first security experiment:** none under the strict predeclared gate. If an exploratory plumbing-only security run is later authorized, Qwen2/P2 is the only defensible candidate and must be labeled `READY_WITH_LIMITATIONS`.

## Optional replacement candidate

`HuggingFaceTB/SmolLM2-1.7B-Instruct` is a public Apache-2.0 instruction-tuned model with approximately 1.7B parameters. Its official model card documents Transformers loading with `AutoTokenizer`, `AutoModelForCausalLM`, and `apply_chat_template`, and describes summarization and function-calling capabilities. It is a candidate only; it was not downloaded or substituted in this iteration. Official card: https://huggingface.co/HuggingFaceTB/SmolLM2-1.7B-Instruct

## Recommendation

Do not run the security benchmark. Freeze P2 and the 20-case set, then investigate an explicitly measured argument-normalization or constrained-decoding adapter without repairing semantic decisions. Reprobe Qwen2 and separately evaluate SmolLM2. Only a model meeting all four predeclared thresholds should enter the primary security comparison; any earlier run must be labeled exploratory.
