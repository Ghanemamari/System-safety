# Iteration 4C — Phi-4-mini-instruct Clean Capability Gate

## Decision: **READY_FOR_SECURITY_REPLICATION**

Clean development capability only; no attacks, validation tasks, or frozen final-test tasks were used.

## Overall capability

| Metric | Result |
|---|---:|
| JSON extraction | 25/25 (100.0%) |
| Schema validity | 24/25 (96.0%) |
| Action accuracy | 25/25 (100.0%) |
| Argument field accuracy | 20/20 (100.0%) |
| Task completion / full success | 18/25 (72.0%) |
| General Utility | 20.333/25 (81.3%) |
| Security-Eligible Utility | 18.000/18 (100.0%) |
| Security eligible | 18/25 (72.0%) |

## Legitimate action capability

| Metric | Result |
|---|---:|
| LAC_read | 5/5 (100.0%) |
| LAC_write | 5/5 (100.0%) |
| LAC_overall | 10/10 (100.0%) |

## Per-family task success

| Family | Full success | Security eligible |
|---|---:|---:|
| read | 5/5 (100.0%) | 5/5 (100.0%) |
| write | 5/5 (100.0%) | 5/5 (100.0%) |
| no_action | 8/15 (53.3%) | 8/15 (53.3%) |
| summarization | 2/5 (40.0%) | 2/5 (40.0%) |
| classification | 3/5 (60.0%) | 3/5 (60.0%) |
| information_extraction | 3/5 (60.0%) | 3/5 (60.0%) |

## Performance

- Model load time (download excluded): 39.378 s
- Steady GPU allocation after load: 7.145 GiB
- Steady GPU reservation after load: 7.148 GiB
- Peak inference allocation: 7.233 GiB
- Peak inference reservation: 7.275 GiB
- Median generation latency: 795.71 ms
- Mean generation latency: 835.68 ms
- p95 generation latency: 1579.47 ms
- Total 25-task inference runtime: 21.278 s

## Reproducibility

- Model: `microsoft/Phi-4-mini-instruct`
- Revision: `cfbefacb99257ffa30c83adab238a50856ac3083`
- Parameters: 3,836,021,760
- Dtype/device: unquantized BF16, fully resident on `cuda:0`
- Native tokenizer chat template used through `apply_chat_template`
- Deterministic generation: `do_sample=false`, `max_new_tokens=192`, seed 53
- Frozen task SHA-256: `44b3780a971bbc9a18377521823814d5c3195ba2595c74cfc80a98b79b8812fb`
- Raw outputs: `raw_runs.jsonl`

### Download provenance

The default `/root` Hugging Face cache had insufficient overlay space, so the first download attempt stopped before completing and before any inference. The pinned official snapshot was then downloaded unchanged to `/workspace/.cache/huggingface/hub` in 19.301 seconds. This was a storage-location correction only; the model revision, files, precision, and inference methodology were unchanged.

## Cross-model capability comparison

Descriptive only; prior models were not rerun.

| Model | Parameters | JSON | Schema | Action | Arguments | General Utility | Eligible | LAC read | LAC write | LAC overall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| HuggingFaceTB/SmolLM2-1.7B-Instruct | 1,711,376,384 | 25/25 (100.0%) | 25/25 (100.0%) | 25/25 (100.0%) | 20/20 (100.0%) | 17.000/25 (68.0%) | 16/25 | 5/5 | 5/5 | 10/10 |
| Qwen/Qwen2.5-7B-Instruct | 7,615,616,512 | 25/25 (100.0%) | 25/25 (100.0%) | 25/25 (100.0%) | 20/20 (100.0%) | 23.000/25 (92.0%) | 23/25 | 5/5 | 5/5 | 10/10 |
| mistralai/Mistral-7B-Instruct-v0.3 | 7,248,023,552 | 25/25 (100.0%) | 25/25 (100.0%) | 21/25 (84.0%) | 17/20 (85.0%) | 17.000/25 (68.0%) | 16/25 | 4/5 | 3/5 | 7/10 |
| microsoft/Phi-4-mini-instruct | 3,836,021,760 | 25/25 (100.0%) | 24/25 (96.0%) | 25/25 (100.0%) | 20/20 (100.0%) | 20.333/25 (81.3%) | 18/25 | 5/5 | 5/5 | 10/10 |

## Common eligibility preparation

| Intersection | Tasks | Read | Write | No-action |
|---|---:|---:|---:|---:|
| SmolLM2 ∩ Phi | 15 | 5 | 5 | 5 |
| Qwen ∩ Phi | 18 | 5 | 5 | 8 |
| Mistral ∩ Phi | 12 | 4 | 3 | 5 |
| SmolLM2 ∩ Qwen ∩ Phi | 15 | 5 | 5 | 5 |
| SmolLM2 ∩ Qwen ∩ Mistral ∩ Phi | 10 | 4 | 3 | 3 |

Exact task IDs are preserved in `common_eligibility.json`. No attacks were run.

## Failure analysis

7 tasks were ineligible. Descriptive failure-label counts: classification failure=2, information extraction failure=2, schema=1, summarization failure=3. Exact expected/proposed actions and arguments, parser/evaluator status, and raw outputs are preserved in `ineligible_tasks.csv` and `raw_runs.jsonl`.

## Regression integrity

- Pre-experiment: 63/63 PASS.
- Post-experiment: 63/63 PASS.
- Frozen tasks, P4, parser, evaluator, simulator, and eligibility rules were not modified.
