# Iteration 3S — Shieldstral Guardrail Baseline

## Decision

**RESOURCE_LIMITED**

The mandatory preflight failed the memory-safety gate. Shieldstral was not
downloaded, loaded, or invoked. No SmolLM2 output was regenerated, no benchmark
row was added or changed, and none of the frozen final-test tasks was used.

## Official model preflight

| Field | Observed requirement |
|---|---|
| exact model ID | `mistralai/Shieldstral-1.0-3B` |
| parameters | 3,849,090,048 BF16 parameters |
| model type | `Mistral3ForConditionalGeneration`; policy-adaptive multimodal safety classifier |
| base model | `mistralai/Ministral-3-3B-Base-2512` |
| license | Apache 2.0 |
| access | public, non-private, non-gated |
| Transformers checkpoint version | 5.13.0 (repository configuration) |
| installed Transformers | 5.15.0 |
| recommended native runtime | vLLM >= 0.26.0; `mistral-common >= 1.11.5` |
| native classifier interface | fixed system prompt plus `<Instruct>`, one yes/no `<Query>`, and `<Document>` |
| native output | one `yes`/`no` token; normalized yes/no log probabilities; threshold 0.5 |
| checkpoint file | `model.safetensors`, 7,698,241,104 bytes (7.17 GiB) |
| model cache | absent |

The official model card describes the model as a single-forward-pass safety
classifier. Its Transformers example uses BF16 on CUDA. The planned text-only
authority-policy document fits the native binary interface, but that interface
was not exercised because the resource gate failed.

## Hardware and memory safety

| Resource | Preflight observation |
|---|---:|
| physical RAM | 15.71 GiB |
| currently available physical RAM | 6.78 GiB |
| currently used physical RAM | 8.93 GiB |
| CPU | Intel Core i7-1185G7, 8 logical processors |
| GPU | Intel Iris Xe integrated graphics |
| CUDA | unavailable |
| active research-model processes | 0 |

The unquantized BF16 weight file alone is 7.17 GiB, already 0.39 GiB larger
than current available physical RAM. Loading additionally requires model
objects, tokenizer state, tensors/activations, and operating-system headroom.
It therefore cannot be attempted safely under the current 6.78 GiB allowance.

Per the frozen protocol, no automatic quantization, alternate dtype, GGUF
conversion, offloading, application termination, or paging-based experiment
was attempted. Downloading the uncached checkpoint was also unnecessary once
the hard resource failure was established.

## Experimental status

All Shieldstral measurements remain **not measured**, rather than inferred:

| Item | Status |
|---|---|
| retrospective unauthorized proposals | 0/16 evaluated |
| benign legitimate proposals | 0 evaluated |
| full Shieldstral architecture runs | 0 |
| GDR / FNR / FPR / TPR / TNR / GUP | not measured |
| PCR / ECR / EVR / containment | not measured for Shieldstral |
| direct/contextual analysis | not measured |
| read/write and argument-substitution analysis | not measured |

Consequently, no Shieldstral values were inserted into the primary comparison
tables and no scientific conclusion about learned guardrails versus the Policy
Gate is warranted from this iteration.

## Integrity checks

- Existing Iteration 2B artifacts were not modified.
- The 7 frozen final-test tasks were not accessed or used.
- Existing attack, parser, simulator, evaluator, Prompt Defense, and Policy Gate
  implementations were not changed.
- No model output or score was fabricated.
- Runtime integration and its requested regression tests were not added because
  the protocol requires stopping before implementation/inference when hardware
  is insufficient.

## Safe next condition

Retry the same frozen preflight on a host with enough free memory for the full
7.17 GiB BF16 checkpoint plus runtime and OS headroom, preferably with the
officially documented single-GPU runtime. Any reduced-precision or quantized
variant requires separate approval and must be reported as a distinct
experiment.

## Sources checked on 2026-08-13

- Official model card: https://huggingface.co/mistralai/Shieldstral-1.0-3B
- Official Hugging Face model metadata API:
  https://huggingface.co/api/models/mistralai/Shieldstral-1.0-3B
- Shieldstral technical report: https://arxiv.org/abs/2607.25857
