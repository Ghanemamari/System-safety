# Iteration 3A — ~3B Model Capability Replication

## Decision

**RESOURCE_LIMITED**

The preferred candidate is suitable in model architecture and nominal total
RAM, but the current process state does not provide enough free physical memory
for a safe unquantized load. The checkpoint was not downloaded or loaded, no
capability task was run, and no attack configuration was prepared.

## Candidate selection (reported before download)

| Field | Selected candidate |
|---|---|
| model_id | `Qwen/Qwen2.5-3B-Instruct` |
| parameter count | 3.09B total; 2.77B non-embedding |
| training | instruction tuned |
| architecture/runtime | causal LM, Transformers-compatible, native chat template |
| repository access | public/non-gated model page |
| license | Qwen Research License; non-commercial research/evaluation grant |
| published tensor type | BF16 |
| published repository/model size | approximately 6.18 GB |
| quantization | not used or attempted |

Official sources checked on 2026-08-12:

- https://huggingface.co/Qwen/Qwen2.5-3B-Instruct
- https://huggingface.co/Qwen/Qwen2.5-3B-Instruct/tree/main
- https://huggingface.co/Qwen/Qwen2.5-3B-Instruct/blob/main/LICENSE

No silent substitution was made.

## Hardware and memory safety assessment

| Resource | Observed/estimated |
|---|---:|
| physical RAM | 15.71 GiB |
| free physical RAM before download/load | 1.45 GiB |
| CUDA | unavailable |
| CPU | Intel Core i7-1185G7, 8 logical CPUs |
| checkpoint cached locally | no |
| BF16 weight storage | approximately 6.18 GB |
| prudent unquantized process budget | approximately 9–12 GB |

The process audit found no lingering project inference process. Most memory was
held by user browser and IDE processes. These processes were not stopped or
modified. At 1.45 GiB free, attempting an unquantized load would predictably
force severe paging or fail, and would violate the requirement to load
conservatively on a 15.7 GB CPU-only host.

The user instruction explicitly requires stopping before changing precision or
quantizing when unquantized loading is unsafe. Therefore no FP32 fallback,
quantization, offloading experiment, model download, or inference was
performed.

## Capability matrix

| Metric | SmolLM2-1.7B | Qwen2.5-3B-Instruct |
|---|---:|---:|
| General Utility | 68% | not measured |
| Task Completion | 64% | not measured |
| Parser/Schema | 100% | not measured |
| Eligible Reads | 5/5 | not measured |
| Eligible Writes | 5/5 | not measured |
| Eligible No-action | 6/15 | not measured |
| Total Security Eligible | 16/25 | not measured |
| LAC_read | 100% | not measured |
| LAC_write | 100% | not measured |
| LAC_overall | 100% | not measured |

No missing measurement is imputed from model-card claims.

## Runtime reporting

Mean, median, p95 latency, experiment duration, and measured peak RAM are not
available because inference did not begin. A future Iteration 2B-style runtime
estimate would be scientifically unreliable without at least one measured
Qwen2.5-3B generation on this CPU, so none is fabricated.

## Frozen methodology status

The intended replication remains the unchanged 25-task Iteration 2A clean
benchmark with P4, native `apply_chat_template`, deterministic decoding,
`max_new_tokens=192`, existing parser/action schemas/simulator/evaluator,
and unchanged eligibility/LAC definitions. No prompt optimization is planned.

The seven frozen test tasks remain untouched. No prompt injection, security
benchmark, additional model, or repetition was run.

## Safe next condition

Retry only after the host has approximately 10–12 GiB free physical RAM, or in
a fresh environment with equivalent headroom. If the user later explicitly
authorizes a precision or quantization change, that would be a separate,
declared experiment and would not be silently compared with the current
unquantized SmolLM2 methodology.
