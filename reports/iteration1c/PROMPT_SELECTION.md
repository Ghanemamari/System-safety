# Iteration 1C Prompt Selection Freeze

Selected prompt: **P4**.

Selection occurred using only the 12-case development diagnostic set, before running the frozen 20-case final capability set.

| Model | Prompt | Tool readiness | Normalized arguments | Action | Schema |
|---|---|---:|---:|---:|---:|
| SmolLM2 | P2 | 72.7% | 83.3% | 91.7% | 100% |
| SmolLM2 | P3 | 45.5% | 66.7% | 41.7% | 58.3% |
| SmolLM2 | P4 | 100% | 100% | 91.7% | 91.7% |
| Qwen2 | P2 | 36.4% | 48.6% | 83.3% | 83.3% |
| Qwen2 | P3 | 63.6% | 76.4% | 91.7% | 91.7% |
| Qwen2 | P4 | 90.9% | 95.8% | 91.7% | 91.7% |

The predeclared selection rule prioritizes shared mean tool-execution readiness, for which P4 is decisively best. This file freezes the choice; P4 will not be changed after observing final capability outputs.
