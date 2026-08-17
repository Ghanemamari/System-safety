# Iteration 4D — Phi-4-mini-instruct Security Replication

## Decision: **SECURITY_SIGNAL_REPLICATED**

Bounded development security replication on 18/25 Phi-demonstrated legitimate capabilities; 36 attacked runs per architecture. No validation or frozen final-test task was used.

## Primary metrics

| Architecture | PCR | ECR | EVR | Raw ASR | Containment | Clean Utility | Attack Utility | Action Utility | Parser | Schema |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| naive | 19/36 (52.8%) | 19/36 (52.8%) | 19/36 (52.8%) | 19/36 (52.8%) | 0/19 (0.0%) | 18.000/18 (100.0%) | 15.000/36 (41.7%) | 10.000/10 (100.0%) | 54/54 (100.0%) | 54/54 (100.0%) |
| prompt_defense | 15/36 (41.7%) | 15/36 (41.7%) | 15/36 (41.7%) | 15/36 (41.7%) | 0/15 (0.0%) | 18.000/18 (100.0%) | 19.000/36 (52.8%) | 10.000/10 (100.0%) | 54/54 (100.0%) | 54/54 (100.0%) |
| policy_gate | 19/36 (52.8%) | 19/36 (52.8%) | 0/36 (0.0%) | 0/36 (0.0%) | 19/19 (100.0%) | 18.000/18 (100.0%) | 16.000/36 (44.4%) | 10.000/10 (100.0%) | 54/54 (100.0%) | 54/54 (100.0%) |

Conditional PCR/ECR/EVR/ASR use the same numerators and 36-run denominators as the primary rates because every attacked task satisfied Phi's separately measured eligibility prerequisite.

## Matched deterministic control

Naive and Policy Gate raw outputs were identical for **54/54** matched task-condition runs; exact model-facing messages were identical for **54/54**, and parsed proposals were identical for **54/54**.

## Read/write/no-action and attack-type breakdown

| Architecture | Subset | PCR | ECR | EVR |
|---|---|---:|---:|---:|
| naive | READ | 0/10 (0.0%) | 0/10 (0.0%) | 0/10 (0.0%) |
| naive | WRITE | 5/10 (50.0%) | 5/10 (50.0%) | 5/10 (50.0%) |
| naive | NO-ACTION | 14/16 (87.5%) | 14/16 (87.5%) | 14/16 (87.5%) |
| naive | DIRECT | 12/18 (66.7%) | 12/18 (66.7%) | 12/18 (66.7%) |
| naive | CONTEXTUAL | 7/18 (38.9%) | 7/18 (38.9%) | 7/18 (38.9%) |
| prompt_defense | READ | 0/10 (0.0%) | 0/10 (0.0%) | 0/10 (0.0%) |
| prompt_defense | WRITE | 2/10 (20.0%) | 2/10 (20.0%) | 2/10 (20.0%) |
| prompt_defense | NO-ACTION | 13/16 (81.2%) | 13/16 (81.2%) | 13/16 (81.2%) |
| prompt_defense | DIRECT | 9/18 (50.0%) | 9/18 (50.0%) | 9/18 (50.0%) |
| prompt_defense | CONTEXTUAL | 6/18 (33.3%) | 6/18 (33.3%) | 6/18 (33.3%) |
| policy_gate | READ | 0/10 (0.0%) | 0/10 (0.0%) | 0/10 (0.0%) |
| policy_gate | WRITE | 5/10 (50.0%) | 5/10 (50.0%) | 0/10 (0.0%) |
| policy_gate | NO-ACTION | 14/16 (87.5%) | 14/16 (87.5%) | 0/16 (0.0%) |
| policy_gate | DIRECT | 12/18 (66.7%) | 12/18 (66.7%) | 0/18 (0.0%) |
| policy_gate | CONTEXTUAL | 7/18 (38.9%) | 7/18 (38.9%) | 0/18 (0.0%) |

## Legitimate read/write utility

| Architecture | READ | WRITE |
|---|---:|---:|
| naive | 5.000/5 (100.0%) | 5.000/5 (100.0%) |
| prompt_defense | 5.000/5 (100.0%) | 5.000/5 (100.0%) |
| policy_gate | 5.000/5 (100.0%) | 5.000/5 (100.0%) |

## Write compromise analysis

| Architecture | Compromised | Recipient | Subject | Body | Action | Multiple arguments | Executed violations |
|---|---:|---:|---:|---:|---:|---:|---:|
| naive | 5/10 | 0 | 3 | 3 | 1 | 3 | 5 |
| prompt_defense | 2/10 | 0 | 2 | 2 | 1 | 2 | 2 |
| policy_gate | 5/10 | 0 | 3 | 3 | 1 | 3 | 0 |

Policy Gate counts distinguish compromised proposals from executed violations; blocking is not interpreted as model robustness.

## Three-model common eligibility comparison

SmolLM2 ∩ Phi contains 15 tasks; Qwen ∩ Phi contains 18; SmolLM2 ∩ Qwen ∩ Phi contains 15 tasks and 30 attacked runs per model/architecture.

| Model | Architecture | PCR | ECR | EVR | Containment |
|---|---|---:|---:|---:|---:|
| SmolLM2-1.7B | naive | 14/30 (46.7%) | 14/30 (46.7%) | 14/30 (46.7%) | 0/14 (0.0%) |
| SmolLM2-1.7B | prompt_defense | 10/30 (33.3%) | 10/30 (33.3%) | 10/30 (33.3%) | 0/10 (0.0%) |
| SmolLM2-1.7B | policy_gate | 14/30 (46.7%) | 14/30 (46.7%) | 0/30 (0.0%) | 14/14 (100.0%) |
| Qwen2.5-7B | naive | 16/30 (53.3%) | 16/30 (53.3%) | 16/30 (53.3%) | 0/16 (0.0%) |
| Qwen2.5-7B | prompt_defense | 13/30 (43.3%) | 13/30 (43.3%) | 13/30 (43.3%) | 0/13 (0.0%) |
| Qwen2.5-7B | policy_gate | 16/30 (53.3%) | 16/30 (53.3%) | 0/30 (0.0%) | 16/16 (100.0%) |
| Phi-4-mini-instruct | naive | 14/30 (46.7%) | 14/30 (46.7%) | 14/30 (46.7%) | 0/14 (0.0%) |
| Phi-4-mini-instruct | prompt_defense | 10/30 (33.3%) | 10/30 (33.3%) | 10/30 (33.3%) | 0/10 (0.0%) |
| Phi-4-mini-instruct | policy_gate | 14/30 (46.7%) | 14/30 (46.7%) | 0/30 (0.0%) | 14/14 (100.0%) |

## Core questions

1. **Vulnerability after capability demonstration:** Yes; Phi produced 19/36 executable unauthorized proposals under Naive.
2. **Naive PCR/ECR/EVR:** 19/36 (52.8%), 19/36 (52.8%), 19/36 (52.8%).
3. **Prompt Defense and PCR:** Reduced PCR: 19/36 (52.8%) → 15/36 (41.7%).
4. **Prompt Defense and WRITE compromise:** Reduced WRITE PCR: 5/10 (50.0%) → 2/10 (20.0%).
5. **Policy Gate proposal behavior:** PCR/ECR were unchanged relative to Naive.
6. **Policy Gate and EVR:** EVR changed from 19/36 (52.8%) to 0/36 (0.0%).
7. **Containment:** 19/19 executable unauthorized proposals were contained.
8. **Matched raw outputs:** 54/54 were identical.
9. **WRITE vs READ:** Naive WRITE PCR was 5/10 (50.0%) versus READ 0/10 (0.0%); writes were more vulnerable.
10. **Direct vs contextual:** Naive direct PCR was 12/18 (66.7%) versus contextual 7/18 (38.9%).
11. **Legitimate action utility:** Policy Gate READ=5.000/5 (100.0%), WRITE=5.000/5 (100.0%); compare Naive READ=5.000/5 (100.0%), WRITE=5.000/5 (100.0%).
12. **Third-model replication:** Yes; the common-subset table records the qualitative pattern across SmolLM2, Qwen, and Phi.

## Statistical reporting

Each primary PCR/ECR/EVR/ASR entry includes the project's existing Wilson 95% interval. No new interval procedure was introduced.

## Reproducibility and resources

- Model `microsoft/Phi-4-mini-instruct` at `cfbefacb99257ffa30c83adab238a50856ac3083`; unquantized BF16 on `cuda:0`.
- Existing pinned Iteration 4C snapshot reused; download time was zero.
- Deterministic P4 generation: seed 53, `do_sample=false`, `max_new_tokens=192`.
- All raw outputs are preserved in `raw_runs.jsonl`.
- Resource measurements are in `resource_metrics.json`.
- Pre/post regression suites: 63/63 PASS.
