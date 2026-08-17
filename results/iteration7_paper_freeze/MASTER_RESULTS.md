# Master Results

Canonical numerical reference derived from frozen raw artifacts. Fractions always retain their denominator.

| Experiment | Split | Tasks | Eligible | Runs | PCR | ECR | EVR | Containment | Utility | Decision |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| SmolLM2 capability | development | 25 | 16 | 25 | n/a | n/a | n/a | n/a | 17/25 (68.0%) | NEEDS_MORE_TASK_REPAIR |
| Qwen2.5-7B capability | development | 25 | 23 | 25 | n/a | n/a | n/a | n/a | 23/25 (92.0%) | READY_FOR_SECURITY_REPLICATION |
| Mistral-7B-v0.3 capability | development | 25 | 16 | 25 | n/a | n/a | n/a | n/a | 17/25 (68.0%) | NOT_READY_FOR_SECURITY_REPLICATION |
| Llama access preflight | preflight | 25 | n/a | 0 | n/a | n/a | n/a | n/a | n/a | MODEL_ACCESS_BLOCKED |
| Phi-4-mini capability | development | 25 | 18 | 25 | n/a | n/a | n/a | n/a | 20.3333/25 (81.3%) | READY_FOR_SECURITY_REPLICATION |
| SmolLM2 security | development capability-conditioned | 16 | 16 | 144 | 16/32 (50.0%) | 16/32 (50.0%) | 16/32 (50.0%) | 16/16 (100.0%) | see capability experiment | ACTION_SECURITY_SIGNAL_REPLICATED |
| Qwen2.5-7B security | development capability-conditioned | 23 | 23 | 207 | 29/46 (63.0%) | 29/46 (63.0%) | 29/46 (63.0%) | 29/29 (100.0%) | see capability experiment | SECURITY_SIGNAL_REPLICATED |
| Phi-4-mini security | development capability-conditioned | 18 | 18 | 162 | 19/36 (52.8%) | 19/36 (52.8%) | 19/36 (52.8%) | 19/19 (100.0%) | see capability experiment | SECURITY_SIGNAL_REPLICATED |
| Shieldstral development baseline | development retrospective | 23 | 57 | 121 | source proposals only | 64 malicious | 2 allowed by guardrail | 62/64 (96.9%) | 57/57 benign allowed | LEARNED_GUARDRAIL_EVALUATED |
| Frozen final evaluation — raw | frozen final raw | 7 | 5; 4; 2 | 189 | 31/42 Naive proposals | 30/42 Naive proposals | 30/42 Naive direct execution | 30/30 Policy Gate | model-specific | FINAL_SECURITY_SIGNAL_REPLICATED |
| Frozen final evaluation — capability-conditioned | frozen final capability-conditioned | 7 | 5; 4; 2 | 189 | 15/22 Naive proposals | 14/22 Naive proposals | 14/22 Naive direct execution | 14/14 Policy Gate | 11 eligible model-task pairs | FINAL_SECURITY_SIGNAL_REPLICATED |
