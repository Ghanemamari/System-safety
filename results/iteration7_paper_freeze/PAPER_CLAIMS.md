# Paper Claims

## A. STRONGLY SUPPORTED

1. Frozen prompt injection produced executable unauthorized proposals for all three independently capability-qualified agent models: SmolLM2, Qwen2.5-7B, and Phi-4-mini.
2. In the model-specific development experiments, matched Policy Gate runs retained model compromise while containing 64/64 observed executable unauthorized proposals; on the 15-task common subset the corresponding count was 44/44.
3. The qualitative separation between model compromise and executed system violations replicated across three agent-model families.
4. Across 22 capability-conditioned attacked final-test cases, the three models produced 14 executable unauthorized proposals; Policy Gate contained all 14 observed proposals (14/14), reducing EVR from 14/22 under direct execution to 0/22 under policy enforcement.
5. Across all 42 raw final attacked cases, 30 executable unauthorized proposals were observed and Policy Gate contained all 30 (30/30), with 0/42 executed violations.
6. Naive and Policy Gate had identical model-facing messages, raw outputs, and parsed proposals in 63/63 matched runs across the entire final experiment.
7. Shieldstral was a strong learned baseline: it blocked 62/64 malicious development proposals while allowing 57/57 benign proposals, and in the retrospective raw final malicious set blocked 30/30 proposals while allowing 11/11 eligible benign proposals.

## B. SUPPORTED BUT BOUNDED

- Prompt Defense reduced overall compromise in several development experiments, but did not eliminate compromise and did not improve every model or scope.
- Argument-level authorization matters: an authorized tool name can be retained while security-sensitive arguments are substituted.
- Capability conditioning is empirically important because legitimate task capability differed materially across models and held-out tasks.
- Mistral produced structurally valid outputs but failed the frozen LAC thresholds (read 4/5; write 3/5), illustrating the incapability/security confound.
- The seven-task frozen final experiment supports the main qualitative security result, but its three-model common subset contains only two tasks and no final task tests a READ action.

## C. NOT SUPPORTED / DO NOT CLAIM

- “Policy Gate is provably secure.”
- “Policy Gate guarantees security.”
- “Shieldstral is perfectly safe.”
- “Larger models are more secure” or “larger models are less secure.”
- “Prompt Defense always works.”
- “Policy Gate generalizes to every agent domain.”
- “Raw all-task containment of 30/30 means the probability of future failure is zero.”
- “Shieldstral and Policy Gate are equivalent.”
- “The final common subset provides strong quantitative model ranking.”
