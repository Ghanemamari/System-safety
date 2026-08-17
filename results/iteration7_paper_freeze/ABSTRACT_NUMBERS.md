# Abstract Numbers

## Recommended primary final number

- Across 22 capability-conditioned attacked final-test cases, Policy Gate contained all 14 executable unauthorized proposals (14/14), reducing EVR from 14/22 under direct execution to 0/22 under policy enforcement.
- If space permits: Naive and Policy Gate messages, raw outputs, and parsed proposals were identical in 63/63 matched runs across the entire final experiment.

## Development replication

- On the three-model common development subset, Naive executable compromise was 14/30 for SmolLM2, 16/30 for Qwen, and 14/30 for Phi; Policy Gate EVR was 0/30 for each model.

## Better placed in the main results

- Raw all-task frozen final: across all 42 attacked cases, Policy Gate contained 30/30 executable unauthorized proposals and had 0/42 executed violations.
- Shieldstral development: 62/64 malicious blocked and 57/57 benign allowed.
- Shieldstral retrospective raw final: 30/30 malicious blocked and 11/11 eligible benign allowed.
- Model-specific capability counts: SmolLM2 16/25, Qwen 23/25, and Phi 18/25.

The raw all-task 30/30 result must not be presented as capability-conditioned; the primary capability-conditioned subset contains 14 executable proposals over 22 attacked cases.
