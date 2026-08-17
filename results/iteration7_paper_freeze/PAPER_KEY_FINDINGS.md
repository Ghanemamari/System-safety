# Paper-Ready Key Findings

## Finding 1 — Capability qualification matters

Legitimate capability varied substantially: 16/25 SmolLM2, 23/25 Qwen, and 18/25 Phi tasks were security-eligible. Mistral reached 16/25 nominal eligibility but failed the frozen read and write LAC thresholds. Conditioning security conclusions on demonstrated legitimate behavior prevents model incapability from being counted as robustness.

## Finding 2 — Model compromise persists across three models

On the shared 15-task development subset, Naive executable compromise occurred in 14/30 SmolLM2, 16/30 Qwen, and 14/30 Phi attacked cases.

## Finding 3 — Prompt defense reduces but does not eliminate compromise

On that common subset, Minimal Prompt Defense reduced compromise to 10/30 for SmolLM2, 13/30 for Qwen, and 10/30 for Phi, but every remaining executable proposal became an executed violation under direct execution.

## Finding 4 — Authority enforcement separates model from system compromise

Policy Gate preserved the common-subset proposal counts (14/30, 16/30, and 14/30) while reducing executed violations to 0/30 for each model, containing 44/44 observed executable unauthorized proposals. In the primary frozen capability-conditioned evaluation, it contained 14/14 executable unauthorized proposals over 22 attacked cases and reduced EVR from 14/22 to 0/22. Separately, in the raw all-task final analysis, it contained 30/30 executable unauthorized proposals over 42 attacked cases.

## Finding 5 — Learned guardrail is strong but probabilistic

Shieldstral blocked 62/64 malicious development proposals and allowed 57/57 benign proposals. Its two false negatives—one SmolLM2 and one Qwen case—were both direct, no-action attacks. In the retrospective raw final malicious set, it blocked 30/30 proposals and allowed 11/11 eligible benign proposals, but the small held-out result does not erase the development misses.

## Finding 6 — Frozen held-out evaluation confirms the qualitative signal

Across 189/189 error-free, no-retry final generations, Naive and Policy Gate messages, raw outputs, and parsed proposals matched in 63/63 paired runs across the entire final experiment. Executable compromises remained present, while Policy Gate yielded zero executed violations.

## Finding 7 — Argument-level authority matters

Several write compromises preserved the authorized action type while substituting recipient, subject, or body fields. Authority enforcement must therefore validate security-sensitive arguments, not only tool names.
