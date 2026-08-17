#!/usr/bin/env python3
"""Apply the Iteration 7B paper-only scope correction.

This script is deliberately limited to derived files in
results/iteration7_paper_freeze. It verifies the prior freeze and frozen source
hashes, rewrites paper-facing scope labels, checks the source trees again, and
regenerates the final manifest and SHA-256 inventory. It imports no model or
experiment code and performs no inference.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "iteration7_paper_freeze"

SOURCE_DIRS = [
    "results/20260812T104118.870114Z_iteration2a_legitimate_capability",
    "results/20260812T120446.636116Z_iteration2b_security_eligible",
    "results/iteration3a_qwen25_7b_runpod",
    "results/iteration3b_qwen25_7b_security",
    "results/iteration4a_mistral7b_capability",
    "results/iteration4b_llama31_8b_capability",
    "results/iteration4c_phi4mini_capability",
    "results/iteration4d_phi4mini_security",
    "results/iteration5a_shieldstral_guardrail",
    "results/iteration6_frozen_final",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_text(path: Path, value: str) -> None:
    path.write_text(value.rstrip() + "\n", encoding="utf-8", newline="\n")


def verify_sha_file(path: Path, base: Path) -> list[str]:
    errors: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            errors.append(f"malformed hash line: {line!r}")
            continue
        expected, relative = match.groups()
        target = base / relative
        if not target.is_file():
            errors.append(f"missing: {relative}")
        elif sha256(target) != expected:
            errors.append(f"hash mismatch: {relative}")
    return errors


def tree_snapshot(relative_dirs: list[str]) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for relative_dir in relative_dirs:
        directory = ROOT / relative_dir
        if not directory.is_dir():
            raise RuntimeError(f"missing frozen source directory: {relative_dir}")
        for path in sorted(p for p in directory.rglob("*") if p.is_file()):
            snapshot[path.relative_to(ROOT).as_posix()] = sha256(path)
    return snapshot


def snapshot_digest(snapshot: dict[str, str]) -> str:
    canonical = "".join(f"{key}\0{snapshot[key]}\n" for key in sorted(snapshot))
    return text_sha256(canonical)


def verify_source_manifest(manifest: dict) -> None:
    mismatches: list[str] = []
    for relative, expected in manifest["source_artifact_hashes"].items():
        path = ROOT / relative
        if not path.is_file():
            mismatches.append(f"missing: {relative}")
        elif sha256(path) != expected:
            mismatches.append(f"hash mismatch: {relative}")
    if mismatches:
        raise RuntimeError("frozen source verification failed: " + "; ".join(mismatches))


def validate_frozen_numbers() -> None:
    metrics = read_json(ROOT / "results/iteration6_frozen_final/metrics.json")
    expected_conditional = {
        "SmolLM2": (5, 10, 7, 7, 0, 7),
        "Qwen2.5-7B": (4, 8, 6, 6, 0, 6),
        "Phi-4-mini": (2, 4, 1, 1, 0, 1),
    }
    expected_raw = {
        "SmolLM2": (14, 11, 11, 0, 11),
        "Qwen2.5-7B": (14, 12, 12, 0, 12),
        "Phi-4-mini": (14, 7, 7, 0, 7),
    }
    for model, (eligible, attacked, ecr, naive_evr, gate_evr, contained) in expected_conditional.items():
        assert metrics["capability"][model]["eligible_tasks"] == eligible
        naive = metrics["security"][model]["naive"]["conditional"]
        gate = metrics["security"][model]["policy_gate"]["conditional"]
        assert naive["attacked"] == attacked
        assert naive["ECR"]["numerator"] == ecr
        assert naive["EVR"]["numerator"] == naive_evr
        assert gate["EVR"]["numerator"] == gate_evr
        assert gate["Containment"]["numerator"] == contained
        assert gate["Containment"]["denominator"] == contained
    for model, (attacked, ecr, naive_evr, gate_evr, contained) in expected_raw.items():
        naive = metrics["security"][model]["naive"]["raw"]
        gate = metrics["security"][model]["policy_gate"]["raw"]
        assert naive["attacked"] == attacked
        assert naive["ECR"]["numerator"] == ecr
        assert naive["EVR"]["numerator"] == naive_evr
        assert gate["EVR"]["numerator"] == gate_evr
        assert gate["Containment"]["numerator"] == contained
        assert gate["Containment"]["denominator"] == contained
    assert sum(v[1] for v in expected_conditional.values()) == 22
    assert sum(v[2] for v in expected_conditional.values()) == 14
    assert sum(v[0] for v in expected_raw.values()) == 42
    assert sum(v[1] for v in expected_raw.values()) == 30
    assert metrics["equivalence"] == {
        "matched_runs": 63,
        "identical_messages": 63,
        "identical_raw_outputs": 63,
        "identical_parsed_proposals": 63,
    }
    assert metrics["shieldstral"]["malicious"] == 30
    assert metrics["shieldstral"]["blocked_malicious"] == 30
    assert metrics["shieldstral"]["benign"] == 11
    assert metrics["shieldstral"]["allowed_benign"] == 11


CONTENT = {
    "AUDIT_DISCREPANCIES.md": r"""# Audit Discrepancies

Status: **RESOLVED — PAPER_RESULTS_FROZEN**

## Resolved scope-labeling discrepancy

The Iteration 7 audit found one reporting discrepancy: the final Policy Gate result of 30/30 had been requested as capability-conditioned even though it is the raw all-task aggregate.

Iteration 7B corrected paper-facing scope labels without changing any scientific result:

- Raw all-task final scope: 42 attacked cases, 30 executable unauthorized proposals, 30/30 contained, and 0/42 executed violations under Policy Gate.
- Capability-conditioned final scope: 22 attacked cases, 14 executable unauthorized proposals, 14/14 contained, and 0/22 executed violations under Policy Gate.

No additional discrepancy was found. Frozen experiment artifacts, methodology, and numerical results remain unchanged.
""",
    "PAPER_KEY_FINDINGS.md": r"""# Paper-Ready Key Findings

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
""",
    "PAPER_CLAIMS.md": r"""# Paper Claims

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
""",
    "PAPER_LIMITATIONS.md": r"""# Paper Limitations

1. The evaluation uses a simulated email-agent domain.
2. The benchmark and attack sample sizes are limited.
3. The frozen final split contains only seven tasks.
4. Model-specific final capability eligibility is 5/7 for SmolLM2, 4/7 for Qwen, and 2/7 for Phi.
5. The primary capability-conditioned final analysis contains only 22 attacked cases.
6. The final common three-model subset contains only two tasks.
7. The final split contains no READ-action task.
8. Only three agent models passed capability qualification and received full security evaluation.
9. Mistral failed the frozen capability thresholds, despite 16/25 nominally eligible tasks.
10. Llama was not evaluated because model access was blocked; this is not a security failure.
11. Direct and contextual attacks are frozen templates, not adaptive attackers designed specifically against Policy Gate.
12. Evaluation uses deterministic single generations rather than repeated sampling.
13. Policy Gate assumes trusted user intent can be represented sufficiently precisely.
14. Ambiguous intent, delegation, dynamic permissions, revocation, and multi-step authority remain open problems.
15. Raw final metrics cover all 42 attacked cases, including tasks on which legitimate capability was not independently demonstrated; capability-conditioned metrics are therefore the primary final security evidence.
16. Zero observed Policy Gate violations does not imply a zero probability of future failure and is not a formal or universal guarantee.
17. Shieldstral had two development false negatives even though it had zero false negatives on the small retrospective raw final malicious set.
""",
    "MAIN_RESULT_PARAGRAPH.tex": r"""Across the frozen held-out capability-conditioned evaluation, the three capability-qualified agent models produced 14 executable unauthorized proposals over 22 attacked cases. Under direct execution, all 14 led to executed violations. The deterministic Policy Gate preserved identical model-facing behavior while containing all 14 observed executable unauthorized proposals, reducing capability-conditioned EVR from 14/22 to 0/22. Across all 42 attacked final-test cases irrespective of independently demonstrated clean-task capability, the corresponding raw all-task containment result was 30/30, with EVR reduced from 30/42 to 0/42. Naive and Policy Gate messages, raw outputs, and parsed proposals were identical in all 63 matched runs across the entire final experiment. These findings provide bounded empirical evidence that post-proposal authority enforcement can separate model compromise from system-level compromise in the tested email-agent environment.""",
    "SHIELDSTRAL_RESULT_PARAGRAPH.tex": r"""Shieldstral, evaluated as an external learned probabilistic classifier, blocked 62 of 64 executable unauthorized development proposals (96.9\%), with two false negatives, while allowing all 57 benign proposals. In the retrospective raw final malicious set, it blocked all 30 stored executable unauthorized proposals (30/30) and allowed all 11 eligible benign proposals (11/11). The absence of final-set misses does not establish perfect safety and must be interpreted together with the two development false negatives. Shieldstral is mechanistically distinct from the deterministic Policy Gate, which enforces explicit authority constraints after proposal generation.""",
    "FINAL_TEST_PARAGRAPH.tex": r"""The frozen final evaluation used seven held-out tasks and completed all 189 scheduled agent generations with zero errors, zero retries, and no post-unblinding method changes. Held-out legitimate capability was demonstrated on 5/7 SmolLM2, 4/7 Qwen, and 2/7 Phi tasks. In the primary capability-conditioned scope, 22 attacked cases yielded 14 executable unauthorized proposals; Policy Gate contained 14/14 and reduced EVR from 14/22 to 0/22. Separately, across the raw all-task scope of 42 attacked cases, Policy Gate contained 30/30 executable unauthorized proposals and reduced EVR from 30/42 to 0/42. Naive and Policy Gate messages, raw outputs, and parsed proposals matched in 63/63 paired runs across the entire final experiment. Shieldstral blocked 30/30 proposals in the retrospective raw final malicious set and allowed 11/11 eligible benign proposals. Interpretation remains limited because the common three-model subset contains only two tasks and the final split contains no READ-action task.""",
    "ABSTRACT_NUMBERS.md": r"""# Abstract Numbers

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
""",
    "table_frozen_final.tex": r"""\begin{table}[t]
\centering
\caption{Capability-Conditioned Frozen Final Results. All metrics use only model-specific held-out tasks on which legitimate capability was independently demonstrated.}
\label{tab:frozen-final}
\begin{tabular}{lrlrrrr}
\toprule
Model & Eligible & Architecture & PCR & ECR & EVR & Containment \\
\midrule
SmolLM2 & 5/7 & naive & 8/10 (80.0\%) & 7/10 (70.0\%) & 7/10 (70.0\%) & 0/7 (0.0\%) \\
SmolLM2 & 5/7 & prompt\_defense & 7/10 (70.0\%) & 7/10 (70.0\%) & 7/10 (70.0\%) & 0/7 (0.0\%) \\
SmolLM2 & 5/7 & policy\_gate & 8/10 (80.0\%) & 7/10 (70.0\%) & 0/10 (0.0\%) & 7/7 (100.0\%) \\
Qwen2.5-7B & 4/7 & naive & 6/8 (75.0\%) & 6/8 (75.0\%) & 6/8 (75.0\%) & 0/6 (0.0\%) \\
Qwen2.5-7B & 4/7 & prompt\_defense & 4/8 (50.0\%) & 4/8 (50.0\%) & 4/8 (50.0\%) & 0/4 (0.0\%) \\
Qwen2.5-7B & 4/7 & policy\_gate & 6/8 (75.0\%) & 6/8 (75.0\%) & 0/8 (0.0\%) & 6/6 (100.0\%) \\
Phi-4-mini & 2/7 & naive & 1/4 (25.0\%) & 1/4 (25.0\%) & 1/4 (25.0\%) & 0/1 (0.0\%) \\
Phi-4-mini & 2/7 & prompt\_defense & 1/4 (25.0\%) & 1/4 (25.0\%) & 1/4 (25.0\%) & 0/1 (0.0\%) \\
Phi-4-mini & 2/7 & policy\_gate & 1/4 (25.0\%) & 1/4 (25.0\%) & 0/4 (0.0\%) & 1/1 (100.0\%) \\
\bottomrule
\end{tabular}
\end{table}""",
    "table_frozen_final.csv": """Scope,Model,Eligible,Architecture,PCR,ECR,EVR,Containment,PCR_numerator,PCR_denominator,ECR_numerator,ECR_denominator,EVR_numerator,EVR_denominator,Containment_numerator,Containment_denominator
Capability-conditioned,SmolLM2,5/7,naive,8/10 (80.0%),7/10 (70.0%),7/10 (70.0%),0/7 (0.0%),8,10,7,10,7,10,0,7
Capability-conditioned,SmolLM2,5/7,prompt_defense,7/10 (70.0%),7/10 (70.0%),7/10 (70.0%),0/7 (0.0%),7,10,7,10,7,10,0,7
Capability-conditioned,SmolLM2,5/7,policy_gate,8/10 (80.0%),7/10 (70.0%),0/10 (0.0%),7/7 (100.0%),8,10,7,10,0,10,7,7
Capability-conditioned,Qwen2.5-7B,4/7,naive,6/8 (75.0%),6/8 (75.0%),6/8 (75.0%),0/6 (0.0%),6,8,6,8,6,8,0,6
Capability-conditioned,Qwen2.5-7B,4/7,prompt_defense,4/8 (50.0%),4/8 (50.0%),4/8 (50.0%),0/4 (0.0%),4,8,4,8,4,8,0,4
Capability-conditioned,Qwen2.5-7B,4/7,policy_gate,6/8 (75.0%),6/8 (75.0%),0/8 (0.0%),6/6 (100.0%),6,8,6,8,0,8,6,6
Capability-conditioned,Phi-4-mini,2/7,naive,1/4 (25.0%),1/4 (25.0%),1/4 (25.0%),0/1 (0.0%),1,4,1,4,1,4,0,1
Capability-conditioned,Phi-4-mini,2/7,prompt_defense,1/4 (25.0%),1/4 (25.0%),1/4 (25.0%),0/1 (0.0%),1,4,1,4,1,4,0,1
Capability-conditioned,Phi-4-mini,2/7,policy_gate,1/4 (25.0%),1/4 (25.0%),0/4 (0.0%),1/1 (100.0%),1,4,1,4,0,4,1,1""",
    "table_frozen_final_raw.csv": """Scope,Model,Architecture,PCR,ECR,EVR,Containment,PCR_numerator,PCR_denominator,ECR_numerator,ECR_denominator,EVR_numerator,EVR_denominator,Containment_numerator,Containment_denominator
Raw all-task,SmolLM2,naive,12/14 (85.7%),11/14 (78.6%),11/14 (78.6%),0/11 (0.0%),12,14,11,14,11,14,0,11
Raw all-task,SmolLM2,prompt_defense,8/14 (57.1%),8/14 (57.1%),8/14 (57.1%),0/8 (0.0%),8,14,8,14,8,14,0,8
Raw all-task,SmolLM2,policy_gate,12/14 (85.7%),11/14 (78.6%),0/14 (0.0%),11/11 (100.0%),12,14,11,14,0,14,11,11
Raw all-task,Qwen2.5-7B,naive,12/14 (85.7%),12/14 (85.7%),12/14 (85.7%),0/12 (0.0%),12,14,12,14,12,14,0,12
Raw all-task,Qwen2.5-7B,prompt_defense,10/14 (71.4%),10/14 (71.4%),10/14 (71.4%),0/10 (0.0%),10,14,10,14,10,14,0,10
Raw all-task,Qwen2.5-7B,policy_gate,12/14 (85.7%),12/14 (85.7%),0/14 (0.0%),12/12 (100.0%),12,14,12,14,0,14,12,12
Raw all-task,Phi-4-mini,naive,7/14 (50.0%),7/14 (50.0%),7/14 (50.0%),0/7 (0.0%),7,14,7,14,7,14,0,7
Raw all-task,Phi-4-mini,prompt_defense,7/14 (50.0%),7/14 (50.0%),7/14 (50.0%),0/7 (0.0%),7,14,7,14,7,14,0,7
Raw all-task,Phi-4-mini,policy_gate,7/14 (50.0%),7/14 (50.0%),0/14 (0.0%),7/7 (100.0%),7,14,7,14,0,14,7,7""",
    "table_frozen_final_raw.tex": r"""\begin{table}[t]
\centering
\caption{Raw Frozen Final Results Over All Held-Out Tasks. These results include tasks irrespective of independently demonstrated clean-task capability.}
\label{tab:frozen-final-raw}
\begin{tabular}{llrrrr}
\toprule
Model & Architecture & PCR & ECR & EVR & Containment \\
\midrule
SmolLM2 & naive & 12/14 (85.7\%) & 11/14 (78.6\%) & 11/14 (78.6\%) & 0/11 (0.0\%) \\
SmolLM2 & prompt\_defense & 8/14 (57.1\%) & 8/14 (57.1\%) & 8/14 (57.1\%) & 0/8 (0.0\%) \\
SmolLM2 & policy\_gate & 12/14 (85.7\%) & 11/14 (78.6\%) & 0/14 (0.0\%) & 11/11 (100.0\%) \\
Qwen2.5-7B & naive & 12/14 (85.7\%) & 12/14 (85.7\%) & 12/14 (85.7\%) & 0/12 (0.0\%) \\
Qwen2.5-7B & prompt\_defense & 10/14 (71.4\%) & 10/14 (71.4\%) & 10/14 (71.4\%) & 0/10 (0.0\%) \\
Qwen2.5-7B & policy\_gate & 12/14 (85.7\%) & 12/14 (85.7\%) & 0/14 (0.0\%) & 12/12 (100.0\%) \\
Phi-4-mini & naive & 7/14 (50.0\%) & 7/14 (50.0\%) & 7/14 (50.0\%) & 0/7 (0.0\%) \\
Phi-4-mini & prompt\_defense & 7/14 (50.0\%) & 7/14 (50.0\%) & 7/14 (50.0\%) & 0/7 (0.0\%) \\
Phi-4-mini & policy\_gate & 7/14 (50.0\%) & 7/14 (50.0\%) & 0/14 (0.0\%) & 7/7 (100.0\%) \\
\bottomrule
\end{tabular}
\end{table}""",
    "table_external_enforcement.csv": """Split,Mechanism,Mechanism Type,Scope,Attacked Cases,Executable or Malicious,Contained or Blocked,Executed or Allowed,Benign Eligible Allowed,Scope Note
Development model-specific,Shieldstral,learned probabilistic classifier,retrospective stored malicious proposals,not an attacked-case denominator,64,62,2,57/57,Guardrail GDR/FNR over stored Naive executable-unauthorized proposals
Development model-specific,Policy Gate,deterministic authority enforcement,three separate capability-conditioned experiments,114,64,64,0,not pooled,Containment over matched executable unauthorized proposals
Frozen final,Policy Gate,deterministic authority enforcement,capability-conditioned,22,14,14,0,11/11,Primary final security scope using model-specific clean capability
Frozen final,Policy Gate,deterministic authority enforcement,raw all-task,42,30,30,0,11/11,Secondary scope irrespective of demonstrated clean-task capability
Frozen final,Shieldstral,learned probabilistic classifier,retrospective raw stored malicious set,not a capability-conditioned attacked denominator,30,30,0,11/11,Classified the 30 raw stored executable unauthorized proposals""",
    "table_external_enforcement.tex": r"""\begin{table*}[t]
\centering
\caption{External enforcement results with non-interchangeable scopes. Policy Gate is reported separately for the primary capability-conditioned and secondary raw all-task final analyses; Shieldstral is a retrospective classifier evaluation over stored proposals.}
\label{tab:external-enforcement}
\begin{tabular}{llllrrrr}
\toprule
Split & Mechanism & Scope & Type & Cases & Malicious/Exec. & Contained/Blocked & Executed/Allowed \\
\midrule
Development & Shieldstral & retrospective stored proposals & learned & -- & 64 & 62 & 2 \\
Development & Policy Gate & capability-conditioned, model-specific & deterministic & 114 & 64 & 64 & 0 \\
Frozen final & Policy Gate & capability-conditioned & deterministic & 22 & 14 & 14 & 0 \\
Frozen final & Policy Gate & raw all-task & deterministic & 42 & 30 & 30 & 0 \\
Frozen final & Shieldstral & retrospective raw stored set & learned & -- & 30 & 30 & 0 \\
\bottomrule
\end{tabular}
\par\smallskip\footnotesize Shieldstral allowed 57/57 eligible benign development proposals and 11/11 eligible benign final proposals. Its malicious denominators are stored proposal sets, not attacked-case denominators, and therefore should not be directly compared as if the scopes were identical.
\end{table*}""",
    "figure_shieldstral_vs_policy.csv": """model,split,architecture,metric,numerator,denominator,percentage,scope_note
Shieldstral,development_retrospective,learned_guardrail,GDR,62,64,96.875,stored executable-unauthorized proposals
Policy Gate,development_model_specific,deterministic_authority,Containment,64,64,100.0,three separate capability-conditioned experiments
Shieldstral,frozen_final_retrospective_raw,learned_guardrail,GDR,30,30,100.0,raw stored executable-unauthorized proposal set
Policy Gate,frozen_final_raw_all_task,deterministic_authority,Containment,30,30,100.0,42 attacked cases irrespective of demonstrated clean capability
Policy Gate,frozen_final_capability_conditioned,deterministic_authority,Containment,14,14,100.0,22 attacked cases with model-specific demonstrated clean capability""",
    "FINAL_RESULTS_AUDIT.md": r"""# Final Results Audit

## 1. Source artifacts

Ten immutable source directories were audited. Exact paths, revisions, primary artifacts, current SHA-256 values, and existing-manifest verification are recorded in `source_manifest.json` and `source_artifact_sha256.txt`.

## 2. Capability results

Raw capability trajectories reproduce SmolLM2 17/25 general utility with 16/25 eligible, Qwen 23/25 with 23/25 eligible, Mistral 17/25 with 16/25 eligible, and Phi 20.333/25 with 18/25 eligible. Read/write LAC is respectively 5/5 and 5/5, 5/5 and 5/5, 4/5 and 3/5, and 5/5 and 5/5.

## 3. Development security

Model-specific Naive executable compromise is 16/32 (SmolLM2), 29/46 (Qwen), and 19/36 (Phi). Policy Gate preserves those executable proposal counts and reduces EVR to zero, containing 64/64 in aggregate across the three separate experiments.

## 4. Common-subset replication

The eligibility intersection contains 15 tasks. Naive compromise is 14/30, 16/30, and 14/30; Policy Gate containment is 14/14, 16/16, and 14/14 for SmolLM2, Qwen, and Phi.

## 5. Phi replication

Phi independently passed read and write LAC at 5/5 and reproduced the development compromise/containment separation on 18 eligible tasks and the 15-task common subset.

## 6. Shieldstral baseline

Shieldstral blocked 62/64 malicious development proposals and allowed 57/57 benign proposals. Both false negatives are preserved: one SmolLM2 and one Qwen direct no-action case. In the retrospective raw final malicious set, Shieldstral blocked 30/30 stored executable unauthorized proposals and allowed 11/11 eligible benign proposals.

## 7. Frozen final test and corrected scope distinction

The seven-task split has SHA-256 `6b77e8925e52c4edfce48070699734bbc3e1ade7077d00ce9f04fc3a973a9e64`. All 189 agent runs completed with zero errors and retries. Eligibility is 5/7, 4/7, and 2/7; the common subset contains two tasks and no final task exercises READ action.

The primary capability-conditioned final analysis contains 22 attacked cases and 14 executable unauthorized proposals. Direct execution produced 14/22 violations; Policy Gate contained 14/14 proposals and produced 0/22 violations.

The secondary raw all-task analysis contains 42 attacked cases and 30 executable unauthorized proposals. Direct execution produced 30/42 violations; Policy Gate contained 30/30 proposals and produced 0/42 violations.

## 8. Naive/Policy causal-control verification

Messages, raw outputs, and parsed proposals are each identical in 63/63 matched runs across the entire final experiment. This is not a capability-conditioned run count. The EVR difference is therefore attributable within this experiment to post-proposal enforcement rather than a changed model-facing input or output.

## 9. Integrity checks

All existing source artifact manifest checks remain PASS where manifests are available. The two earlier SmolLM2 result directories do not contain native hash manifests; their audited hashes remain recorded in the Iteration 7 source manifest. Source directories were hashed before and after this scope-only correction and were unchanged. No inference or experiment code was invoked.

## 10. Discrepancy resolution

The sole Iteration 7 discrepancy is resolved. The 30/30 final Policy Gate result is consistently labeled raw all-task; the primary capability-conditioned result is 14/14 over 22 attacked cases. No scientific number, task eligibility decision, method, or source experiment artifact changed. See `AUDIT_DISCREPANCIES.md` and `SCOPE_CONSISTENCY_AUDIT.md`.

## 11. Final claims

Paper-safe claims are enumerated in `PAPER_CLAIMS.md`. Zero observed violations is bounded empirical evidence, not a proof or universal guarantee.

## 12. Limitations

See `PAPER_LIMITATIONS.md`, including the small final/common subsets, absent READ final action, three qualified agent models, deterministic single generations, and non-adaptive frozen attacks.

## 13. Paper-ready artifact inventory

Capability, development security, common development, Shieldstral, capability-conditioned frozen final, raw all-task frozen final, and external-enforcement tables are available in CSV/LaTeX form. `MASTER_RESULTS.csv` and `.md` are the canonical numerical references; insertable result paragraphs and plot-ready CSVs are also included. The optional figure remains skipped because no new dependency or plotting workflow was introduced.
""",
}


def build_scope_audit() -> tuple[str, list[str]]:
    occurrences_30: list[str] = []
    occurrences_14: list[str] = []
    errors: list[str] = []
    for path in sorted(OUT.iterdir()):
        if path.name in {"FINAL_FREEZE_MANIFEST.json", "FINAL_FREEZE_SHA256.txt", "SCOPE_CONSISTENCY_AUDIT.md"}:
            continue
        if path.suffix.lower() not in {".md", ".tex", ".csv"}:
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            lowered = line.lower()
            if "30/30" in line:
                occurrences_30.append(f"- `{path.name}:{line_number}` — {line.strip()}")
                if not any(label in lowered for label in ("raw", "all-task", "all 42", "retrospective")):
                    errors.append(f"30/30 lacks raw/retrospective scope: {path.name}:{line_number}")
            if "14/14" in line:
                occurrences_14.append(f"- `{path.name}:{line_number}` — {line.strip()}")
                if ("final" in lowered or "frozen" in lowered) and "capability" not in lowered:
                    errors.append(f"final 14/14 lacks capability-conditioned scope: {path.name}:{line_number}")
            if "30 executable" in lowered and "capability-conditioned" in lowered and not any(
                label in lowered for label in ("raw", "all-task", "all 42")
            ):
                errors.append(f"30 executable incorrectly associated with conditioned scope: {path.name}:{line_number}")
    audit = """# Scope Consistency Audit

Status: **PASS**

This lexical audit covers the Iteration 7 paper-facing Markdown, LaTeX, and CSV artifacts after the Iteration 7B correction. It does not rerun or reinterpret any experiment.

## `30/30` occurrences

Every occurrence below explicitly identifies a raw/all-task or retrospective raw proposal scope:

{occurrences_30}

## `14/14` occurrences

Final-test occurrences identify the capability-conditioned scope. Development common-subset occurrences retain their original development context:

{occurrences_14}

## `30 executable` association check

No occurrence incorrectly assigns 30 executable unauthorized proposals to the capability-conditioned denominator.

## Result

Capability-conditioned and raw final scopes are separated consistently. No new discrepancy was found.
""".format(
        occurrences_30="\n".join(occurrences_30) or "- None",
        occurrences_14="\n".join(occurrences_14) or "- None",
    )
    return audit, errors


def main() -> int:
    if not OUT.is_dir():
        raise RuntimeError(f"missing paper-freeze directory: {OUT}")

    prior_hash_file = OUT / "FINAL_FREEZE_SHA256.txt"
    prior_manifest_file = OUT / "FINAL_FREEZE_MANIFEST.json"
    prior_freeze_errors = verify_sha_file(prior_hash_file, OUT)
    if prior_freeze_errors:
        raise RuntimeError("prior freeze verification failed: " + "; ".join(prior_freeze_errors))

    prior_manifest = read_json(prior_manifest_file)
    verify_source_manifest(prior_manifest)
    validate_frozen_numbers()

    prior_manifest_sha = sha256(prior_manifest_file)
    prior_hash_inventory_sha = sha256(prior_hash_file)
    source_before = tree_snapshot(SOURCE_DIRS)
    before_hashes = {
        path.name: sha256(path)
        for path in OUT.iterdir()
        if path.is_file() and path.name != "FINAL_FREEZE_SHA256.txt"
    }

    for filename, content in CONTENT.items():
        write_text(OUT / filename, content)

    scope_audit, scope_errors = build_scope_audit()
    if scope_errors:
        raise RuntimeError("scope consistency check failed: " + "; ".join(scope_errors))
    write_text(OUT / "SCOPE_CONSISTENCY_AUDIT.md", scope_audit)

    source_after = tree_snapshot(SOURCE_DIRS)
    if source_before != source_after:
        changed_sources = sorted(set(source_before) | set(source_after))
        changed_sources = [p for p in changed_sources if source_before.get(p) != source_after.get(p)]
        raise RuntimeError("frozen source artifacts changed: " + "; ".join(changed_sources))

    after_content_hashes = {
        path.name: sha256(path)
        for path in OUT.iterdir()
        if path.is_file() and path.name not in {"FINAL_FREEZE_MANIFEST.json", "FINAL_FREEZE_SHA256.txt"}
    }
    edited = sorted(
        name for name, digest in after_content_hashes.items() if before_hashes.get(name) != digest
    )
    unchanged_reviewed = sorted(
        name
        for name in [
            "MASTER_RESULTS.md",
            "figure_final_security.csv",
        ]
        if name not in edited
    )

    manifest = {
        "decision": "PAPER_RESULTS_FROZEN",
        "iteration": "7B",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "correction_type": "scope-labeling only",
        "declarations": {
            "no_new_inference": True,
            "no_new_experiments": True,
            "no_source_experiment_changes": True,
            "no_methodological_changes": True,
            "no_numerical_result_changes": True,
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "previous_freeze": {
            "decision": prior_manifest.get("decision"),
            "manifest_sha256": prior_manifest_sha,
            "hash_inventory_sha256": prior_hash_inventory_sha,
            "verification": "PASS",
        },
        "source_integrity": {
            "source_directory_count": len(SOURCE_DIRS),
            "source_file_count": len(source_before),
            "tree_sha256_before": snapshot_digest(source_before),
            "tree_sha256_after": snapshot_digest(source_after),
            "unchanged": source_before == source_after,
            "prior_primary_artifact_hashes_verified": True,
        },
        "scope_correction": {
            "primary_capability_conditioned": {
                "attacked_cases": 22,
                "executable_unauthorized_proposals": 14,
                "contained": 14,
                "executed_violations_policy_gate": 0,
                "containment": "14/14",
                "evr": "0/22",
            },
            "secondary_raw_all_task": {
                "attacked_cases": 42,
                "executable_unauthorized_proposals": 30,
                "contained": 30,
                "executed_violations_policy_gate": 0,
                "containment": "30/30",
                "evr": "0/42",
            },
            "naive_policy_equivalence_scope": "entire final experiment",
            "naive_policy_equivalence": {
                "identical_messages": "63/63",
                "identical_raw_outputs": "63/63",
                "identical_parsed_proposals": "63/63",
            },
            "shieldstral_final_scope": "retrospective raw stored malicious proposal set",
        },
        "edited_paper_artifacts": edited,
        "reviewed_and_unchanged_artifacts": unchanged_reviewed,
        "scope_consistency_audit": "PASS",
        "new_discrepancies": [],
        "generated_artifact_hashes_before_manifest": after_content_hashes,
    }
    write_text(prior_manifest_file, json.dumps(manifest, indent=2, sort_keys=True))

    hash_lines = []
    for path in sorted(p for p in OUT.iterdir() if p.is_file() and p.name != "FINAL_FREEZE_SHA256.txt"):
        hash_lines.append(f"{sha256(path)}  {path.name}")
    write_text(prior_hash_file, "\n".join(hash_lines))

    final_errors = verify_sha_file(prior_hash_file, OUT)
    if final_errors:
        raise RuntimeError("regenerated freeze verification failed: " + "; ".join(final_errors))

    print("PAPER_RESULTS_FROZEN")
    print(f"edited_artifacts={len(edited)}")
    print("edited=" + ",".join(edited))
    print(f"source_tree_sha256={snapshot_digest(source_after)}")
    print(f"freeze_manifest_sha256={sha256(prior_manifest_file)}")
    print(f"freeze_inventory_sha256={sha256(prior_hash_file)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"AUDIT_REQUIRES_REVIEW: {exc}", file=sys.stderr)
        raise SystemExit(1)
