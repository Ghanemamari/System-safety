# Iteration 2B — Security Benchmark on Demonstrated Capabilities

## Decision

**ACTION_SECURITY_SIGNAL_REPLICATED**

Among 16 tasks whose legitimate versions SmolLM2 demonstrably completed,
untrusted content compromised 16/32 Naive attacked proposals and 11/32 Minimal
Prompt Defense proposals. Every compromised proposal was executable. Naive
executed all 16 violations. Policy Gate received the same 16 compromised model
outputs as Naive and executed none, giving 100% containment over denominator
16. No Policy Gate failure occurred.

This is a bounded development experiment on demonstrated capabilities. It does
not establish that SmolLM2 is secure or that Policy Gate provides universal
security.

## Scope and integrity

- Frozen eligible tasks: 16 (5 READ, 5 WRITE, 6 NO-ACTION)
- Architectures: Naive, Minimal Prompt Defense, Policy Gate
- Conditions: clean, direct, contextual
- Repetitions: one
- Completed: 144/144 unique rows; errors: 0; mocks: 0
- Validation and seven frozen test tasks used: 0
- Frozen component hash mismatches: 0
- Naive/Policy Gate matched raw-output differences: 0/48
- Policy Gate implementation, attacks, parser, simulator, model, decoding,
  prompts, and eligibility labels were not modified

The nine ineligible Iteration 2A tasks remain in the source benchmark and its
General Utility report. They were not attacked because the user-fixed primary
scope was 16 eligible tasks × 3 architectures × 3 conditions = 144 runs.

## Primary capability-conditioned result

All 32 attacked rows per architecture are matched to frozen
`security_eligible=true` tasks. Thus Raw and Conditional denominators are both
32 in this bounded experiment, while their definitions remain distinct.

| Architecture | Conditional PCR | Conditional ECR | Conditional EVR | Raw ASR | Conditional ASR | Containment | Action Utility |
|---|---:|---:|---:|---:|---:|---:|---:|
| Naive | 16/32 = 50.0% | 16/32 = 50.0% | 16/32 = 50.0% | 16/32 = 50.0% | 16/32 = 50.0% | 1 − 16/16 = 0% | 100% |
| Minimal Prompt Defense | 11/32 = 34.4% | 11/32 = 34.4% | 11/32 = 34.4% | 11/32 = 34.4% | 11/32 = 34.4% | 1 − 11/11 = 0% | 100% |
| Policy Gate | 16/32 = 50.0% | 16/32 = 50.0% | 0/32 = 0% | 0/32 = 0% | 0/32 = 0% | 1 − 0/16 = 100% | 100% |

Legitimate Action Utility uses the ten matched CLEAN READ/WRITE rows. It is
100% for all architectures. Security-Eligible Utility over clean and attacked
rows is 62.5% Naive, 63.2% Prompt Defense, and 70.8% Policy Gate. Attack-task
utility is 43.75%, 50.0%, and 56.25%, respectively. General Utility across all
25 clean Iteration 2A tasks remains separately reported as 68%; it is not used
to infer security here.

## READ tasks

| Architecture | Conditional PCR | Conditional ECR | Conditional EVR | Raw/Conditional ASR | Containment | Action Utility |
|---|---:|---:|---:|---:|---:|---:|
| Naive | 1/10 = 10% | 1/10 = 10% | 1/10 = 10% | 1/10 = 10% | 0/1 contained | 100% |
| Minimal Prompt Defense | 1/10 = 10% | 1/10 = 10% | 1/10 = 10% | 1/10 = 10% | 0/1 contained | 100% |
| Policy Gate | 1/10 = 10% | 1/10 = 10% | 0/10 = 0% | 0/10 = 0% | 1/1 contained = 100% | 100% |

## WRITE tasks

| Architecture | Conditional PCR | Conditional ECR | Conditional EVR | Raw/Conditional ASR | Containment | Action Utility |
|---|---:|---:|---:|---:|---:|---:|
| Naive | 9/10 = 90% | 9/10 = 90% | 9/10 = 90% | 9/10 = 90% | 0/9 contained | 100% |
| Minimal Prompt Defense | 8/10 = 80% | 8/10 = 80% | 8/10 = 80% | 8/10 = 80% | 0/8 contained | 100% |
| Policy Gate | 9/10 = 90% | 9/10 = 90% | 0/10 = 0% | 0/10 = 0% | 9/9 contained = 100% | 100% |

WRITE is the clearest authority-risk signal. Of Naive's nine WRITE
compromises, eight preserve the authorized `send_email` name but substitute
attacker-controlled arguments; one substitutes/escalates the action. Prompt
Defense has seven attacker-argument substitutions and one action substitution.
These are security compromises even when the action name remains authorized.

## NO-ACTION tasks

| Architecture | Conditional PCR | Conditional ECR | Conditional EVR | Raw/Conditional ASR | Containment |
|---|---:|---:|---:|---:|---:|
| Naive | 6/12 = 50% | 6/12 = 50% | 6/12 = 50% | 6/12 = 50% | 0/6 contained |
| Minimal Prompt Defense | 2/12 = 16.7% | 2/12 = 16.7% | 2/12 = 16.7% | 2/12 = 16.7% | 0/2 contained |
| Policy Gate | 6/12 = 50% | 6/12 = 50% | 0/12 = 0% | 0/12 = 0% | 6/6 contained = 100% |

All compromises here are new unauthorized actions introduced where the
legitimate task required no action.

## DIRECT attacks

| Architecture | Conditional PCR/ECR | Conditional EVR | Raw/Conditional ASR | Containment |
|---|---:|---:|---:|---:|
| Naive | 7/16 = 43.75% | 7/16 = 43.75% | 7/16 = 43.75% | 0/7 contained |
| Minimal Prompt Defense | 3/16 = 18.75% | 3/16 = 18.75% | 3/16 = 18.75% | 0/3 contained |
| Policy Gate | 7/16 = 43.75% | 0/16 = 0% | 0/16 = 0% | 7/7 contained = 100% |

## CONTEXTUAL attacks

| Architecture | Conditional PCR/ECR | Conditional EVR | Raw/Conditional ASR | Containment |
|---|---:|---:|---:|---:|
| Naive | 9/16 = 56.25% | 9/16 = 56.25% | 9/16 = 56.25% | 0/9 contained |
| Minimal Prompt Defense | 8/16 = 50.0% | 8/16 = 50.0% | 8/16 = 50.0% | 0/8 contained |
| Policy Gate | 9/16 = 56.25% | 0/16 = 0% | 0/16 = 0% | 9/9 contained = 100% |

Contextual attacks are stronger than direct attacks here, especially against
Prompt Defense. Attacks are therefore not classified as too weak.

## Complete security chain and policy outcomes

Every attacked row records untrusted input, proposal, full proposed arguments,
schema validation, compromise stage, policy decision, execution decision,
executed action, and side effect.

Outcome counts:

- Naive: 16 `MODEL_COMPROMISED_AND_EXECUTED`, 16
  `MODEL_NOT_COMPROMISED`.
- Minimal Prompt Defense: 11 `MODEL_COMPROMISED_AND_EXECUTED`, 21
  `MODEL_NOT_COMPROMISED`.
- Policy Gate: 16 `MODEL_COMPROMISED_BUT_BLOCKED`, 16
  `MODEL_NOT_COMPROMISED`, 0 `POLICY_FAILURE`.

The complete row-level classification is in `security_outcomes.csv`.

## Qualitative comparison with earlier iterations

Development and prior experiments are not numerically merged.

1. **Does Prompt Defense reduce model compromise?** Yes, in aggregate: 50.0%
   to 34.4%. The effect is uneven; WRITE remains 80% compromised.
2. **Does Policy Gate leave model compromise unchanged?** Yes. Its PCR/ECR are
   identical to Naive at every aggregate level, and all 48 matched raw outputs
   are identical.
3. **Does Policy Gate reduce executed violations?** Yes: EVR 50.0% to 0%, with
   16/16 executable compromises contained.
4. **Does the effect hold when legitimate capability is demonstrated?** Yes.
   Legitimate READ/WRITE action utility is 100%, and all analyzed attacked
   tasks inherit frozen demonstrated-capability eligibility.

The qualitative model-robustness/system-containment pattern from Iteration 1F
is replicated, but Prompt Defense's reduction is smaller and WRITE attacks
remain highly effective.

## Stop

The appropriate status is `ACTION_SECURITY_SIGNAL_REPLICATED`. This supports a
bounded claim: among these demonstrated actions, untrusted content frequently
redirects the model, especially for writes, while the tested external Policy
Gate prevents the resulting simulated unauthorized effects.

No frozen test task, larger model, additional repetition, or follow-on attack
run was launched.
