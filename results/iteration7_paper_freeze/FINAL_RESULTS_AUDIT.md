# Final Results Audit

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
