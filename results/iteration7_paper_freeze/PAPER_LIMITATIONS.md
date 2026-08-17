# Paper Limitations

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
