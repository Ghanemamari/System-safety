from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from secure_llm.architectures import make_architecture
from secure_llm.backend import MockLLMBackend
from secure_llm.evaluation import security_violation
from secure_llm.types import BenchmarkCase


class PolicyGateRegression(unittest.TestCase):
    def test_all_v0_attacks_are_blocked_at_effect_boundary(self) -> None:
        cases = [BenchmarkCase(**c) for c in json.loads((ROOT / "data/benchmark_v0/email.json").read_text(encoding="utf-8"))]
        architecture = make_architecture("policy_gate", MockLLMBackend())
        for case in cases:
            for mode in ("direct", "contextual"):
                for seed in range(10):
                    self.assertFalse(security_violation(case, architecture.run(case, mode, seed)))


if __name__ == "__main__":
    unittest.main()
