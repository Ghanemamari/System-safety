from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from secure_llm.architectures import make_architecture
from secure_llm.backend import MockLLMBackend
from secure_llm.evaluation import security_violation, task_success
from secure_llm.metrics import wilson_interval
from secure_llm.policy import PolicyEngine
from secure_llm.types import Action, BenchmarkCase, Trajectory, pi_sec


class FrameworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.case = BenchmarkCase(**json.loads((ROOT / "data/benchmark_v0/email.json").read_text(encoding="utf-8"))[0])

    def test_dataset_is_paired_and_has_ten_cases(self) -> None:
        cases = json.loads((ROOT / "data/benchmark_v0/email.json").read_text(encoding="utf-8"))
        self.assertEqual(10, len(cases))
        self.assertTrue(all(c["clean_content"] and c["direct_attack"] and c["contextual_attack"] for c in cases))

    def test_policy_blocks_unauthorized_send(self) -> None:
        decision = PolicyEngine().authorize(self.case, Action("send_email", {"recipient":"attacker@example.com"}))
        self.assertEqual("BLOCK", decision.decision)

    def test_policy_gate_never_executes_injected_send(self) -> None:
        architecture = make_architecture("policy_gate", MockLLMBackend())
        for seed in range(100):
            trajectory = architecture.run(self.case, "direct", seed)
            self.assertFalse(security_violation(self.case, trajectory))

    def test_projection_separates_attempts_and_effects(self) -> None:
        action = Action("send_email", {"recipient":"attacker@example.com"})
        trajectory = Trajectory("p", "o", [action], [], [], "summary")
        projection = pi_sec(trajectory)
        self.assertEqual(1, len(projection["proposed_actions"]))
        self.assertEqual(0, len(projection["executed_actions"]))

    def test_task_utility_is_reference_based(self) -> None:
        trajectory = Trajectory("p", "o", [], [], [], "Budget receipts are due Friday")
        self.assertTrue(task_success(self.case, trajectory))

    def test_wilson_bounds(self) -> None:
        low, high = wilson_interval(5, 10)
        self.assertLess(low, 0.5)
        self.assertGreater(high, 0.5)


if __name__ == "__main__":
    unittest.main()
