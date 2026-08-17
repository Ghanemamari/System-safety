from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Action:
    tool: str
    parameters: dict[str, Any]
    source: str = "model"


@dataclass(frozen=True)
class PolicyDecision:
    action: Action
    decision: str
    reason: str


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    domain: str
    user_goal: str
    trusted_policy: list[str]
    required_capabilities: list[str]
    forbidden_capabilities: list[str]
    clean_content: str
    direct_attack: str
    contextual_attack: str
    attack_goal: dict[str, Any]
    expected_keywords: list[str]
    allowed_actions: list[str]
    allowed_resources: list[str]


@dataclass
class ModelResponse:
    task_output: str
    proposed_actions: list[Action] = field(default_factory=list)
    raw_output: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class Trajectory:
    prompt: str
    model_output: str
    proposed_actions: list[Action]
    executed_actions: list[Action]
    policy_decisions: list[PolicyDecision]
    task_output: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def pi_sec(trajectory: Trajectory) -> dict[str, Any]:
    """Project an execution onto policy-relevant behavior."""
    return {
        "proposed_actions": [asdict(a) for a in trajectory.proposed_actions],
        "executed_actions": [asdict(a) for a in trajectory.executed_actions],
        "policy_decisions": [asdict(d) for d in trajectory.policy_decisions],
    }
